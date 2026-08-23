"""Tests for the SSO bad-password retry path.

Covers:
  * The bad-password classifier in ``login_protocol`` against real Wireshark
    captures (``example_data/NoProxy_BadPassword.json`` and
    ``NoProxy_ServerListIdle.json``).
  * The new sequence-translation helpers on ``ProxySessionState``.
  * The LoginProxy orchestration: arming, suppressing bad responses, replaying
    the original Login on the existing SOE session, and shifting subsequent
    C->S OP_Packet sequences by ``cs_offset``.
"""

from __future__ import annotations

import json
import struct
import time
from collections.abc import Iterable
from pathlib import Path
from unittest import mock

import pytest

from p99_sso_login_proxy import login_protocol as lp
from p99_sso_login_proxy import soe_protocol as soe
from p99_sso_login_proxy.session import ProxySessionState

CAPTURES_DIR = Path(__file__).resolve().parents[2] / "example_data"
LOGIN_PORT = 5998


# ---------------------------------------------------------------------------
# Capture loading helpers
# ---------------------------------------------------------------------------
def _udp_payloads(capture_path: Path) -> Iterable[tuple[str, bytes]]:
    """Yield ``(direction, raw_payload)`` for every UDP frame in *capture_path*.

    Direction is ``"C->S"`` if the destination port is the login port and
    ``"S->C"`` otherwise. Frames without a UDP payload are skipped.
    """
    with capture_path.open("r", encoding="utf-8") as fh:
        packets = json.load(fh)
    for entry in packets:
        layers = entry["_source"]["layers"]
        udp = layers.get("udp")
        if not udp:
            continue
        payload_hex = udp.get("udp.payload")
        if not payload_hex:
            continue
        direction = "C->S" if int(udp["udp.dstport"]) == LOGIN_PORT else "S->C"
        yield direction, bytes.fromhex(payload_hex.replace(":", ""))


def _login_accepted_app_payload(capture_path: Path) -> bytes:
    """Return the app payload of the first LoginAccepted in *capture_path*.

    The app payload starts with the 2-byte LE app opcode, matching what the
    classifier expects.
    """
    for direction, buf in _udp_payloads(capture_path):
        if direction != "S->C":
            continue
        op = soe.get_transport_opcode(buf)
        if op == soe.TransportOp.Combined:
            cp = soe.CombinedPacket.parse(bytearray(buf))
            for sub in cp:
                if sub.transport_op != soe.TransportOp.Packet:
                    continue
                app_payload = bytes(buf[sub.offset + 4 : sub.offset + sub.length])
                if len(app_payload) >= 2 and lp.get_app_opcode(app_payload) == lp.AppOp.LoginAccepted:
                    return app_payload
        elif op == soe.TransportOp.Packet:
            app_payload = bytes(buf[4:])
            if len(app_payload) >= 2 and lp.get_app_opcode(app_payload) == lp.AppOp.LoginAccepted:
                return app_payload
    raise AssertionError(f"No LoginAccepted in {capture_path.name}")


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not (CAPTURES_DIR / "NoProxy_BadPassword.json").exists(),
    reason="NoProxy_BadPassword.json capture not available",
)
def test_classifier_flags_real_bad_password_capture():
    payload = _login_accepted_app_payload(CAPTURES_DIR / "NoProxy_BadPassword.json")
    assert lp.is_bad_password_login_result(payload) is True


@pytest.mark.skipif(
    not (CAPTURES_DIR / "NoProxy_ServerListIdle.json").exists(),
    reason="NoProxy_ServerListIdle.json capture not available",
)
def test_classifier_rejects_real_good_login_capture():
    payload = _login_accepted_app_payload(CAPTURES_DIR / "NoProxy_ServerListIdle.json")
    assert lp.is_bad_password_login_result(payload) is False


def test_classifier_rejects_non_loginaccepted_payload():
    chat = struct.pack("<H", lp.AppOp.ChatMessage) + b"\x00" * 20
    assert lp.is_bad_password_login_result(chat) is False


def test_classifier_rejects_empty_payload():
    assert lp.is_bad_password_login_result(b"") is False
    assert lp.is_bad_password_login_result(b"\x17\x00") is False


def test_classifier_handles_synthesized_failure():
    """A hand-rolled bad-password payload should classify as bad."""
    plaintext = struct.pack("<III", 12345, 0, lp.LOGIN_RESULT_FAILURE_STATUS) + b"\x00" * 20
    encrypted = lp.des_encrypt(plaintext)
    base = struct.pack("<iBbI", 3, 0, 2, 0)
    payload = struct.pack("<H", lp.AppOp.LoginAccepted) + base + encrypted
    assert lp.is_bad_password_login_result(payload) is True


def test_classifier_handles_synthesized_success_with_lskey_tail():
    plaintext = struct.pack("<III", 1, 0, 0x0007390F) + b"O8A8KN22FZ\x00\x00\x00\x00\x00\x01"
    encrypted = lp.des_encrypt(plaintext)
    base = struct.pack("<iBbI", 3, 0, 2, 0)
    payload = struct.pack("<H", lp.AppOp.LoginAccepted) + base + encrypted
    assert lp.is_bad_password_login_result(payload) is False


# ---------------------------------------------------------------------------
# ProxySessionState retry helpers
# ---------------------------------------------------------------------------
def _build_combined_ack_then_packet(ack_seq: int, packet_seq: int, app_payload: bytes) -> bytearray:
    """Build a small ``Combined[Ack, Packet]`` for tests."""
    ack_sub = struct.pack(">HH", soe.TransportOp.Ack, ack_seq)
    packet_sub = struct.pack(">HH", soe.TransportOp.Packet, packet_seq) + app_payload
    body = bytes([len(ack_sub)]) + ack_sub + bytes([len(packet_sub)]) + packet_sub
    return bytearray(struct.pack(">H", soe.TransportOp.Combined) + body)


def test_default_cs_offset_does_not_shift_packet_subs():
    state = ProxySessionState()
    buf = _build_combined_ack_then_packet(ack_seq=0, packet_seq=1, app_payload=b"\x02\x00")
    state.adjust_combined(buf)
    cp = soe.CombinedPacket.parse(buf)
    packet_sub = next(s for s in cp if s.transport_op == soe.TransportOp.Packet)
    assert soe.get_sequence(buf, packet_sub.offset) == 1


def test_injected_client_packet_shifts_subsequent_packet_subs_by_one():
    state = ProxySessionState()
    state.note_injected_client_packet()
    assert state.cs_offset == 1

    buf = _build_combined_ack_then_packet(ack_seq=0, packet_seq=2, app_payload=b"\x04\x00")
    state.adjust_combined(buf)
    cp = soe.CombinedPacket.parse(buf)
    packet_sub = next(s for s in cp if s.transport_op == soe.TransportOp.Packet)
    assert soe.get_sequence(buf, packet_sub.offset) == 3


def test_adjust_client_packet_shifts_standalone_op_packet():
    state = ProxySessionState()
    state.note_injected_client_packet()

    buf = bytearray(struct.pack(">HH", soe.TransportOp.Packet, 3) + b"\x04\x00")
    state.adjust_client_packet(buf)
    assert soe.get_sequence(buf) == 4


def test_note_suppressed_server_packet_advances_seq_from_server_only():
    state = ProxySessionState()
    state.seq_to_client = 1
    state.seq_from_server = 1

    state.note_suppressed_server_packet(server_seq=1)

    assert state.seq_from_server == 2
    assert state.seq_to_client == 1, "suppressed packet must not consume a client sequence"


def test_reset_clears_cs_offset_and_counters():
    state = ProxySessionState()
    state.note_injected_client_packet()
    state.note_suppressed_server_packet(5)
    state.seq_to_client = 7

    state.reset()

    assert state.cs_offset == 0
    assert state.seq_to_client == 0
    assert state.seq_from_server == 0


def test_adjust_server_ack_no_offset_is_noop():
    state = ProxySessionState()
    buf = bytearray(struct.pack(">HH", soe.TransportOp.Ack, 5))
    state.adjust_server_ack(buf)
    assert soe.get_sequence(buf) == 5


def test_adjust_server_ack_subtracts_cs_offset():
    state = ProxySessionState()
    state.cs_offset = 1
    buf = bytearray(struct.pack(">HH", soe.TransportOp.Ack, 5))
    state.adjust_server_ack(buf)
    assert soe.get_sequence(buf) == 4


def test_adjust_server_ack_clamps_to_zero():
    state = ProxySessionState()
    state.cs_offset = 3
    buf = bytearray(struct.pack(">HH", soe.TransportOp.Ack, 1))
    state.adjust_server_ack(buf)
    assert soe.get_sequence(buf) == 0


def test_recv_combined_applies_rewrites_in_place_and_returns_buffer():
    """The new recv_combined applies all rewrites in place and returns the
    modified buffer. No callback fanout, no double-send."""
    state = ProxySessionState()
    state.cs_offset = 1
    state.seq_to_client = 1
    state.seq_from_server = 2

    inner = struct.pack(">HH", soe.TransportOp.Packet, 2) + struct.pack("<H", lp.AppOp.LoginAccepted) + b"\x00" * 10
    ack = struct.pack(">HH", soe.TransportOp.Ack, 5)
    body = bytes([len(ack)]) + ack + bytes([len(inner)]) + inner
    buf = bytearray(struct.pack(">H", soe.TransportOp.Combined) + body)

    result = state.recv_combined(buf)
    assert result is buf, "should return the same buffer (in-place rewrite)"

    cp = soe.CombinedPacket.parse(result)
    ack_sub = next(s for s in cp if s.transport_op == soe.TransportOp.Ack)
    pkt_sub = next(s for s in cp if s.transport_op == soe.TransportOp.Packet)
    assert soe.get_sequence(result, ack_sub.offset) == 4, "Ack must be translated by cs_offset (5-1)"
    assert soe.get_sequence(result, pkt_sub.offset) == 1, "Packet must be rewritten to seq_to_client"
    assert state.seq_to_client == 2
    assert state.seq_from_server == 3


# ---------------------------------------------------------------------------
# LoginProxy retry orchestration
# ---------------------------------------------------------------------------
def _make_login_combined(username: str, password: str) -> bytearray:
    """Build a Combined[Ack(0), Packet(seq=1, Login(user,pass))] datagram.

    Mirrors what the EQ client sends right after the ChatMessage welcome.
    """
    encrypted = lp.encrypt_login_credentials(username, password)
    base = struct.pack("<iBbI", 3, 0, 2, 0)
    app_payload = struct.pack("<H", lp.AppOp.Login) + base + encrypted
    packet_sub = struct.pack(">HH", soe.TransportOp.Packet, 1) + app_payload
    ack_sub = struct.pack(">HH", soe.TransportOp.Ack, 0)
    body = bytes([len(ack_sub)]) + ack_sub + bytes([len(packet_sub)]) + packet_sub
    return bytearray(struct.pack(">H", soe.TransportOp.Combined) + body)


def _make_login_accepted_combined(account_id: int, status: int, server_seq: int = 1) -> bytearray:
    plaintext = struct.pack("<III", account_id, 0, status) + b"\x00" * 20
    encrypted = lp.des_encrypt(plaintext)
    base = struct.pack("<iBbI", 3, 0, 2, 0)
    app_payload = struct.pack("<H", lp.AppOp.LoginAccepted) + base + encrypted
    packet_sub = struct.pack(">HH", soe.TransportOp.Packet, server_seq) + app_payload
    ack_sub = struct.pack(">HH", soe.TransportOp.Ack, 1)  # acks our Login at seq=1
    body = bytes([len(ack_sub)]) + ack_sub + bytes([len(packet_sub)]) + packet_sub
    return bytearray(struct.pack(">H", soe.TransportOp.Combined) + body)


@pytest.fixture
def login_proxy():
    """Stand up a ``LoginProxy`` with stubbed UI/transport for testing."""
    with mock.patch("p99_sso_login_proxy.ui.PROXY_STATS", new=mock.MagicMock()):
        from p99_sso_login_proxy import server as server_mod

        proxy = server_mod.LoginProxy()
        proxy.transport = mock.MagicMock()
        proxy.client_addr = ("127.0.0.1", 4321)

        # Mimic post-handshake state: ChatMessage (server seq=0) was forwarded.
        proxy.in_session = True
        proxy.last_recv_time = time.time()
        proxy.session.seq_to_client = 1
        proxy.session.seq_from_server = 1
        yield proxy


def _server_sends(proxy) -> list[bytes]:
    """Bytes the proxy has sent to the login server, in order."""
    from p99_sso_login_proxy import config

    return [bytes(call.args[0]) for call in proxy.transport.sendto.call_args_list if call.args[1] == config.EQEMU_ADDR]


def _client_sends(proxy) -> list[bytes]:
    return [bytes(call.args[0]) for call in proxy.transport.sendto.call_args_list if call.args[1] == proxy.client_addr]


def test_armed_bad_password_combined_is_suppressed_and_retry_is_sent(login_proxy):
    proxy = login_proxy
    proxy._sso_original_login = bytes(_make_login_combined("user", "userpass"))
    proxy._sso_retry_armed = True

    bad = _make_login_accepted_combined(account_id=27392, status=0xFFFFFFFF, server_seq=1)
    proxy.handle_server_packet(bad)

    # The surviving server Ack(1) of the client's original Login MUST reach
    # the client so the client retires its packet and doesn't retransmit.
    client_sent = _client_sends(proxy)
    assert len(client_sent) == 1, "the surviving server Ack must be forwarded"
    survivor = client_sent[0]
    assert soe.get_transport_opcode(survivor) == soe.TransportOp.Ack
    assert struct.unpack(">H", survivor[2:4])[0] == 1, "Ack must still reference client's Login(seq=1)"

    server_sent = _server_sends(proxy)
    assert len(server_sent) == 2, "expected ACK + retried Login on the server side"

    ack = server_sent[0]
    assert soe.get_transport_opcode(ack) == soe.TransportOp.Ack
    assert struct.unpack(">H", ack[2:4])[0] == 1, "ACK must reference suppressed server seq"

    retry = bytearray(server_sent[1])
    assert soe.get_transport_opcode(retry) == soe.TransportOp.Combined
    cp = soe.CombinedPacket.parse(retry)
    packet_sub = next(s for s in cp if s.transport_op == soe.TransportOp.Packet)
    assert soe.get_sequence(retry, packet_sub.offset) == 2, "retry Login must land on the next server-side sequence"

    parsed = lp.LoginPacket.parse(retry)
    assert parsed is not None, "retry must still be a valid Login Combined"
    assert parsed.username == "user"
    assert parsed.password == "userpass"

    assert proxy._sso_retry_armed is False
    assert proxy._sso_retry_fired is True
    assert proxy.session.cs_offset == 1
    assert proxy.session.seq_from_server == 2
    assert proxy.session.seq_to_client == 1, "client did not see the bad packet, so its sequence must not advance"


def test_armed_good_login_passes_through_without_retry(login_proxy):
    proxy = login_proxy
    proxy._sso_original_login = bytes(_make_login_combined("user", "userpass"))
    proxy._sso_retry_armed = True

    good = _make_login_accepted_combined(account_id=1, status=0x0007390F, server_seq=1)
    proxy.handle_server_packet(good)

    assert proxy._sso_retry_armed is False, "armed flag must clear after a real login result"
    assert proxy._sso_retry_fired is False
    assert proxy.session.cs_offset == 0, "no retry => no offset"
    assert _server_sends(proxy) == [], "no ACK or retry should be sent"

    # The good Combined must reach the client EXACTLY ONCE (the previous
    # double-send pattern caused issues when sequences diverged after retry).
    client_sent = _client_sends(proxy)
    assert len(client_sent) == 1, "good Combined must be forwarded exactly once"
    forwarded = client_sent[0]
    assert soe.get_transport_opcode(forwarded) == soe.TransportOp.Combined


def test_unarmed_bad_password_is_not_intercepted(login_proxy):
    proxy = login_proxy
    proxy._sso_retry_armed = False

    bad = _make_login_accepted_combined(account_id=27392, status=0xFFFFFFFF, server_seq=1)
    proxy.handle_server_packet(bad)

    assert proxy.session.cs_offset == 0
    assert _server_sends(proxy) == [], "no ACK or retry should be sent when not armed"
    # Without arming, the proxy is just a transparent forwarder: client gets
    # the same Combined the server sent, exactly once.
    assert len(_client_sends(proxy)) == 1


def test_already_fired_retry_does_not_retry_again(login_proxy):
    proxy = login_proxy
    proxy._sso_original_login = bytes(_make_login_combined("user", "userpass"))
    proxy._sso_retry_armed = False
    proxy._sso_retry_fired = True

    bad = _make_login_accepted_combined(account_id=27392, status=0xFFFFFFFF, server_seq=2)
    proxy.handle_server_packet(bad)

    assert _server_sends(proxy) == [], "second bad response must not trigger another retry"


def test_post_retry_client_combined_packet_is_shifted(login_proxy):
    """After a retry, a client OP_Combined[Ack, Packet] must have its inner
    OP_Packet sequence shifted by +1 before forwarding to the server."""
    proxy = login_proxy
    proxy._sso_original_login = bytes(_make_login_combined("user", "userpass"))
    proxy._sso_retry_armed = True
    bad = _make_login_accepted_combined(account_id=27392, status=0xFFFFFFFF, server_seq=1)
    proxy.handle_server_packet(bad)
    proxy.transport.reset_mock()

    server_list_request = _build_combined_ack_then_packet(
        ack_seq=1, packet_seq=2, app_payload=struct.pack("<H", lp.AppOp.ServerListRequest) + b"\x00" * 12
    )
    proxy.handle_client_packet(server_list_request, ("127.0.0.1", 4321))

    server_sent = _server_sends(proxy)
    assert len(server_sent) == 1
    forwarded = server_sent[0]
    cp = soe.CombinedPacket.parse(bytearray(forwarded))
    packet_sub = next(s for s in cp if s.transport_op == soe.TransportOp.Packet)
    assert soe.get_sequence(forwarded, packet_sub.offset) == 3, (
        "client's seq=2 must be forwarded as server-side seq=3 after retry"
    )


def test_post_retry_standalone_client_op_packet_is_shifted(login_proxy):
    proxy = login_proxy
    proxy._sso_original_login = bytes(_make_login_combined("user", "userpass"))
    proxy._sso_retry_armed = True
    bad = _make_login_accepted_combined(account_id=27392, status=0xFFFFFFFF, server_seq=1)
    proxy.handle_server_packet(bad)
    proxy.transport.reset_mock()

    standalone = bytearray(struct.pack(">HH", soe.TransportOp.Packet, 3) + b"\x04\x00" + b"\x00" * 12)
    proxy.handle_client_packet(standalone, ("127.0.0.1", 4321))

    server_sent = _server_sends(proxy)
    assert len(server_sent) == 1
    forwarded = server_sent[0]
    assert soe.get_transport_opcode(forwarded) == soe.TransportOp.Packet
    assert soe.get_sequence(forwarded) == 4, "standalone Packet seq=3 must be forwarded as seq=4"


def test_post_retry_good_login_combined_is_translated_and_forwarded_once(login_proxy):
    """End-to-end: bad-password Combined intercepted, retry fired, GOOD
    LoginAccepted Combined arrives, must be rewritten once and forwarded once.
    """
    proxy = login_proxy
    proxy._sso_original_login = bytes(_make_login_combined("user", "userpass"))
    proxy._sso_retry_armed = True

    # Bad-password response (server-seq=1).
    bad = _make_login_accepted_combined(account_id=27392, status=0xFFFFFFFF, server_seq=1)
    proxy.handle_server_packet(bad)
    proxy.transport.reset_mock()

    # Server now responds to our retry with Combined[Ack(2), LoginAccepted(seq=2, good)].
    good = _make_login_accepted_combined(account_id=1, status=0x0007390F, server_seq=2)
    # _make_login_accepted_combined puts Ack(1) inside; rewrite to Ack(2) for realism.
    cp = soe.CombinedPacket.parse(good)
    ack_sub = next(s for s in cp if s.transport_op == soe.TransportOp.Ack)
    soe.set_sequence(good, ack_sub.offset, 2)
    proxy.handle_server_packet(good)

    client_sent = _client_sends(proxy)
    assert len(client_sent) == 1, "good Combined must be forwarded EXACTLY ONCE post-retry"
    forwarded = client_sent[0]
    assert soe.get_transport_opcode(forwarded) == soe.TransportOp.Combined
    cp_out = soe.CombinedPacket.parse(bytearray(forwarded))
    out_ack = next(s for s in cp_out if s.transport_op == soe.TransportOp.Ack)
    out_pkt = next(s for s in cp_out if s.transport_op == soe.TransportOp.Packet)
    assert soe.get_sequence(forwarded, out_ack.offset) == 1, (
        "server Ack(2) must be translated to Ack(1) by cs_offset, matching client's Login(seq=1)"
    )
    assert soe.get_sequence(forwarded, out_pkt.offset) == 1, (
        "good LoginAccepted must be rewritten to client-seq=1 (the seq the client expected)"
    )

    # Session counters: seq_to_client advances from 1->2 (client sees 1 packet
    # forwarded), seq_from_server advances from 2->3.
    assert proxy.session.seq_to_client == 2
    assert proxy.session.seq_from_server == 3


def test_post_retry_standalone_server_ack_is_translated(login_proxy):
    """A standalone server Ack post-retry must have cs_offset subtracted."""
    proxy = login_proxy
    proxy._sso_original_login = bytes(_make_login_combined("user", "userpass"))
    proxy._sso_retry_armed = True
    bad = _make_login_accepted_combined(account_id=27392, status=0xFFFFFFFF, server_seq=1)
    proxy.handle_server_packet(bad)
    proxy.transport.reset_mock()

    # Server sends standalone Ack(2) acknowledging our retry Login.
    raw_ack = bytearray(struct.pack(">HH", soe.TransportOp.Ack, 2))
    proxy.handle_server_packet(raw_ack)

    client_sent = _client_sends(proxy)
    assert len(client_sent) == 1
    out = client_sent[0]
    assert soe.get_transport_opcode(out) == soe.TransportOp.Ack
    assert soe.get_sequence(out) == 1, "Ack(2) must be translated to Ack(1)"


def test_ordinary_standalone_server_ack_is_suppressed(login_proxy):
    proxy = login_proxy
    raw_ack = bytearray(struct.pack(">HH", soe.TransportOp.Ack, 6))

    proxy.handle_server_packet(raw_ack)

    assert _client_sends(proxy) == []


def test_session_disconnect_resets_retry_state(login_proxy):
    proxy = login_proxy
    proxy._sso_original_login = bytes(_make_login_combined("user", "userpass"))
    proxy._sso_retry_armed = True
    proxy._sso_retry_fired = True
    proxy.session.cs_offset = 1
    proxy.session.seq_from_server = 5

    proxy.handle_client_packet(
        bytearray(struct.pack(">HHI", soe.TransportOp.SessionDisconnect, 0, 0)),
        ("127.0.0.1", 4321),
    )

    assert proxy._sso_original_login is None
    assert proxy._sso_retry_armed is False
    assert proxy._sso_retry_fired is False
    assert proxy.session.cs_offset == 0
    assert proxy.session.seq_from_server == 0
