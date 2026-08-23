# Based in large part on the original work by Zaela:
# https://github.com/Zaela/p99-login-middlemand
from __future__ import annotations

import asyncio
import logging
import struct
import time

from p99_sso_login_proxy import config, local_characters, ui, ws_client
from p99_sso_login_proxy import login_protocol as lp
from p99_sso_login_proxy import soe_protocol as soe
from p99_sso_login_proxy.login_protocol import LoginPacket
from p99_sso_login_proxy.session import ProxySessionState

logger = logging.getLogger("server")


def debug_write_packet(buf: bytes, login_to_client):
    length = len(buf)
    direction = "LOGIN to CLIENT" if login_to_client else "CLIENT to LOGIN"
    lines = [f"{time.time()} {direction} (len {length}):"]
    remaining = length
    print_chars = 64
    for i in range(0, length, 64):
        if remaining > 64:
            remaining -= 64
        else:
            print_chars = remaining
        hex_part = " ".join(f"{x:02x}".upper() for x in buf[i : i + print_chars])
        ascii_part = "".join(chr(x) if 32 <= x < 127 else "." for x in buf[i : i + print_chars])
        lines.append(f"{hex_part}  {ascii_part}")
    logger.debug("\n".join(lines))


class LoginProxy(asyncio.DatagramProtocol):
    transport: asyncio.DatagramTransport
    last_recv_time: float
    in_session: bool
    session: ProxySessionState
    client_addr: tuple[str, int] | None

    def __init__(self):
        super().__init__()
        self.in_session = False
        self.last_recv_time = 0.0
        self.session = ProxySessionState()
        self._auth_in_flight = False
        self._auth_task: asyncio.Task | None = None
        # SSO bad-password retry state. Set in _async_auth_and_forward
        # whenever we successfully rewrite credentials, consumed exactly
        # once on the first server response that follows.
        self._sso_original_login: bytes | None = None
        self._sso_retry_armed: bool = False
        self._sso_retry_fired: bool = False
        self._crc_bytes: int = 0
        self._crc_key: int = 0
        ui.PROXY_STATS.update_status("Initializing")

    def session_free(self):
        self.session.reset()
        self._sso_original_login = None
        self._sso_retry_armed = False
        self._sso_retry_fired = False

    def connection_made(self, transport):
        self.transport = transport
        # Update UI stats with listening information
        local_addr = transport.get_extra_info("sockname")
        if local_addr:
            host, port = local_addr
            ui.PROXY_STATS.update_listening_info(host, port)
            ui.PROXY_STATS.update_status("Listening")
        logger.info("Proxy listening on %s", local_addr)

    # ------------------------------------------------------------------
    # Auth credential rewrite
    # ------------------------------------------------------------------
    def _needs_sso(self, username: str) -> bool:
        """Return True if *username* should go through the SSO API."""
        return (
            not config.PROXY_ONLY
            and username not in config.SKIP_SSO_ACCOUNTS
            and username not in config.LOCAL_ACCOUNT_NAME_MAP
            and username not in config.LOCAL_CHARACTER_NAMES
            and username in config.ALL_CACHED_NAMES
            and bool(config.USER_API_TOKEN)
        )

    def _try_sync_rewrite(
        self,
        buf: bytearray,
        login: LoginPacket,
    ) -> tuple[bytearray, str | None]:
        """Handle non-SSO credential rewrites synchronously.

        Returns ``(result_buf, method)`` where *method* is a non-None
        string if the packet was handled (forwarding should proceed),
        or ``None`` if the caller should attempt SSO auth instead.
        """
        username = login.username.lower()

        if config.PROXY_ONLY:
            ui.PROXY_STATS.user_login(alias=username, account=username, method="proxy_only")
            local_characters.note_login("proxy_only", username)
            return buf, "proxy_only"

        if username in config.SKIP_SSO_ACCOUNTS:
            ui.PROXY_STATS.user_login(alias=username, account=username, method="skip_sso")
            local_characters.note_login("skip_sso", username)
            return buf, "skip_sso"

        if (
            username not in config.ALL_CACHED_NAMES
            and username not in config.LOCAL_ACCOUNT_NAME_MAP
            and username not in config.LOCAL_CHARACTER_NAMES
        ):
            ui.PROXY_STATS.user_login(alias=username, account=username, method="passthrough")
            local_characters.note_login("passthrough", username)
            return buf, "passthrough"

        if username in config.LOCAL_ACCOUNT_NAME_MAP:
            new_user = config.LOCAL_ACCOUNT_NAME_MAP[username]
            new_pass = config.LOCAL_ACCOUNTS[new_user]["password"]
            logger.info("Overwriting client supplied password with local account for %s: %s", username, new_user)
            result_buf = login.rewrite_credentials(new_user, new_pass, config.ENCRYPTION_KEY, config.iv())
            ui.PROXY_STATS.user_login(alias=username, account=new_user, method="local")
            local_characters.note_login("local", new_user)
            return result_buf, "local"

        if username in config.LOCAL_CHARACTER_NAMES:
            character = config.LOCAL_CHARACTERS.get(username) or {}
            new_user = (character.get("account") or "").lower()
            account_data = config.LOCAL_ACCOUNTS.get(new_user) if new_user else None
            if not account_data:
                logger.warning(
                    "Local character %s references unknown account %r; passing through",
                    username,
                    new_user,
                )
                ui.PROXY_STATS.user_login(alias=username, account=username, method="passthrough")
                local_characters.note_login("passthrough", username)
                return buf, "passthrough"
            new_pass = account_data["password"]
            logger.info("Overwriting client supplied password with local character for %s -> %s", username, new_user)
            result_buf = login.rewrite_credentials(new_user, new_pass, config.ENCRYPTION_KEY, config.iv())
            ui.PROXY_STATS.user_login(alias=username, account=new_user, method="local_char")
            local_characters.note_login("local_char", new_user)
            return result_buf, "local_char"

        return buf, None

    async def _async_auth_and_forward(
        self,
        data: bytearray,
        login: LoginPacket,
        recv_time: float,
    ) -> None:
        """Perform SSO auth over WebSocket and forward."""
        username = login.username.lower()
        # Snapshot the original client Login packet so we can replay it if the
        # SSO password is rejected (see _fire_sso_retry).
        original_packet = bytes(data)
        try:
            new_user, encrypted, error_detail = await ws_client.request_login_auth(username)

            if error_detail:
                logger.warning("SSO login rejected for %s: %s", username, error_detail)
                ui.PROXY_STATS.auth_error(username, error_detail)

            if new_user and encrypted:
                logger.info("Auth rewrite successful for %s -> %s", username, new_user)
                data = login.splice_encrypted_credentials(encrypted)
                self._sso_original_login = original_packet
                self._sso_retry_armed = True
                self._sso_retry_fired = False
                logger.debug("SSO retry armed for %s (orig %d bytes)", username, len(original_packet))
                ui.PROXY_STATS.user_login(alias=username, account=new_user, method="sso")
                local_characters.note_login("sso", new_user)
        except Exception:
            logger.exception("Failed to check login for %s", username)
        finally:
            self._auth_in_flight = False
            self.last_recv_time = recv_time
            self.send_to_loginserver(data)

    # ------------------------------------------------------------------
    # SSO bad-password retry  (server -> client interception)
    # ------------------------------------------------------------------
    def _try_intercept_bad_password_combined(
        self,
        data: bytearray,
        start_index: int,
        length: int,
    ) -> bool:
        """Inspect a S->C ``OP_Combined`` for the SSO LoginAccepted response.

        Walks the sub-packets looking for an ``OP_Packet`` carrying a
        ``LoginAccepted``. If we find one:

        * **Good login**: just disarm, return ``False``, let the caller's
          normal Combined dispatch forward everything.
        * **Bad password**: forward the surviving sub-packets (the server's
          ``Ack`` of the client's original Login is critical so the client
          retires its packet) BEFORE firing the retry, then fire the retry,
          and return ``True`` so the caller drops the original datagram.

        Returns ``True`` iff the caller must NOT forward the original
        datagram itself.
        """
        if not self._sso_retry_armed or self._sso_retry_fired:
            return False
        try:
            cp = soe.CombinedPacket.parse(data, start_index, length)
        except (struct.error, ValueError):
            return False

        bad_sub = None
        for sub in cp:
            if sub.transport_op != soe.TransportOp.Packet:
                continue
            classification = self._classify_login_accepted_sub(data, sub.offset, sub.length)
            if classification is None:
                continue
            self._sso_retry_armed = False
            if classification == "good":
                logger.debug("SSO LoginAccepted ok inside Combined; no retry needed")
                return False
            bad_sub = sub
            break

        if bad_sub is None:
            return False

        # Forward the surviving sub-packets first, while cs_offset is still
        # zero. The most important one is the server's Ack of the client's
        # original Login -- if we drop it the client will retransmit and the
        # retry orchestration desynchronizes.
        for sub in cp:
            if sub.offset == bad_sub.offset:
                continue
            self._forward_server_sub(data, sub)

        self._fire_sso_retry(soe.get_sequence(data, bad_sub.offset))
        return True

    def _try_intercept_bad_password_packet(
        self,
        data: bytes,
        start_index: int,
        length: int,
    ) -> bool:
        """Inspect a standalone S->C ``OP_Packet`` for the SSO response.

        On a bad password, fire the retry and tell the caller to suppress.
        On a good login (or any other LoginAccepted-shaped payload), disarm
        and let the caller forward normally.
        """
        if not self._sso_retry_armed or self._sso_retry_fired:
            return False
        classification = self._classify_login_accepted_sub(data, start_index, length)
        if classification is None:
            return False

        self._sso_retry_armed = False
        if classification == "good":
            logger.debug("SSO LoginAccepted ok; no retry needed")
            return False

        self._fire_sso_retry(soe.get_sequence(data, start_index))
        return True

    @staticmethod
    def _classify_login_accepted_sub(
        data: bytes,
        start_index: int,
        length: int,
    ) -> str | None:
        """Return ``"good"``, ``"bad"``, or ``None`` for an OP_Packet sub.

        ``None`` means "not a LoginAccepted" (so we keep waiting). Any
        LoginAccepted (regardless of result) returns either ``"good"`` or
        ``"bad"`` so the caller can disarm.
        """
        if length < 6:  # transport(4) + at least app opcode(2)
            return None
        app_payload = bytes(data[start_index + 4 : start_index + length])
        if len(app_payload) < 2:
            return None
        if lp.get_app_opcode(app_payload) != lp.AppOp.LoginAccepted:
            return None
        return "bad" if lp.is_bad_password_login_result(app_payload) else "good"

    def _forward_server_sub(self, data: bytes, sub) -> None:
        """Forward one sub-packet of a S->C Combined as its own datagram.

        Used when the proxy is surgically removing one sub-packet (the bad
        LoginAccepted) and forwarding the rest. Applies the same rewrites
        that ``recv_combined`` would have applied for a sub of this type.
        """
        sub_buf = bytearray(data[sub.offset : sub.offset + sub.length])
        if sub.transport_op == soe.TransportOp.Ack:
            self.session.adjust_server_ack(sub_buf, 0)
        elif sub.transport_op == soe.TransportOp.Packet:
            self.session.recv_packet(sub_buf, 0)
        # Other transport ops (Fragment etc.) are forwarded raw.
        self.send_to_client(sub_buf)

    def _fire_sso_retry(self, server_seq_to_ack: int) -> None:
        """Replay the original client Login on the existing SOE session.

        Sequencing:
          1. ACK the suppressed bad LoginAccepted directly so the server stops
             retransmitting it.
          2. Advance ``seq_from_server`` past the suppressed packet (without
             advancing ``seq_to_client`` -- the next forwarded server packet
             still slots into the client's expected sequence).
          3. Bump ``cs_offset`` so the replayed Login (and every subsequent
             client OP_Packet) lands at the next server-side sequence.
          4. Send the replayed Login.
        """
        if self._sso_original_login is None:
            logger.error(
                "SSO bad-password detected but no original Login captured "
                "(server seq=%d); cannot retry, forwarding instead",
                server_seq_to_ack,
            )
            self._sso_retry_armed = True  # let it fall through normally
            return

        logger.warning(
            "SSO password rejected by server (seq=%d); retrying with original client credentials",
            server_seq_to_ack,
        )
        self.send_to_loginserver(soe.build_ack(server_seq_to_ack))
        self.session.note_suppressed_server_packet(server_seq_to_ack)
        self.session.note_injected_client_packet()

        retry = bytearray(self._sso_original_login)
        self.session.adjust_combined(retry)
        self._sso_retry_fired = True
        logger.debug(
            "SSO retry fired: cs_offset=%d, seq_from_server=%d, seq_to_client=%d",
            self.session.cs_offset,
            self.session.seq_from_server,
            self.session.seq_to_client,
        )
        self.send_to_loginserver(retry)

    # ------------------------------------------------------------------
    # Client -> Login Server
    # ------------------------------------------------------------------
    @staticmethod
    def _packet_uses_crc(data: bytes | bytearray) -> bool:
        if len(data) < 2:
            return False
        return soe.get_transport_opcode(data) not in (
            soe.TransportOp.SessionRequest,
            soe.TransportOp.SessionResponse,
        )

    def _strip_wire_crc(self, data: bytes | bytearray) -> bytes:
        raw = bytes(data)
        if self._crc_bytes == 0 or not self._packet_uses_crc(raw):
            return raw
        return soe.strip_crc(raw, self._crc_bytes)

    def _append_wire_crc(self, data: bytes | bytearray) -> bytes:
        raw = bytes(data)
        if self._crc_bytes == 0 or not self._packet_uses_crc(raw):
            return raw
        return soe.append_crc(raw, self._crc_key, self._crc_bytes)

    def handle_client_packet(
        self,
        data: bytearray,
        addr: tuple[str, int],
    ):
        """Called on a packet from the client"""
        data = bytearray(self._strip_wire_crc(data))
        recv_time = time.time()
        # debug_write_packet(data, False)

        # logger.debug("Received data from client %s", addr)

        # Store client address for responses
        self.client_addr = addr

        if not self.in_session or (recv_time - self.last_recv_time) > 60:
            logger.debug(
                "Session reset needed: in_session=%s, time_since_last=%.2fs",
                self.in_session,
                recv_time - self.last_recv_time,
            )
            self.session_free()
            if not self.in_session:
                logger.debug("New connection established, updating stats")
                ui.PROXY_STATS.connection_started()

        opcode = soe.get_transport_opcode(data)
        logger.debug("Processing client packet with opcode: %s", soe.transport_name(opcode))

        if opcode == soe.TransportOp.Combined:
            logger.debug("Adjusting combined packet sequence")
            self.session.adjust_combined(data)

            login = LoginPacket.parse(data, config.ENCRYPTION_KEY, config.iv())
            if login and self._needs_sso(login.username.lower()):
                if self._auth_in_flight:
                    self.last_recv_time = recv_time
                    logger.debug("Dropping retry login packet (auth already in flight)")
                    return
                self._auth_in_flight = True
                self._auth_task = asyncio.ensure_future(self._async_auth_and_forward(data, login, recv_time))
                return

            if login:
                result_buf, _method = self._try_sync_rewrite(data, login)
                if result_buf is not data:
                    data = result_buf
                    logger.debug("Authentication data rewritten")
            # Non-login Combined packets fall through

        elif opcode == soe.TransportOp.SessionDisconnect:
            logger.debug("Session disconnect received, cleaning up")
            self.in_session = False
            self.session_free()
            ui.PROXY_STATS.connection_completed()

        elif opcode == soe.TransportOp.Ack:
            logger.debug("Adjusting ACK sequence values")
            self.session.adjust_ack(data)

        elif opcode == soe.TransportOp.Packet:
            # Standalone client OP_Packet (e.g. ServerListRequest sent
            # without a leading ACK). Apply cs_offset if a retry has fired.
            self.session.adjust_client_packet(data)

        elif opcode == soe.TransportOp.KeepAlive:
            logger.debug("Keep-alive packet received")

        self.last_recv_time = recv_time
        logger.debug("Forwarding processed packet to login server")
        self.send_to_loginserver(data)

    # ------------------------------------------------------------------
    # Login Server -> Client
    # ------------------------------------------------------------------
    def handle_server_packet(
        self,
        data: bytes,
        addr: tuple[str, int] | None = None,
        start_index: int = 0,
        length: int | None = None,
    ):
        """Handle packets from the login server"""
        if start_index == 0 and (length is None or length == len(data)):
            data = self._strip_wire_crc(data)
        if length is None:
            length = len(data)
        # debug_write_packet(data, True)
        data = bytearray(data)
        # logger.debug(
        #     "Received message from login server: %s", data)
        opcode = soe.get_transport_opcode(data[start_index:])

        if opcode != soe.TransportOp.Fragment:
            logger.debug("Processing server packet with opcode: %s", soe.transport_name(opcode))

        if opcode == soe.TransportOp.SessionResponse:
            response = soe.parse_session_response(data)
            self._crc_bytes = response["crc_bytes"]
            self._crc_key = response["encode_key"]
            self.in_session = True
            self.session_free()
            logger.debug(
                "Session response received, session established (crc_bytes=%d, crc_key=0x%08X)",
                self._crc_bytes,
                self._crc_key,
            )

        elif opcode == soe.TransportOp.Combined:
            logger.debug("Received combined packet, applying rewrites")
            if self._try_intercept_bad_password_combined(data, start_index, length):
                logger.debug("Suppressed SSO bad-password Combined from server")
                return
            forwarded = self.session.recv_combined(data, start_index, length)
            if forwarded is None:
                return
            data = forwarded

        elif opcode == soe.TransportOp.Packet:
            logger.debug("Processing standard packet")
            if self._try_intercept_bad_password_packet(data, start_index, length):
                logger.debug("Suppressed SSO bad-password Packet from server")
                return
            self.session.recv_packet(data, start_index, length)

        elif opcode == soe.TransportOp.Fragment:
            # logger.debug("Processing fragment packet")
            maybe_server_list = self.session.recv_fragment(data, start_index, length)
            if maybe_server_list is not None:
                # We're finished with the server list, forward it
                data = maybe_server_list
                logger.debug("Server list fragments complete, forwarding to client")
            else:
                # Don't forward, whole point is to filter this
                # logger.debug(
                #     "Fragment part of server list,"
                #     " not forwarding individually")
                return

        elif opcode == soe.TransportOp.Ack:
            if not self.session.cs_offset:
                logger.debug("Skipping ordinary standalone server ACK")
                return
            logger.debug("Forwarding translated post-retry server ACK (cs_offset=%d)", self.session.cs_offset)
            self.session.adjust_server_ack(data, start_index)

        logger.debug("Forwarding processed packet to client")
        self.send_to_client(data)

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------
    def datagram_received(
        self,
        data: bytes,
        addr: tuple[str, int],
    ) -> None:
        """Called when a datagram is received"""
        if addr == config.EQEMU_ADDR:
            # Packet from login server
            self.handle_server_packet(data, addr)
        else:
            # Packet from client
            self.handle_client_packet(bytearray(data), addr)

    def send_to_client(self, data: bytearray | bytes):
        if not data or not self.client_addr:
            logger.debug("Empty data or no client address, not sending to client")
            return
        # logger.debug(
        #     "Sending data to client %s: %s",
        #     self.client_addr, data)
        self.transport.sendto(self._append_wire_crc(data), self.client_addr)

    def send_to_loginserver(self, data: bytearray | bytes):
        if not data:
            logger.debug("Empty data, not sending to loginserver")
            return
        # logger.debug("Sending data to loginserver: %s", data)
        self.transport.sendto(self._append_wire_crc(data), config.EQEMU_ADDR)


async def main():
    # Update UI status
    ui.PROXY_STATS.update_status("Starting")
    logger.info("Starting proxy server")

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        LoginProxy,
        local_addr=(config.LISTEN_HOST, config.LISTEN_PORT),
    )
    logger.info("Started UDP proxy, listening on %s:%s", config.LISTEN_HOST, config.LISTEN_PORT)
    ui.PROXY_STATS.reset_uptime()

    return transport
