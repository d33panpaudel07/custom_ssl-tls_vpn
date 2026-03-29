"""
Bidirectional TCP/TLS traffic relay between VPN clients and internal services.

The ``TunnelRelay`` class is the core data-plane engine of the VPN server.  It
operates entirely within a dedicated daemon thread (started by
``start_relay_threaded``) and is responsible for forwarding raw bytes between:

* The VPN client TLS socket (``session.tls_socket``)
* The plain TCP socket to the internal target service (``internal_socket``)

The relay uses ``select.select`` with a 1-second timeout so that the loop is
interruptible by ``stop()`` without busy-waiting.  Each direction is a simple
``recv`` / ``send`` loop — no message framing is applied to the data layer;
bytes are forwarded verbatim.

Byte accounting (``bytes_client_to_internal``, ``bytes_internal_to_client``)
is updated on every forwarded chunk and reported back to the ``Session``
and the global ``VPNLogger`` at teardown.
"""

import socket
import select
import threading
import logging
from typing import Optional

from custom_ssl_vpn.shared.exceptions import (
    TunnelError,
    ConnectionRefusedError as CustomConnectionRefusedError,
    ForwardingError,
)
from custom_ssl_vpn.server.session import Session, SessionManager
from custom_ssl_vpn.server.logger import get_logger

__all__ = ["TunnelRelay"]


class TunnelRelay:
    """Bidirectional byte relay between a VPN client and an internal TCP target.

    Each instance is owned by a single client session.  Create one, call
    ``connect()`` to open the upstream socket, then call ``start_relay()``
    (or ``start_relay_threaded()``) to begin forwarding.  The relay runs
    until either side closes the connection or ``stop()`` is called.

    Byte-accounting attributes (``bytes_client_to_internal`` and
    ``bytes_internal_to_client``) are updated on every forwarded packet and
    flushed to the session and logger in ``_cleanup``.
    """

    def __init__(
        self,
        session: Session,
        target_host: str,
        target_port: int,
        buffer_size: int,
        session_manager: SessionManager,
    ) -> None:
        """Initialise the relay with session and forwarding target parameters.

        Args:
            session: The authenticated VPN client session.  Must have an active
                ``tls_socket`` before ``start_relay`` is called.
            target_host: Hostname or IPv4/IPv6 address of the internal service
                to proxy towards.
            target_port: TCP port of the internal service.  Must be 1–65535.
            buffer_size: Number of bytes per ``recv`` call on each socket.
                Larger values reduce system-call overhead but increase latency
                for small messages.  Matches ``ServerConfig.BUFFER_SIZE``.
            session_manager: The live ``SessionManager`` used to call
                ``touch_session`` on every packet and ``remove_session`` at
                teardown.
        """
        self.session = session
        self.target_host = target_host
        self.target_port = target_port
        self.buffer_size = buffer_size
        self.session_manager = session_manager

        self.internal_socket: Optional[socket.socket] = None
        self._running = False
        self._logger = get_logger("TunnelRelay")

        # Accounting metrics
        self.bytes_client_to_internal = 0
        self.bytes_internal_to_client = 0

    def connect(self) -> None:
        """Open a plain TCP connection to the internal service target.

        Applies a 5-second connection timeout during the initial handshake,
        then removes the timeout so ``select.select`` can manage blocking in
        the relay loop.  On success, logs a ``TunnelOpen`` event.

        Raises:
            CustomConnectionRefusedError: If the target host actively rejects
                the connection (OS-level ``ConnectionRefusedError``).
            TunnelError: If the connection times out or any other socket error
                occurs (e.g. host unreachable, DNS failure).

        Security note:
            The internal service is accessed over plain TCP (no TLS).  This is
            by design — the TLS tunnel terminates at the VPN server, and the
            connection to the internal service is assumed to be on a trusted
            network segment.
        """
        try:
            self.internal_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Implements the 5 second timeout for connection requirement
            self.internal_socket.settimeout(5.0)
            self.internal_socket.connect((self.target_host, self.target_port))

            # Switch to blocking for select() loop compatibility
            self.internal_socket.settimeout(None)
            self._logger.log_tunnel_open(
                self.session.session_id, self.target_host, self.target_port
            )

        except ConnectionRefusedError as e:
            self._cleanup()
            raise CustomConnectionRefusedError(
                f"Connection refused to {self.target_host}:{self.target_port}",
                context={"error": str(e)},
            )
        except socket.timeout as e:
            self._cleanup()
            raise TunnelError(
                f"Connection timeout towards {self.target_host}:{self.target_port}",
                context={"error": str(e)},
            )
        except Exception as e:
            self._cleanup()
            raise TunnelError(
                f"Failed to connect to internal service target {self.target_host}:{self.target_port}",
                context={"error": str(e)},
            )

    def start_relay(self) -> None:
        """Start the blocking bidirectional forwarding loop.

        Uses ``select.select`` with a 1-second timeout to monitor both
        sockets simultaneously without busy-waiting.  Forwarding stops when:

        * Either side sends an empty read (graceful EOF).
        * ``select`` reports an exceptional condition.
        * ``self._running`` is set to ``False`` externally via ``stop()``.
        * An unhandled exception occurs (re-raised as ``ForwardingError``).

        ``_cleanup`` is called in a ``finally`` block regardless of exit reason.

        Raises:
            TunnelError: If either socket is ``None`` when the method is called.
            ForwardingError: If a read or write error interrupts active forwarding.

        Security note:
            This method may run in a dedicated thread.  Do not call it on the
            server's main thread, as it blocks indefinitely until the relay ends.
        """
        client_socket = self.session.tls_socket
        if not client_socket or not self.internal_socket:
            raise TunnelError(
                "Both sockets must be established prior to initiating relay loop."
            )

        self._running = True
        sockets = [client_socket, self.internal_socket]

        try:
            while self._running:
                # 1.0 second timeout prevents permanent blocking and allows checking self._running
                readable, _, exceptional = select.select(sockets, [], sockets, 1.0)

                if exceptional:
                    self._logger.log_security_event(
                        "RELAY_SOCKET_EXCEPTION",
                        {"session_id": self.session.session_id},
                    )
                    break

                for s in readable:
                    if s is client_socket:
                        # Client sending to Internal target
                        data = s.recv(self.buffer_size)
                        if not data:
                            self._running = False
                            break
                        self._send_all(self.internal_socket, data)
                        self.bytes_client_to_internal += len(data)
                        self.session_manager.touch_session(self.session.session_id)

                    elif s is self.internal_socket:
                        # Internal sending back to Client
                        data = s.recv(self.buffer_size)
                        if not data:
                            self._running = False
                            break
                        self._send_all(client_socket, data)
                        self.bytes_internal_to_client += len(data)
                        self.session_manager.touch_session(self.session.session_id)

        except Exception as e:
            self._logger.log_security_event("RELAY_ERROR", {"error": str(e)})
            raise ForwardingError(
                "Exception interrupted active bidirectional relay.",
                context={"error": str(e)},
            )
        finally:
            self._cleanup()

    def _send_all(self, sock: socket.socket, data: bytes) -> None:
        """Send *data* in its entirety to *sock*, retrying on partial writes.

        Uses a while loop over ``sock.send`` so that if the OS returns fewer
        bytes than requested (which is possible on non-blocking sockets),
        the remainder is re-sent automatically.

        Args:
            sock: Destination socket.  May be a plain TCP socket or an
                ``ssl.SSLSocket``.
            data: Complete byte buffer to transmit.

        Raises:
            ForwardingError: If ``sock.send`` returns 0, indicating the
                underlying connection has been severed.
        """
        total_sent = 0
        while total_sent < len(data):
            sent = sock.send(data[total_sent:])
            if sent == 0:
                raise ForwardingError(
                    "Underlying network connection severed during active send."
                )
            total_sent += sent

    def stop(self) -> None:
        """Signal the relay loop to exit on its next ``select`` timeout cycle.

        Sets ``_running = False``.  The loop checks this flag on each
        iteration, so it will stop within at most 1 second (the select timeout).
        Does not forcibly close sockets; ``_cleanup`` handles that.
        """
        self._running = False

    def start_relay_threaded(self) -> threading.Thread:
        """Run ``start_relay`` in a dedicated daemon thread and return it.

        The thread is named ``TunnelRelay-<session_id>`` for debuggability.
        Because the thread is daemonised, it will not block server shutdown.

        Returns:
            The started ``threading.Thread`` instance.  The caller may join
            it if blocking teardown is desired; otherwise it runs until the
            relay closes naturally.

        Example:
            >>> relay = TunnelRelay(session, host, port, 4096, session_manager)
            >>> relay.connect()
            >>> thread = relay.start_relay_threaded()
            >>> # thread is running concurrently; call relay.stop() to terminate it
        """
        thread = threading.Thread(
            target=self.start_relay,
            daemon=True,
            name=f"TunnelRelay-{self.session.session_id}",
        )
        thread.start()
        return thread

    def _cleanup(self) -> None:
        """Release all resources held by this relay instance.

        Performs the following steps in order:

        1. Logs final byte-accounting metrics at INFO.
        2. Shuts down and closes the internal TCP socket.
        3. Shuts down and closes the client TLS socket.
        4. Logs ``TunnelClose`` via the structured logger.
        5. Flushes per-session byte totals back to ``session.bytes_up/down``.
        6. Reports aggregate bytes to the global ``VPNLogger.log_traffic``.
        7. Removes the session from ``SessionManager``.

        Called from the ``finally`` block of ``start_relay`` so it runs even
        if an exception interrupts the relay loop.
        """
        self._logger._log(
            logging.INFO,
            "Relay Metrics Tracked",
            {
                "session_id": self.session.session_id,
                "bytes_client_to_internal": self.bytes_client_to_internal,
                "bytes_internal_to_client": self.bytes_internal_to_client,
            },
        )

        if self.internal_socket:
            try:
                self.internal_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.internal_socket.close()
            except Exception:
                pass
            self.internal_socket = None

        if self.session.tls_socket:
            try:
                self.session.tls_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.session.tls_socket.close()
            except Exception as e:
                # Log the error but don't re-raise, as cleanup should not mask original exceptions
                self._logger.log_security_event(
                    "TLS_SOCKET_CLOSE_ERROR",
                    {"session_id": self.session.session_id, "error": str(e)},
                )
            self.session.tls_socket = None

        self._logger.log_tunnel_close(self.session.session_id)

        # Post traffic stats directly back to the session limits and global telemetry store
        self.session.bytes_up += self.bytes_client_to_internal
        self.session.bytes_down += self.bytes_internal_to_client

        # Use the already-imported module-level get_logger (no re-import needed)
        get_logger().log_traffic(self.bytes_client_to_internal, self.bytes_internal_to_client)

        # Free associated tracker resources fully on the SessionManager
        self.session_manager.remove_session(self.session.session_id)
