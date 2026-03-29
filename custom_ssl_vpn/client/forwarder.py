"""
Local port-to-VPN-tunnel traffic forwarding logic for the VPN client.

The ``LocalForwarder`` class listens on a local TCP port (e.g.
``127.0.0.1:9000``) and accepts exactly **one** downstream connection from a
local application (browser, ``curl``, database client, etc.).  Once a
connection arrives, it bridges traffic bidirectionally between:

* The local application socket
* The already-established TLS VPN socket provided by ``VPNClient``

The relay uses the same ``select.select`` / 1-second-timeout pattern as
``server/tunnel.py`` to stay responsive to ``stop()`` without busy-waiting.

Only one downstream application connection is supported per tunnel session.
To proxy a second application, create a new VPN session.
"""

import socket
import select
import logging
import ssl
from typing import Optional

from custom_ssl_vpn.shared.exceptions import ForwardingError
from custom_ssl_vpn.shared.protocol import (
    Commands,
    VPNMessage,
    encode_message
)

__all__ = [
    "LocalForwarder"
]


class LocalForwarder:
    """Bridges a single local application connection to the VPN tunnel socket.

    Lifecycle:

    1. ``start(vpn_socket)`` — binds the local port and blocks until one
       downstream client connects.
    2. After the downstream connection is accepted, the listening socket is
       immediately closed (only one client is supported).
    3. The ``_run_relay`` loop forwards bytes in both directions until either
       side closes.
    4. ``_cleanup`` closes the local socket.  The VPN socket is left open
       for ``VPNClient`` to manage.
    """

    def __init__(self, listen_host: str, listen_port: int, buffer_size: int) -> None:
        """Initialise the forwarder with connection and buffer parameters.

        Args:
            listen_host: Interface to bind the local proxy port on.
                Should be ``"127.0.0.1"`` to restrict to the loopback
                interface and prevent external access to the proxy.
            listen_port: Port number on *listen_host* for applications to
                connect to.  Must be 1–65535.
            buffer_size: Number of bytes per ``recv`` call.  Matches
                ``ClientConfig.BUFFER_SIZE``.
        """
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.buffer_size = buffer_size
        
        self._server_socket: Optional[socket.socket] = None
        self._local_socket: Optional[socket.socket] = None
        self._vpn_socket: Optional[ssl.SSLSocket] = None
        self._running = False
        self._logger = logging.getLogger("LocalForwarder")

    def start(self, vpn_socket: ssl.SSLSocket) -> None:
        """Bind to the local port, accept one connection, and begin relaying.

        Blocks until the downstream application connects, then enters the
        relay loop and blocks again until the relay ends.  Both the bind
        and relay phases complete before this method returns.

        Args:
            vpn_socket: The live TLS socket connected to the VPN server,
                as returned by ``VPNClient.connect_to_server``.  Its
                lifecycle is managed by ``VPNClient``; ``LocalForwarder``
                reads from and writes to it but does not close it.

        Raises:
            ForwardingError: If the local socket cannot bind, or if the
                relay loop is interrupted by an unexpected exception.
        """
        self._vpn_socket = vpn_socket
        self._running = True

        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Ensure the socket easily unbinds avoiding OS TIME_WAIT locks across client runs
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self.listen_host, self.listen_port))
            self._server_socket.listen(1)
            
            self._logger.info(f"Local proxy binding active on {self.listen_host}:{self.listen_port}")
            print(f"VPN tunnel ready. Configure application proxy: {self.listen_host}:{self.listen_port} (Waiting for connection...)")
            
            # Block waiting for precisely 1 local application to connect to our exposed proxy port
            self._local_socket, addr = self._server_socket.accept()
            self._logger.info(f"Local application connected from {addr}. Commencing application data relay.")
            print(f"Application connected. Forwarding traffic securely.")

            # Turn off server block since we only accept 1 connection per tunnel
            self._server_socket.close()
            self._server_socket = None
            
            self._run_relay(self._local_socket, self._vpn_socket)

        except OSError as e:
            raise ForwardingError("Failed to bind local listener or accept connection.", context={"error": str(e)})
        except Exception as e:
            raise ForwardingError("Unexpected relay crash.", context={"error": str(e)})
        finally:
            self._cleanup()

    def _run_relay(self, local_sock: socket.socket, vpn_sock: ssl.SSLSocket) -> None:
        """Execute the bidirectional byte relay until either socket closes.

        Uses ``select.select`` with a 1-second timeout so the loop is
        interruptible when ``stop()`` sets ``_running = False``.

        Args:
            local_sock: The downstream application socket.
            vpn_sock: The upstream VPN tunnel TLS socket.

        Raises:
            ForwardingError: If an unexpected exception interrupts the relay.
        """
        sockets = [local_sock, vpn_sock]
        bytes_up = 0
        bytes_down = 0
        
        try:
            while self._running:
                readable, _, exceptional = select.select(sockets, [], sockets, 1.0)
                
                if exceptional:
                    self._logger.error("Relay socket exception encountered.")
                    break
                    
                for s in readable:
                    if s is local_sock:
                        # Upload direction: Local App -> TLS Tunnel
                        data = s.recv(self.buffer_size)
                        if not data:
                            self._logger.info("Local app closed connection (upload path empty).")
                            self._running = False
                            break
                        self._send_all(vpn_sock, data)
                        bytes_up += len(data)
                        
                    elif s is vpn_sock:
                        # Download direction: TLS Tunnel -> Local App
                        data = s.recv(self.buffer_size)
                        if not data:
                            self._logger.info("VPN server closed tunnel connection (download path empty).")
                            self._running = False
                            break
                        self._send_all(local_sock, data)
                        bytes_down += len(data)

        except Exception as e:
            raise ForwardingError("Bidirectional pipe broken.", context={"error": str(e)})
        finally:
            self._logger.info(f"Relay closed. Sent {bytes_up} bytes upstream, received {bytes_down} bytes downstream.")
            print(f"\nConnection closed safely. Bytes Uploaded: {bytes_up} | Downloaded: {bytes_down}")

    def _send_all(self, sock: socket.socket, data: bytes) -> None:
        """Send the full *data* buffer to *sock*, looping on partial writes.

        Args:
            sock: Destination socket (plain or TLS).
            data: Complete byte payload to transmit.

        Raises:
            ForwardingError: If ``sock.send`` returns 0 bytes, indicating the
                peer has closed the connection.
        """
        total_sent = 0
        while total_sent < len(data):
            sent = sock.send(data[total_sent:])
            if sent == 0:
                raise ForwardingError("Network connection severed during active send.")
            total_sent += sent

    def stop(self) -> None:
        """Signal the relay loop to exit within one ``select`` timeout cycle.

        Thread-safe: may be called from a signal handler or a separate thread.
        Does not forcibly close sockets; ``_cleanup`` handles that in the
        ``finally`` block of ``start``.
        """
        self._running = False

    def _cleanup(self) -> None:
        """Release the local application socket and the listener socket.

        The VPN socket lifecycle belongs to ``VPNClient`` — it is not touched
        here.  Called automatically from the ``finally`` block of ``start``.
        """
        self._running = False
        
        # We clean the active client
        if self._local_socket:
            try:
                self._local_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._local_socket.close()
            except OSError:
                pass
            self._local_socket = None
            
        # We clean the proxy listener
        if self._server_socket:
            try:
                self._server_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._server_socket.close()
            except OSError:
                pass
            self._server_socket = None
