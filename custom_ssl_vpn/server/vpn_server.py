"""
Main entry point for the VPN server daemon.

Orchestrates all server-side components: TLS context configuration,
client acceptance, authentication, session registration, and tunnel
establishment.  The ``VPNServer`` class wires together:

* ``AuthManager`` — credential validation
* ``SessionManager`` — session lifecycle tracking
* ``TunnelRelay`` — bidirectional TCP/TLS forwarding
* ``SecurityPolicy`` — IP-level blocking before TLS
* ``MonitoringDashboard`` — SOC telemetry HTTP endpoint

The ``main()`` function is the CLI entry point registered in
``pyproject.toml`` as ``vpn-server``.
"""

import sys
import os
import argparse
import logging
import signal
import socket
import ssl
import threading
import json
from typing import Any, Optional, Tuple

from custom_ssl_vpn.shared.protocol import (
    Commands, 
    VPNMessage, 
    encode_message, 
    decode_message
)
from custom_ssl_vpn.shared.exceptions import (
    AuthenticationError,
    ProtocolError,
    TunnelError
)
from custom_ssl_vpn.server.config import ServerConfig, load_config
from custom_ssl_vpn.server.logger import setup_logger, get_logger
from custom_ssl_vpn.server.auth import AuthManager
from custom_ssl_vpn.server.session import SessionManager
from custom_ssl_vpn.server.tunnel import TunnelRelay
from custom_ssl_vpn.server.security import SecurityPolicy
from custom_ssl_vpn.server.monitor import MonitoringDashboard

__all__ = [
    "VPNServer",
    "main"
]


class VPNServer:
    """Orchestrator that accepts TLS connections and drives the auth–connect–relay lifecycle.

    One ``VPNServer`` instance is created per process.  Call ``start()`` to
    begin accepting clients; call ``stop()`` (typically from a signal handler)
    to initiate graceful shutdown.

    Each accepted connection is handled in its own daemon thread so one slow
    or misbehaving client cannot block others.  Thread references are tracked
    in ``_client_threads`` and joined with a 1-second timeout on shutdown.
    """

    def __init__(self, config: ServerConfig) -> None:
        """Initialise all subsystems and internal state.

        Args:
            config: Validated server configuration.  All runtime limits
                (max clients, timeouts, TLS settings) are sourced from here.
        """
        self.config = config
        self._logger = get_logger("VPNServer")
        
        self.auth_manager = AuthManager(max_attempts=config.MAX_LOGIN_ATTEMPTS)
        self.session_manager = SessionManager(
            max_clients=config.MAX_CLIENTS,
            session_timeout_seconds=config.SESSION_TIMEOUT_SECONDS
        )
        self.security_policy = SecurityPolicy()
        self.monitor = MonitoringDashboard(
            session_manager=self.session_manager,
            max_clients=config.MAX_CLIENTS,
            http_port=9999
        )
        
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._threads_lock = threading.Lock()
        self._client_threads: list[threading.Thread] = []

    def setup_tls_context(self) -> ssl.SSLContext:
        """Build a hardened TLS server context from the current configuration.

        Enforces TLS 1.2 as the minimum protocol version and applies the
        following OP flags:

        * ``OP_NO_SSLv2``, ``OP_NO_SSLv3`` — disable legacy SSL.
        * ``OP_NO_TLSv1``, ``OP_NO_TLSv1_1`` — disable TLS 1.0 / 1.1.
        * ``OP_SINGLE_DH_USE``, ``OP_SINGLE_ECDH_USE`` (when available) —
          enforce Perfect Forward Secrecy by generating a new ephemeral key
          per handshake.

        The cipher list from ``ServerConfig.ALLOWED_CIPHERS`` is applied to
        further restrict negotiable suites.

        Returns:
            A fully configured ``ssl.SSLContext`` ready to wrap incoming
            raw sockets.

        Raises:
            ssl.SSLError: If the certificate or key files cannot be loaded
                (wrong path, key mismatch, or unsupported format).

        Security note:
            Regenerate the server certificate and key before deploying to
            production.  The test certs in ``server/certs/`` are self-signed
            and not trusted by any CA.
        """
        # Minimum TLSv1.2 explicitly mapped to Python 3's high-security defaults
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = getattr(ssl.TLSVersion, self.config.TLS_VERSION, ssl.TLSVersion.TLSv1_2)

        # Aggressive legacy renegotiation/downgrade flags mitigation
        flags = (
            ssl.OP_NO_SSLv2 | 
            ssl.OP_NO_SSLv3 | 
            ssl.OP_NO_TLSv1 | 
            ssl.OP_NO_TLSv1_1
        )
        # Enforce Perfect Forward Secrecy (PFS) by instructing the TLS layer to
        # generate a new DH/ECDH key geometry for EACH connection handshake rather 
        # than reusing parameters, mitigating retrospective decryption if the long-term
        # server private key is ever mathematically compromised in the future.
        if hasattr(ssl, 'OP_SINGLE_DH_USE'):
            flags |= ssl.OP_SINGLE_DH_USE
        if hasattr(ssl, 'OP_SINGLE_ECDH_USE'):
            flags |= ssl.OP_SINGLE_ECDH_USE
            
        # Avoid overriding other defaults set by OpenSSL underneath
        context.options |= flags
        
        context.set_ciphers(self.config.ALLOWED_CIPHERS)
        
        # We fail loudly here during application boot if certs are missing
        context.load_cert_chain(
            certfile=self.config.CERT_PATH, 
            keyfile=self.config.KEY_PATH
        )
        
        return context

    def start(self) -> None:
        """Bind the TCP listener, start the monitoring dashboard, and block in the accept loop.

        This method does not return until ``stop()`` is called from another
        thread or signal handler.  The backing socket uses ``SO_REUSEADDR``
        to avoid the OS ``TIME_WAIT`` delay on quick restarts.

        Raises:
            OSError: If the bind fails (port already in use, permission denied).
            ssl.SSLError: If ``setup_tls_context`` fails to load certificates.
        """
        self._running = True
        context = self.setup_tls_context()
        
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Allow immediate restart on the same port without OS TIME_WAIT
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.config.HOST, self.config.PORT))
        self._server_socket.listen(self.config.MAX_CLIENTS)
        
        self.monitor.start()
        
        self._logger._log(logging.INFO, "Server started listening.", {
            "host": self.config.HOST,
            "port": self.config.PORT,
            "tls": self.config.TLS_VERSION
        })

        try:
            self._accept_loop(context)
        except OSError as e:
            if self._running:
                self._logger.log_security_event("SERVER_SOCKET_CRASH", {"error": str(e)})

    def _accept_loop(self, context: ssl.SSLContext) -> None:
        """Run the main accept loop, dispatching each connection to a worker thread.

        Uses a 1-second socket timeout so the loop can check ``self._running``
        periodically and exit cleanly when ``stop()`` is called.  Each
        accepted socket is checked against ``SecurityPolicy.is_blocked`` before
        a thread is spawned, so blocked IPs are rejected with zero TLS overhead.

        Dead threads are pruned from ``_client_threads`` on each iteration to
        prevent unbounded memory growth for long-running servers.

        Args:
            context: The TLS context used to wrap each accepted raw socket.
        """
        while self._running and self._server_socket:
            try:
                # 1.0 second timeout prevents permanent OS socket blocking
                # which lets python handle signals cleanly on Windows/Linux targets.
                self._server_socket.settimeout(1.0)
                try:
                    raw_socket, addr = self._server_socket.accept()
                except socket.timeout:
                    continue
                    
                client_ip, client_port = addr
                
                if self.security_policy.is_blocked(client_ip):
                    self._logger.log_security_event("BLOCKED_IP_REJECTED", {"ip": client_ip})
                    try:
                        raw_socket.close()
                    except OSError:
                        pass
                    continue
                    
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(raw_socket, addr, context),
                    daemon=True
                )
                
                with self._threads_lock:
                    # Clean up old dead threads from tracking 
                    self._client_threads = [t for t in self._client_threads if t.is_alive()]
                    self._client_threads.append(client_thread)
                    
                client_thread.start()
                
            except ssl.SSLError as e:
                self._logger.log_security_event("TLS_HANDSHAKE_FAIL", {"error": str(e)})
            except Exception as e:
                self._logger.log_security_event("ACCEPT_LOOP_ERROR", {"error": str(e)})

    def _handle_client(
        self, raw_socket: socket.socket, addr: Tuple[str, int], context: ssl.SSLContext
    ) -> None:
        """Manage the full lifecycle of a single VPN client connection.

        Runs in a dedicated daemon thread.  Performs these steps in order:

        1. Wrap *raw_socket* in TLS using *context*.
        2. Set ``AUTH_TIMEOUT_SECONDS`` socket timeout.
        3. Create pre-auth session in ``SessionManager``.
        4. Receive and decode the AUTH message; validate with ``AuthManager``.
        5. Send OK to the client.
        6. Receive and decode the CONNECT message; extract target host/port.
        7. Create ``TunnelRelay``, call ``connect()`` then ``start_relay()``.
        8. Remove timeout (set to ``None`` for blocking relay).

        On any exception the method logs the error, optionally sends an ERROR
        message to the peer, and cleans up the session.

        Args:
            raw_socket: Accepted plain TCP socket from ``accept()``.
            addr: ``(host, port)`` tuple returned by ``accept()``.
            context: TLS server context for ``wrap_socket``.

        Security note:
            ``AuthenticationError`` is caught and logged with the event type
            ``"AUTH_FAILURE"`` — the peer only receives a generic error string
            that does not reveal whether the username or password was wrong.
        """
        client_ip, client_port = addr
        self._logger.log_connection(client_ip, client_port)
        
        session = None
        tls_socket = None
        
        try:
            # Step 1: Wrap raw connection in TLS
            tls_socket = context.wrap_socket(raw_socket, server_side=True)
            
            # Step 2: Establish connection and authentication deadline
            tls_socket.settimeout(self.config.AUTH_TIMEOUT_SECONDS)
            
            # Create pre-auth tracking session 
            session = self.session_manager.create_session(client_ip, client_port, tls_socket)
            
            # Step 3: Parse mandatory initial command 
            buffer = tls_socket.recv(self.config.BUFFER_SIZE)
            
            try:
                msg = decode_message(buffer)
            except ProtocolError as e:
                raise AuthenticationError(f"Protocol breakdown during handshake: {e}")
                
            if msg.command != Commands.AUTH:
                raise AuthenticationError(f"Expected AUTH as first message, got {msg.command}.")
                
            # Expect JSON structured payload inside the auth packet bytes
            # Hardened decoding with 'replace' to prevent UnicodeDecodeError thread crashes
            try:
                auth_payload = json.loads(msg.payload.decode('utf-8', errors='replace'))
            except json.JSONDecodeError:
                raise AuthenticationError("Malformed JSON authentication payload.")
                
            username = auth_payload.get("username", "")
            password = auth_payload.get("password", "")
            
            # Trigger AuthManager with built-in brute force protections
            self.auth_manager.authenticate(username, password, client_ip)
            self.session_manager.authenticate_session(session.session_id, username)
            self._logger.log_auth_success(username, session.session_id)
            
            # Acknowledge authentication to the peer
            tls_socket.sendall(encode_message(VPNMessage(
                command=Commands.OK,
                payload=b"Authenticated.",
                session_id=session.session_id
            )))
            
            # Step 5: Await remote destination CONNECT directive
            buffer = tls_socket.recv(self.config.BUFFER_SIZE)
            connect_msg = decode_message(buffer)
            if connect_msg.command != Commands.CONNECT:
                raise ProtocolError(f"Expected CONNECT following auth, got {connect_msg.command}.")
            
            # Hardened decoding with 'replace' to prevent UnicodeDecodeError thread crashes
            try:
                target_data = json.loads(connect_msg.payload.decode('utf-8', errors='replace'))
            except json.JSONDecodeError:
                raise ProtocolError("Malformed JSON CONNECT payload.")
                
            target_host = target_data.get("host")
            target_port = target_data.get("port")
            
            if not target_host or not isinstance(target_port, int):
                raise ProtocolError("CONNECT payload missing 'host' or valid 'port'.")

            # Step 6: Offload the connection to the TunneyRelay
            relay = TunnelRelay(
                session=session,
                target_host=target_host,
                target_port=target_port,
                buffer_size=self.config.BUFFER_SIZE,
                session_manager=self.session_manager
            )
            
            relay.connect()
            
            # Acknowledge successfully opened upstream connection to peer
            tls_socket.sendall(encode_message(VPNMessage(
                command=Commands.OK,
                payload=b"Tunnel ready.",
                session_id=session.session_id
            )))
            
            # Step 7: Re-enter indefinite blocking mode to yield to the relay read/write loops
            tls_socket.settimeout(None)
            
            # Relinquishes control flow inside THIS thread to the blocking relay logic securely
            relay.start_relay()

        except ssl.SSLError as e:
            # Trap TLS exceptions uniquely since they represent cryptographic failures
            # before any application-layer packets could be exchanged.
            self._logger.log_security_event("TLS_HANDSHAKE_FAILED_OR_ABORTED", {"error": str(e), "ip": client_ip})
            # No need to send an application-layer error packet since TLS didn't establish
        except AuthenticationError as e:
            self._logger.log_auth_failure("UNKNOWN", str(e), 1, client_ip)
            self._send_error_and_close(tls_socket, str(e))
        except ProtocolError as e:
            self._logger.log_security_event("PROTOCOL_ERROR", {"error": str(e), "ip": client_ip})
            self._send_error_and_close(tls_socket, f"Protocol Violation: {e}")
        except socket.timeout:
            self._logger.log_security_event("AUTH_TIMEOUT", {"ip": client_ip})
            self._send_error_and_close(tls_socket, "Authentication window timed out.")
        except json.JSONDecodeError:
            self._logger.log_security_event("MALFORMED_JSON_PAYLOAD", {"ip": client_ip})
            self._send_error_and_close(tls_socket, "Invalid JSON payload.")
        except OSError as e:
            # We silently swallow OS connection resets as they are a normal networking event
            pass
        except Exception as e:
            self._logger.log_security_event("UNHANDLED_CLIENT_EXCEPTION", {"error": str(e), "ip": client_ip})
        finally:
            if session and self.session_manager.get_session(session.session_id):
                self.session_manager.remove_session(session.session_id)
            elif tls_socket:
                try:
                    tls_socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    tls_socket.close()
                except Exception:
                    pass

    def _send_error_and_close(self, tls_socket: Optional[ssl.SSLSocket], reason: str) -> None:
        """Send an ERROR protocol message to the peer and close the socket.

        Sets a 2-second timeout to avoid blocking indefinitely on a broken
        connection.  Silently swallows any exception during the send so that
        cleanup in the caller is not interrupted.

        Args:
            tls_socket: Live (or potentially broken) TLS socket.  If ``None``,
                the call is a no-op.
            reason: Human-readable error description placed in the ERROR
                message payload.  Must not contain sensitive data.
        """
        if tls_socket:
            try:
                # Do not block failing sockets forever
                tls_socket.settimeout(2.0)
                msg_bytes = encode_message(VPNMessage(
                    command=Commands.ERROR,
                    payload=reason.encode('utf-8')
                ))
                tls_socket.sendall(msg_bytes)
            except Exception:
                pass


    def stop(self) -> None:
        """Initiate graceful shutdown: stop accepting, close sessions, join threads.

        Sets ``_running = False``, shuts down the server socket, stops the
        monitoring dashboard, calls ``SessionManager.shutdown()`` (which closes
        all active TLS sockets), and joins client threads with a 1-second
        timeout each.
        """
        self._logger._log(logging.INFO, "Server shutdown initiated.", {})
        self._running = False
        self.monitor.stop()
        
        if self._server_socket:
            try:
                self._server_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None

        self.session_manager.shutdown()
        self.security_policy.shutdown()
        
        # We don't block indefinitely waiting for threads in case they lock, 
        # python main teardown will garbage collect daemon threads anyway 
        # but we give them a short window to respect the running bool internally.
        with self._threads_lock:
            for thread in self._client_threads:
                if thread.is_alive():
                    thread.join(timeout=1.0)


def main() -> None:
    """CLI entry point for the VPN server daemon.

    Parses command-line arguments, loads and optionally overrides the
    ``ServerConfig``, initialises the structured logger, registers
    ``SIGINT``/``SIGTERM`` handlers to call ``server.stop()``, and
    invokes ``server.start()``.

    Command-line flags:
        ``--config``/``-c``: Path to JSON config file (default: ``server/config.json``).
        ``--host``: Override the bind host IP.
        ``--port``: Override the listen port.

    Raises:
        SystemExit(1): On config load failure or fatal server crash.
    """
    parser = argparse.ArgumentParser(description="Custom Application-Layer SSL/TLS VPN Server")
    parser.add_argument("--config", "-c", type=str, help="Path to JSON configuration file", default="server/config.json")
    parser.add_argument("--host", type=str, help="Override bind host IP mapping")
    parser.add_argument("--port", type=int, help="Override listener bind port")
    
    args = parser.parse_args()
    
    try:
        config = load_config(args.config)
        
        # Enable flexible CLI overloading
        if getattr(args, 'host', None):
            config = ServerConfig(**{**config.__dict__, "HOST": args.host})
        if getattr(args, 'port', None):
            config = ServerConfig(**{**config.__dict__, "PORT": args.port})
            
    except Exception as e:
        sys.stderr.write(f"FATAL: Failed to load configuration: {e}\n")
        sys.exit(1)
        
    import logging
    setup_logger(
        log_level=config.LOG_LEVEL, 
        log_file=config.LOG_PATH, 
        log_to_stderr=True
    )
    logger = get_logger("main")
    
    server = VPNServer(config)
    
    def signal_handler(sig: int, frame: Any) -> None:
        logger._log(logging.WARNING, f"Received signal {sig}, terminating.", {})
        server.stop()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        server.start()
    except Exception as e:
        logger._log(logging.CRITICAL, f"Fatal error causing server crash: {e}", {})
        server.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
