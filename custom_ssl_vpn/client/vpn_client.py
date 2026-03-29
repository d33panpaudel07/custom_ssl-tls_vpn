"""
Main entry point for the VPN client application.

Responsible for bootstrapping configuration, establishing the SSL/TLS
client connection to the server, and wiring up the local forwarder components.
Does not contain actual traffic handling business logic.
"""

import sys
import os
import argparse
import signal
import socket
import ssl
import getpass
import json
import logging
from typing import Optional

from custom_ssl_vpn.shared.protocol import (
    Commands,
    VPNMessage, 
    encode_message, 
    decode_message
)
from custom_ssl_vpn.shared.exceptions import (
    AuthenticationError,
    ProtocolError,
    TunnelError,
    ForwardingError
)
from custom_ssl_vpn.client.config import ClientConfig, load_config
from custom_ssl_vpn.client.forwarder import LocalForwarder

__all__ = [
    "VPNClient",
    "main"
]

class VPNClient:
    """
    Central orchestrator establishing the TLS connection and triggering forwarding.
    """

    def __init__(self, config: ClientConfig) -> None:
        """
        Initializes the client application and states.
        
        Args:
            config (ClientConfig): Network properties and binding port intents.
        """
        self.config = config
        self._tls_socket: Optional[ssl.SSLSocket] = None
        self._forwarder: Optional[LocalForwarder] = None
        self._running = False

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        self._logger = logging.getLogger("VPNClient")

    def connect_to_server(self) -> ssl.SSLSocket:
        """
        Establishes the secured and verified TLS pipeline to the upstream server.
        
        Returns:
            ssl.SSLSocket: The raw network socket wrapped securely.
            
        Raises:
            TunnelError: If TLS negotiation fails or server is unreachable.
        """
        try:
            # Build restrictive default TLS context for outbound connections.
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            # Enforce that the server certificate passes CA matching.
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Explicitly load the self-signed CA root
            context.load_verify_locations(cafile=self.config.CA_CERT_PATH)

            self._logger.info(f"Connecting to VPN server {self.config.SERVER_HOST}:{self.config.SERVER_PORT}...")
            
            raw_socket = socket.create_connection(
                (self.config.SERVER_HOST, self.config.SERVER_PORT), 
                timeout=self.config.CONNECT_TIMEOUT_SECONDS
            )
            
            # Applies hostname verification mapped against the SAN inside CA cert wrapper.
            tls_sock = context.wrap_socket(raw_socket, server_hostname=self.config.SERVER_HOST)
            
            self._logger.info("TLS handshaked and connected successfully.")
            return tls_sock
            
        except ssl.SSLError as e:
            raise TunnelError(f"TLS security verification failed: {e}")
        except socket.error as e:
            raise TunnelError(f"Network TCP connection failed: {e}")
        except Exception as e:
            raise TunnelError(f"Unexpected connection error: {e}")

    def authenticate(self, tls_sock: ssl.SSLSocket, username: str, password: str) -> str:
        """
        Initiates the application-layer authentication step inside the connected tunnel.
        
        Args:
            tls_sock (ssl.SSLSocket): Live connection.
            username (str): Target credential identifier.
            password (str): Secret.
            
        Returns:
            str: Assigned session ID token from the server.
            
        Raises:
            AuthenticationError: If the server rejects the credentials.
            ProtocolError: If structural expectations for message return fail.
        """
        payload = json.dumps({
            "username": username,
            "password": password
        }).encode('utf-8')
        
        auth_msg = VPNMessage(command=Commands.AUTH, payload=payload)
        tls_sock.sendall(encode_message(auth_msg))

        buffer = tls_sock.recv(self.config.BUFFER_SIZE)
        if not buffer:
            raise AuthenticationError("Server closed connection prematurely during auth.")

        response = decode_message(buffer)

        if response.command == Commands.ERROR:
            server_reason = response.payload.decode('utf-8', errors='ignore')
            raise AuthenticationError(f"Authentication rejected: {server_reason}")
            
        if response.command != Commands.OK or not response.session_id:
            raise ProtocolError(f"Expected OK response with session_id, got {response.command}")

        self._logger.info("Authentication granted.")
        return response.session_id

    def run(self, target_host: str, target_port: int, override_username: Optional[str] = None, override_password: Optional[str] = None) -> None:
        """
        Runs the full client lifecycle: prompts password -> connects -> auths -> proxies.
        
        Args:
            target_host (str): Desired internal server destination IP.
            target_port (int): Desired internal server port logic.
            override_username (Optional[str]): Prevent runtime prompting for the username.
            override_password (Optional[str]): Prevent runtime prompting for the password.
        """
        self._running = True
        
        username = override_username
        if not username:
            try:
                username = input("VPN Username: ").strip()
            except EOFError:
                return

        if override_password:
            password = override_password
        else:
            try:
                password = getpass.getpass("VPN Password: ")
            except EOFError:
                return

        try:
            self._tls_socket = self.connect_to_server()
            session_id = self.authenticate(self._tls_socket, username, password)

            # Explicitly overwrite password reference to help Garbage Collector
            password = "x" * len(password)
            del password

            # Proceed to send the CONNECT target directive
            connect_payload = json.dumps({
                "host": target_host,
                "port": target_port
            }).encode('utf-8')
            
            connect_msg = VPNMessage(
                command=Commands.CONNECT, 
                payload=connect_payload, 
                session_id=session_id
            )
            
            self._tls_socket.sendall(encode_message(connect_msg))
            buffer = self._tls_socket.recv(self.config.BUFFER_SIZE)
            if not buffer:
                raise ProtocolError("Server disconnected while building tunnel.")

            response = decode_message(buffer)
            if response.command != Commands.OK:
                reason = response.payload.decode('utf-8', errors='ignore')
                raise TunnelError(f"Server rejected proxy request: {reason}")
                
            self._logger.info(f"Server OK. Upstream target connected: {target_host}:{target_port}")

            # Instantiate and block on the forwarder
            self._forwarder = LocalForwarder(
                self.config.LOCAL_LISTEN_HOST, 
                self.config.LOCAL_LISTEN_PORT, 
                self.config.BUFFER_SIZE
            )
            
            # Start blocks indefinitely until exactly one client drops or hits SIGINT
            self._forwarder.start(self._tls_socket)

        except (AuthenticationError, TunnelError, ProtocolError, ForwardingError) as e:
            self._logger.error(f"Failed: {e}")
        except Exception as e:
            self._logger.error(f"Unexpected Exception: {e}")
        finally:
            self.stop()
            self._logger.info("VPN Session terminated.")

    def stop(self) -> None:
        """
        Signals proxy shutdowns and closes the persistent TLS tunnel pipeline.
        """
        self._running = False
        
        if self._forwarder:
            self._forwarder.stop()

        if self._tls_socket:
            try:
                self._tls_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._tls_socket.close()
            except OSError:
                pass
            self._tls_socket = None


def main() -> None:
    """
    Parses CLI overrides, manages SIGINT logic, reads identity bounds, 
    and cascades into the VPN client.
    """
    parser = argparse.ArgumentParser(description="Custom Application-Layer SSL/TLS VPN Client")
    
    parser.add_argument("--config", "-c", type=str, default="client/config.json", help="Path to JSON configuration file")
    
    # Overrides 
    parser.add_argument("--server-host", type=str, help="Override VPN server IP")
    parser.add_argument("--server-port", type=int, help="Override VPN server Port")
    parser.add_argument("--listen-port", type=int, help="Override local application bind port")
    
    # Target proxying destinations
    parser.add_argument("--target-host", type=str, required=True, help="Destination IP requested over the VPN")
    parser.add_argument("--target-port", type=int, required=True, help="Destination Port requested over the VPN")
    
    # Auth skipping convenience 
    parser.add_argument("--username", "-u", type=str, help="Username (skip prompt)")
    parser.add_argument("--password", "-p", type=str, help="Password (skip prompt, use for demos only)")
    
    args = parser.parse_args()
    
    try:
        config = load_config(args.config)
        
        # Apply strict CLI configuration overides over JSON data dynamically
        if args.server_host:
            config = ClientConfig(**{**config.__dict__, "SERVER_HOST": args.server_host})
        if args.server_port:
            config = ClientConfig(**{**config.__dict__, "SERVER_PORT": args.server_port})
        if args.listen_port:
            config = ClientConfig(**{**config.__dict__, "LOCAL_LISTEN_PORT": args.listen_port})
            
    except Exception as e:
        sys.stderr.write(f"FATAL: Failed to load client config: {e}\n")
        sys.exit(1)

    client = VPNClient(config)

    def signal_handler(sig: Any, frame: Any) -> None:
        sys.stderr.write("\nInterrupt received, tearing down secure connection...\n")
        client.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        client.run(
            target_host=args.target_host, 
            target_port=args.target_port,
            override_username=args.username,
            override_password=getattr(args, 'password', None)
        )
    except KeyboardInterrupt:
        client.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
