# Function Reference Index

This document provides a complete technical reference for every public class and function within the Custom SSL VPN project.

## Shared Modules

### `shared.protocol`
Definitions for the application-layer frame and binary codecs.

| Module | Name | Signature | Returns | Raises | Purpose | Dependencies |
|--------|------|-----------|---------|--------|---------|--------------|
| `shared.protocol` | `Commands` | `Enum(str)` | N/A | N/A | All valid command tokens (AUTH, CONNECT, etc.) | None |
| `shared.protocol` | `VPNMessage` | `dataclass` | N/A | N/A | Decoupled representation of a protocol frame | None |
| `shared.protocol` | `encode_message` | `(msg: VPNMessage)` | `bytes` | `UnknownCommandError`, `MalformedMessageError` | Serialises a message to the wire-format buffer | `exceptions` |
| `shared.protocol` | `decode_message` | `(raw: bytes)` | `VPNMessage` | `MalformedMessageError`, `UnknownCommandError` | Deserialises a raw buffer into a structured message | `exceptions` |

### `shared.exceptions`
Domain-specific exception hierarchy.

| Module | Name | Signature | Returns | Raises | Purpose | Dependencies |
|--------|------|-----------|---------|--------|---------|--------------|
| `shared.exceptions` | `VPNBaseException` | `(message: str, context: dict)` | N/A | N/A | Base class for all project-specific errors | None |

---

## Server Modules

### `server.vpn_server`
Central orchestrator for the server daemon.

| Module | Name | Signature | Returns | Raises | Purpose | Dependencies |
|--------|------|-----------|---------|--------|---------|--------------|
| `server.vpn_server` | `VPNServer` | `(config: ServerConfig)` | N/A | N/A | Manages TLS listeners and client worker threads | `config`, `logger`, `auth`, `session`, `tunnel`, `security`, `monitor` |
| `server.vpn_server` | `VPNServer.setup_tls_context` | `()` | `ssl.SSLContext` | `ssl.SSLError` | Hardens TLS settings (PFS, No SSLv3) | `config` |
| `server.vpn_server` | `VPNServer.start` | `()` | `None` | `OSError`, `ssl.SSLError` | Binds port and enters the accept loop | `logger`, `monitor` |
| `server.vpn_server` | `VPNServer.stop` | `()` | `None` | N/A | Triggers graceful teardown of all subsystems | `logger`, `monitor`, `session`, `security` |

### `server.auth`
Secure credential and rate-limit management.

| Module | Name | Signature | Returns | Raises | Purpose | Dependencies |
|--------|------|-----------|---------|--------|---------|--------------|
| `server.auth` | `AuthManager` | `(db_path, max_attempts)` | N/A | N/A | Managed PBKDF2 hashing and brute-force tracking | `exceptions` |
| `server.auth` | `AuthManager.authenticate` | `(user, pass, ip)` | `bool` | `TooManyAttemptsError`, `InvalidCredentialsError` | Validates credentials with timing-safe checks | `exceptions` |
| `server.auth` | `AuthManager.register_user` | `(user, pass)` | `None` | `ValueError` | Securely provisions new users to the datastore | None |
| `server.auth` | `AuthManager.rate_limit_check` | `(client_ip)` | `None` | `TooManyAttemptsError` | Protects server from distributed brute force | `exceptions` |

### `server.tunnel`
The high-performance data plane.

| Module | Name | Signature | Returns | Raises | Purpose | Dependencies |
|--------|------|-----------|---------|--------|---------|--------------|
| `server.tunnel` | `TunnelRelay` | `(session, host, port, ...)` | N/A | N/A | Bridges TLS client to internal TCP service | `session`, `logger` |
| `server.tunnel` | `TunnelRelay.connect` | `()` | `None` | `ConnectionRefusedError`, `TunnelError` | Establishes upstream leg of the tunnel | `logger`, `exceptions` |
| `server.tunnel` | `TunnelRelay.start_relay` | `()` | `None` | `ForwardingError` | Blocks in a bidirectional read/write loop | `logger`, `session`, `exceptions` |

### `server.session`
Lifecycle tracking for active connections.

| Module | Name | Signature | Returns | Raises | Purpose | Dependencies |
|--------|------|-----------|---------|--------|---------|--------------|
| `server.session` | `Session` | `dataclass` | N/A | N/A | Holds socket, IP, and byte-accounting state | None |
| `server.session` | `SessionManager` | `(max_clients, timeout)` | N/A | N/A | Tracks all active tunnels; runs reaper thread | `logger` |
| `server.session` | `SessionManager.create_session` | `(ip, port, tls_socket)` | `Session` | `SessionError` | Registers a new pre-auth connection | `logger`, `exceptions` |

### `server.security`
Low-level firewalling.

| Module | Name | Signature | Returns | Raises | Purpose | Dependencies |
|--------|------|-----------|---------|--------|---------|--------------|
| `server.security` | `SecurityPolicy` | `()` | N/A | N/A | Manages IP-level blocklists (manual & auto) | `logger` |
| `server.security` | `SecurityPolicy.block_ip` | `(ip, reason, duration)` | `None` | N/A | Bans a hostile IP address | `logger` |
| `server.security` | `SecurityPolicy.is_blocked` | `(ip)` | `bool` | N/A | Fast-path check called in `_accept_loop` | None |

---

## Client Modules

### `client.vpn_client`
Client orchestrator.

| Module | Name | Signature | Returns | Raises | Purpose | Dependencies |
|--------|------|-----------|---------|--------|---------|--------------|
| `client.vpn_client` | `VPNClient` | `(config)` | N/A | N/A | High-level CLI wrapper for the VPN connection | `config`, `forwarder` |
| `client.vpn_client` | `VPNClient.connect_to_server` | `()` | `ssl.SSLSocket` | `TunnelError` | Handshakes TLS with certificate verification | `config` |
| `client.vpn_client` | `VPNClient.authenticate` | `(sock, user, pass)` | `str` | `AuthenticationError`, `ProtocolError` | Performs the application-layer auth exchange | `protocol`, `exceptions` |
| `client.vpn_client` | `VPNClient.run` | `(target, port, ...)` | `None` | `Exception` | Orchestrates the full connection and auth lifecycle | `forwarder` |

### `client.forwarder`
Local application gateway.

| Module | Name | Signature | Returns | Raises | Purpose | Dependencies |
|--------|------|-----------|---------|--------|---------|--------------|
| `client.forwarder` | `LocalForwarder` | `(host, port, buf)` | N/A | N/A | Listens on localhost to capture app traffic | `protocol`, `exceptions` |
| `client.forwarder` | `LocalForwarder.start` | `(vpn_socket)` | `None` | `ForwardingError` | Bridges the first app connection to the tunnel | `protocol`, `exceptions` |
