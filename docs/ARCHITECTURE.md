# VPN Architecture Overview

This document outlines the architectural design, module dependencies, data flow, threading model, and TLS termination strategy for the custom SSL/TLS application-layer VPN.

## Module Dependencies

```text
custom_ssl_vpn/
├── client/
│   ├── vpn_client.py  --------------> shared/protocol.py
│   │   ├── config.py
│   │   └── forwarder.py
│
├── server/
│   ├── vpn_server.py  --------------> shared/protocol.py
│   │   ├── config.py
│   │   ├── logger.py
│   │   ├── auth.py
│   │   ├── session.py
│   │   ├── security.py
│   │   ├── monitor.py
│   │   └── tunnel.py
│
└── shared/
    ├── protocol.py    --------------> shared/exceptions.py
    └── exceptions.py
```

## Data Flow

The lifecycle of a tunneled connection flows sequentially through several layers before bidirectional relay begins:

1. **Client Startup:**
   `VPNClient` connects to `VPNServer` and performs a TLS handshake.
2. **Authentication:**
   Client sends `AUTH` message. Server's `AuthManager` validates credentials. On success, an `OK` message containing a `session_id` is returned.
3. **Local Forwarder Binding:**
   The `LocalForwarder` binds to `127.0.0.1:9000` (or configured port) and accepts **one** downstream application connection (e.g., from a browser or script).
4. **Tunnel Request:**
   Client sends a `CONNECT` message specifying the target internal `host:port`.
5. **Relay Setup:**
   The server's `TunnelRelay` establishes a plain TCP connection to the internal service.
6. **Data Relay:**
   Bidirectional traffic starts immediately:
   `Application <──TCP──> LocalForwarder <──TLS (VPN)──> TunnelRelay <──TCP──> Internal Service`

## Threading Model

The server uses a thread-per-client model combined with asynchronous non-blocking relays to maximize throughput and isolation.

### Server Threads
* **Main Thread:** Runs `VPNServer._accept_loop()`. Accepts raw TCP sockets, runs IP blocklist checks, and spawns a new daemon thread for each client.
* **Client Handler Threads (`_handle_client`):** Wraps the socket in TLS, handles the AUTH/CONNECT protocol handshake, and configures the session. Yields to `TunnelRelay`.
* **Tunnel Relay Threads (`TunnelRelay.start_relay`):** Performs bidirectional multiplexing via `select()`. Blocks tightly on I/O.
* **Session Reaper Thread (`SessionManager._expiry_loop`):** Background daemon sweeping expired sessions every 60 seconds.
* **Security Unblock Thread (`SecurityPolicy._scheduled_unblock_loop`):** Background daemon lifting expired temporal IP bans every 10 seconds.
* **Monitor HTTP Thread:** Base HTTP server serving JSON stats on port 9999.

### Client Threads
* **Main Thread:** Handles the CLI interface, TLS connection, authentication, and blocks on `LocalForwarder.start()` until the session ends. No multi-threading is typically launched on the client as it proxies exactly one application connection at a time.

## TLS Termination Points

The VPN relies heavily on end-to-end encryption for the untrusted segment of the journey.

* **Client Terminus:** `ssl.SSLSocket` inside `VPNClient`. Validates the Server CA certificate before transmitting any authentication data.
* **Server Terminus:** `ssl.SSLSocket` created in `VPNServer._handle_client()`. Uses strict TLSv1.2+ configuration with Perfect Forward Secrecy, effectively denying outdated SSLv3 clients before any application byte is read.
* **Internal Network:** The final hop from `VPNServer` (via `TunnelRelay`) to the internal service (e.g., test webserver) uses **plain TCP**, under the zero-trust paradigm assumption that the internal subnet segment connecting the VPN orchestrator and the target is considered explicitly trusted or loopback.
