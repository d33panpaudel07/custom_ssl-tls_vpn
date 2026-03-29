# VPN Call Graph

This document visualizes the execution flow and call hierarchy of the system.

**Legend:**
* ★ = Primary Entry Point (CLI)
* 🔐 = Security Critical (Auth, Encryption, or Firewalling)

## Server Execution Flow

★ **`server.vpn_server.main`**
└── `server.config.load_config` (Loads settings)
└── `server.logger.setup_logger` (Initialises JSON logging)
└── `server.vpn_server.VPNServer.start`
    ├── `server.vpn_server.VPNServer.setup_tls_context` 🔐 (Harden TLS)
    ├── `server.monitor.MonitoringDashboard.start` (SOC data feed)
    └── `server.vpn_server.VPNServer._accept_loop`
        ├── `server.security.SecurityPolicy.is_blocked` 🔐 (TCP-level check)
        └── `server.vpn_server.VPNServer._handle_client` (New Thread)
            ├── `server.session.SessionManager.create_session`
            ├── `shared.protocol.decode_message` (Parse AUTH)
            ├── **`server.auth.AuthManager.authenticate`** 🔐 (Validate Credentials)
            │   └── `server.auth.AuthManager.rate_limit_check`
            ├── `server.session.SessionManager.authenticate_session`
            ├── `shared.protocol.encode_message` (Send OK)
            ├── `shared.protocol.decode_message` (Parse CONNECT)
            ├── `server.tunnel.TunnelRelay.connect` (Upstream TCP)
            └── `server.tunnel.TunnelRelay.start_relay` (Data Plane)
                └── `server.session.SessionManager.touch_session` (Activity)

## Client Execution Flow

★ **`client.vpn_client.main`**
└── `client.config.load_config`
└── `client.vpn_client.VPNClient.run`
    ├── **`client.vpn_client.VPNClient.connect_to_server`** 🔐 (TLS Handshake)
    ├── **`client.vpn_client.VPNClient.authenticate`** 🔐 (App-layer Handshake)
    │   ├── `shared.protocol.encode_message`
    │   └── `shared.protocol.decode_message`
    └── `client.forwarder.LocalForwarder.start`
        └── `client.forwarder.LocalForwarder._run_relay`
            └── `client.forwarder.LocalForwarder._send_all`

## Utility & Maintenance

★ **`server.auth.main`** (_cli_entry)
└── **`server.auth.AuthManager.register_user`** 🔐 (Provisioning)

**`server.session.SessionManager`** (Background)
└── `server.session.SessionManager._expiry_loop` (Reaper)
    └── `server.session.Session.is_expired`

**`server.security.SecurityPolicy`** (Background)
└── `server.security.SecurityPolicy._scheduled_unblock_loop` (Self-healing ban list)
