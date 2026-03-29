# The Complete Custom SSL VPN Lifecycle (0% to 100%)

This document is a comprehensive script to explain the entire VPN system to an external reviewer, teacher, or engineering peer. It walks through what happens from the very start (the setup) to the exact moment data flows securely.

---

## 1. The Goal: Why does this exist?

**The Scenario:** Imagine an internal company server (like an HR database or a private web app). It sits on port `8080`. It is blocked from the internet by a firewall. A remote employee working from home needs to access it, but we don't want to expose port `8080` to the world.

**The Solution:** We run this Custom SSL VPN Server on the edge of the company network. It opens exactly one secure port (`8443`) to the public internet. The remote employee runs the VPN Client, which bypasses the firewall via `8443` and securely tunnels their traffic to the internal `8080` server.

---

## 2. Phase 1: Security Setup (The "0%")

Before anyone can connect, two foundational things must happen:

1.  **Identity (Certificates):** The VPN server generates an **X.509 Certificate** using RSA. This is like a digital passport. The remote employee (the client) has the Certificate Authority (CA) file on their laptop, so they can verify they are talking to the real company server, not a hacker in a coffee shop.
2.  **Authentication (Users):** The server administrator registers the employee's username and password. The password is _never_ saved in plain text. It is passed through the **PBKDF2-HMAC-SHA256** algorithm 100,000 times to create a secure cryptographic hash.

_State: The VPN Server is now running. It is waiting on port `8443`._

---

## 3. Phase 2: The Handshake (0% to 30%)

The remote employee starts the `VPNClient` program on their laptop.

1.  **The TCP Connection:** The client reaches out over the internet and hits the server on port `8443`.
2.  **The Bouncer (Security Policy):** Before the server even replies, the `SecurityPolicy` checks the client's IP address against a Blocklist. If the IP is banned (due to past attacks), the connection is instantly cut off.
3.  **The TLS Handshake (AES & ECDHE):** If allowed, the client and server negotiate a secure TLS 1.2+ connection. They use **ECDHE** (Elliptic Curve Ephemeral) to mathematically agree on a temporary, one-time secret key. All future traffic will be encrypted using **AES-256**.
    - _Analogy: They are now in a soundproof, bulletproof tunnel._

_State: We have a secure pipe, but the server still doesn't know WHO the employee is._

---

## 4. Phase 3: Authentication (30% to 60%)

Inside the bulletproof tunnel, the client application asks the user for their username and password.

1.  **The AUTH Packet:** The client packs the username and password into JSON, encrypts it, and sends it to the server with a command flag: `[AUTH]`.
2.  **Rate Limiting:** The server receives it. The `AuthManager` checks that this IP hasn't failed a password check more than 3 times in the last 5 minutes. If they have, they are temporarily banned.
3.  **Timing-Safe Compare:** The server hashes the password provided by the user and compares it to the database hash using `hmac.compare_digest`. This prevents "timing attacks" where hackers guess passwords by seeing how fast the server rejects them.
4.  **The Session ID:** The password is correct! The server creates a unique `session_id` (a UUID4) and sends an `[OK]` message back to the client.

_State: The secure tunnel is now authenticated._

---

## 5. Phase 4: Proxied Connection (60% to 90%)

The remote employee now wants to talk to the internal Web App on port `8080`.

1.  **The Target Request:** The client sends a `[CONNECT]` packet over the tunnel, asking the server to connect to `127.0.0.1:8080`.
2.  **The Local Gateway:** On the employee's laptop, the `VPNClient` opens a local proxy port (`localhost:9000`). It tells the employee: _"Point your browser to localhost:9000."_
3.  **The Internal Bridge:** On the company side, the `VPNServer` takes the `[CONNECT]` request and reaches into the internal network, finally connecting a raw TCP socket to the Web App at port `8080`.

_State: Both sides are fully wired up._

---

## 6. Phase 5: The Data Plane Relay (90% to 100%)

The employee opens their browser and types `http://localhost:9000`.

1.  **Upstream (Client -> Server):**
    - The browser sends an HTTP `GET /` request locally.
    - The `LocalForwarder` snatches that HTTP text.
    - It shoves the text into the TLS socket (AES encrypted).
    - The encrypted bytes fly across the public internet.
    - The `TunnelRelay` on the server receives them, decrypts them automatically, and pushes the plain HTTP text into port `8080`.
2.  **Downstream (Server -> Client):**
    - The internal app processes the request and sends the HTML response back.
    - The server's `TunnelRelay` catches the HTML, encrypts it, and sends it back across the internet.
    - The client's `LocalForwarder` decrypts it and hands the raw HTML back to the browser.
3.  **The Session Lifecycle (One-Shot Relay):** In this implementation, the `LocalForwarder` is designed for **High Isolation**. It accepts exactly one application connection (e.g., one browser session or one file download). As soon as the browser finishes its request and closes the connection, the `LocalForwarder` breaks the relay loop, triggers a `[DISCONNECT]` to the server, and safely terminates the VPN client. This ensures that the tunnel is never left "hanging" and vulnerable after use.
4.  **The Background Reapers:** While this happens, a `SessionManager` thread constantly checks if anyone has been idle for 60 minutes. If so, it kills the tunnel to save resources. A SOC `Monitor` watches live traffic to detect if someone is downloading too much data or if the server is reaching maximum capacity.

## Conclusion

The lifecycle of the Custom SSL VPN is built around **Transactional Security**. When the employee finishes their work in the browser, the VPN detects the closure and performs a multi-step cleanup: the `[DISCONNECT]` commands fire, the TLS sockets are gracefully shut down, the bytes-transferred metrics are logged for security auditing, and the internal Web App returns to being safely isolated behind the firewall.

> [!NOTE]
> While this "one-shot" behavior provides maximum session isolation, future versions of the project can implement **Multiplexing** to allow multiple browser tabs or concurrent applications to share the same persistent tunnel.
