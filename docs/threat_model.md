# Threat Model: Custom SSL/TLS VPN

This document outlines the security posture of the application-layer VPN, identifying what is being protected, who might attack it, where they might attack, and how the system defends itself.

## 1. Assets (What We Protect)

* **User Credentials:** The plaintext passwords used by clients to authenticate with the server.
* **Session Tokens:** The `session_id` (UUID4) assigned to approved connections, allowing them to tunnel traffic.
* **Tunneled Data:** The raw byte streams of application data (e.g., HTTP headers, payloads, database queries) passing through the VPN.
* **Internal Network Access:** The trusted network segment behind the VPN server where the target services reside.
* **Server Availability:** The ability of the VPN server to accept and process legitimate client connections without being exhausted.

## 2. Threat Actors

* **Script Kiddie / Botnet:** Automated scanners looking for open ports, attempting brute-force logins, or sending garbage data to crash services.
* **MITM (Man-in-the-Middle) Attacker:** An adversary positioned on the network path between the VPN client and server (e.g., a malicious Wi-Fi hotspot acting as a router) attempting to eavesdrop or tamper.
* **Credential Stuffer:** An attacker using lists of compromised usernames and passwords from other breaches to try and gain unauthorized access.

## 3. Attack Surfaces

* **TCP Listener Port (e.g., 8443):** The publicly reachable network port accepting incoming connections before TLS is negotiated.
* **TLS Handshake:** The cryptographic negotiation phase where certificates are exchanged and cipher suites are selected.
* **Authentication Flow:** The custom `AUTH` message protocol where users present their username and password.
* **Tunnel Data Relay:** The bidirectional payload forwarding logic (`DATA` messages) processing untrusted bytes.

## 4. Threat Analysis and Mitigations

| Attack Vector | Likelihood | Impact | Mitigation Implemented |
|---------------|------------|--------|------------------------|
| **Brute Force Authentication** | High | High (Network Compromise) | Rate-limiting tracks failures per IP. IPs are locked out for 5 minutes after 3 consecutive failures. Passwords are hashed using PBKDF2-HMAC (100k iterations). |
| **Distributed Brute Force** | Medium | High (Network Compromise) | Global rate limiter triggers after 100 total failures in a short window across *all* IPs, stopping wide-net distributed attacks. |
| **Eavesdropping (Packet Sniffing)** | High | High (Data Breach) | End-to-End TLSv1.2+ encryption using Perfect Forward Secrecy (`OP_SINGLE_DH_USE`, `OP_SINGLE_ECDH_USE`). Raw data cannot be decrypted from packet captures. |
| **Man-in-the-Middle (MITM)** | Medium | High (Data / Auth Breach) | The Client strictly verifies the Server's certificate against a pinned Root CA (`ssl.CERT_REQUIRED`) and checks the hostname matching. |
| **Timing Attacks on Auth** | Low | Medium (User Enumeration) | `AuthManager` uses `hmac.compare_digest()` for constant-time comparisons. Dummy hashes are calculated for non-existent users to equalize response times. |
| **Denial of Service (DoS)** | High | Medium (Downtime) | A `SecurityPolicy` blocklist drops repeat offenders *before* the expensive TLS handshake. `MAX_CLIENTS` strictly caps memory usage to prevent Out-Of-Memory crashes. |
| **Stale Session Hijacking** | Low | High (Network Compromise) | Background reaper threads violently expire sessions idle for more than the configured timeout (e.g., 3600 seconds), closing their sockets. |
| **Database Corruption** | Low | Medium (Loss of Auth) | The credential JSON store is written atomically (temp file + `os.replace`) to prevent file corruption during power loss. |
