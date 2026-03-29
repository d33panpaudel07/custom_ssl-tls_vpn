# Algorithms and Cryptographic Concepts

This document explains the technical "brain" of the Custom SSL VPN. It breaks down the algorithms used, the security concepts they provide, and the engineering rationale for choosing them over alternatives.

---

## 1. Transport Security (The Tunnel)

The VPN uses **TLS (Transport Layer Security) 1.2 / 1.3** to wrap all traffic.

### 1.1 AES (Advanced Encryption Standard)
*   **Concept**: **Confidentiality** (Ensures no one can read the data).
*   **Alternative**: DES, 3DES, ChaCha20.
*   **Why this?**: 
    *   AES is the industry gold standard. It is a "Symmetric" algorithm, meaning it is extremely fast because it uses the same key for encryption and decryption.
    *   **Alternative Rationale**: DES is "broken" (cryptographically weak). ChaCha20 is great for mobile devices without hardware acceleration, but AES is hardware-accelerated on almost all modern CPUs, making it more efficient for a server.

### 1.2 ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
*   **Concept**: **Forward Secrecy** (Ensures past sessions remain safe if the server key is stolen later).
*   **Alternative**: Static Diffie-Hellman (DH), RSA Key Exchange.
*   **Why this?**: 
    *   In `vpn_server.py`, we use `OP_SINGLE_ECDH_USE`. This generates a *new* temporary key for every single connection.
    *   **Alternative Rationale**: Standard RSA key exchange is vulnerable; if an attacker records your traffic today and steals your private key next year, they can decrypt today's traffic. ECDHE prevents this.

### 1.3 RSA / ECDSA (Digital Signatures)
*   **Concept**: **Authenticity** (Ensures the client is talking to the *real* server).
*   **Alternative**: Shared Keys (PSK).
*   **Why this?**: 
    *   We use X.509 Certificates. The client checks the server's cert against a trusted Certificate Authority (CA).
    *   **Alternative Rationale**: Shared keys are hard to manage at scale. Certificates allow the server to prove its identity without the client needing to know a "secret" beforehand.

---

## 2. Authentication (The Gateway)

How we verify the user's identity before letting them through the tunnel.

### 2.1 PBKDF2-HMAC-SHA256
*   **Concept**: **Credential Security** (Protects passwords at rest).
*   **Alternative**: Argon2, bcrypt, MD5 (Plain).
*   **Why this?**: 
    *   Matches the **standard library** (no 3rd party dependencies). We use 100,000 iterations to make "brute-forcing" the database extremely slow for an attacker.
    *   **Alternative Rationale**: MD5 is dangerously fast and insecure. Argon2 is technically superior but requires external C libraries (like `pynacl`). PBKDF2 is the best "batteries-included" choice for a Python project.

### 2.2 hmac.compare_digest
*   **Concept**: **Timing Attack Prevention** (Confidentiality of the comparison).
*   **Alternative**: Standard `==` operator.
*   **Why this?**: 
    *   The `==` operator stops as soon as it finds a mismatch, meaning it returns faster for "wrong" passwords than for "almost right" ones. This allows an attacker to guess the hash character by character. `compare_digest` always takes the same amount of time.
    *   **Alternative Rationale**: Using `==` is a classic security "gotcha."

---

## 3. Network Reliability / Continuity

### 3.1 Sliding Window Rate Limiting (In `VPNLogger`)
*   **Concept**: **Availability** (Prevents DOS/Brute Force crashes).
*   **Alternative**: Fixed Window, Token Bucket.
*   **Why this?**: 
    *   We track failures in the last 300 seconds (5 mins). This is more "fair" than a fixed window (e.g., "10 fails per hour") because it resets smoothly.
    *   **Alternative Rationale**: Token Bucket is better for high-traffic APIs, but Sliding Window is easier to implement for a VPN security monitor.

### 3.2 TCP SO_REUSEADDR
*   **Concept**: **Reliability / Operational Continuity**.
*   **Alternative**: Waiting for OS timeout.
*   **Why this?**: 
    *   Allows the server to restart immediately on the same port. Without it, we have to wait 1-2 minutes for the OS to release the socket.

---

## Summary Table

| Goal | Technique | Component |
|------|-----------|-----------|
| **Confidentiality** | AES-256-GCM | TLS Layer |
| **Integrity** | SHA-256 (HMAC) | TLS / Protocol |
| **Authenticity** | X.509 Certs (RSA) | TLS Handshake |
| **Identity** | PBKDF2-HMAC | AuthManager |
| **Forward Secrecy** | ECDHE | TLS Handshake |
| **Availability** | IP Blocklist / Rate Limit | SecurityPolicy |
| **Timing Safety** | `compare_digest` | AuthManager |
