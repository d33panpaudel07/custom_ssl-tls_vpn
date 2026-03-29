# Project References and Bibliography

The following is a curated list of references, standards, and documentation used in the design and implementation of the Custom SSL VPN project. These can be directly adapted into the "References" or "Bibliography" section of your final project report.

---

## 1. Core Python Documentation
*These references validate the use of the Python Standard Library for secure networking, concurrency, and telemetry.*

[1] Python Software Foundation, "socket — Low-level networking interface," Python 3.12 Documentation. [Online]. Available: https://docs.python.org/3/library/socket.html
*(Used for: TCP socket creation, binding, and low-level byte transmission in `vpn_server.py` and `forwarder.py`)*

[2] Python Software Foundation, "ssl — TLS/SSL wrapper for socket objects," Python 3.12 Documentation. [Online]. Available: https://docs.python.org/3/library/ssl.html
*(Used for: `SSLContext` configuration, certificate loading, and establishing the encrypted tunnel)*

[3] Python Software Foundation, "select — Waiting for I/O completion," Python 3.12 Documentation. [Online]. Available: https://docs.python.org/3/library/select.html
*(Used for: Non-blocking I/O multiplexing in the `TunnelRelay` and `LocalForwarder` data planes)*

[4] Python Software Foundation, "threading — Thread-based parallelism," Python 3.12 Documentation. [Online]. Available: https://docs.python.org/3/library/threading.html
*(Used for: Daemon threads handling multiple simultaneous client connections and background session reaping)*

[5] Python Software Foundation, "hashlib — Secure hashes and message digests," Python 3.12 Documentation. [Online]. Available: https://docs.python.org/3/library/hashlib.html
*(Used for: PBKDF2 HMAC SHA-256 password hashing in `auth.py`)*

[6] Python Software Foundation, "hmac — Keyed-Hashing for Message Authentication," Python 3.12 Documentation. [Online]. Available: https://docs.python.org/3/library/hmac.html
*(Used for: `compare_digest()` to prevent timing attacks during credential validation)*

[7] Python Software Foundation, "logging — Logging facility for Python," Python 3.12 Documentation. [Online]. Available: https://docs.python.org/3/library/logging.html
*(Used for: Structured, JSON-formatted telemetry and sanitization in `logger.py`)*

[8] Python Software Foundation, "http.server — HTTP servers," Python 3.12 Documentation. [Online]. Available: https://docs.python.org/3/library/http.server.html
*(Used for: Establishing the isolated `/stats` endpoint in the SOC `monitor.py` dashboard)*

## 2. Cryptographic Standards (IETF RFCs)
*These references provide the academic and theoretical backing for the algorithms chosen.*

[9] E. Rescorla, "The Transport Layer Security (TLS) Protocol Version 1.3," RFC 8446, Internet Engineering Task Force, Aug. 2018. [Online]. Available: https://datatracker.ietf.org/doc/html/rfc8446
*(Used for: Justifying the use of modern TLS protocols and the deprecation of SSLv3 / TLSv1.0)*

[10] B. Kaliski, "PKCS #5: Password-Based Cryptography Specification Version 2.0," RFC 2898, Internet Engineering Task Force, Sep. 2000. [Online]. Available: https://datatracker.ietf.org/doc/html/rfc2898
*(Used for: The theoretical foundation of PBKDF2 used in the project's `AuthManager`)*

[11] H. Krawczyk, M. Bellare, and R. Canetti, "HMAC: Keyed-Hashing for Message Authentication," RFC 2104, Internet Engineering Task Force, Feb. 1997. [Online]. Available: https://datatracker.ietf.org/doc/html/rfc2104
*(Used for: Explaining the HMAC construction used to secure the password hashing process)*

[12] D. Cooper et al., "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile," RFC 5280, Internet Engineering Task Force, May 2008. [Online]. Available: https://datatracker.ietf.org/doc/html/rfc5280
*(Used for: The structure and validation of the PEM certificates generated via OpenSSL)*

[13] S. Turner and L. Chen, "Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms," RFC 6151, Internet Engineering Task Force, Mar. 2011. [Online]. Available: https://datatracker.ietf.org/doc/html/rfc6151
*(Used for: Architectural justification on avoiding MD5 and using SHA-256 for integrity and derived keys)*

[14] A. Langley, M. Hamburg, and S. Turner, "Elliptic Curves for Security," RFC 7748, Internet Engineering Task Force, Jan. 2016. [Online]. Available: https://datatracker.ietf.org/doc/html/rfc7748
*(Used for: Justification of Perfect Forward Secrecy using Elliptic Curve Diffie-Hellman in `setup_tls_context`)*

## 3. Network Security & Architectural Concepts
*These references support the system's design patterns, such as rate limiting, logging, and threat mitigation.*

[15] Open Web Application Security Project (OWASP), "Authentication Cheat Sheet," OWASP Foundation. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
*(Used for: Standardizing the brute-force lockout mechanism and timing-safe comparisons)*

[16] National Institute of Standards and Technology (NIST), "Recommendation for Password-Based Key Derivation," NIST Special Publication 800-132, Dec. 2010.
*(Used for: Justifying the choice of 100,000 iterations for the PBKDF2 hashing algorithm)*

[17] W. R. Stevens, B. Fenner, and A. M. Rudoff, *UNIX Network Programming, Volume 1: The Sockets Networking API*, 3rd ed. Addison-Wesley Professional, 2003.
*(Used for: Understanding `SO_REUSEADDR`, socket lifecycle management, and multithreaded server architectures)*

[18] OpenSSL Software Foundation, "OpenSSL Documentation," [Online]. Available: https://www.openssl.org/docs/
*(Used for: The command-line generation of the custom Certificate Authority and Server keys)*

[19] C. Boyd, A. Mathuria, and D. Stebila, *Protocols for Authentication and Key Establishment*, 2nd ed. Springer, 2019.
*(Used for: Theoretical backing of the application-layer `VPNMessage` authentication exchange protocol over the established TLS tunnel)*

[20] MITRE Corporation, "CWE-208: Observable Timing Discrepancy," Common Weakness Enumeration, 2023. [Online]. Available: https://cwe.mitre.org/data/definitions/208.html
*(Used for: Identifying and mitigating the timing-attack vulnerability resolved by `hmac.compare_digest`)*

[21] G. Bossert, F. Guihéry, and G. Hiet, "Towards Automated Anomaly-based Reverse Engineering of Network Protocols," in *IEEE Conference on Communications and Network Security (CNS)*, 2014.
*(Used for: Concept implementation in `MonitoringDashboard.detect_anomalies` mapping heuristic failure rates and abnormal session durations to SOC alerts)*

[22] Center for Internet Security (CIS), "CIS Controls V8," CISecurity.org, May 2021. [Online]. Available: https://www.cisecurity.org/controls/v8/
*(Used for: Adhering to structured audit logs, omitting sensitive data via `logger.sanitize()`, and tracking metrics for incident response)*

