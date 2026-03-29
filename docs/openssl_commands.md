# OpenSSL TLS Certificate Commands

This document contains the exact, copy-pasteable commands needed to generate the cryptographic certificates for the VPN. 

The architecture uses a custom Certificate Authority (CA) to sign the Server's certificate. The Client *only* trusts this specific CA, ensuring nobody can easily spoof the VPN server.

> [!TIP]
> **Easier Alternative**: If we don't have OpenSSL installed or want a faster way, run our included Python script in the root directory:
> ```powershell
> .venv\Scripts\python gen_certs.py
> ```
> This script uses the `cryptography` library to generate all necessary keys and certificates with the correct settings automatically.

---

### Step 1: Generate the Certificate Authority (CA)
First, we act as our own trusted authority and create a Root CA.

**Command:**
```bash
# 1. Generate the CA private key
openssl genrsa -out ca.key 4096

# 2. Create the self-signed CA Root Certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/C=US/ST=State/L=City/O=MyVPN Org/CN=MyVPN Root CA"
```

**Expected Output:**
```text
Generating RSA private key, 4096 bit long modulus
.............................++
...++
e is 65537 (0x10001)
```

**What to do with these files:**
* Place `ca.crt` in `client/certs/` so the Client can verify the Server.
* Keep `ca.key` completely secret (or delete it after signing the server cert).

---

### Step 2: Generate the Server Key and CSR
Next, we generate the actual private key for the VPN Server and a Certificate Signing Request (CSR) to hand to our CA.

**Command:**
```bash
# 1. Generate the Server private key
openssl genrsa -out server.key 2048

# 2. Generate the CSR (Certificate Signing Request)
# NOTE: The CN (Common Name) MUST match the hostname the client connects to!
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=State/L=City/O=MyVPN Org/CN=127.0.0.1"
```

**Expected Output:**
```text
Generating RSA private key, 2048 bit long modulus
...+++
........+++
e is 65537 (0x10001)
```

---

### Step 3: Sign the Server Certificate with the CA
Now, the Certificate Authority uses its power to "approve" the Server's CSR, creating the final `server.crt`.

**Command:**
```bash
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 825 -sha256
```

**Expected Output:**
```text
Signature ok
subject=/C=US/ST=State/L=City/O=MyVPN Org/CN=127.0.0.1
Getting CA Private Key
```

**What to do with these files:**
* Place both `server.key` and `server.crt` in `server/certs/`.

---

### Step 4: Verify the Certificate Chain
Ensure that the newly created Server Certificate is properly linked to the CA.

**Command:**
```bash
openssl verify -CAfile ca.crt server.crt
```

**Expected Output:**
```text
server.crt: OK
```

---

### Step 5: Test the TLS Handshake (Debugging)
If the Python VPN server is struggling, use the native OpenSSL client to test if the port is negotiating TLS properly.

*Make sure our Python VPN Server is running on port 8443 before doing this.*

**Command:**
```bash
openssl s_client -connect 127.0.0.1:8443 -CAfile ca.crt
```

**Expected Output Snippet (Success):**
```text
CONNECTED(00000003)
depth=1 C = US, ST = State, L = City, O = MyVPN Org, CN = MyVPN Root CA
verify return:1
depth=0 C = US, ST = State, L = City, O = MyVPN Org, CN = 127.0.0.1
verify return:1
---
Certificate chain
 0 s:/C=US/ST=State/L=City/O=MyVPN Org/CN=127.0.0.1
   i:/C=US/ST=State/L=City/O=MyVPN Org/CN=MyVPN Root CA
---
Server certificate
-----BEGIN CERTIFICATE-----
MII...
```
*(Press `Ctrl+C` to quit the s_client).*
