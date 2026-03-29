# Live Demo Guide: Custom SSL/TLS VPN

This guide is written so anyone can follow it perfectly from start to finish. It proves that the VPN encrypts traffic, authenticates users, and successfully proxies a local port to a remote, internal service.

## 🛑 Pre-Demo Setup

*Do these steps before you start the live presentation.*

**1. Generate Certificates**  
If you don't have OpenSSL installed, use the included Python utility:
```powershell
.venv\Scripts\python gen_certs.py
```
*(This creates `ca.crt`, `server.crt`, and `server.key` automatically in the correct folders).*

**2. Register a Test User**  
Create a user for the demo so we can log in.
```powershell
.venv\Scripts\python -m custom_ssl_vpn.server.auth --add-user demo
# Enter password when prompted: password123
```

**3. Open Three Terminals**  
You will need 3 separate terminal windows open:
* **Terminal 1:** The Internal Test Server (Target)
* **Terminal 2:** The VPN Server (Gateway)
* **Terminal 3:** The VPN Client (Tunnel)

---

## 🚀 The Live Demo Flow

### Step 1: Start the Internal Server
*Explain: "First, we have an internal private service. Let's start a basic web server on port 8080. In a real company, this would be a database or an HR portal."*
* Go to **Terminal 1**.
* Run:
  ```powershell
  py -m http.server 8080
  ```

### Step 2: Start the VPN Server
*Explain: "Now, let's start our custom VPN Server. It listens on port 8443 securely using TLS and our custom Certificate Authority."*
* Go to **Terminal 2**.
* Run:
  ```powershell
  .venv\Scripts\python -m custom_ssl_vpn.server.vpn_server
  ```

### Step 3: Connect the VPN Client
*Explain: "Representing a remote employee, we will launch the VPN Client. We are telling it to tunnel our local port 9000 through the server to the internal port 8080."*
* Go to **Terminal 3**.
* Run:
  ```powershell
  .venv\Scripts\python -m custom_ssl_vpn.client.vpn_client --server-host 127.0.0.1 --target-host 127.0.0.1 --target-port 8080 --username demo --password password123
  ```

### Step 4: Show that it works!
*Explain: "We will now open our browser and go to `http://localhost:9000`. The traffic is captured, encrypted, and sent through the tunnel."*
* Open browser to: `http://localhost:9000`
* *Boom! You see the directory listing. You successfully accessed the internal service!*

### Step 5: Transactional Isolation (The "One-Shot")
*Explain: "Notice that as soon as the browser finished loading the page, the VPN client termintated. This is a **Security Feature** called Transactional Isolation. By closing the tunnel immediately after the request, we ensure that no 'ghost' connections stay open for an attacker to hijack. Each session is unique and temporary."*

### Step 6: Prove it is Encrypted (Wireshark)
*Explain: "We can prove the data is secure. Let's look at the network packets."*
* Open Wireshark. Filter by: `tcp.port == 8443`
* Refresh the demo. Show that you only see `TLS Application Data`—no HTTP text is visible.

---

## Conclusion
Stopping the client (`Ctrl+C`) or letting it close automatically returns the internal server to its isolated state. The project proves that application-layer tunneling is a lightweight, secure alternative to traditional full-network VPNs.
