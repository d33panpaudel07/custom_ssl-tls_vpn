## FIRST RUN (When running for first we need to setup certificate authorities and a virtual environment)

py -m venv .venv
.venv\Scripts\pip install cryptography
.venv\Scripts\python gen_certs.py
.venv\Scripts\python -c "from custom_ssl_vpn.server.auth import AuthManager; AuthManager().register_user('demo', 'password123')"

---

## SECOND RUN (Commnads below are always used in both first run or second run)

### Terminal 1

py -m http.server 8080

### Terminal 2

.venv\Scripts\python -m custom_ssl_vpn.server.vpn_server

### Terminal 3

.venv\Scripts\python -m custom_ssl_vpn.client.vpn_client --server-host 127.0.0.1 --target-host 127.0.0.1 --target-port 8080 --username demo --password password123
