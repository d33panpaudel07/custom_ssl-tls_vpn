"""
Regenerate CA + server certs with correct Key Usage / Extended Key Usage extensions
so Python 3.10+ ssl module is satisfied.
Run from the repo root:  py gen_certs.py
"""
import datetime, ipaddress, pathlib
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = pathlib.Path(__file__).parent
SERVER_CERTS = ROOT / "custom_ssl_vpn" / "server" / "certs"
CLIENT_CERTS = ROOT / "custom_ssl_vpn" / "client" / "certs"
SERVER_CERTS.mkdir(parents=True, exist_ok=True)
CLIENT_CERTS.mkdir(parents=True, exist_ok=True)

now = datetime.datetime.now(datetime.timezone.utc)
validity = datetime.timedelta(days=3650)

# ── 1. CA key + self-signed cert ─────────────────────────────────────────────
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "Custom VPN Demo CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo"),
])
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + validity)
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True,
    )
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
    .sign(ca_key, hashes.SHA256())
)

# ── 2. Server key + CSR + cert signed by CA ──────────────────────────────────
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
server_cert = (
    x509.CertificateBuilder()
    .subject_name(server_name)
    .issuer_name(ca_name)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + validity)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True,
    )
    .add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
    )
    .add_extension(
        x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.DNSName("localhost"),
        ]), critical=False,
    )
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    .sign(ca_key, hashes.SHA256())
)

# ── 3. Write files ────────────────────────────────────────────────────────────
def pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

(SERVER_CERTS / "server.crt").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
(SERVER_CERTS / "server.key").write_bytes(pem(server_key))
ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
(CLIENT_CERTS / "ca.crt").write_bytes(ca_pem)
# also put ca.crt alongside server certs for reference
(SERVER_CERTS / "ca.crt").write_bytes(ca_pem)

print("Certificates written:")
print(f"  {SERVER_CERTS / 'server.crt'}")
print(f"  {SERVER_CERTS / 'server.key'}")
print(f"  {CLIENT_CERTS / 'ca.crt'}")
print("Done.")
