import os
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERTS_DIR = Path("/certs")

def create_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

def save_key(key, filepath: Path):
    with open(filepath, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

def save_cert(cert, filepath: Path):
    with open(filepath, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def generate_all_certs():
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    print("[Certs] Generating Root CA...")
    ca_key = create_key()
    save_key(ca_key, CERTS_DIR / "ca.key")

    ca_subject = ca_issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureMailScope Lab CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Lab"),
    ])
    
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    save_cert(ca_cert, CERTS_DIR / "ca.crt")

    # 1. Valid Server Certificate (CA Signed)
    print("[Certs] Generating Valid CA-signed Server Certificate...")
    valid_key = create_key()
    save_key(valid_key, CERTS_DIR / "server_valid.key")
    valid_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "postfix.mailnet"),
    ])
    valid_cert = (
        x509.CertificateBuilder()
        .subject_name(valid_subject)
        .issuer_name(ca_subject)
        .public_key(valid_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("postfix.mailnet"),
                x509.DNSName("dovecot.mailnet"),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    save_cert(valid_cert, CERTS_DIR / "server_valid.crt")

    # 2. Self-Signed Server Certificate
    print("[Certs] Generating Self-Signed Server Certificate...")
    ss_key = create_key()
    save_key(ss_key, CERTS_DIR / "server_selfsigned.key")
    ss_subject = ss_issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "postfix.mailnet"),
    ])
    ss_cert = (
        x509.CertificateBuilder()
        .subject_name(ss_subject)
        .issuer_name(ss_issuer)
        .public_key(ss_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("postfix.mailnet"),
                x509.DNSName("dovecot.mailnet"),
            ]),
            critical=False,
        )
        .sign(ss_key, hashes.SHA256())
    )
    save_cert(ss_cert, CERTS_DIR / "server_selfsigned.crt")

    # 3. Expired Server Certificate (CA Signed, but expired in past)
    print("[Certs] Generating Expired CA-signed Server Certificate...")
    exp_key = create_key()
    save_key(exp_key, CERTS_DIR / "server_expired.key")
    exp_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "postfix.mailnet"),
    ])
    exp_cert = (
        x509.CertificateBuilder()
        .subject_name(exp_subject)
        .issuer_name(ca_subject)
        .public_key(exp_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2020, 1, 2, tzinfo=datetime.timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("postfix.mailnet"),
                x509.DNSName("dovecot.mailnet"),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    save_cert(exp_cert, CERTS_DIR / "server_expired.crt")

    print("[Certs] All certificates generated successfully in /certs.")

if __name__ == "__main__":
    generate_all_certs()
