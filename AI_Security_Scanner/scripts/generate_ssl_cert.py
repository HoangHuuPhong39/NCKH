# -*- coding: utf-8 -*-
"""
scripts/generate_ssl_cert.py - Self-Signed SSL/TLS Certificate Generator

Generates a local 2048-bit RSA private key and self-signed certificate
for HTTPS development, testing, and staging deployments.
"""

import os
import subprocess
import sys
from pathlib import Path


def generate_certificates(cert_dir: str = "certs", domain: str = "localhost"):
    out_dir = Path(cert_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    key_file = out_dir / "server.key"
    cert_file = out_dir / "server.crt"

    if key_file.exists() and cert_file.exists():
        print(f"[+] Certificates already exist in {out_dir}/:")
        print(f"    - Key:  {key_file}")
        print(f"    - Cert: {cert_file}")
        return

    print(f"[*] Generating self-signed SSL/TLS certificate for domain: {domain}")

    # Check for OpenSSL CLI
    try:
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_file),
            "-out", str(cert_file),
            "-days", "365",
            "-nodes",
            "-subj", f"/CN={domain}/O=AI Security Scanner Lab/C=VN"
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[+] Generated self-signed certificates successfully:")
        print(f"    - Key:  {key_file}")
        print(f"    - Cert: {cert_file}")
        return
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Python cryptography library fallback
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AI Security Scanner"),
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain), x509.DNSName("127.0.0.1")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"[+] Python cryptography generated certificates successfully:")
        print(f"    - Key:  {key_file}")
        print(f"    - Cert: {cert_file}")
    except ImportError:
        print("[!] OpenSSL CLI and python cryptography package not found.", file=sys.stderr)
        print("[!] Please install openssl or run: pip install cryptography", file=sys.stderr)


if __name__ == "__main__":
    domain_name = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    generate_certificates("certs", domain_name)
