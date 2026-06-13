
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

def generate_self_signed_cert():
    # Create tls_certs directory if it doesn't exist
    if not os.path.exists("tls_certs"):
        os.makedirs("tls_certs")
        print("Created tls_certs directory")

    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Write private key to file
    with open("tls_certs/server.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print("Generated tls_certs/server.key")

    # Generate a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Sindh"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Karachi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"VotingServer"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 365 days
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())

    # Write certificate to file
    with open("tls_certs/server.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("Generated tls_certs/server.crt")

if __name__ == "__main__":
    generate_self_signed_cert()
