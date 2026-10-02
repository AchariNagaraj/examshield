"""
Module 3 — Center Authentication (PKI / mTLS)
Owner: Divya

Sets up the PKI hierarchy: a self-signed root CA (held by the exam
board) and per-center certificates issued and signed by that CA.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from common.constants import RSA_KEY_SIZE_BITS


def generate_ca() -> tuple[RSAPrivateKey, Certificate]:
    """
    Generate a self-signed root CA keypair and certificate for the exam board.

    Returns:
        (ca_private_key, ca_certificate)
    """
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE_BITS,
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ExamShield Root CA"),
    ])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


def issue_center_cert(center_id: str, ca_key: RSAPrivateKey, ca_cert: Certificate) -> tuple[RSAPrivateKey, Certificate]:
    """
    Issue a CA-signed X.509 certificate for a specific exam center.

    Args:
        center_id: unique identifier for the exam center (used as CN/SAN).
        ca_key: CA's private key used to sign the new certificate.
        ca_cert: CA's certificate.

    Returns:
        (center_private_key, center_certificate)
    """
    if not isinstance(center_id, str) or not center_id.strip():
        raise ValueError("center_id must be a non-empty string")

    center_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE_BITS,
    )
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, center_id),
    ])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    center_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(center_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(center_id)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return center_key, center_cert


def save_cert_bundle(center_id: str, key: RSAPrivateKey, cert: Certificate, out_dir: str) -> None:
    """
    Write a center's private key and certificate to disk as PEM files.

    Args:
        center_id: identifier used to name output files.
        key: center's private key.
        cert: center's certificate.
        out_dir: directory to write <center_id>.key.pem and <center_id>.cert.pem.
    """
    if not isinstance(center_id, str) or not center_id.strip():
        raise ValueError("center_id must be a non-empty string")

    output_dir = Path(out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    key_path = output_dir / f"{center_id}.key.pem"
    cert_path = output_dir / f"{center_id}.cert.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
