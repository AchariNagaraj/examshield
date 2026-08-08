"""
Module 3 — Center Authentication (PKI / mTLS)
Owner: Divya

Sets up the PKI hierarchy: a self-signed root CA (held by the exam
board) and per-center certificates issued and signed by that CA.
"""

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509 import Certificate


def generate_ca() -> tuple[RSAPrivateKey, Certificate]:
    """
    Generate a self-signed root CA keypair and certificate for the exam board.

    Returns:
        (ca_private_key, ca_certificate)
    """
    raise NotImplementedError


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
    raise NotImplementedError


def save_cert_bundle(center_id: str, key: RSAPrivateKey, cert: Certificate, out_dir: str) -> None:
    """
    Write a center's private key and certificate to disk as PEM files.

    Args:
        center_id: identifier used to name output files.
        key: center's private key.
        cert: center's certificate.
        out_dir: directory to write <center_id>.key.pem and <center_id>.cert.pem.
    """
    raise NotImplementedError
