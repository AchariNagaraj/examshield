"""
Module 3 — Center Authentication (PKI / mTLS)
Owner: Divya

Mutual TLS handshake setup and authentication between exam centers and
the board/key-release server.
"""

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate


def build_ssl_context_server(ca_cert_path: str, server_cert_path: str, server_key_path: str) -> ssl.SSLContext:
    """
    Build an SSL context for the server side, requiring client certificates.

    Args:
        ca_cert_path: path to CA certificate (to verify client certs).
        server_cert_path: path to server's certificate.
        server_key_path: path to server's private key.

    Returns:
        configured ssl.SSLContext with CERT_REQUIRED for clients.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_verify_locations(cafile=ca_cert_path)
    context.load_cert_chain(certfile=server_cert_path, keyfile=server_key_path)
    context.verify_mode = ssl.CERT_REQUIRED
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


def build_ssl_context_client(ca_cert_path: str, client_cert_path: str, client_key_path: str) -> ssl.SSLContext:
    """
    Build an SSL context for the client (center) side.

    Args:
        ca_cert_path: path to CA certificate (to verify server cert).
        client_cert_path: path to this center's certificate.
        client_key_path: path to this center's private key.

    Returns:
        configured ssl.SSLContext presenting the client certificate.
    """
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert_path)
    context.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


def authenticate_center(client_cert: Certificate, ca_cert: Certificate) -> bool:
    """
    Verify a presented client certificate chains to the trusted CA.

    Args:
        client_cert: certificate presented by the connecting center.
        ca_cert: trusted CA certificate.

    Returns:
        True if the certificate is valid and trusted.
    """
    if not isinstance(client_cert, Certificate) or not isinstance(ca_cert, Certificate):
        return False
    if client_cert.issuer != ca_cert.subject:
        return False

    ca_public_key = ca_cert.public_key()
    try:
        if isinstance(ca_public_key, RSAPublicKey):
            ca_public_key.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                client_cert.signature_hash_algorithm,
            )
        elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                ec.ECDSA(client_cert.signature_hash_algorithm),
            )
        else:
            return False
    except Exception:
        return False

    now = datetime.now(timezone.utc)
    if now < client_cert.not_valid_before_utc or now > client_cert.not_valid_after_utc:
        return False

    return True


def start_mtls_server(host: str, port: int, context: ssl.SSLContext) -> None:
    """
    Start a mutual-TLS server socket listening for center connections.

    Args:
        host: bind address.
        port: bind port.
        context: SSL context from build_ssl_context_server().
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen()

        with context.wrap_socket(server_socket, server_side=True) as tls_server:
            while True:
                try:
                    client_socket, _ = tls_server.accept()
                    with client_socket:
                        client_socket.do_handshake()
                except (ssl.SSLError, ConnectionError):
                    continue
