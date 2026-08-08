"""
Module 3 — Center Authentication (PKI / mTLS)
Owner: Divya

Mutual TLS handshake setup and authentication between exam centers and
the board/key-release server.
"""

import ssl
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
    raise NotImplementedError


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
    raise NotImplementedError


def authenticate_center(client_cert: Certificate, ca_cert: Certificate) -> bool:
    """
    Verify a presented client certificate chains to the trusted CA.

    Args:
        client_cert: certificate presented by the connecting center.
        ca_cert: trusted CA certificate.

    Returns:
        True if the certificate is valid and trusted.
    """
    raise NotImplementedError


def start_mtls_server(host: str, port: int, context: ssl.SSLContext) -> None:
    """
    Start a mutual-TLS server socket listening for center connections.

    Args:
        host: bind address.
        port: bind port.
        context: SSL context from build_ssl_context_server().
    """
    raise NotImplementedError
