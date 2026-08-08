"""
Module 4 — Session Key Exchange & Answer Submission
Owner: Divya

Ephemeral Diffie-Hellman key exchange, generating a fresh session key
for every exam session to provide forward secrecy.
"""

from cryptography.hazmat.primitives.asymmetric.dh import (
    DHParameters,
    DHPrivateKey,
    DHPublicKey,
)


def generate_dh_parameters() -> DHParameters:
    """
    Generate (or load standard) Diffie-Hellman domain parameters.

    Returns:
        DHParameters shared between board and centers.
    """
    raise NotImplementedError


def generate_dh_keypair(parameters: DHParameters) -> tuple[DHPrivateKey, DHPublicKey]:
    """
    Generate an ephemeral DH keypair for one exam session.

    Args:
        parameters: shared DH domain parameters.

    Returns:
        (private_key, public_key)
    """
    raise NotImplementedError


def derive_shared_key(private_key: DHPrivateKey, peer_public_key: DHPublicKey) -> bytes:
    """
    Derive the shared session key from a local private key and peer public key.

    Args:
        private_key: this party's ephemeral DH private key.
        peer_public_key: the other party's ephemeral DH public key.

    Returns:
        derived symmetric session key (post-KDF), suitable for AES.
    """
    raise NotImplementedError


def start_new_session(center_id: str) -> dict:
    """
    Initialize a fresh DH session for a center (forward secrecy: new keys
    every session, discarded afterward).

    Args:
        center_id: identifier of the center starting the session.

    Returns:
        dict with session_id, DH keypair, and metadata.
    """
    raise NotImplementedError
