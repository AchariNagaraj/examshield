"""
Module 4 — Session Key Exchange & Answer Submission
Owner: Divya

Ephemeral Diffie-Hellman key exchange, generating a fresh session key
for every exam session to provide forward secrecy.
"""

from functools import lru_cache
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dh import (
    DHParameters,
    DHPrivateKey,
    DHPublicKey,
    generate_parameters,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common.constants import AES_KEY_SIZE_BYTES, SESSION_ID_LENGTH


@lru_cache(maxsize=1)
def generate_dh_parameters() -> DHParameters:
    """
    Generate (or load standard) Diffie-Hellman domain parameters.

    Returns:
        DHParameters shared between board and centers.
    """
    return generate_parameters(generator=2, key_size=2048)


def generate_dh_keypair(parameters: DHParameters) -> tuple[DHPrivateKey, DHPublicKey]:
    """
    Generate an ephemeral DH keypair for one exam session.

    Args:
        parameters: shared DH domain parameters.

    Returns:
        (private_key, public_key)
    """
    private_key = parameters.generate_private_key()
    return private_key, private_key.public_key()


def derive_shared_key(private_key: DHPrivateKey, peer_public_key: DHPublicKey) -> bytes:
    """
    Derive the shared session key from a local private key and peer public key.

    Args:
        private_key: this party's ephemeral DH private key.
        peer_public_key: the other party's ephemeral DH public key.

    Returns:
        derived symmetric session key (post-KDF), suitable for AES.
    """
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE_BYTES,
        salt=None,
        info=b"ExamShield DH session key",
    ).derive(shared_secret)


def start_new_session(center_id: str) -> dict:
    """
    Initialize a fresh DH session for a center (forward secrecy: new keys
    every session, discarded afterward).

    Args:
        center_id: identifier of the center starting the session.

    Returns:
        dict with session_id, DH keypair, and metadata.
    """
    if not isinstance(center_id, str) or not center_id.strip():
        raise ValueError("center_id must be a non-empty string")

    parameters = generate_dh_parameters()
    private_key, public_key = generate_dh_keypair(parameters)
    return {
        "session_id": secrets.token_hex(SESSION_ID_LENGTH),
        "parameters": parameters,
        "private_key": private_key,
        "public_key": public_key,
        "metadata": {"center_id": center_id},
    }
