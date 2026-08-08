"""
Module 1 — Exam Board Preparation & Watermarking
Owner: Joylin

Core cryptographic primitives used by the exam board to encrypt and sign
exam papers before distribution to centers.
"""

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def generate_rsa_keypair(key_size: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generate an RSA keypair for the exam board.

    Args:
        key_size: RSA key size in bits (2048 or 4096).

    Returns:
        (private_key, public_key)
    """
    raise NotImplementedError


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt data with AES-256-GCM.

    Args:
        plaintext: raw bytes to encrypt.
        key: 32-byte AES key.

    Returns:
        (ciphertext, nonce, tag)
    """
    raise NotImplementedError


def aes_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.

    Args:
        ciphertext: encrypted bytes.
        key: 32-byte AES key.
        nonce: nonce used during encryption.
        tag: GCM authentication tag.

    Returns:
        plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag if tampered/wrong key.
    """
    raise NotImplementedError


def rsa_sign(data: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Sign data with the board's RSA private key (PSS padding, SHA-256).

    Args:
        data: bytes to sign (e.g. hash of exam package).
        private_key: board's RSA private key.

    Returns:
        signature bytes.
    """
    raise NotImplementedError


def rsa_verify(data: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    """
    Verify an RSA signature.

    Args:
        data: original signed bytes.
        signature: signature to verify.
        public_key: signer's RSA public key.

    Returns:
        True if signature is valid, False otherwise.
    """
    raise NotImplementedError


def sha256_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of data.

    Args:
        data: input bytes.

    Returns:
        32-byte hash digest.
    """
    raise NotImplementedError
