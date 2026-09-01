"""
Module 1 — Exam Board Preparation & Watermarking
Owner: Joylin

Core cryptographic primitives used by the exam board to encrypt and sign
exam papers before distribution to centers.
"""

import os
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization


def generate_rsa_keypair(key_size: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Generate an RSA keypair for the exam board.

    Args:
        key_size: RSA key size in bits (2048 or 4096).

    Returns:
        (private_key, public_key)
    """
    if key_size not in (2048, 4096):
        raise ValueError(f"Unsupported RSA key size: {key_size}. Must be 2048 or 4096 bits.")

    private_key = generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt data with AES-256-GCM.

    Args:
        plaintext: raw bytes to encrypt.
        key: 32-byte AES key.

    Returns:
        (ciphertext, nonce, tag)
    """
    if len(key) != 32:
        raise ValueError(f"AES key must be exactly 32 bytes, got {len(key)}")

    # Generate a fresh 12-byte nonce for this encryption
    nonce = os.urandom(12)

    # Encrypt using AES-GCM
    cipher = AESGCM(key)
    encrypted = cipher.encrypt(nonce, plaintext, None)

    # AESGCM.encrypt() returns ciphertext + tag concatenated
    # Split: last 16 bytes are the tag, rest is ciphertext
    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]

    return ciphertext, nonce, tag


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
    if len(key) != 32:
        raise ValueError(f"AES key must be exactly 32 bytes, got {len(key)}")

    # Reconstruct the full encrypted data (ciphertext + tag)
    encrypted = ciphertext + tag

    # Decrypt using AES-GCM
    cipher = AESGCM(key)
    plaintext = cipher.decrypt(nonce, encrypted, None)

    return plaintext


def rsa_sign(data: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Sign data with the board's RSA private key (PSS padding, SHA-256).

    Args:
        data: bytes to sign (e.g. hash of exam package).
        private_key: board's RSA private key.

    Returns:
        signature bytes.
    """
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


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
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        # Any verification failure (InvalidSignature, etc.) returns False
        return False


def sha256_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of data.

    Args:
        data: input bytes.

    Returns:
        32-byte hash digest.
    """
    from cryptography.hazmat.backends import default_backend

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()


def _rsa_wrap_key(aes_key: bytes, public_key: RSAPublicKey) -> bytes:
    """
    Wrap an AES key using RSA-OAEP-SHA256.

    Args:
        aes_key: raw AES-256 key (32 bytes).
        public_key: RSA public key for wrapping.

    Returns:
        encrypted/wrapped key bytes.
    """
    wrapped = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped
