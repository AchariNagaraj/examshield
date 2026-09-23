"""
Module 1 — Exam Board Preparation & Watermarking
Owner: Joylin

Orchestration: reads a plaintext exam paper, encrypts it, embeds a
per-center watermark, signs the package, and writes it to disk ready
for distribution.
"""

import json
import os
from base64 import b64encode, b64decode
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.exceptions import UnsupportedAlgorithm

from common.constants import CERTS_DIR
from module1_board_prep.crypto_utils import (
    generate_rsa_keypair,
    aes_encrypt,
    rsa_sign,
    sha256_hash,
    _rsa_wrap_key,
)
from module1_board_prep.watermark import generate_center_secret, embed_watermark


def _load_center_public_key(center_id: str) -> RSAPublicKey:
    """Load and validate the RSA public key embedded in a center certificate."""
    if not center_id or not center_id.strip():
        raise ValueError("center_id cannot be empty")

    cert_dir = Path(CERTS_DIR).resolve(strict=False)
    candidate = (cert_dir / f"{center_id}.cert.pem").resolve(strict=False)
    if candidate != cert_dir / f"{center_id}.cert.pem" and cert_dir not in candidate.parents:
        raise ValueError(f"Invalid center_id: {center_id}")

    if not candidate.exists():
        raise FileNotFoundError(f"Certificate not found for center '{center_id}' at '{candidate}'")

    try:
        with open(candidate, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValueError(f"Invalid certificate for center '{center_id}'") from exc

    public_key = cert.public_key()
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError(f"Certificate for center '{center_id}' does not contain an RSA public key")

    return public_key


def prepare_exam_package(paper_path: str, center_ids: list[str], master_secret: bytes) -> dict:
    """
    Build a signed, encrypted, watermarked exam package per center.

    Steps:
        1. Read plaintext paper from paper_path.
        2. AES-256-GCM encrypt the paper.
        3. For each center_id, derive a center secret and embed a watermark.
        4. RSA-sign the final package hash with the board's private key.

    Args:
        paper_path: filesystem path to the plaintext exam paper.
        center_ids: list of center identifiers to prepare packages for.
        master_secret: board's master secret for watermark derivation.

    Returns:
        dict containing per-center encrypted+watermarked packages, the
        wrapped AES key, and the board's signature.
    """
    # Validate inputs
    if not center_ids:
        raise ValueError("center_ids cannot be empty")
    if not isinstance(master_secret, bytes) or len(master_secret) == 0:
        raise ValueError("master_secret must be non-empty bytes")

    # Step 1: Read the paper
    if not os.path.exists(paper_path):
        raise FileNotFoundError(f"Paper file not found: {paper_path}")

    with open(paper_path, "rb") as f:
        paper_bytes = f.read()

    if not paper_bytes:
        raise ValueError("Paper file is empty")

    # Step 2: Generate AES-256 key and RSA keypair
    aes_key = os.urandom(32)  # 256 bits
    board_private_key, board_public_key = generate_rsa_keypair(key_size=2048)

    # Step 3: Encrypt the paper
    ciphertext, nonce, tag = aes_encrypt(paper_bytes, aes_key)

    # Step 4: For each center, load the center's certificate and wrap the AES key
    # using the center's RSA public key. This allows Module 2 to unwrap using the
    # center's private key while preserving a board signature over the package.
    centers_data = {}
    wrapped_key_hashes = {}
    for center_id in center_ids:
        center_public_key = _load_center_public_key(center_id)
        wrapped_aes_key = _rsa_wrap_key(aes_key, center_public_key)

        # Derive center secret and watermark the shared ciphertext for this center.
        center_secret = generate_center_secret(center_id, master_secret)
        watermarked_paper = embed_watermark(ciphertext, center_id, center_secret)

        centers_data[center_id] = {
            "watermarked_paper": b64encode(watermarked_paper).decode("utf-8"),
            "ciphertext": b64encode(ciphertext).decode("utf-8"),
            "nonce": b64encode(nonce).decode("utf-8"),
            "tag": b64encode(tag).decode("utf-8"),
            "wrapped_key": b64encode(wrapped_aes_key).decode("utf-8"),
        }
        wrapped_key_hashes[center_id] = b64encode(sha256_hash(wrapped_aes_key)).decode("utf-8")

    # Step 5: Create a deterministic canonical representation for signing.
    # Include the wrapped-key hashes per center so any tampering invalidates the board signature.
    canonical_data = {
        "version": "1.0",
        "algorithm": {
            "encryption": "AES-256-GCM",
            "key_wrap": "RSA-OAEP-SHA256",
            "signature": "RSA-PSS-SHA256",
            "watermark": "HMAC-SHA256",
        },
        "ciphertext_hash": b64encode(sha256_hash(ciphertext)).decode("utf-8"),
        "nonce": b64encode(nonce).decode("utf-8"),
        "tag": b64encode(tag).decode("utf-8"),
        "wrapped_key_hashes": wrapped_key_hashes,
        "center_ids": sorted(center_ids),
    }

    # Convert to deterministic JSON string for signing
    canonical_json = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
    canonical_bytes = canonical_json.encode("utf-8")

    # Step 7: Sign the canonical data
    signature = rsa_sign(canonical_bytes, board_private_key)

    # Step 8: Serialize board public key for inclusion in package
    public_key_pem = board_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Step 9: Build final package
    package = {
        "version": "1.0",
        "algorithm": {
            "encryption": "AES-256-GCM",
            "key_wrap": "RSA-OAEP-SHA256",
            "signature": "RSA-PSS-SHA256",
            "watermark": "HMAC-SHA256",
        },
        "board_public_key_pem": public_key_pem.decode("utf-8"),
        "centers": centers_data,
        "signature": b64encode(signature).decode("utf-8"),
        "canonical_data": canonical_data,
    }

    return package


def save_package(package: dict, output_dir: str) -> None:
    """
    Persist a prepared exam package to disk (one file per center).

    Args:
        package: output of prepare_exam_package().
        output_dir: directory to write package files into.
    """
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Extract centers data
    centers_data = package.get("centers", {})
    board_public_key_pem = package.get("board_public_key_pem", "")
    signature = package.get("signature", "")
    canonical_data = package.get("canonical_data", {})
    algorithm = package.get("algorithm", {})

    # Save one file per center
    for center_id, center_info in centers_data.items():
        # Sanitize center_id for use in filename (avoid path traversal)
        safe_center_id = center_id.replace("/", "_").replace("\\", "_").replace("..", "__")

        # Create per-center package
        center_package = {
            "version": package.get("version", "1.0"),
            "algorithm": algorithm,
            "board_public_key_pem": board_public_key_pem,
            "center_id": center_id,
            "watermarked_paper": center_info.get("watermarked_paper", ""),
            "ciphertext": center_info.get("ciphertext", ""),
            "nonce": center_info.get("nonce", ""),
            "tag": center_info.get("tag", ""),
            "wrapped_key": center_info.get("wrapped_key", ""),
            "signature": signature,
            "canonical_data": canonical_data,
        }

        # Write to file
        filename = f"{safe_center_id}_exam_package.json"
        filepath = output_path / filename

        with open(filepath, "w") as f:
            json.dump(center_package, f, indent=2)

        print(f"Saved package for {center_id}: {filepath}")
