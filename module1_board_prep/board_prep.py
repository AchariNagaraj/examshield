"""
Module 1 — Exam Board Preparation & Watermarking
Owner: Joylin

Orchestration: reads a plaintext exam paper, encrypts it, embeds a
per-center watermark, signs the package, and writes it to disk ready
for distribution.
"""

from module1_board_prep.crypto_utils import (
    generate_rsa_keypair,
    aes_encrypt,
    rsa_sign,
    sha256_hash,
)
from module1_board_prep.watermark import generate_center_secret, embed_watermark


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
    raise NotImplementedError


def save_package(package: dict, output_dir: str) -> None:
    """
    Persist a prepared exam package to disk (one file per center).

    Args:
        package: output of prepare_exam_package().
        output_dir: directory to write package files into.
    """
    raise NotImplementedError
