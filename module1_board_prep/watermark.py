"""
Module 1 — Exam Board Preparation & Watermarking
Owner: Joylin

Per-center HMAC watermarking for leak attribution. Every exam copy
distributed to a center carries a hidden, unique HMAC tag so a leaked
copy can be traced back to its source center.
"""

import hmac
import hashlib
from .crypto_utils import sha256_hash


# --- Watermark Container Format ---
#
# Binary container structure:
#   [MAGIC: 4 bytes "EXAM"]
#   [VERSION: 1 byte = 0x01]
#   [CENTER_ID_LEN: 2 bytes, big-endian]
#   [CENTER_ID: variable length UTF-8]
#   [WATERMARK: 32 bytes (HMAC-SHA256)]
#   [PAPER_LEN: 8 bytes, big-endian]
#   [PAPER_BYTES: variable length]
#
# This format allows extraction of:
#  - center_id (for identification)
#  - watermark tag (for verification)
#  - original paper bytes (for re-hashing and watermark verification)


def generate_center_secret(center_id: str, master_secret: bytes) -> bytes:
    """
    Derive a per-center secret key from the board's master secret.

    Args:
        center_id: unique identifier for the exam center.
        master_secret: board-held master secret (never leaves the board).

    Returns:
        32-byte derived secret unique to this center.
    """
    if not center_id:
        raise ValueError("center_id cannot be empty")
    if not isinstance(master_secret, bytes) or len(master_secret) == 0:
        raise ValueError("master_secret must be non-empty bytes")

    # Derive center secret using HMAC-SHA256
    center_secret = hmac.new(
        master_secret,
        center_id.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    return center_secret


def embed_watermark(paper_bytes: bytes, center_id: str, center_secret: bytes) -> bytes:
    """
    Embed an HMAC-SHA256 watermark into the exam paper metadata.

    Watermark = HMAC-SHA256(sha256(paper_bytes) + center_id, center_secret)

    Args:
        paper_bytes: encrypted (or plaintext, pre-encryption) paper bytes.
        center_id: unique identifier for the exam center.
        center_secret: this center's derived secret.

    Returns:
        paper_bytes with watermark embedded in metadata.
    """
    if not center_id:
        raise ValueError("center_id cannot be empty")
    if not isinstance(center_secret, bytes) or len(center_secret) != 32:
        raise ValueError("center_secret must be 32 bytes")

    # Compute watermark: HMAC-SHA256(sha256(paper) + center_id, center_secret)
    paper_hash = sha256_hash(paper_bytes)
    message = paper_hash + center_id.encode("utf-8")

    watermark = hmac.new(
        center_secret,
        message,
        hashlib.sha256,
    ).digest()

    # Build the container
    center_id_bytes = center_id.encode("utf-8")

    # Pack: MAGIC(4) + VERSION(1) + ID_LEN(2) + ID + WATERMARK(32) + PAPER_LEN(8) + PAPER
    magic = b"EXAM"
    version = bytes([0x01])
    id_len = len(center_id_bytes).to_bytes(2, byteorder="big", signed=False)
    paper_len = len(paper_bytes).to_bytes(8, byteorder="big", signed=False)

    container = magic + version + id_len + center_id_bytes + watermark + paper_len + paper_bytes

    return container


def extract_watermark(watermarked_paper: bytes) -> tuple[str, bytes]:
    """
    Extract the embedded watermark from a paper.

    Args:
        watermarked_paper: paper bytes containing an embedded watermark.

    Returns:
        (center_id, watermark_tag)
    """
    # Minimum container size: 4 + 1 + 2 + 0 + 32 + 8 = 47 bytes
    if len(watermarked_paper) < 47:
        raise ValueError(
            f"Invalid watermarked paper: too short ({len(watermarked_paper)} bytes)"
        )

    # Parse magic
    magic = watermarked_paper[0:4]
    if magic != b"EXAM":
        raise ValueError(f"Invalid magic bytes: expected b'EXAM', got {magic}")

    # Parse version
    version = watermarked_paper[4]
    if version != 0x01:
        raise ValueError(f"Unsupported watermark version: {version}")

    # Parse center ID length
    offset = 5
    id_len = int.from_bytes(watermarked_paper[offset : offset + 2], byteorder="big", signed=False)
    offset += 2

    # Parse center ID
    if offset + id_len > len(watermarked_paper):
        raise ValueError("Invalid center ID length in watermark container")
    center_id = watermarked_paper[offset : offset + id_len].decode("utf-8")
    offset += id_len

    # Parse watermark tag (32 bytes)
    if offset + 32 > len(watermarked_paper):
        raise ValueError("Invalid watermark tag in container")
    watermark_tag = watermarked_paper[offset : offset + 32]
    offset += 32

    return center_id, watermark_tag


def trace_leak(leaked_paper: bytes, center_registry: dict[str, bytes]) -> str:
    """
    Given a leaked paper, determine which center it was distributed to.

    Args:
        leaked_paper: recovered/leaked paper bytes.
        center_registry: mapping of center_id -> center_secret.

    Returns:
        matched center_id, or "UNKNOWN" if no match found.
    """
    try:
        center_id, embedded_watermark = extract_watermark(leaked_paper)
    except ValueError:
        # Malformed watermark container
        return "UNKNOWN"

    # Extract the paper bytes from the container
    # Parse to get the paper bytes
    offset = 0
    offset += 4  # skip magic
    offset += 1  # skip version
    id_len = int.from_bytes(leaked_paper[offset : offset + 2], byteorder="big", signed=False)
    offset += 2
    offset += id_len  # skip center_id
    offset += 32  # skip embedded watermark
    paper_len = int.from_bytes(leaked_paper[offset : offset + 8], byteorder="big", signed=False)
    offset += 8
    paper_bytes = leaked_paper[offset : offset + paper_len]

    # Compute paper hash
    paper_hash = sha256_hash(paper_bytes)

    # Try to match the watermark against each center in the registry
    # using constant-time comparison
    for candidate_center_id, candidate_secret in center_registry.items():
        # Recompute expected watermark
        message = paper_hash + candidate_center_id.encode("utf-8")
        expected_watermark = hmac.new(
            candidate_secret,
            message,
            hashlib.sha256,
        ).digest()

        # Constant-time comparison
        if hmac.compare_digest(embedded_watermark, expected_watermark):
            # Found a match
            return candidate_center_id

    # No match found
    return "UNKNOWN"
