"""
Module 1 — Exam Board Preparation & Watermarking
Owner: Joylin

Per-center HMAC watermarking for leak attribution. Every exam copy
distributed to a center carries a hidden, unique HMAC tag so a leaked
copy can be traced back to its source center.
"""


def generate_center_secret(center_id: str, master_secret: bytes) -> bytes:
    """
    Derive a per-center secret key from the board's master secret.

    Args:
        center_id: unique identifier for the exam center.
        master_secret: board-held master secret (never leaves the board).

    Returns:
        32-byte derived secret unique to this center.
    """
    raise NotImplementedError


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
    raise NotImplementedError


def extract_watermark(watermarked_paper: bytes) -> tuple[str, bytes]:
    """
    Extract the embedded watermark from a paper.

    Args:
        watermarked_paper: paper bytes containing an embedded watermark.

    Returns:
        (center_id, watermark_tag)
    """
    raise NotImplementedError


def trace_leak(leaked_paper: bytes, center_registry: dict[str, bytes]) -> str:
    """
    Given a leaked paper, determine which center it was distributed to.

    Args:
        leaked_paper: recovered/leaked paper bytes.
        center_registry: mapping of center_id -> center_secret.

    Returns:
        matched center_id, or "UNKNOWN" if no match found.
    """
    raise NotImplementedError
