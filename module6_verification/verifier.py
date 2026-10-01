"""
Module 6 — Verification & Reporting
Owner: Elisha

Post-exam verification: confirms the exam paper's signature, the
Merkle root over collected answers, and the audit log's hash chain
are all intact. Produces a single pass/fail verdict per center.
"""

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from module1_board_prep.crypto_utils import rsa_verify
from module5_integrity_audit.audit_log import AuditLog
from module5_integrity_audit.merkle_tree import MerkleTree


def _canonical_json(data: dict) -> bytes:
    """Convert a dictionary into the same deterministic JSON format
    used by Module 1 when creating the board signature.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def _answer_to_bytes(answer) -> bytes:
    """Convert an answer record into deterministic bytes for hashing.

    Module 4 produces dictionaries, while MerkleTree accepts bytes.
    Raw bytes are also supported for compatibility.
    """
    if isinstance(answer, bytes):
        return answer

    if isinstance(answer, dict):
        return _canonical_json(answer)

    raise TypeError("Each answer must be bytes or a dictionary.")


def verify_paper_signature(
    paper_bytes: bytes,
    signature: bytes,
    board_pubkey: RSAPublicKey
) -> bool:
    """
    Verify the exam board's RSA-PSS/SHA-256 signature.

    In ExamShield, Module 1 signs the canonical JSON representation
    of the paper package metadata. Therefore, paper_bytes should be
    the exact canonical bytes that were signed.
    """
    if not isinstance(paper_bytes, bytes):
        return False

    if not isinstance(signature, bytes):
        return False

    try:
        return rsa_verify(
            paper_bytes,
            signature,
            board_pubkey
        )
    except Exception:
        return False


def verify_merkle_root(
    collected_answers: list[bytes],
    claimed_root: bytes
) -> bool:
    """
    Recompute the Merkle root from collected answers and compare it
    with the claimed root.

    Answers may be raw bytes or Module 4 submission dictionaries.
    """
    if not collected_answers:
        return False

    if not isinstance(claimed_root, bytes):
        return False

    try:
        tree = MerkleTree()

        for answer in collected_answers:
            tree.add_leaf(_answer_to_bytes(answer))

        calculated_root = tree.build_tree()

        return calculated_root == claimed_root

    except (TypeError, ValueError):
        return False


def verify_audit_chain(audit_log: AuditLog) -> bool:
    """
    Verify the hash-chained audit log for a session.
    """
    if not isinstance(audit_log, AuditLog):
        return False

    try:
        return audit_log.verify_chain()
    except Exception:
        return False


def full_post_exam_verification(
    center_id: str,
    package: dict,
    audit_log: AuditLog
) -> dict:
    """
    Run all post-exam integrity checks for one center.

    Expected package fields:

        board_public_key_pem
        signature
        canonical_data
        collected_answers
        claimed_merkle_root

    The last two fields are expected to be supplied by Module 4 /
    the exam-session workflow.
    """

    signature_valid = False
    merkle_valid = False
    audit_valid = verify_audit_chain(audit_log)

    try:
        # -----------------------------
        # 1. Verify board signature
        # -----------------------------
        public_key_pem = package["board_public_key_pem"]
        signature_b64 = package["signature"]
        canonical_data = package["canonical_data"]

        board_public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
            if isinstance(public_key_pem, str)
            else public_key_pem
        )

        signature = base64.b64decode(signature_b64)

        signed_bytes = _canonical_json(canonical_data)

        signature_valid = verify_paper_signature(
            signed_bytes,
            signature,
            board_public_key
        )

        # -----------------------------
        # 2. Verify Merkle root
        # -----------------------------
        collected_answers = package.get("collected_answers", [])
        claimed_root_value = package.get("claimed_merkle_root")

        if isinstance(claimed_root_value, str):
            claimed_root = bytes.fromhex(claimed_root_value)
        elif isinstance(claimed_root_value, bytes):
            claimed_root = claimed_root_value
        else:
            claimed_root = None

        if claimed_root is not None:
            merkle_valid = verify_merkle_root(
                collected_answers,
                claimed_root
            )

    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError
    ):
        signature_valid = False
        merkle_valid = False

    overall = (
        signature_valid
        and merkle_valid
        and audit_valid
    )

    return {
        "center_id": center_id,
        "signature_valid": signature_valid,
        "merkle_valid": merkle_valid,
        "audit_valid": audit_valid,
        "overall": overall,
    }