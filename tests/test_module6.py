"""
Tests for Module 6 — Verification & Reporting.
"""

import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from module1_board_prep.crypto_utils import rsa_sign
from module5_integrity_audit.audit_log import AuditLog
from module5_integrity_audit.merkle_tree import MerkleTree
from module6_verification.verifier import (
    _canonical_json,
    verify_paper_signature,
    verify_merkle_root,
    verify_audit_chain,
    full_post_exam_verification,
)


def create_test_rsa_keypair():
    """Create a temporary RSA key pair for testing."""

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key


def test_verify_paper_signature():
    """Valid board signature should be accepted."""

    private_key, public_key = create_test_rsa_keypair()

    data = _canonical_json({
        "center_id": "CENTER01",
        "ciphertext_hash": "abc123"
    })

    signature = rsa_sign(data, private_key)

    assert verify_paper_signature(
        data,
        signature,
        public_key
    )


def test_verify_paper_signature_rejects_tampering():
    """Modified paper metadata should fail signature verification."""

    private_key, public_key = create_test_rsa_keypair()

    original_data = _canonical_json({
        "center_id": "CENTER01",
        "ciphertext_hash": "abc123"
    })

    tampered_data = _canonical_json({
        "center_id": "CENTER01",
        "ciphertext_hash": "changed"
    })

    signature = rsa_sign(original_data, private_key)

    assert not verify_paper_signature(
        tampered_data,
        signature,
        public_key
    )


def test_verify_merkle_root():
    """Correct answers should produce the claimed Merkle root."""

    answers = [
        b"Answer 1",
        b"Answer 2",
        b"Answer 3"
    ]

    tree = MerkleTree(answers)
    claimed_root = tree.build_tree()

    assert verify_merkle_root(
        answers,
        claimed_root
    )


def test_verify_merkle_root_rejects_tampering():
    """Changed answer should produce a different Merkle root."""

    original_answers = [
        b"Answer 1",
        b"Answer 2"
    ]

    tampered_answers = [
        b"Changed Answer",
        b"Answer 2"
    ]

    tree = MerkleTree(original_answers)
    claimed_root = tree.build_tree()

    assert not verify_merkle_root(
        tampered_answers,
        claimed_root
    )


def test_verify_audit_chain():
    """Valid audit log should pass verification."""

    log = AuditLog()

    log.add_entry(
        "CENTER_AUTHENTICATED",
        {"center_id": "CENTER01"}
    )

    log.add_entry(
        "ANSWER_SUBMITTED",
        {
            "student_id": "S001",
            "question_id": "Q1"
        }
    )

    assert verify_audit_chain(log)


def test_verify_audit_chain_rejects_tampering():
    """Modified audit entry should fail verification."""

    log = AuditLog()

    log.add_entry(
        "CENTER_AUTHENTICATED",
        {"center_id": "CENTER01"}
    )

    log.add_entry(
        "ANSWER_SUBMITTED",
        {
            "student_id": "S001",
            "question_id": "Q1"
        }
    )

    log._chain[0]["event"] = "TAMPERED"

    assert not verify_audit_chain(log)


def test_full_post_exam_verification():
    """All verification checks should pass for an intact package."""

    private_key, public_key = create_test_rsa_keypair()

    # -----------------------------
    # Paper signature
    # -----------------------------

    canonical_data = {
        "center_id": "CENTER01",
        "ciphertext_hash": "abc123"
    }

    signed_bytes = _canonical_json(canonical_data)

    signature = rsa_sign(
        signed_bytes,
        private_key
    )

    # -----------------------------
    # Answers + Merkle root
    # -----------------------------

    answers = [
        b"Answer 1",
        b"Answer 2",
        b"Answer 3"
    ]

    tree = MerkleTree(answers)
    claimed_root = tree.build_tree()

    # -----------------------------
    # Audit log
    # -----------------------------

    audit_log = AuditLog()

    audit_log.add_entry(
        "CENTER_AUTHENTICATED",
        {"center_id": "CENTER01"}
    )

    audit_log.add_entry(
        "ANSWER_SUBMITTED",
        {"student_id": "S001"}
    )

    # -----------------------------
    # Public key
    # -----------------------------

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # -----------------------------
    # Package
    # -----------------------------

    package = {
        "board_public_key_pem": public_key_pem,
        "signature": base64.b64encode(signature).decode("utf-8"),
        "canonical_data": canonical_data,
        "collected_answers": answers,
        "claimed_merkle_root": claimed_root
    }

    result = full_post_exam_verification(
        "CENTER01",
        package,
        audit_log
    )

    assert result["center_id"] == "CENTER01"
    assert result["signature_valid"]
    assert result["merkle_valid"]
    assert result["audit_valid"]
    assert result["overall"]


def test_full_post_exam_verification_detects_tampered_answer():
    """Full verification should fail if an answer is modified."""

    private_key, public_key = create_test_rsa_keypair()

    canonical_data = {
        "center_id": "CENTER01",
        "ciphertext_hash": "abc123"
    }

    signed_bytes = _canonical_json(canonical_data)
    signature = rsa_sign(signed_bytes, private_key)

    original_answers = [
        b"Answer 1",
        b"Answer 2"
    ]

    tree = MerkleTree(original_answers)
    claimed_root = tree.build_tree()

    audit_log = AuditLog()
    audit_log.add_entry(
        "ANSWER_SUBMITTED",
        {"student_id": "S001"}
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    package = {
        "board_public_key_pem": public_key_pem,
        "signature": base64.b64encode(signature).decode("utf-8"),
        "canonical_data": canonical_data,

        # Tampered answer
        "collected_answers": [
            b"Changed Answer",
            b"Answer 2"
        ],

        # Root was created from the original answers
        "claimed_merkle_root": claimed_root
    }

    result = full_post_exam_verification(
        "CENTER01",
        package,
        audit_log
    )

    assert result["signature_valid"]
    assert not result["merkle_valid"]
    assert result["audit_valid"]
    assert not result["overall"]
from module6_verification.report_generator import (
    generate_integrity_report,
    export_report_pdf,
)


def test_generate_integrity_report():
    """Integrity report should contain all verification results."""

    verification_result = {
        "center_id": "CENTER01",
        "signature_valid": True,
        "merkle_valid": True,
        "audit_valid": True,
        "overall": True,
    }

    report = generate_integrity_report(
        verification_result,
        "CENTER01"
    )

    assert "EXAMSHIELD INTEGRITY REPORT" in report
    assert "CENTER01" in report
    assert "Paper Signature Verification : PASS" in report
    assert "Answer Merkle Root            : PASS" in report
    assert "Audit Log Verification        : PASS" in report
    assert "Overall Integrity Status      : PASS" in report


def test_generate_failed_integrity_report():
    """Failed verification should appear as FAIL in the report."""

    verification_result = {
        "signature_valid": True,
        "merkle_valid": False,
        "audit_valid": True,
        "overall": False,
    }

    report = generate_integrity_report(
        verification_result,
        "CENTER01"
    )

    assert "Answer Merkle Root            : FAIL" in report
    assert "Overall Integrity Status      : FAIL" in report


def test_export_report_pdf(tmp_path):
    """PDF report should be successfully created."""

    report = generate_integrity_report(
        {
            "signature_valid": True,
            "merkle_valid": True,
            "audit_valid": True,
            "overall": True,
        },
        "CENTER01"
    )

    output_file = tmp_path / "integrity_report.pdf"

    export_report_pdf(
        report,
        str(output_file)
    )

    assert output_file.exists()
    assert output_file.stat().st_size > 0