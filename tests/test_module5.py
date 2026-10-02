"""
Tests for Module 5 — Integrity & Audit Log.
"""

import json

import pytest

from module5_integrity_audit.merkle_tree import MerkleTree
from module5_integrity_audit.audit_log import AuditLog


# -------------------------
# Merkle Tree Tests
# -------------------------

def test_merkle_tree_builds_root():
    tree = MerkleTree()

    tree.add_leaf(b"Answer 1")
    tree.add_leaf(b"Answer 2")

    root = tree.build_tree()

    assert isinstance(root, bytes)
    assert len(root) == 32


def test_merkle_proof_verifies_valid_leaf():
    tree = MerkleTree()

    tree.add_leaf(b"Answer 1")
    tree.add_leaf(b"Answer 2")
    tree.add_leaf(b"Answer 3")

    root = tree.build_tree()
    proof = tree.get_proof(0)

    assert tree.verify_proof(
        b"Answer 1",
        proof,
        root
    )


def test_merkle_proof_rejects_tampered_leaf():
    tree = MerkleTree()

    tree.add_leaf(b"Answer 1")
    tree.add_leaf(b"Answer 2")

    root = tree.build_tree()
    proof = tree.get_proof(0)

    assert not tree.verify_proof(
        b"Changed Answer",
        proof,
        root
    )


def test_merkle_tree_rejects_invalid_leaf_index():
    tree = MerkleTree([b"Answer 1"])

    tree.build_tree()

    with pytest.raises(IndexError):
        tree.get_proof(5)


def test_merkle_tree_handles_odd_number_of_leaves():
    tree = MerkleTree()

    tree.add_leaf(b"Answer 1")
    tree.add_leaf(b"Answer 2")
    tree.add_leaf(b"Answer 3")

    root = tree.build_tree()

    assert isinstance(root, bytes)
    assert len(root) == 32


# -------------------------
# Audit Log Tests
# -------------------------

def test_audit_log_starts_empty():
    log = AuditLog()

    assert log.get_chain() == []
    assert log.verify_chain()


def test_audit_log_add_entry():
    log = AuditLog()

    entry_hash = log.add_entry(
        "CENTER_AUTHENTICATED",
        {"center_id": "CENTER01"}
    )

    assert isinstance(entry_hash, bytes)
    assert len(entry_hash) == 32
    assert len(log.get_chain()) == 1


def test_audit_log_chain_verifies():
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

    assert log.verify_chain()


def test_audit_log_detects_tampering():
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

    assert log.verify_chain()

    # Simulate tampering with an existing audit entry.
    log._chain[0]["event"] = "TAMPERED"

    assert not log.verify_chain()


def test_audit_log_export(tmp_path):
    log = AuditLog()

    log.add_entry(
        "CENTER_AUTHENTICATED",
        {"center_id": "CENTER01"}
    )

    output_file = tmp_path / "audit_log.json"

    log.export_log(str(output_file))

    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    assert len(data) == 1
    assert data[0]["event"] == "CENTER_AUTHENTICATED"