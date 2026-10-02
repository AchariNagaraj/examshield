"""
ExamShield — End-to-End Integration Demo

Ties all six modules together into a single runnable flow for the viva
demonstration. Each stage is implemented by its respective module owner;
this script only orchestrates calls across modules.

Run once all modules are implemented:
    python demo_flow.py
"""
import base64
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

# Module 1 — Joylin
from module1_board_prep.board_prep import prepare_exam_package, save_package

# Module 2 — Nagaraj
from module2_key_release.key_release_engine import KeyReleaseEngine

# Module 3 — Divya
from module3_center_auth.pki_setup import (
    generate_ca,
    issue_center_cert,
    save_cert_bundle,
)
from module3_center_auth.mtls_auth import authenticate_center

# Module 4 — Divya
from module4_session_answers.dh_session import (
    start_new_session,
    generate_dh_keypair,
    derive_shared_key,
)
from module4_session_answers.answer_submission import (
    encrypt_answer,
    submit_answer,
    batch_collect_answers,
)

# Module 5 — Elisha
from module5_integrity_audit.merkle_tree import MerkleTree
from module5_integrity_audit.audit_log import AuditLog

# Module 6 — Elisha
from module6_verification.verifier import full_post_exam_verification
from module6_verification.report_generator import generate_integrity_report


def run_full_demo():
    """
    Orchestrates the complete ExamShield flow:

        1. Board prepares & signs the exam package (Module 1).
        2. Center authenticates via mTLS/PKI (Module 3).
        3. Adaptive engine approves and releases the AES key (Module 2).
        4. Center runs the exam; students submit answers over a fresh
           DH session (Module 4).
        5. Answers are hashed into a Merkle tree; every step is recorded
           in a hash-chained audit log (Module 5).
        6. Board verifies the signature, Merkle root, and audit chain,
           and generates the final integrity report (Module 6).
    """
    print("=== ExamShield End-to-End Demo ===")

    # 1. Center certificate setup (Module 3)
    ca_key, ca_cert = generate_ca()

    center_key, center_cert = issue_center_cert(
        "center_001",
        ca_key,
        ca_cert
    )

    save_cert_bundle(
        "center_001",
        center_key,
        center_cert,
        "certs/"
    )
    from cryptography.hazmat.primitives import serialization

    with open("certs/examshield_ca.cert.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print("✓ Center certificate generated")

    # 2. Center authentication (Module 3)
    authenticated = authenticate_center(
        center_cert,
        ca_cert
    )

    print(f"✓ Center authentication: {authenticated}")

    # 3. Board preparation (Module 1)
    package = prepare_exam_package(
        "sample_exam.txt",
        ["center_001"],
        b"examshield-demo-secret"
    )

    save_package(package, "data/")

    print("✓ Exam package prepared")
    # 4. Adaptive key release (Module 2)
    exam_start_time = datetime.now(timezone.utc)

    # Demo board key used to sign the release timestamp.
    board_timestamp_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    engine = KeyReleaseEngine(
        exam_start_time=exam_start_time,
        valid_window_sec=300
    )

    engine.board_pubkey = board_timestamp_key.public_key()
    engine.ca_cert = ca_cert

    # Create a board-signed timestamp.
    timestamp_text = exam_start_time.isoformat().replace("+00:00", "Z")

    timestamp_signature = board_timestamp_key.sign(
        timestamp_text.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signed_timestamp = json.dumps({
        "timestamp": timestamp_text,
        "signature": base64.b64encode(timestamp_signature).decode("ascii")
    }, separators=(",", ":")).encode("utf-8")

    # Read the center certificate.
    with open("certs/center_001.cert.pem", "rb") as f:
        center_cert_bytes = f.read()

    approved, reason = engine.request_release(
        "center_001",
        center_cert_bytes,
        signed_timestamp,
        0.1
    )

    print(f"✓ Key release request: {approved} ({reason})")

    # 5. Session + answer submission (Module 4)

    session = start_new_session("center_001")

    # Generate a second DH keypair to simulate the peer side.

    peer_private, peer_public = generate_dh_keypair(
        session["parameters"]
    )

    # Derive the same session key on both sides.
    center_session_key = derive_shared_key(
        session["private_key"],
        peer_public
    )

    peer_session_key = derive_shared_key(
        peer_private,
        session["public_key"]
    )

    print(f"✓ DH session established: {center_session_key == peer_session_key}")

    # Encrypt student answers.
    ciphertext1, nonce1, tag1 = encrypt_answer(
        "AES provides confidentiality for examination data.",
        center_session_key
    )

    ciphertext2, nonce2, tag2 = encrypt_answer(
        "A Merkle Tree helps verify data integrity.",
        center_session_key
    )

    # Submit answers.
    record1 = submit_answer(
        "student_001",
        "q1",
        ciphertext1,
        session["session_id"]
    )

    record2 = submit_answer(
        "student_002",
        "q2",
        ciphertext2,
        session["session_id"]
    )

    collected_answers = batch_collect_answers(
        [record1, record2]
    )

    print(f"✓ Answers collected: {len(collected_answers)}")
        # 6. Integrity: Merkle tree + audit log (Module 5)

    tree = MerkleTree()
    audit = AuditLog()

    # Create deterministic Merkle leaves from submitted answers.
    answer_leaves = []

    for record in collected_answers:
        leaf_data = json.dumps(
            {
                "student_id": record["student_id"],
                "question_id": record["question_id"],
                "encrypted_answer": base64.b64encode(
                    record["encrypted_answer"]
                ).decode("ascii"),
                "session_id": record["session_id"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        answer_leaves.append(leaf_data)
        tree.add_leaf(leaf_data)

        audit.add_entry(
            "ANSWER_SUBMITTED",
            {
                "student_id": record["student_id"],
                "question_id": record["question_id"],
                "session_id": record["session_id"],
                "answer_hash": __import__("hashlib")
                .sha256(leaf_data)
                .hexdigest(),
            },
        )

    merkle_root = tree.build_tree()

    print(f"✓ Merkle root generated: {merkle_root.hex()[:16]}...")
    print(f"✓ Audit log entries: {len(audit.get_chain())}")
    print(f"✓ Audit chain valid: {audit.verify_chain()}")
        # 7. Post-exam verification + report (Module 6)

    verification_package = dict(package)

    verification_package["collected_answers"] = answer_leaves
    verification_package["claimed_merkle_root"] = merkle_root.hex()

    result = full_post_exam_verification(
        "center_001",
        verification_package,
        audit,
    )

    print(f"✓ Signature verification: {result['signature_valid']}")
    print(f"✓ Merkle verification: {result['merkle_valid']}")
    print(f"✓ Audit verification: {result['audit_valid']}")
    print(f"✓ Overall integrity: {result['overall']}")

    report = generate_integrity_report(
        result,
        "center_001",
    )

    print("\n" + report)

    print("Demo flow scaffolded — fill in each module to run end-to-end.")


if __name__ == "__main__":
    run_full_demo()