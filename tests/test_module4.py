"""Tests for Module 4 — Session Key Exchange & Answer Submission."""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from module4_session_answers.dh_session import (
    derive_shared_key,
    generate_dh_keypair,
    generate_dh_parameters,
    start_new_session,
)
from module4_session_answers.answer_submission import (
    encrypt_answer,
    submit_answer,
    batch_collect_answers,
)


def test_dh_parties_derive_same_shared_key():
    parameters = generate_dh_parameters()
    private_a, public_a = generate_dh_keypair(parameters)
    private_b, public_b = generate_dh_keypair(parameters)

    key_a = derive_shared_key(private_a, public_b)
    key_b = derive_shared_key(private_b, public_a)

    assert key_a == key_b
    assert len(key_a) == 32


def test_new_sessions_have_unique_ids():
    session_a = start_new_session("CENTER-001")
    session_b = start_new_session("CENTER-001")

    assert session_a["session_id"] != session_b["session_id"]
    assert session_a["metadata"]["center_id"] == "CENTER-001"
    assert session_b["metadata"]["center_id"] == "CENTER-001"


def test_start_session_rejects_empty_center_id():
    with pytest.raises(ValueError):
        start_new_session(" ")


def test_encrypt_answer_can_be_decrypted():
    key = AESGCM.generate_key(bit_length=256)
    answer = "My exam answer"

    ciphertext, nonce, tag = encrypt_answer(answer, key)
    decrypted = AESGCM(key).decrypt(nonce, ciphertext + tag, None)

    assert decrypted.decode("utf-8") == answer


def test_encrypt_answer_rejects_invalid_inputs():
    with pytest.raises(TypeError):
        encrypt_answer(123, b"x" * 32)

    with pytest.raises(TypeError):
        encrypt_answer("answer", "not-a-key")


def test_submit_answer_returns_submission_record():
    record = submit_answer(
        "STUDENT-001",
        "Q1",
        b"encrypted-data",
        "SESSION-001",
    )

    assert record == {
        "student_id": "STUDENT-001",
        "question_id": "Q1",
        "encrypted_answer": b"encrypted-data",
        "session_id": "SESSION-001",
    }


def test_submit_answer_rejects_empty_identifiers():
    with pytest.raises(ValueError):
        submit_answer("", "Q1", b"data", "SESSION-001")


def test_batch_collect_removes_duplicate_submissions():
    first = submit_answer(
        "STUDENT-001", "Q1", b"data-1", "SESSION-001"
    )
    duplicate = submit_answer(
        "STUDENT-001", "Q1", b"data-2", "SESSION-001"
    )

    result = batch_collect_answers([first, duplicate])

    assert len(result) == 1
    assert result[0]["encrypted_answer"] == b"data-1"


def test_batch_collect_rejects_invalid_submission():
    with pytest.raises(ValueError):
        batch_collect_answers([{"student_id": "STUDENT-001"}])


def test_batch_collect_rejects_non_list():
    with pytest.raises(TypeError):
        batch_collect_answers("not a list")