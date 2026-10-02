"""
Module 4 — Session Key Exchange & Answer Submission
Owner: Divya

Handles per-answer encryption using the session key and collection of
submitted answers ready for hashing into the integrity layer (Module 5).
"""


from module1_board_prep.crypto_utils import aes_encrypt


def encrypt_answer(answer_text: str, session_key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt a single answer with the session's AES key.

    Args:
        answer_text: plaintext student answer.
        session_key: AES key derived from the DH session.

    Returns:
        (ciphertext, nonce, tag)
    """
    if not isinstance(answer_text, str):
        raise TypeError("answer_text must be a string")
    if not isinstance(session_key, bytes):
        raise TypeError("session_key must be bytes")

    return aes_encrypt(answer_text.encode("utf-8"), session_key)


def submit_answer(student_id: str, question_id: str, encrypted_answer: bytes, session_id: str) -> dict:
    """
    Package an encrypted answer submission with metadata.

    Args:
        student_id: submitting student's identifier.
        question_id: identifier of the question being answered.
        encrypted_answer: output ciphertext from encrypt_answer().
        session_id: active exam session identifier.

    Returns:
        dict representing one submission record.
    """
    for name, value in (
        ("student_id", student_id),
        ("question_id", question_id),
        ("session_id", session_id),
    ):
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        if not value.strip():
            raise ValueError(f"{name} cannot be empty")
    if not isinstance(encrypted_answer, bytes):
        raise TypeError("encrypted_answer must be bytes")

    return {
        "student_id": student_id,
        "question_id": question_id,
        "encrypted_answer": encrypted_answer,
        "session_id": session_id,
    }


def batch_collect_answers(submissions: list[dict]) -> list[dict]:
    """
    Validate and collect a batch of answer submissions for a session.

    Args:
        submissions: list of submission records from submit_answer().

    Returns:
        validated/deduplicated list of submission records, ready to be
        fed into Module 5's Merkle tree.
    """
    if not isinstance(submissions, list):
        raise TypeError("submissions must be a list")

    required_fields = {"student_id", "question_id", "encrypted_answer", "session_id"}
    collected = []
    seen = set()

    for index, submission in enumerate(submissions):
        if not isinstance(submission, dict):
            raise ValueError(f"submission at index {index} must be a dictionary")
        if not required_fields.issubset(submission):
            raise ValueError(f"submission at index {index} is missing required fields")

        student_id = submission["student_id"]
        question_id = submission["question_id"]
        session_id = submission["session_id"]
        encrypted_answer = submission["encrypted_answer"]
        for name, value in (
            ("student_id", student_id),
            ("question_id", question_id),
            ("session_id", session_id),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"submission at index {index} has an invalid {name}")
        if not isinstance(encrypted_answer, bytes):
            raise ValueError(f"submission at index {index} has an invalid encrypted_answer")

        duplicate_key = (session_id, student_id, question_id)
        if duplicate_key in seen:
            continue
        seen.add(duplicate_key)
        collected.append(dict(submission))

    return collected
