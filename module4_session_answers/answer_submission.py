"""
Module 4 — Session Key Exchange & Answer Submission
Owner: Divya

Handles per-answer encryption using the session key and collection of
submitted answers ready for hashing into the integrity layer (Module 5).
"""


def encrypt_answer(answer_text: str, session_key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt a single answer with the session's AES key.

    Args:
        answer_text: plaintext student answer.
        session_key: AES key derived from the DH session.

    Returns:
        (ciphertext, nonce, tag)
    """
    raise NotImplementedError


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
    raise NotImplementedError


def batch_collect_answers(submissions: list[dict]) -> list[dict]:
    """
    Validate and collect a batch of answer submissions for a session.

    Args:
        submissions: list of submission records from submit_answer().

    Returns:
        validated/deduplicated list of submission records, ready to be
        fed into Module 5's Merkle tree.
    """
    raise NotImplementedError
