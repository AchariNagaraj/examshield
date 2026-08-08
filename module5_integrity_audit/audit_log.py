"""
Module 5 — Integrity & Audit Log
Owner: Elisha

Hash-chained audit log: every event (key release, answer submission,
auth attempt, etc.) is appended with a hash linking it to the previous
entry, making post-hoc tampering detectable.
"""


class AuditLog:
    """Append-only, hash-chained log of exam-session events."""

    def __init__(self):
        """Initialize an empty audit log with a genesis hash."""
        raise NotImplementedError

    def add_entry(self, event: str, metadata: dict) -> bytes:
        """
        Append a new event to the chain.

        hash_i = SHA256(hash_{i-1} + serialized(event, metadata))

        Args:
            event: short event name/type (e.g. "KEY_RELEASED", "ANSWER_SUBMITTED").
            metadata: event-specific details (center_id, timestamp, etc.).

        Returns:
            the new entry's hash (becomes the chain head).
        """
        raise NotImplementedError

    def get_chain(self) -> list[dict]:
        """
        Return the full ordered list of log entries.

        Returns:
            list of dicts, each containing event, metadata, hash, prev_hash.
        """
        raise NotImplementedError

    def verify_chain(self) -> bool:
        """
        Recompute all hashes in order and check the chain is unbroken.

        Returns:
            True if no entry has been tampered with or removed.
        """
        raise NotImplementedError

    def export_log(self, path: str) -> None:
        """
        Write the full audit chain to disk (e.g. as JSON).

        Args:
            path: output file path.
        """
        raise NotImplementedError
