"""
Module 5 — Integrity & Audit Log
Owner: Elisha

Hash-chained audit log: every event is linked to the previous entry,
making post-hoc tampering detectable.
"""

import hashlib
import json


class AuditLog:
    """Append-only, hash-chained log of exam-session events."""

    def __init__(self):
        """Initialize an empty audit log with a genesis hash."""
        self._genesis_hash = hashlib.sha256(
            b"EXAMSHIELD-GENESIS"
        ).digest()

        self._chain = []

    def add_entry(self, event: str, metadata: dict) -> bytes:
        """
        Append a new event to the chain.

        hash_i = SHA256(hash_{i-1} + serialized(event, metadata))

        Args:
            event: short event name/type.
            metadata: event-specific details.

        Returns:
            the new entry's hash.
        """
        if not isinstance(event, str):
            raise TypeError("Event must be a string.")

        if not isinstance(metadata, dict):
            raise TypeError("Metadata must be a dictionary.")

        if self._chain:
            previous_hash = self._chain[-1]["hash"]
        else:
            previous_hash = self._genesis_hash

        serialized_data = json.dumps(
            {
                "event": event,
                "metadata": metadata
            },
            sort_keys=True,
            separators=(",", ":")
        ).encode("utf-8")

        entry_hash = hashlib.sha256(
            previous_hash + serialized_data
        ).digest()

        entry = {
            "event": event,
            "metadata": metadata,
            "hash": entry_hash,
            "prev_hash": previous_hash
        }

        self._chain.append(entry)

        return entry_hash

    def get_chain(self) -> list[dict]:
        """
        Return the full ordered list of log entries.
        """
        return self._chain.copy()

    def verify_chain(self) -> bool:
        """
        Recompute all hashes and check that the chain is unbroken.

        Returns:
            True if the chain is intact.
        """
        previous_hash = self._genesis_hash

        for entry in self._chain:
            serialized_data = json.dumps(
                {
                    "event": entry["event"],
                    "metadata": entry["metadata"]
                },
                sort_keys=True,
                separators=(",", ":")
            ).encode("utf-8")

            expected_hash = hashlib.sha256(
                previous_hash + serialized_data
            ).digest()

            if entry["prev_hash"] != previous_hash:
                return False

            if entry["hash"] != expected_hash:
                return False

            previous_hash = entry["hash"]

        return True

    def export_log(self, path: str) -> None:
        """
        Write the full audit chain to disk as JSON.
        """

        export_data = []

        for entry in self._chain:
            export_data.append(
                {
                    "event": entry["event"],
                    "metadata": entry["metadata"],
                    "hash": entry["hash"].hex(),
                    "prev_hash": entry["prev_hash"].hex()
                }
            )

        with open(path, "w", encoding="utf-8") as file:
            json.dump(export_data, file, indent=2)