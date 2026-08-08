"""
Module 5 — Integrity & Audit Log
Owner: Elisha

Merkle tree over submitted answers for per-answer tamper-evident
integrity. Only the root hash needs to be signed/published; individual
answers can be proven present via inclusion proofs.
"""


class MerkleTree:
    """Binary Merkle tree built from SHA-256 leaf hashes of answer records."""

    def __init__(self, leaves: list[bytes] = None):
        """
        Args:
            leaves: optional initial list of leaf hashes (raw, pre-hashed data).
        """
        raise NotImplementedError

    def add_leaf(self, data: bytes) -> None:
        """
        Add a new leaf (e.g. hash of an answer record) to the tree.

        Args:
            data: raw bytes to be hashed and added as a leaf.
        """
        raise NotImplementedError

    def build_tree(self) -> bytes:
        """
        Build the full tree from current leaves and compute the root.

        Returns:
            root hash (32 bytes).
        """
        raise NotImplementedError

    def get_proof(self, leaf_index: int) -> list[tuple[bytes, str]]:
        """
        Generate an inclusion proof for a given leaf.

        Args:
            leaf_index: index of the leaf to prove.

        Returns:
            list of (sibling_hash, direction) pairs, direction is "L" or "R",
            ordered from leaf level up to the root.
        """
        raise NotImplementedError

    def verify_proof(self, leaf: bytes, proof: list[tuple[bytes, str]], root: bytes) -> bool:
        """
        Verify a leaf belongs to the tree with the given root, using its proof.

        Args:
            leaf: raw leaf data (pre-hash).
            proof: inclusion proof from get_proof().
            root: claimed Merkle root to verify against.

        Returns:
            True if the recomputed root matches `root`.
        """
        raise NotImplementedError
