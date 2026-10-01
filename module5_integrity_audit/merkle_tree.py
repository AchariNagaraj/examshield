"""
Module 5 — Integrity & Audit Log
Owner: Elisha

Merkle tree over submitted answers for per-answer tamper-evident
integrity. Only the root hash needs to be signed/published; individual
answers can be proven present via inclusion proofs.
"""

import hashlib


class MerkleTree:
    """Binary Merkle tree built from SHA-256 leaf hashes of answer records."""

    def __init__(self, leaves: list[bytes] = None):
        """
        Args:
            leaves: optional list of raw data items to use as leaves.
        """
        self.leaves = []
        self.levels = []
        self.root = None

        if leaves:
            for data in leaves:
                self.add_leaf(data)

    def add_leaf(self, data: bytes) -> None:
        """
        Add a new leaf to the tree.

        Args:
            data: raw bytes to be hashed and added as a leaf.
        """
        if not isinstance(data, bytes):
            raise TypeError("Leaf data must be bytes.")

        leaf_hash = hashlib.sha256(data).digest()
        self.leaves.append(leaf_hash)

        # Tree must be rebuilt after adding a new leaf.
        self.levels = []
        self.root = None

    def build_tree(self) -> bytes:
        """
        Build the full tree from current leaves and compute the root.

        Returns:
            root hash (32 bytes).
        """
        if not self.leaves:
            raise ValueError("Cannot build a Merkle tree with no leaves.")

        # Start with the leaf hashes.
        current_level = self.leaves.copy()
        self.levels = [current_level]

        # Continue until only the root remains.
        while len(current_level) > 1:
            next_level = []

            for i in range(0, len(current_level), 2):
                left = current_level[i]

                # If there is no right node, duplicate the left node.
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left

                parent = hashlib.sha256(left + right).digest()
                next_level.append(parent)

            current_level = next_level
            self.levels.append(current_level)

        self.root = current_level[0]
        return self.root

    def get_proof(self, leaf_index: int) -> list[tuple[bytes, str]]:
        """
        Generate an inclusion proof for a given leaf.

        Args:
            leaf_index: index of the leaf to prove.

        Returns:
            list of (sibling_hash, direction) pairs, direction is "L" or "R",
            ordered from leaf level up to the root.
        """
        if not self.leaves:
            raise ValueError("Cannot create a proof for an empty tree.")

        if not isinstance(leaf_index, int):
            raise TypeError("Leaf index must be an integer.")

        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError("Leaf index out of range.")

        # Build the tree if it has not been built yet.
        if not self.levels:
            self.build_tree()

        proof = []
        index = leaf_index

        # Stop before the root level.
        for level in self.levels[:-1]:
            if index % 2 == 0:
                # Current node is on the left.
                sibling_index = index + 1

                # If it is the last odd node, it is duplicated.
                if sibling_index >= len(level):
                    sibling_index = index

                proof.append((level[sibling_index], "R"))
            else:
                # Current node is on the right.
                sibling_index = index - 1
                proof.append((level[sibling_index], "L"))

            index //= 2

        return proof

    def verify_proof(
        self,
        leaf: bytes,
        proof: list[tuple[bytes, str]],
        root: bytes
    ) -> bool:
        """
        Verify a leaf belongs to the tree with the given root.

        Args:
            leaf: raw leaf data.
            proof: inclusion proof from get_proof().
            root: claimed Merkle root to verify against.

        Returns:
            True if the recomputed root matches `root`.
        """
        if not isinstance(leaf, bytes):
            raise TypeError("Leaf data must be bytes.")

        if not isinstance(root, bytes):
            raise TypeError("Root must be bytes.")

        current_hash = hashlib.sha256(leaf).digest()

        for sibling_hash, direction in proof:
            if not isinstance(sibling_hash, bytes):
                raise TypeError("Sibling hash must be bytes.")

            if direction == "L":
                current_hash = hashlib.sha256(
                    sibling_hash + current_hash
                ).digest()

            elif direction == "R":
                current_hash = hashlib.sha256(
                    current_hash + sibling_hash
                ).digest()

            else:
                raise ValueError("Proof direction must be 'L' or 'R'.")

        return current_hash == root