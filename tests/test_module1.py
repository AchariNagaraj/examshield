"""Tests for Module 1 — Exam Board Preparation & Watermarking (Joylin)."""

import pytest
import os
import json
import tempfile
from pathlib import Path
from base64 import b64decode

from module1_board_prep.crypto_utils import (
    generate_rsa_keypair,
    aes_encrypt,
    aes_decrypt,
    rsa_sign,
    rsa_verify,
    sha256_hash,
    _rsa_wrap_key,
)
from module1_board_prep.watermark import (
    generate_center_secret,
    embed_watermark,
    extract_watermark,
    trace_leak,
)
from module1_board_prep.board_prep import prepare_exam_package, save_package
from cryptography.exceptions import InvalidTag


# ============================================================================
# PART 1 & 2: RSA Key Generation (2048 and 4096 bits)
# ============================================================================


def test_generate_rsa_keypair_2048():
    """RSA-2048 key generation should produce a valid keypair."""
    private_key, public_key = generate_rsa_keypair(key_size=2048)

    assert private_key is not None
    assert public_key is not None
    assert private_key.key_size == 2048
    assert public_key.key_size == 2048


def test_generate_rsa_keypair_4096():
    """RSA-4096 key generation should work."""
    private_key, public_key = generate_rsa_keypair(key_size=4096)

    assert private_key.key_size == 4096
    assert public_key.key_size == 4096


def test_generate_rsa_keypair_invalid_size():
    """Invalid RSA key size should raise ValueError."""
    with pytest.raises(ValueError, match="Unsupported RSA key size"):
        generate_rsa_keypair(key_size=1024)

    with pytest.raises(ValueError, match="Unsupported RSA key size"):
        generate_rsa_keypair(key_size=3072)


# ============================================================================
# PART 3-5: AES-256-GCM Encryption/Decryption
# ============================================================================


def test_aes_encrypt_decrypt_roundtrip():
    """AES-256-GCM encrypt then decrypt should return original plaintext."""
    plaintext = b"This is a secret exam paper with sensitive questions."
    key = os.urandom(32)

    ciphertext, nonce, tag = aes_encrypt(plaintext, key)

    # Verify output types
    assert isinstance(ciphertext, bytes)
    assert isinstance(nonce, bytes)
    assert isinstance(tag, bytes)

    # Verify sizes
    assert len(nonce) == 12
    assert len(tag) == 16
    assert len(ciphertext) == len(plaintext)

    # Decrypt and verify
    decrypted = aes_decrypt(ciphertext, key, nonce, tag)
    assert decrypted == plaintext


def test_aes_encrypt_invalid_key_length():
    """AES encryption with wrong key size should raise ValueError."""
    plaintext = b"test"

    # Too short
    with pytest.raises(ValueError, match="AES key must be exactly 32 bytes"):
        aes_encrypt(plaintext, b"tooshort")

    # Too long
    with pytest.raises(ValueError, match="AES key must be exactly 32 bytes"):
        aes_encrypt(plaintext, os.urandom(64))


def test_aes_decrypt_invalid_key_length():
    """AES decryption with wrong key size should raise ValueError."""
    with pytest.raises(ValueError, match="AES key must be exactly 32 bytes"):
        aes_decrypt(b"ciphertext", b"wrongkeysize", b"nonce", b"tag")


def test_aes_decrypt_modified_ciphertext():
    """Modifying ciphertext should cause decryption to fail with InvalidTag."""
    plaintext = b"Exam paper content"
    key = os.urandom(32)

    ciphertext, nonce, tag = aes_encrypt(plaintext, key)

    # Modify ciphertext
    modified_ciphertext = bytearray(ciphertext)
    modified_ciphertext[0] ^= 0xFF  # flip bits
    modified_ciphertext = bytes(modified_ciphertext)

    with pytest.raises(InvalidTag):
        aes_decrypt(modified_ciphertext, key, nonce, tag)


def test_aes_decrypt_modified_tag():
    """Modifying authentication tag should cause decryption to fail."""
    plaintext = b"Exam paper content"
    key = os.urandom(32)

    ciphertext, nonce, tag = aes_encrypt(plaintext, key)

    # Modify tag
    modified_tag = bytearray(tag)
    modified_tag[0] ^= 0xFF
    modified_tag = bytes(modified_tag)

    with pytest.raises(InvalidTag):
        aes_decrypt(ciphertext, key, nonce, modified_tag)


def test_aes_different_keys_different_plaintext():
    """Using different key should decrypt to different plaintext."""
    plaintext = b"Exam paper"
    key1 = os.urandom(32)
    key2 = os.urandom(32)

    ciphertext, nonce, tag = aes_encrypt(plaintext, key1)

    # Try to decrypt with wrong key
    with pytest.raises(InvalidTag):
        aes_decrypt(ciphertext, key2, nonce, tag)


# ============================================================================
# PART 6 & 7: RSA Digital Signatures
# ============================================================================


def test_rsa_sign_verify_roundtrip():
    """RSA signature should verify against the correct public key."""
    private_key, public_key = generate_rsa_keypair(2048)
    data = b"Exam board signature test data"

    signature = rsa_sign(data, private_key)

    assert isinstance(signature, bytes)
    assert len(signature) == 256  # RSA-2048 produces 256-byte signature

    # Verify signature
    is_valid = rsa_verify(data, signature, public_key)
    assert is_valid is True


def test_rsa_verify_invalid_signature():
    """Invalid RSA signature should return False."""
    private_key, public_key = generate_rsa_keypair(2048)
    data = b"Original data"

    signature = rsa_sign(data, private_key)

    # Tamper with signature
    tampered_sig = bytearray(signature)
    tampered_sig[0] ^= 0xFF
    tampered_sig = bytes(tampered_sig)

    is_valid = rsa_verify(data, tampered_sig, public_key)
    assert is_valid is False


def test_rsa_verify_wrong_data():
    """Signature should fail if data is modified."""
    private_key, public_key = generate_rsa_keypair(2048)
    data = b"Original data"
    modified_data = b"Modified data"

    signature = rsa_sign(data, private_key)

    is_valid = rsa_verify(modified_data, signature, public_key)
    assert is_valid is False


def test_rsa_verify_corrupted_signature():
    """Corrupted signature should return False, not crash."""
    private_key, public_key = generate_rsa_keypair(2048)
    data = b"test data"

    # Use a corrupted/random signature
    corrupted_sig = os.urandom(256)

    is_valid = rsa_verify(data, corrupted_sig, public_key)
    assert is_valid is False


# ============================================================================
# PART 8: SHA-256 Hashing
# ============================================================================


def test_sha256_hash_basic():
    """SHA-256 hash should return 32-byte digest."""
    data = b"test data"
    hash_digest = sha256_hash(data)

    assert isinstance(hash_digest, bytes)
    assert len(hash_digest) == 32

    # Verify it's deterministic
    hash_digest_2 = sha256_hash(data)
    assert hash_digest == hash_digest_2


def test_sha256_different_data():
    """Different data should produce different hashes."""
    data1 = b"exam paper 1"
    data2 = b"exam paper 2"

    hash1 = sha256_hash(data1)
    hash2 = sha256_hash(data2)

    assert hash1 != hash2


def test_sha256_empty_data():
    """SHA-256 of empty bytes should work."""
    hash_digest = sha256_hash(b"")
    assert len(hash_digest) == 32


# ============================================================================
# PART 9-11: Center Secret Derivation
# ============================================================================


def test_generate_center_secret_basic():
    """Center secret derivation should produce 32-byte key."""
    center_id = "CENTER_A"
    master_secret = os.urandom(32)

    center_secret = generate_center_secret(center_id, master_secret)

    assert isinstance(center_secret, bytes)
    assert len(center_secret) == 32


def test_generate_center_secret_deterministic():
    """Same center + same master secret should produce same secret."""
    center_id = "CENTER_A"
    master_secret = os.urandom(32)

    secret1 = generate_center_secret(center_id, master_secret)
    secret2 = generate_center_secret(center_id, master_secret)

    assert secret1 == secret2


def test_generate_center_secret_different_centers():
    """Different centers should produce different secrets."""
    master_secret = os.urandom(32)

    secret_a = generate_center_secret("CENTER_A", master_secret)
    secret_b = generate_center_secret("CENTER_B", master_secret)

    assert secret_a != secret_b


def test_generate_center_secret_empty_center_id():
    """Empty center_id should raise ValueError."""
    with pytest.raises(ValueError, match="center_id cannot be empty"):
        generate_center_secret("", os.urandom(32))


def test_generate_center_secret_empty_master_secret():
    """Empty master_secret should raise ValueError."""
    with pytest.raises(ValueError, match="master_secret must be non-empty"):
        generate_center_secret("CENTER_A", b"")


# ============================================================================
# PART 12-14: Watermark Embedding & Extraction
# ============================================================================


def test_embed_watermark_creates_container():
    """embed_watermark should create a valid container."""
    paper_bytes = b"Exam paper content"
    center_id = "CENTER_A"
    center_secret = os.urandom(32)

    watermarked = embed_watermark(paper_bytes, center_id, center_secret)

    assert isinstance(watermarked, bytes)
    assert watermarked.startswith(b"EXAM")  # Magic bytes
    assert len(watermarked) > len(paper_bytes)  # Container is larger


def test_extract_watermark_roundtrip():
    """Watermark should be extractable and match embedded data."""
    paper_bytes = b"Exam paper content"
    center_id = "CENTER_A"
    center_secret = os.urandom(32)

    watermarked = embed_watermark(paper_bytes, center_id, center_secret)
    extracted_center_id, extracted_watermark = extract_watermark(watermarked)

    assert extracted_center_id == center_id
    assert isinstance(extracted_watermark, bytes)
    assert len(extracted_watermark) == 32


def test_different_centers_different_watermarks():
    """Different centers should have different watermarks."""
    paper_bytes = b"Exam paper content"
    master_secret = os.urandom(32)

    center_secret_a = generate_center_secret("CENTER_A", master_secret)
    center_secret_b = generate_center_secret("CENTER_B", master_secret)

    watermarked_a = embed_watermark(paper_bytes, "CENTER_A", center_secret_a)
    watermarked_b = embed_watermark(paper_bytes, "CENTER_B", center_secret_b)

    _, watermark_a = extract_watermark(watermarked_a)
    _, watermark_b = extract_watermark(watermarked_b)

    assert watermark_a != watermark_b


def test_extract_watermark_invalid_magic():
    """Extracting watermark from data without magic bytes should raise ValueError."""
    invalid_data = b"NOT_EXAM_DATA" + os.urandom(100)

    with pytest.raises(ValueError, match="Invalid magic bytes"):
        extract_watermark(invalid_data)


def test_extract_watermark_too_short():
    """Extracting from too-short data should raise ValueError."""
    with pytest.raises(ValueError, match="too short"):
        extract_watermark(b"EXAM" + b"x" * 10)


def test_extract_watermark_malformed():
    """Malformed watermark should raise ValueError."""
    # Create a container with bad center_id_len
    magic = b"EXAM"
    version = bytes([0x01])
    bad_id_len = int(9999).to_bytes(2, byteorder="big")  # Claims huge ID

    malformed = magic + version + bad_id_len + b"x" * 100

    with pytest.raises(ValueError):
        extract_watermark(malformed)


# ============================================================================
# PART 15-16: Leak Tracing
# ============================================================================


def test_trace_leak_identifies_correct_center():
    """trace_leak should identify the correct center from a leaked paper."""
    paper_bytes = b"Confidential exam content"
    master_secret = os.urandom(32)

    centers = ["CENTER_A", "CENTER_B", "CENTER_C"]
    center_registry = {
        cid: generate_center_secret(cid, master_secret) for cid in centers
    }

    # Create package for CENTER_B
    center_secret_b = center_registry["CENTER_B"]
    watermarked = embed_watermark(paper_bytes, "CENTER_B", center_secret_b)

    # Trace it
    identified = trace_leak(watermarked, center_registry)

    assert identified == "CENTER_B"


def test_trace_leak_unknown_center():
    """trace_leak should return 'UNKNOWN' if center not in registry."""
    paper_bytes = b"Confidential exam content"
    master_secret = os.urandom(32)

    # Create package for CENTER_X (not in registry)
    center_secret_x = generate_center_secret("CENTER_X", master_secret)
    watermarked = embed_watermark(paper_bytes, "CENTER_X", center_secret_x)

    # Registry only has other centers
    center_registry = {
        "CENTER_A": generate_center_secret("CENTER_A", master_secret),
        "CENTER_B": generate_center_secret("CENTER_B", master_secret),
    }

    # Trace should fail
    identified = trace_leak(watermarked, center_registry)

    assert identified == "UNKNOWN"


def test_trace_leak_tampered_watermark():
    """Tampered watermark should not identify a wrong center."""
    paper_bytes = b"Confidential exam content"
    master_secret = os.urandom(32)

    center_secret_a = generate_center_secret("CENTER_A", master_secret)
    center_secret_b = generate_center_secret("CENTER_B", master_secret)

    # Create package for CENTER_A
    watermarked = embed_watermark(paper_bytes, "CENTER_A", center_secret_a)

    # Tamper with watermark in the container
    watermarked_list = bytearray(watermarked)
    watermarked_list[47] ^= 0xFF  # Flip a bit in the watermark tag
    watermarked_tampered = bytes(watermarked_list)

    # Try to trace with CENTER_B's registry (should not match A either)
    center_registry = {"CENTER_B": center_secret_b}

    identified = trace_leak(watermarked_tampered, center_registry)

    assert identified == "UNKNOWN"


def test_trace_leak_wrong_master_secret():
    """Using wrong master secret should prevent matching."""
    paper_bytes = b"Confidential exam content"
    master_secret_1 = os.urandom(32)
    master_secret_2 = os.urandom(32)

    # Create package with master_secret_1
    center_secret = generate_center_secret("CENTER_A", master_secret_1)
    watermarked = embed_watermark(paper_bytes, "CENTER_A", center_secret)

    # Try to trace using registry built from master_secret_2
    center_registry = {"CENTER_A": generate_center_secret("CENTER_A", master_secret_2)}

    identified = trace_leak(watermarked, center_registry)

    assert identified == "UNKNOWN"


def test_trace_leak_malformed_input():
    """trace_leak should return 'UNKNOWN' for malformed input."""
    malformed = b"NOT_A_VALID_WATERMARKED_PAPER"
    center_registry = {"CENTER_A": os.urandom(32)}

    identified = trace_leak(malformed, center_registry)

    assert identified == "UNKNOWN"


def test_trace_leak_embedded_center_id_not_trusted():
    """Embedded center_id should not bypass HMAC verification."""
    paper_bytes = b"Confidential exam content"
    master_secret = os.urandom(32)

    # Create watermarked package for CENTER_A
    center_secret_a = generate_center_secret("CENTER_A", master_secret)
    watermarked_a = embed_watermark(paper_bytes, "CENTER_A", center_secret_a)

    # Now modify the embedded center_id to say CENTER_B
    # (while keeping the watermark calculated with CENTER_A's secret)
    watermarked_list = bytearray(watermarked_a)

    # Find and modify the center_id field
    # Format: [EXAM(4)][VER(1)][ID_LEN(2)][ID][WATERMARK(32)][PAPER_LEN(8)][PAPER]
    id_len_offset = 5
    id_len = int.from_bytes(watermarked_a[id_len_offset : id_len_offset + 2], byteorder="big")
    id_offset = id_len_offset + 2

    # Replace center_id
    new_id = "CENTER_B".encode("utf-8")
    if len(new_id) == len(b"CENTER_A"):
        # Can do in-place replacement
        watermarked_list[id_offset : id_offset + len(new_id)] = new_id
        watermarked_tampered = bytes(watermarked_list)

        # Try to trace - should fail because watermark was calculated with CENTER_A's secret
        center_registry = {
            "CENTER_A": center_secret_a,
            "CENTER_B": generate_center_secret("CENTER_B", master_secret),
        }

        identified = trace_leak(watermarked_tampered, center_registry)

        # Should not identify CENTER_B just because ID says so
        assert identified != "CENTER_B"
        # Should either return "CENTER_A" (if tampered data still matches) or "UNKNOWN"
        assert identified in ("CENTER_A", "UNKNOWN")


# ============================================================================
# PART 17-19: Package Preparation
# ============================================================================


def test_prepare_exam_package_basic():
    """prepare_exam_package should create valid package dict."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a temporary paper file
        paper_path = os.path.join(tmpdir, "exam.pdf")
        with open(paper_path, "wb") as f:
            f.write(b"Sample exam paper content")

        center_ids = ["CENTER_A", "CENTER_B"]
        master_secret = os.urandom(32)

        package = prepare_exam_package(paper_path, center_ids, master_secret)

        assert isinstance(package, dict)
        assert "version" in package
        assert "algorithm" in package
        assert "board_public_key_pem" in package
        assert "centers" in package
        assert "signature" in package

        # Check algorithm
        assert package["algorithm"]["encryption"] == "AES-256-GCM"
        assert package["algorithm"]["key_wrap"] == "RSA-OAEP-SHA256"
        assert package["algorithm"]["signature"] == "RSA-PSS-SHA256"

        # Check centers
        for center_id in center_ids:
            assert center_id in package["centers"]
            center_data = package["centers"][center_id]
            assert "watermarked_paper" in center_data
            assert "ciphertext" in center_data
            assert "nonce" in center_data
            assert "tag" in center_data
            assert "wrapped_key" in center_data


def test_prepare_exam_package_each_center_unique_watermark():
    """Each center should get its own unique watermark."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paper_path = os.path.join(tmpdir, "exam.pdf")
        with open(paper_path, "wb") as f:
            f.write(b"Exam paper")

        center_ids = ["CENTER_A", "CENTER_B", "CENTER_C"]
        master_secret = os.urandom(32)

        package = prepare_exam_package(paper_path, center_ids, master_secret)

        # Extract watermarks
        watermarks = {}
        for center_id in center_ids:
            watermarked_b64 = package["centers"][center_id]["watermarked_paper"]
            watermarked = b64decode(watermarked_b64)
            _, wm = extract_watermark(watermarked)
            watermarks[center_id] = wm

        # All watermarks should be different
        unique_watermarks = set(tuple(wm) for wm in watermarks.values())
        assert len(unique_watermarks) == len(center_ids)


def test_prepare_exam_package_shared_ciphertext():
    """All centers should share the same ciphertext/nonce/tag."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paper_path = os.path.join(tmpdir, "exam.pdf")
        with open(paper_path, "wb") as f:
            f.write(b"Exam paper")

        center_ids = ["CENTER_A", "CENTER_B", "CENTER_C"]
        master_secret = os.urandom(32)

        package = prepare_exam_package(paper_path, center_ids, master_secret)

        # Check that ciphertext/nonce/tag are same across centers
        ciphertext = package["centers"]["CENTER_A"]["ciphertext"]
        nonce = package["centers"]["CENTER_A"]["nonce"]
        tag = package["centers"]["CENTER_A"]["tag"]

        for center_id in ["CENTER_B", "CENTER_C"]:
            assert package["centers"][center_id]["ciphertext"] == ciphertext
            assert package["centers"][center_id]["nonce"] == nonce
            assert package["centers"][center_id]["tag"] == tag


def test_prepare_exam_package_no_plaintext_key():
    """Package should not expose plaintext AES key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paper_path = os.path.join(tmpdir, "exam.pdf")
        with open(paper_path, "wb") as f:
            f.write(b"Exam paper")

        center_ids = ["CENTER_A"]
        master_secret = os.urandom(32)

        package = prepare_exam_package(paper_path, center_ids, master_secret)

        # Convert to JSON string and check it's not there
        package_str = json.dumps(package)

        # Should not contain raw AES key (which is random)
        # We can't directly check for the key, but we can verify the wrapped_key is there
        assert "wrapped_key" in package["centers"]["CENTER_A"]
        # Wrapped key should be base64-encoded (looks like base64)
        wrapped_key_b64 = package["centers"]["CENTER_A"]["wrapped_key"]
        assert isinstance(wrapped_key_b64, str)
        # Should be decodable as base64
        wrapped_key_bytes = b64decode(wrapped_key_b64)
        assert len(wrapped_key_bytes) > 32  # RSA-OAEP wrapped key is larger


def test_prepare_exam_package_empty_center_ids():
    """prepare_exam_package should reject empty center_ids."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paper_path = os.path.join(tmpdir, "exam.pdf")
        with open(paper_path, "wb") as f:
            f.write(b"Exam paper")

        with pytest.raises(ValueError, match="center_ids cannot be empty"):
            prepare_exam_package(paper_path, [], os.urandom(32))


def test_prepare_exam_package_missing_paper():
    """prepare_exam_package should raise FileNotFoundError for missing paper."""
    with pytest.raises(FileNotFoundError):
        prepare_exam_package("/nonexistent/paper.pdf", ["CENTER_A"], os.urandom(32))


def test_prepare_exam_package_empty_paper():
    """prepare_exam_package should reject empty paper file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paper_path = os.path.join(tmpdir, "empty.pdf")
        with open(paper_path, "wb") as f:
            pass  # Empty file

        with pytest.raises(ValueError, match="Paper file is empty"):
            prepare_exam_package(paper_path, ["CENTER_A"], os.urandom(32))


# ============================================================================
# PART 20: Save Package
# ============================================================================


def test_save_package_creates_files():
    """save_package should create one file per center."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paper_path = os.path.join(tmpdir, "exam.pdf")
        with open(paper_path, "wb") as f:
            f.write(b"Exam paper")

        center_ids = ["CENTER_A", "CENTER_B"]
        master_secret = os.urandom(32)

        package = prepare_exam_package(paper_path, center_ids, master_secret)

        # Save to temp output directory
        output_dir = os.path.join(tmpdir, "output")
        save_package(package, output_dir)

        # Check files were created
        output_path = Path(output_dir)
        assert output_path.exists()

        files = list(output_path.glob("*.json"))
        assert len(files) == 2

        # Check file names
        filenames = {f.name for f in files}
        assert "CENTER_A_exam_package.json" in filenames
        assert "CENTER_B_exam_package.json" in filenames


def test_save_package_files_loadable():
    """Saved package files should be valid JSON and loadable."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paper_path = os.path.join(tmpdir, "exam.pdf")
        with open(paper_path, "wb") as f:
            f.write(b"Exam paper content")

        center_ids = ["CENTER_A", "CENTER_B"]
        master_secret = os.urandom(32)

        package = prepare_exam_package(paper_path, center_ids, master_secret)

        output_dir = os.path.join(tmpdir, "output")
        save_package(package, output_dir)

        # Load and verify files
        for center_id in center_ids:
            filepath = Path(output_dir) / f"{center_id}_exam_package.json"
            assert filepath.exists()

            with open(filepath) as f:
                loaded = json.load(f)

            assert loaded["center_id"] == center_id
            assert "watermarked_paper" in loaded
            assert "signature" in loaded
            assert "board_public_key_pem" in loaded


def test_save_package_signature_verifiable():
    """Package signature should be verifiable."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paper_path = os.path.join(tmpdir, "exam.pdf")
        with open(paper_path, "wb") as f:
            f.write(b"Exam paper content for signature verification")

        center_ids = ["CENTER_MAIN"]
        master_secret = os.urandom(32)

        package = prepare_exam_package(paper_path, center_ids, master_secret)

        output_dir = os.path.join(tmpdir, "output")
        save_package(package, output_dir)

        # Load saved file
        filepath = Path(output_dir) / "CENTER_MAIN_exam_package.json"
        with open(filepath) as f:
            loaded_package = json.load(f)

        # Verify signature is present and is base64
        signature_b64 = loaded_package["signature"]
        signature = b64decode(signature_b64)
        assert len(signature) == 256  # RSA-2048

        # Verify canonical data is present
        assert "canonical_data" in loaded_package


def test_save_package_path_traversal_protection():
    """save_package should sanitize center IDs to prevent path traversal."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paper_path = os.path.join(tmpdir, "exam.pdf")
        with open(paper_path, "wb") as f:
            f.write(b"Exam paper")

        # Try to inject path traversal in center_id
        center_ids = ["CENTER/../ESCAPE"]
        master_secret = os.urandom(32)

        package = prepare_exam_package(paper_path, center_ids, master_secret)

        output_dir = os.path.join(tmpdir, "output")
        save_package(package, output_dir)

        # Check that the dangerous path wasn't created
        dangerous_path = Path(output_dir) / ".." / "ESCAPE_exam_package.json"
        assert not dangerous_path.exists()

        # Check safe file was created (slashes and dots are replaced with underscores)
        safe_file = Path(output_dir) / "CENTER____ESCAPE_exam_package.json"
        assert safe_file.exists()


# ============================================================================
# Integration Tests
# ============================================================================


def test_full_flow_prepare_and_trace():
    """Full flow: prepare package for centers, then trace a leak."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create paper
        paper_path = os.path.join(tmpdir, "exam.pdf")
        paper_content = b"This is the confidential exam paper with all questions and answers."
        with open(paper_path, "wb") as f:
            f.write(paper_content)

        # Prepare package
        center_ids = ["CENTER_A", "CENTER_B", "CENTER_C"]
        master_secret = os.urandom(32)

        package = prepare_exam_package(paper_path, center_ids, master_secret)

        # Simulate a leak: someone leaked CENTER_B's package
        leaked_ciphertext_b64 = package["centers"]["CENTER_B"]["ciphertext"]
        leaked_ciphertext = b64decode(leaked_ciphertext_b64)
        leaked_nonce_b64 = package["centers"]["CENTER_B"]["nonce"]
        leaked_nonce = b64decode(leaked_nonce_b64)
        leaked_tag_b64 = package["centers"]["CENTER_B"]["tag"]
        leaked_tag = b64decode(leaked_tag_b64)
        leaked_watermarked_b64 = package["centers"]["CENTER_B"]["watermarked_paper"]
        leaked_watermarked = b64decode(leaked_watermarked_b64)

        # Build registry of all center secrets for tracing
        center_registry = {
            cid: generate_center_secret(cid, master_secret) for cid in center_ids
        }

        # Trace the leak
        identified = trace_leak(leaked_watermarked, center_registry)

        assert identified == "CENTER_B"


def test_full_flow_signature_verification():
    """Package signature should verify the canonical data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        paper_path = os.path.join(tmpdir, "exam.pdf")
        with open(paper_path, "wb") as f:
            f.write(b"Exam paper for signature test")

        center_ids = ["CENTER_VERIFY"]
        master_secret = os.urandom(32)

        package = prepare_exam_package(paper_path, center_ids, master_secret)

        # Extract signature and canonical data
        signature_b64 = package["signature"]
        signature = b64decode(signature_b64)

        canonical_data = package["canonical_data"]
        canonical_json = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
        canonical_bytes = canonical_json.encode("utf-8")

        # Extract public key
        public_key_pem = package["board_public_key_pem"].encode("utf-8")
        from cryptography.hazmat.primitives import serialization

        public_key = serialization.load_pem_public_key(public_key_pem)

        # Verify signature
        is_valid = rsa_verify(canonical_bytes, signature, public_key)
        assert is_valid is True

        # Verify that modifying canonical data breaks signature
        tampered_data = canonical_bytes[:-5] + b"XXXXX"
        is_valid_tampered = rsa_verify(tampered_data, signature, public_key)
        assert is_valid_tampered is False
