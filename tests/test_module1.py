"""Tests for Module 1 — Exam Board Preparation & Watermarking (Joylin)."""

import pytest


def test_aes_encrypt_decrypt_roundtrip():
    """AES-256-GCM encrypt then decrypt should return original plaintext."""
    pytest.skip("implement once crypto_utils.aes_encrypt/aes_decrypt are done")


def test_rsa_sign_verify_roundtrip():
    """RSA signature should verify against the correct public key."""
    pytest.skip("implement once crypto_utils.rsa_sign/rsa_verify are done")


def test_watermark_embed_extract_roundtrip():
    """Embedded watermark should be recoverable and match the center_id."""
    pytest.skip("implement once watermark.embed_watermark/extract_watermark are done")


def test_trace_leak_matches_correct_center():
    """trace_leak should identify the correct center from a leaked paper."""
    pytest.skip("implement once watermark.trace_leak is done")
