"""Tests for Module 2 — Adaptive Key Release Engine."""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from module2_key_release.anomaly_detector import compute_anomaly_score, is_anomalous
from module2_key_release.key_release_engine import KeyReleaseEngine


def _build_ca_and_cert(common_name: str, valid_days: int = 365):
    """Create a simple CA certificate and a signed center certificate."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ExamShield Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days))
        .sign(ca_key, hashes.SHA256())
    )

    center_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    center_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(center_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days))
        .sign(ca_key, hashes.SHA256())
    )

    return ca_key, ca_cert, center_key, center_cert


def test_compute_anomaly_score_normal_inputs_low_score():
    """Normal inputs should produce a low anomaly score."""
    score = compute_anomaly_score(0, 5, 30)
    assert 0.0 <= score <= 1.0
    assert score < 0.4


def test_compute_anomaly_score_high_failed_auth_increases_score():
    """High failed authentication attempts should raise the anomaly score."""
    low = compute_anomaly_score(0, 5, 30)
    high = compute_anomaly_score(30, 5, 30)
    assert high > low


def test_compute_anomaly_score_high_request_rate_increases_score():
    """High request rate should raise the anomaly score."""
    low = compute_anomaly_score(0, 5, 30)
    high = compute_anomaly_score(0, 200, 30)
    assert high > low


def test_compute_anomaly_score_large_time_deviation_increases_score():
    """Large time drift should raise the anomaly score."""
    low = compute_anomaly_score(0, 5, 30)
    high = compute_anomaly_score(0, 5, 7200)
    assert high > low


def test_compute_anomaly_score_is_bounded():
    """Anomaly score must always stay in the 0..1 range."""
    for values in [
        (0, 0, 0),
        (10, 20, 100),
        (1000, 500, 100000),
    ]:
        score = compute_anomaly_score(*values)
        assert 0.0 <= score <= 1.0


def test_is_anomalous_threshold_behavior():
    """is_anomalous should return True at/above threshold and False below it."""
    assert is_anomalous(0.69, 0.7) is False
    assert is_anomalous(0.7, 0.7) is True
    assert is_anomalous(0.9, 0.7) is True


def test_is_anomalous_rejects_invalid_score_and_threshold():
    """Invalid score/threshold values should raise ValueError."""
    with pytest.raises(ValueError):
        is_anomalous(-0.1)
    with pytest.raises(ValueError):
        is_anomalous(1.1)
    with pytest.raises(ValueError):
        is_anomalous(0.5, -0.1)
    with pytest.raises(ValueError):
        is_anomalous(0.5, 1.1)


# ---------------------------------------------------------------------------
# Timestamp tests
# ---------------------------------------------------------------------------


def _make_signed_timestamp(ts: datetime, board_private_key):
    """Create a JSON-encoded timestamp payload signed with RSA-PSS."""
    timestamp_text = ts.isoformat().replace("+00:00", "Z")
    signature = board_private_key.sign(
        timestamp_text.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    payload = {
        "timestamp": timestamp_text,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def test_verify_timestamp_valid_inside_window():
    """A valid board-signed timestamp within the valid window should pass."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start, valid_window_sec=300)
    board_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    board_pubkey = board_private_key.public_key()
    engine.board_pubkey = board_pubkey

    valid_payload = _make_signed_timestamp(exam_start + timedelta(seconds=60), board_private_key)
    assert engine.verify_timestamp(valid_payload, board_pubkey) is True


def test_verify_timestamp_outside_window_fails():
    """A valid signature outside the valid window should be rejected."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start, valid_window_sec=300)
    board_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    board_pubkey = board_private_key.public_key()

    old_payload = _make_signed_timestamp(exam_start + timedelta(minutes=10), board_private_key)
    assert engine.verify_timestamp(old_payload, board_pubkey) is False


def test_verify_timestamp_invalid_signature_returns_false():
    """An invalid signature should not pass verification."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start, valid_window_sec=300)
    board_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    board_pubkey = board_private_key.public_key()
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    bad_payload = _make_signed_timestamp(exam_start + timedelta(seconds=30), other_key)
    assert engine.verify_timestamp(bad_payload, board_pubkey) is False


def test_verify_timestamp_malformed_input_returns_false():
    """Malformed timestamp data should fail safely."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start, valid_window_sec=300)
    board_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    board_pubkey = board_key.public_key()

    assert engine.verify_timestamp(b"not json", board_pubkey) is False
    assert engine.verify_timestamp(b"{\"timestamp\": 123, \"signature\": \"bad\"}", board_pubkey) is False


def test_verify_timestamp_exact_window_boundary():
    """A timestamp at the exact valid boundary should be accepted."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start, valid_window_sec=300)
    board_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    board_pubkey = board_private_key.public_key()

    boundary = exam_start + timedelta(seconds=300)
    bound_payload = _make_signed_timestamp(boundary, board_private_key)
    assert engine.verify_timestamp(bound_payload, board_pubkey) is True


# ---------------------------------------------------------------------------
# Certificate tests
# ---------------------------------------------------------------------------


def test_verify_certificate_valid_center_certificate():
    """A properly signed certificate from the trusted CA should pass."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    _, ca_cert, _, center_cert = _build_ca_and_cert("CENTER_001")
    cert_bytes = center_cert.public_bytes(serialization.Encoding.PEM)

    assert engine.verify_certificate(cert_bytes, ca_cert) is True


def test_verify_certificate_wrong_ca_rejected():
    """A certificate signed by a different CA should be rejected."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    _, ca_cert_1, _, center_cert = _build_ca_and_cert("CENTER_001")
    _, ca_cert_2, _, _ = _build_ca_and_cert("ANOTHER_CA")
    cert_bytes = center_cert.public_bytes(serialization.Encoding.PEM)

    assert engine.verify_certificate(cert_bytes, ca_cert_2) is False


def test_verify_certificate_expired_certificate_rejected():
    """Expired certificates should be rejected."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ExamShield Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=10))
        .not_valid_after(datetime.now(timezone.utc) - timedelta(days=1))
        .sign(ca_key, hashes.SHA256())
    )

    center_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "CENTER_EXPIRED"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(center_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=10))
        .not_valid_after(datetime.now(timezone.utc) - timedelta(days=1))
        .sign(ca_key, hashes.SHA256())
    )

    cert_bytes = expired_cert.public_bytes(serialization.Encoding.PEM)
    assert engine.verify_certificate(cert_bytes, ca_cert) is False


def test_verify_certificate_malformed_input_returns_false():
    """Malformed certificate data should fail safely."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    _, ca_cert, _, _ = _build_ca_and_cert("CA")
    assert engine.verify_certificate(b"not-a-certificate", ca_cert) is False


# ---------------------------------------------------------------------------
# request_release tests
# ---------------------------------------------------------------------------


def test_request_release_all_three_valid_conditions_approve():
    """All valid gates should be approved."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    board_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    engine.board_pubkey = board_private_key.public_key()

    _, ca_cert, _, center_cert = _build_ca_and_cert("CENTER_001")
    engine.ca_cert = ca_cert

    signed_timestamp = _make_signed_timestamp(exam_start + timedelta(seconds=120), board_private_key)
    approved, reason = engine.request_release(
        "CENTER_001",
        center_cert.public_bytes(serialization.Encoding.PEM),
        signed_timestamp,
        0.1,
    )

    assert approved is True
    assert reason == "Key release approved"


def test_request_release_invalid_timestamp_denies_release():
    """An invalid timestamp should deny release."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    board_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    engine.board_pubkey = board_private_key.public_key()
    _, ca_cert, _, center_cert = _build_ca_and_cert("CENTER_001")
    engine.ca_cert = ca_cert

    signed_timestamp = _make_signed_timestamp(exam_start + timedelta(minutes=10), board_private_key)
    approved, reason = engine.request_release(
        "CENTER_001",
        center_cert.public_bytes(serialization.Encoding.PEM),
        signed_timestamp,
        0.1,
    )

    assert approved is False
    assert reason == "Invalid or expired timestamp"


def test_request_release_invalid_certificate_denies_release():
    """An invalid certificate should deny release."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    board_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    engine.board_pubkey = board_private_key.public_key()

    _, ca_cert, _, _ = _build_ca_and_cert("CENTER_001")
    engine.ca_cert = ca_cert

    signed_timestamp = _make_signed_timestamp(exam_start + timedelta(seconds=60), board_private_key)
    approved, reason = engine.request_release(
        "CENTER_001",
        b"not-a-certificate",
        signed_timestamp,
        0.1,
    )

    assert approved is False
    assert reason == "Invalid center certificate"


def test_request_release_anomalous_score_denies_release():
    """An anomalous score should deny release."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    board_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    engine.board_pubkey = board_private_key.public_key()
    _, ca_cert, _, center_cert = _build_ca_and_cert("CENTER_001")
    engine.ca_cert = ca_cert

    signed_timestamp = _make_signed_timestamp(exam_start + timedelta(seconds=60), board_private_key)
    approved, reason = engine.request_release(
        "CENTER_001",
        center_cert.public_bytes(serialization.Encoding.PEM),
        signed_timestamp,
        0.9,
    )

    assert approved is False
    assert reason == "Anomalous request"


def test_request_release_rejects_invalid_center_id():
    """Empty center ids must be rejected."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    board_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    engine.board_pubkey = board_private_key.public_key()
    _, ca_cert, _, center_cert = _build_ca_and_cert("CENTER_001")
    engine.ca_cert = ca_cert

    signed_timestamp = _make_signed_timestamp(exam_start + timedelta(seconds=60), board_private_key)
    approved, reason = engine.request_release(
        "   ",
        center_cert.public_bytes(serialization.Encoding.PEM),
        signed_timestamp,
        0.1,
    )

    assert approved is False
    assert reason == "Invalid center identifier"


# ---------------------------------------------------------------------------
# release_key tests
# ---------------------------------------------------------------------------


def test_release_key_successful_unwrap_with_matching_private_key():
    """A matching private key should unwrap the AES key successfully."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    center_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    center_public_key = center_private_key.public_key()
    aes_key = b"A" * 32

    wrapped_key = center_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    engine._last_request_approved = True
    engine._last_approved_center = "CENTER_001"
    unwrapped = engine.release_key("CENTER_001", wrapped_key, center_private_key)

    assert unwrapped == aes_key


def test_release_key_rejects_incompatible_private_key():
    """A private key that cannot decrypt the wrapped payload should be rejected."""
    exam_start = datetime.now(timezone.utc)
    engine = KeyReleaseEngine(exam_start_time=exam_start)
    wrong_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    correct_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    aes_key = b"B" * 32

    wrapped_key = correct_private_key.public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    engine._last_request_approved = True
    engine._last_approved_center = "CENTER_001"

    with pytest.raises(ValueError, match="Unable to unwrap AES key"):
        engine.release_key("CENTER_001", wrapped_key, wrong_private_key)


def test_release_key_requires_prior_approval():
    """Release should require an approved request for the same center."""
    engine = KeyReleaseEngine(datetime.now(timezone.utc))
    center_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    aes_key = b"C" * 32
    wrapped = center_key.public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    with pytest.raises(PermissionError):
        engine.release_key("CENTER_001", wrapped, center_key)


def test_release_key_rejects_wrong_center_after_approval():
    """Releasing for a different center than the one approved should fail."""
    engine = KeyReleaseEngine(datetime.now(timezone.utc))
    center_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    aes_key = b"D" * 32
    wrapped = center_key.public_key().encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    engine._last_request_approved = True
    engine._last_approved_center = "CENTER_001"

    with pytest.raises(PermissionError):
        engine.release_key("CENTER_002", wrapped, center_key)

