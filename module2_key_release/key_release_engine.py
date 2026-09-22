"""
Module 2 — Adaptive Key Release Engine
Owner: Nagaraj

Gates release of the AES decryption key to a center based on three
combined conditions: signed timestamp validity, certificate validity,
and anomaly score. All three must pass for a key to be released.
"""

import base64
import json
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509 import Certificate

from common.constants import DEFAULT_ANOMALY_THRESHOLD, DEFAULT_KEY_RELEASE_WINDOW_SEC
from module1_board_prep.crypto_utils import rsa_verify
from module2_key_release.anomaly_detector import is_anomalous


class KeyReleaseEngine:
    """Adaptive gating engine controlling when exam decryption keys are released."""

    def __init__(self, exam_start_time: datetime, valid_window_sec: int = DEFAULT_KEY_RELEASE_WINDOW_SEC):
        """
        Args:
            exam_start_time: scheduled exam start time.
            valid_window_sec: how many seconds around start_time a request is valid.
        """
        if not isinstance(exam_start_time, datetime):
            raise TypeError("exam_start_time must be a datetime instance")

        if valid_window_sec <= 0:
            raise ValueError("valid_window_sec must be positive")

        if exam_start_time.tzinfo is None:
            self.exam_start_time = exam_start_time.replace(tzinfo=timezone.utc)
        else:
            self.exam_start_time = exam_start_time.astimezone(timezone.utc)

        self.valid_window_sec = int(valid_window_sec)
        self.board_pubkey: RSAPublicKey | None = None
        self.ca_cert: Certificate | None = None
        self._last_approved_center: str | None = None
        self._last_request_approved = False

    @staticmethod
    def _to_utc(dt: datetime) -> datetime:
        """Normalize a datetime to timezone-aware UTC."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def verify_timestamp(self, signed_timestamp: bytes, board_pubkey: RSAPublicKey) -> bool:
        """
        Verify a board-signed timestamp is authentic and within the valid window.

        The timestamp payload is a compact JSON object with:
            {
                "timestamp": "2026-01-01T10:00:00Z",
                "signature": "base64-encoded RSA-PSS signature"
            }

        The signature is created using the same RSA-PSS + SHA-256 scheme as the
        Module 1 crypto utilities. The timestamp is accepted only if the signature
        verifies and the timestamp falls within the configured valid window.

        Args:
            signed_timestamp: timestamp bytes signed by the exam board.
            board_pubkey: board's RSA public key.

        Returns:
            True if signature is valid and timestamp falls in the valid window.
        """
        if not isinstance(signed_timestamp, (bytes, bytearray)):
            return False
        if board_pubkey is None:
            return False

        try:
            payload = json.loads(signed_timestamp.decode("utf-8"))
        except (TypeError, ValueError, UnicodeDecodeError):
            return False

        if not isinstance(payload, dict):
            return False

        ts_value = payload.get("timestamp")
        signature_value = payload.get("signature")
        if not isinstance(ts_value, str) or not isinstance(signature_value, str):
            return False

        try:
            signature = base64.b64decode(signature_value, validate=True)
        except (TypeError, ValueError):
            return False

        try:
            board_pubkey.verify(
                signature,
                ts_value.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception:
            return False

        try:
            parsed_timestamp = datetime.fromisoformat(ts_value.replace("Z", "+00:00"))
        except ValueError:
            return False

        parsed_timestamp = self._to_utc(parsed_timestamp)
        exam_start_time = self._to_utc(self.exam_start_time)
        delta_seconds = abs((parsed_timestamp - exam_start_time).total_seconds())

        return delta_seconds <= self.valid_window_sec

    def verify_certificate(self, cert_bytes: bytes, ca_cert: Certificate) -> bool:
        """
        Verify a center's X.509 certificate against the trusted CA.

        Args:
            cert_bytes: center's certificate (DER or PEM encoded).
            ca_cert: trusted root/CA certificate.

        Returns:
            True if the certificate chains to the CA and is not expired/revoked.
        """
        if not isinstance(cert_bytes, (bytes, bytearray)) or ca_cert is None:
            return False

        try:
            if isinstance(cert_bytes, bytearray):
                cert_bytes = bytes(cert_bytes)

            if cert_bytes.startswith(b"-----BEGIN"):
                cert = x509.load_pem_x509_certificate(cert_bytes)
            else:
                cert = x509.load_der_x509_certificate(cert_bytes)
        except ValueError:
            return False

        if cert.issuer != ca_cert.subject:
            return False

        ca_public_key = ca_cert.public_key()
        try:
            if isinstance(ca_public_key, RSAPublicKey):
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
            else:
                return False
        except Exception:
            return False

        now = datetime.now(timezone.utc)
        not_before = self._to_utc(cert.not_valid_before)
        not_after = self._to_utc(cert.not_valid_after)

        if now < not_before or now > not_after:
            return False

        return True

    def request_release(self, center_id: str, cert_bytes: bytes, signed_timestamp: bytes,
                         anomaly_score: float) -> tuple[bool, str]:
        """
        Evaluate all gating conditions and decide whether to approve key release.

        Args:
            center_id: requesting center's identifier.
            cert_bytes: requesting center's certificate.
            signed_timestamp: board-signed timestamp accompanying the request.
            anomaly_score: precomputed anomaly score for this request.

        Returns:
            (approved, reason) — reason explains approval or rejection cause.
        """
        if not isinstance(center_id, str) or not center_id.strip():
            return False, "Invalid center identifier"

        if not isinstance(anomaly_score, (int, float)) or isinstance(anomaly_score, bool):
            return False, "Invalid anomaly score"

        if not 0.0 <= float(anomaly_score) <= 1.0:
            return False, "Invalid anomaly score"

        if self.board_pubkey is None:
            return False, "Invalid or expired timestamp"

        if not self.verify_timestamp(signed_timestamp, self.board_pubkey):
            return False, "Invalid or expired timestamp"

        if self.ca_cert is None:
            return False, "Invalid center certificate"

        if not self.verify_certificate(cert_bytes, self.ca_cert):
            return False, "Invalid center certificate"

        if is_anomalous(float(anomaly_score), DEFAULT_ANOMALY_THRESHOLD):
            return False, "Anomalous request"

        self._last_request_approved = True
        self._last_approved_center = center_id.strip()
        return True, "Key release approved"

    def release_key(self, center_id: str, wrapped_key: bytes, center_privkey: RSAPrivateKey) -> bytes:
        """
        Unwrap and release the AES key to an approved center.

        Args:
            center_id: approved center's identifier.
            wrapped_key: RSA-wrapped AES key.
            center_privkey: center's RSA private key used to unwrap.

        Returns:
            raw AES key bytes.
        """
        if not isinstance(center_id, str) or not center_id.strip():
            raise ValueError("center_id must be a non-empty string")

        if not self._last_request_approved or self._last_approved_center != center_id.strip():
            raise PermissionError("No approved key release for this center")

        if not isinstance(wrapped_key, (bytes, bytearray)):
            raise TypeError("wrapped_key must be bytes")

        try:
            plaintext_key = center_privkey.decrypt(
                bytes(wrapped_key),
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except ValueError as exc:
            raise ValueError("Unable to unwrap AES key with supplied center private key") from exc

        if len(plaintext_key) != 32:
            raise ValueError("Unwrapped AES key is not 32 bytes")

        self._last_request_approved = False
        self._last_approved_center = None
        return plaintext_key
