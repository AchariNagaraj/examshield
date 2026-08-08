"""
Module 2 — Adaptive Key Release Engine
Owner: Nagaraj

Lightweight anomaly scoring used as one of the gating conditions before
the AES decryption key is released to a center.
"""


def compute_anomaly_score(failed_auth_count: int, request_rate: int, time_deviation_sec: int) -> float:
    """
    Compute a 0.0-1.0 anomaly score from observed request signals.

    Higher scores indicate more suspicious behavior (e.g. repeated auth
    failures, unusually high request rate, large deviation from expected
    exam start time).

    Args:
        failed_auth_count: number of failed authentication attempts by this center.
        request_rate: requests per minute from this center.
        time_deviation_sec: seconds between request time and scheduled exam start.

    Returns:
        anomaly score between 0.0 (normal) and 1.0 (highly suspicious).
    """
    raise NotImplementedError


def is_anomalous(score: float, threshold: float = 0.7) -> bool:
    """
    Decide whether an anomaly score should block key release.

    Args:
        score: anomaly score from compute_anomaly_score().
        threshold: cutoff above which the request is treated as anomalous.

    Returns:
        True if score exceeds threshold.
    """
    raise NotImplementedError
