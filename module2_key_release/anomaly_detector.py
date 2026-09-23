"""
Module 2 — Adaptive Key Release Engine
Owner: Nagaraj

Lightweight anomaly scoring used as one of the gating conditions before
the AES decryption key is released to a center.
"""

from common.constants import DEFAULT_ANOMALY_THRESHOLD


def compute_anomaly_score(failed_auth_count: int, request_rate: int, time_deviation_sec: int) -> float:
    """
    Compute a 0.0-1.0 anomaly score from observed request signals.

    The score combines three normalized signals:
      1. failed authentication count
      2. requests per minute
      3. deviation from the scheduled exam start time

    Each component is normalized to a 0..1 range and then combined with a
    simple weighted average so the score remains explainable and deterministic.

    Args:
        failed_auth_count: number of failed authentication attempts by this center.
        request_rate: requests per minute from this center.
        time_deviation_sec: absolute seconds between request time and scheduled exam start.

    Returns:
        anomaly score between 0.0 (normal) and 1.0 (highly suspicious).
    """
    if failed_auth_count < 0:
        raise ValueError("failed_auth_count must be non-negative")
    if request_rate < 0:
        raise ValueError("request_rate must be non-negative")
    if time_deviation_sec < 0:
        raise ValueError("time_deviation_sec must be non-negative")

    # Simple, explainable normalization.
    # A few failed attempts should not be considered suspicious, while a high
    # count or bursty traffic should. The specific thresholds are intentionally
    # small enough to be easy to explain in a PBL viva.
    auth_signal = min(failed_auth_count / 15.0, 1.0)
    request_signal = min(request_rate / 100.0, 1.0)
    time_signal = min(time_deviation_sec / 3600.0, 1.0)

    # Weighted combination keeps the score in [0, 1].
    score = (0.5 * auth_signal) + (0.3 * request_signal) + (0.2 * time_signal)
    return float(score)


def is_anomalous(score: float, threshold: float = DEFAULT_ANOMALY_THRESHOLD) -> bool:
    """
    Decide whether an anomaly score should block key release.

    Args:
        score: anomaly score from compute_anomaly_score().
        threshold: cutoff above which the request is treated as anomalous.

    Returns:
        True if score is greater than or equal to the threshold.
    """
    if not 0.0 <= score <= 1.0:
        raise ValueError("score must be within [0.0, 1.0]")
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be within [0.0, 1.0]")

    return score >= threshold
