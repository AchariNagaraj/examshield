"""
Shared constants used across ExamShield modules.
"""

# --- Crypto ---
AES_KEY_SIZE_BYTES = 32          # AES-256
RSA_KEY_SIZE_BITS = 2048         # bump to 4096 for board's root key if desired
GCM_NONCE_SIZE_BYTES = 12
SHA256_DIGEST_SIZE_BYTES = 32

# --- Key Release Engine ---
DEFAULT_KEY_RELEASE_WINDOW_SEC = 300      # +/- 5 min around scheduled start
DEFAULT_ANOMALY_THRESHOLD = 0.7

# --- Session ---
SESSION_ID_LENGTH = 16

# --- Paths (override in local dev / CI as needed) ---
CERTS_DIR = "certs/"
DATA_DIR = "data/"
