# ExamShield

**End-to-end secure architecture for offline Computer-Based Test (CBT) exam distribution and answer submission.**

Academic PBL project — cryptography and network security. Targets offline exam centers with unreliable connectivity, combining AES-256, RSA, ephemeral Diffie-Hellman, mutual TLS/PKI, HMAC watermarking, and Merkle-tree/hash-chained audit logging into a single deployable system.

## Architecture

| Component | Purpose |
|---|---|
| AES-256-GCM | Bulk encryption of exam papers and answers |
| RSA-2048/4096 | Digital signatures, non-repudiation, key wrapping |
| Ephemeral Diffie-Hellman | Per-session forward secrecy |
| Mutual TLS (X.509/PKI) | Center authentication |
| HMAC-SHA256 | Per-center watermarking for leak attribution |
| SHA-256 + Merkle Trees | Per-answer integrity |
| Hash-chained audit log | Tamper-evident event storage |
| Adaptive Key Release Engine | Time + certificate + anomaly gated key release |

## Folder Structure

```
examshield/
├── module1_board_prep/       # Joylin — paper encryption, signing, watermarking
├── module2_key_release/      # Nagaraj — adaptive key release engine
├── module3_center_auth/      # Divya — PKI setup, mutual TLS
├── module4_session_answers/  # Divya — DH session exchange, answer submission
├── module5_integrity_audit/  # Elisha — Merkle tree, hash-chained audit log
├── module6_verification/     # Elisha — post-exam verification, reporting
├── common/                   # shared constants
├── tests/                    # unit tests, one file per module
├── certs/                    # generated CA + center certs (gitignored contents)
├── data/                     # sample exam papers, generated packages (gitignored contents)
├── demo_flow.py              # end-to-end integration script
└── requirements.txt
```

## Module Ownership

| Module | Owner | Files |
|---|---|---|
| 1 — Exam Board Prep & Watermarking | **Joylin** | `crypto_utils.py`, `watermark.py`, `board_prep.py` |
| 2 — Adaptive Key Release Engine | **Nagaraj** | `anomaly_detector.py`, `key_release_engine.py` |
| 3 — Center Authentication (PKI/mTLS) | **Divya** | `pki_setup.py`, `mtls_auth.py` |
| 4 — Session Exchange & Answer Submission | **Divya** | `dh_session.py`, `answer_submission.py` |
| 5 — Integrity & Audit Log | **Elisha** | `merkle_tree.py`, `audit_log.py` |
| 6 — Verification & Reporting | **Elisha** | `verifier.py`, `report_generator.py` |

## Setup

```bash
git clone <repo-url>
cd examshield
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Working on Your Module

1. Checkout your module branch: `git checkout -b module<N>-<yourname>`
2. Implement the functions in your module's files (all stubbed with docstrings, raise `NotImplementedError`)
3. Write/pass tests in `tests/`
4. Push and open a PR into `main`

See `CONTRIBUTING.md` for full workflow.

## Running the Demo

Once all modules are implemented:
```bash
python demo_flow.py
```

## Status

🚧 Scaffold stage — all functions stubbed, implementation in progress per module owner.
