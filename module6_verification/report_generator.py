"""
Module 6 — Verification & Reporting
Owner: Elisha

Generates a human-readable integrity report from verification results,
for inclusion in the viva demo / submission.
"""


def generate_integrity_report(verification_result: dict, center_id: str) -> str:
    """
    Build a plain-text/markdown integrity report from verification results.

    Args:
        verification_result: output of verifier.full_post_exam_verification().
        center_id: center the report is for.

    Returns:
        formatted report text.
    """
    raise NotImplementedError


def export_report_pdf(report_text: str, output_path: str) -> None:
    """
    Export a generated report to PDF.

    Args:
        report_text: text from generate_integrity_report().
        output_path: destination PDF file path.
    """
    raise NotImplementedError
