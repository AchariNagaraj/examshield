from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
)
import os
import secrets
from datetime import datetime, timezone
import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509

from module1_board_prep.board_prep import prepare_exam_package, save_package
from module2_key_release.key_release_engine import KeyReleaseEngine
from module3_center_auth.pki_setup import (
    generate_ca,
    issue_center_cert,
    save_cert_bundle,
)
from module3_center_auth.mtls_auth import authenticate_center
from module4_session_answers.dh_session import (
    start_new_session,
    generate_dh_keypair,
    derive_shared_key,
    generate_dh_parameters,
)
from module4_session_answers.answer_submission import (
    encrypt_answer,
    submit_answer,
    batch_collect_answers,
)
from module5_integrity_audit.merkle_tree import MerkleTree
from module5_integrity_audit.audit_log import AuditLog
from module6_verification.verifier import (
    full_post_exam_verification,
    get_integrity_details,
)
from module6_verification.report_generator import (
    generate_integrity_report,
    export_report_pdf,
)
# Pre-generate DH parameters at application startup.
generate_dh_parameters()
app = Flask(__name__)

app.secret_key = "examshield-demo-secret"

# Temporary server-side state for the local prototype.
# This lets the later modules access the package created here.
demo_state = {
    "package": None,
    "center_ids": [],
    "paper_name": None,
    "package_ready": False,
    "session_key": None,

    # Module 2 state
    "key_release_engine": None,
    "timestamp_valid": False,
    "certificate_valid": False,
    "anomaly_score": 0.10,
    "threshold": 0.70,
    "key_release_approved": False,
    "key_release_message": "Waiting for authorization",

    "center_authenticated": False,
    "center_id": "center_001",
    "certificate_status": "NOT VERIFIED",
    "ca_status": "NOT VERIFIED",

    "session": None,
    "session_established": False,
    "answers_collected": 0,

    "merkle_root": None,
    "audit_log": None,
    "audit_log_object": None,
    "answer_leaves": [],
    "integrity_verified": False,

    "verification_result": None,
    "report_text": None,
    "report_path": None,

    "ca_key": None,
    "ca_cert": None,
}
# Load or create the persistent ExamShield Root CA
ca_key_path = os.path.join("certs", "examshield_ca.key.pem")
ca_cert_path = os.path.join("certs", "examshield_ca.cert.pem")

os.makedirs("certs", exist_ok=True)

if os.path.exists(ca_key_path) and os.path.exists(ca_cert_path):
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

else:
    ca_key, ca_cert = generate_ca()

    with open(ca_key_path, "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(ca_cert_path, "wb") as f:
        f.write(
            ca_cert.public_bytes(serialization.Encoding.PEM)
        )

demo_state["ca_key"] = ca_key
demo_state["ca_cert"] = ca_cert

@app.route("/")
def dashboard():
    return render_template(
        "dashboard.html",
        active_page="Dashboard",
        center_id=demo_state["center_id"],
    )


@app.route("/papers")
def papers():
    return render_template(
        "papers.html",
        active_page="Exam Papers",
        package_ready=demo_state["package_ready"],
        paper_name=demo_state["paper_name"],
        center_ids=demo_state["center_ids"]
    )


@app.route("/papers/prepare", methods=["POST"])
def prepare_paper():
    """Run the real Module 1 exam-paper preparation flow."""

    paper = request.files.get("paper")
    center_ids_text = request.form.get("center_ids", "").strip()

    # Validate uploaded paper
    if not paper or not paper.filename:
        flash("Please select an exam paper.", "error")
        return redirect(url_for("papers"))

    # Validate centers
    center_ids = [
        center.strip()
        for center in center_ids_text.split(",")
        if center.strip()
    ]

    if not center_ids:
        flash("Please enter at least one exam center.", "error")
        return redirect(url_for("papers"))

    # Create temporary upload directory
    upload_dir = os.path.join("data", "ui_uploads")
    os.makedirs(upload_dir, exist_ok=True)

    paper_path = os.path.join(upload_dir, paper.filename)
    paper.save(paper_path)

    try:
        # Master secret used by the existing watermark implementation.
        master_secret = secrets.token_bytes(32)

        # Run YOUR real Module 1 implementation
        package = prepare_exam_package(
            paper_path=paper_path,
            center_ids=center_ids,
            master_secret=master_secret,
        )

        # Save one package per center
        output_dir = os.path.join("data", "exam_packages")
        save_package(package, output_dir)

        # Store package for the later modules
        demo_state["package"] = package
        demo_state["center_ids"] = center_ids
        demo_state["paper_name"] = paper.filename
        demo_state["package_ready"] = True

        flash(
            f"Exam paper secured successfully for {len(center_ids)} center(s).",
            "success",
        )

    except Exception as e:
        flash(f"Paper preparation failed: {str(e)}", "error")

    return redirect(url_for("papers"))


def get_registered_centers():
    cert_dir = "certs"

    if not os.path.exists(cert_dir):
        return []

    centers = []

    for filename in os.listdir(cert_dir):
        if filename.endswith(".cert.pem") and filename != "examshield_ca.cert.pem":
            center_id = filename.rsplit(".cert.pem", 1)[0]
            centers.append(center_id)

    return sorted(centers)


@app.route("/centers")
def centers():
    registered_centers = get_registered_centers()

    return render_template(
        "centers.html",
        active_page="Center Authorization",
        center_id=demo_state["center_id"],
        centers=registered_centers,
        authenticated=demo_state["center_authenticated"],
        certificate_status=demo_state["certificate_status"],
        ca_status=demo_state["ca_status"],
    )
@app.route("/centers/authorize", methods=["POST"])
def authorize_center():
    center_id = request.form.get("center_id", "").strip()

    try:
        ca_path = os.path.join("certs", "examshield_ca.cert.pem")
        center_path = os.path.join(
            "certs",
            f"{center_id}.cert.pem"
        )

        if not os.path.exists(ca_path):
            raise FileNotFoundError("CA certificate not found.")

        if not os.path.exists(center_path):
            raise FileNotFoundError("Center certificate not found.")

        with open(ca_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        with open(center_path, "rb") as f:
            center_cert = x509.load_pem_x509_certificate(f.read())

        authenticated = authenticate_center(
            center_cert,
            ca_cert
        )
        demo_state["center_id"] = center_id
        demo_state["center_authenticated"] = authenticated
        demo_state["certificate_status"] = (
            "VALID" if authenticated else "INVALID"
        )
        demo_state["ca_status"] = (
            "TRUSTED" if authenticated else "NOT TRUSTED"
        )

        if authenticated:
            flash(
                "Center authenticated successfully using PKI certificate verification.",
                "success"
            )
        else:
            flash(
                "Center authentication failed.",
                "error"
            )

    except Exception as e:
        demo_state["center_authenticated"] = False
        demo_state["certificate_status"] = "ERROR"
        demo_state["ca_status"] = "ERROR"

        flash(f"Center authentication failed: {str(e)}", "error")

    return redirect(url_for("centers"))

@app.route("/centers/register", methods=["POST"])
def register_center():
    center_id = request.form.get("center_id", "").strip()

    if not center_id:
        flash("Center ID cannot be empty.", "error")
        return redirect(url_for("centers"))

    try:
        # Check whether this center is already registered
        cert_path = os.path.join("certs", f"{center_id}.cert.pem")

        if os.path.exists(cert_path):
            flash(f"Center '{center_id}' is already registered.", "error")
            return redirect(url_for("centers"))

        # Use the existing ExamShield CA
        ca_key = demo_state["ca_key"]
        ca_cert = demo_state["ca_cert"]

        if ca_key is None or ca_cert is None:
            raise ValueError("ExamShield CA is not available.")

        # Generate a unique certificate and key for the new center
        center_key, center_cert = issue_center_cert(
            center_id,
            ca_key,
            ca_cert
        )

        # Save the center certificate and private key
        save_cert_bundle(
            center_id,
            center_key,
            center_cert,
            "certs"
        )

        flash(
            f"Center '{center_id}' registered successfully.",
            "success"
        )

    except Exception as e:
        flash(f"Center registration failed: {str(e)}", "error")

    return redirect(url_for("centers"))
@app.route("/key-release")
def key_release():
    registered_centers = get_registered_centers()

    return render_template(
        "key_release.html",
        active_page="Key Release",
        center_id=demo_state["center_id"],
        centers=registered_centers,
        timestamp_valid=demo_state["timestamp_valid"],
        certificate_valid=demo_state["certificate_valid"],
        anomaly_score=demo_state["anomaly_score"],
        threshold=demo_state["threshold"],
        approved=demo_state["key_release_approved"],
    )
@app.route("/key-release/authorize", methods=["POST"])
def authorize_key_release():
    """Run the real Module 2 controlled key-release checks."""

    center_id = request.form.get("center_id", "").strip()

    if not center_id:
        flash("Please select an examination center.", "error")
        return redirect(url_for("key_release"))
    demo_state["center_id"] = center_id

    try:
        # Make sure Module 1 has already prepared a package.
        if not demo_state["package_ready"] or not demo_state["package"]:
            flash("Please prepare an exam paper first.", "error")
            return redirect(url_for("key_release"))

        # ---------------------------------------------------------
        # 1. Load the CA certificate saved by demo_flow.py
        # ---------------------------------------------------------
        ca_cert_path = os.path.join(
            "certs",
            "examshield_ca.cert.pem"
        )

        center_cert_path = os.path.join(
            "certs",
            f"{center_id}.cert.pem"
        )

        if not os.path.exists(ca_cert_path):
            raise FileNotFoundError(
                "CA certificate not found. Run demo_flow.py first."
            )

        if not os.path.exists(center_cert_path):
            raise FileNotFoundError(
                "Center certificate not found. Run demo_flow.py first."
            )

        with open(ca_cert_path, "rb") as file:
            ca_cert = x509.load_pem_x509_certificate(file.read())

        with open(center_cert_path, "rb") as file:
            center_cert_bytes = file.read()

        # ---------------------------------------------------------
        # 2. Create the Module 2 key-release engine
        # ---------------------------------------------------------
        exam_start_time = datetime.now(timezone.utc)

        engine = KeyReleaseEngine(
            exam_start_time=exam_start_time
        )

        engine.ca_cert = ca_cert

        # ---------------------------------------------------------
        # 3. Generate a board signing key for the demo timestamp
        # ---------------------------------------------------------
        board_timestamp_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        engine.board_pubkey = board_timestamp_key.public_key()

        # ---------------------------------------------------------
        # 4. Create a board-signed timestamp
        # ---------------------------------------------------------
        timestamp_text = exam_start_time.isoformat().replace(
            "+00:00",
            "Z"
        )

        signature = board_timestamp_key.sign(
            timestamp_text.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        signed_timestamp = json.dumps({
            "timestamp": timestamp_text,
            "signature": base64.b64encode(signature).decode("ascii"),
        }, separators=(",", ":")).encode("utf-8")

        # ---------------------------------------------------------
        # 5. Run the real Module 2 checks
        # ---------------------------------------------------------
        timestamp_valid = engine.verify_timestamp(
            signed_timestamp,
            engine.board_pubkey,
        )

        certificate_valid = engine.verify_certificate(
            center_cert_bytes,
            ca_cert,
        )

        anomaly_score = demo_state["anomaly_score"]

        approved, message = engine.request_release(
            center_id=center_id,
            cert_bytes=center_cert_bytes,
            signed_timestamp=signed_timestamp,
            anomaly_score=anomaly_score,
        )

        # ---------------------------------------------------------
        # 6. Save results for the UI
        # ---------------------------------------------------------
        demo_state["key_release_engine"] = engine
        demo_state["timestamp_valid"] = timestamp_valid
        demo_state["certificate_valid"] = certificate_valid
        demo_state["key_release_approved"] = approved
        demo_state["key_release_message"] = message

        if approved:
            flash(
                f"Key release approved: {message}",
                "success",
            )
        else:
            flash(
                f"Key release rejected: {message}",
                "error",
            )

    except Exception as e:
        demo_state["timestamp_valid"] = False
        demo_state["certificate_valid"] = False
        demo_state["key_release_approved"] = False
        demo_state["key_release_message"] = str(e)

        flash(
            f"Key release failed: {str(e)}",
            "error",
        )

    return redirect(url_for("key_release"))


@app.route("/sessions")
def sessions():
    registered_centers = get_registered_centers()

    return render_template(
        "sessions.html",
        active_page="Exam Sessions",
        centers=registered_centers,
        center_id=demo_state["center_id"],
        session_established=demo_state["session_established"],
        answers_collected=demo_state["answers_collected"],
    )
@app.route("/sessions/start", methods=["POST"])
def start_session():
    try:
        center_id = request.form.get("center_id", "").strip()

        if not center_id:
            flash("Please select an examination center.", "error")
            return redirect(url_for("sessions"))
        demo_state["center_id"] = center_id

        session = start_new_session(center_id)

        # Generate peer DH key pair to simulate the board side.
        peer_private, peer_public = generate_dh_keypair(
            session["parameters"]
        )

        # Derive the same session key on both sides.
        center_shared_key = derive_shared_key(
            session["private_key"],
            peer_public
        )

        board_shared_key = derive_shared_key(
            peer_private,
            session["public_key"]
        )

        if center_shared_key != board_shared_key:
            raise ValueError("DH shared keys do not match.")

        demo_state["session"] = session
        demo_state["session_key"] = center_shared_key
        demo_state["session_established"] = True
        demo_state["answers_collected"] = 0

        flash(
            "Secure DH session established successfully.",
            "success"
        )

    except Exception as e:
        demo_state["session_established"] = False
        flash(f"Session creation failed: {str(e)}", "error")

    return redirect(url_for("sessions"))


@app.route("/integrity")
def integrity():
    return render_template(
        "integrity.html",
        active_page="Integrity & Audit",
        merkle_root=demo_state["merkle_root"],
        audit_log=demo_state["audit_log"],
        integrity_verified=demo_state["integrity_verified"],
    )
@app.route("/integrity/generate", methods=["POST"])
def generate_integrity():
    try:
        if not demo_state["session_established"]:
            flash("Start an exam session first.", "error")
            return redirect(url_for("integrity"))

        tree = MerkleTree()
        audit_log = AuditLog()
        answer_leaves = []
        # Demo answer records
        answers = [
            {
                "student_id": "STU001",
                "question_id": "Q1",
                "answer": "Answer submitted securely"
            },
            {
                "student_id": "STU002",
                "question_id": "Q1",
                "answer": "Another secure answer"
            }
        ]

        for answer in answers:
            leaf_data = json.dumps(
                answer,
                sort_keys=True,
                separators=(",", ":")
            ).encode("utf-8")

            tree.add_leaf(leaf_data)
            answer_leaves.append(leaf_data)

            audit_log.add_entry(
                "ANSWER_SUBMITTED",
                {
                    "student_id": answer["student_id"],
                    "question_id": answer["question_id"],
                    "leaf_hash": __import__("hashlib")
                    .sha256(leaf_data)
                    .hexdigest(),
                }
            )

        root = tree.build_tree()

        demo_state["merkle_root"] = root.hex()
        demo_state["audit_log"] = audit_log.get_chain()
        demo_state["audit_log_object"] = audit_log
        demo_state["answer_leaves"] = answer_leaves
        demo_state["integrity_verified"] = audit_log.verify_chain()
        demo_state["verification_result"] = None

        flash(
            "Merkle tree and audit chain generated successfully.",
            "success"
        )

    except Exception as e:
        demo_state["integrity_verified"] = False
        flash(f"Integrity generation failed: {str(e)}", "error")

    return redirect(url_for("integrity"))

@app.route("/verification")
def verification():
    result = demo_state["verification_result"]

    return render_template(
        "verification.html",
        active_page="Verification",
        center_id=demo_state["center_id"],
        verification_result=result,
        integrity_details=demo_state.get("integrity_details"),
    )


@app.route("/verification/run", methods=["POST"])
def run_verification():
    try:
        # Make sure the required previous modules have run.
        if not demo_state["package_ready"]:
            flash("Please prepare an exam paper first.", "error")
            return redirect(url_for("verification"))

        if not demo_state["session_established"]:
            flash("Please start the exam session first.", "error")
            return redirect(url_for("verification"))

        if not demo_state["audit_log_object"]:
            flash("Please generate the integrity proof first.", "error")
            return redirect(url_for("verification"))

        package = dict(demo_state["package"])

        # Give Module 6 the same answer leaves and Merkle root
        # generated by Module 5.
        package["collected_answers"] = demo_state["answer_leaves"]
        package["claimed_merkle_root"] = demo_state["merkle_root"]

        result = full_post_exam_verification(
            center_id=demo_state["center_id"],
            package=package,
            audit_log=demo_state["audit_log_object"],
        )

        demo_state["verification_result"] = result
        demo_state["integrity_details"] = get_integrity_details(result)

        if result["overall"]:
            flash(
                "Full post-exam verification completed successfully.",
                "success",
            )
        else:
            flash(
                "Verification completed, but one or more integrity checks failed.",
                "error",
            )

    except Exception as e:
        demo_state["verification_result"] = None
        flash(f"Verification failed: {str(e)}", "error")

    return redirect(url_for("verification"))

@app.route("/reports")
def reports():
    return render_template(
        "reports.html",
        active_page="Reports",
        center_id=demo_state["center_id"],
        verification_result=demo_state["verification_result"],
        report_text=demo_state.get("report_text"),
    )
@app.route("/reports/generate", methods=["POST"])
def generate_report():
    try:
        result = demo_state["verification_result"]

        if not result:
            flash("Run full verification first.", "error")
            return redirect(url_for("reports"))

        center_id = demo_state["center_id"]

        # Generate the report text
        report_text = generate_integrity_report(
            result,
            center_id
        )

        # Create reports directory
        report_dir = os.path.join("data", "reports")
        os.makedirs(report_dir, exist_ok=True)

        # PDF location
        report_path = os.path.join(
            report_dir,
            "examshield_integrity_report.pdf"
        )

        # Export PDF
        export_report_pdf(
            report_text,
            report_path
        )

        # Save report information in demo state
        demo_state["report_text"] = report_text
        demo_state["report_path"] = report_path

        flash("Integrity report generated successfully.", "success")

    except Exception as e:
        flash(
            f"Report generation failed: {str(e)}",
            "error"
        )

    return redirect(url_for("reports"))
@app.route("/reports/download")
def download_report():
    report_path = demo_state.get("report_path")

    if not report_path or not os.path.exists(report_path):
        flash("Please generate the integrity report first.", "error")
        return redirect(url_for("reports"))

    return send_file(
        report_path,
        as_attachment=True,
        download_name="ExamShield_Integrity_Report.pdf"
    )
@app.route("/verification/tamper-answer", methods=["POST"])
def tamper_answer_demo():
    try:
        if not demo_state["answer_leaves"]:
            flash("Please generate the integrity proof first.", "error")
            return redirect(url_for("verification"))

        # Make a copy so the original answer data is not permanently changed.
        tampered_answers = list(demo_state["answer_leaves"])

        # Modify the first submitted answer.
        original_answer = tampered_answers[0]
        tampered_answers[0] = original_answer + b" TAMPERED"

        package = dict(demo_state["package"])
        package["collected_answers"] = tampered_answers

        # IMPORTANT:
        # Use the original Merkle root generated before tampering.
        package["claimed_merkle_root"] = demo_state["merkle_root"]

        result = full_post_exam_verification(
            center_id=demo_state["center_id"],
            package=package,
            audit_log=demo_state["audit_log_object"],
        )

        demo_state["verification_result"] = result
        demo_state["integrity_details"] = get_integrity_details(result)

        if result["overall"]:
            flash("Unexpected result: tampered answer was accepted.", "error")
        else:
            flash(
                "Demo tampering detected: submitted answer integrity failed.",
                "error",
            )

    except Exception as e:
        flash(f"Tamper demonstration failed: {str(e)}", "error")

    return redirect(url_for("verification"))

if __name__ == "__main__":
    app.run(debug=True)