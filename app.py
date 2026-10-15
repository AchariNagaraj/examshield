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
    "package_version": 0,
    "revoked_packages": [],
    "incident_resolved": False,
    "incident_resolution": "",
    "incident_resolution_time": "",
    "replacement_requested": False,
    "replacement_pending_authorization": False,
    "exam_on_hold": False,

    # Module 2 state
    "key_release_engine": None,
    "timestamp_valid": False,
    "certificate_valid": False,
    "anomaly_score": 0.10,
    "threshold": 0.70,
    "key_release_approved": False,
    "key_release_message": "Waiting for authorization",

    "emergency_lock": False,
    "emergency_lock_reason": None,
    "emergency_lock_time": None,

    "center_authenticated": False,
    "center_id": "center_001",
    "certificate_status": "NOT VERIFIED",
    "ca_status": "NOT VERIFIED",

    "session": None,
    "session_established": False,
    "exam_active": False,
    "exam_ended": False,
    "exam_end_time": None,
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
    # A replacement after an incident must be explicitly selected.
    if demo_state["emergency_lock"]:
        if not (
            demo_state.get("incident_resolved", False)
            and demo_state.get("replacement_requested", False)
        ):
            flash(
                "Resolve the incident and select Replace Paper first.",
                "error",
            )
            return redirect(url_for("papers"))
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

        # Record replacement and invalidate the previous in-memory package.
        old_version = demo_state.get("package_version", 0)

        if demo_state.get("package") is not None:
            demo_state.setdefault("revoked_packages", []).append(old_version)

        demo_state["package_version"] = old_version + 1
        package["package_version"] = demo_state["package_version"]

        demo_state["package"] = package
        demo_state["center_ids"] = center_ids
        demo_state["paper_name"] = paper.filename
        demo_state["package_ready"] = True
        if demo_state.get("replacement_requested", False):
            demo_state["replacement_pending_authorization"] = True
            demo_state["replacement_requested"] = False
            demo_state["exam_on_hold"] = False

        # Reset state belonging to the previous exam.
        demo_state["key_release_approved"] = False
        demo_state["session"] = None
        demo_state["session_key"] = None
        demo_state["session_established"] = False
        demo_state["exam_active"] = False
        demo_state["exam_ended"] = False
        demo_state["exam_end_time"] = None
        demo_state["merkle_root"] = None
        demo_state["answer_leaves"] = []
        demo_state["answers_collected"] = 0
        demo_state["verification_result"] = None
        demo_state["integrity_details"] = None
        demo_state["report_text"] = None
        demo_state["report_path"] = None

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
        emergency_lock=demo_state["emergency_lock"],
        emergency_lock_reason=demo_state["emergency_lock_reason"],
        emergency_lock_time=demo_state["emergency_lock_time"],
        incident_resolved=demo_state.get("incident_resolved", False),
        incident_resolution=demo_state.get("incident_resolution", ""),
        incident_resolution_time=demo_state.get("incident_resolution_time", ""),
        replacement_pending_authorization=demo_state.get(
            "replacement_pending_authorization", False
        ),
        replacement_requested=demo_state.get("replacement_requested", False),
        exam_on_hold=demo_state.get("exam_on_hold", False),
    )
@app.route("/key-release/authorize", methods=["POST"])
def authorize_key_release():
    """Run the real Module 2 controlled key-release checks."""

    center_id = request.form.get("center_id", "").strip()

    if demo_state["emergency_lock"]:
        demo_state["key_release_approved"] = False
        demo_state["key_release_message"] = "Emergency Lock is active."
        flash(
            "Key release blocked! Emergency Lock is active.",
            "error"
        )
        return redirect(url_for("key_release"))

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
                message if "key release approved" in message.lower()
                else f"Key release approved: {message}",
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

@app.route("/key-release/emergency-lock", methods=["POST"])
def activate_emergency_lock():
    reason = request.form.get("reason", "").strip()

    if not reason:
        reason = "Suspected examination-paper security incident"

    if demo_state["emergency_lock"]:
        flash("Emergency Lock is already active.", "error")
        return redirect(url_for("key_release"))

    # Activate Emergency Lock
    demo_state["emergency_lock"] = True
    demo_state["emergency_lock_reason"] = reason
    demo_state["emergency_lock_time"] = datetime.now(
        timezone.utc
    ).isoformat()

    # Suspend an active exam without marking it as completed
    demo_state["exam_active"] = False

    # Block further key-release approvals
    demo_state["key_release_approved"] = False
    demo_state["key_release_message"] = "Emergency Lock is active."

    # Record the emergency in the audit chain
    audit_log = demo_state.get("audit_log_object")

    if audit_log is None:
        audit_log = AuditLog()

    audit_log.add_entry(
        "EMERGENCY_LOCK_ACTIVATED",
        {
            "center_id": demo_state["center_id"],
            "reason": reason,
            "timestamp": demo_state["emergency_lock_time"],
        },
    )

    demo_state["audit_log_object"] = audit_log
    demo_state["audit_log"] = audit_log.get_chain()
    demo_state["integrity_verified"] = audit_log.verify_chain()

    flash(
        "Emergency Lock activated. Further key releases are blocked.",
        "error",
    )

    return redirect(url_for("key_release"))


@app.route("/key-release/resolve-incident", methods=["POST"])
def resolve_incident():
    if not demo_state["emergency_lock"]:
        flash("There is no active incident to resolve.", "error")
        return redirect(url_for("key_release"))
    if demo_state.get("incident_resolved", False):
        flash("This incident has already been resolved.", "error")
        return redirect(url_for("key_release"))
    resolution = request.form.get("resolution", "").strip()

    if not resolution:
        flash("Please provide the incident resolution details.", "error")
        return redirect(url_for("key_release"))

    # Record resolution in the existing audit chain
    audit_log = demo_state.get("audit_log_object")

    if audit_log is None:
        audit_log = AuditLog()

    resolved_at = datetime.now(timezone.utc).isoformat()

    audit_log.add_entry(
        "INCIDENT_RESOLVED",
        {
            "center_id": demo_state["center_id"],
            "resolution": resolution,
            "timestamp": resolved_at,
            "previous_lock_reason": demo_state.get(
                "emergency_lock_reason", ""
            ),
        },
    )

    # Update the audit state without replacing earlier entries
    demo_state["audit_log_object"] = audit_log
    demo_state["audit_log"] = audit_log.get_chain()
    demo_state["integrity_verified"] = audit_log.verify_chain()

    # Mark the incident resolved, but do not release any key
    demo_state["incident_resolved"] = True
    demo_state["incident_resolution"] = resolution
    demo_state["incident_resolution_time"] = resolved_at

    # Keep Emergency Lock active until a separate authorized action
    # explicitly lifts it after investigation.
    flash(
        "Incident resolution recorded. Emergency Lock remains active.",
        "success",
    )

    return redirect(url_for("key_release"))

@app.route("/incident/decision", methods=["POST"])
def incident_decision():
    if not demo_state["emergency_lock"]:
        flash("No active Emergency Lock.", "error")
        return redirect(url_for("key_release"))

    if not demo_state.get("incident_resolved", False):
        flash("Resolve the incident before choosing an action.", "error")
        return redirect(url_for("key_release"))

    decision = request.form.get("decision", "").strip()

    if decision == "hold":
        demo_state["exam_on_hold"] = True
        demo_state["replacement_requested"] = False
        demo_state["replacement_pending_authorization"] = False

        flash(
            "Exam remains ON HOLD. Emergency Lock is still active.",
            "success",
        )
        return redirect(url_for("key_release"))

    if decision == "replace":
        demo_state["exam_on_hold"] = False
        demo_state["replacement_requested"] = True
        demo_state["replacement_pending_authorization"] = False

        flash(
            "Replacement selected. Prepare the replacement paper next.",
            "success",
        )
        return redirect(url_for("papers"))

    flash("Please select a valid incident decision.", "error")
    return redirect(url_for("key_release"))

@app.route("/incident/resume", methods=["POST"])
def resume_after_incident():
    if not demo_state["emergency_lock"]:
        flash("Emergency Lock is not active.", "error")
        return redirect(url_for("key_release"))

    if not demo_state.get("incident_resolved", False):
        flash("Resolve the incident first.", "error")
        return redirect(url_for("key_release"))

    if not demo_state.get("replacement_pending_authorization", False):
        flash(
            "Prepare a replacement paper before resuming this exam.",
            "error",
        )
        return redirect(url_for("key_release"))

    if not demo_state.get("package_ready", False):
        flash("No replacement package is ready.", "error")
        return redirect(url_for("key_release"))

    # Explicit authorization to resume; a fresh key release is required.
    demo_state["emergency_lock"] = False
    demo_state["emergency_lock_reason"] = None
    demo_state["emergency_lock_time"] = None
    demo_state["incident_resolved"] = False
    demo_state["replacement_pending_authorization"] = False
    demo_state["key_release_approved"] = False
    demo_state["key_release_message"] = (
        "Replacement prepared. Fresh key authorization required."
    )

    audit_log = demo_state.get("audit_log_object")
    if audit_log is None:
        audit_log = AuditLog()

    audit_log.add_entry(
        "REPLACEMENT_AUTHORIZED_FOR_RESUMPTION",
        {
            "center_id": demo_state["center_id"],
            "package_version": demo_state["package_version"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

    demo_state["audit_log_object"] = audit_log
    demo_state["audit_log"] = audit_log.get_chain()
    demo_state["integrity_verified"] = audit_log.verify_chain()

    flash(
        "Resumption authorized. Perform a fresh key-release authorization.",
        "success",
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
        exam_active=demo_state["exam_active"],
        exam_ended=demo_state["exam_ended"],
        exam_end_time=demo_state["exam_end_time"],
        emergency_lock=demo_state["emergency_lock"],
    )
@app.route("/sessions/end", methods=["GET", "POST"])
def end_session():
    print("🔥 END SESSION ROUTE HIT")
    try:
        if not demo_state["session_established"]:
            flash("No active exam session.", "error")
            return redirect(url_for("sessions"))

        if not demo_state["exam_active"]:
            flash("Exam session is not active.", "error")
            return redirect(url_for("sessions"))

        # Stop the exam
        demo_state["exam_active"] = False
        demo_state["exam_ended"] = True
        print("🔥 exam_active =", demo_state["exam_active"])
        print("🔥 exam_ended =", demo_state["exam_ended"])
        demo_state["exam_end_time"] = datetime.now(timezone.utc).isoformat()

        # Create final integrity records
        tree = MerkleTree()

        # Preserve the existing audit history, including emergency events.
        audit_log = demo_state.get("audit_log_object")
        if audit_log is None:
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

        # Record exam end
        audit_log.add_entry(
            "EXAM_ENDED",
            {
                "center_id": demo_state["center_id"],
                "answers_collected": len(answer_leaves),
            },
        )

        # Generate final Merkle root
        root = tree.build_tree()

        demo_state["merkle_root"] = root.hex()
        demo_state["audit_log"] = audit_log.get_chain()
        demo_state["audit_log_object"] = audit_log
        demo_state["answer_leaves"] = answer_leaves
        demo_state["answers_collected"] = len(answer_leaves)
        demo_state["integrity_verified"] = audit_log.verify_chain()
        demo_state["verification_result"] = None

        flash(
            "Exam session ended and final integrity data was generated successfully.",
            "success"
        )

    except Exception as e:
        flash(f"Failed to end exam session: {str(e)}", "error")

    return redirect(url_for("sessions"))
@app.route("/sessions/start", methods=["POST"])
def start_session():
    try:
        if demo_state["emergency_lock"]:
            flash(
                "Cannot start exam: Emergency Lock is active. Exam is on hold.",
                "error",
            )
            return redirect(url_for("sessions"))
        center_id = request.form.get("center_id", "").strip()

        if not center_id:
            flash("Please select an examination center.", "error")
            return redirect(url_for("sessions"))
        demo_state["center_id"] = center_id

        session = start_new_session(center_id)
        
        demo_state["exam_active"] = True
        demo_state["exam_ended"] = False
        demo_state["exam_end_time"] = None

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
        if not demo_state["exam_ended"]:
            flash("Please end the exam session first.", "error")
            return redirect(url_for("integrity"))

        if demo_state["audit_log_object"] and demo_state["merkle_root"]:
            flash("Final integrity data has already been generated.", "success")
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
# Normal verification requires an ended exam.
# If Emergency Lock is active, allow verification of the
# available evidence even if the exam never reached its end state.
        if (
            not demo_state["exam_ended"]
            and not demo_state.get("emergency_lock", False)
        ):
            flash("Please end the exam session first.", "error")
            return redirect(url_for("verification"))
        # Emergency Lock may interrupt the exam before integrity data is finalized.
        if demo_state.get("emergency_lock", False):
            package = dict(demo_state["package"]) if demo_state["package"] else {}

            if not package:
                package = {}

            package["emergency_lock"] = True

            result = {
                "overall": False,
                "exam_on_hold": True,
                "signature_valid": None,
                "merkle_valid": None,
                "audit_valid": (
                    demo_state["audit_log_object"].verify_chain()
                    if demo_state.get("audit_log_object")
                    else None
                ),
                "message": (
                    "Emergency Lock is active. The exam is on hold; "
                    "final integrity data may be incomplete."
                ),
            }

            demo_state["verification_result"] = result
            demo_state["integrity_details"] = get_integrity_details(result)

            flash(
                "Verification status: ON HOLD. Final integrity data is incomplete.",
                "error",
            )
            return redirect(url_for("verification"))

        # Normal verification still requires finalized integrity data.
        if not demo_state["answer_leaves"] or not demo_state["merkle_root"]:
            flash(
                "Exam integrity data is not finalized. Please end the exam session first.",
                "error",
            )
            return redirect(url_for("verification"))


        package = dict(demo_state["package"]) if demo_state["package"] else {}
        print("DEBUG package_ready:", demo_state.get("package_ready"))
        print("DEBUG package keys:", list(package.keys()))
        if not package:
            flash(
                "Exam paper package is not available. Verification can only check the finalized answer integrity.",
                "error",
            )
            return redirect(url_for("verification"))

        # Give Module 6 the same answer leaves and Merkle root
        # generated by Module 5.
        package["collected_answers"] = demo_state["answer_leaves"]
        package["claimed_merkle_root"] = demo_state["merkle_root"]
        package["emergency_lock"] = demo_state.get("emergency_lock", False)
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
        package["emergency_lock"] = demo_state.get("emergency_lock", False)
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