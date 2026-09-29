"""
PrivacyGuard Edge — Flask Application Entry Point.

Universal local DLP scanner for documents, spreadsheets, source code, images, and text.
Ensures zero data leakage with 100% on-device processing.

Routes:
  GET  /                     Landing page with Upload, Direct Text Scanner & Presets
  POST /analyze              Execute full analysis pipeline on file or pasted text
  GET  /redact/<id>          Download redacted text with custom style options
  GET  /report/<id>          Download formatted PDF risk report
  GET  /export/json/<id>     Export structured findings as JSON
  GET  /export/csv/<id>      Export structured findings as CSV
  POST /api/scan             REST API endpoint for programmatic scanning
  GET  /system-status        Diagnostics, rule catalog, and engine status
  GET  /health               Liveness healthcheck
"""
import os
import uuid
import traceback
from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, flash, jsonify, Response
)

from dlp import extractor, detector, ner, risk_engine, redactor, report_pdf, ai_status
from dlp.security import validate_and_build_path, check_size, safe_delete, UploadRejected, MAX_UPLOAD_BYTES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
REPORT_DIR = os.path.join(BASE_DIR, "static", "uploads", "reports")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "privacyguard-edge-secret-dev-key")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES  # 100 MB configurable cap

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# In-memory session store for local/dev usage
_RESULTS = {}

# Sample text presets for 1-click testing
SAMPLE_PRESETS = {
    "employee_kyc": {
        "title": "Employee KYC & Financial Record",
        "text": """CONFIDENTIAL - INTERNAL USE ONLY
Employee Onboarding Form
Name: Rajesh Sharma
Employee ID: EMP-98421
Email: rajesh.sharma@enterprise-tech.in
Phone: +91 9876543210
Date of Birth: 14/08/1988
Aadhaar Number: 5489 1234 8924
PAN Card: ABCPS1234F
Bank Account: 918273645120 (HDFC Bank)
IFSC Code: HDFC0001234
UPI ID: rajesh.sharma@okaxis
Annual CTC: ₹28,50,000 per annum
Blood Group: O+
Emergency Contact: +91 9123456780
Residence Pincode: 560001 (Bangalore, Karnataka)"""
    },
    "devops_cloud": {
        "title": "DevOps & Cloud Credentials Config",
        "text": """# Production Infrastructure Configuration (DO NOT DISTRIBUTE)
[aws_production]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[api_integrations]
openai_api_key = sk-proj-mockSecretOpenAiKeyForTesting1234567890abcdef
github_token = ghp_mockGithubTokenForTesting1234567890ab
stripe_live_secret = sk_test_51MockStripeSecretKeyForTesting1234567890ab
slack_bot_token = xoxb-mockslacktoken123456789012345678901234
database_url = postgres://dbadmin:SuperP@ssw0rd2026!@192.168.1.105:5432/customer_db
jwt_signing_secret = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.G3s2f7h4"""
    },
    "healthcare_patient": {
        "title": "Medical Center Patient Admission",
        "text": """METRO HEALTHCARE HOSPITAL - PATIENT DISCHARGE SUMMARY
Strictly Private & Confidential Medical Record

Patient Name: Emily Watson
Date of Birth: 22/05/1991
Age: 35 years old
Patient MRN: MRN-8472910
Medical Record Number: RX-992140
Blood Group: A-
Contact Email: emily.watson91@gmail.com
Primary Phone: +1 (555) 234-5678
US SSN: 987-65-4321
Billing Card: 4532 0150 1234 5671 (Visa)
CVV: 842
Zip Code: 90210
Diagnosis & Notes: Patient presented with symptoms; prescribed medications.
Payment processed via insurance account."""
    },
    "icon_rich_profile": {
        "title": "Modern Profile with Icons & Symbols (📞 ✉️ 💳 🆔 📍)",
        "text": """👤 Rajesh Sharma (Senior Security Engineer)
✉️ rajesh.sharma@enterprise-tech.in
📞 +91 9876543210
📍 560001 (Bangalore, Karnataka)
🎂 14/08/1988
🆔 Aadhaar: 5489 1234 8924
🪪 PAN: ABCPS1234F
💳 Card: 4532 0150 1234 5671
💰 Salary: ₹28,50,000 per annum
🔒 Secret Key = AKIAIOSFODNN7EXAMPLE
🩸 Blood Group: O+"""
    }
}



@app.route("/")
def index():
    return render_template("index.html", presets=SAMPLE_PRESETS, max_mb=MAX_UPLOAD_BYTES // (1024 * 1024))


@app.route("/dashboard")
def dashboard_redirect():
    return redirect(url_for("index"))


@app.route("/analyze", methods=["POST"])
def analyze():
    pasted_text = request.form.get("pasted_text", "").strip()
    upload = request.files.get("document")

    # If no file uploaded and no pasted text provided
    if (upload is None or upload.filename == "") and not pasted_text:
        flash("Please upload a document or paste text to analyze.")
        return redirect(url_for("index"))

    temp_path = None
    filename = "Pasted_Snippet.txt"
    text = ""
    extraction = {}

    try:
        if upload and upload.filename != "":
            filename = upload.filename
            file_bytes = upload.read()
            check_size(file_bytes)
            temp_path = validate_and_build_path(upload.filename, UPLOAD_DIR)
            with open(temp_path, "wb") as f:
                f.write(file_bytes)

            # Extract text
            extraction = extractor.extract_text(temp_path)
            text = extraction.get("text", "")
        else:
            # Pasted text mode
            text = pasted_text
            extraction = {
                "text": text,
                "source_type": "text_snippet",
                "char_count": len(text),
                "word_count": len(text.split()),
                "line_count": text.count("\n") + 1,
                "note": "Analyzed from direct text input",
            }

        # Run Hybrid Detection: Regex + Checksums + NER
        regex_findings = detector.detect(text)
        ner_findings = ner.detect_entities(text)
        all_findings = detector.deduplicate(regex_findings + ner_findings)
        all_findings.sort(key=lambda f: (-f.get("confidence", 0), f.get("start", 0)))

        # Risk Engine Assessment
        assessment = risk_engine.assess(all_findings)

        # Explanations for HIGH & CRITICAL findings
        explanations = [
            risk_engine.explain_finding(f)
            for f in all_findings
            if f.get("severity") in ("HIGH", "CRITICAL")
        ]

        # Semantic Highlighted HTML for interactive review
        highlighted = redactor.highlight_html(text, all_findings)

        # Pre-generate default redacted previews
        redacted_tagged = redactor.redact_text(text, all_findings, style="TAG")
        redacted_masked = redactor.redact_text(text, all_findings, style="MASK")
        redacted_blocks = redactor.redact_text(text, all_findings, style="BLOCK")

        result_id = uuid.uuid4().hex
        _RESULTS[result_id] = {
            "filename": filename,
            "text": text,
            "findings": all_findings,
            "assessment": assessment,
            "explanations": explanations,
            "extraction_note": extraction.get("note"),
            "extraction": extraction,
            "highlighted": highlighted,
            "redacted_tagged": redacted_tagged,
            "redacted_masked": redacted_masked,
            "redacted_blocks": redacted_blocks,
        }

        return render_template(
            "results.html",
            result_id=result_id,
            filename=filename,
            extraction=extraction,
            findings=all_findings,
            assessment=assessment,
            explanations=explanations,
            highlighted=highlighted,
            redacted_tagged=redacted_tagged,
            redacted_masked=redacted_masked,
            redacted_blocks=redacted_blocks,
            ner_status=ner.ner_status(),
        )

    except UploadRejected as e:
        flash(str(e))
        return redirect(url_for("index"))
    except Exception:
        app.logger.error("Analysis failed:\n%s", traceback.format_exc())
        flash("An error occurred while analyzing this content. Please verify the file and try again.")
        return redirect(url_for("index"))
    finally:
        safe_delete(temp_path)


@app.route("/redact/<result_id>")
def redact(result_id):
    result = _RESULTS.get(result_id)
    if not result:
        flash("That analysis session is no longer available. Please re-analyze the document.")
        return redirect(url_for("index"))

    style = request.args.get("style", "TAG").upper()
    redacted_text = redactor.redact_text(result["text"], result["findings"], style=style)

    out_path = os.path.join(REPORT_DIR, f"{result_id}_redacted_{style}.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(redacted_text)

    base_name = os.path.splitext(result["filename"])[0]
    return send_file(
        out_path,
        as_attachment=True,
        download_name=f"redacted_{base_name}_{style.lower()}.txt",
    )


@app.route("/report/<result_id>")
def report(result_id):
    result = _RESULTS.get(result_id)
    if not result:
        flash("That analysis session is no longer available. Please re-analyze the document.")
        return redirect(url_for("index"))

    out_path = os.path.join(REPORT_DIR, f"{result_id}_report.pdf")
    report_pdf.generate_report(
        out_path,
        result["filename"],
        result["assessment"],
        result["findings"],
        result["explanations"],
    )
    base_name = os.path.splitext(result["filename"])[0]
    return send_file(
        out_path,
        as_attachment=True,
        download_name=f"PrivacyGuardEdge_Report_{base_name}.pdf",
    )


@app.route("/export/json/<result_id>")
def export_json(result_id):
    result = _RESULTS.get(result_id)
    if not result:
        return jsonify({"error": "Result not found"}), 404

    payload = {
        "filename": result["filename"],
        "assessment": result["assessment"],
        "findings_count": len(result["findings"]),
        "findings": result["findings"],
        "explanations": result["explanations"],
    }
    return jsonify(payload)


@app.route("/export/csv/<result_id>")
def export_csv(result_id):
    result = _RESULTS.get(result_id)
    if not result:
        flash("Result not found.")
        return redirect(url_for("index"))

    csv_data = redactor.export_findings_csv(result["findings"])
    base_name = os.path.splitext(result["filename"])[0]
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename=findings_{base_name}.csv"}
    )


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """REST API endpoint for programmatic scanning."""
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    if not text:
        return jsonify({"error": "No text provided in request body"}), 400

    regex_findings = detector.detect(text)
    ner_findings = ner.detect_entities(text)
    all_findings = detector.deduplicate(regex_findings + ner_findings)
    all_findings.sort(key=lambda f: (-f.get("confidence", 0), f.get("start", 0)))

    assessment = risk_engine.assess(all_findings)
    redacted_text = redactor.redact_text(text, all_findings, style=data.get("style", "TAG"))

    return jsonify({
        "status": "success",
        "risk_level": assessment["level"],
        "risk_score": assessment["score"],
        "findings_count": len(all_findings),
        "findings": all_findings,
        "recommendation": assessment["recommendation"],
        "redacted_text": redacted_text,
    })


@app.route("/system-status")
def system_status():
    return render_template("system_status.html", status=ai_status.full_status())


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "PrivacyGuard Edge",
        "version": "2.0.0",
        "privacy": "100% on-device local execution",
    })


@app.errorhandler(413)
def too_large(_e):
    max_mb = MAX_UPLOAD_BYTES // (1024 * 1024)
    flash(f"File exceeds the maximum allowed upload size of {max_mb} MB.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
