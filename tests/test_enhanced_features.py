"""
tests/test_enhanced_features.py

Comprehensive tests for enhanced DLP features:
- Checksum validation (Luhn, Verhoeff, PAN)
- Multi-style redaction
- Large files and universal extraction
- REST API scanning
- CSV/JSON export
"""
import io
import json
import pytest
from app import app
from dlp import detector, extractor, redactor, risk_engine, security


def test_luhn_algorithm_validation():
    # Valid test card (Visa)
    assert detector.validate_luhn("4532015012345671") is True
    assert detector.validate_luhn("4111111111111111") is True
    # Invalid card number (fails Luhn)
    assert detector.validate_luhn("4532015012345679") is False


def test_verhoeff_algorithm_validation():
    # Valid Aadhaar with Verhoeff checksum
    assert detector.validate_verhoeff("548912348924") is True
    # Invalid checksum
    assert detector.validate_verhoeff("548912348921") is False


def test_pan_format_validation():
    # Valid individual PAN (4th letter 'P')
    assert detector.validate_pan("ABCPS1234F") is True
    # Valid company PAN (4th letter 'C')
    assert detector.validate_pan("AAACC1234K") is True
    # Invalid entity code
    assert detector.validate_pan("ABCXS1234F") is False


def test_custom_redaction_styles():
    text = "User contact is user@example.com and key is AKIAIOSFODNN7EXAMPLE."
    findings = [
        {"type": "EMAIL", "category": "Personal Information", "start": 16, "end": 32, "severity": "MEDIUM"},
        {"type": "AWS_ACCESS_KEY", "category": "Credentials", "start": 44, "end": 64, "severity": "CRITICAL"},
    ]

    # Tag style
    tag_redacted = redactor.redact_text(text, findings, style="TAG")
    assert "[REDACTED - EMAIL]" in tag_redacted
    assert "[REDACTED - AWS_ACCESS_KEY]" in tag_redacted

    # Minimal style
    minimal_redacted = redactor.redact_text(text, findings, style="MINIMAL")
    assert "[REDACTED]" in minimal_redacted

    # Mask style
    mask_redacted = redactor.redact_text(text, findings, style="MASK")
    assert "•" in mask_redacted
    assert "user@example.com" not in mask_redacted

    # Block style
    block_redacted = redactor.redact_text(text, findings, style="BLOCK")
    assert "█" in block_redacted


def test_csv_export_format():
    findings = [
        {"type": "EMAIL", "category": "Personal Information", "value": "u***r@test.com",
         "severity": "MEDIUM", "confidence": 0.95, "source": "regex", "start": 0, "end": 14}
    ]
    csv_out = redactor.export_findings_csv(findings)
    assert "Type,Category,Detected Value,Severity,Confidence,Source,Start,End" in csv_out
    assert "EMAIL" in csv_out
    assert "Personal Information" in csv_out


def test_large_upload_limit_config():
    # Default is 100 MB
    assert security.MAX_UPLOAD_BYTES == 100 * 1024 * 1024
    # Test checking valid and oversized buffers
    small_bytes = b"Hello world" * 100
    security.check_size(small_bytes)  # Should not raise

    with pytest.raises(security.UploadRejected):
        oversized_bytes = b"X" * (101 * 1024 * 1024)
        security.check_size(oversized_bytes)


def test_flask_api_scan_endpoint():
    client = app.test_client()
    payload = {
        "text": "Secret AWS Key: AKIAIOSFODNN7EXAMPLE and email test@enterprise.in",
        "style": "TAG"
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["findings_count"] >= 2
    assert "redacted_text" in data
    assert "[REDACTED" in data["redacted_text"]


def test_flask_analyze_pasted_text():
    client = app.test_client()
    response = client.post(
        "/analyze",
        data={"pasted_text": "Personal PAN card is ABCPS1234F and phone is +91 9876543210"},
        follow_redirects=True
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Scan Completed Locally" in html
    assert "ABCPS1234F" in html or "Government Identifier" in html
