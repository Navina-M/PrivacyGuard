from dlp import detector


def test_email_detected():
    findings = detector.detect("Contact me at test.user@example.com please.")
    types = [f["type"] for f in findings]
    assert "EMAIL" in types


def test_pan_detected():
    findings = detector.detect("PAN card number: ABCDE1234F")
    types = [f["type"] for f in findings]
    assert "PAN" in types


def test_password_field_detected():
    findings = detector.detect("password: Sup3rSecret!99")
    types = [f["type"] for f in findings]
    assert "PASSWORD_FIELD" in types


def test_aws_key_detected():
    findings = detector.detect("AKIAABCDEFGHIJKLMNOP is my old key, rotate it.")
    types = [f["type"] for f in findings]
    assert "AWS_ACCESS_KEY" in types


def test_ipv4_detected():
    findings = detector.detect("Server IP: 192.168.1.25")
    types = [f["type"] for f in findings]
    assert "IPV4" in types


def test_no_findings_on_clean_text():
    findings = detector.detect("This is a perfectly ordinary sentence about weather.")
    # weather sentence should not trigger government/financial/credential types
    high_risk_types = {"PAN", "AADHAAR", "PASSWORD_FIELD", "AWS_ACCESS_KEY"}
    found_types = {f["type"] for f in findings}
    assert not (found_types & high_risk_types)


def test_detected_value_stored():
    findings = detector.detect("password: Sup3rSecret!99")
    values = [f["value"] for f in findings]
    assert any("Sup3rSecret!99" in v for v in values)


def test_deduplicate_removes_exact_duplicates():
    findings = [
        {"type": "EMAIL", "value": "a@b.com", "start": 0, "end": 5},
        {"type": "EMAIL", "value": "a@b.com", "start": 0, "end": 5},
    ]
    result = detector.deduplicate(findings)
    assert len(result) == 1
