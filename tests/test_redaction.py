from dlp import redactor


def test_redact_replaces_span():
    text = "My password: hunter2 is secret."
    findings = [{"type": "PASSWORD_FIELD", "start": 3, "end": 20, "severity": "CRITICAL"}]
    redacted = redactor.redact_text(text, findings)
    assert "hunter2" not in redacted
    assert "[REDACTED - PASSWORD_FIELD]" in redacted


def test_redact_no_findings_returns_original():
    text = "Nothing sensitive here."
    assert redactor.redact_text(text, []) == text


def test_highlight_html_escapes_and_wraps():
    text = "Email: a@b.com"
    findings = [{"type": "EMAIL", "start": 7, "end": 14, "severity": "MEDIUM"}]
    html = redactor.highlight_html(text, findings)
    assert "<mark" in html
    assert "a@b.com" in html


def test_non_overlapping_keeps_first_span():
    text = "abcdefgh"
    findings = [
        {"type": "A", "start": 0, "end": 4, "severity": "HIGH"},
        {"type": "B", "start": 2, "end": 6, "severity": "LOW"},
    ]
    result = redactor._non_overlapping(findings)
    assert len(result) == 1
    assert result[0]["type"] == "A"
