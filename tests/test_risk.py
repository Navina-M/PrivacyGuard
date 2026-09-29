from dlp import risk_engine


def test_no_findings_is_low_risk():
    result = risk_engine.assess([])
    assert result["level"] == "LOW"
    assert result["score"] == 0


def test_critical_findings_raise_score():
    findings = [
        {"type": "PASSWORD_FIELD", "category": "Credentials", "severity": "CRITICAL", "confidence": 0.95},
        {"type": "AWS_ACCESS_KEY", "category": "Credentials", "severity": "CRITICAL", "confidence": 0.95},
        {"type": "PAN", "category": "Government Identifier", "severity": "HIGH", "confidence": 0.9},
    ]
    result = risk_engine.assess(findings)
    assert result["score"] > 50
    assert result["level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_multiple_categories_add_reason():
    findings = [
        {"type": "PAN", "category": "Government Identifier", "severity": "HIGH", "confidence": 0.9},
        {"type": "PASSWORD_FIELD", "category": "Credentials", "severity": "CRITICAL", "confidence": 0.9},
        {"type": "BANK_ACCOUNT_IN", "category": "Financial Information", "severity": "HIGH", "confidence": 0.9},
    ]
    result = risk_engine.assess(findings)
    joined = " ".join(result["reasons"])
    assert "government identifier" in joined.lower()
    assert "credential" in joined.lower()


def test_explain_finding_low_confidence_flags_review():
    finding = {"type": "BANK_ACCOUNT_IN", "category": "Financial Information",
               "severity": "HIGH", "confidence": 0.4, "source": "regex"}
    explanation = risk_engine.explain_finding(finding)
    assert explanation["confidence"] == "Low"
    assert "review" in explanation["reason"].lower()


def test_explain_finding_credentials_recommend_rotation():
    finding = {"type": "API_KEY_GENERIC", "category": "Credentials",
               "severity": "CRITICAL", "confidence": 0.95, "source": "regex"}
    explanation = risk_engine.explain_finding(finding)
    assert "rotate" in explanation["recommended_action"].lower()
