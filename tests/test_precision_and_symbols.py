"""
tests/test_precision_and_symbols.py

Verify high-precision sensitive data detection:
- Zero false positives on common uppercase words, headers, and dates without context.
- High recall on sensitive data preceded by icons (📞, ✉️, 💳, 🆔, 🎂, 📍, 🔒, 💰, ₹, $).
- Full preservation of Unicode symbols and icons.
"""
from dlp import detector, extractor, ner, redactor


def test_no_false_positive_on_common_uppercase_words():
    """Ensure words like INTERNAL, SECURITY, CONFIDENTIAL, DOCUMENT, TRANSFER are never detected as SWIFT codes."""
    text = "CONFIDENTIAL - INTERNAL USE ONLY. DOCUMENT TRANSFER AND SECURITY PROTOCOL."
    findings = detector.detect(text)
    types = [f["type"] for f in findings]
    assert "SWIFT_BIC" not in types
    assert "BANK_ACCOUNT_IN" not in types


def test_no_false_positive_on_random_dates():
    """Ensure regular publication/meeting dates without birth context are not flagged as DOB."""
    text = "The quarterly financial report was published on 15/03/2024 and reviewed on 20/04/2024."
    findings = detector.detect(text)
    types = [f["type"] for f in findings]
    assert "DOB" not in types


def test_no_false_positive_on_standalone_numbers():
    """Ensure random 10-digit timestamps or tracking numbers without bank keywords/icons are not flagged as bank accounts."""
    text = "Order tracking sequence: 1712894563. Build duration was 4928103948 ms."
    findings = detector.detect(text)
    types = [f["type"] for f in findings]
    assert "BANK_ACCOUNT_IN" not in types


def test_icon_based_phone_detection():
    text = "Reach out: 📞 +91 9876543210 or 📱 9876543211"
    findings = detector.detect(text)
    types = [f["type"] for f in findings]
    assert "PHONE_IN" in types


def test_icon_based_email_detection():
    text = "Send reports to: ✉️ security.lead@enterprise.com and 📧 audit@fintech.io"
    findings = detector.detect(text)
    types = [f["type"] for f in findings]
    assert "EMAIL" in types
    assert len([f for f in findings if f["type"] == "EMAIL"]) >= 2


def test_icon_based_card_detection():
    text = "💳 Card: 4532 0150 1234 5671 (Visa Gold)"
    findings = detector.detect(text)
    types = [f["type"] for f in findings]
    assert "CREDIT_CARD" in types


def test_icon_based_aadhaar_and_pan_detection():
    text = "🆔 5489 1234 8924\n🪪 ABCPS1234F"
    findings = detector.detect(text)
    types = [f["type"] for f in findings]
    assert "AADHAAR" in types
    assert "PAN" in types


def test_icon_based_dob_detection():
    text = "🎂 14/08/1988"
    findings = detector.detect(text)
    types = [f["type"] for f in findings]
    assert "DOB" in types


def test_icon_based_salary_detection():
    text = "💰 Salary: ₹28,50,000 per annum and CTC: $175,000"
    findings = detector.detect(text)
    types = [f["type"] for f in findings]
    assert "SALARY_MENTION" in types


def test_icon_based_pincode_detection():
    text = "📍 560001 (Bangalore Office)"
    findings = detector.detect(text)
    types = [f["type"] for f in findings]
    assert "PINCODE_IN" in types


def test_ner_ignores_common_non_person_words():
    text = "Monday meeting about Application Form and Hospital Discharge Summary Notes in Bangalore, India."
    ner_findings = ner.detect_entities(text)
    flagged_values = [f["value"].lower() for f in ner_findings]
    assert "monday" not in flagged_values
    assert "hospital" not in flagged_values
    assert "india" not in flagged_values
    assert "form" not in flagged_values


def test_e2e_clean_text_no_unwanted_words():
    from app import app
    client = app.test_client()
    text = "CONFIDENTIAL - INTERNAL USE ONLY. The project was submitted on 15/03/2024 by the development team in Bangalore, India. Order ref: 1849204819."
    response = client.post("/api/scan", json={"text": text, "style": "TAG"})
    assert response.status_code == 200
    data = response.get_json()
    types = [f["type"] for f in data["findings"]]
    assert "SWIFT_BIC" not in types
    assert "BANK_ACCOUNT_IN" not in types
    assert "DOB" not in types


def test_e2e_symbols_and_icons_analysis():
    from app import app
    client = app.test_client()
    text = "👤 Rajesh Sharma\n✉️ rajesh@example.com\n📞 +91 9876543210\n🎂 14/08/1988\n💳 4532 0150 1234 5671\n💰 ₹28,50,000\n📍 560001"
    response = client.post("/api/scan", json={"text": text, "style": "TAG"})
    assert response.status_code == 200
    data = response.get_json()
    types = [f["type"] for f in data["findings"]]
    assert "EMAIL" in types
    assert "PHONE_IN" in types
    assert "DOB" in types
    assert "CREDIT_CARD" in types
    assert "SALARY_MENTION" in types
    assert "PINCODE_IN" in types

