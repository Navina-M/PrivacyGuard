from dlp import ner, ai_status


def test_ner_detect_entities_never_raises_when_unavailable():
    # Should return [] rather than raise, regardless of whether spaCy
    # happens to be installed in the test environment.
    result = ner.detect_entities("John works at Example Corp in Chennai.")
    assert isinstance(result, list)


def test_ner_status_shape():
    status = ner.ner_status()
    assert "available" in status
    assert "reason" in status
    if not status["available"]:
        assert status["reason"]  # must explain why


def test_snapdragon_status_never_claims_enabled():
    status = ai_status.snapdragon_status()
    assert status["status"] != "Enabled"
    assert "Not Available" in status["status"] or "Deployment Ready" in status["status"]


def test_full_status_shape():
    status = ai_status.full_status()
    assert "system" in status
    assert "ai_backend" in status
    assert "snapdragon" in status
    assert "privacy_mode" in status
    assert status["privacy_mode"]["enabled"] is True
