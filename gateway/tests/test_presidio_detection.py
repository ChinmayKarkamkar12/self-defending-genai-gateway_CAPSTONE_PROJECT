from app.core.redaction.analyzer import analyze_text


def test_detects_email_and_phone():
    text = "Contact me at jane.smith@example.com or call 415-555-2671."

    spans = analyze_text(text, ["EMAIL_ADDRESS", "PHONE_NUMBER"])

    types = {s.entity_type for s in spans}
    assert "EMAIL_ADDRESS" in types
    assert "PHONE_NUMBER" in types


def test_restricts_to_enabled_entities():
    text = "Contact me at jane.smith@example.com or call 415-555-2671."

    spans = analyze_text(text, ["EMAIL_ADDRESS"])

    assert all(s.entity_type == "EMAIL_ADDRESS" for s in spans)
