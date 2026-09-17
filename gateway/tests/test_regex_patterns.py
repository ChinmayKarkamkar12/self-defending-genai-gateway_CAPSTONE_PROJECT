from app.core.redaction.patterns import detect_api_keys, detect_credit_cards


def test_detects_api_key_format():
    text = "My key is sk-abcdefghijklmnopqrstuvwxyz123456, don't share it."

    spans = detect_api_keys(text)

    assert len(spans) == 1
    assert spans[0].entity_type == "API_KEY"


def test_detects_aws_key_format():
    text = "AKIAABCDEFGHIJKLMNOP was in the log."

    spans = detect_api_keys(text)

    assert len(spans) == 1


def test_credit_card_luhn_validation():
    # Documented Luhn-valid Visa test number (never a real card).
    valid_text = "Card on file: 4111111111111111."
    spans = detect_credit_cards(valid_text)
    assert len(spans) == 1
    assert spans[0].entity_type == "CREDIT_CARD"

    # Same length, deliberately not Luhn-valid.
    invalid_text = "Random digits: 1234567890123456."
    spans = detect_credit_cards(invalid_text)
    assert spans == []
