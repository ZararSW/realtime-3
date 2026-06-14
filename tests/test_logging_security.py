"""Verify the logging SecurityFilter redacts secret values (not just labels)."""
from scanner.logging_config import SecurityFilter


def test_api_key_value_is_redacted():
    flt = SecurityFilter()
    # Clearly synthetic value (no real provider prefix) that still matches the
    # redaction regex's 20+ [A-Za-z0-9_-] requirement, so it won't trip secret scanners.
    secret = "EXAMPLE_FAKE_API_KEY_0123456789"
    out = flt._sanitize_message(f"Using api_key={secret} for provider")
    assert secret not in out
    assert "***REDACTED***" in out


def test_password_value_is_redacted():
    flt = SecurityFilter()
    out = flt._sanitize_message("password=SuperSecret123")
    assert "SuperSecret123" not in out
    assert "***REDACTED***" in out
