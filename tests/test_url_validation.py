"""Tests for run.validate_and_normalize_url — the CLI's first line of defense."""
import pytest

from run import validate_and_normalize_url


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "http://example.com"),
        ("http://example.com", "http://example.com"),
        ("https://testphp.vulnweb.com/", "https://testphp.vulnweb.com/"),
        ("  https://x.io/a?b=1  ", "https://x.io/a?b=1"),
        ("localhost:8080", "http://localhost:8080"),
    ],
)
def test_normalizes_valid_urls(raw, expected):
    assert validate_and_normalize_url(raw) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "ftp://example.com",
        "javascript:alert(1)",
        "data:text/html,<script>",
        "file:///etc/passwd",
        "vbscript:msgbox(1)",
    ],
)
def test_rejects_invalid_or_dangerous_urls(bad):
    with pytest.raises(ValueError):
        validate_and_normalize_url(bad)
