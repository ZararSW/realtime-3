"""Tests for the report data-transformation helpers in run.py."""
import json

import pytest

from scanner.cli import (
    extract_target_url,
    make_json_serializable,
    map_priority_to_severity,
    determine_severity_from_type,
)


def test_extract_target_url_prefers_first_matching_field():
    assert extract_target_url({"target_url": "http://a", "url": "http://b"}) == "http://a"
    assert extract_target_url({"site": "http://c"}) == "http://c"
    assert extract_target_url({}) == "Unknown Target"


def test_make_json_serializable_handles_sets_and_nesting():
    out = make_json_serializable({"a": {1, 2}, "b": [{"c": {3}}]})
    assert sorted(out["a"]) == [1, 2]
    assert out["b"][0]["c"] == [3]
    # The whole structure must now be JSON-serializable.
    json.dumps(out)


@pytest.mark.parametrize(
    "priority,severity",
    [
        ("Critical", "High"),
        ("High", "Medium"),
        ("Medium", "Low"),
        ("Low", "Info"),
        ("Unknown", "Low"),
    ],
)
def test_map_priority_to_severity(priority, severity):
    assert map_priority_to_severity(priority) == severity


@pytest.mark.parametrize(
    "vuln_type,severity",
    [
        ("SQL Injection", "Critical"),
        ("command execution", "Critical"),
        ("Reflected XSS", "High"),
        ("csrf token missing", "High"),
        ("Information Disclosure", "Medium"),
        ("random low thing", "Low"),
    ],
)
def test_determine_severity_from_type(vuln_type, severity):
    assert determine_severity_from_type(vuln_type) == severity
