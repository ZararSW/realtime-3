"""Smoke tests for the AI policy layer (rule-based / no-AI fallback)."""
from scanner import ai_policy


def test_enable_ai_flag_is_boolean():
    assert isinstance(ai_policy.ENABLE_AI, bool)


def test_aipolicy_class_is_available():
    assert hasattr(ai_policy, "AIPolicy")


def test_get_payloads_returns_a_list_without_ai():
    form_metadata = {"action": "/login", "inputs": [{"name": "q", "type": "text"}]}
    payloads = ai_policy.get_payloads(form_metadata, enable_ai=False)
    assert isinstance(payloads, list)
