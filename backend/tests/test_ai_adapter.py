"""Tests for the AI adapter: guarded/naive prompts, validation, cache, fallback."""

import json
import os
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from shared.contracts import (
    ActionProposal,
    ActionType,
    Confidence,
    Event,
    Explanation,
    Incident,
    IncidentStatus,
    Category,
    Severity,
    LinkRule,
)
from backend.incidents.demo_data import get_scenario_data
import backend.ai.adapter as adapter_module
from backend.ai.adapter import (
    _build_guarded_user_prompt,
    _build_naive_user_prompt,
    _fallback_explanation,
    _validate_and_build,
    explain,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_incident_and_events():
    """Return the account takeover incident and its events."""
    events_raw, incidents_raw = get_scenario_data("account")
    # Build proper Pydantic objects
    events = [Event.model_validate(e) for e in events_raw]
    incident = Incident.model_validate(incidents_raw[0])
    return incident, events


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Redirect cache directory to a temporary path for each test."""
    monkeypatch.setattr(adapter_module, "_CACHE_DIR", tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# Test: guarded vs naive prompt construction
# ---------------------------------------------------------------------------

def test_guarded_prompt_warns_about_untrusted_data(sample_incident_and_events):
    incident, events = sample_incident_and_events
    prompt = _build_guarded_user_prompt(incident, events)
    assert "UNTRUSTED DATA" in prompt
    assert "attacker-controlled" in prompt.lower() or "UNTRUSTED DATA" in prompt


def test_naive_prompt_does_not_warn(sample_incident_and_events):
    incident, events = sample_incident_and_events
    prompt = _build_naive_user_prompt(incident, events)
    assert "UNTRUSTED DATA" not in prompt
    assert "attacker-controlled" not in prompt.lower()


def test_guarded_and_naive_prompts_are_different(sample_incident_and_events):
    incident, events = sample_incident_and_events
    guarded = _build_guarded_user_prompt(incident, events)
    naive = _build_naive_user_prompt(incident, events)
    assert guarded != naive


def test_guarded_prompt_caps_attribute_values(sample_incident_and_events):
    """Attribute values longer than 300 chars must be truncated in the guarded prompt."""
    incident, events = sample_incident_and_events
    # Mutate first event's attributes to have a long value
    long_val = "A" * 1000
    events[0].attributes["injected"] = long_val
    prompt = _build_guarded_user_prompt(incident, events)
    assert long_val not in prompt
    assert "A" * 300 in prompt


# ---------------------------------------------------------------------------
# Test: output validation
# ---------------------------------------------------------------------------

def test_validate_drops_hallucinated_event_ids(sample_incident_and_events):
    incident, events = sample_incident_and_events
    raw = {
        "summary": "Test summary",
        "observed_facts": [
            {"text": "Real fact", "evidence_event_ids": ["evt-100"]},
            {"text": "Hallucinated fact", "evidence_event_ids": ["evt-FAKE-9999"]},
        ],
        "interpretation": "Test interpretation.",
        "potential_impact": ["Some impact"],
        "confidence_label": "likely",
        "recommended_next_steps": ["Step 1"],
        "recommended_actions": [],
    }
    expl = _validate_and_build(raw, incident, events, "en", "guarded")
    # evt-100 is real — should be kept
    assert "evt-100" in expl.observed_facts[0].evidence_event_ids
    # evt-FAKE-9999 is hallucinated — should be dropped
    for fact in expl.observed_facts:
        assert "evt-FAKE-9999" not in fact.evidence_event_ids


def test_validate_drops_out_of_scope_targets(sample_incident_and_events):
    incident, events = sample_incident_and_events
    raw = {
        "summary": "Test",
        "observed_facts": [],
        "interpretation": "Test.",
        "potential_impact": [],
        "confidence_label": "low",
        "recommended_next_steps": [],
        "recommended_actions": [
            {"action_type": "lock_account", "target_id": "priya.rec", "reason": "Valid"},
            {"action_type": "lock_account", "target_id": "ceo", "reason": "Attacker tried to add"},
        ],
    }
    expl = _validate_and_build(raw, incident, events, "en", "guarded")
    target_ids = [a.target_id for a in expl.recommended_actions]
    assert "priya.rec" in target_ids  # in affected_users
    assert "ceo" not in target_ids  # out of scope — dropped


def test_validate_drops_invalid_action_types(sample_incident_and_events):
    incident, events = sample_incident_and_events
    raw = {
        "summary": "Test",
        "observed_facts": [],
        "interpretation": "Test.",
        "potential_impact": [],
        "confidence_label": "low",
        "recommended_next_steps": [],
        "recommended_actions": [
            {"action_type": "IGNORE_ALL_RULES", "target_id": "priya.rec", "reason": "Injected"},
        ],
    }
    expl = _validate_and_build(raw, incident, events, "en", "guarded")
    assert len(expl.recommended_actions) == 0


def test_validate_fixes_unknown_confidence(sample_incident_and_events):
    incident, events = sample_incident_and_events
    raw = {
        "summary": "s",
        "observed_facts": [],
        "interpretation": "i",
        "potential_impact": [],
        "confidence_label": "very_high_definitely",
        "recommended_next_steps": [],
        "recommended_actions": [],
    }
    expl = _validate_and_build(raw, incident, events, "en", "guarded")
    assert expl.confidence_label == Confidence.needs_review


# ---------------------------------------------------------------------------
# Test: fallback
# ---------------------------------------------------------------------------

def test_fallback_when_llm_client_raises(sample_incident_and_events, monkeypatch):
    incident, events = sample_incident_and_events

    class BrokenClient(adapter_module.LLMClient):
        def generate(self, system_prompt, user_prompt):
            raise RuntimeError("Simulated LLM failure")

    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MODEL", "gemini-test")
    monkeypatch.setattr(adapter_module, "_get_client", lambda: BrokenClient())

    result = explain(incident, events, "en", "guarded")
    assert result.generated_by == "fallback"
    assert result.incident_id == incident.incident_id


def test_fallback_when_llm_returns_invalid_json(sample_incident_and_events, monkeypatch):
    incident, events = sample_incident_and_events

    class BadJsonClient(adapter_module.LLMClient):
        def generate(self, system_prompt, user_prompt):
            return "This is not JSON at all!"

    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_API_KEY", "fake-key")
    monkeypatch.setattr(adapter_module, "_get_client", lambda: BadJsonClient())

    result = explain(incident, events, "en", "guarded")
    assert result.generated_by == "fallback"


# ---------------------------------------------------------------------------
# Test: cache
# ---------------------------------------------------------------------------

def test_cache_used_when_provider_is_none(sample_incident_and_events, isolated_cache):
    incident, events = sample_incident_and_events
    # Pre-populate cache
    cached_expl = _fallback_explanation(incident, "en", "guarded")
    cached_expl_dict = cached_expl.model_dump(mode="json")
    cached_expl_dict["generated_by"] = "llm"  # pretend it came from LLM
    cache_file = isolated_cache / f"{incident.incident_id}_en.json"
    cache_file.write_text(json.dumps(cached_expl_dict), encoding="utf-8")

    result = explain(incident, events, "en", "guarded")
    assert result.generated_by == "cache"  # loaded from cache, not LLM


def test_no_cache_and_provider_none_returns_fallback(sample_incident_and_events, monkeypatch):
    incident, events = sample_incident_and_events
    monkeypatch.setenv("LLM_PROVIDER", "none")

    result = explain(incident, events, "en", "guarded")
    assert result.generated_by == "fallback"


def test_successful_llm_call_writes_cache(sample_incident_and_events, monkeypatch, isolated_cache):
    incident, events = sample_incident_and_events

    good_response = json.dumps({
        "summary": "Test incident.",
        "observed_facts": [{"text": "Auth failures seen.", "evidence_event_ids": ["evt-101"]}],
        "interpretation": "Brute force attempt followed by success.",
        "potential_impact": ["Account compromise"],
        "confidence_label": "likely",
        "recommended_next_steps": ["Lock the account."],
        "recommended_actions": [
            {"action_type": "lock_account", "target_id": "priya.rec", "reason": "Suspicious login."}
        ],
    })

    class GoodClient(adapter_module.LLMClient):
        def generate(self, system_prompt, user_prompt):
            return good_response

    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_API_KEY", "fake-key")
    monkeypatch.setattr(adapter_module, "_get_client", lambda: GoodClient())

    result = explain(incident, events, "en", "guarded")
    assert result.generated_by == "llm"
    cache_file = isolated_cache / f"{incident.incident_id}_en.json"
    assert cache_file.exists()


# ---------------------------------------------------------------------------
# Test: language gating
# ---------------------------------------------------------------------------

def test_non_english_returns_english_by_default(sample_incident_and_events, monkeypatch):
    incident, events = sample_incident_and_events
    monkeypatch.setenv("LLM_PROVIDER", "none")
    monkeypatch.delenv("ALLOW_UNREVIEWED_LANGS", raising=False)

    result = explain(incident, events, "hi", "guarded")
    assert result.lang == "en"  # falls back to en when ALLOW_UNREVIEWED_LANGS=false


def test_non_english_allowed_when_flag_set(sample_incident_and_events, monkeypatch, isolated_cache):
    incident, events = sample_incident_and_events
    monkeypatch.setenv("ALLOW_UNREVIEWED_LANGS", "true")
    monkeypatch.setenv("LLM_PROVIDER", "none")

    result = explain(incident, events, "hi", "guarded")
    # With no cache and no LLM, it falls back; lang should stay "hi"
    assert result.lang == "hi"
