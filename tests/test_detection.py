# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Detection-block parsing: the web-target replacement for the ASAN parser."""
import json

from harness.detection import (
    parse_detection,
    primary_class,
    trigger_route,
    detection_reason,
    fired_classes,
    detection_excerpt,
    signature,
    NO_ROUTE,
)


def _block(primary, classes, trigger_step=0, http=None, always_on=None):
    d = {
        "fired": bool(classes),
        "primary_class": primary,
        "classes": classes,
        "trigger_step_index": trigger_step,
        "evidence": {"always_on": always_on or {}, "http": http or []},
    }
    return f"<<<DETECTION>>>\n{json.dumps(d)}\n<<<END DETECTION>>>"


RACE = _block(
    "DATA_INTEGRITY_VIOLATION",
    ["DATA_INTEGRITY_VIOLATION", "UNEXPECTED_5XX"],
    trigger_step=1,
    http=[
        {"step_index": 0, "method": "POST", "path": "/api/login", "route": "/api/login", "status": 200},
        {"step_index": 1, "method": "POST", "path": "/api/recipes/101/like",
         "route": "/api/recipes/:id/like", "status": 200},
    ],
    always_on={"ranking_drift": [{"recipe_id": 101, "ranking_likes": -1, "actual_likes": 0}]},
)

CORS = _block(
    "CORS_POLICY_VIOLATION",
    ["CORS_POLICY_VIOLATION"],
    trigger_step=0,
    http=[{"step_index": 0, "method": "OPTIONS", "path": "/api/profile",
           "route": "/api/profile", "status": 204}],
    always_on={"cors": [{"origin": "https://attacker.test"}]},
)


# ── parse_detection ──────────────────────────────────────────────────────────

def test_parse_basic():
    d = parse_detection(RACE)
    assert d["primary_class"] == "DATA_INTEGRITY_VIOLATION"


def test_parse_none_without_block():
    assert parse_detection("no block here") is None
    assert parse_detection("") is None


def test_parse_takes_last_block():
    # An agent that iterated in one message leaves several; the last is the one
    # it stands behind.
    two = _block("HANG", ["HANG"]) + "\nthen\n" + RACE
    assert parse_detection(two)["primary_class"] == "DATA_INTEGRITY_VIOLATION"


def test_parse_skips_malformed_prefers_valid():
    bad = "<<<DETECTION>>>\n{ not json\n<<<END DETECTION>>>\n" + RACE
    assert parse_detection(bad)["primary_class"] == "DATA_INTEGRITY_VIOLATION"


# ── primary_class ────────────────────────────────────────────────────────────

def test_primary_class_reads_field():
    assert primary_class(RACE) == "DATA_INTEGRITY_VIOLATION"


def test_primary_class_falls_back_to_precedence():
    # No primary_class field, but a classes list — precedence picks integrity.
    d = {"classes": ["UNEXPECTED_5XX", "DATA_INTEGRITY_VIOLATION"]}
    block = f"<<<DETECTION>>>\n{json.dumps(d)}\n<<<END DETECTION>>>"
    assert primary_class(block) == "DATA_INTEGRITY_VIOLATION"


def test_primary_class_none_when_absent():
    assert primary_class("nothing") is None


# ── trigger_route ────────────────────────────────────────────────────────────

def test_trigger_route_uses_template():
    # Concrete path /api/recipes/101/like → route template.
    assert trigger_route(RACE) == "POST /api/recipes/:id/like"


def test_trigger_route_follows_trigger_index():
    assert trigger_route(CORS) == "OPTIONS /api/profile"


def test_trigger_route_none_without_http():
    assert trigger_route(_block("HANG", ["HANG"], http=[])) is None


# ── detection_reason ─────────────────────────────────────────────────────────

def test_reason_shape():
    r = detection_reason(RACE)
    assert r == {"primary_class": "DATA_INTEGRITY_VIOLATION",
                 "route": "POST /api/recipes/:id/like"}


# ── fired_classes ────────────────────────────────────────────────────────────

def test_fired_classes_ordered_by_precedence():
    assert fired_classes(RACE) == ["DATA_INTEGRITY_VIOLATION", "UNEXPECTED_5XX"]


def test_fired_classes_respects_n():
    assert fired_classes(RACE, n=1) == ["DATA_INTEGRITY_VIOLATION"]


def test_fired_classes_empty():
    assert fired_classes("") == []


# ── detection_excerpt ────────────────────────────────────────────────────────

def test_excerpt_has_class_and_route():
    ex = detection_excerpt(RACE)
    assert "DATA_INTEGRITY_VIOLATION" in ex
    assert "POST /api/recipes/:id/like" in ex


def test_excerpt_names_missing_block():
    ex = detection_excerpt("some stderr\nrunner error: boom")
    assert ex.startswith("<no detection block>")
    assert "boom" in ex


def test_excerpt_empty_input():
    assert detection_excerpt("") == ""


# ── signature ────────────────────────────────────────────────────────────────

def test_signature_from_block():
    crash = {"crash_type": "DATA_INTEGRITY_VIOLATION", "crash_output": RACE}
    assert signature(crash) == ("DATA_INTEGRITY_VIOLATION", "POST /api/recipes/:id/like")


def test_signature_prefers_parsed_primary_over_agent_tag():
    # Agent's free-text crash_type disagrees; the parsed primary_class wins.
    crash = {"crash_type": "i-broke-it", "crash_output": RACE}
    assert signature(crash)[0] == "DATA_INTEGRITY_VIOLATION"


def test_signature_falls_back_to_agent_tag_without_block():
    crash = {"crash_type": "SOME_CLASS", "crash_output": "no block"}
    assert signature(crash) == ("SOME_CLASS", NO_ROUTE)


def test_signature_unknown_when_nothing():
    assert signature({}) == ("unknown", NO_ROUTE)
