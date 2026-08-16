# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Judge + compare stages: prompt construction, output tag parsing, manifest."""
import json

from harness.judge import _parse_judge
from harness.prompts.judge_prompt import build_judge_prompt, build_compare_prompt
from harness.cli import _read_manifest, _next_bug_id, _append_manifest


# ── judge output parsing ─────────────────────────────────────────────────────

def test_parse_judge_new():
    v = _parse_judge("<judgment>NEW</judgment><reasoning>distinct root cause</reasoning>")
    assert v.judgment == "NEW"
    assert v.bug_id is None
    assert v.reasoning == "distinct root cause"


def test_parse_judge_dup_skip():
    v = _parse_judge("<judgment>DUP_SKIP</judgment><bug_id>2</bug_id><reasoning>same GIF overflow</reasoning>")
    assert v.judgment == "DUP_SKIP"
    assert v.bug_id == 2


def test_parse_judge_dup_better():
    v = _parse_judge("<judgment>DUP_BETTER</judgment><bug_id>0</bug_id><reasoning>smaller PoC, weak existing report</reasoning>")
    assert v.judgment == "DUP_BETTER"
    assert v.bug_id == 0


def test_parse_judge_dup_without_bug_id_falls_open():
    # DUP_* without a bug_id is incoherent — fail open to NEW so crashes
    # aren't silently dropped.
    v = _parse_judge("<judgment>DUP_SKIP</judgment><reasoning>forgot to say which</reasoning>")
    assert v.judgment == "NEW"


def test_parse_judge_unparseable_falls_open():
    v = _parse_judge("")
    assert v.judgment == "NEW"
    assert v.bug_id is None


def test_parse_judge_case_insensitive():
    v = _parse_judge("<judgment>new</judgment>")
    assert v.judgment == "NEW"


# ── judge prompt building ────────────────────────────────────────────────────

DETECTION_EXCERPT = """\
primary_class: DATA_INTEGRITY_VIOLATION
classes: DATA_INTEGRITY_VIOLATION, UNEXPECTED_5XX
trigger: POST /api/recipes/:id/like
evidence: ranking_drift, negative_counters"""


def test_judge_prompt_empty_manifest():
    p = build_judge_prompt(
        detection_excerpt=DETECTION_EXCERPT,
        dup_check="Compared against the log; the like-race root cause is not listed.",
        grade_status="crash_found", grade_score=1.0, poc_size=280,
        manifest_entries=[],
    )
    assert "first crash to reach the judge" in p
    assert "DATA_INTEGRITY_VIOLATION" in p
    assert "crash_found" in p
    assert "280 bytes" in p
    assert "<judgment>" in p


def test_judge_prompt_with_manifest():
    entries = [
        {"bug_id": 0, "run_idx": 3,
         "detection_excerpt": "primary_class: ORIGIN_ESCAPE\ntrigger: POST /api/signup",
         "report_text": None},
        {"bug_id": 1, "run_idx": 7,
         "detection_excerpt": "primary_class: UNSAFE_CONTENT_TYPE\ntrigger: POST /api/recipes",
         "report_text": "<capability>Stored HTML served with text/html.</capability>"},
    ]
    p = build_judge_prompt(
        detection_excerpt=DETECTION_EXCERPT, dup_check="novel",
        grade_status="crash_found", grade_score=1.0, poc_size=280,
        manifest_entries=entries,
    )
    assert "bug_00" in p and "report pending" in p
    assert "bug_01" in p and "report landed" in p
    assert "Stored HTML served" in p
    assert "ORIGIN_ESCAPE" in p


# ── compare prompt building ──────────────────────────────────────────────────

def test_compare_prompt_has_both():
    p = build_compare_prompt(
        report_a="<capability>Old analysis here.</capability>",
        report_b="<capability>New analysis here, more thorough.</capability>",
    )
    assert "Report A" in p
    assert "Report B" in p
    assert "Old analysis" in p
    assert "New analysis" in p
    assert "<winner>" in p


# ── manifest round-trip ──────────────────────────────────────────────────────

def test_manifest_empty(tmp_path):
    reports_root = tmp_path / "reports"
    assert _read_manifest(reports_root) == []
    assert _next_bug_id([]) == 0


def test_manifest_append_and_read(tmp_path):
    reports_root = tmp_path / "reports"
    _append_manifest(reports_root, 0, run_idx=3, excerpt="primary_class: ORIGIN_ESCAPE")
    _append_manifest(reports_root, 1, run_idx=7, excerpt="primary_class: DATA_INTEGRITY_VIOLATION")

    entries = _read_manifest(reports_root)
    assert len(entries) == 2
    assert entries[0]["bug_id"] == 0
    assert entries[0]["run_idx"] == 3
    assert "ORIGIN_ESCAPE" in entries[0]["detection_excerpt"]
    assert entries[0]["report_text"] is None  # no report.json landed
    assert _next_bug_id(entries) == 2


def test_manifest_picks_up_landed_report(tmp_path):
    reports_root = tmp_path / "reports"
    _append_manifest(reports_root, 0, run_idx=5, excerpt="primary_class: ORIGIN_ESCAPE")

    bug_dir = reports_root / "bug_00"
    bug_dir.mkdir()
    (bug_dir / "report.json").write_text(json.dumps({
        "bug_id": 0, "status": "report_submitted",
        "report": "<primitive>WRITE of size 239, controlled.</primitive>",
    }))

    entries = _read_manifest(reports_root)
    assert entries[0]["report_text"] == "<primitive>WRITE of size 239, controlled.</primitive>"
