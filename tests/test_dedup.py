# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Post-hoc dedup: signature extraction + results-tree grouping.

Summary-only view — the judge agent gates report dispatch in streaming mode;
dedup just answers "these N findings cluster into M signatures".
"""
import json

from harness.dedup import _signature, dedup, format_report, NO_ROUTE


def _block(primary, classes, trigger_step=1, http=None, always_on=None):
    d = {
        "fired": bool(classes),
        "primary_class": primary,
        "classes": classes,
        "trigger_step_index": trigger_step,
        "evidence": {"always_on": always_on or {}, "http": http or []},
    }
    return f"<<<DETECTION>>>\n{json.dumps(d)}\n<<<END DETECTION>>>"


# Same root cause (the like race), two concrete recipe ids — must dedupe to one
# signature because the route is templated.
RACE_101 = _block(
    "DATA_INTEGRITY_VIOLATION", ["DATA_INTEGRITY_VIOLATION"],
    http=[{"step_index": 1, "method": "POST", "path": "/api/recipes/101/like",
           "route": "/api/recipes/:id/like", "status": 200}])
RACE_909 = _block(
    "DATA_INTEGRITY_VIOLATION", ["DATA_INTEGRITY_VIOLATION"],
    http=[{"step_index": 1, "method": "POST", "path": "/api/recipes/909/like",
           "route": "/api/recipes/:id/like", "status": 200}])
CORS = _block(
    "CORS_POLICY_VIOLATION", ["CORS_POLICY_VIOLATION"], trigger_step=0,
    http=[{"step_index": 0, "method": "OPTIONS", "path": "/api/profile",
           "route": "/api/profile", "status": 204}])

SIG_RACE = ("DATA_INTEGRITY_VIOLATION", "POST /api/recipes/:id/like")
SIG_CORS = ("CORS_POLICY_VIOLATION", "OPTIONS /api/profile")


# ── _signature ───────────────────────────────────────────────────────────────

def test_signature_basic():
    crash = {"crash_type": "DATA_INTEGRITY_VIOLATION", "crash_output": RACE_101}
    assert _signature(crash) == SIG_RACE


def test_signature_route_template_collapses_ids():
    a = {"crash_type": "DATA_INTEGRITY_VIOLATION", "crash_output": RACE_101}
    b = {"crash_type": "DATA_INTEGRITY_VIOLATION", "crash_output": RACE_909}
    assert _signature(a) == _signature(b)


def test_signature_no_route_fallback():
    crash = {"crash_type": "HANG", "crash_output": "no block"}
    assert _signature(crash) == ("HANG", NO_ROUTE)


def test_signature_missing_fields():
    assert _signature({}) == ("unknown", NO_ROUTE)


# ── dedup (results tree walk) ────────────────────────────────────────────────

def _write_result(path, status, crash_type=None, crash_output=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    crash = None
    if crash_type is not None:
        crash = {
            "poc_path": "/tmp/poc.bin",
            "poc_bytes": "AAAA",
            "reproduction_command": "/work/run_poc.js /tmp/poc.bin",
            "crash_type": crash_type,
            "crash_output": crash_output or "",
            "exit_code": 2,
        }
    path.write_text(json.dumps({
        "target": "eathub", "status": status, "crash": crash,
        "verdict": None, "timings": {}, "error": None,
        "find_transcript": "stub", "grade_transcript": "stub",
    }))


def _build_tree(tmp_path):
    """3 findings on the race signature (one rejected), 1 CORS, plus a no-find."""
    root = tmp_path / "results" / "eathub" / "20260101T000000Z"
    _write_result(root / "run_000" / "result.json", "crash_found",
                  "DATA_INTEGRITY_VIOLATION", RACE_101)
    _write_result(root / "run_002" / "result.json", "crash_found",
                  "DATA_INTEGRITY_VIOLATION", RACE_909)  # different id, same sig
    _write_result(root / "run_003" / "result.json", "crash_rejected",
                  "DATA_INTEGRITY_VIOLATION", RACE_101)
    _write_result(root / "run_001" / "result.json", "crash_found",
                  "CORS_POLICY_VIOLATION", CORS)
    _write_result(root / "run_004" / "result.json", "no_crash_found")
    return root


def test_dedup_groups_duplicates(tmp_path):
    groups = dedup(_build_tree(tmp_path))
    assert set(groups.keys()) == {SIG_RACE, SIG_CORS}
    assert len(groups[SIG_RACE]) == 3
    assert len(groups[SIG_CORS]) == 1


def test_dedup_includes_rejected(tmp_path):
    groups = dedup(_build_tree(tmp_path))
    statuses = {status for _, status, _ in groups[SIG_RACE]}
    assert statuses == {"crash_found", "crash_rejected"}


def test_dedup_signature_prefers_parsed_class(tmp_path):
    root = tmp_path / "batch"
    _write_result(root / "run_000" / "result.json", "crash_found",
                  "free-text-nonsense", RACE_101)
    groups = dedup(root)
    assert SIG_RACE in groups


def test_dedup_skips_null_crash(tmp_path):
    groups = dedup(_build_tree(tmp_path))
    total = sum(len(v) for v in groups.values())
    assert total == 4


def test_dedup_walks_nested_batches(tmp_path):
    target_root = tmp_path / "results" / "eathub"
    _write_result(target_root / "20260101T000000Z" / "result.json", "crash_found",
                  "DATA_INTEGRITY_VIOLATION", RACE_101)
    _write_result(target_root / "20260102T000000Z" / "result.json", "crash_found",
                  "DATA_INTEGRITY_VIOLATION", RACE_909)
    groups = dedup(target_root)
    assert len(groups) == 1
    (_, entries), = groups.items()
    assert len(entries) == 2


def test_dedup_skips_malformed_json(tmp_path):
    root = tmp_path / "batch"
    _write_result(root / "run_000" / "result.json", "crash_found",
                  "DATA_INTEGRITY_VIOLATION", RACE_101)
    (root / "run_001").mkdir(parents=True)
    (root / "run_001" / "result.json").write_text("{ not valid json")
    groups = dedup(root)
    assert sum(len(v) for v in groups.values()) == 1


def test_dedup_empty_dir(tmp_path):
    assert dedup(tmp_path) == {}


# ── format_report ────────────────────────────────────────────────────────────

def test_format_report_sorted_by_count(tmp_path):
    report = format_report(dedup(_build_tree(tmp_path)), _build_tree(tmp_path))
    pos_race = report.index("DATA_INTEGRITY_VIOLATION")
    pos_cors = report.index("CORS_POLICY_VIOLATION")
    assert pos_race < pos_cors
    assert "[3x]" in report
    assert "[1x]" in report
    assert "2 unique signature(s) across 4 crash(es)" in report


def test_format_report_shows_route(tmp_path):
    report = format_report(dedup(_build_tree(tmp_path)), _build_tree(tmp_path))
    assert "at POST /api/recipes/:id/like" in report
    assert "at OPTIONS /api/profile" in report


def test_format_report_shows_relative_paths(tmp_path):
    root = _build_tree(tmp_path)
    report = format_report(dedup(root), root)
    assert "run_000/result.json" in report
    assert str(tmp_path) not in report


def test_format_report_shows_status(tmp_path):
    root = _build_tree(tmp_path)
    report = format_report(dedup(root), root)
    assert "(crash_found)" in report
    assert "(crash_rejected)" in report


def test_format_report_empty():
    assert format_report({}) == "No crashes found.\n"
