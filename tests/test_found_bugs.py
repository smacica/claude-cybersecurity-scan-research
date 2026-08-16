# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Runtime bug-sharing: found_bugs.jsonl write/read + detection-excerpt format."""
import json

from harness.artifacts import CrashArtifact
from harness.cli import _append_found, _read_found_summaries, _seed_found_bugs
from harness.prompts.find_prompt import build_find_prompt


def _block(primary, classes, route, always_on=None):
    d = {
        "fired": True, "primary_class": primary, "classes": classes,
        "trigger_step_index": 1,
        "evidence": {
            "always_on": always_on or {},
            "http": [{"step_index": 1, "method": route.split()[0],
                      "path": route.split()[1], "route": route.split()[1],
                      "status": 200}],
        },
    }
    return f"<<<DETECTION>>>\n{json.dumps(d)}\n<<<END DETECTION>>>"


RACE = _block("DATA_INTEGRITY_VIOLATION", ["DATA_INTEGRITY_VIOLATION"],
              "POST /api/recipes/:id/like",
              always_on={"ranking_drift": [{"recipe_id": 101, "ranking_likes": -1}]})
ORIGIN = _block("ORIGIN_ESCAPE", ["ORIGIN_ESCAPE"], "POST /api/signup",
                always_on={"origin_escape": [{"host": "attacker.test"}]})


# ── jsonl append/read round-trip (detection-excerpt format) ──────────────────

def _mk_crash(crash_type="DATA_INTEGRITY_VIOLATION", crash_output=RACE):
    return CrashArtifact(
        poc_path="/tmp/poc.bin",
        poc_bytes=b'{"steps":[]}',
        reproduction_command="/work/run_poc.js /tmp/poc.bin",
        crash_type=crash_type,
        crash_output=crash_output,
        exit_code=2,
    )


def test_append_writes_detection_excerpt(tmp_path):
    p = tmp_path / "found_bugs.jsonl"
    _append_found(p, _mk_crash(), run_idx=3)

    entry = json.loads(p.read_text().strip())
    assert entry["run_idx"] == 3
    assert "detection_excerpt" in entry
    assert "DATA_INTEGRITY_VIOLATION" in entry["detection_excerpt"]
    assert "POST /api/recipes/:id/like" in entry["detection_excerpt"]
    # Old ASAN-era fields are gone.
    assert "asan_excerpt" not in entry
    assert "top_frame" not in entry
    assert "crash_type" not in entry


def test_append_and_read_excerpts(tmp_path):
    p = tmp_path / "found_bugs.jsonl"
    _append_found(p, _mk_crash(), run_idx=0)
    _append_found(p, _mk_crash(crash_type="ORIGIN_ESCAPE", crash_output=ORIGIN), run_idx=1)

    excerpts = _read_found_summaries(p)
    assert len(excerpts) == 2
    assert "DATA_INTEGRITY_VIOLATION" in excerpts[0]
    assert "ORIGIN_ESCAPE" in excerpts[1]


def test_seed_then_append_mixed_formats(tmp_path):
    # Config-seeded entries are prose; runtime entries are detection excerpts.
    p = tmp_path / "found_bugs.jsonl"
    _seed_found_bugs(p, ["Malformed JSON body yields 500 instead of 400"])
    _append_found(p, _mk_crash(), run_idx=0)

    entries = _read_found_summaries(p)
    assert len(entries) == 2
    assert "Malformed JSON" in entries[0]           # config prose
    assert "DATA_INTEGRITY_VIOLATION" in entries[1]  # detection excerpt


def test_read_missing_file(tmp_path):
    assert _read_found_summaries(tmp_path / "nope.jsonl") == []


def test_read_empty_file(tmp_path):
    p = tmp_path / "found_bugs.jsonl"
    p.write_text("")
    assert _read_found_summaries(p) == []


def test_read_skips_malformed_lines(tmp_path):
    p = tmp_path / "found_bugs.jsonl"
    p.write_text(
        '{"summary": "good entry 1"}\n'
        'not json at all\n'
        '{"no_usable_field": true}\n'
        '\n'
        '{"detection_excerpt": "good entry 2"}\n'
    )
    assert _read_found_summaries(p) == ["good entry 1", "good entry 2"]


# ── concurrent-agents prompt section ─────────────────────────────────────────

def test_concurrent_section_renders_with_path():
    p = build_find_prompt("url", "abc", "/work/app", "/work/run_poc.js",
                          found_bugs_path="/results/eathub/found_bugs.jsonl")
    assert "## Concurrent Agents" in p
    assert "/results/eathub/found_bugs.jsonl" in p
    assert "cat /results/eathub/found_bugs.jsonl" in p


def test_concurrent_section_omitted_without_path():
    p = build_find_prompt("url", "abc", "/work/app", "/work/run_poc.js")
    assert "## Concurrent Agents" not in p


def test_concurrent_section_describes_readonly_mount():
    p = build_find_prompt("url", "abc", "/work/app", "/work/run_poc.js",
                          found_bugs_path="/tmp/found_bugs.jsonl")
    sect = p[p.index("## Concurrent Agents"):]
    assert "read-only" in sect.lower()
    assert "/tmp/found_bugs.jsonl" in sect


def test_concurrent_section_mentions_detection_excerpt():
    # The comparison guidance references the detection excerpt, not an ASAN frame.
    p = build_find_prompt("url", "abc", "/work/app", "/work/run_poc.js",
                          found_bugs_path="/r/found.jsonl")
    sect = p[p.index("## Concurrent Agents"):]
    assert "detection excerpt" in sect.lower()
    assert "primary class" in sect.lower()


def test_all_optional_sections_render_in_order():
    p = build_find_prompt("url", "abc", "/work/app", "/work/run_poc.js",
                          focus_area="Vote counters", known_bugs=["bug1"],
                          found_bugs_path="/r/found.jsonl")
    positions = [
        p.index("## Setup"),
        p.index("## Focus Area"),
        p.index("## Already Filed"),
        p.index("## Concurrent Agents"),
        p.index("## The seeded fixture"),
    ]
    assert positions == sorted(positions)
