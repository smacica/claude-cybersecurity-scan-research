# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""End-to-end grader validation against real Docker (eathub, no LLM).

Hand-crafted patches with known verdicts, asserting grade_patch agrees. Every
assertion is a deterministic oracle (the runner's own exit code / npm test);
re-attack is unit-tested separately with mocks since it needs an LLM in the
loop.

The PoC here is the flagship like/ranking race (targets/eathub/fixtures/
race_poc.json). T1 runs `run_poc.js` against the (possibly patched) app:
exit 2 = the race still fires, exit 0 = the fix stopped it.

Skipped if Docker can't spawn containers (set VULN_PIPELINE_DOCKER_RUNTIME=runsc
on hosts where the default runtime is unavailable).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from harness import docker_ops
from harness.artifacts import CrashArtifact
from harness.config import TargetConfig
from harness.patch_grade import grade_patch

REPO = Path(__file__).resolve().parents[1]
EATHUB = TargetConfig.load(REPO / "targets" / "eathub")

_RACE_POC = (REPO / "targets" / "eathub" / "fixtures" / "race_poc.json").read_bytes()

# The detection block the find-agent would have submitted for the race. Only the
# reproduction_command and poc_bytes are load-bearing for the ladder; the
# crash_output is carried for the focus hint.
RACE_CRASH = CrashArtifact(
    poc_path="/tmp/poc.bin",
    poc_bytes=_RACE_POC,
    # Bare path, no `node` prefix — this is exactly what the find prompt tells
    # the agent to emit (`{binary_path} <poc>`). It only runs because the image
    # ships run_poc.js with a shebang and the exec bit; a prior `node ...` form
    # here masked a Permission-denied regression that would have failed grading
    # for every real finding.
    reproduction_command="/work/run_poc.js /tmp/poc.bin",
    crash_type="DATA_INTEGRITY_VIOLATION",
    crash_output=(
        "<<<DETECTION>>>\n"
        + json.dumps({
            "fired": True,
            "primary_class": "DATA_INTEGRITY_VIOLATION",
            "classes": ["DATA_INTEGRITY_VIOLATION"],
            "trigger_step_index": 1,
            "evidence": {"always_on": {"ranking_drift": [{"recipe_id": 101}]},
                         "http": [{"step_index": 1, "method": "POST",
                                   "path": "/api/recipes/101/like",
                                   "route": "/api/recipes/:id/like", "status": 200}]},
        })
        + "\n<<<END DETECTION>>>\n"
    ),
    exit_code=2,
)


def _docker_available() -> bool:
    if not docker_ops.image_exists(EATHUB.image_tag):
        return False
    try:
        docker_ops.run(EATHUB.image_tag, name="pgrade_probe")
        return True
    except RuntimeError:
        return False
    finally:
        docker_ops.rm("pgrade_probe")


pytestmark = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker can't spawn containers (set VULN_PIPELINE_DOCKER_RUNTIME)",
)


def _grade(diff_path: str):
    diff = (REPO / diff_path).read_bytes()
    return asyncio.run(
        grade_patch(
            EATHUB,
            RACE_CRASH,
            diff,
            model="unused",
            container_name="pgrade_e2e_eathub",
            run_reattack=False,
        )
    )


def test_noop_diff_passes_t0_fails_t1():
    """A comment-only change builds (syntax-checks) but leaves the race live,
    so T1 must fail — the runner still exits 2."""
    v = _grade("tests/fixtures/eathub_noop.diff")
    assert v.t0_builds
    assert not v.t1_poc_stops
    assert not v.passed


def test_golden_diff_passes_all():
    """Serializing handlelike stops the race: T1 clean (exit 0) and npm test
    stays green at T2."""
    v = _grade("tests/fixtures/eathub_race_golden.diff")
    assert v.t0_builds
    assert v.t1_poc_stops
    assert v.t2_tests_pass
    assert v.passed


def test_malformed_diff_fails_t0():
    """Garbage diff bytes must fail at T0 (apply step)."""
    v = asyncio.run(
        grade_patch(
            EATHUB,
            RACE_CRASH,
            b"not a diff\n",
            model="unused",
            container_name="pgrade_e2e_eathub",
            run_reattack=False,
        )
    )
    assert not v.t0_builds
    assert "apply" in v.evidence.get("t0", "")
