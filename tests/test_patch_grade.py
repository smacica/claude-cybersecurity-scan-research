# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Patch grader: T0-T3 ladder, PatchVerdict semantics, short-circuit ordering.

docker_ops + find.run_find are mocked; e2e against real Docker lives in
tests/test_patch_grade_e2e.py (eathub only).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from harness.artifacts import CrashArtifact, PatchVerdict
from harness.config import TargetConfig
from harness.patch_grade import _t1_passes, grade_patch

# ── fixtures ─────────────────────────────────────────────────────────────────

CANARY = TargetConfig(
    name="eathub",
    dockerfile_dir="targets/eathub",
    image_tag="vuln-pipeline-eathub:latest",
    github_url="(local)",
    commit="n/a",
    binary_path="/work/run_poc.js",
    source_root="/work/app",
    build_command="cd /work/app && git ls-files -z '*.js' | xargs -0 -n1 -r node --check",
    test_command=None,
)

ALPHA_CRASH = CrashArtifact(
    poc_path="/tmp/poc.bin",
    poc_bytes=b'{"steps":[]}',
    reproduction_command="node /work/run_poc.js /tmp/poc.bin",
    crash_type="DATA_INTEGRITY_VIOLATION",
    crash_output=(
        "<<<DETECTION>>>\n"
        '{"primary_class": "DATA_INTEGRITY_VIOLATION", '
        '"classes": ["DATA_INTEGRITY_VIOLATION"], '
        '"evidence": {"http": [{"step_index": 0, "method": "POST", '
        '"path": "/api/recipes/101/like", "route": "/api/recipes/:id/like"}]}}\n'
        "<<<END DETECTION>>>\n"
    ),
    exit_code=2,
)

DIFF = b"--- a/db.js\n+++ b/db.js\n@@ -1 +1 @@\n-x\n+y\n"


# ── PatchVerdict semantics ───────────────────────────────────────────────────


def test_verdict_passed_all_true():
    v = PatchVerdict(
        t0_builds=True,
        t1_poc_stops=True,
        t2_tests_pass=True,
        re_attack_clean=True,
        t3_style_score=None,
        evidence={},
        timings={},
    )
    assert v.passed


def test_verdict_passed_t2_none_is_ok():
    v = PatchVerdict(
        t0_builds=True,
        t1_poc_stops=True,
        t2_tests_pass=None,
        re_attack_clean=True,
        t3_style_score=None,
        evidence={},
        timings={},
    )
    assert v.passed


def test_verdict_failed_on_t2_false():
    v = PatchVerdict(
        t0_builds=True,
        t1_poc_stops=True,
        t2_tests_pass=False,
        re_attack_clean=True,
        t3_style_score=None,
        evidence={},
        timings={},
    )
    assert not v.passed


def test_verdict_failed_on_reattack():
    v = PatchVerdict(
        t0_builds=True,
        t1_poc_stops=True,
        t2_tests_pass=None,
        re_attack_clean=False,
        t3_style_score=None,
        evidence={},
        timings={},
    )
    assert not v.passed


def test_verdict_t3_never_gates():
    v = PatchVerdict(
        t0_builds=True,
        t1_poc_stops=True,
        t2_tests_pass=None,
        re_attack_clean=True,
        t3_style_score=0.0,
        evidence={},
        timings={},
    )
    assert v.passed


def test_verdict_roundtrip():
    v = PatchVerdict(
        t0_builds=True,
        t1_poc_stops=False,
        t2_tests_pass=None,
        re_attack_clean=False,
        t3_style_score=7.0,
        evidence={"t1": "asan"},
        timings={"t0": 1.2},
    )
    assert PatchVerdict.from_dict(v.to_dict()) == v


# ── T1 oracle ────────────────────────────────────────────────────────────────


def test_t1_passes_clean_exit():
    # rc 0 = replay ran, no oracle fired = the fix worked. The detection block
    # in stdout is not consulted — the exit code carries the whole signal.
    assert _t1_passes(0, "<<<DETECTION>>>\n{\"fired\": false}\n<<<END DETECTION>>>\n", "")


def test_t1_fails_when_oracle_still_fires():
    # rc 2 = an oracle fired = the PoC still reproduces.
    assert not _t1_passes(2, "<<<DETECTION>>>\n{\"fired\": true}\n<<<END DETECTION>>>\n", "")


def test_t1_fails_on_hang():
    # rc 3 = hang. Not a pass; patch.py labels it "t1 (replay hung)".
    assert not _t1_passes(3, "", "timed out")


def test_t1_fails_on_runner_error():
    # rc 1 = runner/infra error. Not a pass; patch.py routes it via ladder_error.
    assert not _t1_passes(1, "", "runner error: malformed PoC")


# ── ladder short-circuit (mocked docker) ─────────────────────────────────────


def _exec_sequence(results):
    """Mock for docker_ops.exec_sh that returns a fixed sequence of (rc,out,err)."""
    it = iter(results)

    def _f(container, cmd, timeout=None):
        return next(it)

    return _f


@pytest.fixture
def mock_docker():
    with patch("harness.patch_grade.docker_ops") as m:
        m.run.return_value = "pgrade"
        m.commit.return_value = "patched:tmp"
        yield m


def test_t0_fail_short_circuits(mock_docker):
    # apply ok; build fails
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (0, "", ""),  # git apply
            (1, "", "error: ..."),  # build_command
        ]
    )
    v = asyncio.run(
        grade_patch(CANARY, ALPHA_CRASH, DIFF, model="m", run_reattack=False)
    )
    assert not v.t0_builds
    assert not v.t1_poc_stops
    assert v.t2_tests_pass is None
    assert "t0" in v.evidence
    # T1 never ran
    assert mock_docker.exec_sh.call_count == 2


def test_apply_fail_is_t0_fail(mock_docker):
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (1, "", "error: patch does not apply"),
        ]
    )
    v = asyncio.run(
        grade_patch(CANARY, ALPHA_CRASH, DIFF, model="m", run_reattack=False)
    )
    assert not v.t0_builds
    assert "does not apply" in v.evidence["t0"]


def test_multi_diff_reland_collapses(mock_docker):
    # Two-diff golden where #1 is a reland of #0: check passes for #0,
    # check fails for #1 (already applied) → skipped; build + T1 still pass.
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (0, "", ""),  # apply --check #0
            (0, "", ""),  # git apply #0
            (1, "", "already applied"),  # apply --check #1 → skip
            (0, "", ""),  # build
            (0, "", ""),  # T1
        ]
    )
    v = asyncio.run(
        grade_patch(CANARY, ALPHA_CRASH, [DIFF, DIFF], model="m", run_reattack=False)
    )
    assert v.t0_builds and v.t1_poc_stops and v.passed


def test_multi_diff_none_apply_is_t0_fail(mock_docker):
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (1, "", "no"),
            (1, "", "no"),
        ]
    )
    v = asyncio.run(
        grade_patch(CANARY, ALPHA_CRASH, [DIFF, DIFF], model="m", run_reattack=False)
    )
    assert not v.t0_builds
    assert "no diff applied cleanly" in v.evidence["t0"]


def test_t1_fail_short_circuits(mock_docker):
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (0, "", ""),  # apply
            (0, "", ""),  # build
            (2, '<<<DETECTION>>>\n{"fired": true}\n<<<END DETECTION>>>\n', ""),  # oracle still fires
        ]
    )
    v = asyncio.run(
        grade_patch(CANARY, ALPHA_CRASH, DIFF, model="m", run_reattack=False)
    )
    assert v.t0_builds
    assert not v.t1_poc_stops
    assert not v.passed


def test_t1_runner_error_sets_ladder_error(mock_docker):
    # rc=1 from the runner means the harness broke (e.g. the patch changed a
    # response shape the PoC captures from), not that the PoC still fires.
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (0, "", ""),  # apply
            (0, "", ""),  # build
            (1, "", "runner error: unresolved capture ${recipe_id}"),  # T1 infra error
        ]
    )
    v = asyncio.run(
        grade_patch(CANARY, ALPHA_CRASH, DIFF, model="m", run_reattack=False)
    )
    assert not v.t1_poc_stops
    assert v.ladder_error is not None
    assert "harness error" in v.ladder_error


def test_t1_hang_is_not_a_ladder_error(mock_docker):
    # rc=3 (hang) is a genuine patch failure (introduced or unfixed hang), not
    # infra — so ladder_error stays None.
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (0, "", ""),  # apply
            (0, "", ""),  # build
            (3, '<<<DETECTION>>>\n{"primary_class": "HANG"}\n<<<END DETECTION>>>\n', ""),
        ]
    )
    v = asyncio.run(
        grade_patch(CANARY, ALPHA_CRASH, DIFF, model="m", run_reattack=False)
    )
    assert not v.t1_poc_stops
    assert v.ladder_error is None


def test_t2_runs_when_configured(mock_docker):
    target = TargetConfig(**{**CANARY.__dict__, "test_command": "make check"})
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (0, "", ""),  # apply
            (0, "", ""),  # build
            (0, "ok", ""),  # PoC clean
            (0, "PASS", ""),  # tests
        ]
    )
    v = asyncio.run(
        grade_patch(target, ALPHA_CRASH, DIFF, model="m", run_reattack=False)
    )
    assert v.t2_tests_pass is True


def test_t2_none_when_no_suite(mock_docker):
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (0, "", ""),
            (0, "", ""),
            (0, "ok", ""),
        ]
    )
    v = asyncio.run(
        grade_patch(CANARY, ALPHA_CRASH, DIFF, model="m", run_reattack=False)
    )
    assert v.t2_tests_pass is None


def test_reattack_clean_when_no_crash(mock_docker):
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (0, "", ""),
            (0, "", ""),
            (0, "ok", ""),
        ]
    )
    with patch(
        "harness.patch_grade.run_find", new=AsyncMock(return_value=(None, None, {}))
    ):
        v = asyncio.run(grade_patch(CANARY, ALPHA_CRASH, DIFF, model="m"))
    assert v.re_attack_clean
    assert v.passed


def test_reattack_dirty_when_same_signature(mock_docker):
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (0, "", ""),
            (0, "", ""),
            (0, "ok", ""),
        ]
    )
    same_crash = CrashArtifact(
        poc_path="/tmp/p",
        poc_bytes=b"x",
        reproduction_command="/work/entry /tmp/p",
        crash_type="heap-buffer-overflow",
        crash_output="    #1 0x40 in parse_alpha /work/entry.c:26\n",
        exit_code=134,
    )
    with patch(
        "harness.patch_grade.run_find",
        new=AsyncMock(return_value=(same_crash, None, {})),
    ):
        v = asyncio.run(grade_patch(CANARY, ALPHA_CRASH, DIFF, model="m"))
    assert not v.re_attack_clean
    assert not v.passed
    assert "parse_alpha" in v.evidence["re_attack"]


def test_reattack_any_crash_fails(mock_docker):
    mock_docker.exec_sh.side_effect = _exec_sequence(
        [
            (0, "", ""),
            (0, "", ""),
            (0, "ok", ""),
        ]
    )
    other_crash = CrashArtifact(
        poc_path="/tmp/p",
        poc_bytes=b"x",
        reproduction_command="/work/entry /tmp/p",
        crash_type="stack-buffer-overflow",
        crash_output="    #1 0x40 in parse_bravo /work/entry.c:38\n",
        exit_code=134,
    )
    with patch(
        "harness.patch_grade.run_find",
        new=AsyncMock(return_value=(other_crash, None, {})),
    ):
        v = asyncio.run(grade_patch(CANARY, ALPHA_CRASH, DIFF, model="m"))
    assert v.re_attack_clean is False
    assert "re_attack" in v.evidence


def test_no_build_command_raises():
    target = TargetConfig(**{**CANARY.__dict__, "build_command": None})
    with pytest.raises(ValueError, match="build_command"):
        asyncio.run(grade_patch(target, ALPHA_CRASH, DIFF, model="m"))
