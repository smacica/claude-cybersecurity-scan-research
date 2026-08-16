# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Detection-block parsing.

Replaces the ASAN stack-trace parser. The runner (``run_poc.js``) emits a
machine-readable block on stdout::

    <<<DETECTION>>>
    {"fired": true, "primary_class": "...", "classes": [...],
     "trigger_step_index": 3, "evidence": {...}}
    <<<END DETECTION>>>

Shared by the runtime bug-sharing jsonl (cli.py) and post-hoc dedup (dedup.py).

Why this file has to exist rather than letting the ASAN parser degrade: on
non-ASAN text ``crash_reason`` returned ``{"crash_type": None}`` and
``dedup._signature`` fell through to *the agent's own* ``<crash_type>`` tag, so
dedup would look like it was working while doing nothing finer than grouping by
the agent's self-report. ``asan_excerpt`` degraded to "first three non-empty
lines", which is what lands in ``found_bugs.jsonl`` — the channel every
concurrent find agent reads for dup-checking.
"""
from __future__ import annotations

import json
import re


_BLOCK = re.compile(
    r"<<<DETECTION>>>\s*(.*?)\s*<<<END DETECTION>>>",
    re.DOTALL,
)

# Fixed precedence, highest first. The runner sorts `classes` by this and emits
# `primary_class` itself; this copy is the fallback for a block that carries
# `classes` but no `primary_class` (an older runner, or a hand-written PoC
# transcript).
PRECEDENCE = (
    "DATA_INTEGRITY_VIOLATION",
    "CROSS_ACCOUNT_ACCESS",
    "ORIGIN_ESCAPE",
    "CORS_POLICY_VIOLATION",
    "UNSAFE_CONTENT_TYPE",
    "INFO_DISCLOSURE",
    "UNCAUGHT_EXCEPTION",
    "UNEXPECTED_5XX",
    "HANG",
)

NO_ROUTE = "<no-route>"


def parse_detection(crash_output: str) -> dict | None:
    """The last detection block in ``crash_output``, or None.

    Last rather than first: an agent that iterated inside one message leaves
    several blocks, and the final one is the submission it is standing behind.
    """
    matches = _BLOCK.findall(crash_output or "")
    for raw in reversed(matches):
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(d, dict):
            return d
    return None


def primary_class(crash_output: str) -> str | None:
    """The class the crash is keyed on, by the runner's own precedence."""
    d = parse_detection(crash_output)
    if not d:
        return None
    if d.get("primary_class"):
        return str(d["primary_class"])
    classes = [c for c in (d.get("classes") or []) if isinstance(c, str)]
    for c in PRECEDENCE:
        if c in classes:
            return c
    return classes[0] if classes else None


def trigger_route(crash_output: str) -> str | None:
    """``METHOD /route/template`` for the step that tripped the oracle.

    Route *templates*, not concrete paths — the runner normalises id segments so
    ``/api/recipes/7/like`` and ``/api/recipes/9/like`` do not fragment into two
    signatures. Returns None when the block carries no usable transcript.
    """
    d = parse_detection(crash_output)
    if not d:
        return None
    http = d.get("evidence", {}).get("http")
    if not isinstance(http, list) or not http:
        return None

    idx = d.get("trigger_step_index")
    candidates = [e for e in http if isinstance(e, dict)]
    chosen = None
    if idx is not None:
        for e in candidates:
            if e.get("step_index") == idx:
                chosen = e
                break
    if chosen is None:
        chosen = candidates[-1]

    method = str(chosen.get("method") or "").upper()
    route = str(chosen.get("route") or chosen.get("path") or "")
    if not route:
        return None
    return f"{method} {route}".strip()


def detection_reason(crash_output: str) -> dict[str, str | None]:
    """primary_class + trigger route parsed from the detection block.

    Display-only: feeds found_bugs.jsonl excerpts and the dedup summary. Not a
    decision input — agents judge semantic duplicates from the raw block.
    """
    return {
        "primary_class": primary_class(crash_output),
        "route": trigger_route(crash_output),
    }


def fired_classes(crash_output: str, n: int = 3) -> list[str]:
    """Top-N classes in precedence order.

    The analogue of the old ``project_frames`` — used for the re-attack focus
    hint. Empty list when nothing parses.
    """
    d = parse_detection(crash_output)
    if not d:
        return []
    classes = [c for c in (d.get("classes") or []) if isinstance(c, str)]
    ordered = [c for c in PRECEDENCE if c in classes]
    ordered += [c for c in classes if c not in PRECEDENCE]
    return ordered[:n]


def _evidence_keys(d: dict) -> list[str]:
    ev = d.get("evidence") or {}
    always_on = ev.get("always_on") if isinstance(ev, dict) else None
    if isinstance(always_on, dict):
        return [k for k in always_on if k != "hang"]
    return []


def detection_excerpt(crash_output: str, max_chars: int = 700) -> str:
    """Compact, comparable summary for dedup context.

    ~300-500 bytes — enough for a find- or judge-agent to compare two findings
    semantically without the full transcript.
    """
    d = parse_detection(crash_output)
    if not d:
        # No parseable block. Fall back to the first few non-empty lines so the
        # entry is not blank, but say so plainly: a silent fallback here is what
        # makes a broken oracle look like a working one.
        lines = [l.strip() for l in (crash_output or "").splitlines() if l.strip()]
        if not lines:
            return ""
        return "<no detection block>\n" + "\n".join(lines[:3])[:max_chars]

    parts = [f"primary_class: {d.get('primary_class') or primary_class(crash_output) or 'unknown'}"]
    classes = [c for c in (d.get("classes") or []) if isinstance(c, str)]
    if classes:
        parts.append(f"classes: {', '.join(classes)}")
    route = trigger_route(crash_output)
    if route:
        parts.append(f"trigger: {route}")
    keys = _evidence_keys(d)
    if keys:
        parts.append(f"evidence: {', '.join(keys)}")

    ev = (d.get("evidence") or {}).get("always_on") or {}
    for key in ("duplicate_like_rows", "ranking_drift", "negative_counters",
                "invariant_failures", "cross_account", "origin_escape", "cors",
                "unsafe_content_type", "info_disclosure", "uncaught",
                "server_errors", "hang"):
        val = ev.get(key)
        if val:
            parts.append(f"{key}: {json.dumps(val)[:200]}")
            break

    return "\n".join(parts)[:max_chars]


def signature(crash: dict) -> tuple[str, str]:
    """(primary_class, trigger route) for a crash dict from result.json."""
    reason = crash.get("reason") or detection_reason(crash.get("crash_output") or "")
    cls = (reason.get("primary_class")
           or crash.get("crash_type")
           or "unknown")
    route = reason.get("route") or trigger_route(crash.get("crash_output") or "")
    return (cls, route or NO_ROUTE)
