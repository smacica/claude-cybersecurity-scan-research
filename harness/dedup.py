# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Post-hoc crash deduplication — summary view only.

  vuln-pipeline dedup results/<target>/<timestamp>/    # one batch
  vuln-pipeline dedup results/<target>/                # all batches

Walks result.json files under the given root and groups crashes by
(primary_class, trigger route). Includes both crash_found and crash_rejected
results — a rejected crash is still signal.

This is a summary artifact, not a phase gate. In streaming mode the judge
agent decides which crashes get reports; this subcommand just answers "these
N crashes cluster into M signatures" for the results writeup.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

from .detection import detection_reason, signature as _detection_signature


NO_ROUTE = "<no-route>"


def _signature(crash: dict) -> tuple[str, str]:
    return _detection_signature(crash)


def dedup(results_root: Path) -> dict[tuple[str, str], list[tuple[Path, str, dict]]]:
    """Group crashes under results_root by signature.

    Returns {(primary_class, route): [(result_json_path, status, reason), ...]}
    where reason is the pipeline-parsed {primary_class, route}.
    Skips results where crash is null. Silently skips unreadable/malformed
    files — a half-written result.json from a killed run shouldn't abort
    the whole report.
    """
    groups: dict[tuple[str, str], list[tuple[Path, str, dict]]] = defaultdict(list)
    for path in sorted(results_root.rglob("result.json")):
        try:
            result = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        crash = result.get("crash")
        if not crash:
            continue
        reason = crash.get("reason") or detection_reason(crash.get("crash_output") or "")
        sig = _signature(crash)
        groups[sig].append((path, result.get("status", "unknown"), reason))
    return dict(groups)


def format_report(groups: dict[tuple[str, str], list[tuple[Path, str, dict]]],
                  root: Path | None = None) -> str:
    if not groups:
        return "No crashes found.\n"

    # Sort: largest group first, then alphabetical by signature.
    ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    total = sum(len(v) for v in groups.values())

    lines = [f"{len(groups)} unique signature(s) across {total} crash(es):", ""]
    for (cls, route), entries in ordered:
        where = f" at {route}" if route != NO_ROUTE else ""
        lines.append(f"[{len(entries)}x] {cls}{where}")
        for path, status, _ in entries:
            shown = path.relative_to(root) if root else path
            lines.append(f"     {shown}  ({status})")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m harness.dedup <results_dir>", file=sys.stderr)
        sys.exit(1)
    root = Path(sys.argv[1])
    print(format_report(dedup(root), root))
