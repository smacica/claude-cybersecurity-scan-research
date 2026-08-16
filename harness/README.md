# Harness: autonomous vulnerability discovery

This package is the reference pipeline: an autonomous, multi-agent harness
for finding, verifying, reporting, and patching security-property violations
in a web application. It runs Claude Code agents inside gVisor-isolated
containers, boots the target app on loopback, and grades every finding with
an executable oracle (a replay fires a security oracle, or it doesn't). It
began as a C/C++ + ASAN demo and was ported to web via `/customize`.

This README is the copy-paste path to a demo. For the architecture, every
CLI flag, and rate-limit math, see [`docs/pipeline.md`](../docs/pipeline.md).

> ⚠️ **`run`, `recon`, `report`, and `patch` execute target code.** The
> harness refuses to spawn agents outside its gVisor sandbox. Run
> `scripts/setup_sandbox.sh` once, then invoke everything through
> `bin/vp-sandboxed`. Never mount credentials into the agent environment.
> See [`docs/security.md`](../docs/security.md).

## Prerequisites

- Linux host (x86_64 or aarch64), required by gVisor. On macOS/Windows, run
  inside a Linux VM.
- Docker.
- Python 3.11+.
- An Anthropic API key or Claude Code OAuth token.

## Demo: find findings in EatHub

The bundled `eathub` target is an Express/SQLite recipe API. The pipeline
finds real issues from source — a check-then-act race in the like/ranking
counter, host-header injection into verification links, reflected-origin CORS,
upload content-type confusion — with no hints and no network to the agent. The
app is vendored under `targets/eathub/app/`; the image bakes in its
dependencies and a replay runner (`run_poc.js`) that boots the app and reports
which security oracles fire. Your own target works the same way: a Dockerfile
that builds your app and a runner that exercises it.

### Setup (once)

```bash
cd <repo-root>
python3 -m venv .venv
.venv/bin/pip install -e .
export ANTHROPIC_API_KEY=sk-ant-...        # or CLAUDE_CODE_OAUTH_TOKEN, or Bedrock — see docs/agent-sandbox.md
export VULN_PIPELINE_MODEL=<model-id>      # Claude Opus recommended; override per-call with --model

# Installs gVisor, builds the target + agent images, verifies isolation; needs sudo.
# The eathub image bakes in the app (targets/eathub/app/), its node_modules, and
# the run_poc.js runner.
# (Build it directly to see what's inside: docker build -t vuln-pipeline-eathub:latest targets/eathub/)
./scripts/setup_sandbox.sh
```

### Run (end to end)

One command runs **recon → find → grade → judge → report**:

```bash
bin/vp-sandboxed run eathub --auto-focus --runs 3 --parallel --stream
# --auto-focus : run recon first and feed its focus_areas partition to the find agents
# --runs 3 --parallel : 3 concurrent find agents, each in its own container
# --stream : judge + report stream as each grade lands (first report in minutes)
#
# → results/eathub/<timestamp>/run_NNN/{result.json, poc.bin, find_transcript.jsonl}
#   results/eathub/<timestamp>/reports/bug_NN/report.json
```

Then patch the confirmed crashes. This is a separate step on purpose, so
you can read the reports and decide what's worth fixing before spending
tokens. `patch` takes a results **batch directory**, not a target name: each
`run` writes a new `results/eathub/<timestamp>/`, so if you've scanned more
than once you need to say which batch you're patching (the intended loop is
scan → patch → re-scan the patched tree). To patch the batch you just ran,
resolve the newest timestamp with shell expansion:

```bash
bin/vp-sandboxed patch results/eathub/$(ls -t results/eathub | head -1)/
# → resolves to the most recent batch
#   results/eathub/<timestamp>/reports/bug_NN/{patch.diff, patch_result.json}
```

Or name the batch explicitly; the `run` command prints it in its summary
(`run 0: crash_found → results/eathub/20260519T.../run_000/result.json`):

```bash
bin/vp-sandboxed patch results/eathub/<timestamp>/
```

The first confirmed finding (the like/ranking race) typically lands within
minutes. To let a `HANG` finding count as a submission, add `--accept-dos`.
Full oracle set, fixtures, and the honest coverage table in
[`targets/eathub/README.md`](../targets/eathub/README.md).

> **Network note.** The `docker build` step in `setup_sandbox.sh` needs
> outbound HTTPS to fetch the target source. After that, the find/grade/patch
> agents run with egress locked to the configured allowlist (default
> `api.anthropic.com:443`; see [`docs/agent-sandbox.md`](../docs/agent-sandbox.md)
> for Bedrock/Vertex); they never see the network beyond it. This is the
> setup → attack isolation split described in
> [`docs/security.md`](../docs/security.md#separating-setup-and-attack-phases).

> **Env-name note.** The `VULN_PIPELINE_*` env vars and the `vp-internal`
> network name are the contract with `bin/vp-sandboxed` and
> `scripts/setup_sandbox.sh`, and they configure the sandbox for **both**
> pipelines — `dnr-pipeline` uses the same proxy, network, and runtime
> despite the `VULN_` prefix. Renaming them is a breaking change for
> existing user environments; treat them as repo-wide sandbox config.

### Run (step by step)

If you'd rather inspect each phase before committing tokens to the next:

```bash
# Recon only: read the source, print a focus_areas: YAML block.
# Review it, optionally edit it, paste it into targets/eathub/config.yaml.
bin/vp-sandboxed recon eathub

# Find + grade only, using the focus_areas you pasted (no recon, no reports)
bin/vp-sandboxed run eathub --runs 3 --parallel

# Report after the fact, once all grades land
vuln-pipeline report results/eathub/<timestamp>/

# Patch
bin/vp-sandboxed patch results/eathub/<timestamp>/
```

## Watching a run

Each find-agent is a headless `claude -p` session inside its own container.
Tail its transcript as it works:

```bash
tail -f results/eathub/<timestamp>/run_000/find_transcript.jsonl | python3 -c \
  'import sys, json
for line in sys.stdin:
    m = json.loads(line)
    if m.get("type") == "assistant":
        for b in m.get("message", {}).get("content", []):
            if b.get("type") == "tool_use":
                print(f"→ {b['name']}: {str(b.get('input',{}))[:120]}")'
```

## After the run

```bash
vuln-pipeline dedup  results/eathub/<timestamp>/   # group crashes by root-cause signature
vuln-pipeline report results/eathub/<timestamp>/   # exploitability analysis per unique bug
vuln-pipeline run    eathub --resume results/eathub/<timestamp>/   # retry failed/killed runs
```

## Other targets

```bash
ls targets/
```

`eathub` is the worked web-app target and the fast smoke test — an
Express/SQLite recipe API vendored under `targets/eathub/app/`, with a
`run_poc.js` replay runner and nine security oracles. Its `README.md`
documents the oracle set, the fixtures, and the honest coverage table.
`dnrcanary` is a different kind of target (`kind: dnr`) for the detection &
response track, not the find→grade pipeline.

## Port to your stack

The domain-specific pieces live in `prompts/`, `detection.py` (the runner's
detection-block parser, which replaced `asan.py`), and
`patch_grade.py:_t1_passes()`. The orchestration (`cli.py`, `find.py`,
`grade.py`, `report.py`) is mostly domain-neutral. See
[`docs/customizing.md`](../docs/customizing.md), or run `/customize` in
Claude Code from the repo root.
