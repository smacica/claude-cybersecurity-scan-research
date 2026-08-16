# vuln-pipeline demo: EatHub

End-to-end walkthrough on the `eathub` target — a bundled Express/SQLite recipe
API. The "detector" is not AddressSanitizer here: a runner (`run_poc.js`) boots
the app on loopback, replays a JSON PoC against it, and reports which security
oracles fired.

| Finding | Where | Class | Expected time to first hit |
|---|---|---|---|
| Like/ranking race | `db.js` `handlelike`, `POST /api/recipes/:id/like` | `DATA_INTEGRITY_VIOLATION` (check-then-act, no transaction) | first, minutes |
| Host-header verification links | `user.js` `baseUrl`, `POST /api/signup` | `ORIGIN_ESCAPE` | minutes |
| CORS reflects any origin | `index.js` | `CORS_POLICY_VIOLATION` | minutes |
| Upload content-type confusion | `file_uploud.js`, `POST /api/recipes` | `UNSAFE_CONTENT_TYPE` | minutes |

Full target details, the oracle set, and the honest coverage table:
[`targets/eathub/README.md`](targets/eathub/README.md).

## 0. Prerequisites

- Linux host with Docker.
- A model to drive the agents. The pipeline reads `VULN_PIPELINE_MODEL` from
  the environment (or `--model` per command); it is never read from target
  config. This walkthrough exports it once in step 2.

## 1. One-time setup

Installs the venv + pipeline, registers the gVisor `runsc` runtime, and starts
the egress-allowlist proxy on the `vp-internal` network. Safe to re-run.

```bash
scripts/setup_sandbox.sh
```

`bin/vp-sandboxed` is the entry point from here on — it checks the sandbox is
up, exports the runtime/proxy env, and execs `.venv/bin/vuln-pipeline`.

## 2. Auth

Pick one, per [`docs/agent-sandbox.md`](docs/agent-sandbox.md):

```bash
# Local dev / laptop (recommended for the demo)
claude setup-token                       # prints CLAUDE_CODE_OAUTH_TOKEN
export CLAUDE_CODE_OAUTH_TOKEN=<token>

# or: an API key
export ANTHROPIC_API_KEY=sk-ant-...

# or: Amazon Bedrock (see docs/agent-sandbox.md for the full setup)
export CLAUDE_CODE_USE_BEDROCK=1
export AWS_REGION=us-east-1
export AWS_BEARER_TOKEN_BEDROCK=...
```

Set the model once for the session — every `vuln-pipeline` subcommand reads it:

```bash
export VULN_PIPELINE_MODEL=<model-id>
```

## 3. Recon (read-only)

Runs a single agent that reads the source tree and proposes `focus_areas`.
Prints YAML to stdout — review before launching finds.

```bash
bin/vp-sandboxed recon eathub
```

Expect a partition by route group — the vote/counter path, the auth/verification
flow, the upload path, CORS — which is where the findings live.

## 4. Small first wave (calibration)

First-time use on a target: 3 parallel finds, capped turns, streaming reports.
Gives a feel for token burn and whether prompts are landing before scaling up.

```bash
bin/vp-sandboxed run eathub \
    --auto-focus --runs 3 --parallel --stream --max-turns 100
```

The pipeline auto-builds `vuln-pipeline-eathub:latest` from
`targets/eathub/Dockerfile` on first run. (Do **not** pass `--novelty` — this
target has no upstream to diff against, and the pipeline refuses it.)

## 5. Full wave

Launch in the background so you can tail logs while it runs. `--accept-dos`
lowers the floor so a `HANG` finding (the like race at a high `repeat` crossing
into an unresolved-promise hang) counts as a submission — off by default.

```bash
bin/vp-sandboxed run eathub \
    --auto-focus --runs 15 --parallel --stream \
    2>&1 | tee eathub_run.log &
```

## 6. Watch it

```bash
RESULTS=$(ls -td results/eathub/*/ | head -1)
tail -f eathub_run.log                              # heartbeat + per-action progress
cat   $RESULTS/found_bugs.jsonl                     # findings landed so far (detection excerpts)
ls    $RESULTS/run_*/result.json                    # graded runs
cat   $RESULTS/reports/judge_log.jsonl              # NEW / DUP_BETTER / DUP_SKIP per finding
cat   $RESULTS/reports/manifest.jsonl               # bug_NN assignments
ls    $RESULTS/reports/bug_*/report.json            # exploitability reports written so far
```

The first report (`bug_00`, typically the like/ranking race) lands within
minutes of launch. Stragglers don't block disk writes — kill a stuck find with
`docker rm -f find_eathub_<N>`.

## 7. Read the findings

```bash
RESULTS=$(command ls -td results/eathub/*/ | head -1)
jq . "${RESULTS}reports/bug_00/report.json"
cat  $RESULTS/reports/bug_00/poc.bin | jq .         # the JSON replay PoC
```

Each `report.json` is a structured exploitability analysis: precondition (who
can trigger it), capability, reachability from the real attack surface, blast
radius across other users' rows, persistence, plus an agent-judged severity.

## 8. (Optional) Patch phase

Generates a fix per unique finding and walks it through syntax-check →
oracle-stops → `npm test` → 50-turn re-attack. `targets/eathub/config.yaml`
already has the required `build_command` and `test_command`.

```bash
bin/vp-sandboxed patch $RESULTS
cat $RESULTS/reports/bug_00/patch.diff
jq  . $RESULTS/reports/bug_00/patch_result.json     # t0_builds .. re_attack_clean
```

The ladder verifies the finding is gone, not that the diff is safe to upstream —
review `patch.diff` by hand (see
[`docs/patching.md#reviewing-generated-patches`](docs/patching.md#reviewing-generated-patches)).

## 9. Cleanup

```bash
docker ps -a --filter name=eathub                   # any leftover agent containers
docker rm -f $(docker ps -aq --filter name=eathub)  # if needed
```

Results stay on disk under `results/eathub/<timestamp>/`. The app is vendored
under `targets/eathub/app/`, so nothing is fetched at build time.
