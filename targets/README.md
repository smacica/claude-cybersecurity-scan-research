# Adding a new target

Two kinds of targets live in this directory, with entirely different
contracts:

- [**Vuln-pipeline targets**](#vuln-pipeline-targets-replay-runner) · An application plus a runner that replays a PoC against it and reports which security oracles fired
- [**Detection & response targets**](#detection--response-targets-kind-dnr) · A runnable demo app plus a generated log corpus with a planted attack campaign

## Vuln-pipeline targets (replay runner)

A target is a directory under `targets/` containing everything the pipeline
needs to build an image, run the application, and point the find-agent at a
runner. The shipped example is `eathub`, an Express/SQLite web app — read it
alongside this section.

The pipeline never execs `binary_path` itself: it is a string interpolated into
agent prompts ("the runner is here, go run it"). The find/grade/report agents
run it by hand, and it is executed programmatically only at patch T1. What
crosses the find→grade boundary is the PoC bytes plus the agent's `crash_output`
(the runner's `<<<DETECTION>>>` block).

### Required files

#### `config.yaml`

```yaml
image_tag: vuln-pipeline-<name>:latest   # docker tag to build/run
github_url: https://github.com/...      # for the prompt; use a prose placeholder for a
                                        # local/private target — but then NEVER pass --novelty
commit: <full-sha>                      # pin exactly what you tested ("n/a" for a local target)
binary_path: /work/run_poc.js           # the RUNNER, path INSIDE the container
source_root: /work/app                  # the app source, path INSIDE the container
```

Put the runner **one level above `source_root`** (runner at `/work/run_poc.js`,
source at `/work/app`). This is load-bearing: `patch.py` scopes the patch
agent's `git diff` to `source_root`, and `git apply` refuses to escape it, so no
diff the agent emits can touch its own verifier.

Optional fields:

```yaml
focus_areas:                            # starting points for parallel runs (or use --auto-focus)
  - "Vote counters (handlelike, db.js:140, route POST /api/recipes/:id/like) — check-then-act, no transaction"

known_bugs:                             # rendered into the prompt as do-not-resubmit
  - "Malformed JSON body yields 500 instead of 400 — fires UNCAUGHT_EXCEPTION + UNEXPECTED_5XX. Known LOW."

attack_surface: |                       # anchors the report-agent's reachability section
  Express 4 JSON API behind express-session with a SQLite store. Reachable
  surface: local auth + recipe/comment/like CRUD + the image read route.
  Unconfigured integrations degrade to disabled.

build_command: >-                       # in-container "rebuild" for the patch grader (T0).
  cd /work/app && git rev-parse --git-dir >/dev/null 2>&1 || { echo FATAL >&2; exit 1; };
  git ls-files -z '*.js' '*.mjs' | xargs -0 -n1 -r node --check
                                        # For an interpreted target this is an OFFLINE syntax
                                        # check, not a compile. It must not reach the network
                                        # (T0 runs with --network none). The `git rev-parse`
                                        # guard is required: without a repo, `git ls-files` exits
                                        # 128 with empty output and `xargs -r` exits 0, so the
                                        # check would pass having verified NOTHING.

test_command: cd /work/app && npm test  # regression suite for the patch grader (T2).
                                        # Optional; T2 is skipped if absent.

memory_limit: 4g                        # docker --memory for agent containers (default 4g)
build_timeout_s: 1800                   # cap on in-container builds (default 1800)
```

**`known_bugs` format matters.** These go into the find-agent's prompt. Key on
the **primary oracle class and the route/root cause**, not the exact evidence:
the same bug can fire adjacent classes or land at a neighbouring route depending
on the PoC.

#### The runner

`binary_path` is a script taking one argument — a PoC file — that:
- boots a fresh, seeded instance of the app in an isolated copy of the tree (one
  per replay, so concurrent replays don't collide), on a loopback port it picks
  itself;
- replays the PoC's steps, evaluates every security oracle, prints a
  `<<<DETECTION>>>` block, and exits `0` (nothing fired) / `1` (runner/infra
  error) / `2` (an oracle fired) / `3` (hang);
- parses the PoC **by content, never by extension** — the grader runs it as
  `/tmp/poc.bin`.

See `targets/eathub/run_poc.js` for the worked example (temp-dir isolation,
runner-side port reservation, per-session cookie jars, `parallel` race blocks,
nine oracles, read-only SQLite invariants) and `harness/detection.py` for the
block the pipeline reads back out of `crash_output`.

#### `Dockerfile`

Must produce an image where `{binary_path}` (the runner) and `{source_root}`
(the app source) exist, the app's dependencies are baked in (T0 has no network),
and `{source_root}` is a **git repo with a baseline commit** — the patch grader
runs `git apply` / `git ls-files` there but never `git init`. Remember only
`/work` survives the agent base's `COPY --from`, and the base pins Node 22 (see
`harness/agent_image.py`). Read `targets/eathub/Dockerfile` — it also handles
the SPA-shell stub and the `.gitignore`-preservation hazard specific to that
app.

### No pipeline code changes needed

The pipeline reads `config.yaml` and runs `docker build` on this directory.
No Python edits needed to add a target (unless it needs a runtime the agent base
doesn't ship).

## Detection & response targets (`kind: dnr`)

`targets/dnrcanary/` is a different kind of target: a deliberately
vulnerable web app plus a generated log corpus with a planted attack
campaign, used by the detection & response track rather than the
find→grade pipeline.

### `config.yaml`

The `kind: dnr` marker routes the target: vuln-pipeline refuses it, and
dnr-pipeline refuses targets without it. The commands and paths below are
the contract — dnrcanary's filenames (`generate_logs.py`,
`ground_truth.yaml`, `grade.py`) are conventions, not requirements.
`seed_command` and `app_command` are run by the /dnr-* skills from the
target directory and rendered into the pipeline's hunt/grade prompts,
where they run from `/work` in-container (your `app/` tree lands at
`/work/app`) — keep their paths target-relative.

```yaml
kind: dnr
seed_command: python3 app/seed.py         # deterministic DB seed
app_command: python3 app/app.py           # must bind 127.0.0.1 only
generate_logs_command: python3 generate_logs.py --seed 42
port: 5151
logs_dir: logs                            # optional (default logs); mounted ro into the hunt container
ground_truth: ground_truth.yaml           # campaign manifest, the dnr analog of known_bugs; spoiler
grader: grade.py                          # deterministic scorer for a hunter's INCIDENTS.json; spoiler
```

Generating logs is the required first step: `generate_logs_command`
writes the gitignored `logs/`, and its source encodes the campaign — a
spoiler, so run it, don't read it.

### The hunt-agent image (no Dockerfile)

A dnr target ships no Dockerfile, `entry.c`, or ASAN build. Instead the
dnr pipeline builds the hunt-agent image itself: the shared CLI base, a
fixed apt layer (`python3 python3-flask python3-yaml sqlite3 curl`), and
your `app/` tree copied in wholesale. Your demo app must run on that
stack — any other runtime dependency means editing `DNR_APT_PACKAGES` in
`dnr_harness/agent_image.py`, the one place a dnr target can require a
pipeline change.

### Where spoilers may live

The config loader enforces the hunt/answer-key separation, not just
convention:

- every configured path must stay inside the target directory
- `ground_truth` and `grader` must not sit inside `logs_dir` or `app/`:
  logs are mounted into the hunt container and `app/` is copied into its
  image, so a spoiler under either would ship to the hunt agent
- the grade stage mounts `ground_truth` and `grader` read-only at
  runtime; they never enter any image

See `targets/dnrcanary/README.md` for the worked example.
