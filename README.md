# Comparing Claude's security-scanning approaches on EatHub

Three different ways of pointing Claude at the same codebase, run against the
same target app: **[EatHub](https://github.com/smacica/Eathub)**, an
Express/SQLite recipe-sharing API (vendored in this repo at
[`targets/eathub/`](targets/eathub/), threat-modeled in
[`THREAT_MODEL.md`](THREAT_MODEL.md)).

| | Scope | Method | Verification | Found | Results |
|---|---|---|---|---|---|
| **`/security-review`** | Diff only (`main` → branch) | Single-pass LLM read + independent FP filter | None — reasoning only | **1 MEDIUM** (2 more raised, then self-rejected) | [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md) |
| **Static skill scan** (this repo) | Whole codebase | LLM read, broad, then multi-agent triage | 3-vote adversarial re-verification per finding, still reasoning only | **2 HIGH / 4 MEDIUM / 1 LOW** (from 13 raw: 4H/5M/4L) — [2 more it couldn't verify](#what-neither-approach-could-verify) | [`VULN-FINDINGS.md`](VULN-FINDINGS.md) → [`TRIAGE.md`](TRIAGE.md) |
| **Reference pipeline** (`vuln-pipeline`, this repo) | HTTP-reachable attack surface only | Agent writes a PoC, replays it against a live sandboxed instance | Execution — a detector oracle actually has to fire, twice, in two separate containers | **1 HIGH / 1 MEDIUM** (3 crashes submitted, 1 killed on review) | [`REFERENCE-PIPELINE.md`](REFERENCE-PIPELINE.md) |

The short version:

- `/security-review` — cheap and fast, but only sees your diff.
- Static skill scan — sees everything, but produces things a human (or a
  second pass) has to believe.
- Reference pipeline — fewest false positives, because it has to actually
  break the app; costs coverage, since it only reaches what it can exploit
  inside a sandbox.

The counts aren't directly comparable — different scopes, different bars. The
overlap is small on purpose: each approach found things the other two didn't.

---

## 1. `/security-review` — diff-only skill

The built-in
[`claude-code-security-review`](https://github.com/anthropics/claude-code-security-review)
skill, not something this repo ships. Requires git, only diffs the current
branch against `main` — meant for incremental changes, not a codebase audit.

- **Run:** Opus 5, against the branch adding backend logging (pino logger,
  `pino-http` middleware, audit events). Cheap — few commits to read.
- **Result:** [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md)

| Finding | Verdict |
|---|---|
| Plaintext credentials written to logs via the error serializer (`index.js:70`) | **Confirmed — Medium** |
| Correlation id taken from client-controlled `X-Request-Id` (`request_log.js:47`) | Rejected (false positive) |
| `trust proxy` makes the logged `ip` spoofable (`index.js:40`) | Rejected (false positive) |

**The confirmed finding**, in short:

- The new error handler logs the full error object
  (`req.log.error({ err }, 'unhandled error')`).
- `pino`'s default error serializer copies every enumerable own property onto
  the log line.
- `body-parser` attaches the raw request body to a JSON-parse-failure error.
- So a malformed signup/login POST puts the victim's plaintext password and
  email into the retained log stream.
- Full chain: [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md#finding-1--plaintext-credentials-written-to-logs-via-the-error-serializer)

### Why the static scan cleared the same code — the threat model did it

The whole-codebase scan read these exact lines and passed them — and the cause
is the threat model, not the scanner. [`VULN-FINDINGS.md`](VULN-FINDINGS.md)
files `index.js:68-75` under *Checked and clean* (*"returns a generic message
and logs the error server-side; no stack or SQL text reaches the response"*),
and it wasn't a stale checkout: the scanned tree has `backend-logging` as an
ancestor, so line 70 was already `req.log.error({ err })`. But the scan was
**scoped by [`THREAT_MODEL.md`](THREAT_MODEL.md) sections 3 and 4**, and that
document had already closed the question — T5's mitigation column asserts
outright that *"secrets are never written to logs"*, and logs appear in the
model **only as an integrity asset** (§2 and T20 ask *can an attacker corrupt
the log?*, never *what confidential data lands in it?*). So the scanner checked
the response path — the question the model actually posed — answered it
correctly, and stopped. Note what did *not* cause this: the local-only framing.
`THREAT_MODEL.md:15-23` scores threats **"against the deployment the README
documents and the owner intends"** regardless. **The lesson is that a
threat-model-scoped scan inherits the model's blind spots, including its
confident ones** — treat asserted mitigations as claims to verify, not as scope
reductions, and re-run the model when a feature changes the shape of the system
(structured logging turned logs into a new data sink; the model still called
them an integrity concern).

### What this scan cannot find

Filtered out by design, per the skill's own [false-positive filtering
policy](https://github.com/anthropics/claude-code-security-review#false-positive-filtering)
— not missed by accident:

- Denial of Service vulnerabilities
- Rate limiting concerns
- Memory/CPU exhaustion issues
- Generic input validation without proven impact
- Open redirect vulnerabilities

This run's own "Excluded by policy" line adds: resource exhaustion, secrets at
rest on disk, missing hardening measures, log spoofing, and findings confined
to documentation.

Worth noting against the other two approaches: **the reference pipeline's
flagship finding sits squarely inside this exclusion list.** The like/ranking
race is a DoS-adjacent concurrency defect that also trips `SQLITE_BUSY` and
hangs — `/security-review` would filter it out even if the race were in the
diff.

---

## 2. `defending-code-reference-harness` scan (this repo)

Built for whole-codebase, ongoing scanning rather than one diff. Two genuinely
different halves.

### 2a. Static skill scan

Three skills, run in sequence, re-runnable as the codebase changes:

| Skill | Purpose | Output |
|---|---|---|
| [`/threat-model`](.claude/skills/threat-model/) | Profile the target — access, trust boundaries, assets, attack surface. Run once unless the app changes. | [`THREAT_MODEL.md`](THREAT_MODEL.md) |
| [`/vuln-scan`](.claude/skills/vuln-scan/) | Broad static read across the whole tree — finds everything, including false positives, no code execution | [`VULN-FINDINGS.md`](VULN-FINDINGS.md) |
| [`/triage`](.claude/skills/triage/) | 3 independent subagents per finding vote real/false-positive, then dedupe + re-rank by exploitability | [`TRIAGE.md`](TRIAGE.md) |
| `/patch` | Generates candidate fixes | *(not run this pass)* |

- **Run:** interactive, two ~5-hour Claude Pro sessions (the second one's limit
  is what killed two verifier agents mid-run, below).
- **Token cost:** no usage data was recorded, so this is an estimate from the
  fan-out — **low single-digit millions of tokens**, dominated by triage:
  - the app is ~2.3k LOC (~30k tokens for a full read of the tree)
  - `/vuln-scan` runs one review subagent per focus area, each reading its
    slice plus `THREAT_MODEL.md`
  - `/triage` is the expensive half: 13 findings × 3 independent verifiers =
    **39 subagent runs**, each re-reading the relevant source to vote, plus a
    dedupe and re-rank pass over the whole set
- **Raw:** [`VULN-FINDINGS.md`](VULN-FINDINGS.md) — 13 findings (4 HIGH /
  5 MEDIUM / 4 LOW, several under 0.4 confidence).
- **Triaged:** [`TRIAGE.md`](TRIAGE.md) — 0 duplicates, 6 false positives,
  7 acted-on (**2 HIGH / 4 MEDIUM / 1 LOW**). Two of the seven are flagged
  `needs_manual_test` — see [below](#what-neither-approach-could-verify).

**The two HIGH findings that survived triage:**

- **Account takeover via Google sign-in linking** (`db.js:553`) — attacker
  pre-registers the victim's email locally; victim later signs in with Google;
  the app sets `email_verified = 1` on the pre-existing row without checking
  who created it. The attacker's own password now unlocks the victim's account.
- **Upload extension trusted from the client** (`file_uploud.js:10`) — a
  `.html`/`.svg` upload is served back same-origin with no content-type
  sniffing or CSP → stored XSS on the app's own origin.

**Triage also killed things the raw scan claimed:** a hardcoded session-secret
fallback that looked like full auth bypass turned out not to be exploitable
against a server-side session store; a SQL-injection claim on the internal
query helpers was unanimously rejected because every call site uses literal
identifiers. Read [`TRIAGE.md`](TRIAGE.md)'s "What the verifiers changed"
before acting on its list.

**Two findings it could not settle** (`needs_manual_test` in `TRIAGE.md`):

- **f005 — Host-header verification links** (MEDIUM, `routes/user.js:19`) —
  all 3 verifiers voted true positive, but one precondition is *platform*
  behaviour: does the ingress forward a request with an unrecognised `Host`,
  or reject it? No amount of source reading settles that. `TRIAGE.md`'s own
  words: *"Recommend a human build a PoC; static reasoning hit its limit."*
- **f013 — unbounded email regex / ReDoS** (LOW, `routes/user.js:23`) —
  **0 votes.** All three verifier agents were killed by a session limit before
  returning a verdict, and there was no time to retry before reset. Carried
  forward under the recall policy rather than dropped, because that's an
  infrastructure failure, not an analytical judgment.

### 2b. Reference pipeline (`vuln-pipeline`)

The part that actually runs the app: `recon → find → grade ("verify") → report
→ patch`, in a loop, each agent in its own gVisor sandbox with only a JSON PoC
crossing the trust boundary.

This repo originally shipped only a C/C++ + AddressSanitizer harness, so the
EatHub target was built with `/customize` first — swapping the ASAN detector
for a `run_poc.js` runner that replays an HTTP PoC and checks nine security
oracles (data-integrity, cross-account access, origin escape, CORS
misconfiguration, unsafe uploaded content-type, info disclosure, uncaught
exceptions, unexpected 5xx, hangs — table in
[`targets/eathub/README.md`](targets/eathub/README.md#the-oracle-set)).

**Available subcommands:**

| Command | Does | Used this pass? |
|---|---|---|
| `vuln-pipeline recon <target>` | Proposes focus areas from the source | Yes, via `--auto-focus` |
| `vuln-pipeline run <target> --runs N --parallel --stream` | Find + grade + judge + report, streamed as each crash lands | **Yes** — the whole loop |
| `vuln-pipeline dedup <results_dir>` | Groups crashes by signature (batch mode) | No — `--stream` dedupes live |
| `vuln-pipeline report <results_dir>` | Standalone exploitability report per crash (batch recovery) | No — folded into `--stream` |
| `vuln-pipeline patch <results_dir>` | Generates + verifies a fix per crash | **No** — skipped, same as the static side |

- **Run:** Sonnet 5, `run --stream` with 3 parallel find-agents over
  recon-proposed focus areas. Most token-intensive of the three — every find,
  grade, and report step is its own agent in its own container.
- **Vulnerabilities found:** [`REFERENCE-PIPELINE.md`](REFERENCE-PIPELINE.md)
  — write-up of each confirmed bug (root cause, chain, impact, why the severity).
- **Raw results:** [`results/eathub/20260816T195551Z/`](results/eathub/20260816T195551Z/)
  — [`focus_areas.json`](results/eathub/20260816T195551Z/focus_areas.json)
  (recon output), [`found_bugs.jsonl`](results/eathub/20260816T195551Z/found_bugs.jsonl)
  (crashes as they landed), `run_00N/result.json` (grade verdicts),
  [`reports/`](results/eathub/20260816T195551Z/reports/) (judge log, manifest,
  per-bug reports + PoC bytes).

**What the run produced — 3 finds, 3 reports, 2 real bugs:**

| Bug | Oracle / route | Grade | Report verdict |
|---|---|---|---|
| [`bug_01`](results/eathub/20260816T195551Z/reports/bug_01/report.json) | `UNSAFE_CONTENT_TYPE` — `POST /api/recipes` | passed, 3/3 replays, score 0.90 | **HIGH** — attacker plants a script-executing SVG served back unauthenticated same-origin |
| [`bug_00`](results/eathub/20260816T195551Z/reports/bug_00/report.json) | `DATA_INTEGRITY_VIOLATION` — `POST /api/recipes/:id/like` | passed, 3/3 replays, score 0.94 | **MEDIUM** — 5 concurrent likes produce duplicate `likes` rows and ranking drift; corruption is durable |
| [`bug_02`](results/eathub/20260816T195551Z/reports/bug_02/report.json) | `CROSS_ACCOUNT_ACCESS` — `DELETE /api/comments/:id` | **rejected** at grade, score 0.05 | **NOT-A-BUG** — recipe owners deleting comments on their own recipes is the documented rule (`db.js:362-387`) |

`bug_02` is the interesting one: the oracle fired for real (actor 1 deleted
owner 2's comment, HTTP 200, 3/3 runs), and both the grade agent and the
report agent independently killed it as intended behaviour. The execution
evidence is necessary but not sufficient — a second reader still has to decide
whether the violated invariant was ever an invariant.

**Scope, honestly:**

- The sandbox seeds a disposable instance with synthetic fixtures and **Google
  OAuth, SMTP, and the Gemini integration all unconfigured and disabled by
  design** — see [`engagement_context.md`](targets/eathub/engagement_context.md)
  and the `attack_surface` note in [`config.yaml`](targets/eathub/config.yaml).
- That's a deliberate cut, not an oversight: a fake Google IdP inside the
  sandbox is new attack surface that can itself manufacture false positives.
  Deferred as v2 work.
- The effect: anything needing a real OAuth round-trip is out of reach —
  including both triaged findings that hinge on Google linking (account
  takeover, missing OAuth `state`).
- `targets/eathub/README.md`'s coverage table puts the pipeline's honest reach
  at **3 of the 7** triaged true positives (upload content-type confusion,
  CORS credential reflection, Host-header verification links). The other four
  are itemised [below](#what-neither-approach-could-verify).
- The flagship finding — the check-then-act race in the like/ranking counter
  (`db.js:140-201`, `bug_00` above) — **isn't in the static triage list at
  all.** It was only found because the pipeline can fire concurrent requests
  at a live process. That's the argument for running it *alongside* the static
  scan, not instead of it.

---

## What neither approach could verify

Every finding that is still an open question — nothing below has been proven
real *or* disproven. Listed so it doesn't quietly disappear between the two
result files.

| Finding | Sev | Static verdict | Why the pipeline can't settle it | What it needs |
|---|---|---|---|---|
| **Google sign-in links a pre-registered local account** (`db.js:553`, f001) | HIGH | 3/3 true positive | Google OAuth is unconfigured in the sandbox by design — no IdP to round-trip against | A local fake IdP + `GOOGLE_CLIENT_ID` in the seed (deferred v2) |
| **OAuth flow omits `state`** (`google_strategy.js:13`, f004) | MED | true positive | Same — the whole OAuth path is disabled | Same OAuth stub |
| **Host-header verification links** (`routes/user.js:19`, f005) | MED | **`needs_manual_test`** — 3/3 true positive, but blocked on a precondition | The `ORIGIN_ESCAPE` oracle *does* cover it in the sandbox — but the open question is whether the real ingress forwards an unrecognised `Host` or rejects it, which no sandbox answers | A test against the actual deployment platform (DigitalOcean routes by Host) |
| **`SESSION_SECRET` dev fallback** (`session_config.js:22`, f003) | MED | true positive, but the scanner's auth-bypass mechanism was refuted | No reachable PoC — it's a fail-open hardening defect, and the server-side session store means a known secret still can't mint a session | Nothing to execute; fix on principle |
| **Unbounded email regex / ReDoS** (`routes/user.js:23`, f013) | LOW | **`needs_manual_test`** — **0 votes**, all 3 verifiers killed by a session limit | Measured, and it's a non-issue: **0.26 ms** at the 100 kB body cap | Effectively settled by measurement; the 254-char cap costs nothing anyway |

Reading it back:

- **2 findings are open because of the tooling** — f005 and f013 are the two
  `needs_manual_test` entries. f013 is the only one that failed for a boring
  reason (session limit), and the pipeline has since measured it into
  irrelevance. f005 is the one genuinely worth a human hour.
- **2 more are open because of a deliberate scope cut** — f001 and f004 both
  need the OAuth stub. f001 is a HIGH, so this is the most expensive gap in
  the whole comparison.
- **1 is open by nature** — f003 has no PoC to write, in any harness.

---

## Where to look

- [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md) — `/security-review` output (diff-only), 1 MEDIUM
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — EatHub's threat model
- [`VULN-FINDINGS.md`](VULN-FINDINGS.md) — raw static scan (`/vuln-scan`), 13 findings
- [`TRIAGE.md`](TRIAGE.md) — triaged static findings, 2 HIGH / 4 MEDIUM / 1 LOW
- [`REFERENCE-PIPELINE.md`](REFERENCE-PIPELINE.md) — pipeline vulnerabilities, written up: 1 HIGH / 1 MEDIUM
- [`results/eathub/20260816T195551Z/`](results/eathub/20260816T195551Z/) — the raw pipeline run: focus areas, found bugs, grade verdicts, transcripts
  - [`reports/manifest.jsonl`](results/eathub/20260816T195551Z/reports/manifest.jsonl) — bug-id assignments
  - [`reports/judge_log.jsonl`](results/eathub/20260816T195551Z/reports/judge_log.jsonl) — NEW/DUP verdicts with reasoning
  - [`reports/bug_01/report.json`](results/eathub/20260816T195551Z/reports/bug_01/report.json) — the HIGH (stored SVG XSS)
  - [`reports/bug_00/report.json`](results/eathub/20260816T195551Z/reports/bug_00/report.json) — the MEDIUM (like/ranking race)
- [`targets/eathub/`](targets/eathub/) — the vendored app, `run_poc.js` runner, oracle set, and the pipeline's coverage table against `TRIAGE.md`
- [`github.com/smacica/Eathub`](https://github.com/smacica/Eathub) — the real upstream app these scans target
- [`HARNESS-README.md`](HARNESS-README.md) — this repo's original upstream README (pipeline internals, setup, docs index)
- [`docs/blog-post.md`](docs/blog-post.md) — the discovery → triage → patch loop, and using a threat model to scope discovery and calibrate triage severity
