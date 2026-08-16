# Comparing Claude's security-scanning approaches on EatHub

Three different ways of pointing Claude at the same codebase, run against the
same target app: **[EatHub](https://github.com/smacica/Eathub)**, an
Express/SQLite recipe-sharing API (vendored in this repo at
[`targets/eathub/`](targets/eathub/), threat-modeled in
[`THREAT_MODEL.md`](THREAT_MODEL.md)). The three approaches:

| | Scope | Method | Verification |
|---|---|---|---|
| **`/security-review`** | Diff only (`main` → branch) | Single-pass LLM read + independent FP filter | None — reasoning only |
| **Static skill scan** (this repo) | Whole codebase | LLM read, broad, then multi-agent triage | 3-vote adversarial re-verification per finding, still reasoning only |
| **Reference pipeline** (`vuln-pipeline`, this repo) | HTTP-reachable attack surface only | Agent writes a PoC, replays it against a live sandboxed instance | Execution — a detector oracle actually has to fire, twice, in two separate containers |

The short version: `/security-review` is cheap and fast but only sees your
diff; the static skill scan sees everything but produces things that need a
human (or a second pass) to believe; the reference pipeline produces the
fewest false positives because it has to actually break the app, at the cost
of only covering what it can reach and exploit inside a sandbox.

---

## 1. `/security-review` — diff-only skill

This is the built-in
[`claude-code-security-review`](https://github.com/anthropics/claude-code-security-review)
skill, not something this repo ships. It requires git and only diffs the
current branch against `main` — it is meant for small, incremental changes,
not a full codebase audit.

**Run:** Opus 5, against the branch that added the backend logging feature
(pino logger, `pino-http` request-logging middleware, audit events). Cheap —
few commits in the diff, so little to read.

**Result:** [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md) — one confirmed
**Medium**, two candidates raised and then rejected by its own false-positive
pass:

| # | Finding | Verdict |
|---|---|---|
| Plaintext credentials written to logs via the error serializer (`index.js:70`) | **Confirmed — Medium** |
| Correlation id taken from client-controlled `X-Request-Id` (`request_log.js:47`) | Rejected (false positive) |
| `trust proxy` makes the logged `ip` spoofable (`index.js:40`) | Rejected (false positive) |

The confirmed finding: the new error handler logs the full error object
(`req.log.error({ err }, 'unhandled error')`), and `pino`'s default error
serializer copies every enumerable own property onto the log line — including
the raw request body that `body-parser` attaches to a JSON-parse-failure
error. A malformed signup/login POST puts the victim's plaintext password and
email into the retained log stream. Full chain in
[`SECURITY-REVIEW.md`](SECURITY-REVIEW.md#finding-1--plaintext-credentials-written-to-logs-via-the-error-serializer).

**On "the harness found this too, but downgraded it because the app is
dev-only":** that's not quite what happened, worth correcting. The static
scan's [`VULN-FINDINGS.md`](VULN-FINDINGS.md) does contain an entry at the
same line numbers —

> **Error middleware does not leak.** `index.js:68-75` returns a generic
> message and logs the error server-side; no stack or SQL text reaches the
> response.

— under "Checked and clean." But `VULN-FINDINGS.md` is timestamped
`2026-08-15T07:59:02Z`, and its target directory predates the logging-feature
branch: at that point `index.js`'s error handler still did
`console.error(err.message)` — a genuinely clean line. The static scan never
re-ran against the branch that introduced the vulnerable `req.log.error({ err
})` call, so it didn't re-examine the same code after it changed; it isn't a
case of the harness independently confirming the bug and then talking itself
out of it. And on severity: [`THREAT_MODEL.md`](THREAT_MODEL.md) and
[`TRIAGE.md`](TRIAGE.md) both score findings against the **intended
production deployment**, not the current local-only state, on purpose (TRIAGE
context line: *"environment = internet-facing web service (judged against the
intended public deployment, not the current local-only state)"*) — so "it's
only dev, devs are the only ones reading the logs" is not how this repo's
triage policy would have scored it either, had it seen the finding.

**What it structurally can't catch**, per the skill's own [false-positive
filtering
policy](https://github.com/anthropics/claude-code-security-review#false-positive-filtering):
denial-of-service, rate-limiting concerns, memory/CPU exhaustion, generic
input validation without proven impact, and open-redirect issues are all
filtered out by design, not missed by accident. This run's own "Excluded by
policy" line adds a few more: resource exhaustion, secrets at rest on disk,
missing hardening measures, log spoofing, and findings confined to
documentation.

---

## 2. `defending-code-reference-harness` scan (this repo)

This repo (`vuln-pipeline` + its skills) is built for whole-codebase, ongoing
scanning rather than one diff. It has two genuinely different halves:

### 2a. Static skill scan

Three skills, meant to be run in sequence and re-run as the codebase changes:

| Skill | Purpose | Output |
|---|---|---|
| [`/threat-model`](.claude/skills/threat-model/) | Profile the target — who accesses it, trust boundaries, assets, attack surface. Run once unless the app or its rules change. | [`THREAT_MODEL.md`](THREAT_MODEL.md) |
| [`/vuln-scan`](.claude/skills/vuln-scan/) | Broad static read across the whole tree — finds everything, including false positives, no code execution | [`VULN-FINDINGS.md`](VULN-FINDINGS.md) |
| [`/triage`](.claude/skills/triage/) | Spins up 3 independent subagents per finding to vote real/false-positive, dedupes, re-ranks by derived exploitability | [`TRIAGE.md`](TRIAGE.md) |
| `/patch` | Generates candidate fixes | *(not run this pass)* |

**Run:** interactively, across two ~5-hour Claude Pro sessions (token-heavy —
each finding gets three separate verifier subagents plus a ranking pass).

**Result:** [`VULN-FINDINGS.md`](VULN-FINDINGS.md) surfaced **13 raw
findings** (4 HIGH / 5 MEDIUM / 4 LOW, several sub-0.4-confidence). After
[`TRIAGE.md`](TRIAGE.md)'s adversarial re-verification: **0 duplicates, 6
false positives, 7 acted-on (2 HIGH / 4 MEDIUM / 1 LOW)** — two of the seven
(one MEDIUM, the LOW) are flagged `needs_manual_test` because a session limit
killed their verifier agents mid-run rather than because of an analytical
call (see the caveat at the top of `TRIAGE.md`).

The two HIGH findings that survived triage:

- **Account takeover via Google sign-in linking** — an attacker pre-registers
  a victim's email locally, the victim later signs in with Google, and the app
  sets `email_verified = 1` on the pre-existing row without checking who
  created it — the attacker's own password now unlocks the victim's account
  (`db.js:553`).
- **Upload extension trusted from the client** — a `.html`/`.svg` upload is
  served back same-origin with no content-type sniffing or CSP, giving stored
  XSS on the app's own origin (`file_uploud.js:10`).

Notably, `TRIAGE.md` also **downgraded or killed** several of the raw scan's
own claims after independent verification — a session-secret hardcoded
fallback that looked like a full auth bypass turned out not to be exploitable
against a server-side session store; a SQL-injection claim on the internal
query helpers was unanimously rejected because every call site uses literal
identifiers. Worth reading `TRIAGE.md`'s "What the verifiers changed" section
before acting on any of its list.

### 2b. Reference pipeline (`vuln-pipeline`)

The part that actually runs the app. `recon → find → grade ("verify") →
report → patch`, in a loop, each find/grade/report agent in its own gVisor
sandbox with only a JSON PoC crossing the trust boundary between them.
Because there's originally only a C/C++ + AddressSanitizer harness in this
repo, the EatHub target had to be built with `/customize` first — porting the
detector from ASAN crashes to a `run_poc.js` runner that replays an HTTP PoC
and checks a set of security oracles (data-integrity violations,
cross-account access, origin escape, CORS misconfiguration, unsafe uploaded
content-type, info disclosure, uncaught exceptions, unexpected 5xx, hangs —
full table in [`targets/eathub/README.md`](targets/eathub/README.md#the-oracle-set)).

**Available subcommands** (what each does, and why some weren't part of this
pass):

| Command | Does | Used this pass? |
|---|---|---|
| `vuln-pipeline recon <target>` | Proposes focus areas from the source | Implicitly, via `--auto-focus` |
| `vuln-pipeline run <target> --runs N --parallel --stream` | Find + grade + judge + report, streamed as each crash lands | **Yes** — this is the "recon → find → verify → report" loop |
| `vuln-pipeline dedup <results_dir>` | Groups crashes by signature (batch mode only, superseded by the streaming judge) | No — `--stream` handles dedup live |
| `vuln-pipeline report <results_dir>` | Standalone exploitability report per unique crash (batch-mode recovery) | No — folded into `--stream` |
| `vuln-pipeline patch <results_dir>` | Generates + verifies a fix per unique crash, `--novelty` disabled for this target since it has no real upstream | **No** — patch phase skipped for this pass, same as the static-scan side |

**Run:** Sonnet 5, `run --stream` (recon-informed focus areas, then find +
grade in a loop) — the most token-intensive of the three, since every find,
grade, and report step is its own agent inside its own container.

**Scope, honestly:** the sandbox seeds a disposable instance with synthetic
fixture data and **Google OAuth, SMTP, and the Gemini integration all
unconfigured and disabled by design** — see
[`targets/eathub/engagement_context.md`](targets/eathub/engagement_context.md)
and the `attack_surface` note in
[`targets/eathub/config.yaml`](targets/eathub/config.yaml). That's a
deliberate scope cut, not an oversight: standing up a fake Google IdP inside
the sandbox is new attack surface that can itself produce false positives, so
it's called out as deferred v2 work rather than silently skipped. The
practical effect matches what you'd expect — anything requiring a real OAuth
round-trip is out of reach for this track, including both HIGH/MEDIUM
findings from the static triage that hinge on the Google-linking flow
(account takeover via email linking, and the missing OAuth `state`
parameter). `targets/eathub/README.md`'s own coverage table against the
triaged findings puts the pipeline's honest reach at **3 of the 7** triaged
true positives (upload content-type confusion, CORS credential reflection,
Host-header verification links) — the other four are either OAuth-gated,
hardening-only with no reachable PoC (the session-secret fallback), or a
measured non-issue (the ReDoS candidate ran in 0.26 ms at the body-size cap).
The pipeline's flagship finding — a check-then-act race in the like/ranking
counter (`db.js:140-201`) — **isn't in the static triage list at all**; it
was only found because the pipeline can actually fire concurrent requests at
a live process, which is the entire point of running it alongside the static
scan rather than instead of it.

> **Note on this run's actual output:** `results/` is gitignored by this repo
> (it holds live per-run state — PoCs, transcripts, `reports/bug_NN/`) and
> wasn't present on disk in this workspace when this summary was written, so
> the bug-count/report figures for this specific pass aren't included here.
> If you still have the `results/eathub/<timestamp>/` directory from the run,
> point me at it (or paste `found_bugs.jsonl` / `reports/manifest.jsonl`) and
> I'll fold the actual numbers into this table.

---

## 3. Mythos / further reading

This repo's harness is described (in
[`HARNESS-README.md`](HARNESS-README.md) and
[`docs/blog-post.md`](docs/blog-post.md)) as a public reference
implementation distilled from Anthropic's internal work with security teams
during the Claude Mythos Preview — the same lineage as the hosted
[Claude Security](https://claude.com/product/claude-security) product. The
public writeups intentionally stop short of the part where an internal
system actually attacks a target — that's the part this repo's
`vuln-pipeline` reference-implements in the open, scoped down to a sandboxed
toy target. What *is* shared publicly and is worth reading regardless of
which of the three approaches above you use: the discovery → triage → patch
loop, and using a threat model both to scope discovery (partition a large
codebase, skip out-of-scope areas) and to calibrate triage severity — see
`docs/blog-post.md`'s
[triage section](docs/blog-post.md#5-triage-deduplicate-by-root-cause-rank-by-preconditions-and-impact).

---

## Where to look

- [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md) — `/security-review` output (diff-only)
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — EatHub's threat model
- [`VULN-FINDINGS.md`](VULN-FINDINGS.md) — raw static scan (`/vuln-scan`), 13 findings
- [`TRIAGE.md`](TRIAGE.md) — triaged/verified static findings, 2 HIGH / 4 MEDIUM / 1 LOW
- [`targets/eathub/`](targets/eathub/) — the vendored app, `run_poc.js` runner, oracle set, and the reference pipeline's coverage table against `TRIAGE.md`
- [`https://github.com/smacica/Eathub`](https://github.com/smacica/Eathub) — the real upstream app these scans target
- [`HARNESS-README.md`](HARNESS-README.md) — this repo's original upstream README (pipeline internals, setup, docs index)
