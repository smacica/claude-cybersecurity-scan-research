# Reference pipeline — vulnerabilities found on EatHub

Execution-verified results from `vuln-pipeline run targets/eathub --stream`.
Every finding below was reproduced by replaying a JSON PoC against a live
sandboxed instance of the app, in two separate containers.

- **Run:** Sonnet 5, 3 parallel find-agents over recon-proposed focus areas
- **Raw output:** [`results/eathub/20260816T195551Z/`](results/eathub/20260816T195551Z/)
- **Outcome:** 3 crashes submitted → 2 confirmed bugs (**1 HIGH / 1 MEDIUM**),
  1 rejected as intended behaviour

| # | Severity | Vulnerability | Route | Verification |
|---|---|---|---|---|
| [bug_01](#bug_01--stored-xss-via-svg-upload--high) | **HIGH** | Stored XSS via unrestricted SVG upload | `POST /api/recipes` → `GET /data/recipes_pics/:file` | oracle `UNSAFE_CONTENT_TYPE`, 3/3 replays, grade 0.90 |
| [bug_00](#bug_00--likeranking-counter-race--medium) | **MEDIUM** | Check-then-act race in the like/ranking counter | `POST /api/recipes/:id/like` | oracle `DATA_INTEGRITY_VIOLATION`, 3/3 replays, grade 0.94 |
| [bug_02](#bug_02--comment-deletion--not-a-bug) | — | Cross-account comment deletion | `DELETE /api/comments/:id` | oracle fired 3/3, but **rejected** at grade (0.05) and at report |

---

## bug_01 — Stored XSS via SVG upload — HIGH

**Report:** [`reports/bug_01/report.json`](results/eathub/20260816T195551Z/reports/bug_01/report.json)
· **PoC:** [`reports/bug_01/workspace/poc.bin`](results/eathub/20260816T195551Z/reports/bug_01/workspace/poc.bin)

**Root cause**

- `file_uploud.js:17-19` — `fileFilter` trusts the client-supplied mimetype
  (`file.mimetype.startsWith('image/')`), so `image/svg+xml` passes.
- `file_uploud.js:10` — the stored filename keeps the client's extension, so
  `evil.svg` lands on disk as `<recipe_id>.svg`.
- `routes/recipe.js:279-286` — `GET /data/recipes_pics/:filename` has **no auth
  middleware**, `res.sendFile()` with no `Content-Type` override and no
  `Content-Disposition`.
- No `X-Content-Type-Options: nosniff` and no CSP anywhere in the app.

**Chain**

1. Attacker self-registers (`POST /api/signup`, fully self-service).
2. Uploads a recipe with an SVG "photo" containing `<script>`.
3. The file is served back same-origin as `image/svg+xml`, unauthenticated.
4. A victim opening that URL as a document executes attacker JS in the EatHub
   origin with their session attached.

**Impact**

- Session cookie is `httpOnly`, so `document.cookie` theft is blocked — but
  same-origin script can call any `/api/*` endpoint as the victim: read
  `/api/profile`, create/delete their recipes, post comments and likes, force
  logout.
- The poisoned recipe surfaces through the **public** `GET /api/recipes`
  listing, so exposure isn't limited to links the attacker distributes.
- Persistent: written to `data/recipes_pics/` on disk with a matching DB row,
  survives restart, no scanning or expiry. Only the planting attacker (or DB
  access) can remove it.
- Report flags two escalation paths it did not execute: the permissive CORS
  config (`index.js:43-44`, `origin: clientUrl || true, credentials: true`)
  widening exfiltration, and worm propagation via re-upload as the victim.

**Not CRITICAL because** the victim must load the URL as a document, `httpOnly`
blocks direct cookie theft, and the app has no password/email-change endpoint
to convert session access into permanent account takeover.

**Overlap:** this is the execution-verified version of the static scan's HIGH
"upload extension trusted from the client" ([`TRIAGE.md`](TRIAGE.md)).

---

## bug_00 — Like/ranking counter race — MEDIUM

**Report:** [`reports/bug_00/report.json`](results/eathub/20260816T195551Z/reports/bug_00/report.json)
· **PoC:** [`reports/bug_00/workspace/poc.bin`](results/eathub/20260816T195551Z/reports/bug_00/workspace/poc.bin)

**Root cause**

- `handlelike()` (`db.js:140-201`) is a classic check-then-act: `SELECT` the
  existing like row, then `INSERT` / `UPDATE` / `DELETE` based on what it read,
  then a separate `dbUpdate` applying ±1 to `ranking.likes`/`dislikes`.
- No transaction, no serialization, and the `likes` table has **no
  `UNIQUE(recipe_id, user_id)` constraint** (`db.js:44-49`).
- The route is gated only by `isLoggedIn` — no ownership check, no relationship
  to the recipe, no rate limit.

**Observed**

- 5 concurrent likes from one account → duplicate `likes` rows for the same
  `(recipe_id, user_id)` pair.
- At `repeat: 20` → `ranking.likes` for recipe 101 went **negative (-7)**
  against 6 real like rows, a drift of -13. The counter diverges from ground
  truth in either direction, unboundedly, per burst.
- Same burst also produced an unhandled promise rejection (`SQLITE_BUSY:
  database is locked`) and a request exceeding the 15s budget.

**Impact**

- `ranking.likes` is the sort key for the public "most liked" listing
  (`db.js:224`, served at `GET /api/recipes`), so one unprivileged account can
  inflate its own recipe's rank or drive a rival's displayed count negative —
  visible to every visitor, including anonymous ones.
- Durable: plain SQLite rows on disk, nothing reconciles or recomputes them.
  Further likes compound the drift rather than repair it.
- Trivially scriptable across the whole catalog; no rate limiting observed.

**Not HIGH because** the primitive is counter corruption plus an incidental
DoS side effect, not account takeover or data exfiltration. The
`SQLITE_BUSY`/hang behaviour was seen once at `repeat: 20` and not proven as a
reliable denial of service.

**This one is pipeline-only** — it does not appear anywhere in
[`TRIAGE.md`](TRIAGE.md). It was found only because the pipeline can fire
concurrent requests at a live process, which is the argument for running it
alongside the static scan rather than instead of it.

---

## bug_02 — Comment deletion — NOT-A-BUG

**Report:** [`reports/bug_02/report.json`](results/eathub/20260816T195551Z/reports/bug_02/report.json)

- The `CROSS_ACCOUNT_ACCESS` oracle fired for real, 3/3 runs: actor 1 deleted
  owner 2's comment, HTTP 200.
- Both the grade agent (criterion 5 failed, score 0.05) and the report agent
  independently killed it: recipe owners deleting comments on their own recipes
  is the documented, intentional authorization rule (`db.js:362-387`,
  `README.md:349`).

Worth keeping visible: execution evidence is **necessary but not sufficient**.
The oracle correctly detected a cross-account write; a second reader still had
to decide whether the violated invariant was ever an invariant.

---

## Scope caveats

- The sandbox runs with **Google OAuth, SMTP, and the Gemini integration
  unconfigured and disabled** ([`engagement_context.md`](targets/eathub/engagement_context.md),
  `attack_surface` in [`config.yaml`](targets/eathub/config.yaml)). Deliberate:
  a fake IdP inside the sandbox is new attack surface that can manufacture its
  own false positives. Deferred as v2 work.
- Anything needing a real OAuth round-trip is therefore unreachable here —
  including both triaged findings that hinge on Google linking (account
  takeover via email linking, missing OAuth `state`).
- `targets/eathub/README.md`'s coverage table puts the pipeline's honest reach
  at **3 of the 7** triaged true positives. The other four are OAuth-gated,
  hardening-only with no reachable PoC (the session-secret fallback), or a
  measured non-issue (the ReDoS candidate ran in 0.26 ms at the body-size cap).
- `--novelty` was off, so all three reports carry `novelty_status:
  NOT_CHECKED` — no upstream fix status was determined.
- The patch phase was not run this pass.
