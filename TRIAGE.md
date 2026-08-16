# Triage Report

13 findings in → 0 duplicates, 6 false positives, 7 confirmed (2 high / 4 medium / 1 low), 2 need manual test.

Context: interactive; environment = internet-facing web service (judged against the intended public deployment, not the current local-only state); scoring = derived HIGH/MEDIUM/LOW from preconditions; 3-vote adversarial verification; recall tie-breaking; org rules from `.claude/fp-rules.txt`.

> **Two caveats on how this run finished.** An Anthropic session limit killed 16 verifier agents across two waves. Twelve of thirteen findings still got their full three independent votes. **f013 got none** — it is carried as `needs_manual_test` under the recall policy, which reflects an infrastructure failure, not an analytical judgment. The same limit blocked the Phase-4 ranking agents, so **severity below was derived inline by the orchestrator** by applying the precondition rule to preconditions the verifiers established, rather than by independent ranking agents.

## Act on these

### [HIGH] Upload filename takes its extension from the client, and the file is served back from the application origin  (f002)
`file_uploud.js:10` | xss | claimed HIGH (alignment +3) | confidence 9.0/10
**Owner:** component: file_uploud.js; no CODEOWNERS entry; top committer jozoforza (3/4 recent commits); serving side routes/recipe.js is smacica (10/15)
**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV
**Preconditions (2):**
- Attacker holds any verified account (open signup, so effectively free)
- Victim opens the uploaded file's URL directly — the SPA renders photos in an `<img>`, where `.html`/`.svg` will not execute, so the attacker must distribute the app-origin link

**Threat-model match:** Code execution in a visitor's browser
**Why:** `file_uploud.js:10` takes the stored extension from client-controlled `file.originalname`, and the sole gate at `file_uploud.js:18` tests `file.mimetype` — the client-written multipart Content-Type, not a byte-derived type. A grep of the tree shows no magic-byte or extension allowlist anywhere. The file is served same-origin by `routes/recipe.js:281` via `res.sendFile` with no options, so Express sets `Content-Type: text/html` for a `.html` upload, and `index.js` sets no CSP or `X-Content-Type-Options`. The uploader learns the URL because `recipe.js:68` stores the path and `recipe.js:78` returns the id. Org rule O6 expressly leaves inbound upload naming/typing reportable.

One verifier read `node_modules/send/index.js:825-841` directly to confirm Content-Type derives from `mime.lookup(path)` with no `Content-Disposition`.

**Scanner correction:** the original write-up's `document.cookie` exfiltration does **not** work — `session_config.js:25` sets `httpOnly`. Impact is undiminished: the payload drives authenticated same-origin `fetch` (delete the victim's recipes, read `/api/recipes/mine`, post as them).
**Reachability evidence:** routes/recipe.js:58

---

### [HIGH] Account takeover: Google sign-in links to a pre-registered local account and marks it verified  (f001)
`db.js:553` | auth-bypass | claimed HIGH (alignment +3) | confidence 8.7/10
**Owner:** component: db.js (auth/identity layer); no CODEOWNERS entry; top committers smacica (8/16) and jozoforza (8/16) — split ownership, route to both
**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV
**Preconditions (2):**
- Attacker registers the victim's email via the open signup route **before** the victim's first Google sign-in (`db.js:576` refuses an already-taken address, so the ordering is strict)
- The victim subsequently signs in with Google at least once

**Threat-model match:** Account takeover / impersonation
**Why:** `db.js:554` sets `email_verified = 1` on any pre-existing row matched only by email (`db.js:549`; `dbFindByEmail` is a plain `LOWER(email)` match at `db.js:471`) and never clears `password`. So an attacker-created local row from the unauthenticated `/api/signup` (`routes/user.js:44`, inserted `email_verified: false` with an attacker-chosen bcrypt hash via `db.js:585`) becomes sign-inable the moment the real owner authenticates with Google. `local_strategy.js:30` gates local sign-in solely on `email_verified`, and `bcrypt.compare` at `local_strategy.js:25` matches the attacker's own password, bypassing the intended `dbConsumeEmailToken` proof-of-ownership path entirely. `profile.emails[0].verified` is never consulted (`google_strategy.js:25`).

Two preconditions caps the raw derivation at MEDIUM, but both are cheap: signup is open and unrated, and the second is the victim simply using the product as intended. Boosted to HIGH on the operator's first-named unacceptable outcome.
**Reachability evidence:** google_strategy.js:22

---

### [MEDIUM] OAuth flow omits the state parameter, allowing login CSRF  (f004)
`google_strategy.js:13` | csrf | claimed MEDIUM (alignment +2) | confidence 8.0/10
**Owner:** component: google_strategy.js; no CODEOWNERS entry; top committer smacica (2/2 recent commits — sole author)
**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV
**Preconditions (2):**
- Attacker obtains an unspent Google authorization code for their own account (free — signup is open)
- Victim's browser is induced to visit the callback URL within the code's ~10-minute validity window

**Threat-model match:** Loss or tampering of user content — one-step boost deliberately **not** applied
**Why:** The strategy omits `state`/`store` and both authenticate calls (`routes/user.js:138`, `:146`) omit it too, so `passport-oauth2/lib/strategy.js:113` installs a `NullStore` whose `verify` in `lib/state/null.js` returns `cb(null, true)` unconditionally — the callback accepts any well-formed code from any browser with zero session binding. All three verifiers traced this in the installed passport-oauth2 1.8.0 rather than relying on memory. A project-wide grep finds no CSRF handling anywhere, and `routes/user.js:157` does not require `returnTo` to have been set, so an unsolicited callback is not rejected. `sameSite: 'lax'` is still sent on the top-level GET navigation — the comment at `session_config.js:26` says so explicitly.

Bounded: `db.js:542` never consults `req.user`, so the attacker cannot link their identity onto a victim's live session. All three verifiers judged MEDIUM correct, so the available threat boost was withheld.
**Reachability evidence:** routes/user.js:138

---

### [MEDIUM] CORS reflects any Origin with credentials enabled  (f006)
`index.js:43` | cors-misconfiguration | claimed MEDIUM (alignment +2) | confidence 7.3/10
**Owner:** component: index.js (app wiring); no CODEOWNERS entry; top committer smacica (8/14 recent commits)
**Verdict:** mitigated, votes 3 TP / 0 FP / 0 CV
**Preconditions (3):**
- `CLIENT_URL` is empty in production — the README's explicit instruction
- Attacker controls an origin that is same-**site** with the deployment (a sibling subdomain), **or** the operator later sets `sameSite:'none'` to split the SPA onto its own origin
- Victim visits that origin while holding a live session

**Threat-model match:** User PII exposure (emails)
**Why:** `index.js:43-44` passes `origin: clientUrl || true, credentials: true`, and `clientUrl` is empty in the documented production config, so cors 2.8.5 takes the reflect branch at `node_modules/cors/lib/index.js:57-66` and emits the attacker's Origin alongside `Allow-Credentials: true` — all three verifiers confirmed this in the library source rather than inferring it from the option name.

**Honestly assessed:** `sameSite: 'lax'` blunts the headline scenario. A conforming browser withholds `connect.sid` on a cross-site fetch, `isLoggedIn` returns 401, and an arbitrary site reads nothing. The scanner's "any site" framing was overstated. What survives: Lax is same-*site*, not same-*origin*, so any subdomain foothold gets the cookie attached and `index.js:43` is then the only control preventing a credentialed read of `/api/profile`'s email; and `app.options('*')` pre-clears non-simple methods on every path. One verifier noted the perversity that the reflect branch fires *only* in the same-origin deployment, where no CORS is needed at all.
**Reachability evidence:** index.js:43

---

### [MEDIUM] Verification links are built from the Host header when PUBLIC_URL is unset  (f005)
`routes/user.js:19` | host-header-injection | claimed HIGH (alignment −2) | confidence 7.3/10
**Owner:** component: routes/user.js; no CODEOWNERS entry; top committer smacica (6/10 recent commits)
**Verdict:** needs_manual_test, votes 3 TP / 0 FP / 0 CV
**Preconditions (3):**
- `PUBLIC_URL` is empty in production — the shipped default, and absent from the README's production env block
- The platform ingress forwards a request carrying an unrecognised `Host` rather than rejecting it (DigitalOcean routes by Host; unverifiable from source)
- Victim clicks the confirmation button in the mail, which the mail explicitly asks them to do

**Threat-model match:** Account takeover / impersonation
**Why:** `routes/user.js:19` feeds the raw `req.get('host')` into `issueVerificationEmail` at `:53` and `:123`, both unauthenticated, and `local_strategy.js:46` concatenates it with a live token that `mailer.js:27` mails as a clickable href. `PUBLIC_URL` fails open and ships empty in both `.env.example:18` and the actual `.env`. One verifier confirmed against installed Express 4.18.2 (`node_modules/express/lib/request.js:427-449`) that the `X-Forwarded-Host`/trust-proxy logic lives only on `req.hostname`, so `app.set('trust proxy', 1)` is no protection here.

**Downgraded from HIGH:** two of three verifiers established that `dbConsumeEmailToken` only sets `email_verified` and never calls `req.login`, so a stolen token grants no session. Real outcomes are service-authentic phishing and account pre-hijacking that **chains with f001**.

> Recommend a human build a PoC; static reasoning hit its limit. Precondition 2 is a platform behaviour no amount of source reading can settle.

**Reachability evidence:** routes/user.js:53

---

### [MEDIUM] Session signing secret silently falls back to a hardcoded literal  (f003)
`session_config.js:22` | hardcoded-secret | claimed HIGH (alignment −2) | confidence 7.0/10
**Owner:** component: session_config.js; no CODEOWNERS entry; top committer jozoforza (3/5 recent commits)
**Verdict:** mitigated, votes 3 TP / 0 FP / 0 CV
**Preconditions (2):**
- Operator deploys with `SESSION_SECRET` unset or misspelled — reachable via the README's own `cp .env.example .env` flow, since `.env.example` ships the variable empty and `''` is falsy
- Attacker knows the literal, which is published in this repository

**Threat-model match:** none
**Why:** `session_config.js:22` is verbatim `secret: process.env.SESSION_SECRET || "dev-only-secret"` with only a `logger.warn` at `:11-13`, mounted unconditionally at `index.js:47`.

**The scanner's mechanism was wrong, and all three verifiers found it independently.** `express-sqlite3` is a *server-side* store, so `connect.sid` carries only a signed uuid-v4 session id — a known secret cannot mint a session naming an arbitrary `user_id`, because `deserializeUser` reads the id from the stored row, not the cookie. Session fixation, the next-best chain, is closed by passport 0.6's `req.session.regenerate` inside `req.login`. The fail-open defect is real and explicitly in scope per org rules, but the "no password, no token, no interaction" auth-bypass narrative does not hold.

**Before this reaches an engineer, rewrite the description and exploit scenario** — all three verifiers said so explicitly. Note `''` is falsy, so the empty `.env.example` value hits the fallback too, and `google_strategy.js:9-11` has the identical fail-open shape.
**Reachability evidence:** index.js:47

---

### [LOW] Email format regex runs against an unbounded request string  (f013)
`routes/user.js:23` | redos | claimed LOW (alignment 0) | confidence 0.0/10
**Owner:** component: routes/user.js; no CODEOWNERS entry; top committer smacica (6/10 recent commits)
**Verdict:** needs_manual_test, votes 0 TP / 0 FP / 3 CV
**Preconditions (1):**
- **UNVERIFIED** — no verifier completed. Claimed: attacker POSTs a large crafted email field to the unauthenticated signup route, bounded by the 100 kB body-parser limit

**Threat-model match:** none
**Why:** **NOT VERIFIED.** All three verifier agents were terminated by a session limit before producing a verdict, and a retry was impossible before reset. Three unparseable votes count as `cannot_verify`, yielding no majority; under the recall policy that is carried forward rather than dropped. This reflects an infrastructure failure, not an analytical judgment.

The underlying claim is unchanged from the scanner: `looksLikeEmail` tests `/^[^\s@]+@[^\s@]+\.[^\s@]+$/` (`routes/user.js:23`) against `String(req.body.email || '').trim()` (`:33`) with no length cap, bounded only by the 100 kB body-parser limit (`index.js:48`). The scanner itself scored it 0.3 and conceded the pattern is polynomial, not exponential — the weakest finding in the batch and the least costly to leave unverified.

> Recommend a human build a PoC; static reasoning hit its limit. Time the regex against a 100 kB crafted input. The fix — a 254-character cap before the test — costs nothing either way.

**Reachability evidence:** (none recorded)

---

## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f007 | Verification links printed to stdout when SMTP unset | mailer.js:39 | 3/3 FALSE_POSITIVE (conf 7.0) — rule 3, intentional_behavior + not_actionable. The token is not an authenticator (`/verify-email` never calls `req.login`; `db.js:517` only sets `email_verified`), stdout is not HTTP-reachable, and the fallback is warned at boot, documented in the README, and carved out by name in `test/no_console.test.js:9-14`. Also: the pre-hijack chain is blocked by `db.js:576-579`, and *misconfigured* SMTP never reaches this branch — only fully-absent config does. |
| f008 | Query helpers interpolate table, column and LIMIT into SQL | db.js:593 | 3/3 FALSE_POSITIVE (conf 9.0) — org rule O1, not_actionable. All three enumerated every call site: all identifiers are literals, `dbUpdate`/`dbDel` are imported by no module outside `db.js`, `dbDel` has zero callers, and the one variable identifier is selected from frozen arrays behind a 0/1 route gate. |
| f009 | Recipe ids truncate a UUID to 32 bits | routes/recipe.js:37 | 3/3 FALSE_POSITIVE (conf 7.3) — rule 13, implausible_trigger + not_actionable. The id is not a secret (`routes/recipe.js:287` publishes every id and photo path unauthenticated; deletes are ownership-gated at `db.js:270`), and the attacker cannot influence `req.recipeId`, making a targeted overwrite 1-in-2^32 for a random thumbnail swap. Real reliability defect (~1% collisions at 10k recipes) — file as robustness. |
| f010 | safeNext accepts backslash-prefixed paths | routes/user.js:14 | 3/3 FALSE_POSITIVE (conf 8.7) — org rule O5, already_handled + implausible_trigger. The bypass is real, but `req.login` (`routes/user.js:152`) passes no options, so passport 0.6 regenerates the session and express-session installs a blank one, wiping `returnTo` one line before it is read. O5 also names these exact routes. Worth a one-line hardening fix, since a passport upgrade or `keepSessionInfo:true` would arm it. |
| f011 | Vote endpoint forwards an unparsed path parameter | routes/recipe.js:266 | 3/3 FALSE_POSITIVE (conf 8.0) — rule 13, already_handled. The scanner's own open question was answered against it: `PRAGMA foreign_keys = ON` via `db.get` **does** apply (SQLite sets flag pragmas at compile time, on node-sqlite3's single shared handle), so the FK rejects bogus ids and no orphan row is written. The affinity claim is backwards — bound parameters get identical INTEGER conversion on both the dedupe SELECT and the INSERT, so no vote-stuffing primitive exists. |
| f012 | dbDel's two-column branch runs a SELECT as the delete | db.js:646 | 3/3 FALSE_POSITIVE (conf 9.0) — rule 2, not_actionable. The bug is real but `dbDel` has zero callers and no dynamic reach. Decisively, the exact failure hypothesised — token invalidation resolving without revoking — is already implemented correctly elsewhere at `db.js:484` and `db.js:510`. Worth a cleanup ticket alongside the other unused exports (`addLike`, `dbRecipes`). |

## What the verifiers changed

Worth reading before acting on the list — three of my own scan's claims did not survive:

1. **f003's exploit mechanism was wrong.** A forged cookie cannot name a `user_id` against a server-side session store. Severity drops HIGH → MEDIUM and the description needs rewriting.
2. **f002's cookie-theft detail was wrong** (`httpOnly`), though the finding itself stands at HIGH.
3. **f005's severity was inflated** — the verification token grants no session.

And two findings I rated as real were unanimously rejected at confidence 9: **f008** (SQLi, disposed of by your own org rule O1) and **f012** (dead code). The `--fp-rules` file did real work here: O1 and O5 each independently decided a finding.
