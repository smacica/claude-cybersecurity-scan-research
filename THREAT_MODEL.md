# Threat Model: EatHub

## 1. System context

EatHub is a recipe-sharing web application: an Express 4 JSON API (~19 JavaScript
files) backed by a single SQLite file, serving a Vue 3 single-page app that is built
into a sibling `../frontend/dist` and served from the same origin in production.
Users sign in either with an email address and password (bcryptjs hashes, activation
gated on a mailed 24-hour verification link) or with Google via
`passport-google-oauth20`. Signed-in users publish recipes with a photo upload,
comment, like, and generate recipes through the Gemini API under app-enforced
free-tier quotas. Sessions are cookie-based and persisted in the same SQLite file
through `express-sqlite3`.

**Current state (owner, 2026-08-15): the application runs in local development only
and has never been deployed.** The threats below are nonetheless scored against the
deployment the README documents and the owner intends — a single DigitalOcean App
Platform process behind the platform's TLS-terminating proxy (`trust proxy 1`),
configuration as app-level environment variables, JSON logs to stdout, and an
ephemeral container filesystem holding both `data/main.db` and every uploaded recipe
photo. Scoring against the intended deployment is deliberate: the purpose of this
model is to say what must be true before EatHub goes public, not to record that
nothing is currently reachable.

Signup at launch is intended to be **open to anyone on the internet**. The primary
adversary is therefore a remote unauthenticated attacker; the secondary adversary is
any authenticated user, since an account will cost nothing but a working email
address. Billing is deliberately left disabled on the Google Cloud project holding
the Gemini key, which caps AI-quota abuse at feature denial rather than cost. Recent
work in the tree has been on structured logging and audit events, session-cookie
hardening, and user-enumeration-safe auth responses.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| Account credentials | bcrypt password hashes and `google_id` links in `users`; compromise means account takeover and password reuse elsewhere | high |
| Session records | Session ids and serialized sessions in the `sessions` table of `data/main.db`; a session id is a bearer credential for a full week | high |
| Email verification tokens | `email_tokens` rows; each is a single-use bearer credential that flips `email_verified` and thereby unlocks sign-in | high |
| User PII | Email addresses, usernames, profile pictures, bios; the email is the account identifier and is not exposed by public endpoints today | medium |
| User-generated content | Recipes, uploaded photos, comments, like counters; integrity and availability matter more than confidentiality, as all of it is public by design | medium |
| Gemini API key and free-tier budget | Server-held key plus a hard global cap of 20 generations/day; exhausting it disables the feature for everyone. Billing is off, so it cannot become a bill | high |
| SMTP credentials and sender reputation | Provider credentials in the environment plus the deliverability of the sending domain, which unbounded mail triggering can burn | high |
| Application secrets | `SESSION_SECRET`, `GOOGLE_CLIENT_SECRET`, `SMTP_PASS`, `GEMINI_API_KEY` — in `.env` locally and app-level environment variables in production | high |
| Application origin trust | Everything served from the app's own origin executes with the app's privileges in the browser, including bytes users upload and text the model writes | high |
| Service availability and disk capacity | One Node process, one SQLite file, one ephemeral disk shared by the database and every uploaded photo | medium |
| Audit and request log integrity | pino request lines plus named audit events (`sign_in`, `sign_in_failed`, `recipe_deleted`, `delete_denied`, `ai_*`) are the only record of who did what | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| POST /api/signup | Unauthenticated account creation; validates email shape and an 8-character minimum password, hashes with bcrypt, issues and mails a verification token (`routes/user.js:32`) | unauth internet → user store + outbound SMTP | Account credentials, Email verification tokens, User PII, SMTP credentials and sender reputation |
| POST /api/login | Unauthenticated credential check via passport-local; rejects unverified accounts with 403 (`routes/user.js:68`, `local_strategy.js:13`) | unauth internet → credential verification + session issue | Account credentials, Session records |
| POST /api/resend-verification | Unauthenticated; re-issues and mails a verification link for any registered unverified address, answering identically either way (`routes/user.js:116`) | unauth internet → outbound SMTP | Email verification tokens, SMTP credentials and sender reputation |
| GET /verify-email | Consumes a token from the query string, marks the account verified, redirects into the SPA (`routes/user.js:98`, `db.js:500`) | bearer token from an email client → account state | Email verification tokens, Account credentials |
| Google OAuth routes | `/auth/google` stores a `returnTo` and hands off to Google; the callback exchanges the code and finds or creates the user, linking by `google_id` and then by email (`routes/user.js:135`, `db.js:542`) | federated identity provider → local identity + session | Account credentials, Session records, User PII |
| Session cookie connect.sid | httpOnly, sameSite lax, `secure` only when `NODE_ENV=production`, 7-day maxAge, uuid ids, stored by express-sqlite3 0.0.4 inside `data/main.db` (`session_config.js:15`) | browser-held bearer credential → every authenticated route | Session records, User-generated content, Gemini API key and free-tier budget |
| POST /api/recipes (multipart upload) | Authenticated recipe create; multer diskStorage writes to `data/recipes_pics` named `recipeId + path.extname(originalname)`, 5 MB cap, filter on the client-declared mimetype (`routes/recipe.js:58`, `file_uploud.js:4`) | authenticated user bytes → server filesystem | Application origin trust, Service availability and disk capacity, User-generated content |
| GET /data/recipes_pics/:filename | Unauthenticated read-back of uploaded bytes through `res.sendFile` with `path.basename()` applied (`routes/recipe.js:279`) | user-uploaded bytes → served from the application origin | Application origin trust, Session records |
| POST /api/recipes/generate | Authenticated; user text (capped at 400/200 characters) goes to the Gemini Interactions API labelled as data, and the JSON reply is re-validated and stored as a recipe (`routes/recipe.js:145`, `gemini.js:120`) | user text → third-party model; model output → stored application content | Gemini API key and free-tier budget, User-generated content, Application origin trust |
| Comment endpoints | Unauthenticated read of a recipe's comments joined with author username and picture; authenticated create (1000-character cap) and delete by comment author or recipe owner (`routes/recipe.js:195-258`) | authenticated write / unauthenticated read of user content | User-generated content, User PII |
| POST /api/recipes/:recipe_id/like | Authenticated vote toggle; the path parameter is passed through unparsed to the likes and ranking queries (`routes/recipe.js:260`, `db.js:140`) | authenticated write to shared ranking counters | User-generated content |
| Public recipe reads | `GET /api/recipes` returns every ranking row joined recipe-by-recipe with no pagination; `GET /api/recipes/:id` returns a whole recipe row (`routes/recipe.js:287-320`, `db.js:225`) | unauth internet → full content corpus | User-generated content, Service availability and disk capacity |
| Recipe and comment delete | Authenticated destructive operations with ownership enforced inside `db.js` and a denial audit event (`db.js:264`, `db.js:363`) | authenticated user → another user's content | User-generated content |
| CORS policy | `cors({ origin: CLIENT_URL \|\| true, credentials: true })` plus a wildcard OPTIONS handler; `CLIENT_URL` is documented as empty in production, so any Origin is reflected (`index.js:43`) | cross-origin browser context → credentialed API | Session records, User PII, User-generated content |
| Client-controlled request headers | `trust proxy 1` makes `req.ip` read X-Forwarded-For; `x-request-id` is reused when it matches a charset/length regex; `Host` feeds `baseUrl()` when `PUBLIC_URL` is unset (`index.js:40`, `request_log.js:47`, `routes/user.js:18`) | untrusted headers → req.ip, log correlation, links inside verification emails | Audit and request log integrity, Email verification tokens |
| Static SPA serving and catch-all route | `express.static` over `../frontend/dist`, an `/api` 404 JSON guard, then `GET *` returns index.html (`index.js:52-64`) | disk → browser origin | Application origin trust |
| db.js query helpers | `dbFind`/`dbUpdate`/`dbDel` build SQL by string-interpolating table, column and LIMIT while parameterizing only the values (`db.js:591`, `db.js:617`, `db.js:640`) | caller-supplied identifiers → SQL text | Account credentials, User PII, User-generated content, Session records |
| Environment configuration | dotenv `.env` locally, app-level environment variables in production; missing values silently degrade to a `dev-only-secret` session key, a `missing-client-id` OAuth client, and console-printed verification links | operator/platform → process secrets and security-relevant defaults | Application secrets, Session records |
| data/main.db on ephemeral disk | One SQLite file holds users, tokens, recipes, comments, likes, ai_usage and the session table, on a filesystem the platform discards on redeploy (`db.js:10`, `session_config.js:7`) | platform lifecycle → all persistent state | Account credentials, Session records, User-generated content, Service availability and disk capacity |
| npm dependency supply chain | `package.json`/`package-lock.json` pull multer 1.4.5-lts.1, express-sqlite3 0.0.4 and express 4.18.2, plus unused mysql/express-mysql-session and nodemon declared as production dependencies | public registry → runtime code execution | Application secrets, Account credentials, Service availability and disk capacity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Account takeover by pre-registering a victim's email address and waiting for their Google sign-in to link and verify it | remote_unauth | POST /api/signup, Google OAuth routes | Account credentials, User PII | critical | likely | unmitigated | none — the owner confirms the email-based linking is deliberate, but the pre-registration case was not considered | |
| T2 | Stored cross-site scripting by uploading a file whose extension the attacker chooses and having it served back from the application origin | remote_auth | POST /api/recipes (multipart upload), GET /data/recipes_pics/:filename | Application origin trust, Session records | critical | likely | unmitigated | 5 MB size cap; `path.basename()` on the read path; httpOnly cookie limits direct token theft | |
| T3 | Remote code execution or denial of service through a known-vulnerable or compromised npm dependency | supply_chain | npm dependency supply chain, POST /api/recipes (multipart upload) | Application secrets, Account credentials, Service availability and disk capacity | critical | possible | unmitigated | package-lock.json pins exact versions | multer 1.4.5-lts.1 (1.x end-of-life, 2025 DoS advisories), express-sqlite3 0.0.4 |
| T4 | Database compromise via SQL injection as the identifier-interpolating query helpers acquire new callers | remote_unauth | db.js query helpers | Account credentials, User PII, User-generated content, Session records | critical | possible | partially_mitigated | every value is bound; all identifier arguments are literals at the current call sites | |
| T5 | Full authentication bypass through disclosure or predictability of the session signing secret | remote_unauth | Environment configuration, Session cookie connect.sid | Application secrets, Session records, Account credentials | critical | possible | partially_mitigated | `.env` is gitignored and was never committed; a warning is logged when `SESSION_SECRET` is absent; secrets are never written to logs | |
| T6 | Irrecoverable loss of every account, session and uploaded photo when the container filesystem is replaced | local_admin | data/main.db on ephemeral disk | Account credentials, Session records, User-generated content, Service availability and disk capacity | high | almost_certain | risk_accepted | consciously accepted while the app is local-only; the owner treats real storage plus backups as a launch blocker | |
| T7 | Account compromise by credential stuffing or brute force against the sign-in endpoint | remote_unauth | POST /api/login | Account credentials, Session records | high | likely | partially_mitigated | bcrypt cost 10; identical message for unknown address and wrong password; `sign_in_failed` audit event | |
| T8 | Denial of service through disk exhaustion and unbounded reads | remote_auth | POST /api/recipes (multipart upload), Public recipe reads, Comment endpoints | Service availability and disk capacity | high | likely | partially_mitigated | 5 MB per file; 100 kB JSON body cap; 1000-character comment cap; authentication required | |
| T9 | Cross-origin theft of authenticated API responses because any Origin is reflected with credentials allowed | remote_unauth | CORS policy, Session cookie connect.sid | Session records, User PII, User-generated content | high | possible | partially_mitigated | sameSite lax keeps the cookie off cross-site fetches today | |
| T10 | Verification-token theft by poisoning the link inside the outgoing email through the Host header | remote_unauth | Client-controlled request headers, POST /api/signup, POST /api/resend-verification, GET /verify-email | Email verification tokens, Account credentials | high | possible | partially_mitigated | `PUBLIC_URL` overrides the header when set, and the README instructs setting it in production; the production value is not yet chosen | |
| T11 | Session takeover through weaknesses in the unmaintained session store or its configuration | remote_unauth | Session cookie connect.sid, data/main.db on ephemeral disk | Session records, Account credentials | high | possible | partially_mitigated | httpOnly; sameSite lax; `secure` when `NODE_ENV=production`; uuid v4 ids; passport regenerates the session on login; expired rows pruned hourly | 3825322, express-sqlite3 0.0.4 |
| T12 | Stored content injection through recipe text, comments or model output rendered by the single-page app | remote_auth | Comment endpoints, POST /api/recipes/generate, POST /api/recipes (multipart upload) | Application origin trust, User-generated content | high | rare | partially_mitigated | owner states the SPA uses plain interpolation only, so Vue escapes everything (not verified — the frontend is outside this checkout); server-side length caps; model output re-validated against a fixed schema | |
| T13 | Amplified impact of any content injection, plus clickjacking, because no security response headers are set | remote_unauth | Static SPA serving and catch-all route, GET /data/recipes_pics/:filename | Application origin trust, Session records | medium | likely | unmitigated | none | |
| T14 | Denial of the AI feature for all users by exhausting the shared free-tier budget from disposable accounts | remote_auth | POST /api/recipes/generate | Gemini API key and free-tier budget | medium | likely | partially_mitigated | global 20/day, per-user 3/day and 5/minute caps; slot reserved before the call; verified email required to sign in; billing disabled on the Cloud project, so exhaustion can never become a charge | |
| T15 | Mail flooding of third parties and destruction of sender reputation via the unauthenticated mail-triggering endpoints | remote_unauth | POST /api/signup, POST /api/resend-verification | SMTP credentials and sender reputation | medium | likely | unmitigated | one live token per user; resend only fires for registered unverified addresses | |
| T16 | Prompt injection steering the model into writing attacker-chosen content that is stored as a recipe | remote_auth | POST /api/recipes/generate | User-generated content, Application origin trust | medium | possible | partially_mitigated | system instruction forbids following embedded instructions; user text labelled as data; response schema enforced; title, description and list lengths capped; non-food requests rejected | |
| T17 | Login cross-site request forgery through the OAuth callback, silently signing a victim into the attacker's account | remote_unauth | Google OAuth routes | User-generated content, User PII | medium | possible | unmitigated | none — the strategy is configured without the `state` parameter | |
| T18 | Destruction or modification of another user's recipes and comments | remote_auth | Recipe and comment delete | User-generated content | medium | rare | mitigated | ownership checked in `dbDeleteRecipe` and `dbDeleteComment` before the delete; 403 plus a `delete_denied` audit event | |
| T19 | Bulk harvesting of the content corpus and of the usernames attached to comments | remote_unauth | Public recipe reads, Comment endpoints | User-generated content, User PII | low | likely | partially_mitigated | email addresses are never returned by public endpoints; signup, resend and login answer identically regardless of whether the address exists | |
| T20 | Forged attribution in the audit trail through spoofed client headers | remote_unauth | Client-controlled request headers | Audit and request log integrity | low | possible | partially_mitigated | `x-request-id` validated against a charset/length regex before reuse; `trust proxy` set to one hop; query strings stripped from logged paths | 6cc33d1 |
| T21 | Content integrity loss from colliding recipe identifiers | remote_auth | POST /api/recipes (multipart upload), POST /api/recipes/generate | User-generated content | low | possible | unmitigated | none | |
| T22 | Ranking manipulation and orphan rows through unvalidated identifiers on the vote endpoint | remote_auth | POST /api/recipes/:recipe_id/like | User-generated content | low | possible | partially_mitigated | the vote value is checked to be 0 or 1; values are bound; foreign keys are enabled on the connection | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Open redirect through the post-sign-in landing parameter | `safeNext()` accepts only paths starting with a single slash, and the base is server-side config |
| Path traversal out of the recipe photo directory | `path.basename()` is applied on read and the write destination is fixed |
| Brute forcing an email verification token | 256 bits of `crypto.randomBytes` entropy, single use, 24-hour lifetime, and the token is stripped from logged paths |
| Session fixation | passport 0.6 regenerates the session inside `req.login` |
| User enumeration via the signup and resend endpoints | responses are identical for registered and unregistered addresses; timing differences are not worth treating as a separate threat at this scale |
| Repudiation of authenticated actions | named audit events cover sign-in, sign-up, verification, logout, recipe create and delete, denied deletes and AI usage, each correlated by request id |
| Unbounded cost from AI abuse | billing is deliberately disabled on the Cloud project, so Google refuses calls past the free allowance rather than charging; the residual risk is feature denial, tracked as T14 |
| Insider abuse of the database or logs | single-maintainer personal project; there is no separation-of-duties model to enforce |
| Attacks on the Vue frontend build and its dependencies | the frontend lives outside this checkout (`../frontend`) and was not reviewed |

## 6. Open questions

Owner-stated facts to verify in code or configuration:

- **[Owner-states]** The SPA renders user and model text with plain interpolation
  only, never `v-html` or a markdown/HTML renderer. This is the only thing holding
  T12 at `rare`; confirm it in `../frontend` before trusting that score, and add a
  lint rule so it stays true.
- **[Owner-states]** Billing is disabled on the Google Cloud project holding the
  Gemini key. Worth re-checking at launch, since enabling it silently converts T14
  from feature denial into an unbounded bill.

Decisions still to make before launch:

- Production values for `PUBLIC_URL`, `CLIENT_URL` and `NODE_ENV` are undecided
  because nothing is deployed. `PUBLIC_URL` (T10) and the CORS origin (T9) are the
  two that must be settled deliberately rather than left to the defaults.
- Will anything sit in front of the app — CDN, WAF, platform rate limiting — that
  would blunt T7, T8 and T15? If not, those controls have to live in the app.
- Which SMTP provider? A shared sending pool makes the reputation damage in T15
  someone else's problem too, which some providers treat as grounds for suspension.
- Where will persistent state live once T6 becomes a launch blocker, and has a
  restore actually been tested rather than just configured?
- Will the Google OAuth consent screen be published? Open public signup requires it;
  leaving it in *Testing* is itself a partial control on the authenticated-attacker
  threats.
- How long should request logs and audit events be retained, and is there a path for
  a user to delete their account and content?
- Is there any alerting on the `sign_in_failed`, `delete_denied` and
  `ai_quota_denied` audit events, or are they written and never read?

## 7. Provenance

- mode: bootstrap-then-interview
- date: 2026-08-15
- target: /Users/smacica/Documents/program/claude_scan/Auth_Recepie_Website @ 56f9c50
- inputs: git-log + README/docs mined; owner interview 2026-08-15; no external vuln file supplied
- owner: Stefan Macica

## 8. Recommended mitigations

Owner's launch gate (2026-08-15): **T1–T5 plus every `S`-effort row below must land
before public launch**; the rest is post-launch backlog. New dependencies are
acceptable where they are the standard answer. T6 is accepted while the app is
local-only and becomes a blocker the moment real users exist.

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Require proof of control of the address before linking a Google identity to an existing local account, and never auto-verify a pre-existing unverified account | T1 | yes | S |
| Store uploads under a fully server-generated name with an extension derived from sniffed content, serve them with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, and ideally from a separate origin | T2, T13 | yes | M |
| Add helmet with a strict CSP (`default-src 'self'`), HSTS, nosniff and `frame-ancestors 'none'` | T2, T12, T13 | partial | S |
| Pin CORS to an explicit origin allowlist and never fall back to reflecting the request Origin | T9 | yes | S |
| Always derive external links from a configured `PUBLIC_URL`, never from the `Host` header | T10 | yes | S |
| Rate-limit and lock out per IP and per account on every unauthenticated endpoint (login, signup, resend), e.g. with express-rate-limit | T7, T15, T19 | partial | S |
| Enable the OAuth `state` parameter and add a CSRF token (or SameSite=Strict) for state-changing routes | T17, T9 | partial | S |
| Fail closed on missing security-critical configuration (`SESSION_SECRET`, `GOOGLE_*`) instead of falling back to development defaults | T5 | partial | S |
| Generate recipe ids as full 128-bit values (or a database sequence) rather than `parseInt(uuid(), 16)` | T21, T22 | yes | S |
| Replace the identifier-interpolating db helpers with per-table query functions that use bound parameters and fixed identifiers | T4 | yes | M |
| Adopt a maintained session store, drop the unused mysql, express-mysql-session and nodemon production dependencies, move multer to a supported major, and turn on automated dependency scanning (npm audit / Dependabot) | T3, T11 | partial | M |
| Enforce per-account storage and creation quotas, and paginate every public read | T8, T14, T19 | partial | M |
| Move persistent state off the container filesystem (managed Postgres, or an attached volume for SQLite plus object storage for photos) with automated, restore-tested backups | T6, T8 | yes | L |
