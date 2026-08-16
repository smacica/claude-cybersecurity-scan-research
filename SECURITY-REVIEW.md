# SECURITY REVIEW — `security-review-skill-scan`

Focused security review of the changes on this branch against `main`. Date: 2026-08-15.

**Scope reviewed:** the backend logging feature (pino logger, pino-http request logging
middleware, audit events, the `no_console` guard) plus the commit that moved the Vue
frontend out into the sibling `../frontend` folder.

**Method:** one identification pass over the full branch diff and the surrounding source,
then an independent false-positive filter pass per candidate finding, each verifying the
claim against the actual source and the installed dependency code in `node_modules`.
Findings below are limited to security issues *newly introduced by this branch* —
pre-existing issues in the codebase are out of scope.

**Excluded by policy:** denial of service, resource exhaustion, rate limiting, secrets at
rest on disk, missing hardening measures, log spoofing, and findings in documentation.

## Result

| # | Finding | File | Severity | Verdict | Confidence |
|---|---------|------|----------|---------|------------|
| 1 | Plaintext credentials written to logs via the error serializer | `index.js:70` | Medium | **Confirmed** | 8/10 |
| 2 | Correlation id taken from client-controlled `X-Request-Id` | `request_log.js:47` | — | Rejected (false positive) | 8/10 |
| 3 | `trust proxy` makes the logged `ip` spoofable | `index.js:40` | — | Rejected (false positive) | 9/10 |

One confirmed Medium. No High findings. No injection, authentication-bypass, or
authorization flaws were introduced by this branch.

---

## Finding 1 — Plaintext credentials written to logs via the error serializer

* **Severity:** Medium
* **Category:** `sensitive_data_exposure` / `insecure_logging`
* **Confidence:** 8/10 — every link in the chain verified against installed dependency code
* **Locations:** `index.js:68-70` (error handler), `index.js:48-49` (body-parser mount),
  `logger.js:8-14` (serializer config)

### Description

This branch replaces the old error-handler line

```js
console.error('unhandled error on', req.method, req.originalUrl, '-', err && err.message);
```

with a full-object log:

```js
// index.js:68-70
app.use(function(err, req, res, next) {
  req.log.error({ err }, 'unhandled error');
```

`logger.js:13` registers `pino.stdSerializers.err`, which is **not** an allowlist. In the
installed `pino-std-serializers@7.1.0` (`lib/err.js:28-40`), after copying
`type`/`message`/`stack` it runs `for (const key in err)` and copies every remaining
enumerable own property of the error onto the log line. No `redact` option is configured
anywhere in `logger.js`.

`body-parser@1.20.1` attaches the **raw, unparsed request body** to the error it raises on
a JSON parse failure (`lib/read.js:129-134`):

```js
} catch (err) {
  next(createError(400, err, { body: str, type: err.type || 'entity.parse.failed' }))
```

`http-errors` assigns those props directly onto the existing error as own enumerable
properties (`index.js:98-102`). `normalizeJsonSyntaxError` (`json.js:208-222`) strips other
own props but runs *before* `createError`, so `body` survives.

`bodyParser.json()` is mounted app-wide at `index.js:48`, so its `next(err)` skips straight
to the only error middleware at `index.js:68`. `/api/signup` (`routes/user.js:32`) and
`/api/login` (`routes/user.js:68`) both accept plaintext passwords in a JSON body. The log
level is `error` (50), so the line survives any realistic `LOG_LEVEL`.

This breaks the invariant the branch itself documents. `README.md` states that "Bodies and
query strings are never logged … which is what keeps passwords, the `/verify-email` token
and the `connect.sid` cookie out." The allowlist in `request_log.js` holds for the
*request* line, but the error-handler line bypasses it entirely. The previous
`console.error` printed only `err.message`, so this exposure is new to this branch.

### Exploit scenario

A login or signup POST whose JSON body is malformed — a truncated or corrupted payload, a
mangling proxy, a buggy client, or a deliberately malformed request — emits:

```json
{"level":50,"err":{"type":"SyntaxError","message":"Expected double-quoted property name …",
 "stack":"…","expose":true,"statusCode":400,"status":400,
 "body":"{\"email\":\"victim@example.com\",\"password\":\"CorrectHorseBattery1\",}"},
 "msg":"unhandled error"}
```

The victim's email address and plaintext password land in the retained runtime log stream,
readable by anyone with console or log-forwarding access and by any downstream aggregator.
Passwords are stored bcrypt-hashed, so the log tier becomes the weakest link: an operator,
contractor, or attacker who reaches only the logs obtains reusable plaintext credentials
for this app and for any site where the user reused that password.

### Scope notes

* Exposure is limited to the requester's **own** body — this cannot be used to extract a
  third party's password on demand. The risk is accumulation of legitimate users'
  credentials in logs.
* `bodyParser.urlencoded` (`index.js:49`) is the same sink. A `verify` callback failure
  (`read.js:113-116`) would be too, though none is configured.
* The `entity.too.large` path (`read.js:91`) does **not** carry the body, so genuinely
  oversized or aborted bodies do not leak — only complete-but-unparseable ones.
* Secondary exposure on the same line: `err.stack` and every other enumerable error
  property from *any* middleware error reaches the log unfiltered. This is a fail-open
  denylist pattern — exactly what the design spec's decision table rejects.

### Recommendation

Enforce the redaction guarantee centrally in `logger.js`:

```js
redact: { paths: ['err.body', 'err.raw.body'], remove: true }
```

or wrap the serializer with an explicit allowlist:

```js
serializers: {
  err (e) {
    const s = pino.stdSerializers.err(e);
    delete s.body;
    delete s.raw;
    return s;
  }
}
```

Add a regression test mirroring the redaction test in `test/request_log.test.js`: POST
malformed JSON containing a sentinel password to the real app and assert the sentinel never
appears in captured output.

Separately (correctness, not security): handle `err.type === 'entity.parse.failed'` in the
error handler and return the intended `400` rather than rewriting it to `500` at
`index.js:74`.

---

## Rejected candidates

Both were raised by the identification pass and rejected on verification. Recorded here so
the reasoning is not re-derived on the next review.

### Correlation id taken from client-controlled `X-Request-Id` — `request_log.js:42-49`

`genReqId` returns a client-supplied `x-request-id` verbatim when it matches
`REQUEST_ID = /^[A-Za-z0-9._-]{1,200}$/` (`request_log.js:20`), and nothing strips the
header first.

**Rejected.** A full grep shows `reqId` has no consumer outside pino's log-correlation
binding — no authorization, session, CSRF, idempotency, dedup, or cache use. The charset
and length regex already blocks newline and control-character injection, so no forged log
*line* is possible; only the grouping key can be made degenerate. Every request still emits
its own line with independent `time`, `ip`, `path`, `status`, and `userId`
(`request_log.js:70-86`), and audit events carry their own `ip`/`reason`/`userId`
(`routes/user.js:76-79`), so nothing is suppressed or overwritten. An attacker also cannot
observe another user's `reqId` — it is never echoed in a response header or body. This is
the excluded log-spoofing class plus a hardening suggestion.

*Still worth doing as defense in depth:* always generate `crypto.randomUUID()` for `reqId`
and record any client-supplied value in a separate, clearly-untrusted field.

### `trust proxy` makes the logged `ip` spoofable — `index.js:40`

`app.set('trust proxy', 1)` is added by this branch, making `req.ip` derive from
`X-Forwarded-For`, and the branch simultaneously starts recording `req.ip` on every request
line (`request_log.js:83`) and on both `sign_in_failed` audit events (`routes/user.js:77`,
`routes/user.js:149`).

**Rejected.** `req.ip` is write-only into log fields — there is no IP-keyed authentication,
authorization, session, or throttling logic anywhere. Authentication is session-cookie
based; `isLoggedIn` (`google_strategy.js:38`) checks only `request.user`; authorization is
ownership-by-`user_id`; `ai_quota.js` throttles on `user_id` plus a global minute window,
never on IP. Spoofing `X-Forwarded-For` therefore only injects an attacker-chosen string
into a log line.

The setting is also **load-bearing for security**: `session_config.js:28` sets
`cookie.secure` in production, and express-session refuses to set a secure cookie behind a
TLS-terminating proxy without `trust proxy`; it also makes `baseUrl(req)`
(`routes/user.js:19`) emit `https` verification links. Loosening it would be a net
regression. `1` is the correct hop count for a single DigitalOcean load balancer.

---

## Examined and found sound

Recorded so the next review does not repeat the work:

* **Request-line field allowlist** (`request_log.js:63-86`) — `serializers: { req: () =>
  undefined, res: () => undefined }` plus `customProps` is a genuine allowlist. `pathOf`
  (`request_log.js:24-26`) strips the query string, so the `/verify-email?token=` value
  never reaches a log line. No header other than `User-Agent` is captured, and the
  `connect.sid` cookie cannot reach the request line.
* **Static-asset log skipping** (`request_log.js:28-31`) — no audit-evasion path found. The
  `API_PREFIX` guard covers all `/api/*` routes, and the only non-`/api` routes
  (`/verify-email`, `/auth/google`, `/auth/google/callback`) match exactly and cannot carry
  an attacker-chosen extension. Percent-encoding the path does not route, since Express
  matches the undecoded pathname.
* **`GEMINI_API_KEY` in error logs** (`gemini.js:147-175`) — the key travels as an
  `x-goog-api-key` header (`gemini.js:134`), not in the URL, so the logged
  `body.slice(0,400)` of an upstream error cannot echo it.
* **Email-verification token** (`routes/user.js:110`, `db.js:500-512`) — token queries are
  fully parameterized, so the token cannot surface in a sqlite error message.
* **`console.log` of the verification link** (`mailer.js:37`, exempted at
  `test/no_console.test.js:13-14`) — pre-existing behaviour; only the comment and the test
  allowlist are new on this branch.
* **`deserializeUser` now calling `done(err)`** (`index.js:29-35`) — a sanctioned change
  that fails closed, so there is no authentication-bypass path.

## Noted, below the reporting bar

* **Vite `server.fs.allow: ['..']`** (`../frontend/vite.config.js:23`) — the frontend move
  re-points `..` from the backend project root to the shared `claude_scan/` parent, widening
  the dev server's `/@fs/` root to include unrelated sibling projects. Dev-server-only and
  localhost-bound by default. Worth tightening to an explicit
  `['../Auth_Recepie_Website/shared']`.
