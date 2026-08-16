# Backend logging design

Date: 2026-08-14
Status: approved, ready for implementation planning

## Goal

Replace the 48 scattered `console.log` calls in the Express backend with a
structured logging layer that serves four purposes:

1. Debugging production issues on DigitalOcean.
2. Seeing traffic: which endpoints get hit, how often, how slow.
3. A consistent logger with levels instead of ad-hoc `console` calls.
4. A security audit trail for sign-ins, deletions and AI usage.

Inspired by
[Automated Logging in Express.js](https://mirzaleka.medium.com/automated-logging-in-express-js-a1f85ca6c5cd),
but two of that article's central choices are deliberately not followed. See
[Deviations from the article](#deviations-from-the-article).

## Constraints

**The host filesystem is ephemeral.** The README targets DigitalOcean App
Platform. Anything written to `logs/*.log` is lost on every redeploy and
restart, and App Platform offers no convenient way to read files out of the
container. File-based logging is therefore not useful here.

**The app handles credentials.** `POST /api/signup` and `POST /api/login`
receive plaintext passwords in the body. `GET /verify-email?token=` carries a
working credential in the query string. Every authenticated request carries a
`connect.sid` session cookie. Any logging design has to treat all three as
things that must never reach the log.

## Decisions

| Decision | Choice | Reason |
| --- | --- | --- |
| Destination | stdout only, newline-delimited JSON | App Platform captures stdout; no rotation or disk config needed |
| Library | `pino` + `pino-http`, `pino-pretty` as devDependency | JSON-to-stdout is pino's default; `pino-http` supplies request ids and the response hook |
| Depth | Metadata only | Nothing sensitive is ever read, so nothing sensitive can leak |
| Response hook | `pino-http` (internally `res.on('finish')`) | With no bodies to capture there is no reason to monkey-patch `res.send` |

Versions current at time of writing: pino 10.3.1, pino-http 11.0.0,
pino-pretty 13.1.3.

## Architecture

Three new root-level modules, following the existing flat snake_case
convention (`google_strategy.js`, `session_config.js`, `ai_quota.js`).

### `logger.js`

Owns the pino instance and nothing else. Reads `LOG_LEVEL`, sets base fields,
registers serializers (including pino's `stdSerializers.err`). Exports a single
`logger`.

Imported directly by every module that has no request in scope: `db.js`,
`gemini.js`, `mailer.js`, `session_config.js`, and the two passport strategies.

### `request_log.js`

Owns the `pino-http` middleware and its policy: which requests to skip, how
status maps to level, and which request fields survive into the log. Exports
`requestLog`. The metadata-only rule is enforced here, in one readable place.

### `audit.js`

One named function per security event: `signIn`, `signInFailed`, `signUp`,
`emailVerified`, `logout`, `recipeCreated`, `recipeDeleted`, `deleteDenied`,
`aiGenerated`, `aiQuotaDenied`, `aiRejected`.

This is a module rather than loose `logger.info('user signed in')` calls
because audit lines are the ones that get filtered on later. A query for
`event:"sign_in_failed"` only works if that string is defined in exactly one
place, and a function signature forces the same fields every time.

Each function takes the request's logger as its first argument, so the audit
line carries the same `reqId` as the request that caused it.

## Data flow

1. `requestLog` is registered in `index.js` immediately after `cors`, before
   `session` — early enough that a failure inside session or passport still
   produces a log line.
2. `pino-http` attaches `req.log`, a child logger carrying a generated `reqId`.
3. The line is written when the response finishes, not on entry. By then
   passport has populated `req.user`, so the request line carries the user id
   with no extra plumbing.
4. Route handlers use `req.log.error({ err }, '<message>')`, so errors share a
   `reqId` with their request.
5. Audit calls pass `req.log` and inherit the same `reqId`.
6. Modules with no request in scope use the base `logger` and log without a
   `reqId`. This is an accepted boundary: those modules genuinely do not know
   which request they are serving, and threading a logger through every
   database function would be a large, invasive change for little gain.

## The request line

One line per completed request:

```json
{"level":30,"time":1755100000000,"env":"production","reqId":"req-1f",
 "method":"GET","path":"/api/recipes/42","status":200,"durationMs":14,
 "userId":7,"ip":"203.0.113.9","ua":"Mozilla/5.0 …","msg":"request"}
```

Exactly seven request-derived fields: `method`, `path`, `status`,
`durationMs`, `userId`, `ip`, `ua`. `userId` is `null` for anonymous requests.

### `path`, never `url`

`pino-http`'s default request serializer logs `req.url`, **which includes the
query string**. On this app that writes `/verify-email?token=<real token>` into
the log, and that token is a working credential until consumed. The custom
serializer uses `req.originalUrl.split('?')[0]`, so query values never enter
the log object. The same reasoning drops `req.headers` wholesale, since that is
what carries `connect.sid`.

The serializer **builds a fresh object containing only the seven fields**
rather than deleting unwanted keys from pino's default. This fails closed: a
future route that accepts a sensitive query parameter cannot leak, because
nothing is logged unless it is explicitly on the list.

### Status to level

| Status | Level |
| --- | --- |
| 2xx, 3xx | `info` |
| 4xx | `warn` |
| 5xx | `error` |

`level>=40` is then a complete "everything wrong today" filter.

### Noise control

`express.static` serves the built Vue bundle, so without a filter every page
load writes a line per JS chunk, CSS file and AI picture. The middleware skips
requests whose path starts with `/assets/` or `/ai_pics/`, or ends in a
static-asset extension.

Skipping is decided by path prefix rather than by checking whether `static`
handled the request, because the decision must be made before the response
finishes.

### Two operational notes

**`durationMs` on `POST /api/recipes/generate` will read 3000–10000.** That
covers the Gemini call. It is not a slow-endpoint bug, and it is the main thing
that would otherwise look alarming in the traffic view.

**`app.set('trust proxy', 1)` is required.** App Platform sits behind a proxy,
so `req.ip` returns the proxy's address without it and the `ip` field is
worthless in production. The setting has no effect in development.

### Request ids

`genReqId` reuses an incoming `x-request-id` header when the platform supplies
one, otherwise `crypto.randomUUID()`. `pino-http`'s default is a per-process
counter, which restarts at 1 on every deploy and collides across instances.

`reqId` is **not** free once the `req` serializer is suppressed — see
[Validated behaviour](#validated-behaviour-pino-http-1100).

## Validated behaviour (pino-http 11.0.0)

The design was run against pino 10.3.1 / pino-http 11.0.0 / express 4 before
planning. The leak checks pass: a request to
`/verify-email?token=SUPERSECRET123` carrying a `connect.sid` cookie produced
log output containing neither value, and `/assets/app.js` produced no line at
all. Three corrections came out of that exercise.

**1. `reqId` binds itself once both quiet-logger options are set.** The flat
request line is achieved by returning `undefined` from the `req` and `res`
serializers and building the fields in `customProps`. Setting both
`quietReqLogger` and `quietResLogger` makes pino-http bind `reqId` itself
(`logger.child({ reqId: req.id })`) onto a single child logger, before
`customProps` ever runs, and that same child logger backs both `req.log`
inside route handlers and the request-completion line. `reqId` must **not**
be added again inside `customProps` — that would write the field twice on the
wire — and no extra middleware is needed to attach it.

**2. `userId` is `null` on `req.log.*` lines.** pino-http evaluates
`customProps` once when it creates the child logger, which happens before
passport populates `req.user`. The request-completion line re-evaluates them
and does carry the real `userId`. So an in-route error line shows
`userId: null`, and the user is found by matching its `reqId` to the request
line. This is why `reqId` is load-bearing rather than a nicety.

**3. pino-http fabricates an error on every 5xx.** For any response with status
≥ 500 it logs `new Error('failed with status code 500')` whose stack points
into `pino-http/logger.js` — misleading noise next to the real error. It is
suppressed with:

```js
customErrorObject: (req, res, error, val) => ({ durationMs: val.durationMs })
```

This also keeps the request line metadata-only, consistent with the rest of the
design; the genuine error is logged separately by the error middleware under
the same `reqId`. Suppressing it also restores `durationMs`, which pino-http
otherwise omits from the error branch.

**Note on `ip`:** values arrive IPv6-mapped (`::ffff:127.0.0.1` locally). This
is left as-is rather than normalised, since the raw value is what the proxy
reports.

## Audit events

| Event | Fields | Purpose |
| --- | --- | --- |
| `sign_in` | `userId`, `method` (google/local) | Who got in, and how |
| `sign_in_failed` | `ip`, `reason` (bad_password/unverified/google) | Brute-force signal |
| `sign_up` | `userId` | New account created |
| `email_verified` | `userId` | Token actually consumed |
| `logout` | `userId` | Closes the session pair |
| `recipe_created` | `userId`, `recipeId`, `source` (manual/ai) | Content provenance; separates hand-written from generated |
| `recipe_deleted` | `userId`, `recipeId` | Destructive and irreversible |
| `delete_denied` | `userId`, `recipeId`, `kind` (recipe/comment) | Attempt to delete another user's content |
| `ai_generated` | `userId`, `remaining` | Quota burn-down over time |
| `ai_quota_denied` | `userId`, `reason` | Cost control: the free tier is being hit |
| `ai_rejected` | `userId`, `reason` (not-food) | Prompt-abuse signal |

The three AI events matter most: the quota guard is the only thing between this
app and a bill, and at present nothing records when it refuses someone.

### Decision: no email address on `sign_in_failed`

Only `ip` and `reason` are logged. The signup and resend-verification routes
deliberately never reveal whether an address is registered; writing attempted
addresses into an audit log would partly undo that, and a failed attempt often
carries a third party's address or a typo of one.

Accepted cost: brute force is detectable by source IP but not by targeted
account.

## Error handling

Three touchpoints, all in existing code. None of them changes control flow,
status codes, or any response body.

**Error middleware** (`index.js:56`) becomes
`req.log.error({ err }, 'unhandled error')` and keeps its existing
`res.headersSent` guard, which is correct as written.

**`process.on('unhandledRejection')`** (`index.js:66`) keeps its current
behaviour of logging and continuing to serve — that handler is what stopped one
bad database row taking the whole server down. It uses the base logger.

**Route `.catch` handlers** keep their existing status codes and messages
exactly. Only `console.log(err)` changes, to
`req.log.error({ err }, '<message>')`.

Errors must be logged as `{ err }` so pino's `stdSerializers.err` handles them.
A bare `JSON.stringify(someError)` produces `{}` and loses the stack silently.

## Configuration

One new environment variable:

| Variable | Default | Meaning |
| --- | --- | --- |
| `LOG_LEVEL` | `info` when `NODE_ENV === 'production'`, otherwise `debug` | Minimum level written |

Added to `.env.example` and the README environment table.

`pino-pretty` is a devDependency, piped in the script rather than wired in as a
transport, so it stays out of the production dependency tree:

```json
"start": "node index.js",
"dev":   "nodemon index.js | pino-pretty"
```

nodemon's own `[nodemon] restarting` output is not JSON; pino-pretty passes
unparseable lines through untouched, so those still show.

## Migrating the 48 console calls

| File | Calls | Target |
| --- | --- | --- |
| `routes/recipe.js` | 14 | `req.log` |
| `routes/user.js` | 9 | `req.log` |
| `db.js` | 8 | base `logger` |
| `index.js` | 6 | base `logger` |
| `gemini.js` | 5 | base `logger` |
| `google_strategy.js` | 2 | base `logger` |
| `mailer.js` | 2 | base `logger` |
| `local_strategy.js` | 1 | base `logger` |
| `session_config.js` | 1 | base `logger` |

Levels are assigned by meaning, not mechanically. Caught exceptions become
`error`. The calls that are really warnings today become `warn`:
`no ai_pics folder found`, `ranking row … has no recipe, skipping`, and the
missing `GEMINI_API_KEY` notice. Startup messages stay `info`.

## Testing

`npm test` is currently the `exit 1` stub. Node's built-in `node:test` needs no
new dependency, so the script becomes `"test": "node --test"`.

Two automated tests:

1. **Serializer redaction.** Given a request shaped like
   `GET /verify-email?token=secret123` with a `connect.sid` cookie header,
   assert the serialized output contains neither the token string nor the
   cookie, and that `path` is exactly `/verify-email`. This is the security
   invariant of the whole design and the kind of thing a later refactor breaks
   silently.
2. **Status-to-level mapping.** 200 → info, 404 → warn, 500 → error.

Manual verification:

- `npm run dev`, load a page, confirm asset requests are absent from the log.
- Sign in; confirm the `sign_in` audit line shares a `reqId` with its request
  line.
- Request a bad recipe id; confirm the 404 logs at `warn`.
- Confirm `npm start` emits raw JSON with no pretty formatting.

## Deviations from the article

| Article | This design | Reason |
| --- | --- | --- |
| winston | pino | Destination is stdout JSON, which is pino's default. The article chose winston for its MongoDB and file-rotation transports, both dropped here. |
| `winston-daily-rotate-file` | stdout only | App Platform's filesystem is ephemeral |
| MongoDB transport | none | No MongoDB in this stack; SQLite only |
| Override `res.send` | `pino-http` finish hook | Nothing to capture from the body, so no reason to monkey-patch Express |
| Log bodies, mask `password` | Log no bodies | A denylist fails open: any future field not on the list gets logged in full |

## Out of scope

- File output and rotation.
- Shipping to an external log service.
- Request or response bodies.
- Frontend logging.
- The SQLite persistence question. `data/` is on the same ephemeral filesystem
  as `logs/` would be; whether a volume is attached needs checking separately
  and is not addressed here.

## Delivery

Several small commits rather than one, since the change touches 48 call sites
across 9 files. Suggested sequence: add dependencies, add the three modules,
wire up `index.js`, migrate routes, migrate remaining modules, add tests, update
docs.
