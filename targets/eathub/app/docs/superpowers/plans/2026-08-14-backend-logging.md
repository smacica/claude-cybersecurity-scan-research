# Backend Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace 48 scattered `console.log` calls in the Express backend with structured JSON logging to stdout, adding per-request correlation ids and a security audit trail.

**Architecture:** Three new root-level modules — `logger.js` (the pino instance), `request_log.js` (the pino-http middleware and its metadata-only policy), `audit.js` (named security events). Request lines are emitted by pino-http when the response finishes; route handlers use the per-request child logger `req.log` so their errors share a `reqId` with the request that caused them.

**Tech Stack:** Node 26, Express 4, pino 10, pino-http 11, pino-pretty 13 (dev only), `node:test`.

**Spec:** `docs/superpowers/specs/2026-08-14-backend-logging-design.md`

## Global Constraints

- **stdout only.** No file transports, no rotation, no external log service. DigitalOcean App Platform's filesystem is ephemeral.
- **Metadata only.** Never log request bodies, response bodies, headers, or query-string values. Passwords arrive in bodies on `/api/signup` and `/api/login`; a live credential arrives in the query string on `/verify-email?token=`; `connect.sid` rides in the cookie header.
- **Serializers fail closed.** Build a fresh object containing only named fields; never delete keys from a default object.
- **Exactly seven request-derived fields** on a request line: `method`, `path`, `status`, `durationMs`, `userId`, `ip`, `ua` — plus `reqId`, `level`, `time`, `env`, `pid`, `msg`.
- **No behaviour changes**, with exactly one sanctioned exception. Status codes, response bodies, redirects and control flow stay byte-for-byte identical; this work only changes what gets logged. **The single exception, approved before execution:** Task 4 Step 2 adds the missing `done(err)` call in `deserializeUser`. Today that path swallows the error and never calls `done`, so the request hangs until the browser gives up; after the change it fails as a 500. This is intended, not scope creep. No other behaviour change is permitted — if a task appears to require one, stop and report it.
- **Errors are logged as `{ err }`** so pino's `stdSerializers.err` handles them. `JSON.stringify(new Error('x'))` is `{}` and loses the stack silently.
- **Commit author must be `smacica <s.macica7@gmail.com>`.** Never Claude as author or co-author. Short lowercase commit subjects. Use:
  `git -c user.name="smacica" -c user.email="s.macica7@gmail.com" commit --author="smacica <s.macica7@gmail.com>" -m "<subject>"`
- **`npm test` must pass** at the end of every task from Task 1 onward.

## File Structure

| File | Status | Responsibility |
| --- | --- | --- |
| `logger.js` | create | The pino instance: level, base fields, error serializer. Nothing else. |
| `request_log.js` | create | pino-http middleware: field allowlist, level mapping, static-asset skipping, request ids. |
| `audit.js` | create | One named function per security event. |
| `test/logger.test.js` | create | Level resolution. |
| `test/request_log.test.js` | create | Redaction invariant, level mapping, static skipping, reqId correlation. |
| `test/audit.test.js` | create | Event names and field shapes. |
| `test/no_console.test.js` | create | Regression guard: no `console.*` left in backend source. |
| `package.json` | modify | Dependencies and scripts. |
| `index.js` | modify | Wire middleware, `trust proxy`, migrate 6 calls. |
| `routes/recipe.js` | modify | Migrate 14 calls, add 6 audit calls. |
| `routes/user.js` | modify | Migrate 9 calls, add 6 audit calls. |
| `db.js` | modify | Migrate 8 calls. |
| `gemini.js` | modify | Migrate 5 calls. |
| `google_strategy.js` | modify | Migrate 2 calls. |
| `mailer.js` | modify | Migrate 2 calls. |
| `local_strategy.js` | modify | Migrate 1 call. |
| `session_config.js` | modify | Migrate 1 call. |
| `.env.example` | modify | Document `LOG_LEVEL`. |
| `README.md` | modify | Document logging. |

Console-call totals per file are exact and were counted from the current tree; they sum to 48. Use them to check your work.

---

### Task 1: Dependencies and the base logger

**Files:**
- Modify: `package.json`
- Create: `logger.js`
- Create: `test/logger.test.js`

**Interfaces:**
- Consumes: nothing.
- Produces: `require('./logger')` → `{ logger, options }`.
  - `logger` — the pino instance. Level is `process.env.LOG_LEVEL`, else `info` when `NODE_ENV === 'production'`, else `debug`.
  - `options` — the plain options object the instance was built from. Exported so Task 2 can build an identically-configured instance pointed at a test sink. `logger.child({}, { destination })` does **not** work: pino accepts the option and silently ignores it, so a child cannot redirect output.

- [ ] **Step 1: Install dependencies**

```bash
npm install pino@^10.3.1 pino-http@^11.0.0
npm install --save-dev pino-pretty@^13.1.3
```

- [ ] **Step 2: Update the scripts in `package.json`**

Replace the existing `test` and `dev` scripts. `start` stays exactly as it is, so production emits raw JSON.

```json
"scripts": {
  "test": "node --test",
  "start": "node index.js",
  "dev": "nodemon index.js | pino-pretty",
  "build": "npm --prefix frontend install && npm --prefix frontend run build"
}
```

- [ ] **Step 3: Write the failing test**

Create `test/logger.test.js`. The logger reads env at require time, so each case clears the module from the require cache and restores env afterwards.

```js
const test = require('node:test')
const assert = require('node:assert')

const loggerPath = require.resolve('../logger')

//logger.js reads env once at require time, so each case needs a fresh module
function loadLogger(env){
  const before = { NODE_ENV: process.env.NODE_ENV, LOG_LEVEL: process.env.LOG_LEVEL }
  delete process.env.NODE_ENV
  delete process.env.LOG_LEVEL
  Object.assign(process.env, env)
  delete require.cache[loggerPath]

  try {
    return require('../logger').logger
  } finally {
    delete process.env.NODE_ENV
    delete process.env.LOG_LEVEL
    for (const [key, value] of Object.entries(before)) {
      if (value !== undefined) process.env[key] = value
    }
    delete require.cache[loggerPath]
  }
}

test('defaults to info in production', () => {
  assert.strictEqual(loadLogger({ NODE_ENV: 'production' }).level, 'info')
})

test('defaults to debug outside production', () => {
  assert.strictEqual(loadLogger({ NODE_ENV: 'development' }).level, 'debug')
})

test('LOG_LEVEL wins over the default', () => {
  assert.strictEqual(loadLogger({ NODE_ENV: 'production', LOG_LEVEL: 'warn' }).level, 'warn')
})

test('serializes an Error with its stack', () => {
  const logger = loadLogger({ LOG_LEVEL: 'debug' })
  const serialized = logger[Symbol.for('pino.serializers')].err(new Error('boom'))

  assert.strictEqual(serialized.message, 'boom')
  assert.strictEqual(serialized.type, 'Error')
  assert.ok(serialized.stack.includes('boom'))
})
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module '../logger'`

- [ ] **Step 5: Write `logger.js`**

```js
const pino = require('pino')

//stdout only. the digitalocean app platform filesystem is ephemeral, so log files
//would be lost on every redeploy and there is no easy way to read them back out.
//see docs/superpowers/specs/2026-08-14-backend-logging-design.md
const isProduction = process.env.NODE_ENV === 'production'

const options = {
  level: process.env.LOG_LEVEL || (isProduction ? 'info' : 'debug'),
  //hostname is a throwaway container id on app platform, so it is dropped
  base: { env: process.env.NODE_ENV || 'development', pid: process.pid },
  //without this an Error logs as {} and the stack disappears silently
  serializers: { err: pino.stdSerializers.err }
}

const logger = pino(options)

//options is exported so the tests can build an identically configured logger
//pointed at a capture stream. a child logger cannot redirect output - pino takes
//the destination option and quietly ignores it.
module.exports = { logger, options }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `npm test`
Expected: PASS, 4 tests

- [ ] **Step 7: Commit**

```bash
git add package.json package-lock.json logger.js test/logger.test.js
git -c user.name="smacica" -c user.email="s.macica7@gmail.com" \
  commit --author="smacica <s.macica7@gmail.com>" -m "add pino logger"
```

---

### Task 2: The request logging middleware

This task carries the security invariant of the whole feature. The tests come first and matter more than the implementation.

**Files:**
- Create: `request_log.js`
- Create: `test/request_log.test.js`

**Interfaces:**
- Consumes: `require('./logger')` → `{ logger, options }` from Task 1.
- Produces: `require('./request_log')` → `{ requestLog, attachReqId, buildRequestLog, pathOf, isStatic }`.
  - `buildRequestLog(destination?)` → `{ requestLog, attachReqId }`. With no argument it uses the shared `logger`; with a writable stream it builds a fresh pino instance from `options` pointed at that stream, which is how the tests capture output.
  - `requestLog` — the pino-http middleware, mounted with `app.use(requestLog)`.
  - `attachReqId` — Express middleware `(req, res, next)`, mounted immediately after `requestLog`.
  - `pathOf(req)` → `string`, the path with any query string removed.
  - `isStatic(path)` → `boolean`.

- [ ] **Step 1: Write the failing test**

Create `test/request_log.test.js`. It boots a tiny Express app with only this middleware, captures pino's output through a writable stream, and asserts on the parsed lines.

```js
const test = require('node:test')
const assert = require('node:assert')
const { Writable } = require('node:stream')
const express = require('express')

const { pathOf, isStatic } = require('../request_log')

//captures every line the middleware writes, so assertions run on real output
//rather than on a mock of it
function makeApp(){
  const lines = []
  const sink = new Writable({
    write(chunk, encoding, callback){
      lines.push(JSON.parse(chunk.toString()))
      callback()
    }
  })

  const { buildRequestLog } = require('../request_log')
  const { requestLog, attachReqId } = buildRequestLog(sink)

  const app = express()
  app.set('trust proxy', 1)
  app.use(requestLog)
  app.use(attachReqId)
  //stands in for passport, which also runs after the logger
  app.use((req, res, next) => { req.user = { user_id: 7 }; next() })

  app.get('/verify-email', (req, res) => res.json({ ok: true }))
  app.get('/assets/app.js', (req, res) => res.send('x'))
  app.get('/ai_pics/one.jpg', (req, res) => res.send('x'))
  app.get('/api/boom', (req, res) => {
    req.log.error({ err: new Error('kaboom') }, 'handler failed')
    res.status(500).json({})
  })
  app.get('/api/missing', (req, res) => res.status(404).json({}))
  app.get('/api/fine', (req, res) => res.json({}))

  return { app, lines }
}

//makes one request against an ephemeral port and resolves once the line is written
async function request(app, path, headers = {}){
  const { lines } = app
  const server = app.app.listen(0)
  await new Promise(resolve => server.once('listening', resolve))

  try {
    await fetch(`http://127.0.0.1:${server.address().port}${path}`, { headers })
    //the finish handler runs a tick after the response is delivered
    await new Promise(resolve => setTimeout(resolve, 50))
  } finally {
    server.close()
  }

  return lines
}

test('pathOf drops the query string', () => {
  assert.strictEqual(pathOf({ originalUrl: '/verify-email?token=abc' }), '/verify-email')
  assert.strictEqual(pathOf({ originalUrl: '/api/recipes/42' }), '/api/recipes/42')
})

test('isStatic matches bundle paths and asset extensions', () => {
  assert.ok(isStatic('/assets/index-a1b2.js'))
  assert.ok(isStatic('/ai_pics/one.jpg'))
  assert.ok(isStatic('/favicon.ico'))
  assert.ok(!isStatic('/api/recipes'))
  assert.ok(!isStatic('/verify-email'))
})

test('never logs a token from the query string or a session cookie', async () => {
  const app = makeApp()
  const lines = await request(app, '/verify-email?token=SUPERSECRET123', {
    cookie: 'connect.sid=SESSIONVALUE',
    'user-agent': 'probe/1.0'
  })

  const dump = JSON.stringify(lines)
  assert.ok(!dump.includes('SUPERSECRET123'), 'the verification token reached the log')
  assert.ok(!dump.includes('SESSIONVALUE'), 'the session cookie reached the log')

  const line = lines.find(entry => entry.msg === 'request')
  assert.strictEqual(line.path, '/verify-email')
  assert.strictEqual(line.ua, 'probe/1.0')
})

test('logs exactly the allowlisted fields', async () => {
  const app = makeApp()
  const lines = await request(app, '/api/fine')
  const line = lines.find(entry => entry.msg === 'request')

  assert.deepStrictEqual(
    Object.keys(line).sort(),
    ['durationMs', 'env', 'ip', 'level', 'method', 'msg', 'path', 'pid', 'reqId', 'status', 'time', 'ua', 'userId'].sort()
  )
  assert.strictEqual(line.userId, 7)
})

test('maps status onto level', async () => {
  const ok = await request(makeApp(), '/api/fine')
  assert.strictEqual(ok.find(entry => entry.msg === 'request').level, 30)

  const missing = await request(makeApp(), '/api/missing')
  assert.strictEqual(missing.find(entry => entry.msg === 'request').level, 40)

  const broken = await request(makeApp(), '/api/boom')
  assert.strictEqual(broken.find(entry => entry.msg === 'request').level, 50)
})

test('skips static assets', async () => {
  const bundle = await request(makeApp(), '/assets/app.js')
  assert.strictEqual(bundle.length, 0)

  const picture = await request(makeApp(), '/ai_pics/one.jpg')
  assert.strictEqual(picture.length, 0)
})

test('a handler error shares its reqId with the request line', async () => {
  const lines = await request(makeApp(), '/api/boom')

  const handler = lines.find(entry => entry.msg === 'handler failed')
  const requestLine = lines.find(entry => entry.msg === 'request')

  assert.ok(handler.reqId, 'the handler line has no reqId')
  assert.strictEqual(handler.reqId, requestLine.reqId)
  assert.strictEqual(handler.err.message, 'kaboom')
})

test('the request line carries no fabricated error on a 500', async () => {
  const lines = await request(makeApp(), '/api/boom')
  const requestLine = lines.find(entry => entry.msg === 'request')

  assert.strictEqual(requestLine.err, undefined)
  assert.strictEqual(typeof requestLine.durationMs, 'number')
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module '../request_log'`

- [ ] **Step 3: Write `request_log.js`**

Every non-obvious line here is load-bearing and was verified against pino-http 11.0.0. Do not simplify it without re-running the tests.

```js
const crypto = require('node:crypto')
const pino = require('pino')
const pinoHttp = require('pino-http')
const { logger, options } = require('./logger')

//express.static serves the built vue bundle, so without this every page load
//writes a line per js chunk, stylesheet and picture
const STATIC_PREFIXES = ['/assets/', '/ai_pics/']
const STATIC_FILE = /\.(js|mjs|css|map|png|jpe?g|webp|svg|gif|ico|woff2?|ttf)$/i

//originalUrl carries the query string, and /verify-email?token=... is a working
//credential until it is used. only ever keep what comes before the '?'.
function pathOf(req){
  return String(req.originalUrl || req.url || '').split('?')[0]
}

function isStatic(path){
  return STATIC_PREFIXES.some(prefix => path.startsWith(prefix)) || STATIC_FILE.test(path)
}

//the destination argument only exists so the tests can capture output. it has to
//be a whole new instance: logger.child({}, { destination }) is accepted by pino
//and then silently ignored, so the output would still go to stdout.
function buildRequestLog(destination){
  const target = destination ? pino(options, destination) : logger

  const requestLog = pinoHttp({
    logger: target,

    genReqId(req){
      //reuse the platform's id when there is one, so a log line can be matched
      //against the proxy's own record of the request
      return req.headers['x-request-id'] || crypto.randomUUID()
    },

    //returning undefined keeps the raw req and res out of the log entirely.
    //this is what makes the field list an allowlist rather than a denylist:
    //nothing appears unless customProps names it below.
    serializers: { req: () => undefined, res: () => undefined },

    customAttributeKeys: { responseTime: 'durationMs' },

    customProps(req, res){
      return {
        //suppressing the req serializer also discarded pino-http's request id,
        //so it has to be put back by hand
        reqId: req.id,
        method: req.method,
        path: pathOf(req),
        status: res.statusCode,
        //null on lines logged through req.log: pino-http evaluates this once when
        //it builds the child logger, which is before passport sets req.user. the
        //request line below is re-evaluated at finish and does carry the id.
        userId: req.user ? req.user.user_id : null,
        ip: req.ip || null,
        ua: req.headers['user-agent'] || null
      }
    },

    customLogLevel(req, res, err){
      if(err || res.statusCode >= 500){
        return 'error'
      }
      if(res.statusCode >= 400){
        return 'warn'
      }
      return 'info'
    },

    customSuccessMessage: () => 'request',
    customErrorMessage: () => 'request',

    //for any 5xx pino-http invents an Error whose stack points into its own
    //logger.js. keep the request line metadata-only and let the error middleware
    //log the real cause under the same reqId. this also restores durationMs,
    //which pino-http otherwise leaves off the error branch.
    customErrorObject: (req, res, error, val) => ({ durationMs: val.durationMs }),

    autoLogging: {
      ignore: req => isStatic(pathOf(req))
    }
  })

  //req.log is a child built before passport runs, and it lost its request id along
  //with the req serializer. rebinding it here is what makes an in-route error
  //greppable against the request that caused it.
  function attachReqId(req, res, next){
    req.log = req.log.child({ reqId: req.id })
    next()
  }

  return { requestLog, attachReqId }
}

const { requestLog, attachReqId } = buildRequestLog()

module.exports = { requestLog, attachReqId, buildRequestLog, pathOf, isStatic }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test`
Expected: PASS, 12 tests total

If `logs exactly the allowlisted fields` fails on an unexpected key, do not delete the assertion — a new key means something is leaking into the line that the design did not sanction.

- [ ] **Step 5: Commit**

```bash
git add request_log.js test/request_log.test.js
git -c user.name="smacica" -c user.email="s.macica7@gmail.com" \
  commit --author="smacica <s.macica7@gmail.com>" -m "add request logging middleware"
```

---

### Task 3: Audit events

**Files:**
- Create: `audit.js`
- Create: `test/audit.test.js`

**Interfaces:**
- Consumes: `require('./logger')` → `{ logger }`.
- Produces: `require('./audit')` → `{ audit }`. Every function takes the request logger first and is called as `audit.signIn(req.log, { ... })`. Passing a falsy logger falls back to the base logger, so a call site without a request still works.

```
audit.signIn(log, { userId, method })          method: 'google' | 'local'
audit.signInFailed(log, { ip, reason })        reason: 'bad_password' | 'unverified' | 'google'
audit.signUp(log, { userId })
audit.emailVerified(log, { userId })
audit.logout(log, { userId })
audit.recipeCreated(log, { userId, recipeId, source })   source: 'manual' | 'ai'
audit.recipeDeleted(log, { userId, recipeId })
audit.deleteDenied(log, { userId, recipeId, kind })      kind: 'recipe' | 'comment'
audit.aiGenerated(log, { userId, remaining })
audit.aiQuotaDenied(log, { userId, reason })
audit.aiRejected(log, { userId, reason })
```

- [ ] **Step 1: Write the failing test**

Create `test/audit.test.js`.

```js
const test = require('node:test')
const assert = require('node:assert')

const { audit } = require('../audit')

//stands in for req.log and records what it was handed
function fakeLog(){
  const calls = []
  return {
    calls,
    info(fields, msg){ calls.push({ level: 'info', fields, msg }) },
    warn(fields, msg){ calls.push({ level: 'warn', fields, msg }) }
  }
}

test('signIn logs the event name and fields', () => {
  const log = fakeLog()
  audit.signIn(log, { userId: 7, method: 'google' })

  assert.strictEqual(log.calls.length, 1)
  assert.strictEqual(log.calls[0].level, 'info')
  assert.deepStrictEqual(log.calls[0].fields, { event: 'sign_in', userId: 7, method: 'google' })
})

test('signInFailed is a warning and carries no email address', () => {
  const log = fakeLog()
  audit.signInFailed(log, { ip: '203.0.113.9', reason: 'bad_password' })

  assert.strictEqual(log.calls[0].level, 'warn')
  assert.deepStrictEqual(log.calls[0].fields, {
    event: 'sign_in_failed', ip: '203.0.113.9', reason: 'bad_password'
  })
  //deliberate: signup never reveals whether an address is registered, and the
  //audit log must not undo that
  assert.ok(!JSON.stringify(log.calls[0]).includes('@'))
})

test('deleteDenied is a warning', () => {
  const log = fakeLog()
  audit.deleteDenied(log, { userId: 7, recipeId: 42, kind: 'recipe' })

  assert.strictEqual(log.calls[0].level, 'warn')
  assert.strictEqual(log.calls[0].fields.event, 'delete_denied')
})

test('aiQuotaDenied is a warning', () => {
  const log = fakeLog()
  audit.aiQuotaDenied(log, { userId: 7, reason: 'user-daily' })

  assert.strictEqual(log.calls[0].level, 'warn')
  assert.strictEqual(log.calls[0].fields.event, 'ai_quota_denied')
})

test('every event has a distinct name', () => {
  const seen = new Set()

  for(const name of Object.keys(audit)){
    const log = fakeLog()
    audit[name](log, {})

    const event = log.calls[0].fields.event
    assert.ok(event, `${name} logged no event field`)
    assert.ok(!seen.has(event), `${event} is used twice`)
    seen.add(event)
  }

  assert.strictEqual(seen.size, 11)
})

test('falls back to the base logger when none is given', () => {
  //must not throw
  audit.signIn(null, { userId: 7, method: 'local' })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module '../audit'`

- [ ] **Step 3: Write `audit.js`**

```js
const { logger } = require('./logger')

//audit lines are the ones that get filtered on later, so every event name is
//defined exactly once here. a query for event:"sign_in_failed" only works if
//nothing else in the codebase spells it differently.
function event(name, level = 'info'){
  return function(log, fields = {}){
    const target = log || logger
    target[level]({ event: name, ...fields }, name)
  }
}

const audit = {
  signIn:         event('sign_in'),
  signInFailed:   event('sign_in_failed', 'warn'),
  signUp:         event('sign_up'),
  emailVerified:  event('email_verified'),
  logout:         event('logout'),
  recipeCreated:  event('recipe_created'),
  recipeDeleted:  event('recipe_deleted'),
  deleteDenied:   event('delete_denied', 'warn'),
  aiGenerated:    event('ai_generated'),
  aiQuotaDenied:  event('ai_quota_denied', 'warn'),
  aiRejected:     event('ai_rejected', 'warn')
}

module.exports = { audit }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test`
Expected: PASS, 18 tests total

- [ ] **Step 5: Commit**

```bash
git add audit.js test/audit.test.js
git -c user.name="smacica" -c user.email="s.macica7@gmail.com" \
  commit --author="smacica <s.macica7@gmail.com>" -m "add audit events"
```

---

### Task 4: Wire the middleware into the app

**Files:**
- Modify: `index.js` (6 console calls, lines 30, 57, 67, 72, 78, 80)

**Interfaces:**
- Consumes: `{ logger }` from Task 1, `{ requestLog }` from Task 2.
- Produces: `req.log` on every request, available to Tasks 5 and 6.

- [ ] **Step 0: Delete the dead `attachReqId` middleware**

Task 2 originally used `attachReqId` to rebind `req.log` with the request id. Its
fix round set `quietReqLogger`/`quietResLogger`, which makes pino-http bind
`reqId` onto `req.log` itself, so the rebind was removed and the function is now
a no-op whose two branches both just call `next()`. Its name promises a rebind it
no longer performs, so it goes rather than being mounted.

In `request_log.js`: delete the `attachReqId` function and remove it from both
the `buildRequestLog` return object and `module.exports`. `buildRequestLog` now
returns `{ requestLog }`, and the module exports
`{ requestLog, buildRequestLog, pathOf, isStatic }`.

In `test/request_log.test.js`: `makeApp` destructures and mounts `attachReqId` —
remove both. Do not change any assertion. All 16 tests must still pass, which is
the check that `reqId` correlation survives without it.

- [ ] **Step 1: Add the requires**

After the existing `const path = require('path')` on line 12:

```js
const { logger } = require('./logger')
const { requestLog } = require('./request_log')
```

- [ ] **Step 2: Fix the deserializeUser handler**

Replace lines 27–30:

```js
passport.deserializeUser((id, done) => {
  dbFind('users', 'user_id', id)
  .then(user => done(null, user))
  .catch(err => {
    logger.error({ err }, 'could not deserialize the session user')
    done(err)
  })});
```

Note this also passes the error to `done`, which the old code did not — without it a failed lookup left the callback hanging. This is a deliberate fix, not an accident of the migration.

- [ ] **Step 3: Set trust proxy and mount the middleware**

App Platform sits behind a proxy, so without `trust proxy` every `ip` in the log is the proxy's address. Add it immediately before the middleware block, then mount the logger right after `cors` and before `session`, so a failure inside session or passport still produces a line.

```js
//app platform terminates tls in front of us, so req.ip is the proxy without this
app.set('trust proxy', 1)

//middleware
app.use(cors({ origin: clientUrl || true, credentials: true }))
app.options('*', cors({ origin: clientUrl || true, credentials: true }));
//before session and passport on purpose - a failure in either still gets logged
app.use(requestLog);
app.use(session(sessionConf));
```

- [ ] **Step 4: Replace the error middleware**

Replace lines 56–62:

```js
app.use(function(err, req, res, next) {
  //req.log carries the reqId, so this line can be matched to its request
  req.log.error({ err }, 'unhandled error');
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ message: 'something went wrong' });
});
```

- [ ] **Step 5: Replace the unhandledRejection handler and the startup logs**

```js
//a rejected promise nobody caught used to take the whole server down with it, which
//turned one bad database row into a total outage. log it and keep serving.
process.on('unhandledRejection', (reason) => {
  logger.error({ err: reason }, 'unhandled promise rejection');
});

const port = process.env.PORT || 4000
app.listen(port, () => {
    logger.info({ port, clientUrl: clientUrl || null }, `listening on http://localhost:${port}`)

    //CLIENT_URL decides where sign in drops the browser afterwards. Pointing it at
    //the vite port and then browsing the built app on this port sends people to a
    //dead address once google hands them back, so say plainly where they will land.
    if(clientUrl){
      logger.info(`after sign in the browser goes to ${clientUrl} - keep that dev server running`)
    }else{
      logger.info('after sign in the browser stays on this server')
    }
  })
```

- [ ] **Step 6: Verify no console calls remain in `index.js`**

Run: `grep -n "console\." index.js`
Expected: no output

- [ ] **Step 7: Verify the server boots and logs**

Run: `npm test && npm start`

Expected: a JSON line on stdout containing `"msg":"listening on http://localhost:4000"`.

In a second terminal:

```bash
curl -s localhost:4000/api/recipes > /dev/null
curl -s localhost:4000/api/nope > /dev/null
```

Expected in the server output: one line with `"path":"/api/recipes"` and `"level":30`, and one with `"path":"/api/nope"` and `"level":40`. Both must have a `reqId`. Stop the server with Ctrl-C.

- [ ] **Step 8: Commit**

```bash
git add index.js
git -c user.name="smacica" -c user.email="s.macica7@gmail.com" \
  commit --author="smacica <s.macica7@gmail.com>" -m "wire request logging into the app"
```

---

### Task 5: Migrate `routes/recipe.js`

14 console calls at lines 23, 77, 100, 106, 121, 177, 192, 218, 222, 241, 260, 277, 287, 303. Plus six audit calls.

**Files:**
- Modify: `routes/recipe.js`

**Interfaces:**
- Consumes: `req.log` from Task 4, `{ audit }` from Task 3, `{ logger }` from Task 1.
- Produces: nothing new.

- [ ] **Step 1: Add the requires**

After line 12 (`const aiQuota = require('../ai_quota')`):

```js
const { logger } = require('../logger')
const { audit } = require('../audit')
```

The module-level `ai_pics` warning at line 23 runs at require time, before any request exists, so it uses `logger` rather than `req.log`.

- [ ] **Step 2: Replace the module-level warning (line 23)**

```js
}catch(err){
  logger.warn('no ai_pics folder found, generated recipes will have no photo')
}
```

- [ ] **Step 3: Replace the in-route error logs**

Each of these is inside a route and becomes `req.log.error({ err }, '<message>')`. Keep every surrounding status code and response body exactly as it is.

| Line | Replacement |
| --- | --- |
| 77 | `req.log.error({ err }, 'could not save the recipe')` |
| 100 | `req.log.warn({ err }, 'could not delete the recipe photo')` |
| 106 | `req.log.error({ err }, 'could not delete the recipe')` |
| 121 | `req.log.error({ err }, 'could not read the ai quota')` |
| 177 | `req.log.error({ err }, 'could not save the generated recipe')` |
| 192 | `req.log.error({ err }, 'could not load the comments')` |
| 218 | `req.log.error({ err }, 'could not save the comment')` |
| 222 | `req.log.error({ err }, 'could not save the comment')` |
| 241 | `req.log.error({ err }, 'could not delete the comment')` |
| 260 | `req.log.error({ err }, 'could not record the vote')` |
| 277 | `req.log.error({ err }, 'could not load the recipes')` |
| 287 | `req.log.error({ err }, 'could not load your recipes')` |
| 303 | `req.log.error({ err }, 'could not load the recipe')` |

Line 100 is a `warn` rather than an `error` because a leftover image file does not fail the request — the existing comment says so.

Line 260 keeps its existing comment (`//without this a rejection left the request open until the browser gave up`).

- [ ] **Step 4: Add the audit calls**

In the create route, inside the `insertRecipe(recipe).then(...)` success branch (around line 74), before the response:

```js
insertRecipe(recipe).then(()=>{
  audit.recipeCreated(req.log, { userId: req.user.user_id, recipeId: recipe.recipe_id, source: 'manual' })
  res.status(201).json({recipe_id: recipe.recipe_id})
}).catch(err=>{
```

In the delete route, in both branches of the `if(!result.deleted)` check and on success:

```js
dbDeleteRecipe(id, req.user.user_id).then(result=>{
  if(!result.deleted){
    const status = result.reason === 'forbidden' ? 403 : 404
    const message = result.reason === 'forbidden' ? "that is not your recipe" : "recipe not found"
    //a forbidden delete is someone reaching for another person's recipe
    if(result.reason === 'forbidden'){
      audit.deleteDenied(req.log, { userId: req.user.user_id, recipeId: id, kind: 'recipe' })
    }
    return res.status(status).json({message})
  }
  audit.recipeDeleted(req.log, { userId: req.user.user_id, recipeId: id })
```

In the generate route, on a refused quota slot (around line 152):

```js
const slot = await aiQuota.reserve(req.user.user_id)
if(!slot.ok){
  audit.aiQuotaDenied(req.log, { userId: req.user.user_id, reason: slot.reason })
  return res.status(429).json({message: slot.message, reason: slot.reason})
}
```

On a refused generation (around line 158):

```js
if(!result.ok){
  const [status, message] = FAILURES[result.reason] || FAILURES.upstream
  audit.aiRejected(req.log, { userId: req.user.user_id, reason: result.reason })
  return res.status(status).json({message, reason: result.reason})
}
```

And after the insert succeeds (around line 174):

```js
await insertRecipe(recipe)
audit.recipeCreated(req.log, { userId: req.user.user_id, recipeId: recipe.recipe_id, source: 'ai' })
audit.aiGenerated(req.log, { userId: req.user.user_id, remaining: slot.remaining })
res.status(201).json({ recipe_id: recipe.recipe_id, remaining: slot.remaining })
```

In the comment delete route, on a forbidden result (around line 234):

```js
if(!result.deleted){
  const status = result.reason === 'forbidden' ? 403 : 404
  const message = result.reason === 'forbidden' ? "that is not your comment" : "comment not found"
  if(result.reason === 'forbidden'){
    audit.deleteDenied(req.log, { userId: req.user.user_id, recipeId: id, kind: 'comment' })
  }
  return res.status(status).json({message})
}
```

- [ ] **Step 5: Verify**

Run: `grep -c "console\." routes/recipe.js`
Expected: `0`

Run: `npm test`
Expected: PASS, 18 tests

Run: `node -e "require('./routes/recipe.js')"`
Expected: no output and exit code 0 — proves the file still parses and its requires resolve.

- [ ] **Step 6: Commit**

```bash
git add routes/recipe.js
git -c user.name="smacica" -c user.email="s.macica7@gmail.com" \
  commit --author="smacica <s.macica7@gmail.com>" -m "log recipe routes"
```

---

### Task 6: Migrate `routes/user.js`

9 console calls at lines 61, 83, 103, 119, 140, 146, 160, 166, 179. Plus six audit calls.

**Files:**
- Modify: `routes/user.js`

**Interfaces:**
- Consumes: `req.log` from Task 4, `{ audit }` from Task 3.
- Produces: nothing new.

- [ ] **Step 1: Add the require**

After line 6:

```js
const { audit } = require('../audit')
```

- [ ] **Step 2: Replace the error logs**

| Line | Replacement |
| --- | --- |
| 61 | `req.log.error({ err }, 'could not create the account')` |
| 83 | `req.log.error({ err }, 'signed in but could not load the profile')` |
| 103 | `req.log.error({ err }, 'could not consume the verification token')` |
| 119 | `req.log.error({ err }, 'could not resend the verification link')` |
| 140 | `req.log.warn({ err }, 'google sign in failed')` |
| 146 | `req.log.warn({ err }, 'google sign in failed at login')` |
| 160 | `req.log.error({ err }, 'logout failed')` |
| 166 | `req.log.error({ err }, 'could not destroy the session')` |
| 179 | `req.log.error({ err }, 'could not load the profile')` |

Lines 140 and 146 need care: the existing code logs `err ? err.message : 'no user returned'`, and `err` may be null when Google simply refused. Write them as:

```js
if(err || !user){
    req.log.warn({ err }, 'google sign in failed')
    audit.signInFailed(req.log, { ip: req.ip, reason: 'google' })
    return res.redirect(`${clientUrl}/signin?error=auth`)
}
```

and

```js
req.login(user, function(err){
    if(err){
        req.log.warn({ err }, 'google sign in failed at login')
        return res.redirect(`${clientUrl}/signin?error=auth`)
    }
```

- [ ] **Step 3: Add the audit calls**

Signup success, inside the `if(user)` branch after the verification email is issued (around line 52):

```js
if(user){
    const { delivered } = await issueVerificationEmail(user, baseUrl(req))
    audit.signUp(req.log, { userId: user.user_id })
    return res.status(201).json({
```

Local login — the failure branch (around line 71) and the success branch (around line 80):

```js
if(!user){
    //401 for a bad password, 403 when the account exists but is not confirmed
    const status = info?.code === 'unverified' ? 403 : 401
    audit.signInFailed(req.log, {
        ip: req.ip,
        reason: info?.code === 'unverified' ? 'unverified' : 'bad_password'
    })
    return res.status(status).json({message: info?.message || "Wrong email or password.", code: info?.code})
}
req.login(user, function(err){
    if(err){
        return next(err)
    }
    audit.signIn(req.log, { userId: user.user_id, method: 'local' })
```

Email verification success (around line 101). On success `dbConsumeEmailToken`
resolves the full user row (`db.js:520` returns `dbFind('users', 'user_id', …)`),
so `result.user_id` is present. It resolves `null` when the token is unknown and
`{ expired: true }` when it has lapsed, and both of those return before this line:

```js
audit.emailVerified(req.log, { userId: result.user_id })
res.redirect(`${clientUrl}/signin?verify=ok`)
```

Google login success, after `delete req.session.returnTo` (around line 149):

```js
const returnTo = safeNext(req.session.returnTo)
delete req.session.returnTo
audit.signIn(req.log, { userId: user.user_id, method: 'google' })
res.redirect(clientUrl + returnTo)
```

Logout — capture the user id before `req.logout` clears it:

```js
router.post('/api/logout', function(req, res, next){
    //req.user is gone once logout runs, so read it first
    const userId = req.user ? req.user.user_id : null

    req.logout(function(err) {
        if (err) {
            req.log.error({ err }, 'logout failed')
            return next(err);
        }
        //drop the session row too, otherwise the old cookie still resolves
        req.session.destroy(function(err) {
            if (err) {
                req.log.error({ err }, 'could not destroy the session')
            }
            res.clearCookie('connect.sid')
            audit.logout(req.log, { userId })
            res.json({message: "you have been logged out"})
        })
    });
});
```

- [ ] **Step 4: Verify**

Run: `grep -c "console\." routes/user.js`
Expected: `0`

Run: `npm test && node -e "require('./routes/user.js')"`
Expected: tests PASS, then no output and exit code 0

- [ ] **Step 5: Commit**

```bash
git add routes/user.js
git -c user.name="smacica" -c user.email="s.macica7@gmail.com" \
  commit --author="smacica <s.macica7@gmail.com>" -m "log auth routes"
```

---

### Task 7: Migrate the remaining modules

19 console calls across six files, none of which has a request in scope. All use the base `logger`.

**Files:**
- Modify: `db.js` (lines 104, 116, 118, 121, 126, 131, 134, 211)
- Modify: `gemini.js` (lines 13, 149, 156, 164, 172)
- Modify: `google_strategy.js` (lines 9, 29)
- Modify: `mailer.js` (lines 7, 36)
- Modify: `local_strategy.js` (line 35)
- Modify: `session_config.js` (line 11)

**Interfaces:**
- Consumes: `{ logger }` from Task 1.
- Produces: nothing new.

- [ ] **Step 1: `db.js`**

Add `const { logger } = require('./logger')` near the top requires, then:

| Line | Replacement |
| --- | --- |
| 104 | `logger.info('users table migrated')` |
| 116 | `logger.error({ err }, 'could not open the database')` |
| 118 | `logger.info('sqlite connected')` |
| 121 | `logger.error({ err }, 'could not turn foreign keys on')` |
| 126 | `return logger.error({ err }, 'could not apply the schema')` |
| 131 | `logger.error({ err }, 'could not apply the indexes')` |
| 134 | `.catch(err => logger.error({ err }, 'could not migrate the users table'))` |
| 211 | `logger.warn({ recipeId: rank.recipe_id }, 'ranking row has no recipe, skipping')` |

Line 116 is inside `if(err)` where the variable is already named `err`, so `{ err }` works directly. Keep the `return` on line 126 — dropping it changes control flow.

Watch for a require cycle: `db.js` must require `./logger`, and `logger.js` requires only `pino`. There is no cycle. Do not have `logger.js` require anything from the app.

- [ ] **Step 2: `gemini.js`**

Add `const { logger } = require('./logger')` after the existing require on line 1.

| Line | Replacement |
| --- | --- |
| 13 | `logger.warn('GEMINI_API_KEY is missing, AI recipe generation is switched off. See README.md')` |
| 149 | `logger.error({ err }, 'gemini request failed')` |
| 156 | `logger.error({ status: response.status, body: body.slice(0, 400) }, 'gemini returned an error status')` |
| 164 | `logger.error('gemini returned no text')` |
| 172 | `logger.error({ text: text.slice(0, 200) }, 'gemini returned text that is not json')` |

Line 149 currently distinguishes a timeout by hand; `{ err }` captures `err.name` through the serializer, and the `reason` returned on the next line already encodes it, so the hand-written branch is no longer needed in the log message.

Lines 156 and 172 log truncated upstream content. That content is the model's own output and the request was a recipe prompt, so this stays within the metadata-only rule — but keep the existing `.slice()` truncation exactly.

- [ ] **Step 3: `google_strategy.js`**

Add `const { logger } = require('./logger')` after line 2.

| Line | Replacement |
| --- | --- |
| 9 | `logger.warn('GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are missing, sign in will fail. See README.md')` |
| 29 | `logger.error({ err }, 'could not find or create the google user')` |

- [ ] **Step 4: `mailer.js`**

Add `const { logger } = require('./logger')` near the top.

| Line | Replacement |
| --- | --- |
| 7 | `logger.warn('SMTP_* are not set, verification links will be printed to this console instead of emailed. See README.md')` |
| 36 | leave as `console.log` — see below |

Line 36 prints the verification link to the console as the developer fallback when SMTP is not configured. That is deliberate developer output, not logging: it must stay readable and must not be filtered out by `LOG_LEVEL`. Keep it as `console.log` and add a comment saying why:

```js
//deliberately console.log and not the logger: this is the dev fallback for a
//missing smtp setup and has to stay readable and unfilterable
console.log(`\n--- verification link for ${to} ---\n${link}\n---\n`)
```

Task 8's regression test allowlists this one line.

- [ ] **Step 5: `local_strategy.js`**

Add `const { logger } = require('./logger')` near the top.

| Line | Replacement |
| --- | --- |
| 35 | `logger.error({ err }, 'local sign in failed')` |

- [ ] **Step 6: `session_config.js`**

Add `const { logger } = require('./logger')` near the top.

| Line | Replacement |
| --- | --- |
| 11 | `logger.warn('SESSION_SECRET is missing, falling back to a development value. See README.md')` |

- [ ] **Step 7: Verify**

Run:

```bash
grep -rn "console\." --include="*.js" --exclude-dir=node_modules --exclude-dir=frontend --exclude-dir=test .
```

Expected: exactly one line — the verification-link fallback in `mailer.js`.

Run: `npm test && npm start`
Expected: tests PASS; the server boots and the startup lines are JSON. Stop with Ctrl-C.

- [ ] **Step 8: Commit**

```bash
git add db.js gemini.js google_strategy.js mailer.js local_strategy.js session_config.js
git -c user.name="smacica" -c user.email="s.macica7@gmail.com" \
  commit --author="smacica <s.macica7@gmail.com>" -m "log remaining backend modules"
```

---

### Task 8: Regression guard and documentation

**Files:**
- Create: `test/no_console.test.js`
- Modify: `.env.example`
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Write the failing test**

Create `test/no_console.test.js`. This is what stops the 48 calls creeping back in.

```js
const test = require('node:test')
const assert = require('node:assert')
const fs = require('node:fs')
const path = require('node:path')

const root = path.join(__dirname, '..')
const SKIP_DIRS = new Set(['node_modules', 'frontend', '.git', 'data', 'test', '.idea', '.vscode'])

//the verification-link fallback is deliberate developer output: it has to stay
//readable and must not be filtered out by LOG_LEVEL
const ALLOWED = new Set(['mailer.js'])

function backendFiles(dir = root, found = []){
  for(const entry of fs.readdirSync(dir, { withFileTypes: true })){
    if(entry.isDirectory()){
      if(!SKIP_DIRS.has(entry.name)) backendFiles(path.join(dir, entry.name), found)
    }else if(entry.name.endsWith('.js')){
      found.push(path.join(dir, entry.name))
    }
  }
  return found
}

test('backend code logs through the logger, not console', () => {
  const offenders = []

  for(const file of backendFiles()){
    const relative = path.relative(root, file)
    if(ALLOWED.has(relative)) continue

    fs.readFileSync(file, 'utf8').split('\n').forEach((line, index) => {
      if(/console\.(log|error|warn|info|debug)\(/.test(line)){
        offenders.push(`${relative}:${index + 1}`)
      }
    })
  }

  assert.deepStrictEqual(offenders, [], `use logger or req.log instead of console at: ${offenders.join(', ')}`)
})
```

- [ ] **Step 2: Run the test**

Run: `npm test`
Expected: PASS. If it fails, a console call was missed in Tasks 4–7 — fix the file it names rather than adding it to `ALLOWED`.

- [ ] **Step 3: Document `LOG_LEVEL` in `.env.example`**

Append:

```dotenv
# fatal | error | warn | info | debug | trace
# defaults to info when NODE_ENV=production, debug otherwise
LOG_LEVEL=
```

- [ ] **Step 4: Document logging in `README.md`**

Add a `## Logging` section:

````markdown
## Logging

The backend writes newline-delimited JSON to stdout. Nothing is written to disk,
because the App Platform filesystem is ephemeral — DigitalOcean captures stdout
into the runtime log console.

In development the `dev` script pipes through `pino-pretty` for readable output:

```bash
npm run dev
```

`npm start` leaves the output as raw JSON, which is what you want in production.

Each completed request logs one line:

```json
{"level":30,"time":1755100000000,"env":"production","reqId":"…","method":"GET",
 "path":"/api/recipes/42","status":200,"durationMs":14,"userId":7,
 "ip":"203.0.113.9","ua":"Mozilla/5.0 …","msg":"request"}
```

2xx and 3xx log at `info`, 4xx at `warn`, 5xx at `error`, so `level>=40` finds
everything that went wrong. Requests for the built frontend bundle and the AI
artwork are not logged.

**Bodies, headers and query strings are never logged.** Passwords arrive in
request bodies, the email verification token arrives in a query string, and the
session cookie arrives in a header — none of them can reach the log, because the
serializer names the fields it keeps rather than the ones it drops.

Errors logged inside a route share their `reqId` with the request line, so
grepping one id gives the request and everything that happened during it. Those
in-route lines show `userId: null`; the request line is the one that carries the
user id.

Security-relevant actions log an `event` field: `sign_in`, `sign_in_failed`,
`sign_up`, `email_verified`, `logout`, `recipe_created`, `recipe_deleted`,
`delete_denied`, `ai_generated`, `ai_quota_denied`, `ai_rejected`. The AI three
are worth watching — they show when the Gemini free-tier guard is being hit.

Set `LOG_LEVEL` to change verbosity. It defaults to `info` in production and
`debug` elsewhere.
````

- [ ] **Step 5: Full verification**

```bash
npm test
npm start
```

Then in a second terminal:

```bash
curl -s localhost:4000/api/recipes > /dev/null
curl -s "localhost:4000/verify-email?token=SHOULD_NOT_APPEAR" > /dev/null
```

Expected in the server output: a line for `/api/recipes`, and a line whose `path`
is exactly `/verify-email` with **no trace of `SHOULD_NOT_APPEAR` anywhere**.
Stop the server.

- [ ] **Step 6: Commit**

```bash
git add test/no_console.test.js .env.example README.md
git -c user.name="smacica" -c user.email="s.macica7@gmail.com" \
  commit --author="smacica <s.macica7@gmail.com>" -m "guard against console logging, document logging"
```

---

## Verification checklist

After Task 8, all of the following must hold:

- [ ] `npm test` passes — 19 tests across four files.
- [ ] `grep -rn "console\." --include="*.js" --exclude-dir=node_modules --exclude-dir=frontend --exclude-dir=test .` returns only the `mailer.js` fallback.
- [ ] `npm start` emits raw JSON; `npm run dev` emits readable coloured lines.
- [ ] Loading the app in a browser produces no log lines for `/assets/*`.
- [ ] Signing in produces a `sign_in` line whose `reqId` matches a request line.
- [ ] A request to `/verify-email?token=X` logs `path: "/verify-email"` and no `X`.
- [ ] Every commit is authored `smacica <s.macica7@gmail.com>`, and `git log --format="%an %ae" -8` shows no Claude attribution.
