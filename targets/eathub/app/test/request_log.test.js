const test = require('node:test')
const assert = require('node:assert')
const { Writable } = require('node:stream')
const express = require('express')

const { pathOf, isStatic } = require('../request_log')

//captures every line the middleware writes, so assertions run on real output
//rather than on a mock of it
function makeApp(){
  const lines = []
  //raw, unparsed chunks: JSON.parse collapses duplicate keys (last wins), so
  //a test for double-written fields has to look at the wire bytes, not this
  const rawLines = []
  const sink = new Writable({
    write(chunk, encoding, callback){
      const raw = chunk.toString()
      rawLines.push(raw)
      lines.push(JSON.parse(raw))
      callback()
    }
  })

  const { buildRequestLog } = require('../request_log')
  const { requestLog } = buildRequestLog(sink)

  const app = express()
  app.set('trust proxy', 1)
  app.use(requestLog)
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
  //a parameterized route whose :id can end in a static-looking extension
  app.get('/api/recipes/:id', (req, res) => res.json({}))

  return { app, lines, rawLines }
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

test('writes each field exactly once on the wire, even when userId and status change mid-request', async () => {
  const app = makeApp()
  //hits both the in-handler line (written through req.log)
  //and the finish line (written through customProps at response time), since
  //the double-write bug could hide in either one
  await request(app, '/api/boom')

  //JSON.parse would silently collapse a duplicated key (last value wins), which
  //is exactly why this has to inspect the raw bytes pino wrote rather than the
  //already-parsed `lines` array
  assert.ok(app.rawLines.length >= 2, 'expected both a handler line and a request line')

  for(const raw of app.rawLines){
    const keys = Array.from(raw.matchAll(/"(\w+)":/g), match => match[1])
    const counts = {}
    for(const key of keys){
      counts[key] = (counts[key] || 0) + 1
    }
    const duplicated = Object.entries(counts).filter(([, count]) => count > 1)
    assert.deepStrictEqual(duplicated, [], `field(s) written more than once in ${raw}: ${JSON.stringify(duplicated)}`)
  }
})

test('logs a parameterized api path even when it ends like a static asset', async () => {
  const hit = await request(makeApp(), '/api/recipes/42.css')
  const line = hit.find(entry => entry.msg === 'request')
  assert.ok(line, 'the request line for /api/recipes/42.css was suppressed')
  assert.strictEqual(line.path, '/api/recipes/42.css')

  //a genuine static asset must still be skipped
  const bundle = await request(makeApp(), '/assets/app.js')
  assert.strictEqual(bundle.length, 0)
})

test('replaces a forged x-request-id but honours a well-formed one', async () => {
  const honoured = await request(makeApp(), '/api/fine', { 'x-request-id': 'upstream-abc.123_XYZ' })
  assert.strictEqual(
    honoured.find(entry => entry.msg === 'request').reqId,
    'upstream-abc.123_XYZ'
  )

  const tooLong = 'a'.repeat(250)
  const overLong = await request(makeApp(), '/api/fine', { 'x-request-id': tooLong })
  const overLongId = overLong.find(entry => entry.msg === 'request').reqId
  assert.notStrictEqual(overLongId, tooLong, 'an oversized header was logged verbatim')

  const illegal = await request(makeApp(), '/api/fine', { 'x-request-id': 'has spaces/slashes;here' })
  const illegalId = illegal.find(entry => entry.msg === 'request').reqId
  assert.notStrictEqual(illegalId, 'has spaces/slashes;here', 'a header with illegal characters was logged verbatim')
})
