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
