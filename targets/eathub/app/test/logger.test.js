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
