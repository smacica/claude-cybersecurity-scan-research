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
