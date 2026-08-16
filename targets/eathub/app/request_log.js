const crypto = require('node:crypto')
const pino = require('pino')
const pinoHttp = require('pino-http')
const { logger, options } = require('./logger')

//express.static serves the built vue bundle, so without this every page load
//writes a line per js chunk, stylesheet and picture
const STATIC_PREFIXES = ['/assets/', '/ai_pics/']
const STATIC_FILE = /\.(js|mjs|css|map|png|jpe?g|webp|svg|gif|ico|woff2?|ttf)$/i

//a param on a route like /api/recipes/:id can end in one of the STATIC_FILE
//extensions (e.g. /api/recipes/42.css), which would otherwise match the
//extension test below and vanish from the audit trail. api paths are never
//static, no matter what they end in.
const API_PREFIX = '/api/'

//a well-formed id: short and free of anything that could blow past node's
//header size cap or get interpreted downstream. anything else is treated as
//untrusted client input and replaced.
const REQUEST_ID = /^[A-Za-z0-9._-]{1,200}$/

//originalUrl carries the query string, and /verify-email?token=... is a working
//credential until it is used. only ever keep what comes before the '?'.
function pathOf(req){
  return String(req.originalUrl || req.url || '').split('?')[0]
}

function isStatic(path){
  return STATIC_PREFIXES.some(prefix => path.startsWith(prefix)) ||
    (!path.startsWith(API_PREFIX) && STATIC_FILE.test(path))
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
      //against the proxy's own record of the request. a client-forged header is
      //never trusted verbatim: it could collide ids across requests to poison
      //correlation, or run toward node's ~16KB header cap.
      const incoming = req.headers['x-request-id']
      return incoming && REQUEST_ID.test(incoming) ? incoming : crypto.randomUUID()
    },

    //quiets both the request-side and response-side child loggers pino-http
    //binds at request entry, so customProps binds exactly once, at finish.
    //quietReqLogger alone is not enough: pino-http still uses the entry-bound
    //fullReqLogger as res.log unless quietResLogger is also set, and that is
    //the logger the final "request" line is written through. without both,
    //every field is written twice on the wire (once at entry with stale
    //values, once at finish) because pino-http's own dedup guard only fires
    //when both binding sets are byte-identical, which they never are once
    //userId or status changes.
    quietReqLogger: true,
    quietResLogger: true,

    //returning undefined keeps the raw req and res out of the log entirely.
    //this is what makes the field list an allowlist rather than a denylist:
    //nothing appears unless customProps names it below.
    serializers: { req: () => undefined, res: () => undefined },

    customAttributeKeys: { responseTime: 'durationMs' },

    customProps(req, res){
      return {
        //reqId is not listed here: quietReqLogger/quietResLogger make pino-http
        //bind it itself (logger.child({ reqId: req.id })) before customProps
        //ever runs, so adding it again would write the field twice on the wire
        method: req.method,
        path: pathOf(req),
        status: res.statusCode,
        //req.user is set by passport, which runs after this middleware, so it is
        //only ever readable here at finish (customProps is evaluated once per
        //line thanks to quietReqLogger above). lines logged through req.log
        //during the handler carry only reqId, not this field at all.
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

  return { requestLog }
}

const { requestLog } = buildRequestLog()

module.exports = { requestLog, buildRequestLog, pathOf, isStatic }
