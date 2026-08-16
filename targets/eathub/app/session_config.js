const uuid = require('uuid').v4
var session = require('express-session');
const Store = require('express-sqlite3')(session);
const { logger } = require('./logger')

const storeOptions = {
  db: './data/main.db',
  concurentDb: true, // Enable SQLite3 WAL.
};

if (!process.env.SESSION_SECRET) {
  logger.warn('SESSION_SECRET is missing, falling back to a development value. See README.md')
}

sessionConf = {
    genid: (req) => {
      return uuid() // use UUIDs for session IDs
    },
    resave: false,
    //no session row until something is actually stored on it
    saveUninitialized: false,
    secret: process.env.SESSION_SECRET || "dev-only-secret",
    store: new Store(storeOptions),
    cookie: {
      httpOnly: true,
      //the oauth callback is a top level redirect, lax still sends the cookie
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // a week
    },
  }
module.exports = {sessionConf}
