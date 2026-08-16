const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { dbFindByEmail, dbCreateEmailToken } = require('./db')
const { sendVerificationEmail } = require('./mailer')
const { logger } = require('./logger')

const TOKEN_LIFETIME = 24 * 60 * 60 * 1000 // a day

const hashPassword = password => bcrypt.hash(password, 10)

//signs in with the email address, there is no separate username to remember
const strategy = new LocalStrategy(
  { usernameField: "email", passwordField: "password" },
  async function (email, password, done) {
    try {
      const user = await dbFindByEmail(email)

      //same answer whether the address is unknown or the password is wrong,
      //otherwise this endpoint tells strangers which addresses have accounts
      if (!user || !user.password) {
        return done(null, false, { message: "Wrong email or password." })
      }

      const isMatch = await bcrypt.compare(password, user.password)
      if (!isMatch) {
        return done(null, false, { message: "Wrong email or password." })
      }

      if (!user.email_verified) {
        return done(null, false, { code: "unverified", message: "Confirm your email address first." })
      }

      return done(null, user)
    } catch (err) {
      logger.error({ err }, 'local sign in failed')
      return done(err)
    }
  }
)

//builds a fresh token, stores it and mails the link out
async function issueVerificationEmail(user, baseUrl) {
  const token = crypto.randomBytes(32).toString('hex')
  await dbCreateEmailToken(user.user_id, token, Date.now() + TOKEN_LIFETIME)
  const link = `${baseUrl}/verify-email?token=${token}`
  return sendVerificationEmail(user.email, link)
}

module.exports = { strategy, hashPassword, issueVerificationEmail }
