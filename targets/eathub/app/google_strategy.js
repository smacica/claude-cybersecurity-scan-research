const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { dbFind, dbFindOrCreateGoogleUser } = require('./db')
const { logger } = require('./logger')

//where google sends the browser back to - must match the redirect uri
//registered in the google cloud console, character for character
const callbackURL = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:4000/auth/google/callback'

if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
  logger.warn('GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are missing, sign in will fail. See README.md')
}

const strategy = new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID || 'missing-client-id',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'missing-client-secret',
    callbackURL,
    scope: ['profile', 'email']
  },
  async function (accessToken, refreshToken, profile, done) {
    try {
      const user = await dbFindOrCreateGoogleUser({
        google_id: profile.id,
        username: profile.displayName,
        email: profile.emails?.[0]?.value || null,
        profile_pic: profile.photos?.[0]?.value || null
      })
      return done(null, user)
    } catch (err) {
      logger.error({ err }, 'could not find or create the google user')
      return done(err)
    }
  }
)

//the vue app calls these as an api, so answer with a status it can act on
//instead of redirecting into the html shell
function isLoggedIn(request, response, done) {
  if (request.user) {
    return done();
  }
  return response.status(401).json({ message: "you are not signed in" })
}

function addLikesToUser(user) {
  return new Promise((resolve, reject) => {
    dbFind('likes', 'user_id', user.user_id, false, false, 'all').then(givenLikes => {
      resolve({
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        profile_pic: user.profile_pic,
        bio: user.bio,
        likes: givenLikes
      })
    }).catch(err => { reject(new Error(err)) })
  })
}

module.exports = { strategy, isLoggedIn, addLikesToUser }
