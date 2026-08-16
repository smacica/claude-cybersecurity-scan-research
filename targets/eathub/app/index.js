require('dotenv').config()
const express = require('express');
var cors = require('cors')
const session = require('express-session')
const passport = require('passport')
const {strategy: googleStrategy} = require('./google_strategy')
const {strategy: localStrategy} = require('./local_strategy')
const app = express();
const {dbFind} = require('./db')
const {sessionConf} = require('./session_config')
const bodyParser = require('body-parser');
const path = require('path');
const { logger } = require('./logger')
const { requestLog } = require('./request_log')
//routes
const user = require('./routes/user')
const recipe = require('./routes/recipe')

//vite writes the vue app here, `npm run build` inside ../frontend/
const clientDir = path.join(__dirname, '..', 'frontend', 'dist')
//in dev the vue app runs on its own port, in prod it is served from clientDir
const clientUrl = process.env.CLIENT_URL || ''

passport.use(googleStrategy)
passport.use(localStrategy)
passport.serializeUser((user, done) => {
  done(null, user.user_id);
});
passport.deserializeUser((id, done) => {
  dbFind('users', 'user_id', id)
  .then(user => done(null, user))
  .catch(err => {
    logger.error({ err }, 'could not deserialize the session user')
    done(err)
  })});

//app platform terminates tls in front of us, so req.ip is the proxy without this.
//it also makes req.secure/req.protocol reflect the original scheme, which is what
//lets session_config set the production cookie and makes emailed verification links https
app.set('trust proxy', 1)

//middleware
app.use(cors({ origin: clientUrl || true, credentials: true }))
app.options('*', cors({ origin: clientUrl || true, credentials: true }));
//before session and passport on purpose - a failure in either still gets logged
app.use(requestLog);
app.use(session(sessionConf));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(clientDir));
app.use('/',user)
app.use('/',recipe)

//an unknown /api path is a mistake, not a page - never answer it with the html shell
app.use('/api', function(req, res) {
  res.status(404).json({ message: 'no such endpoint' });
});

//vue router owns the rest of the urls, so everything else gets index.html
app.get('*', function(req, res) {
  res.sendFile(path.join(clientDir, 'index.html'));
});

//registered last so it catches whatever the routes above threw, rather than the
//request hanging or falling through to the html shell
app.use(function(err, req, res, next) {
  //req.log carries the reqId, so this line can be matched to its request
  req.log.error({ err }, 'unhandled error');
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ message: 'something went wrong' });
});

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
