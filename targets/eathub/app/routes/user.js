const express = require('express');
const passport = require('passport');
const router = express.Router()
const { isLoggedIn, addLikesToUser } = require('../google_strategy')
const { hashPassword, issueVerificationEmail } = require('../local_strategy')
const { dbCreateLocalUser, dbFindByEmail, dbConsumeEmailToken } = require('../db')
const { audit } = require('../audit')

//in dev the vue app runs on :5173, in prod it is served from this same origin
const clientUrl = process.env.CLIENT_URL || ''

//never send the browser to an address someone put in the query string
function safeNext(value){
    return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') ? value : '/'
}

//the verification link has to be absolute, it is opened from a mail client
function baseUrl(req){
    return process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`
}

function looksLikeEmail(value){
    return typeof value === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
}

router.get('/api/auth', isLoggedIn, function(req, res) {
    res.json({message: 'you are authorized'});
});

/* ---------- email + password ---------- */

router.post('/api/signup', async function(req, res){
    const email = String(req.body.email || '').trim()
    const password = String(req.body.password || '')

    if(!looksLikeEmail(email)){
        return res.status(400).json({message: "That does not look like an email address."})
    }
    if(password.length < 8){
        return res.status(400).json({message: "Use at least 8 characters for the password."})
    }

    try{
        const user = await dbCreateLocalUser({
            email,
            password: await hashPassword(password),
            username: req.body.username
        })

        //an address that is already taken gets the same answer as a new one, so this
        //route cannot be used to find out who has an account. the owner just gets no mail.
        if(user){
            const { delivered } = await issueVerificationEmail(user, baseUrl(req))
            audit.signUp(req.log, { userId: user.user_id })
            return res.status(201).json({
                message: "Check your inbox for the confirmation link.",
                //lets the dev setup say "look in the server console" instead
                delivered
            })
        }
        return res.status(201).json({message: "Check your inbox for the confirmation link.", delivered: true})
    }catch(err){
        req.log.error({ err }, 'could not create the account')
        res.status(500).json({message: "Could not create the account."})
    }
})

router.post('/api/login', function(req, res, next){
    passport.authenticate('local', function(err, user, info){
        if(err){
            return next(err)
        }
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
            addLikesToUser(user).then(user_object=>{
                res.json(user_object)
            }).catch(err=>{
                req.log.error({ err }, 'signed in but could not load the profile')
                res.status(500).json({message: "Signed in, but could not load the profile."})
            })
        })
    })(req, res, next)
})

//opened from the email client, so it redirects into the app rather than answering json
router.get('/verify-email', async function(req, res){
    try{
        const result = await dbConsumeEmailToken(String(req.query.token || ''))

        if(!result){
            return res.redirect(`${clientUrl}/signin?verify=invalid`)
        }
        if(result.expired){
            return res.redirect(`${clientUrl}/signin?verify=expired`)
        }
        audit.emailVerified(req.log, { userId: result.user_id })
        res.redirect(`${clientUrl}/signin?verify=ok`)
    }catch(err){
        req.log.error({ err }, 'could not consume the verification token')
        res.redirect(`${clientUrl}/signin?verify=invalid`)
    }
})

router.post('/api/resend-verification', async function(req, res){
    const email = String(req.body.email || '').trim()

    try{
        const user = await dbFindByEmail(email)
        //again, never confirm whether the address is registered
        if(user && !user.email_verified){
            await issueVerificationEmail(user, baseUrl(req))
        }
        res.json({message: "If that address needs confirming, a new link is on its way."})
    }catch(err){
        req.log.error({ err }, 'could not resend the verification link')
        res.status(500).json({message: "Could not send the link."})
    }
})

/* ---------- google ---------- */

//step 1 - hand the browser over to google
router.get('/auth/google', function(req, res, next){
    //remember where the user wanted to go, google only gives us the callback back
    req.session.returnTo = safeNext(req.query.next)
    passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next)
});

//step 2 - google sends the browser back here with a code.
//this is a browser navigation, so every outcome has to end in a redirect. the plain
//failureRedirect option only covers a refused sign in, not an error thrown while
//exchanging the code, which used to surface as a raw 500 page.
router.get('/auth/google/callback', function(req, res, next){
    passport.authenticate('google', function(err, user){
        if(err || !user){
            req.log.warn({ err }, 'google sign in failed')
            audit.signInFailed(req.log, { ip: req.ip, reason: 'google' })
            return res.redirect(`${clientUrl}/signin?error=auth`)
        }
        req.login(user, function(err){
            if(err){
                req.log.warn({ err }, 'google sign in failed at login')
                return res.redirect(`${clientUrl}/signin?error=auth`)
            }
            const returnTo = safeNext(req.session.returnTo)
            delete req.session.returnTo
            audit.signIn(req.log, { userId: user.user_id, method: 'google' })
            res.redirect(clientUrl + returnTo)
        })
    })(req, res, next)
});

/* ---------- session ---------- */

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

router.get('/api/profile', isLoggedIn, function(req,res){
    addLikesToUser(req.user).then(user_object=>{
        res.json(user_object)
    }).catch(err=>{
        req.log.error({ err }, 'could not load the profile')
        res.status(500).json({message: "could not load the profile"})
    })
})

module.exports = router
