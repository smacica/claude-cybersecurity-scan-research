const { logger } = require('./logger')

//audit lines are the ones that get filtered on later, so every event name is
//defined exactly once here. a query for event:"sign_in_failed" only works if
//nothing else in the codebase spells it differently.
function event(name, level = 'info'){
  return function(log, fields = {}){
    const target = log || logger
    target[level]({ event: name, ...fields }, name)
  }
}

const audit = {
  signIn:         event('sign_in'),
  signInFailed:   event('sign_in_failed', 'warn'),
  signUp:         event('sign_up'),
  emailVerified:  event('email_verified'),
  logout:         event('logout'),
  recipeCreated:  event('recipe_created'),
  recipeDeleted:  event('recipe_deleted'),
  deleteDenied:   event('delete_denied', 'warn'),
  aiGenerated:    event('ai_generated'),
  aiQuotaDenied:  event('ai_quota_denied', 'warn'),
  aiRejected:     event('ai_rejected', 'warn')
}

module.exports = { audit }
