const { dbAiUsage, dbAiUsageIncrement } = require('./db')

//Google does not publish the free tier numbers any more and they differ per account,
//so these are deliberately low. Check your real limit at
//https://aistudio.google.com/rate-limit and raise them in .env if there is room.
const DAILY_LIMIT = Number(process.env.AI_DAILY_LIMIT || 20)
const USER_DAILY_LIMIT = Number(process.env.AI_USER_DAILY_LIMIT || 3)
const PER_MINUTE_LIMIT = Number(process.env.AI_PER_MINUTE_LIMIT || 5)

//the day the daily quota resets on. Google resets RPD at midnight Pacific,
//so count the same way rather than in whatever timezone the server sits in.
function quotaDay(now = new Date()){
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Los_Angeles',
    year: 'numeric', month: '2-digit', day: '2-digit'
  }).format(now)
}

//the per-minute cap only guards against bursts, so memory is enough for it
let minuteWindow = []

function minuteCallsLeft(now = Date.now()){
  minuteWindow = minuteWindow.filter(stamp => now - stamp < 60000)
  return PER_MINUTE_LIMIT - minuteWindow.length
}

//checks every cap and books the call in one step, so two requests arriving together
//cannot both look at the same remaining count and both go through
async function reserve(user_id){
  const day = quotaDay()

  if(minuteCallsLeft() <= 0){
    return { ok: false, reason: 'minute', message: 'Too many generations at once. Try again in a minute.' }
  }

  const usage = await dbAiUsage(day, user_id)

  if(usage.total >= DAILY_LIMIT){
    return {
      ok: false,
      reason: 'daily',
      message: 'EatHub has used up its free AI generations for today. It resets at midnight Pacific.'
    }
  }
  if(usage.user >= USER_DAILY_LIMIT){
    return {
      ok: false,
      reason: 'user-daily',
      message: `You have used your ${USER_DAILY_LIMIT} AI generations for today.`
    }
  }

  minuteWindow.push(Date.now())
  await dbAiUsageIncrement(day, user_id)

  return {
    ok: true,
    remaining: {
      user: USER_DAILY_LIMIT - usage.user - 1,
      total: DAILY_LIMIT - usage.total - 1
    }
  }
}

//what is left without booking anything, for showing the counter in the ui
async function peek(user_id){
  const usage = await dbAiUsage(quotaDay(), user_id)
  return {
    user: Math.max(0, USER_DAILY_LIMIT - usage.user),
    total: Math.max(0, DAILY_LIMIT - usage.total),
    userLimit: USER_DAILY_LIMIT
  }
}

module.exports = { reserve, peek, quotaDay, limits: { DAILY_LIMIT, USER_DAILY_LIMIT, PER_MINUTE_LIMIT } }
