const nodemailer = require('nodemailer')
const { logger } = require('./logger')

const from = process.env.MAIL_FROM || 'EatHub <no-reply@eathub.local>'
const configured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS)

if (!configured) {
  logger.warn('SMTP_* are not set, verification links will be printed to this console instead of emailed. See README.md')
}

const transport = configured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      //port 465 speaks TLS from the first byte, 587 upgrades with STARTTLS
      secure: Number(process.env.SMTP_PORT || 587) === 465,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    })
  : null

function verificationEmail(link) {
  return {
    subject: 'Confirm your EatHub address',
    text: `Welcome to EatHub.\n\nConfirm your email address by opening this link:\n${link}\n\nThe link is good for 24 hours. If you did not sign up, ignore this message.`,
    html: `<p>Welcome to EatHub.</p>
<p>Confirm your email address:</p>
<p><a href="${link}" style="background:#d2551e;color:#fff;padding:12px 22px;border-radius:999px;text-decoration:none;font-family:sans-serif">Confirm my address</a></p>
<p style="color:#6b5647;font-family:sans-serif;font-size:13px">The link is good for 24 hours. If you did not sign up, ignore this message.</p>`
  }
}

async function sendVerificationEmail(to, link) {
  const message = verificationEmail(link)

  //without smtp credentials there is nowhere to send, so make the link usable anyway
  if (!transport) {
    //deliberately console.log and not the logger: this is the dev fallback for a
    //missing smtp setup and has to stay readable and unfilterable
    console.log(`\n--- verification link for ${to} ---\n${link}\n---\n`)
    return { delivered: false }
  }

  await transport.sendMail({ from, to, ...message })
  return { delivered: true }
}

module.exports = { sendVerificationEmail, mailConfigured: configured }
