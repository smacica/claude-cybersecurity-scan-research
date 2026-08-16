# EatHub

Recipe sharing site. Express + SQLite API, Vue 3 frontend. Sign in with Google or
with an email address confirmed by a verification link.

```
claude_scan/
├── Auth_Recepie_Website/   express api (routes/, db.js, gemini.js, ai_quota.js)
│   └── shared/             code both sides import (ingredient emoji rules)
└── frontend/               vue 3 + vite app, builds into frontend/dist
```

The frontend is a sibling folder, not a subfolder. The Express side expects to find
it at `../frontend` relative to this project root.

`shared/ingredients.mjs` is written as ESM and used by both: Vite imports it through
the `@shared` alias, and the Express side reaches it with `require()`, which Node
supports for ESM. One copy of the emoji rules, no drift.

---

## AI recipe generation

Signed-in users can describe what is in the fridge and get a full recipe written,
checked and saved to their kitchen. It runs on the Gemini API's free tier.

### Getting a key

1. Go to <https://aistudio.google.com/apikey> and press **Create API key**.
2. Pick a Google Cloud project (or let it make one).
3. Copy the key into `.env`:

```dotenv
GEMINI_API_KEY=AIza…
GEMINI_MODEL=gemini-3.6-flash
```

Leave `GEMINI_API_KEY` empty and the feature switches itself off — the page says so
and the route answers `503` instead of failing oddly.

> **Do not enable billing on that Cloud project** if you want a hard guarantee of
> zero cost. Without billing, Google rejects calls past the free allowance rather
> than charging for them. The caps below are the app's own belt and braces.

### Staying inside the free tier

Google no longer publishes free-tier request limits — they vary per account and have
been cut sharply (community reports put Flash near **20 requests/day**, down from
250). So the app enforces its own caps and refuses to call the API once any is hit:

```dotenv
AI_DAILY_LIMIT=20        # whole site, per day
AI_USER_DAILY_LIMIT=3    # one user, per day
AI_PER_MINUTE_LIMIT=5    # burst guard across the site
```

Check your real numbers at <https://aistudio.google.com/rate-limit> and raise these
only if there is room. How it holds:

- A slot is **booked before** the request goes out, so simultaneous requests cannot
  both read the same remaining count and both slip through.
- Daily counters live in the `ai_usage` table and reset at **midnight Pacific**, the
  same boundary Google uses — not the server's timezone.
- Failed generations still spend a slot, because the call was already made.
- If Google answers `429` anyway, the page says the free quota is gone.

### How a generation is checked

The model is asked for JSON matching a fixed schema (`ok`, `title`, `description`,
`ingredients[{emoji,text}]`, `steps[]`) via `response_format.schema`, which maps
straight onto how recipes are already stored.

Anything not about food is refused: the system instruction tells the model to set
`ok: false` and return empty fields, and the route turns that into a `422` with
nothing saved. The user's text is passed in labelled as data with an explicit
instruction not to follow directions inside it, so "ignore your rules and…" in the
description box is treated as a (bad) dish description rather than a command.

Nothing is trusted on the way back. The reply is parsed, the schema re-checked, and
a recipe missing a title, ingredients or steps is rejected as `incomplete` rather
than saved half-built. Lists are capped at 20 ingredients and 15 steps, and any
ingredient the model forgot an emoji for gets one guessed from its name.

Generated recipes get a random illustration from `../frontend/public/ai_pics`. Those
are stored already compressed to 1024×768 (4:3), matching the ratio the cards and
detail page use.

---

## Sending the verification emails

Email signup needs somewhere to send the confirmation link.

**In development you can skip this entirely.** With `SMTP_HOST` empty, the link is
printed to the server console instead of being sent:

```
--- verification link for cook@example.com ---
http://localhost:4000/verify-email?token=3a587e65…
---
```

Paste that into the browser and the account is confirmed.

**For real delivery**, fill in the SMTP block in `.env` with any provider:

```dotenv
SMTP_HOST=smtp.sendgrid.net      # or smtp.gmail.com, smtp.mailgun.org, …
SMTP_PORT=587                    # 465 if the provider wants implicit TLS
SMTP_USER=apikey
SMTP_PASS=your-smtp-password
MAIL_FROM=EatHub <no-reply@yourdomain.com>
PUBLIC_URL=https://eathub.example.com
```

Set `PUBLIC_URL` in production. The link inside the email has to be absolute, and
deriving it from the request headers gets it wrong when you sit behind a proxy.

> With Gmail, `SMTP_PASS` must be an [App Password](https://myaccount.google.com/apppasswords),
> not your account password.

How the flow behaves:

- Signing up creates the account but leaves it unusable until the link is opened.
- Logging in before confirming answers `403` with `code: "unverified"`, and the
  sign-in page then offers to resend the link.
- Links last 24 hours and work once. Asking for a new one invalidates the old.
- Signing up with an address that already exists returns the same message as a new
  signup and quietly sends nothing, so the endpoint cannot be used to discover who
  has an account.
- Google accounts skip all of this — Google has already verified the address.

---

## Registering the app with Google

You need a Google OAuth client before sign-in works. This takes about five minutes.

### 1. Create a project

1. Go to <https://console.cloud.google.com/>.
2. Open the project dropdown in the top bar → **New project**.
3. Name it `EatHub` → **Create**, then make sure it is the selected project.

### 2. Configure the consent screen

1. Go to **APIs & Services → OAuth consent screen**.
2. Pick **External** (unless you have a Google Workspace and only want your own
   organisation to sign in) → **Create**.
3. Fill in the required fields:
   - **App name**: `EatHub`
   - **User support email**: your address
   - **Developer contact information**: your address
4. **Save and continue**.
5. On the **Scopes** step click **Add or remove scopes** and tick:
   - `.../auth/userinfo.email`
   - `.../auth/userinfo.profile`

   These are the only two the app uses. **Update** → **Save and continue**.
6. On the **Test users** step, add every Google account you want to sign in with
   while the app is still unpublished — including your own. **Save and continue**.

> While the app is in *Testing*, only the listed test users can sign in, and their
> sessions expire after 7 days. That is fine for development. To open it up to
> anyone, go back to the consent screen and press **Publish app**. An app that only
> asks for email and profile does not need Google's verification review.

### 3. Create the OAuth client

1. Go to **APIs & Services → Credentials → Create credentials → OAuth client ID**.
2. **Application type**: `Web application`.
3. **Name**: `EatHub web`.
4. Under **Authorised JavaScript origins** add:
   - `http://localhost:4000`
   - `http://localhost:5173` (only needed for the Vite dev server)
   - your production origin, e.g. `https://eathub.example.com`
5. Under **Authorised redirect URIs** add — these must match
   `GOOGLE_CALLBACK_URL` **exactly**, including scheme, port and trailing path:
   - `http://localhost:4000/auth/google/callback`
   - `https://eathub.example.com/auth/google/callback`
6. **Create**. Copy the **Client ID** and **Client secret**.

### 4. Put the credentials in `.env`

```bash
cp .env.example .env
```

```dotenv
GOOGLE_CLIENT_ID=1234567890-abcdefg.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-secret
GOOGLE_CALLBACK_URL=http://localhost:4000/auth/google/callback
CLIENT_URL=
SESSION_SECRET=paste-the-output-of-openssl-rand-hex-32
PORT=4000
```

`SESSION_SECRET` — generate one with:

```bash
openssl rand -hex 32
```

`.env` is gitignored. Never commit the client secret.

### 5. In production

Set the same variables in your host's environment (on DigitalOcean: App → Settings
→ App-Level Environment Variables) with the production values:

```dotenv
GOOGLE_CALLBACK_URL=https://eathub.example.com/auth/google/callback
CLIENT_URL=
NODE_ENV=production
```

Leave `CLIENT_URL` empty in production — the API serves the built Vue app from the
same origin. `NODE_ENV=production` turns on the `Secure` flag for the session
cookie, so the site must be served over HTTPS.

### Common errors

| Message | Cause |
| --- | --- |
| `redirect_uri_mismatch` | The URI in **Credentials** is not character-for-character equal to `GOOGLE_CALLBACK_URL`. Check `http` vs `https`, the port, and the trailing `/callback`. |
| `access_blocked: EatHub has not completed the Google verification process` | The account is not in **Test users** and the app is unpublished. |
| `invalid_client` | Wrong `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`, or `.env` was not loaded — restart the server after editing it. |
| Signed in, but bounced straight back to `/signin` | The session cookie was rejected. In production check `NODE_ENV=production` **and** HTTPS; in dev check `CLIENT_URL=http://localhost:5173`. |

---

## Running it

### Development (two processes, hot reload)

```bash
npm install
npm run dev                       # api on http://localhost:4000
```

```bash
cd ../frontend
npm install
npm run dev                       # ui on http://localhost:5173
```

Set `CLIENT_URL=http://localhost:5173` in `.env` so Google sends you back to the
Vite server after signing in. Vite proxies the API routes through to port 4000.

### Production (one process)

```bash
npm install
npm run build                     # builds ../frontend/dist
npm start                         # serves the api and the built ui on :4000
```

---

## Logging

The backend writes newline-delimited JSON to stdout. Nothing is written to disk,
because the App Platform filesystem is ephemeral — DigitalOcean captures stdout
into the runtime log console.

In development the `dev` script pipes through `pino-pretty` for readable output:

```bash
npm run dev
```

`npm start` leaves the output as raw JSON, which is what you want in production.

Each completed request logs one line:

```json
{"level":30,"time":1755100000000,"env":"production","pid":30213,"reqId":"…","method":"GET",
 "path":"/api/recipes/42","status":200,"durationMs":14,"userId":7,
 "ip":"203.0.113.9","ua":"Mozilla/5.0 …","msg":"request"}
```

2xx and 3xx log at `info`, 4xx at `warn`, 5xx at `error`, so `level>=40` finds
everything that went wrong. Requests for the built frontend bundle and the AI
artwork are not logged.

**Bodies and query strings are never logged, and of all the request headers only
`User-Agent` is.** The serializer names the handful of fields it keeps rather
than the ones it drops, so no body, no query-string value, and no header beyond
that one allowlisted `User-Agent` can reach a log line — which is what keeps
passwords, the `/verify-email` token and the `connect.sid` cookie out.

Errors logged inside a route share their `reqId` with the request line, so
grepping one id gives the request and everything that happened during it. Those
in-route lines carry only `reqId`, with no `userId` field at all; the request
line is the one that carries the user id.

Security-relevant actions log an `event` field: `sign_in`, `sign_in_failed`,
`sign_up`, `email_verified`, `logout`, `recipe_created`, `recipe_deleted`,
`delete_denied`, `ai_generated`, `ai_quota_denied`, `ai_rejected`. The AI three
are worth watching — they show when the Gemini free-tier guard is being hit.

Set `LOG_LEVEL` to change verbosity. It defaults to `info` in production and
`debug` elsewhere.

## Auth notes

- Two ways in: Google, or an email address plus a password of at least 8 characters
  confirmed by a verification link. Passwords are stored as bcrypt hashes.
- `users.google_id` identifies a Google account. If a Google email matches a row
  that already existed, that row is linked instead of a duplicate being created,
  and it counts as verified from then on.
- Wrong password and unknown address give the same `401` and the same wording, so
  the login route cannot be used to enumerate accounts.
- On first start, `db.js` migrates an older database: it adds `google_id`,
  `email_verified` and a nullable `password`, creates the `email_tokens` and
  `comments` tables, and marks existing Google accounts verified. Password hashes
  from the original schema are not carried over — those accounts sign in with
  Google, or sign up again with the same address.
- Sessions live in the same SQLite file; the cookie lasts a week.

## API

The JSON API lives under `/api`, which keeps it clear of the Vue router — the app
owns `/recipe/:id` as a page, the API owns `/api/recipes/:id` as data. Three paths
stay outside `/api` on purpose: `/auth/google*` is registered in the Google console,
`/verify-email` is already sitting in people's inboxes, and `/data/recipes_pics/…`
is stored in the `photo` column of existing rows.

| Method | Route | Auth | |
| --- | --- | --- | --- |
| POST | `/api/signup` | – | Body `{ email, password }`. Sends the confirmation link. |
| POST | `/api/login` | – | Body `{ email, password }`. `403` + `code: "unverified"` if unconfirmed. |
| GET | `/verify-email?token=` | – | Opened from the email, redirects to `/signin?verify=…`. |
| POST | `/api/resend-verification` | – | Body `{ email }`. |
| GET | `/auth/google` | – | Starts sign-in. Takes `?next=/path` to return to. |
| GET | `/auth/google/callback` | – | Google redirects here. |
| GET | `/api/profile` | ✔ | Current user. |
| POST | `/api/logout` | – | Destroys the session. |
| GET | `/api/recipes` | – | All recipes, most liked first. |
| POST | `/api/recipes` | ✔ | Multipart: `name`, `info`, `image`, and `recipe` / `ingredients` as JSON arrays. |
| POST | `/api/recipes/generate` | ✔ | Body `{ ingredients, description }`. Writes and saves a recipe. `422` if it is not a food request. |
| GET | `/api/ai/quota` | ✔ | Generations left today. |
| GET | `/api/recipes/mine` | ✔ | Recipes you posted. |
| GET | `/api/recipes/:id` | – | One recipe. |
| DELETE | `/api/recipes/:id` | ✔ | Author only. Removes the photo and cascades likes and comments. |
| POST | `/api/recipes/:id/like` | ✔ | Body `{ "like": 1 }` or `{ "like": 0 }`. |
| GET | `/api/recipes/:id/comments` | – | Newest first, with author name and picture. |
| POST | `/api/recipes/:id/comments` | ✔ | Body `{ body }`, up to 1000 characters. |
| DELETE | `/api/comments/:comment_id` | ✔ | The comment's author or the recipe's author. |
| GET | `/data/recipes_pics/:file` | – | Uploaded photos. |

Protected routes answer `401` with `{ "message": "you are not signed in" }`, and an
unknown `/api` path answers `404` JSON rather than the HTML shell.
