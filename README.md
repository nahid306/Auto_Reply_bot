# Messenger "Seen" Auto-Reply Bot

A small Node.js app that connects a **Facebook Page** to the official Meta Messenger Platform. When a person
reads a message your Page sent, the bot replies once with a configurable text (default: `Hi`). It includes a
dashboard to connect Pages, choose recipients, pause the bot and read logs.

> Uses only official Meta APIs and webhooks. No browser automation, no scraping, no unofficial access.

## Features
- Connect a Page through Facebook Login (for Business)
- Real-time `message_reads` and `messages` webhooks, with signature verification
- Duplicate protection (one reply per read event) and a per-recipient cooldown that prevents reply loops
- Page tokens encrypted at rest with AES-256-GCM
- Retries with backoff for network, 5xx and rate-limit errors
- Dashboard: enable or disable the bot, manage recipients, view activity logs

## Important limits (set by Meta, not by this app)
- **Pages only.** The Messenger Platform works with Facebook Pages. It cannot send messages from, or read
  read-receipts for, a personal Messenger account. Messages arrive from the Page's name.
- **"Seen" means the person read a message your Page sent.**
- **24-hour window.** The bot can reply only within 24 hours of the person's last message to the Page. Otherwise
  it logs a skip. Meta's supported options beyond that are One-Time Notifications and opt-in Marketing Messages.
  Check the current Messenger Platform policy before using message tags.
- **No contact list.** Apps cannot list people; a recipient appears after they message the Page.
- **Development mode.** Until your app passes App Review for `pages_messaging`, only people with a role on the
  app (admin, developer, tester) can use it.

## Requirements
- Node.js **22.13 or newer** (24 recommended). SQLite is built in (`node:sqlite`), so there is nothing to compile.
- A Facebook Page you manage
- A Meta developer app (type Business) with **Messenger** and **Facebook Login for Business**
- A public HTTPS URL (a tunnel such as Cloudflare Tunnel or ngrok works for local testing)

## Project structure
```
src/server.js      Express server: OAuth, webhook, bot logic, dashboard API
public/index.html  Dashboard
.env.example       Configuration template
```

## Setup

### 1. Install
```bash
git clone <your-repo-url>
cd <repo-folder>
npm install
cp .env.example .env        # Windows: copy .env.example .env
```

### 2. Generate secrets
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"   # TOKEN_ENC_KEY
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"      # SESSION_SECRET
```
Put each value in `.env`. Keep `TOKEN_ENC_KEY` safe: if you lose it, stored Page tokens cannot be decrypted and
you will need to reconnect.

### 3. Configure `.env`
| Variable | Value |
|---|---|
| `APP_ID`, `APP_SECRET` | Meta app → App settings → Basic |
| `VERIFY_TOKEN` | Any random string you choose; also enter it in the Meta webhook form |
| `BASE_URL` | Your public HTTPS URL, no trailing slash |
| `TOKEN_ENC_KEY`, `SESSION_SECRET` | From step 2 |
| `FB_CONFIG_ID` | Configuration ID (Facebook Login for Business), if you use it |
| `GRAPH_VERSION` | Graph API version; check Meta's changelog for supported versions |

### 4. Start a public tunnel
```bash
cloudflared tunnel --url http://localhost:3000
# or: ngrok http 3000
```
Copy the `https://...` URL into `BASE_URL`. Free tunnel URLs change on every restart; when that happens, update
`BASE_URL`, the Meta redirect URI and the webhook URL, then restart the server.

### 5. Configure the Meta app
1. **Facebook Login for Business → Settings**: add `BASE_URL/auth/callback` to *Valid OAuth Redirect URIs* and save.
2. **Facebook Login for Business → Configurations**: create a configuration with the permissions
   `pages_show_list`, `pages_messaging`, `pages_manage_metadata`. Copy its ID into `FB_CONFIG_ID`.
3. **Messenger → API settings → Configure webhooks**: callback URL `BASE_URL/webhook`, your `VERIFY_TOKEN`.
   Subscribe to `messages` and `message_reads`. The server must be running when you click *Verify and save*.
4. **App roles**: add any test accounts as Testers while the app is in Development mode.

### 6. Run
```bash
npm start
```
Open `BASE_URL` in your browser (not `localhost`, because the login cookie is tied to the domain).

## Using it
1. Click **Connect Facebook**, choose your Page and allow the permissions.
2. From a tester account, send your Page a message.
3. In the dashboard, pick that person under **Recipients**, set the message and cooldown, then **Save recipient**.
4. Click **Enable bot** on the Page.
5. Reply to the person from the Page inbox. When they read it, the bot sends the configured message.
6. Check **Activity** for `Sent`, `Skipped` or error lines.

## How it works
- **Dedupe:** each event is stored as `page:person:watermark`; redeliveries are ignored.
- **Loop guard:** the person reading the bot's own reply triggers another read event. A per-recipient cooldown
  (default 24 h) is claimed atomically before sending and released if the send fails.
- **Errors:** transient failures are retried; token errors (code 190) mark the Page as needing reconnection.
- **Security:** webhook signatures (`X-Hub-Signature-256`) verified, `appsecret_proof` on Graph calls, HMAC-signed
  session cookie, custom header required for state-changing API calls.

## Troubleshooting
| Problem | Fix |
|---|---|
| `Missing env var ...` | A value in `.env` is empty, or `.env` is not saved |
| Webhook verification fails | Server not running, tunnel down, or `VERIFY_TOKEN` differs from `.env` |
| `Login failed: invalid state` | Start from the `BASE_URL` address, not `localhost`; don't refresh the callback page |
| `Error validating client secret` | `APP_SECRET` is wrong; copy it again from App settings → Basic |
| `No Pages found` | Tick the Page in the login dialog; the account needs full Page access |
| No reply sent | Read the Activity log: usually the 24-hour window or the cooldown |

## Deploying
Run behind HTTPS on a host that keeps the process alive (a VPS, Render, Railway, Fly.io), with a persistent disk for
`bot.db`, and set `BASE_URL` to the real domain. Going live for the public needs Meta App Review, a privacy policy
URL and a data-deletion URL.

## Security notes
- Never commit `.env` or `bot.db`; both are in `.gitignore`.
- If a secret leaks, reset the App Secret in the Meta dashboard and generate a new `TOKEN_ENC_KEY` and `SESSION_SECRET`.

## License
Add a license of your choice (for example MIT) before publishing.
