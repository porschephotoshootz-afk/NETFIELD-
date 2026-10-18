# Toolkit signup Worker

Planned URL: `https://toolkit-signup.starswarm.workers.dev`

This Worker takes Pro email signups for StarSwarm Security Agentic Toolkit. A signup record is `signup:<email>` and the value is `{ ts, source: "toolkit-pro" }`. The record does not include an IP address. Short-lived rate-limit counters use a hash of the address and expire after 10 minutes.

Nothing in this folder is deployed by the app change. The owner deploys it from the Cloudflare account `starswarm` on the workers.dev free plan.

## Before it can go live

1. The KV namespace `toolkit-signup-kv` exists and its id is already in `wrangler.toml`. For a fresh account, create one and replace the id:

   ```sh
   npx wrangler kv namespace create SIGNUPS
   ```

2. Set the export secret. Wrangler prompts for the value. Do not pass it on the command line and do not commit it:

   ```sh
   npx wrangler secret put EXPORT_TOKEN
   ```

3. Optional. Create a free Turnstile widget for `porschephotoshootz-afk.github.io`, then:

   ```sh
   npx wrangler secret put TURNSTILE_SECRET
   ```

   Put the site key in `js/config.js` as `TURNSTILE_SITE_KEY`. Leave that string empty to skip the widget. If `TURNSTILE_SECRET` is unset, the Worker relies on the honeypot and the rate limit.

4. Deploy:

   ```sh
   npx wrangler deploy
   ```

5. Set `SIGNUP_URL` in `js/config.js` to `https://toolkit-signup.starswarm.workers.dev/api/signup`. While that string is empty, the Pro tab says signups open soon and does not show the form.

## Endpoints

`POST /api/signup` accepts JSON or form data with `email` and `company`. `company` is a honeypot. A filled honeypot returns 200 and stores nothing. The email is trimmed and lowercased. Sending the same email again returns 200 and keeps the original timestamp. Browsers must send `Origin: https://porschephotoshootz-afk.github.io`.

`GET /api/export?format=csv` returns `email,timestamp` rows. It requires `Authorization: Bearer <EXPORT_TOKEN>`. There is no public list.

```sh
curl -sS -H "Authorization: Bearer $EXPORT_TOKEN" "https://toolkit-signup.starswarm.workers.dev/api/export?format=csv"
```

## Free KV

The workers.dev free plan allows about 1,000 KV writes per day. Each new signup writes the record and a rate-limit counter, so the practical daily signup count is lower than 1,000. Duplicate signups do not rewrite the original record.
