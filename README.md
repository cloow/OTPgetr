# OTPgetr — Gmail Verification Code Grabber

It watches your Gmail, and the moment a **new** verification
code arrives, it copies the code to your clipboard and shows a green
**PASTE ME!** popup near your cursor for 5 seconds (it disappears on its own).
You just **Ctrl+V** (and Enter) into the field. Works for codes in email
**text** and codes inside
**images**. No need to open Gmail.

Phone SMS codes work too: forward the text to this Gmail with the subject
**`smsotp`** (via MacroDroid or an Apple Shortcut) and it flows through the same
pipeline.  (coming soon)

## Why this is safe
- Uses Google's official Gmail API only to read your recent messages. The script
  can never send, delete, or change anything.
- Login happens once in **your default browser (Chrome)** — you're already
  signed in, so it's one click. Your password never touches the script.
- Revoke access anytime: https://myaccount.google.com/permissions

## Setup (about 5 minutes, one time)

### 1. Install Python packages
```
pip install -r requirements.txt
```

### 2. Get your Google API credentials (credentials.json)
1. Go to https://console.cloud.google.com/ and create a project (any name).
2. Find **Gmail API** → **Enable**.
3. **APIs & Services → OAuth consent screen** → **External** → fill in app name
   and your email → save. Add your own Gmail address as a **Test user**.
4. **APIs & Services → Credentials → Create Credentials → OAuth client ID** →
   Application type: **Desktop app** → Create.
5. **Download JSON**, rename it to `credentials.json`, and put it in this folder
   next to `OTPgetr.py`.

> **Heads-up:** while the app stays in "testing" mode, Google expires the login
> token after **7 days**, so every so often you'll re-do the one-click browser
> login. That's normal — nothing broke.

### 3. (For image-based codes) Add your Anthropic API key
Some companies put codes inside images. The script sends just those images to
Claude (Haiku), which reads them in about a second (a fraction of a cent each).
Claude is also a fallback when a text email is formatted so oddly the normal
pattern-matching misses the code. Plain-text codes are extracted **locally
first** (instant, free) — the API is only called when an email actually looks
like an OTP, never on ordinary mail.

1. Create a key at https://platform.claude.com (a few dollars of credit lasts a
   very long time at this usage).
2. Save it in `api_key.txt` in this folder (just the key), or set the
   `ANTHROPIC_API_KEY` environment variable.

### 4. Run it
```
python OTPgetr.py
```
First run: your default browser opens, pick your Google account, click Allow. A
`token.json` is saved so you don't log in again. Leave the window running.

While running:
- **NUMPAD `*`** — force an immediate check now (optional)
- **CTRL + NUMPAD `*`** — quit
- **CTRL + ALT + K** — add, change, or turn off your Anthropic API key
- **CTRL + ALT + R** — reconnect Gmail | **CTRL + ALT + B** — block the last code

## Tweaks (top of OTPgetr.py)
- `POPUP_SECONDS` — popup duration (default 5)
- `POPUP_AT_CURSOR` — `True` = near cursor, `False` = top-center
- `LOOKBACK_MINUTES` — how far back a "new" email can be (default 5)
- `POLL_SECONDS` — how often Gmail is checked (default 4)
- `SMS_SUBJECT` — the subject that marks a forwarded phone SMS (default `smsotp`)

## How it decides what's a code
- **Forwarded SMS** (subject `smsotp`) is trusted, so even a bare number counts.
- **Ordinary mail** must have a real keyword ("code", "verification", "OTP",
  etc.) near the digits, so random 6-digit numbers (order IDs, prices) don't
  false-trigger.
- Only emails that **arrive after startup** are processed — existing inbox codes
  are ignored (baseline taken on launch).

## Notes
- Keep `credentials.json`, `token.json`, and `api_key.txt` private.
- If no code is found nothing pops; a red popup only appears on an actual error.
- Activity is logged to `otpgetr.log` (auto-rotates, never fills your disk).
