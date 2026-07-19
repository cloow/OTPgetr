---
id: 01-otpgetr
title: OTPgetr — Gmail Verification Code Grabber
edition: MDD
depends_on: []
relates: []
source_files:
  - OTPgetr.py
  - spam_review.py
routes: []
models: []
test_files: []
data_flow: reads-existing
last_synced: 2026-07-19
status: draft
phase: reverse-engineered
mdd_version: 11
tags: [otp, gmail, gmail-api, oauth, clipboard, ocr, anthropic, hotkeys, windows, spam-review]
path: Tools/OTPgetr
integration_contracts: []
satisfies_contracts: []
security_read_sites: []
known_issues:
  - "Testing-mode OAuth: Gmail token expires every 7 days, requiring a re-auth (browser re-login)."
  - "RESOLVED 2026-07-19: removed OTPgetr_personal.py (hardcoded key). Key now comes from the ANTHROPIC_API_KEY env var (User scope) or the optional api_key.txt paste — no secret in source."
  - "OCR/vision path depends on optional deps (Windows OCR + anthropic); cloud fallback silently disables if 'anthropic' package is missing."
  - "Spam-review (spam_review.py) adds a Claude API call per copied candidate while CLAUDE_REVIEW_ENABLED=True. It is a temporary quality gate; set the flag False (or remove the import) to revert. Fail-open: an API outage lets codes through unreviewed."
---

# OTPgetr — Gmail Verification Code Grabber

> ⚠️ Reverse-engineered doc — "Purpose" and business intent are inferred from
> code + README. Review before treating as source of truth.

## Purpose

A local Windows desktop utility that watches a Gmail inbox and, the moment a
**new** verification code (OTP) arrives, extracts the code, copies it to the
clipboard, and shows a green **"PASTE ME!"** popup near the cursor for a few
seconds. The user just presses Ctrl+V — no need to open Gmail. Handles codes in
email **text** and in **images**, plus forwarded phone SMS codes (subject
`smsotp`).

## Architecture

Single-process Python app, multi-threaded:

- **Poller / Listener** (`Listener` class) — polls Gmail every `POLL_SECONDS`
  (default 4s) via the Gmail API, scanning the newest `MAX_EMAILS_TO_SCAN`
  messages within `LOOKBACK_MINUTES`. Only emails arriving **after startup** are
  processed (a baseline is taken on launch), so existing inbox codes are ignored.
  Scan scope is `SCAN_SCOPE` (config). Currently `"in:anywhere"` (Inbox + all
  tabs + Spam + Trash) — temporarily scanning everything to gather promo/spam
  data for the filters. Set to `"in:anywhere -in:trash"` to stop reading Trash.
  Promo codes that live in Spam/Trash are caught by the spam-review gate.
- **Popup UI** (`PopupApp`, tkinter) — renders the transient "PASTE ME!" popup at
  the cursor (`POPUP_AT_CURSOR`) or top-center; auto-dismisses after
  `POPUP_SECONDS`. Red popup only on actual error.
- **Hotkeys** (`keyboard`) — NUMPAD `*` forces an immediate check; `ctrl+alt+r`
  re-auths Gmail on demand; `ctrl+alt+b` blocklists the last copied code;
  `ctrl+alt+k` opens the API-key setup window (add / change / turn off);
  `ctrl+alt+`NUMPAD `3` opens the live log viewer; Ctrl+NUMPAD `*` quits.
- **Log viewer** (`LogViewer`, tkinter) — a dark, read-only "console" window
  that true-tails `otpgetr.log` (appends new lines only, colour-coded, auto-scroll
  unless scrolled up) and prints a dim `waiting.. HH:MM` liveness tick every 60s.
  Polls are silent (no per-4s line). Lets the user see activity without a
  terminal, since the app runs windowless. Opened via Ctrl+Alt+NUMPAD 3; single
  instance.
- **Single-instance guard** — binds localhost port `SINGLE_INSTANCE_PORT`
  (49731) so a second copy can't run.
- **Logging** — rotating file log (`otpgetr.log`, `LOG_FILE_MB` cap,
  `LOG_BACKUPS` kept) plus periodic heartbeat every `HEARTBEAT_MINUTES`.

## Auth (Google OAuth)

- **Scope:** `gmail.readonly` only — the app can read recent messages but can
  never send, delete, or modify anything.
- **Flow:** `InstalledAppFlow` desktop/loopback login in the default browser;
  token cached to `token.json`, creation time tracked in `token_meta.json`.
- **Token lifecycle:** silent refresh when possible; `TOKEN_EXPIRY_DAYS = 7`
  (testing-mode limit), with a re-auth nudge starting `REAUTH_WARN_HOURS` before
  expiry. `TokenExpired` raised when re-login is required.
- **credentials.json** — the OAuth client (Desktop app) downloaded from Google
  Cloud; kept next to the script. `LOGIN_HINT_EMAIL` (blank by default) can
  pre-fill the account chooser if set.

## Code-detection logic

Two-stage, local-first:

1. **Local text extraction (instant, free):** regex over the email text.
   - `_CODE_TOKEN` — 4–8 digit runs, or 5–8 char uppercase alphanumeric
     containing a digit.
   - `_KEYWORD` — requires a real OTP keyword ("code", "verification", "verify",
     "otp", "one-time", "passcode", "pin", "2fa") near the digits for **ordinary
     mail**, so order IDs / prices don't false-trigger.
   - Split-code handling (`SPLIT_RE`, e.g. `123 456`) and bare-number handling
     (`BARE_RE`) — bare numbers only trusted for forwarded SMS (`smsotp`).
2. **Image / vision fallback (only when needed):**
   - **Windows OCR** (`windows_ocr`) with preprocessing/upscaling
     (`OCR_MIN_EDGE`..`OCR_MAX_EDGE`).
   - **Claude vision fallback** (`claude_extract`, model `claude-haiku-4-5`) —
     called only when an email actually looks like an OTP but local/OCR
     extraction misses it, or the code is inside an image. Images are downscaled
     (`MAX_IMAGE_EDGE`) before sending. Key read from the `ANTHROPIC_API_KEY`
     env var (preferred) or an optional pasted `api_key.txt`.

## Spam-review gate (spam_review.py — temporary quality layer)

Sits between "a regex/OCR/vision found a code" and "copy it". Added to stop
false positives (promo / coupon codes like SALE10, EXTRA30, PATXS508) from being
copied as if they were OTPs. Wired in at the single choke point
`extract_code_from_message.accept()`, so every tier (local regex, OCR, Claude
vision, Claude text) passes through the same gate. Forwarded SMS (`smsotp`) is
trusted and skips review.

Two stages, cheapest first:

1. **filters.json blocklist** (next to the exe, hot-reloaded every check — edit
   it and it applies with **no restart**). Fields: `codes` (exact),
   `code_patterns` (regex on the code), `senders` (substring on From),
   `subjects` (substring on Subject). Gitignored (holds personal senders).
2. **Claude reviewer** (`REVIEW_MODEL = claude-haiku-4-5`) — for anything that
   clears the blocklist, the sender + subject + body + candidate code are sent
   to the Anthropic API and classified verification vs. spam. On a **spam**
   verdict the code is dropped and a filter is **auto-added** (exact code + full
   sender address, not the domain — so a shared domain like google.com can still
   deliver real OTPs from other addresses), so the same source is free next time.

**Fail-open:** if the API errors or no key is configured, the code is allowed
through — a missed real OTP is worse than an occasional promo. Controlled by
`CLAUDE_REVIEW_ENABLED` (master switch) and `AUTO_FILTER_ON_SPAM` in
spam_review.py. This is a **removable** layer: flip the flag False or delete the
`import spam_review` + `screen_candidate` call to revert; the blocklist keeps
working with the reviewer off.

**Manual override:** hotkey `ctrl+alt+b` blocklists the last copied code (adds
its code + sender) for when one still slips through.

## Business rules

- Only process emails that arrive **after** the app starts (launch baseline).
- Ordinary mail needs an OTP keyword adjacent to the digits; forwarded SMS
  (subject `smsotp`) is trusted and accepts bare numbers.
- Process oldest-unseen first so the **newest** code ends up last on the
  clipboard.
- Cloud/vision API is never called on ordinary mail — only on messages that
  already look like an OTP.

## Configuration (top of OTPgetr.py)

`POLL_SECONDS`, `LOOKBACK_MINUTES`, `MAX_EMAILS_TO_SCAN`, `POPUP_SECONDS`,
`POPUP_AT_CURSOR`, `SMS_SUBJECT`, `LOGIN_HINT_EMAIL`, `MAX_IMAGE_EDGE`,
`HEARTBEAT_MINUTES`, `LOG_FILE_MB`, `LOG_BACKUPS`, `TOKEN_EXPIRY_DAYS`,
`REAUTH_WARN_HOURS`.

## Secrets (never commit)

`credentials.json`, `token.json`, `token_meta.json`, and `api_key.txt` (only
created if the user pastes a key instead of using the env var). All gitignored.
The Anthropic key is normally supplied via the `ANTHROPIC_API_KEY` env var, so no
secret lives in source. (The old `OTPgetr_personal.py`, which hardcoded the key,
was removed 2026-07-19.)

## API key setup

Single code path — no separate personal build. The first-run setup popup offers a
checkbox, **"Use my Windows environment variable (ANTHROPIC_API_KEY)"**:

- **Checked** (pre-checked when the env var is already detected): the key is read
  live from `ANTHROPIC_API_KEY` at runtime; nothing is written to disk.
- **Unchecked + paste**: the typed key is saved to `api_key.txt` (gitignored).
- Either choice, or "Do not use", writes a marker so the popup never shows again.

`_read_api_key()` checks the env var first, so setting `ANTHROPIC_API_KEY`
suppresses the popup entirely and behaves identically to a pasted key.

**Change the key any time — `ctrl+alt+k`:** opens the same setup window at
runtime to add, change, or turn off the key. Saving resets the cached client
(`reset_claude_client()`) so the change takes effect with no restart. A brief
toast confirms ("API key updated ✓" / "Cloud backup off").

**Passive nudge:** when an email *looks* like an image-based OTP that local
regex + Windows OCR couldn't read and **no key is set**, `extract_code_from_message`
flags `meta["needs_key"]` and the listener shows a quiet, auto-dismissing toast
("Image code needs a key — CTRL+ALT+K to add one"). It uses the same
`overrideredirect`/no-focus-steal popup as everything else (won't pull you out of
a fullscreen game) and is rate-limited to once per `KEY_NUDGE_COOLDOWN_MIN`
minutes (default 30) so it never spams.

## Related

- Shares the same Google OAuth desktop-app pattern as the reusable
  `google_auth` module (`gmail.readonly` vs that module's broader registry).
