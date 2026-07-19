"""
spam_review.py — verification-vs-spam gate for OTPgetr.
---------------------------------------------------------------------------
This is an OPTIONAL, self-contained layer that sits between "a regex found a
code" and "copy it to the clipboard". It exists to stop false positives like
promo / coupon codes (SALE10, EXTRA30, PATXS508 ...) from being copied.

Two lines of defence, cheapest first:

  1. filters.json  — a user-editable blocklist next to the exe. Hot-reloaded on
     every check, so you can add an entry and it applies WITHOUT restarting.
       {
         "codes":         ["SALE10", "EXTRA30"],   exact code strings
         "code_patterns": ["^(SALE|SAVE|GET)\\d+$"], regex tested against the code
         "senders":       ["deals@store.com"],      substring match on the From header
         "subjects":      ["% off", "newsletter"]    substring match on the Subject
       }

  2. Claude reviewer — for any candidate that clears the blocklist, the email
     (sender + subject + body + the candidate code) is sent to your Anthropic
     API and classified: is this a genuine login/verification/2FA message, or
     is it spam/marketing? On a "spam" verdict the code is dropped AND a filter
     is auto-added (sender + code) so the same source never costs an API call
     again.

REMOVAL: this whole feature is gated by CLAUDE_REVIEW_ENABLED below. Set it to
False (or delete the `import spam_review` + `screen_candidate` call in
OTPgetr.py) to go back to the old behaviour. The filters.json blocklist keeps
working even with the reviewer off.

Fail-open by design: if the API errors or is unavailable, the code is allowed
through — a missed real OTP is worse than an occasional promo slipping past.
"""

import json
import logging
import os
import re

log = logging.getLogger("otpgetr")

# ----------------------------- CONFIG (remove me to disable) -----------------

CLAUDE_REVIEW_ENABLED = True          # master switch for the Claude reviewer
AUTO_FILTER_ON_SPAM = True            # auto-add a filter when Claude says "spam"
REVIEW_MODEL = "claude-haiku-4-5"     # cheap + accurate enough to classify
REVIEW_MAX_CHARS = 4000               # email-body chars sent to the reviewer

# ----------------------------- FILTER STORE ----------------------------------

_FIELDS = ("codes", "code_patterns", "senders", "subjects")

FILTERS_FILE = None                   # set by init()
_filters = {k: [] for k in _FIELDS}
_filters_mtime = None
_compiled = []                        # compiled code_patterns


def init(script_dir: str):
    """Point the filter store at <script_dir>/filters.json and load it."""
    global FILTERS_FILE
    FILTERS_FILE = os.path.join(script_dir, "filters.json")
    _load(force=True)
    log.info("spam_review ready (review=%s, filters=%s codes / %s senders)",
             CLAUDE_REVIEW_ENABLED, len(_filters["codes"]), len(_filters["senders"]))


def _default():
    return {k: [] for k in _FIELDS}


def _load(force: bool = False):
    """(Re)load filters.json if it changed on disk. Cheap enough to call often."""
    global _filters, _filters_mtime, _compiled
    if FILTERS_FILE is None:
        return
    try:
        if not os.path.exists(FILTERS_FILE):
            _filters = _default()
            _save()                    # create a starter file the user can edit
            _filters_mtime = os.path.getmtime(FILTERS_FILE)
            _compile()
            return
        mtime = os.path.getmtime(FILTERS_FILE)
        if not force and mtime == _filters_mtime:
            return
        with open(FILTERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = _default()
        for k in _FIELDS:
            v = data.get(k, [])
            if isinstance(v, list):
                merged[k] = [str(x) for x in v if str(x).strip()]
        _filters = merged
        _filters_mtime = mtime
        _compile()
    except Exception as e:
        log.warning("filters.json load failed (%s) — keeping last good set.", e)


def _compile():
    global _compiled
    out = []
    for p in _filters.get("code_patterns", []):
        try:
            out.append(re.compile(p, re.IGNORECASE))
        except re.error as e:
            log.warning("bad code_pattern %r skipped: %s", p, e)
    _compiled = out


def _save():
    try:
        with open(FILTERS_FILE, "w", encoding="utf-8") as f:
            json.dump(_filters, f, indent=2)
        # keep our mtime cache in step so _save() doesn't trigger a self-reload
        globals()["_filters_mtime"] = os.path.getmtime(FILTERS_FILE)
    except Exception as e:
        log.warning("could not write filters.json: %s", e)


def _sender_email(sender: str) -> str:
    """Pull the bare address out of a 'Name <a@b.com>' From header."""
    m = re.search(r"<([^>]+)>", sender or "")
    if m:
        return m.group(1).strip().lower()
    m = re.search(r"[\w.+-]+@[\w.-]+", sender or "")
    return m.group(0).lower() if m else (sender or "").strip().lower()


def matches_filter(code: str, sender: str, subject: str):
    """Return a short reason string if the blocklist blocks this, else None."""
    _load()                            # hot-reload manual edits
    cl = (code or "").strip().lower()
    for x in _filters["codes"]:
        if x.lower() == cl:
            return f"code={x}"
    for rx in _compiled:
        if code and rx.search(code):
            return f"code_pattern={rx.pattern}"
    s = (sender or "").lower()
    for x in _filters["senders"]:
        if x.lower() in s:
            return f"sender={x}"
    sub = (subject or "").lower()
    for x in _filters["subjects"]:
        if x.lower() in sub:
            return f"subject={x}"
    return None


def add_filter(code=None, sender=None, subject=None, reason=""):
    """Add a blocklist entry: the exact code + the exact sender address.
    We deliberately block the FULL sender address (not the domain) so a shared
    domain like google.com can still deliver real OTPs from other addresses."""
    _load(force=True)
    changed = False
    addr = _sender_email(sender)
    if addr and addr not in [x.lower() for x in _filters["senders"]]:
        _filters["senders"].append(addr)
        changed = True
    if code:
        c = code.strip()
        if c and c.lower() not in [x.lower() for x in _filters["codes"]]:
            _filters["codes"].append(c)
            changed = True
    if changed:
        _save()
        log.info("filter added: code=%s sender=%s %s",
                 code, addr, ("(" + reason + ")") if reason else "")
    return changed


# ----------------------------- CLAUDE REVIEWER -------------------------------

REVIEW_PROMPT = (
    "You are a strict gate for a tool that auto-copies login codes to the "
    "clipboard. You get ONE email plus ONE candidate code a regex pulled from "
    "it. Decide if this email is a genuine account-security message whose job "
    "is to deliver a login / sign-in / verification / 2FA / password-reset "
    "code the user is trying to use right now.\n"
    "Answer false for anything else: marketing, promotions, discount or coupon "
    "codes (SALE10, EXTRA30, ...), order/tracking numbers, referral codes, "
    "newsletters, social notifications, or receipts.\n"
    'Reply with ONLY compact JSON and nothing else: '
    '{"is_verification": true or false, "reason": "<=8 words"}'
)


def _parse_verdict(raw: str):
    m = re.search(r"\{.*\}", raw or "", re.DOTALL)
    if m:
        try:
            d = json.loads(m.group(0))
            return {"is_verification": bool(d.get("is_verification")),
                    "reason": str(d.get("reason", ""))[:80]}
        except Exception:
            pass
    low = (raw or "").lower()
    if "true" in low and "false" not in low:
        return {"is_verification": True, "reason": "parsed:true"}
    if "false" in low and "true" not in low:
        return {"is_verification": False, "reason": "parsed:false"}
    return None


def claude_review(client, sender, subject, text, code):
    """Return {'is_verification': bool, 'reason': str} or None if unavailable."""
    if not client:                     # None or False (no key / not installed)
        return None
    payload = (
        f"From: {sender}\nSubject: {subject}\nCandidate code: {code}\n\n"
        f"Body:\n{(text or '')[:REVIEW_MAX_CHARS]}"
    )
    try:
        resp = client.messages.create(
            model=REVIEW_MODEL,
            max_tokens=60,
            messages=[{"role": "user", "content": REVIEW_PROMPT + "\n\n" + payload}],
        )
        raw = "".join(b.text for b in resp.content if b.type == "text").strip()
        return _parse_verdict(raw)
    except Exception as e:
        log.warning("Claude review error (%s) — allowing code through.", e)
        return None


# ----------------------------- PUBLIC ENTRY POINTS ---------------------------

def screen_candidate(client, code, sender, subject, text):
    """Gate one candidate code. Returns (allow: bool, reason: str).
    On a spam verdict, also auto-adds a filter so it's free next time."""
    hit = matches_filter(code, sender, subject)
    if hit:
        return False, "filtered (" + hit + ")"

    if not CLAUDE_REVIEW_ENABLED:
        return True, "review-off"

    verdict = claude_review(client, sender, subject, text, code)
    if verdict is None:
        return True, "review-unavailable"        # fail-open: never drop a real OTP
    if verdict["is_verification"]:
        return True, "verified: " + verdict["reason"]

    if AUTO_FILTER_ON_SPAM:
        add_filter(code=code, sender=sender, subject=subject,
                   reason="claude:" + verdict["reason"])
    return False, "spam: " + verdict["reason"]


def block_last(code, sender, subject):
    """User pressed the block hotkey on the most recently copied code."""
    return add_filter(code=code, sender=sender, subject=subject,
                      reason="manual block")
