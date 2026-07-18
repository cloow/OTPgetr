"""
OTPgetr — Gmail Verification Code Grabber (auto-detect background listener)
---------------------------------------------------------------------------
Start it and leave it running. It quietly polls your Gmail every few seconds.
The moment a NEW verification code arrives (text OR image-based), it copies the
code to your clipboard and shows a green "PASTE ME!" popup near your cursor for
3 seconds. You just Ctrl+V (and Enter) into the field yourself.

Also handles codes texted to your phone: forward them to this Gmail with the
subject "smsotp" (via MacroDroid / Apple Shortcut) and they flow through the
same pipeline.

Hotkeys while running:
  NUMPAD *          -> force an immediate check right now (optional)
  CTRL + NUMPAD *   -> quit

Setup (one time):
  1. pip install -r requirements.txt
  2. Put your Google OAuth credentials.json in this folder (see README).
  3. (For image codes) Put your Anthropic API key in api_key.txt, or set
     ANTHROPIC_API_KEY.
  4. Run:  python OTPgetr.py

Privacy notes:
  - Gmail access is READ-ONLY. The script can never send, delete, or modify
    mail, and your Google password is never seen or stored.
  - Only emails that arrive AFTER the script starts are processed.
  - Codes are found in a waterfall, cheapest/most-private first:
      1. local text regex (on your machine),
      2. built-in Windows OCR for image codes (on your machine),
      3. Anthropic API as a last resort only (this is the ONLY step that
         sends any content off your PC, and only if 1 and 2 both fail on an
         email that already looks like an OTP).
  - Revoke Gmail access anytime at https://myaccount.google.com/permissions
"""

import asyncio
import base64
import gc
import io
import json
import logging
import logging.handlers
import os
import queue
import re
import sys
import threading
import time
from html import unescape

try:
    import psutil          # optional: precise memory reporting
    _HAVE_PSUTIL = True
except ImportError:
    _HAVE_PSUTIL = False

import keyboard          # hotkeys (quit / manual trigger)
import pyperclip         # clipboard
import tkinter as tk     # popup

from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# ----------------------------- CONFIG ---------------------------------------

POLL_SECONDS = 4              # how often to check Gmail (fast but light)
LOOKBACK_MINUTES = 5          # how far back a "new" email can be on each check
MAX_EMAILS_TO_SCAN = 2        # newest N emails per check (2 is plenty at 4s)
POPUP_SECONDS = 3             # popup on-screen time (auto-dismiss)
POPUP_AT_CURSOR = True        # True: near mouse cursor. False: top-center.
TRIGGER_SCAN = 55            # numpad * scan code: force an immediate check
REAUTH_HOTKEY = "ctrl+alt+r"  # reconnect / refresh Gmail login on demand
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
SINGLE_INSTANCE_PORT = 49731  # localhost port used only to detect a 2nd copy
# Pre-selects this Google account at login so you skip the "which Gmail?"
# chooser (leave "" to be asked). Does not bypass the final Allow click.
LOGIN_HINT_EMAIL = ""

# Subject that marks a phone SMS you forwarded to yourself. These are trusted,
# so a bare number is accepted as the code. Ordinary mail needs a keyword.
SMS_SUBJECT = "smsotp"

# Image minimization before sending to Claude (privacy + speed).
MAX_IMAGE_EDGE = 1000

HEARTBEAT_MINUTES = 15       # how often to log a health snapshot
LOG_FILE_MB = 2             # size before the log rotates
LOG_BACKUPS = 5            # how many rotated logs to keep

# Path handling works both as a .py and as a PyInstaller .exe:
#   SCRIPT_DIR   = writable folder next to the exe (token, log, api_key live here)
#   RESOURCE_DIR = where bundled read-only files (credentials.json) are unpacked
if getattr(sys, "frozen", False):
    SCRIPT_DIR = os.path.dirname(sys.executable)
    RESOURCE_DIR = getattr(sys, "_MEIPASS", SCRIPT_DIR)
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    RESOURCE_DIR = SCRIPT_DIR

# Prefer a credentials.json sitting next to the exe (lets a user drop in their
# own); otherwise fall back to the copy bundled inside the exe.
_local_creds = os.path.join(SCRIPT_DIR, "credentials.json")
CREDENTIALS_FILE = _local_creds if os.path.exists(_local_creds) \
    else os.path.join(RESOURCE_DIR, "credentials.json")
TOKEN_FILE = os.path.join(SCRIPT_DIR, "token.json")
TOKEN_META_FILE = os.path.join(SCRIPT_DIR, "token_meta.json")
LOG_FILE = os.path.join(SCRIPT_DIR, "otpgetr.log")

# In "testing" publishing mode Google expires the refresh token 7 days after it
# is granted (the browser login), regardless of use. We track that clock so we
# can warn ahead of time and reconnect gracefully instead of ambushing you.
TOKEN_EXPIRY_DAYS = 7
REAUTH_WARN_HOURS = 24        # start nudging this long before expiry

# ----------------------------- LOGGING / DIAGNOSTICS -------------------------

log = logging.getLogger("otpgetr")


def setup_logging():
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s  %(levelname)-7s %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=LOG_FILE_MB * 1024 * 1024, backupCount=LOG_BACKUPS,
        encoding="utf-8")
    fh.setFormatter(fmt)
    log.addHandler(fh)
    # A windowed (no-console) build has no stderr — only add console logging
    # when there's actually a console to write to.
    if sys.stderr is not None:
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        log.addHandler(ch)
    sys.excepthook = lambda *a: log.critical("Uncaught exception", exc_info=a)
    if hasattr(threading, "excepthook"):
        threading.excepthook = lambda a: log.critical(
            "Uncaught thread exception",
            exc_info=(a.exc_type, a.exc_value, a.exc_traceback))


class Stats:
    """Lightweight counters + a periodic health snapshot to spot leaks."""
    def __init__(self):
        self.start = time.time()
        self.polls = 0
        self.codes = 0
        self.errors = 0
        self.ocr_calls = 0
        self.api_calls = 0
        self._proc = psutil.Process(os.getpid()) if _HAVE_PSUTIL else None
        self._last_rss = None

    def rss_mb(self):
        if self._proc:
            return self._proc.memory_info().rss / 1024 / 1024
        return None

    def heartbeat(self, seen_ids, popup_root):
        up = time.time() - self.start
        hrs, rem = divmod(int(up), 3600)
        mins = rem // 60
        rss = self.rss_mb()
        try:
            live_windows = len(popup_root.winfo_children())
        except Exception:
            live_windows = -1
        parts = [
            f"uptime={hrs}h{mins:02d}m",
            f"polls={self.polls}",
            f"codes={self.codes}",
            f"ocr={self.ocr_calls}",
            f"api_calls={self.api_calls}",
            f"errors={self.errors}",
            f"seen_ids={len(seen_ids)}",
            f"threads={threading.active_count()}",
            f"live_windows={live_windows}",
            f"gc_objects={len(gc.get_objects())}",
        ]
        hrs = token_hours_left()
        if hrs is not None:
            parts.append(f"token_expires_in={hrs / 24:.1f}d")
        if rss is not None:
            delta = "" if self._last_rss is None else f" (Δ{rss - self._last_rss:+.1f})"
            parts.insert(1, f"rss={rss:.1f}MB{delta}")
            self._last_rss = rss
        log.info("HEARTBEAT  " + "  ".join(parts))

# ----------------------------- GMAIL AUTH -----------------------------------

class TokenExpired(Exception):
    """Refresh token is dead — an interactive (browser) login is required."""


def _save_token(creds):
    with open(TOKEN_FILE, "w") as f:
        f.write(creds.to_json())


def set_token_created(ts):
    """Record when the refresh token was granted (starts the 7-day clock)."""
    try:
        with open(TOKEN_META_FILE, "w") as f:
            json.dump({"created_at": ts}, f)
    except Exception as e:
        log.warning("could not write token_meta.json: %s", e)


def get_token_created():
    """Epoch when the current token was granted, or None if unknown.
    If a token exists without metadata (e.g. from before this feature), seed
    the clock from the token file's timestamp as a best-effort estimate."""
    try:
        if os.path.exists(TOKEN_META_FILE):
            return json.load(open(TOKEN_META_FILE)).get("created_at")
    except Exception:
        pass
    if os.path.exists(TOKEN_FILE):
        ts = os.path.getmtime(TOKEN_FILE)
        set_token_created(ts)          # remember the estimate
        log.info("No token_meta.json — estimated token age from file date.")
        return ts
    return None


def token_expiry_epoch():
    created = get_token_created()
    return None if created is None else created + TOKEN_EXPIRY_DAYS * 86400


def token_hours_left():
    exp = token_expiry_epoch()
    return None if exp is None else (exp - time.time()) / 3600.0


def interactive_login():
    """Open the browser for a fresh login. STEALS FOCUS — only call when the
    user chose this moment (startup, or they pressed the reconnect hotkey)."""
    if not os.path.exists(CREDENTIALS_FILE):
        raise SystemExit(
            "\nMissing credentials.json — see README.md for the setup.\n")
    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
    # Opens your DEFAULT browser (your Chrome) — existing login handles it.
    # login_hint pre-selects your account (skips the multi-Gmail chooser). We do
    # NOT force prompt=consent, so Google can skip the Allow screen when it
    # already remembers your grant — fewer clicks per reconnect.
    kwargs = {}
    if LOGIN_HINT_EMAIL:
        kwargs["login_hint"] = LOGIN_HINT_EMAIL
    creds = flow.run_local_server(port=0, **kwargs)
    _save_token(creds)
    set_token_created(time.time())     # (re)start the 7-day clock now
    log.info("Interactive login complete — token clock reset.")
    return build("gmail", "v1", credentials=creds)


def get_gmail_service(allow_interactive=True):
    """Return a Gmail service. If the token needs a browser login, only do it
    when allow_interactive is True; otherwise raise TokenExpired so the caller
    can decide (e.g. don't hijack focus mid-game)."""
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if creds and creds.valid:
        return build("gmail", "v1", credentials=creds)

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())          # normal ~hourly access refresh
            _save_token(creds)                # NOTE: does not reset 7-day clock
            return build("gmail", "v1", credentials=creds)
        except RefreshError:
            log.warning("Refresh token rejected (7-day expiry reached).")
            if not allow_interactive:
                raise TokenExpired()
            # else fall through to a browser login

    # No usable token → need a browser login.
    if allow_interactive:
        return interactive_login()
    raise TokenExpired()


# ----------------------------- CODE EXTRACTION -------------------------------

# Codes near a keyword. The code itself must contain a digit (so words like
# "passcode" never match), and uppercase-only codes are matched case-sensitively.
_CODE_TOKEN = r"(\d{4,8}|(?-i:(?=[A-Z0-9]*\d)[A-Z0-9]{5,8}))"
_KEYWORD = r"(?:code|verification|verify|otp|one[- ]?time|passcode|pin|2fa)"
# Code AFTER the keyword: "your code is 814052"
KEYWORD_RE = re.compile(
    r"\b" + _KEYWORD + r"\b.{0,40}?\b" + _CODE_TOKEN + r"\b",
    re.IGNORECASE | re.DOTALL,
)
# Code BEFORE the keyword: "G-558212 is your verification code"
KEYWORD_RE_REV = re.compile(
    r"\b" + _CODE_TOKEN + r"\b.{0,40}?\b" + _KEYWORD + r"\b",
    re.IGNORECASE | re.DOTALL,
)
# "123 456" / "123-456"
SPLIT_RE = re.compile(r"(?<!\d)(\d{3})[\s-](\d{3})(?!\d)")
# A bare 4-8 digit number — only trusted for forwarded-SMS ("smsotp") mail.
BARE_RE = re.compile(r"(?<![\d.])(\d{4,8})(?![\d.])")
# Cheap "does this even look like an OTP email?" gate before spending an API call.
KEYWORD_HINT_RE = re.compile(
    r"code|verification|verify|otp|one[- ]?time|passcode|pin|2fa|security",
    re.IGNORECASE,
)


def html_to_text(html: str) -> str:
    html = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<[^>]+>", " ", html)
    return unescape(html)


def find_code_in_text(text: str, allow_bare: bool = False):
    if not text:
        return None
    m = KEYWORD_RE.search(text)
    if m:
        return m.group(1)
    m = KEYWORD_RE_REV.search(text)
    if m:
        return m.group(1)
    m = SPLIT_RE.search(text)
    if m:
        return m.group(1) + m.group(2)
    if allow_bare:
        m = BARE_RE.search(text)
        if m:
            return m.group(1)
    return None


# ----------------------------- WINDOWS OCR (local image codes) ---------------
# Reads codes out of images on-device using the built-in Windows OCR engine.
# Nothing leaves your PC. This runs BEFORE the cloud fallback.

OCR_MIN_EDGE = 900      # upscale small images to at least this (helps accuracy)
OCR_MAX_EDGE = 2400     # cap huge images
# Inline alphanumeric code (must contain a digit), for OCR'd text like "AB12CD".
CODE_INLINE_RE = re.compile(r"(?-i:\b(?=[A-Z0-9]*\d)[A-Z0-9]{4,8}\b)")


def _get_ocr_deps():
    """Lazy-import the Windows OCR bits. Returns a tuple or None if unavailable
    (so the app still runs, just skipping the OCR tier)."""
    try:
        from winrt.windows.media.ocr import OcrEngine
        from winrt.windows.globalization import Language
        from winrt.windows.graphics.imaging import BitmapDecoder
        from winrt.windows.storage.streams import (
            InMemoryRandomAccessStream, DataWriter)
        return (OcrEngine, Language, BitmapDecoder,
                InMemoryRandomAccessStream, DataWriter)
    except Exception as e:
        log.warning("Windows OCR unavailable (%s) — will rely on cloud fallback.", e)
        return None


def _preprocess_for_ocr(data: bytes) -> bytes:
    """Upscale tiny images / cap giant ones so OCR reads them well."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert("RGB")
        edge = max(img.size)
        scale = None
        if edge < OCR_MIN_EDGE:
            scale = OCR_MIN_EDGE / edge
        elif edge > OCR_MAX_EDGE:
            scale = OCR_MAX_EDGE / edge
        if scale:
            img = img.resize((max(1, int(img.width * scale)),
                              max(1, int(img.height * scale))), Image.LANCZOS)
        out = io.BytesIO()
        img.save(out, "PNG")
        return out.getvalue()
    except Exception:
        return data


async def _ocr_async(data: bytes, deps) -> str:
    OcrEngine, Language, BitmapDecoder, InMemoryRandomAccessStream, DataWriter = deps
    stream = InMemoryRandomAccessStream()
    writer = DataWriter(stream)
    writer.write_bytes(data)
    await writer.store_async()
    stream.seek(0)
    decoder = await BitmapDecoder.create_async(stream)
    bmp = await decoder.get_software_bitmap_async()
    engine = OcrEngine.try_create_from_user_profile_languages()
    if engine is None:
        engine = OcrEngine.try_create_from_language(Language("en-US"))
    if engine is None:
        return ""
    result = await engine.recognize_async(bmp)
    return result.text or ""


def windows_ocr(data: bytes) -> str:
    deps = _get_ocr_deps()
    if not deps:
        return ""
    try:
        return asyncio.run(_ocr_async(_preprocess_for_ocr(data), deps)) or ""
    except Exception as e:
        log.warning("Windows OCR failed: %s", e)
        return ""


def ocr_extract_code(images):
    """OCR each image locally and pull out a code. Returns code or None."""
    for data in (images or [])[:5]:
        text = windows_ocr(data)
        if not text:
            continue
        # Join digit groups split by spaces/dashes ("44 21 09" -> "442109")
        # WITHOUT gluing adjacent words together.
        text = re.sub(r"(?<=\d)[ \-](?=\d)", "", text)
        # An image is usually JUST the code, so bare numbers are fine here.
        code = find_code_in_text(text, allow_bare=True)
        if not code:
            m = CODE_INLINE_RE.search(text)
            if m:
                code = m.group(0)
        if code:
            if STATS is not None:
                STATS.ocr_calls += 1
            return code
    return None


# ----------------------------- CLAUDE (cloud fallback) -----------------------

ANTHROPIC_MODEL = "claude-haiku-4-5"   # fast + cheap, supports vision
# Where a user-entered key is saved (next to the script/exe).
API_KEY_FILE_LOCAL = os.path.join(SCRIPT_DIR, "api_key.txt")

_CLIENT = None  # initialized lazily
STATS = None    # set in main(); used for lightweight counters


def _read_api_key() -> str:
    """Find the Anthropic key at call time: env var, a key next to the
    script/exe, or a bundled copy (baked into the exe). Empty string if none."""
    k = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if k:
        return k
    for path in (API_KEY_FILE_LOCAL, os.path.join(RESOURCE_DIR, "api_key.txt")):
        try:
            if os.path.exists(path):
                v = open(path).read().strip()
                if v:
                    return v
        except Exception:
            pass
    return ""


def get_claude_client():
    global _CLIENT
    if _CLIENT is not None:
        return _CLIENT
    try:
        import anthropic
    except ImportError:
        log.warning("Package 'anthropic' not installed — cloud fallback disabled.")
        _CLIENT = False
        return _CLIENT
    key = _read_api_key()
    if not key:
        log.warning("No Anthropic API key — cloud fallback disabled (local OCR still works).")
        _CLIENT = False
        return _CLIENT
    _CLIENT = anthropic.Anthropic(api_key=key)
    return _CLIENT


def sniff_media_type(data: bytes) -> str:
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return "image/png"


def downscale_image(data: bytes):
    """Shrink oversized images before upload. Returns (bytes, media_type).
    Falls back to the original bytes if Pillow isn't installed or on error."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        long_edge = max(img.size)
        if long_edge <= MAX_IMAGE_EDGE:
            return data, sniff_media_type(data)
        scale = MAX_IMAGE_EDGE / long_edge
        new_size = (max(1, int(img.width * scale)), max(1, int(img.height * scale)))
        img = img.convert("RGB").resize(new_size, Image.LANCZOS)
        out = io.BytesIO()
        img.save(out, format="PNG", optimize=True)
        return out.getvalue(), "image/png"
    except Exception:
        return data, sniff_media_type(data)


CODE_SHAPE_RE = re.compile(r"^[A-Z0-9]{4,10}$|^\d{4,10}$", re.IGNORECASE)

EXTRACT_PROMPT = (
    "This content is from an automated email. Find the verification / one-time "
    "code (OTP) in it. Reply with ONLY the code itself — no spaces, no dashes, "
    "no other words. If there is no verification code, reply with exactly: NONE"
)


def claude_extract(images=None, text=None):
    client = get_claude_client()
    if not client:
        return None
    content = []
    for data in (images or [])[:5]:
        small, media_type = downscale_image(data)
        content.append({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": media_type,
                "data": base64.standard_b64encode(small).decode(),
            },
        })
    if text:
        content.append({"type": "text", "text": "Email text:\n" + text[:6000]})
    if not content:
        return None
    content.append({"type": "text", "text": EXTRACT_PROMPT})
    if STATS is not None:
        STATS.api_calls += 1
    try:
        resp = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=50,
            messages=[{"role": "user", "content": content}],
        )
        answer = "".join(b.text for b in resp.content if b.type == "text").strip()
        answer = answer.replace(" ", "").replace("-", "")
        if answer.upper() != "NONE" and CODE_SHAPE_RE.match(answer):
            return answer
    except Exception as e:
        if STATS is not None:
            STATS.errors += 1
        log.error("Claude API error: %s", e)
    return None


# ----------------------------- EMAIL SCANNING --------------------------------

def walk_parts(payload):
    stack = [payload]
    while stack:
        part = stack.pop()
        yield part
        for child in part.get("parts", []) or []:
            stack.append(child)


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def extract_code_from_message(service, msg_id: str):
    msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
    payload = msg.get("payload", {})

    texts, images = [], []
    for part in walk_parts(payload):
        mime = part.get("mimeType", "")
        body = part.get("body", {})
        if mime == "text/plain" and body.get("data"):
            texts.append(b64url_decode(body["data"]).decode("utf-8", "ignore"))
        elif mime == "text/html" and body.get("data"):
            texts.append(html_to_text(b64url_decode(body["data"]).decode("utf-8", "ignore")))
        elif mime.startswith("image/"):
            if body.get("data"):
                images.append(b64url_decode(body["data"]))
            elif body.get("attachmentId"):
                att = (
                    service.users().messages().attachments()
                    .get(userId="me", messageId=msg_id, id=body["attachmentId"])
                    .execute()
                )
                if att.get("data"):
                    images.append(b64url_decode(att["data"]))

    headers = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
    subject = headers.get("subject", "")
    trusted = SMS_SUBJECT in subject.lower()   # a forwarded phone SMS
    texts.insert(0, subject + "\n" + msg.get("snippet", ""))
    joined = "\n".join(texts)

    # Waterfall: cheapest/most-private first, cloud only as the last resort.

    # 1) Local regex on text (instant, free, nothing leaves your machine).
    for t in texts:
        code = find_code_in_text(t, allow_bare=trusted)
        if code:
            return code, "local regex (text)"

    # Only work harder if this actually looks like an OTP email.
    looks_like_otp = trusted or bool(KEYWORD_HINT_RE.search(joined))

    # 2) Windows OCR on images (local, on-device, nothing leaves your PC).
    if images and looks_like_otp:
        code = ocr_extract_code(images)
        if code:
            return code, f"Windows OCR ({len(images)} image(s))"

    # 3) Cloud fallback (Anthropic) — ONLY if a key is configured. With no key
    #    get_claude_client() is False, so this tier is skipped entirely and can
    #    never error out on a missing key.
    if looks_like_otp and get_claude_client():
        if images:
            code = claude_extract(images=images, text=joined[:6000])
            if code:
                return code, f"Claude vision ({len(images)} image(s))"
        if joined.strip():
            code = claude_extract(text=joined.strip())
            if code:
                return code, "Claude text fallback"

    # 4) we cooked.
    return None, None


# ----------------------------- POPUP -----------------------------------------

class PopupApp:
    """Tk root lives in the main thread; other threads send events via queue."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.events = queue.Queue()
        self.root.after(100, self._poll)

    def _poll(self):
        try:
            while True:
                kind, text = self.events.get_nowait()
                if kind == "quit":
                    self.root.destroy()
                    return
                self._show(text, kind)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _show(self, text, kind="ok"):
        win = tk.Toplevel(self.root)
        win.overrideredirect(True)          # no title bar
        win.attributes("-topmost", True)
        # overrideredirect + no focus_force => shows without stealing focus,
        # so it won't yank you out of a fullscreen game.
        bg = {"ok": "#16a34a", "err": "#dc2626", "warn": "#d97706"}.get(kind, "#16a34a")
        # ~40% smaller than the original (font 16 / pad 20x12).
        frame = tk.Frame(win, bg=bg, padx=12, pady=7)
        frame.pack()
        tk.Label(
            frame, text=text, bg=bg, fg="white",
            font=("Segoe UI", 10, "bold"), justify="center",
        ).pack()
        win.update_idletasks()
        if POPUP_AT_CURSOR:
            x = self.root.winfo_pointerx() + 15
            y = self.root.winfo_pointery() + 15
        else:
            x = (win.winfo_screenwidth() - win.winfo_width()) // 2
            y = 40
        win.geometry(f"+{x}+{y}")
        win.after(POPUP_SECONDS * 1000, win.destroy)  # auto-dismiss

    def notify(self, kind, text=None):
        self.events.put((kind, text))

    def run(self):
        self.root.mainloop()


# ----------------------------- BACKGROUND LISTENER ---------------------------

class Listener:
    def __init__(self, service, app, stats):
        self.service = service
        self.app = app
        self.stats = stats
        self.seen_ids = set()       # message IDs already processed
        self.last_code = None       # avoid re-popping identical back-to-back code
        self.wake = threading.Event()
        self.stop = threading.Event()
        self.needs_reauth = False   # True once the refresh token has expired
        self.warned_expiry = False  # True once we've nudged about upcoming expiry
        self.reauth_lock = threading.Lock()

    def _list_recent_ids(self):
        after_epoch = int(time.time()) - LOOKBACK_MINUTES * 60
        # 'in:anywhere' includes Spam, Trash, and all category tabs.
        resp = (
            self.service.users().messages()
            .list(userId="me", q=f"in:anywhere after:{after_epoch}",
                  maxResults=MAX_EMAILS_TO_SCAN)
            .execute()
        )
        return [m["id"] for m in resp.get("messages", [])]

    def seed_baseline(self):
        """Mark whatever is already in the inbox as seen, so we only react to
        emails that arrive AFTER startup."""
        try:
            for mid in self._list_recent_ids():
                self.seen_ids.add(mid)
        except Exception as e:
            log.warning("baseline seed failed: %s", e)

    def enter_reauth_wait(self):
        """Refresh token died mid-run. Pause quietly and wait for the user to
        reconnect on their own terms — no browser, no focus stealing."""
        if self.needs_reauth:
            return
        self.needs_reauth = True
        log.warning("Gmail sign-in expired — paused. Press %s to reconnect.",
                    REAUTH_HOTKEY.upper())
        self.app.notify("warn",
                        f"OTPGetr sign-in expired\nPress {REAUTH_HOTKEY.upper()} to reconnect")

    def reauth_now(self):
        """Open the browser and re-login. Only ever called because the user
        pressed the reconnect hotkey, i.e. they chose this moment."""
        with self.reauth_lock:
            log.info("Reconnect requested — opening browser.")
            self.app.notify("ok", "Reconnecting…\nChrome will open")
            try:
                self.service = interactive_login()
            except Exception as e:
                log.error("Reconnect failed: %s", e)
                self.app.notify("err", "Reconnect failed\nsee otpgetr.log")
                return
            self.needs_reauth = False
            self.warned_expiry = False
            self.seen_ids.clear()
            self.seed_baseline()   # don't dump codes that arrived while expired
            self.app.notify("ok", "OTPGetr reconnected ✓")
        self.wake.set()

    def _maybe_warn_expiry(self):
        """Nudge (orange popup) once when the 7-day token is close to expiring,
        so the user can reconnect between sessions instead of mid-game."""
        if self.needs_reauth or self.warned_expiry:
            return
        hrs = token_hours_left()
        if hrs is not None and hrs <= REAUTH_WARN_HOURS:
            self.warned_expiry = True
            log.warning("Gmail token expires in ~%.1fh.", hrs)
            when = f"in ~{int(hrs)}h" if hrs > 0 else "now"
            self.app.notify("warn",
                            f"OTPGetr sign-in expires {when}\n"
                            f"Reconnect when free: {REAUTH_HOTKEY.upper()}")

    def check_once(self):
        if self.needs_reauth:
            return                      # paused until the user reconnects
        self.stats.polls += 1
        try:
            ids = self._list_recent_ids()
        except RefreshError:
            self.enter_reauth_wait()
            return
        except Exception as e:
            self.stats.errors += 1
            log.warning("Gmail check failed: %s", e)
            return
        # Process oldest-unseen first so the newest code ends up on the clipboard.
        new_ids = [mid for mid in ids if mid not in self.seen_ids]
        for mid in reversed(new_ids):
            self.seen_ids.add(mid)
            try:
                code, method = extract_code_from_message(self.service, mid)
            except RefreshError:
                self.enter_reauth_wait()
                return
            except Exception as e:
                self.stats.errors += 1
                log.warning("read failed for %s: %s", mid, e)
                continue
            if code and code != self.last_code:
                self.last_code = code
                self.stats.codes += 1
                pyperclip.copy(code)
                self.app.notify("ok", f"PASTE ME!\n{code}")
                log.info("copied %s  (via %s)", code, method)

    def run(self):
        self.seed_baseline()
        log.info("Listening. Checking every %ss. NUMPAD * = check now | "
                 "CTRL + NUMPAD * = quit | %s = reconnect",
                 POLL_SECONDS, REAUTH_HOTKEY.upper())
        self.stats.heartbeat(self.seen_ids, self.app.root)   # baseline snapshot
        next_beat = time.time() + HEARTBEAT_MINUTES * 60
        while not self.stop.is_set():
            self._maybe_warn_expiry()
            self.check_once()
            if len(self.seen_ids) > 500:      # keep memory bounded in long sessions
                self.seen_ids = set(list(self.seen_ids)[-200:])
            if time.time() >= next_beat:
                self.stats.heartbeat(self.seen_ids, self.app.root)
                next_beat = time.time() + HEARTBEAT_MINUTES * 60
            self.wake.wait(timeout=POLL_SECONDS)
            self.wake.clear()

    def trigger_now(self):
        self.wake.set()

    def shutdown(self):
        self.stop.set()
        self.wake.set()


# ----------------------------- MAIN ------------------------------------------

_INSTANCE_LOCK = None   # module-level so the socket stays open for the run


def acquire_single_instance():
    """Return True if we're the only copy running. Uses a localhost port bind
    as a cross-process lock (auto-released when the process ends)."""
    global _INSTANCE_LOCK
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", SINGLE_INSTANCE_PORT))
        _INSTANCE_LOCK = s          # keep a reference alive for the whole run
        return True
    except OSError:
        s.close()
        return False


def authorize_with_retry():
    """Gmail auth, retried — network may not be up yet at Windows startup."""
    for attempt in range(1, 25):
        try:
            return get_gmail_service()
        except SystemExit:
            raise
        except Exception as e:
            log.warning("Gmail auth failed (attempt %d): %s — retrying in 5s",
                        attempt, e)
            time.sleep(5)
    log.critical("Could not authorize with Gmail after retries.")
    return None


def _prompt_api_key() -> str:
    """Small first-run window asking for the Anthropic key. Returns the entered
    key (or "" if skipped). Runs its own short-lived Tk root."""
    import tkinter as tk
    root = tk.Tk()
    root.title("OTPGetr — Setup")
    root.attributes("-topmost", True)
    out = {"key": ""}

    tk.Label(root, text="OTPGetr — first-time setup",
             font=("Segoe UI", 13, "bold")).pack(padx=24, pady=(18, 4))
    tk.Label(root, justify="left", font=("Segoe UI", 10), text=(
        "Optional: paste your Anthropic API key.\n\n"
        "It's only a backup — used to read codes inside images that the built-in\n"
        "Windows reader can't handle. The app works fully without it.\n\n"
        "\"Do not use\" turns the backup off and won't ask again."
    )).pack(padx=24, pady=(0, 12))

    entry = tk.Entry(root, width=56, font=("Consolas", 10))
    entry.pack(padx=24, pady=(0, 14))
    entry.focus_set()

    def _save():
        out["key"] = entry.get().strip()
        root.destroy()

    def _dont_use():
        out["key"] = ""
        root.destroy()

    bar = tk.Frame(root)
    bar.pack(pady=(0, 18))
    tk.Button(bar, text="Save", width=14, command=_save).pack(side="left", padx=8)
    tk.Button(bar, text="Do not use", width=14, command=_dont_use).pack(side="left", padx=8)
    root.bind("<Return>", lambda e: _save())
    # Closing the window (X) counts as "Do not use" so we never re-prompt.
    root.protocol("WM_DELETE_WINDOW", _dont_use)

    root.update_idletasks()
    w, h = root.winfo_width(), root.winfo_height()
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 3
    root.geometry(f"+{x}+{y}")
    root.mainloop()
    return out["key"]


def ensure_api_key():
    """First run only: if no key exists anywhere (env / local file / bundled),
    ask once and save the answer so we never prompt again."""
    if _read_api_key():
        return                                  # already configured — no prompt
    if os.path.exists(API_KEY_FILE_LOCAL):
        return                                  # user already chose (even if blank)
    try:
        key = _prompt_api_key()
    except Exception as e:
        log.warning("Setup prompt failed (%s) — continuing without a key.", e)
        key = ""
    try:
        with open(API_KEY_FILE_LOCAL, "w") as f:
            f.write(key)
        log.info("First-run setup: API key %s.",
                 "saved" if key else "skipped (local OCR only)")
    except Exception as e:
        log.warning("Could not save api_key.txt: %s", e)


def main():
    global STATS
    setup_logging()

    if not acquire_single_instance():
        log.info("Another copy of OTPGetr is already running — exiting.")
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0, "OTPGetr is already running.", "OTPGetr", 0x40)
        except Exception:
            pass
        return

    STATS = Stats()
    log.info("=== OTPGetr starting (psutil=%s) ===", _HAVE_PSUTIL)

    # Lock in the token-age estimate before the first refresh rewrites the file
    # timestamp (only matters for a pre-existing token with no metadata yet).
    get_token_created()

    # First-run setup: ask for the optional Anthropic key (once), then log in.
    ensure_api_key()

    log.info("Authorizing with Gmail...")
    # Startup = user isn't gaming yet, so an expired token just opens Chrome.
    service = authorize_with_retry()
    if service is None:
        return
    hrs = token_hours_left()
    if hrs is not None:
        log.info("Authorized. Sign-in valid for ~%.1f more days.", hrs / 24)
    else:
        log.info("Authorized.")

    app = PopupApp()
    listener = Listener(service, app, STATS)

    def on_hotkey():
        if keyboard.is_pressed("ctrl"):
            log.info("Quit hotkey pressed.")
            STATS.heartbeat(listener.seen_ids, app.root)   # final snapshot
            listener.shutdown()
            app.notify("quit")
        else:
            listener.trigger_now()   # manual immediate check

    keyboard.add_hotkey(TRIGGER_SCAN,
                        lambda: threading.Thread(target=on_hotkey, daemon=True).start())
    # Reconnect on demand — opens Chrome, so it's only ever fired by the user.
    keyboard.add_hotkey(REAUTH_HOTKEY,
                        lambda: threading.Thread(target=listener.reauth_now, daemon=True).start())

    t = threading.Thread(target=listener.run, daemon=True)
    t.start()

    app.run()               # blocks until quit
    keyboard.unhook_all()
    log.info("=== OTPGetr stopped ===")


if __name__ == "__main__":
    main()
