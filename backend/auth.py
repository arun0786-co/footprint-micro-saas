# email codes + short tokens, so people can only scan an email they own.
# kept in memory only, nothing is saved to disk.
import base64
import hashlib
import hmac
import os
import secrets
import time

SECRET = (os.environ.get("APP_SECRET") or secrets.token_hex(32)).encode()
CODE_TTL = 10 * 60
TOKEN_TTL = 30 * 60
MAX_TRIES = 5

codes = {}  # email -> [code hash, expires, wrong tries]


def norm(email):
    return (email or "").strip().lower()


def sign(text):
    return hmac.new(SECRET, text.encode(), hashlib.sha256).hexdigest()


def new_code(email):
    code = f"{secrets.randbelow(10 ** 6):06d}"
    codes[norm(email)] = [sign(f"{norm(email)}:{code}"), time.time() + CODE_TTL, 0]
    return code


def check_code(email, code):
    email = norm(email)
    item = codes.get(email)
    if not item:
        return False
    h, exp, tries = item
    if time.time() > exp or tries >= MAX_TRIES:
        codes.pop(email, None)
        return False
    if hmac.compare_digest(h, sign(f"{email}:{(code or '').strip()}")):
        codes.pop(email, None)
        return True
    item[2] += 1
    return False


def make_token(email, now=None):
    exp = int((now or time.time()) + TOKEN_TTL)
    body = f"{norm(email)}|{exp}"
    return base64.urlsafe_b64encode(f"{body}|{sign(body)}".encode()).decode()


def read_token(token, now=None):
    """gives back the email if the token is good, else None"""
    try:
        raw = base64.urlsafe_b64decode((token or "").encode()).decode()
        email, exp, sig = raw.rsplit("|", 2)
    except Exception:
        return None
    if not hmac.compare_digest(sig, sign(f"{email}|{exp}")):
        return None
    if (now or time.time()) > int(exp):
        return None
    return email


class limiter:
    """very simple 'max n calls per hour' counter"""

    def __init__(self, n, window=3600):
        self.n, self.window, self.hits = n, window, {}

    def ok(self, key, now=None):
        now = now or time.time()
        times = [t for t in self.hits.get(key, []) if now - t < self.window]
        if len(times) >= self.n:
            self.hits[key] = times
            return False
        times.append(now)
        self.hits[key] = times
        return True
