# footprint check - see what is out there about YOU online.
# run:  uvicorn main:app --reload   (from the backend folder)
import asyncio
import os
import re

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import auth
import checks
import mailer
import score

DEV = os.environ.get("DEV") == "1"
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
MAX_NAMES = 3

app = FastAPI(title="footprint check")

code_ip = auth.limiter(10)
code_mail = auth.limiter(3)
scan_ip = auth.limiter(10)


class email_in(BaseModel):
    email: str


class code_in(BaseModel):
    email: str
    code: str


class scan_in(BaseModel):
    token: str
    usernames: list[str] = []
    mine: bool = False


def ip_of(req: Request):
    fwd = req.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return req.client.host if req.client else "?"


def mask(email):
    user, _, domain = email.partition("@")
    return user[:2] + "***@" + domain


@app.get("/api/config")
def config():
    return {
        "pay_link": os.environ.get("PAY_LINK", ""),
        "price": os.environ.get("PRO_PRICE", "₹99 / month"),
        "dev": DEV and mailer.mail_mode() == "dev",
    }


@app.post("/api/start")
def start(body: email_in, req: Request):
    email = auth.norm(body.email)
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "that does not look like an email")
    if not code_ip.ok(ip_of(req)) or not code_mail.ok(email):
        raise HTTPException(429, "too many codes asked, wait a bit and try again")
    code = auth.new_code(email)
    try:
        mode = mailer.send_code(email, code)
    except Exception:
        raise HTTPException(502, "could not send the email, try again later")
    out = {"sent": True}
    if DEV and mode == "dev":
        out["dev_code"] = code  # only when running locally without mail set up
    return out


@app.post("/api/verify")
def verify(body: code_in):
    if not auth.check_code(body.email, body.code):
        raise HTTPException(400, "wrong or old code")
    return {"token": auth.make_token(body.email)}


async def safe(coro):
    try:
        return await coro, None
    except checks.limit_hit as e:
        return None, str(e)
    except Exception:
        return None, "this check failed, try again later"


@app.post("/api/scan")
async def scan(body: scan_in, req: Request):
    email = auth.read_token(body.token)
    if not email:
        raise HTTPException(401, "your session ran out, verify your email again")
    names = [n.strip() for n in body.usernames if n.strip()][:MAX_NAMES]
    if names and not body.mine:
        raise HTTPException(400, "you can only check your own usernames")
    bad = [n for n in names if not checks.ok_name(n)]
    if bad:
        raise HTTPException(400, f"usernames can only have letters, numbers, _ . - ({bad[0]})")
    if not scan_ip.ok(ip_of(req)):
        raise HTTPException(429, "too many scans, wait a bit and try again")

    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        jobs = [checks.email_breaches(client, email, os.environ.get("HIBP_KEY")), checks.gravatar(client, email)]
        jobs += [checks.username_scan(client, n) for n in names]
        (br, br_err), (grav, _), *users = await asyncio.gather(*(safe(j) for j in jobs))

    breaches = (br or {}).get("breaches", [])
    found = [s for u, _ in users if u for s in u["sites"] if s["state"] == "yes"]
    return {
        "email": mask(email),
        "score": score.make_score(breaches, grav, len(found)),
        "breaches": {"list": breaches, "source": (br or {}).get("source"), "link": (br or {}).get("link"),
                     "error": br_err},
        "gravatar": grav,
        "usernames": [u for u, _ in users if u],
        "todo": score.make_todo(breaches, grav, found),
    }


# serve the built frontend (npm run build) from the same server
dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.isdir(dist):
    app.mount("/", StaticFiles(directory=dist, html=True), name="site")
