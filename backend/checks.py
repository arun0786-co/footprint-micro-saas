# the actual checks. all network calls are here so tests can swap them out.
import asyncio
import hashlib
import re
from urllib.parse import quote

import httpx

from sites import HAND_CHECK, SITES

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,40}$")


class limit_hit(Exception):
    pass


def ok_name(name):
    return bool(NAME_RE.match(name or ""))


async def breaches_xon(client, email):
    """free api from xposedornot.com. only for low volume use."""
    r = await client.get("https://api.xposedornot.com/v1/breach-analytics", params={"email": email})
    if r.status_code == 429:
        raise limit_hit("breach check limit hit, try again in an hour")
    if r.status_code == 404:
        return []
    r.raise_for_status()
    found = (r.json().get("ExposedBreaches") or {}).get("breaches_details") or []
    out = []
    for b in found:
        out.append({
            "name": b.get("breach", "?"),
            "year": str(b.get("xposed_date") or ""),
            "data": [d.strip() for d in (b.get("xposed_data") or "").split(";") if d.strip()],
            "password_risk": b.get("password_risk") or "unknown",
            "domain": b.get("domain") or "",
        })
    return out


async def breaches_hibp(client, email, key):
    """paid api from haveibeenpwned.com, needs a key. must show attribution."""
    r = await client.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                         params={"truncateResponse": "false"},
                         headers={"hibp-api-key": key, "user-agent": "footprint-check"})
    if r.status_code == 404:
        return []
    if r.status_code == 429:
        raise limit_hit("breach check limit hit, try again soon")
    r.raise_for_status()
    return [{
        "name": b["Name"],
        "year": b.get("BreachDate", "")[:4],
        "data": b.get("DataClasses", []),
        "password_risk": "unknown",
        "domain": b.get("Domain", ""),
    } for b in r.json()]


async def email_breaches(client, email, hibp_key=None):
    if hibp_key:
        return {"source": "Have I Been Pwned", "link": "https://haveibeenpwned.com",
                "breaches": await breaches_hibp(client, email, hibp_key)}
    return {"source": "XposedOrNot", "link": "https://xposedornot.com",
            "breaches": await breaches_xon(client, email)}


async def gravatar(client, email):
    """gravatar shows a public profile (name, photo, links) for an email if you ever made one"""
    h = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    r = await client.get(f"https://gravatar.com/{h}.json", headers={"user-agent": UA})
    if r.status_code != 200:
        return None
    try:
        entry = r.json()["entry"][0]
    except (KeyError, IndexError, ValueError):
        return {"url": f"https://gravatar.com/{h}"}
    return {"url": entry.get("profileUrl") or f"https://gravatar.com/{h}",
            "name": entry.get("displayName", ""), "has_photo": bool(entry.get("thumbnailUrl"))}


async def one_site(client, site, name):
    url = site["url"].format(name)
    show = site.get("show", site["url"]).format(name)
    try:
        r = await client.get(url, headers={"user-agent": UA})
    except httpx.HTTPError:
        return {"site": site["name"], "url": show, "state": "unknown"}
    state = "unknown"
    if r.status_code in site.get("missing", [404, 410]):
        state = "no"
    elif r.status_code in site.get("found", [200]):
        state = "yes"
        body = r.text
        if "missing_body" in site and body.strip() == site["missing_body"]:
            state = "no"
        if "missing_text" in site and site["missing_text"] in body:
            state = "no"
    return {"site": site["name"], "url": show, "state": state}


async def username_scan(client, name):
    res = await asyncio.gather(*(one_site(client, s, name) for s in SITES))
    hand = [{"site": n, "url": u.format(name)} for n, u in HAND_CHECK]
    return {"username": name, "sites": list(res), "check_yourself": hand}
