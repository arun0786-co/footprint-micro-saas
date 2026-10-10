import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DEV"] = "1"

import auth  # noqa: E402
import checks  # noqa: E402
import main  # noqa: E402
import score  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

main.DEV = True


@pytest.fixture
def client(monkeypatch):
    # fresh limits for every test
    main.code_ip, main.code_mail, main.scan_ip = auth.limiter(10), auth.limiter(3), auth.limiter(10)
    monkeypatch.delenv("RESEND_KEY", raising=False)
    monkeypatch.delenv("SMTP_HOST", raising=False)

    async def fake_breaches(client, email, key=None):
        return {"source": "XposedOrNot", "link": "x", "breaches": [
            {"name": "Adobe", "year": "2013", "data": ["Email addresses", "Passwords"], "password_risk": "easytocrack", "domain": ""},
            {"name": "Canva", "year": "2019", "data": ["Email addresses", "Names"], "password_risk": "hardtocrack", "domain": ""},
        ]}

    async def fake_grav(client, email):
        return {"url": "https://gravatar.com/x", "name": "a", "has_photo": True}

    async def fake_users(client, name):
        return {"username": name, "sites": [{"site": "GitHub", "url": "u", "state": "yes"},
                                            {"site": "Vimeo", "url": "u", "state": "no"}], "check_yourself": []}

    monkeypatch.setattr(checks, "email_breaches", fake_breaches)
    monkeypatch.setattr(checks, "gravatar", fake_grav)
    monkeypatch.setattr(checks, "username_scan", fake_users)
    return TestClient(main.app)


def login(c, email="arun@example.com"):
    code = c.post("/api/start", json={"email": email}).json()["dev_code"]
    return c.post("/api/verify", json={"email": email, "code": code}).json()["token"]


def test_full_flow(client):
    tok = login(client)
    r = client.post("/api/scan", json={"token": tok, "usernames": ["arun_k"], "mine": True})
    assert r.status_code == 200
    d = r.json()
    assert d["email"] == "ar***@example.com"
    assert len(d["breaches"]["list"]) == 2
    assert d["usernames"][0]["sites"][0]["state"] == "yes"
    assert d["score"] < 100
    assert any("Adobe" in t["text"] for t in d["todo"])


def test_bad_email(client):
    assert client.post("/api/start", json={"email": "nope"}).status_code == 400


def test_wrong_code(client):
    client.post("/api/start", json={"email": "a@b.com"})
    assert client.post("/api/verify", json={"email": "a@b.com", "code": "000000x"}).status_code == 400


def test_code_only_works_once(client):
    code = client.post("/api/start", json={"email": "a@b.com"}).json()["dev_code"]
    assert client.post("/api/verify", json={"email": "a@b.com", "code": code}).status_code == 200
    assert client.post("/api/verify", json={"email": "a@b.com", "code": code}).status_code == 400


def test_scan_needs_token(client):
    assert client.post("/api/scan", json={"token": "junk"}).status_code == 401


def test_usernames_must_be_mine(client):
    tok = login(client)
    r = client.post("/api/scan", json={"token": tok, "usernames": ["someone"], "mine": False})
    assert r.status_code == 400


def test_bad_username(client):
    tok = login(client)
    r = client.post("/api/scan", json={"token": tok, "usernames": ["../etc"], "mine": True})
    assert r.status_code == 400


def test_code_rate_limit(client):
    for _ in range(3):
        assert client.post("/api/start", json={"email": "a@b.com"}).status_code == 200
    assert client.post("/api/start", json={"email": "a@b.com"}).status_code == 429


def test_breach_fail_is_partial(client, monkeypatch):
    async def boom(client, email, key=None):
        raise checks.limit_hit("limit hit")
    monkeypatch.setattr(checks, "email_breaches", boom)
    tok = login(client)
    d = client.post("/api/scan", json={"token": tok}).json()
    assert d["breaches"]["error"] == "limit hit"
    assert d["gravatar"]


# --- small parts ---

def test_token_expires():
    tok = auth.make_token("a@b.com", now=1000)
    assert auth.read_token(tok, now=1001) == "a@b.com"
    assert auth.read_token(tok, now=1000 + auth.TOKEN_TTL + 1) is None


def test_token_tamper():
    tok = auth.make_token("a@b.com")
    import base64
    raw = base64.urlsafe_b64decode(tok).decode().replace("a@b.com", "x@b.com")
    assert auth.read_token(base64.urlsafe_b64encode(raw.encode()).decode()) is None


def test_code_max_tries():
    code = auth.new_code("t@b.com")
    for _ in range(auth.MAX_TRIES):
        assert not auth.check_code("t@b.com", "nope")
    assert not auth.check_code("t@b.com", code)  # locked after too many tries


def test_limiter_window():
    lim = auth.limiter(2, window=10)
    assert lim.ok("k", now=0) and lim.ok("k", now=1)
    assert not lim.ok("k", now=2)
    assert lim.ok("k", now=11)


def test_score_and_todo():
    assert score.make_score([], None, 0) == 100
    b = [{"name": "X", "year": "", "data": ["Passwords"], "password_risk": "plaintext", "domain": ""}]
    assert score.make_score(b, None, 0) == 100 - 8 - 5 - 10
    todo = score.make_todo(b, None, [])
    assert todo[0]["level"] == "high"


def test_ok_name():
    assert checks.ok_name("arun.k_99")
    assert not checks.ok_name("a")
    assert not checks.ok_name("a/b")


def fake_transport(rules):
    def handler(req):
        for part, (status, text) in rules.items():
            if part in str(req.url):
                return httpx.Response(status, text=text)
        return httpx.Response(500)
    return httpx.MockTransport(handler)


def test_site_rules():
    t = fake_transport({
        "github.com/arun": (200, "hi"),
        "gitlab.com": (200, "[]"),
        "steamcommunity": (200, "The specified profile could not be found."),
        "vimeo": (404, ""),
        "dribbble": (302, ""),
    })

    async def go():
        async with httpx.AsyncClient(transport=t) as c:
            return await checks.username_scan(c, "arun")
    res = {s["site"]: s["state"] for s in asyncio.run(go())["sites"]}
    assert res["GitHub"] == "yes"
    assert res["GitLab"] == "no"
    assert res["Steam"] == "no"
    assert res["Vimeo"] == "no"
    assert res["Dribbble"] == "yes"
    assert res["Lichess"] == "unknown"  # 500 = we dont know


def test_xon_parse():
    body = '{"ExposedBreaches":{"breaches_details":[{"breach":"Adobe","xposed_date":"2013",' \
           '"xposed_data":"Email addresses;Passwords","password_risk":"easytocrack","domain":"adobe.com"}]}}'
    t = fake_transport({"breach-analytics": (200, body)})

    async def go():
        async with httpx.AsyncClient(transport=t) as c:
            return await checks.breaches_xon(c, "a@b.com")
    out = asyncio.run(go())
    assert out[0]["name"] == "Adobe" and out[0]["data"] == ["Email addresses", "Passwords"]


def test_xon_not_found():
    body = '{"BreachMetrics":null,"ExposedBreaches":null}'
    t = fake_transport({"breach-analytics": (200, body)})

    async def go():
        async with httpx.AsyncClient(transport=t) as c:
            return await checks.breaches_xon(c, "a@b.com")
    assert asyncio.run(go()) == []
