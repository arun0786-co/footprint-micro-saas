# footprint check

a small web app that shows what the internet knows about **you**:

- is your email in any data leak (and what leaked: passwords, phone, address...)
- does your email have a public gravatar profile
- on which sites your username shows up (github, chess.com, soundcloud and more)
- is your password leaked (checked in your browser, the password never leaves the page)
- a privacy score and a simple "what to do now" list

you have to confirm your email with a 6 digit code first, so people can only check their own email. nothing is saved, codes live in memory for 10 min.

## run it

backend (python 3.10+):

```
cd backend
pip install -r requirements.txt
DEV=1 uvicorn main:app --reload
```

`DEV=1` means no email is needed, the code is filled in on the page. only use that on your own laptop.

frontend:

```
cd frontend
npm install
npm run dev
```

open http://localhost:5173. or run `npm run build` once and the backend serves the page itself on http://localhost:8000.

## settings

see `backend/.env.example`. the main ones:
- `APP_SECRET` - long random string
- `RESEND_KEY` + `MAIL_FROM` - to send the codes by email (resend.com has a free plan). or use `SMTP_*`
- `HIBP_KEY` - optional paid key from haveibeenpwned.com. without it we use xposedornot, which is free but only for low use (25 checks an hour)
- `PAY_LINK`, `PRO_PRICE` - shows the "pro" box

## deploy

one service on render.com (free): build command `pip install -r backend/requirements.txt && cd frontend && npm install && npm run build`, start command `uvicorn main:app --app-dir backend --host 0.0.0.0 --port $PORT`. set the env vars there.

## tests

```
cd backend && pytest
```

## todo

- pro plan: weekly re-check + email when you show up in a new leak (needs a small database)
- more sites for the username check
- breach data is shown with credit to XposedOrNot / Have I Been Pwned, keep that if you change the page
