# sends the login code. uses resend.com if RESEND_KEY is set, else smtp, else prints it (dev).
import os
import smtplib
from email.message import EmailMessage

import httpx

SUBJECT = "your footprint check code"


def body(code):
    return (f"your code is {code}\n\n"
            "it works for 10 minutes. if you did not ask for this, someone typed your email "
            "by mistake, you can ignore this mail.\n")


def mail_mode():
    if os.environ.get("RESEND_KEY"):
        return "resend"
    if os.environ.get("SMTP_HOST"):
        return "smtp"
    return "dev"


def send_code(email, code):
    mode = mail_mode()
    sender = os.environ.get("MAIL_FROM", "footprint <noreply@example.com>")
    if mode == "resend":
        r = httpx.post("https://api.resend.com/emails", timeout=10,
                       headers={"Authorization": f"Bearer {os.environ['RESEND_KEY']}"},
                       json={"from": sender, "to": [email], "subject": SUBJECT, "text": body(code)})
        r.raise_for_status()
    elif mode == "smtp":
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = sender, email, SUBJECT
        msg.set_content(body(code))
        with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", 587))) as s:
            s.starttls()
            s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
            s.send_message(msg)
    else:
        print(f"[dev] code for {email}: {code}", flush=True)
    return mode
