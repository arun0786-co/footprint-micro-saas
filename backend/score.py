# turns the raw results into a score and a todo list in plain words

PASS_WORDS = ("password", "passwords", "password hints", "auth tokens")
BAD_PASS = ("plaintext", "easytocrack")


def has_pass(b):
    return any(d.lower() in PASS_WORDS for d in b["data"])


def make_score(breaches, grav, accounts):
    """100 = very little out there, 0 = a lot. its a rough guide, not science"""
    score = 100
    score -= min(50, 8 * len(breaches))
    score -= min(20, 5 * sum(1 for b in breaches if has_pass(b)))
    score -= 10 if any(b["password_risk"].lower() in BAD_PASS for b in breaches) else 0
    score -= 5 if grav else 0
    score -= min(15, 2 * accounts)
    return max(0, score)


def make_todo(breaches, grav, found):
    todo = []
    with_pass = [b["name"] for b in breaches if has_pass(b)]
    if with_pass:
        names = ", ".join(with_pass[:6]) + (" and more" if len(with_pass) > 6 else "")
        todo.append(("high", f"your password leaked in: {names}. change it there AND on every site where you used the same one."))
    plain = [b["name"] for b in breaches if b["password_risk"].lower() in BAD_PASS]
    if plain:
        todo.append(("high", f"{', '.join(plain[:4])} stored passwords badly (plain text or easy to crack). treat those passwords as public."))
    if breaches:
        todo.append(("high", "turn on 2 step login (2FA) for your email account. if someone gets your email they can reset everything else."))
        phone = [b["name"] for b in breaches if any("phone" in d.lower() for d in b["data"])]
        if phone:
            todo.append(("medium", "your phone number leaked too. expect spam calls and be careful with OTP / bank scam calls."))
    if grav:
        todo.append(("medium", f"you have a public gravatar profile ({grav['url']}). check what it shows and remove what you dont want public."))
    if found:
        todo.append(("low", f"we found your username on {len(found)} site(s). delete old accounts you dont use any more."))
    todo.append(("low", "use a password manager (bitwarden is free) so every site gets a different password."))
    return [{"level": lv, "text": t} for lv, t in todo]
