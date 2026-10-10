# sites we can check for a username.
# only sites that give a clear yes / no. tested by hand on 10 oct 2026
# (a real name vs a random one). sites that block bots or always say 200 are in HAND_CHECK.

SITES = [
    {"name": "GitHub", "url": "https://github.com/{}"},
    {"name": "GitLab", "url": "https://gitlab.com/api/v4/users?username={}", "show": "https://gitlab.com/{}",
     "missing_body": "[]"},
    {"name": "DEV", "url": "https://dev.to/api/users/by_username?url={}", "show": "https://dev.to/{}"},
    {"name": "Hacker News", "url": "https://hacker-news.firebaseio.com/v0/user/{}.json",
     "show": "https://news.ycombinator.com/user?id={}", "missing_body": "null"},
    {"name": "Chess.com", "url": "https://api.chess.com/pub/player/{}", "show": "https://www.chess.com/member/{}"},
    {"name": "Lichess", "url": "https://lichess.org/api/user/{}", "show": "https://lichess.org/@/{}"},
    {"name": "Codeforces", "url": "https://codeforces.com/api/user.info?handles={}",
     "show": "https://codeforces.com/profile/{}", "missing": [400]},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{}"},
    {"name": "Vimeo", "url": "https://vimeo.com/{}"},
    {"name": "Behance", "url": "https://www.behance.net/{}"},
    {"name": "Tumblr", "url": "https://{}.tumblr.com"},
    {"name": "Dribbble", "url": "https://dribbble.com/{}", "found": [200, 302]},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{}", "missing_text": "The specified profile could not be found"},
]

# big sites block automatic checks, so we just give the person the links
HAND_CHECK = [
    ("Instagram", "https://www.instagram.com/{}/"),
    ("X / Twitter", "https://x.com/{}"),
    ("Facebook", "https://www.facebook.com/{}"),
    ("LinkedIn", "https://www.linkedin.com/in/{}"),
    ("Reddit", "https://www.reddit.com/user/{}"),
    ("Medium", "https://medium.com/@{}"),
    ("LeetCode", "https://leetcode.com/u/{}/"),
    ("Telegram", "https://t.me/{}"),
    ("Pinterest", "https://www.pinterest.com/{}/"),
    ("Kaggle", "https://www.kaggle.com/{}"),
]
