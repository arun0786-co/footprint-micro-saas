import "./style.css";
import { times_leaked } from "./pwned.js";

const $ = (id) => document.getElementById(id);
let email = "";
let token = "";

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function show_msg(text, bad = false) {
  const m = $("msg");
  m.textContent = text;
  m.className = "msg" + (bad ? " bad" : "");
  if (!text) m.classList.add("hidden");
}

async function api(path, body) {
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || "something went wrong, try again");
  return data;
}

function busy(form, on) {
  for (const b of form.querySelectorAll("button")) b.disabled = on;
}

$("email_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  busy(e.target, true);
  try {
    email = $("email").value.trim();
    const out = await api("/api/start", { email });
    $("step_code").classList.remove("hidden");
    if (out.dev_code) {
      $("code").value = out.dev_code;
      $("code_hint").textContent = "dev mode: no email set up, so the code is filled in for you.";
    }
    $("code").focus();
    show_msg("");
  } catch (err) {
    show_msg(err.message, true);
  }
  busy(e.target, false);
});

$("code_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  busy(e.target, true);
  try {
    const out = await api("/api/verify", { email, code: $("code").value.trim() });
    token = out.token;
    $("step_email").classList.add("hidden");
    $("step_code").classList.add("hidden");
    $("step_scan").classList.remove("hidden");
    show_msg("");
  } catch (err) {
    show_msg(err.message, true);
  }
  busy(e.target, false);
});

$("scan_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  busy(e.target, true);
  show_msg("scanning... this takes about 10 seconds");
  try {
    const usernames = $("names").value.split(",").map((s) => s.trim()).filter(Boolean);
    const out = await api("/api/scan", { token, usernames, mine: $("mine").checked });
    show_msg("");
    draw(out);
  } catch (err) {
    show_msg(err.message, true);
  }
  busy(e.target, false);
});

function score_color(s) {
  if (s >= 75) return "good";
  if (s >= 45) return "mid";
  return "bad";
}

function draw(r) {
  const parts = [];
  parts.push(`<div class="card score ${score_color(r.score)}">
    <div class="big">${r.score}<span>/100</span></div>
    <div><b>privacy score for ${esc(r.email)}</b><br><span class="hint">100 = almost nothing out there. its a rough guide.</span></div>
  </div>`);

  if (r.todo.length) {
    parts.push(`<div class="card"><h2>what to do now</h2><ul class="todo">
      ${r.todo.map((t) => `<li class="${t.level}"><span class="tag">${t.level}</span>${esc(t.text)}</li>`).join("")}
    </ul></div>`);
  }

  const b = r.breaches;
  let leaks;
  if (b.error) leaks = `<p class="msg bad">${esc(b.error)}</p>`;
  else if (!b.list.length) leaks = `<p class="ok">good news, this email is not in any known data leak.</p>`;
  else {
    leaks = `<p>found in <b>${b.list.length}</b> data leaks:</p><div class="leaks">
      ${b.list.map((x, i) => `<div class="leak${i >= 10 ? " more hidden" : ""}"><b>${esc(x.name)}</b> <span class="hint">${esc(x.year)}</span>
        <div class="chips">${x.data.map((d) => `<span class="chip${/pass/i.test(d) ? " red" : ""}">${esc(d)}</span>`).join("")}</div></div>`).join("")}
    </div>${b.list.length > 10 ? `<button class="show_all" type="button">show all ${b.list.length}</button>` : ""}`;
  }
  parts.push(`<div class="card"><h2>data leaks</h2>${leaks}
    ${b.source ? `<p class="hint">source: <a href="${esc(b.link)}" target="_blank" rel="noopener">${esc(b.source)}</a></p>` : ""}</div>`);

  if (r.gravatar) {
    parts.push(`<div class="card"><h2>public profile</h2><p>your email has a public gravatar profile
      <a href="${esc(r.gravatar.url)}" target="_blank" rel="noopener">(see it)</a>. anyone with your email can see it.</p></div>`);
  }

  for (const u of r.usernames) {
    const rows = u.sites.map((s) => `<a class="site ${s.state}" href="${esc(s.url)}" target="_blank" rel="noopener">
      <span>${esc(s.site)}</span><b>${{ yes: "found", no: "not found", unknown: "?" }[s.state]}</b></a>`).join("");
    const hand = u.check_yourself.map((s) => `<a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.site)}</a>`).join(" &middot; ");
    parts.push(`<div class="card"><h2>username: ${esc(u.username)}</h2><div class="sites">${rows}</div>
      <p class="hint">these sites block automatic checks, click to check yourself: ${hand}</p></div>`);
  }

  $("results").innerHTML = parts.join("");
  const more = $("results").querySelector(".show_all");
  if (more) more.addEventListener("click", () => {
    for (const el of $("results").querySelectorAll(".leak.more")) el.classList.remove("hidden");
    more.remove();
  });
  $("results").classList.remove("hidden");
  $("results").scrollIntoView({ behavior: "smooth" });
}

$("pass_form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("pass_out");
  const pw = $("pass").value;
  if (!pw) return;
  busy(e.target, true);
  try {
    const n = await times_leaked(pw);
    out.textContent = n
      ? `this password was seen ${n.toLocaleString()} times in leaks. dont use it anywhere.`
      : "not found in any known leak. still, use a different password on every site.";
    out.className = "msg" + (n ? " bad" : " good");
  } catch (err) {
    out.textContent = err.message;
    out.className = "msg bad";
  }
  $("pass").value = "";
  busy(e.target, false);
});

api("/api/config").then((c) => {
  if (c.pay_link) {
    $("pro").classList.remove("hidden");
    $("pro_link").href = c.pay_link;
    $("pro_price").textContent = c.price;
  }
}).catch(() => {});
