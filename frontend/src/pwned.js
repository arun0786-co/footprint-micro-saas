// password leak check with k-anonymity.
// we hash the password here, send only the first 5 hex chars, and look for the rest in the answer.

async function sha1_hex(text) {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export async function times_leaked(password) {
  const hash = await sha1_hex(password);
  const head = hash.slice(0, 5);
  const tail = hash.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${head}`, { headers: { "Add-Padding": "true" } });
  if (!res.ok) throw new Error("password check is down, try later");
  const text = await res.text();
  for (const line of text.split("\n")) {
    const [rest, count] = line.trim().split(":");
    if (rest === tail) return parseInt(count, 10); // padding lines have count 0
  }
  return 0;
}
