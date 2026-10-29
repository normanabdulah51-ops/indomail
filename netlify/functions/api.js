// Penghubung antara tampilan inbox dan smtp.dev.
// API key dan kunci sesi disimpan di environment variable Netlify, tidak pernah dikirim ke browser.
const crypto = require("crypto");
const tls = require("tls");
const BASE = "https://api.smtp.dev";
const enc = encodeURIComponent;
const ids = new Map();
const fails = new Map();
const TTL = 12 * 3600 * 1000;
const members = (r) => (Array.isArray(r) ? r : (r && (r.member || r["hydra:member"])) || []);
const hasNext = (r) => Array.isArray(r) ? r.length >= 30 : !!(r && ((r.view && r.view.next) || (r["hydra:view"] && r["hydra:view"]["hydra:next"])));

const reply = (status, body) => ({
  statusCode: status,
  headers: { "content-type": "application/json", "cache-control": "no-store" },
  body: JSON.stringify(body),
});

async function smtp(path, opts = {}) {
  const res = await fetch(BASE + path, {
    ...opts,
    headers: { "X-API-KEY": process.env.SMTPDEV_API_KEY, Accept: "application/json", ...opts.headers },
  });
  if (res.status === 204) return null;
  if (!res.ok) throw new Error("smtp.dev " + res.status);
  return res.json();
}

async function accountId(address) {
  if (ids.has(address)) return ids.get(address);
  const r = await smtp("/accounts?address=" + enc(address));
  const acc = members(r).find((a) => a.address.toLowerCase() === address);
  if (!acc) throw new Error("Akun tidak ditemukan");
  ids.set(address, acc.id);
  return acc.id;
}

// Cek password mailbox lewat IMAP (API smtp.dev tidak punya endpoint login).
function imapLogin(user, pass) {
  return new Promise((resolve) => {
    if (/[\r\n\0]/.test(user + pass)) return resolve({ ok: false, why: "karakter tidak valid" });
    const q = (s) => '"' + s.replace(/(["\\])/g, "\\$1") + '"';
    const sock = tls.connect(993, "imap.smtp.dev", { servername: "imap.smtp.dev" });
    let buf = "", sent = false, done = false;
    const end = (ok, why) => { if (done) return; done = true; sock.destroy(); resolve({ ok, why }); };
    sock.setTimeout(8000, () => end(false, "IMAP timeout"));
    sock.on("error", (e) => end(false, "IMAP error: " + e.message));
    sock.on("close", () => end(false, "IMAP koneksi ditutup"));
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      if (!sent) {
        if (!buf.includes("\r\n")) return;
        sent = true; buf = "";
        sock.write(`a1 LOGIN ${q(user)} ${q(pass)}\r\n`);
      } else if (/^a1 OK/mi.test(buf)) end(true, "");
      else if (/^a1 (NO|BAD)/mi.test(buf)) end(false, "IMAP menolak: " + (buf.match(/^a1 .*/mi) || [""])[0].slice(0, 80));
    });
  });
}

const sign = (p) => crypto.createHmac("sha256", process.env.SESSION_SECRET).update(p).digest("base64url");
function makeToken(address) {
  const p = Buffer.from(JSON.stringify({ a: address, e: Date.now() + TTL })).toString("base64url");
  return p + "." + sign(p);
}
function readToken(header) {
  const [p, s] = String(header || "").replace(/^Bearer /, "").split(".");
  if (!p || !s) return null;
  const a = Buffer.from(s), b = Buffer.from(sign(p));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const d = JSON.parse(Buffer.from(p, "base64url").toString());
    return d.e > Date.now() ? d.a : null;
  } catch { return null; }
}
const recent = (k) => { const n = Date.now(); const f = (fails.get(k) || []).filter((t) => n - t < 600000); fails.set(k, f); return f; };

exports.handler = async (event) => {
  const q = event.queryStringParameters || {};
  if (!process.env.SESSION_SECRET || !process.env.SMTPDEV_API_KEY) return reply(500, { error: "Konfigurasi server belum lengkap" });
  try {
    if (q.action === "login") {
      if (event.httpMethod !== "POST") return reply(405, { error: "method" });
      let b; try { b = JSON.parse(event.body || "{}"); } catch { b = {}; }
      const address = String(b.address || "").trim().toLowerCase();
      const password = String(b.password || "");
      const bad = (why) => { recent(address).push(Date.now()); return reply(401, { error: "Email atau password salah" + (process.env.DEBUG_LOGIN === "1" && why ? " [" + why + "]" : "") }); };
      if (!address || !password) return bad();
      if (process.env.DEBUG_LOGIN !== "1" && recent(address).length >= 5) return reply(429, { error: "Terlalu banyak percobaan. Coba lagi dalam 10 menit." });
      let why = "";
      try {
        await accountId(address);
        const r = await imapLogin(address, password);
        if (r.ok) return reply(200, { token: makeToken(address), address });
        why = r.why;
      } catch (e) { why = "API smtp.dev: " + e.message; }
      return bad(why);
    }

    const address = readToken(event.headers.authorization);
    if (!address) return reply(401, { error: "unauthorized" });
    const id = await accountId(address);
    const box = `/accounts/${id}/mailboxes/${enc(q.mailbox || "")}`;
    const msg = `${box}/messages/${enc(q.id || "")}`;
    switch (q.action) {
      case "check":
        return reply(200, { address });
      case "mailboxes":
        return reply(200, members(await smtp(`/accounts/${id}/mailboxes`)));
      case "messages": {
        const r = await smtp(`${box}/messages?page=${Number(q.page) || 1}`);
        return reply(200, { items: members(r), next: hasNext(r) });
      }
      case "message": {
        const m = await smtp(msg);
        if (!m.isRead) {
          await smtp(msg, {
            method: "PATCH",
            headers: { "Content-Type": "application/merge-patch+json" },
            body: JSON.stringify({ isRead: true }),
          }).catch(() => {});
        }
        return reply(200, m);
      }
      case "delete":
        if (event.httpMethod !== "POST") return reply(405, { error: "method" });
        await smtp(msg, { method: "DELETE" });
        return reply(200, { ok: true });
      default:
        return reply(400, { error: "action" });
    }
  } catch (e) {
    return reply(502, { error: e.message });
  }
};
