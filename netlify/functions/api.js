// Penghubung aman antara tampilan inbox dan API smtp.dev.
// API key disimpan di environment variable Netlify, tidak pernah dikirim ke browser.
const crypto = require("crypto");
const BASE = "https://api.smtp.dev";
const enc = encodeURIComponent;
let cachedId;

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

async function accountId() {
  if (cachedId) return cachedId;
  const want = (process.env.MAIL_ADDRESS || "").toLowerCase();
  const r = await smtp("/accounts?address=" + enc(want));
  const acc = (r.member || []).find((a) => a.address.toLowerCase() === want);
  if (!acc) throw new Error("Akun email tidak ditemukan");
  return (cachedId = acc.id);
}

function allowed(event) {
  const a = Buffer.from(event.headers["x-access-password"] || "");
  const b = Buffer.from(process.env.ACCESS_PASSWORD || "");
  return b.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
}

exports.handler = async (event) => {
  if (!allowed(event)) return reply(401, { error: "unauthorized" });
  const q = event.queryStringParameters || {};
  try {
    const id = await accountId();
    const box = `/accounts/${id}/mailboxes/${enc(q.mailbox || "")}`;
    const msg = `${box}/messages/${enc(q.id || "")}`;
    switch (q.action) {
      case "check":
        return reply(200, { address: process.env.MAIL_ADDRESS });
      case "mailboxes":
        return reply(200, (await smtp(`/accounts/${id}/mailboxes`)).member || []);
      case "messages": {
        const r = await smtp(`${box}/messages?page=${Number(q.page) || 1}`);
        return reply(200, { items: r.member || [], next: !!(r.view && r.view.next) });
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
