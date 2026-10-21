import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const users = () => getStore({ name: "users", consistency: "strong" });
const datas = () => getStore({ name: "userdata", consistency: "strong" });
const conf = () => getStore({ name: "config", consistency: "strong" });

const json = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

let SECRET;
async function secret() {
  if (SECRET) return SECRET;
  if (process.env.JWT_SECRET) return (SECRET = process.env.JWT_SECRET);
  let s = await conf().get("secret");
  if (!s) { s = crypto.randomBytes(32).toString("hex"); await conf().set("secret", s); }
  return (SECRET = s);
}
async function sign(p) {
  const body = Buffer.from(JSON.stringify(p)).toString("base64url");
  const sig = crypto.createHmac("sha256", await secret()).update(body).digest("base64url");
  return body + "." + sig;
}
async function verify(t) {
  if (!t) return null;
  const [body, sig] = t.split(".");
  if (!body || !sig) return null;
  const exp = crypto.createHmac("sha256", await secret()).update(body).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(exp);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
const hash = (pw, salt) =>
  new Promise((res, rej) => crypto.scrypt(pw, salt, 64, (e, k) => (e ? rej(e) : res(k.toString("hex")))));
const uid = (email) => crypto.createHash("sha256").update(email).digest("hex").slice(0, 24);
const pub = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, photo: u.photo || "", created: u.created });
const token = (u) => sign({ id: u.id, exp: Date.now() + 1000 * 60 * 60 * 24 * 60 });

export default async (req) => {
  const path = new URL(req.url).pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  const m = req.method;
  try {
    // ---------- public ----------
    if (path[0] === "register" && m === "POST") {
      const b = await req.json();
      const name = String(b.name || "").trim().slice(0, 40);
      const email = String(b.email || "").trim().toLowerCase();
      const password = String(b.password || "");
      if (!name) return json({ error: "নাম দিন" }, 400);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "সঠিক ইমেইল দিন" }, 400);
      if (password.length < 6) return json({ error: "পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে" }, 400);
      const id = uid(email);
      if (await users().get(id)) return json({ error: "এই ইমেইলে আগেই অ্যাকাউন্ট আছে" }, 409);
      const { blobs } = await users().list();
      const admin = blobs.length === 0 || (process.env.ADMIN_EMAIL || "").toLowerCase() === email;
      const salt = crypto.randomBytes(16).toString("hex");
      const u = { id, name, email, salt, pass: await hash(password, salt), role: admin ? "admin" : "user", photo: "", created: Date.now() };
      await users().setJSON(id, u);
      return json({ token: await token(u), user: pub(u) });
    }
    if (path[0] === "login" && m === "POST") {
      const b = await req.json();
      const email = String(b.email || "").trim().toLowerCase();
      const u = await users().get(uid(email), { type: "json" });
      if (!u) return json({ error: "ইমেইল বা পাসওয়ার্ড ভুল" }, 401);
      const h = await hash(String(b.password || ""), u.salt);
      if (!crypto.timingSafeEqual(Buffer.from(h), Buffer.from(u.pass))) return json({ error: "ইমেইল বা পাসওয়ার্ড ভুল" }, 401);
      return json({ token: await token(u), user: pub(u) });
    }

    // ---------- logged in ----------
    const p = await verify((req.headers.get("authorization") || "").replace(/^Bearer\s+/i, ""));
    if (!p) return json({ error: "আবার লগইন করুন" }, 401);
    const me = await users().get(p.id, { type: "json" });
    if (!me) return json({ error: "অ্যাকাউন্টটি আর নেই" }, 401);

    if (path[0] === "me" && m === "GET") {
      return json({ user: pub(me), data: (await datas().get(me.id, { type: "json" })) || null });
    }
    if (path[0] === "data" && m === "PUT") {
      const text = await req.text();
      if (text.length > 4_000_000) return json({ error: "ডেটা অনেক বড়" }, 413);
      const d = JSON.parse(text);
      if (!d || !Array.isArray(d.tx)) return json({ error: "ডেটা সঠিক নয়" }, 400);
      d.updatedAt = Date.now();
      await datas().setJSON(me.id, d);
      return json({ ok: true, updatedAt: d.updatedAt });
    }
    if (path[0] === "profile" && m === "PUT") {
      const b = await req.json();
      if (typeof b.photo === "string") {
        if (b.photo && (!b.photo.startsWith("data:image/") || b.photo.length > 200_000)) return json({ error: "ছবি সঠিক নয়" }, 400);
        me.photo = b.photo;
      }
      if (typeof b.name === "string" && b.name.trim()) me.name = b.name.trim().slice(0, 40);
      await users().setJSON(me.id, me);
      return json({ user: pub(me) });
    }

    // ---------- admin ----------
    if (path[0] === "admin") {
      if (me.role !== "admin") return json({ error: "অনুমতি নেই" }, 403);
      if (path[1] === "users" && m === "GET" && !path[2]) {
        const { blobs } = await users().list();
        const list = [];
        for (const k of blobs) {
          const u = await users().get(k.key, { type: "json" });
          if (!u) continue;
          const d = await datas().get(u.id, { type: "json" });
          list.push({ ...pub(u), tx: d?.tx?.length || 0 });
        }
        list.sort((a, b) => a.created - b.created);
        return json({ users: list });
      }
      if (path[1] === "users" && m === "DELETE" && path[2]) {
        if (path[2] === me.id) return json({ error: "নিজেকে ডিলিট করা যাবে না" }, 400);
        await users().delete(path[2]);
        await datas().delete(path[2]);
        return json({ ok: true });
      }
    }
    return json({ error: "পাওয়া যায়নি" }, 404);
  } catch (e) {
    return json({ error: "সার্ভারে সমস্যা হয়েছে" }, 500);
  }
};

export const config = { path: "/api/*" };
