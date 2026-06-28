/**
 * Duck Bot for Carla — all-in-one Cloudflare Worker (Web Push, no passcode).
 *   Secrets : VAPID_PRIVATE (JWK JSON string)
 *   Vars    : VENUE, ACTIVITY, VAPID_PUBLIC (default below), VAPID_SUBJECT
 *   KV      : STATE   ("watches", "slotstate", "subs")
 *   Cron    : every 1 minute
 */

const DEFAULTS = {
  VENUE: "west-reservoir-centre",
  ACTIVITY: "open-water-swimming",
  BOT_NAME: "Duck Bot for Carla",
  VAPID_PUBLIC: "BLL5Mq0pGaubKWk4zFl7f5OrOXn2q7FKJZ5C035mCnOvg8Xnf_5jWs_-sxIdvKY94-TpW7c3oIW8ML64Kcd7Ok8",
  VAPID_SUBJECT: "mailto:gabrieljwhitehead@icloud.com",
};
const MAX_HOURS = 24 * 14;

const cfg = (env, k) => (env[k] && String(env[k]).trim()) || DEFAULTS[k] || "";
const nowMs = () => Date.now();

function bookingUrl(env, date) {
  return `https://bookings.better.org.uk/location/${cfg(env, "VENUE")}/${cfg(env, "ACTIVITY")}/${date}/by-time`;
}

async function getWatches(env) { return (await env.STATE.get("watches", { type: "json" })) || []; }
async function putWatches(env, w) { await env.STATE.put("watches", JSON.stringify(w)); }
async function getSlotState(env) { return (await env.STATE.get("slotstate", { type: "json" })) || {}; }
async function getSubs(env) { return (await env.STATE.get("subs", { type: "json" })) || []; }
async function putSubs(env, s) { await env.STATE.put("subs", JSON.stringify(s)); }

async function getAvailability(env, date) {
  const url =
    `https://better-admin.org.uk/api/activities/venue/${cfg(env, "VENUE")}` +
    `/activity/${cfg(env, "ACTIVITY")}/v2/times?date=${encodeURIComponent(date)}`;
  const r = await fetch(url, {
    headers: {
      Accept: "application/json",
      "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      Referer: "https://bookings.better.org.uk/",
      Origin: "https://bookings.better.org.uk",
    },
    cf: { cacheTtl: 0 },
  });
  if (!r.ok) throw new Error(`availability API ${r.status}`);
  const body = await r.json();
  return (body.data || []).map((s) => {
    const status = (s.action_to_show && s.action_to_show.status) || "";
    const spaces = s.spaces_remaining;
    return {
      key: s.composite_key || ((s.starts_at && s.starts_at.format_24_hour) || ""),
      start: (s.starts_at && s.starts_at.format_24_hour) || "",
      start12: (s.starts_at && s.starts_at.format_12_hour) || "",
      end12: (s.ends_at && s.ends_at.format_12_hour) || "",
      spaces: typeof spaces === "number" ? spaces : null,
      humanDate: (s.date && (s.date.full_date_pretty || s.date.date_pretty)) || date,
      available: status === "BOOK" || (typeof spaces === "number" && spaces > 0),
    };
  });
}

// =============================== WEB PUSH ===================================
const _enc = new TextEncoder();
function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  s += "=".repeat(pad);
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function bytesToB64url(buf) {
  const u = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function concatU8(...a) {
  let n = a.reduce((x, y) => x + y.length, 0);
  let o = new Uint8Array(n), p = 0;
  for (const x of a) { o.set(x, p); p += x.length; }
  return o;
}
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const b = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, len * 8);
  return new Uint8Array(b);
}
async function encryptPayload(payloadStr, p256dhB64, authB64) {
  const uaPub = b64urlToBytes(p256dhB64);
  const auth = b64urlToBytes(authB64);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const as = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", as.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(auth, ecdh, concatU8(_enc.encode("WebPush: info\0"), uaPub, asPub), 32);
  const cek = await hkdf(salt, ikm, _enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, _enc.encode("Content-Encoding: nonce\0"), 12);
  const pt = concatU8(_enc.encode(payloadStr), new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, pt));
  const header = concatU8(salt, new Uint8Array([0, 0, 0x10, 0]), new Uint8Array([asPub.length]), asPub);
  return concatU8(header, ct);
}
async function vapidAuth(endpoint, env) {
  const aud = new URL(endpoint).origin;
  const jwk = JSON.parse(cfg(env, "VAPID_PRIVATE"));
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const header = bytesToB64url(_enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const payload = bytesToB64url(_enc.encode(JSON.stringify({
    aud, exp: Math.floor(Date.now() / 1000) + 43200, sub: cfg(env, "VAPID_SUBJECT"),
  })));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, _enc.encode(header + "." + payload)));
  return { jwt: header + "." + payload + "." + bytesToB64url(sig), pub: cfg(env, "VAPID_PUBLIC") };
}
async function sendPush(env, sub, payloadObj) {
  try {
    if (!cfg(env, "VAPID_PRIVATE")) return { status: 0, error: "VAPID_PRIVATE not set" };
    const body = await encryptPayload(JSON.stringify(payloadObj), sub.keys.p256dh, sub.keys.auth);
    const { jwt, pub } = await vapidAuth(sub.endpoint, env);
    const r = await fetch(sub.endpoint, {
      method: "POST",
      headers: {
        Authorization: "vapid t=" + jwt + ", k=" + pub,
        "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream",
        TTL: "2419200",
        Urgency: "high",
      },
      body,
    });
    return { status: r.status };
  } catch (e) {
    return { status: 0, error: String(e.message || e) };
  }
}
async function pushAll(env, payloadObj) {
  const subs = await getSubs(env);
  if (!subs.length) return { subs: 0, sent: 0, results: [] };
  const results = [], keep = [];
  for (const s of subs) {
    const r = await sendPush(env, s, payloadObj);
    results.push(r.status || r.error);
    if (r.status !== 404 && r.status !== 410) keep.push(s);
  }
  if (keep.length !== subs.length) await putSubs(env, keep);
  return { subs: subs.length, sent: results.filter((x) => x >= 200 && x < 300).length, results };
}

function matches(slot, sessions) {
  return !sessions || sessions.length === 0 || sessions.includes(slot.start);
}

async function runCheck(env) {
  let watches = await getWatches(env);
  const t = nowMs();
  const live = watches.filter((w) => w.expiresAt > t);
  if (live.length !== watches.length) { await putWatches(env, live); watches = live; }
  if (watches.length === 0) return { active: 0, alerts: 0 };

  const dates = [...new Set(watches.map((w) => w.date))];
  const slotState = await getSlotState(env);
  let stateChanged = false, alerts = 0;

  for (const date of dates) {
    let slots;
    try { slots = await getAvailability(env, date); }
    catch (e) { console.log(`availability error ${date}: ${e.message}`); continue; }
    const watchesForDate = watches.filter((w) => w.date === date);

    for (const slot of slots) {
      const sk = `${date}|${slot.key}`;
      const prev = slotState[sk];
      const interested = watchesForDate.some((w) => matches(slot, w.sessions));
      if (interested && slot.available && prev === false) {
        alerts++;
        const spacesTxt = slot.spaces != null ? `${slot.spaces} space(s)` : "available";
        await pushAll(env, {
          title: `🦆 Cancellation — ${slot.start} swim`,
          body: `${slot.start12}${slot.end12 ? "–" + slot.end12 : ""} on ${slot.humanDate} · ${spacesTxt}`,
          url: bookingUrl(env, date),
        });
      }
      if (slotState[sk] !== slot.available) { slotState[sk] = slot.available; stateChanged = true; }
    }
  }
  for (const sk of Object.keys(slotState)) {
    if (!dates.includes(sk.split("|")[0])) { delete slotState[sk]; stateChanged = true; }
  }
  if (stateChanged) await env.STATE.put("slotstate", JSON.stringify(slotState));
  return { active: watches.length, alerts };
}

// ============================ WEB / API =====================================
function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8" } });
}
function publicWatch(env, w) {
  return {
    id: w.id, date: w.date, sessions: w.sessions, createdBy: w.createdBy || "",
    createdAt: w.createdAt, expiresAt: w.expiresAt,
    minutesLeft: Math.max(0, Math.round((w.expiresAt - nowMs()) / 60000)),
  };
}

async function handleApi(request, env, path, url) {
  if (request.method === "GET" && path === "/api/vapidkey") {
    return json({ key: cfg(env, "VAPID_PUBLIC") });
  }
  if (request.method === "GET" && path === "/api/availability") {
    const date = url.searchParams.get("date") || "";
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return json({ ok: false, error: "bad date" }, 400);
    const slots = await getAvailability(env, date);
    return json({ ok: true, date, slots, bookingUrl: bookingUrl(env, date) });
  }
  if (request.method === "GET" && path === "/api/watches") {
    const watches = (await getWatches(env)).filter((w) => w.expiresAt > nowMs());
    return json({ ok: true, watches: watches.map((w) => publicWatch(env, w)) });
  }
  if (request.method === "POST" && path === "/api/watch") {
    const b = await request.json().catch(() => ({}));
    const date = String(b.date || "").trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return json({ ok: false, error: "bad date" }, 400);
    let hours = Number(b.hours);
    if (!isFinite(hours) || hours <= 0) hours = 3;
    hours = Math.min(MAX_HOURS, Math.max(0.1, hours));
    const sessions = Array.isArray(b.sessions) ? b.sessions.filter((s) => /^\d{2}:\d{2}$/.test(s)) : [];
    const watches = (await getWatches(env)).filter((w) => w.expiresAt > nowMs());
    const w = { id: crypto.randomUUID(), date, sessions, hours, createdBy: "", createdAt: nowMs(), expiresAt: nowMs() + hours * 3600 * 1000 };
    watches.push(w);
    await putWatches(env, watches);
    return json({ ok: true, watch: publicWatch(env, w) });
  }
  if (request.method === "POST" && path === "/api/cancel") {
    const b = await request.json().catch(() => ({}));
    const id = String(b.id || "");
    const watches = (await getWatches(env)).filter((w) => w.expiresAt > nowMs() && w.id !== id);
    await putWatches(env, watches);
    return json({ ok: true });
  }
  if (request.method === "POST" && path === "/api/subscribe") {
    const b = await request.json().catch(() => ({}));
    const sub = b.subscription || b;
    if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
      return json({ ok: false, error: "invalid subscription" }, 400);
    }
    const subs = await getSubs(env);
    const rec = { endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth }, createdAt: nowMs() };
    const others = subs.filter((s) => s.endpoint !== sub.endpoint);
    others.push(rec);
    await putSubs(env, others);
    return json({ ok: true, devices: others.length });
  }
  if (request.method === "POST" && path === "/api/test-alert") {
    const push = await pushAll(env, {
      title: "🦆 Duck Bot for Carla", body: "Test alert — notifications are working!", url: "https://bookings.better.org.uk/",
    });
    return json({ ok: true, push });
  }
  return json({ ok: false, error: "not found" }, 404);
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(runCheck(env).then((r) => console.log("check:", JSON.stringify(r))));
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === "GET" && path === "/") {
      return new Response(PAGE_HTML, { headers: { "content-type": "text/html; charset=utf-8" } });
    }
    if (request.method === "GET" && path === "/sw.js") {
      return new Response(SW_JS, { headers: { "content-type": "application/javascript; charset=utf-8", "Service-Worker-Allowed": "/" } });
    }
    if (request.method === "GET" && path === "/manifest.json") {
      return new Response(MANIFEST, { headers: { "content-type": "application/manifest+json; charset=utf-8" } });
    }
    if (request.method === "GET" && (path === "/icon-180.png" || path === "/icon-192.png" || path === "/icon-512.png")) {
      const b64 = path === "/icon-512.png" ? ICON_512 : path === "/icon-192.png" ? ICON_192 : ICON_180;
      return new Response(b64urlToBytes(b64.replace(/\+/g, "-").replace(/\//g, "_")), {
        headers: { "content-type": "image/png", "cache-control": "public, max-age=86400" },
      });
    }
    if (path.startsWith("/api/")) {
      try { return await handleApi(request, env, path, url); }
      catch (e) { return json({ ok: false, error: String(e.message || e) }, 502); }
    }
    return new Response("Not found", { status: 404 });
  },
};

const MANIFEST = JSON.stringify({
  name: "Duck Bot for Carla", short_name: "Duck Bot", start_url: "/", scope: "/",
  display: "standalone", background_color: "#bfe8ff", theme_color: "#2f6f4f",
  icons: [
    { src: "/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any maskable" },
    { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any maskable" },
  ],
});

const SW_JS = `
self.addEventListener('install', (e) => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('push', (event) => {
  let d = { title: 'Duck Bot for Carla', body: '', url: '/' };
  try { d = event.data.json(); } catch (e) { try { d.body = event.data.text(); } catch (_) {} }
  event.waitUntil(self.registration.showNotification(d.title || 'Duck Bot for Carla', {
    body: d.body || '', icon: '/icon-192.png', badge: '/icon-192.png',
    tag: 'duck', renotify: true, data: { url: d.url || '/' },
  }));
});
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((cl) => {
    for (const c of cl) { if ('focus' in c) { c.navigate(url); return c.focus(); } }
    return self.clients.openWindow(url);
  }));
});
`;

const DUCK = `<svg class="duck" viewBox="0 0 80 70" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <ellipse cx="40" cy="64" rx="26" ry="5" fill="#ffffff" opacity="0.35"/>
  <ellipse cx="36" cy="44" rx="24" ry="16" fill="#ffd23f"/>
  <path d="M14 42 q-9 2 -12 9 q10 1 14 -3 z" fill="#ffcf2e"/>
  <ellipse cx="40" cy="46" rx="11" ry="9" fill="#ffe27a" opacity="0.7"/>
  <circle cx="54" cy="28" r="13" fill="#ffd23f"/>
  <path d="M40 27 a14 14 0 0 1 28 0 q-14 -7 -28 0 z" fill="#e23b3b"/>
  <circle cx="54" cy="13" r="3" fill="#b91c1c"/>
  <path d="M40 27 q-3 1 -3 3" stroke="#b91c1c" stroke-width="2" fill="none" stroke-linecap="round"/>
  <circle cx="58" cy="29" r="2.4" fill="#1f2937"/>
  <path d="M66 30 l13 3 l-13 4 q-2 -3 0 -7 z" fill="#f59e0b"/>
</svg>`;

const PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
<title>Duck Bot for Carla</title>
<link rel="manifest" href="/manifest.json" />
<meta name="theme-color" content="#7cc4e8" />
<meta name="apple-mobile-web-app-capable" content="yes" />
<meta name="apple-mobile-web-app-status-bar-style" content="default" />
<meta name="apple-mobile-web-app-title" content="Duck Bot" />
<link rel="apple-touch-icon" href="/icon-180.png" />
<style>
  :root{--ink:#143246;--muted:#5b7488;--line:#d7e6ef;--accent:#1f7a8c;--accent2:#2f9e73;
    --open:#137a4a;--open-bg:#e4f7ec;--full:#a83a3a;--full-bg:#fbe9e9;--r:16px;}
  *{box-sizing:border-box}
  html,body{margin:0;min-height:100%}
  body{color:var(--ink);padding:18px 16px 40px;position:relative;overflow-x:hidden;
    font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    background:linear-gradient(180deg,#cdeffb 0%,#a6dcf2 30%,#6fc1e8 70%,#4aa8d8 100%);
    background-attachment:fixed}
  body::before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.5;
    background:
      radial-gradient(120px 18px at 20% 30%, rgba(255,255,255,.45), transparent 70%),
      radial-gradient(160px 20px at 75% 55%, rgba(255,255,255,.35), transparent 70%),
      radial-gradient(140px 16px at 45% 80%, rgba(255,255,255,.4), transparent 70%);}
  body::after{content:"";position:fixed;left:0;right:0;bottom:0;height:46%;z-index:0;pointer-events:none;opacity:.35;
    background:repeating-linear-gradient(180deg, transparent 0 26px, rgba(255,255,255,.18) 26px 28px);}
  .wrap{max-width:940px;margin:0 auto;position:relative;z-index:2}
  .head{display:flex;align-items:center;gap:10px;margin:2px 0 4px}
  .head h1{font-size:1.5rem;margin:0}
  .duck{width:46px;height:40px;flex:none}
  .head .duck{animation:bob 3s ease-in-out infinite}
  .sub{color:#0f4258;margin:0 0 14px;font-size:.95rem;font-weight:500}
  .banner{background:rgba(255,255,255,.78);border:1px solid var(--line);border-radius:12px;
    padding:10px 13px;font-size:.86rem;color:#13485f;margin-bottom:16px;backdrop-filter:blur(4px)}
  .banner b{color:var(--accent)}
  .cols{display:grid;grid-template-columns:1fr;gap:16px;align-items:start}
  @media(min-width:760px){.cols{grid-template-columns:1fr 1fr}}
  .col{min-width:0}
  .card{background:rgba(255,255,255,.86);border:1px solid var(--line);border-radius:var(--r);
    padding:16px;margin-bottom:16px;backdrop-filter:blur(6px);box-shadow:0 6px 20px rgba(20,70,100,.08)}
  label{display:block;font-weight:700;font-size:.9rem;margin:10px 0 6px}
  input[type=date],input[type=number]{width:100%;padding:11px 12px;border:1px solid var(--line);
    border-radius:10px;font-size:1rem;background:#fff;color:var(--ink)}
  button{width:100%;padding:13px 16px;border:0;border-radius:12px;background:var(--accent);
    color:#fff;font-size:1rem;font-weight:700;cursor:pointer;margin-top:14px;transition:transform .05s}
  button:active{transform:scale(.99)}
  button.go{background:var(--accent2)}
  button.secondary{background:#e7f1f6;color:var(--ink)}
  button.tiny{width:auto;margin:0;padding:6px 12px;font-size:.82rem}
  button:disabled{opacity:.55;cursor:default}
  .slots{display:grid;grid-template-columns:repeat(auto-fill,minmax(72px,1fr));gap:5px;margin-top:10px}
  .slot{display:flex;align-items:center;justify-content:center;gap:4px;padding:6px 3px;border:1.5px solid var(--line);
    border-radius:9px;background:#fff;color:var(--ink);cursor:pointer;font-size:.8rem;font-variant-numeric:tabular-nums;user-select:none}
  .slot .t{font-weight:700}
  .slot.open{border-color:#bfe6cf;background:var(--open-bg);color:#0c5b39}
  .slot.open .b{background:var(--open);color:#fff;border-radius:6px;padding:0 5px;font-size:.7rem;line-height:1.5}
  .slot.full{color:var(--full);background:var(--full-bg);border-color:#f0d7d7}
  .slot.sel{outline:2.5px solid var(--accent);outline-offset:-1px;border-color:var(--accent)}
  .legend{font-size:.74rem;color:var(--muted);margin-top:8px;display:flex;gap:14px;flex-wrap:wrap}
  .legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:4px;vertical-align:-1px}
  .muted{color:var(--muted);font-size:.88rem}.note{font-size:.82rem;color:var(--muted);margin-top:8px}
  .msg{padding:11px 13px;border-radius:10px;margin-top:12px;font-size:.92rem;display:none}
  .msg.ok{background:var(--open-bg);color:var(--open);display:block}
  .msg.err{background:var(--full-bg);color:var(--full);display:block}
  .msg.info{background:#e7f1f6;color:#13485f;display:block}
  .watch{display:flex;gap:8px;align-items:center;padding:8px 0;border-top:1px solid var(--line);font-size:.9rem}
  .watch:first-child{border-top:0}.dot{width:9px;height:9px;border-radius:50%;background:var(--open);flex:none}
  a{color:var(--accent)}.center{text-align:center}
  .floatduck{position:fixed;z-index:1;width:64px;height:56px;opacity:.9;pointer-events:none}
  .floatduck.d1{left:4%;bottom:8%;animation:bob 4s ease-in-out infinite}
  .floatduck.d2{right:6%;bottom:18%;width:48px;height:42px;animation:bob 3.4s ease-in-out infinite .6s}
  .floatduck.d3{right:14%;bottom:3%;width:40px;height:35px;opacity:.8;animation:bob 4.6s ease-in-out infinite .3s}
  @media(max-width:620px){.floatduck.d2{display:none}}
  @keyframes bob{0%,100%{transform:translateY(0) rotate(-2deg)}50%{transform:translateY(-7px) rotate(2deg)}}
</style>
</head>
<body>
<div class="floatduck d1">${DUCK}</div>
<div class="floatduck d2">${DUCK}</div>
<div class="floatduck d3">${DUCK}</div>
<div class="wrap">
  <div class="head">${DUCK}<h1>Duck Bot for Carla</h1></div>
  <p class="sub">Watches West Reservoir for open-water cancellations and pings your phone the second a slot frees up.</p>
  <div class="banner">🗓️ <b>Booking opens ~6–7 days ahead, rolling.</b> A date appears about a week out and the good slots vanish fast — so set a reminder to book the moment your day opens, then let Duck Bot snag any cancellations after that.</div>

  <div class="cols">
   <div class="col">
    <div class="card">
      <label for="date">Date</label>
      <input id="date" type="date" />
      <button id="check" class="secondary">Check availability</button>
      <div id="grid" class="slots"></div>
      <div class="legend"><span><i style="background:#e4f7ec;border:1px solid #bfe6cf"></i>open</span>
        <span><i style="background:#fbe9e9;border:1px solid #f0d7d7"></i>full</span>
        <span>tap a time to watch it</span></div>
      <div id="gridMsg" class="muted center" style="margin-top:10px"></div>
    </div>
   </div>
   <div class="col">
    <div class="card">
      <label for="hours">Watch for (hours)</label>
      <input id="hours" type="number" min="0.5" max="24" step="0.5" value="3" />
      <p class="note">Tap the time(s) above to watch only those, or leave none selected to watch every session that day.</p>
      <button id="start" class="go">Start watching</button>
      <div id="startMsg" class="msg"></div>
    </div>

    <div class="card">
      <strong style="font-size:.95rem">🔔 Notifications on this device</strong>
      <button id="enablePush">Enable notifications</button>
      <div id="pushStatus" class="msg"></div>
      <button id="test" class="secondary">Send test alert</button>
      <div id="testMsg" class="msg"></div>
    </div>

    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <strong style="font-size:.95rem">Active watches</strong>
        <button id="refresh" class="secondary tiny">Refresh</button>
      </div>
      <div id="watches" class="muted" style="margin-top:8px">—</div>
    </div>
   </div>
  </div>
  <p class="note center" style="margin-top:6px">Duck Bot only alerts you — it never books or pays. Be ready to grab the slot yourself. 🦆</p>
</div>

<script>
const $=(i)=>document.getElementById(i);
async function api(path,opts={}){
  const r=await fetch(path,opts);
  const data=await r.json().catch(()=>({ok:false,error:"bad response"}));
  if(!data.ok)throw new Error(data.error||("HTTP "+r.status));
  return data;
}
function setMsg(id,t,ok){const el=$(id);el.className="msg "+(ok===true?"ok":ok==="info"?"info":"err");el.textContent=t;}

$("check").onclick=async()=>{
  const date=$("date").value;if(!date)return;
  $("gridMsg").textContent="Loading…";$("grid").innerHTML="";
  try{const d=await api("/api/availability?date="+encodeURIComponent(date));
    renderGrid(d.slots);$("gridMsg").textContent=d.slots.length?"":"No sessions for that date (it may not be open for booking yet).";
  }catch(e){$("gridMsg").textContent="Error: "+e.message;}
};
function renderGrid(slots){
  const g=$("grid");g.innerHTML="";
  slots.forEach((s)=>{
    const el=document.createElement("button");el.type="button";
    el.className="slot "+(s.available?"open":"full");el.dataset.t=s.start;
    el.innerHTML='<span class="t">'+s.start+'</span>'+(s.available&&s.spaces!=null?'<span class="b">'+s.spaces+'</span>':'');
    el.onclick=()=>el.classList.toggle("sel");
    g.appendChild(el);
  });
}
$("start").onclick=async()=>{
  const date=$("date").value;if(!date){setMsg("startMsg","Pick a date first.",false);return;}
  const sessions=[...$("grid").querySelectorAll(".slot.sel")].map((c)=>c.dataset.t);
  let hours=parseFloat($("hours").value)||3;hours=Math.min(24,Math.max(0.5,hours));$("hours").value=hours;
  $("start").disabled=true;setMsg("startMsg","Starting…",true);
  try{await api("/api/watch",{method:"POST",headers:{"content-type":"application/json"},
      body:JSON.stringify({date,sessions,hours})});
    const scope=sessions.length?sessions.join(", "):"all sessions";
    setMsg("startMsg","✅ Watching "+date+" ("+scope+") for "+hours+"h.",true);loadWatches();
  }catch(e){setMsg("startMsg","Error: "+e.message,false);}finally{$("start").disabled=false;}
};

$("refresh").onclick=loadWatches;
async function loadWatches(){
  $("watches").textContent="Loading…";
  try{const d=await api("/api/watches");
    if(!d.watches.length){$("watches").textContent="No active watches.";return;}
    $("watches").innerHTML="";
    d.watches.forEach((w)=>{
      const div=document.createElement("div");div.className="watch";
      const scope=w.sessions.length?w.sessions.join(", "):"all";
      const h=Math.floor(w.minutesLeft/60),m=w.minutesLeft%60;
      div.innerHTML='<span class="dot"></span><span>'+w.date+' ('+scope+')</span>'+
        '<span class="muted" style="margin-left:auto">'+h+'h'+m+'m left</span>';
      const btn=document.createElement("button");btn.className="secondary tiny";btn.textContent="Stop";
      btn.style.marginLeft="8px";btn.onclick=async()=>{await api("/api/cancel",{method:"POST",
        headers:{"content-type":"application/json"},body:JSON.stringify({id:w.id})});loadWatches();};
      div.appendChild(btn);$("watches").appendChild(div);
    });
  }catch(e){$("watches").textContent="Couldn't load: "+e.message;}
}

function urlB64ToU8(s){const pad="=".repeat((4-s.length%4)%4);const b=(s+pad).replace(/-/g,"+").replace(/_/g,"/");
  const raw=atob(b);const u=new Uint8Array(raw.length);for(let i=0;i<raw.length;i++)u[i]=raw.charCodeAt(i);return u;}
function isIOS(){return /iphone|ipad|ipod/i.test(navigator.userAgent);}
function isStandalone(){return window.navigator.standalone===true||matchMedia("(display-mode: standalone)").matches;}
async function refreshPushState(){
  if(!("serviceWorker" in navigator)||!("PushManager" in window)){setMsg("pushStatus","This browser doesn't support push notifications.","info");return;}
  if(isIOS()&&!isStandalone()){setMsg("pushStatus","On iPhone: tap Share → Add to Home Screen, then open Duck Bot from your Home Screen and tap Enable.","info");return;}
  try{const reg=await navigator.serviceWorker.getRegistration();const sub=reg&&await reg.pushManager.getSubscription();
    if(sub&&Notification.permission==="granted")setMsg("pushStatus","✅ Notifications are on for this device.",true);
    else $("pushStatus").className="msg";
  }catch(e){$("pushStatus").className="msg";}
}
$("enablePush").onclick=async()=>{
  if(!("serviceWorker" in navigator)||!("PushManager" in window)){setMsg("pushStatus","This browser doesn't support push.",false);return;}
  if(isIOS()&&!isStandalone()){setMsg("pushStatus","On iPhone you must first add Duck Bot to your Home Screen: tap Share → Add to Home Screen, then open it from there and tap Enable.","info");return;}
  setMsg("pushStatus","Enabling…",true);
  try{
    const reg=await navigator.serviceWorker.register("/sw.js");await navigator.serviceWorker.ready;
    const perm=await Notification.requestPermission();
    if(perm!=="granted"){setMsg("pushStatus","Permission was not granted.",false);return;}
    const {key}=await (await fetch("/api/vapidkey")).json();
    let sub=await reg.pushManager.getSubscription();
    if(!sub)sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlB64ToU8(key)});
    const res=await api("/api/subscribe",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({subscription:sub.toJSON()})});
    setMsg("pushStatus","✅ Notifications enabled ("+res.devices+" device(s)).",true);
  }catch(e){setMsg("pushStatus","Error: "+e.message,false);}
};
$("test").onclick=async()=>{
  setMsg("testMsg","Sending…",true);
  try{const d=await api("/api/test-alert",{method:"POST"});
    if(d.push.subs===0)setMsg("testMsg","No devices enabled yet — tap Enable notifications first.",false);
    else if(d.push.sent>0)setMsg("testMsg","Sent to "+d.push.sent+" device(s) — check your phone.",true);
    else setMsg("testMsg","Push attempted but provider returned: "+JSON.stringify(d.push.results),false);
  }catch(e){setMsg("testMsg","Error: "+e.message,false);}
};

if("serviceWorker" in navigator){navigator.serviceWorker.register("/sw.js").catch(()=>{});}
(function init(){
  const d=new Date();d.setDate(d.getDate()+1);$("date").value=d.toISOString().slice(0,10);
  loadWatches();refreshPushState();
})();
</script>
</body>
</html>`;

const ICON_180 = "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";
const ICON_192 = "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";
const ICON_512 = "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";
