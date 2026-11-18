// api/reset.js — Hamza Tech Service password-reset email relay.
// Vercel serverless function. Deploy the `server/` folder as the Vercel
// project root (see server/README.md). The desktop app POSTs JSON
// {email, code, shop}; this emails the 6-digit code to the shop's own
// email address via Gmail SMTP. No database.
//
// Env vars (Vercel project settings — NEVER hardcode credentials):
//   GMAIL_USER          — the Gmail address the code is sent FROM
//   GMAIL_APP_PASSWORD  — a Gmail App Password (Google Account → Security →
//                         2-Step Verification → App passwords), NOT the
//                         normal Gmail password.
//
// Rate limiting is IN-MEMORY (per function instance): 10/hour per IP,
// 5/hour per email. Limitation: Vercel may run several instances of this
// function, each with its own memory, so the limits are approximate — a
// determined sender could get a few multiples of the limit through. For a
// 6-digit code that expires in 15 minutes and allows 5 attempts, that is
// an acceptable trade-off; use Vercel KV / Upstash if strict limits are
// ever needed.
//
// Response contract (matches the PHP alternative, server/reset-relay.php):
//   200 { ok: true }                        — email sent
//   400 { ok: false, error: '...' }         — bad request (email/code)
//   405 { ok: false, error: 'POST only' }   — wrong method
//   429 { ok: false, error: 'Too many requests, try later' }
//   500 { ok: false, error: '...' }         — mail not configured / send failed
'use strict';

const nodemailer = require('nodemailer');

const REPLY_TO = 'sajanwebdevelper@gmail.com';
const MAX_PER_IP = 10;
const MAX_PER_EMAIL = 5;
const WINDOW_MS = 60 * 60 * 1000;

// In-memory rate-limit store: key ('ip:<ip>' / 'em:<email>') → [timestamps].
const rateLimit = new Map();
function rateLimited(key, max) {
  const now = Date.now();
  const hits = (rateLimit.get(key) || []).filter(t => now - t < WINDOW_MS);
  if (hits.length >= max) {
    rateLimit.set(key, hits);
    return true;
  }
  hits.push(now);
  rateLimit.set(key, hits);
  return false;
}

function sendJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(obj));
}

function clientIp(req) {
  const fwd = req.headers && req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd) return fwd.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    sendJson(res, 405, { ok: false, error: 'POST only' });
    return;
  }

  let data = req.body;
  if (typeof data === 'string') {
    try { data = JSON.parse(data); } catch { data = null; }
  }
  if (!data || typeof data !== 'object') {
    sendJson(res, 400, { ok: false, error: 'Bad JSON' });
    return;
  }

  const email = String(data.email || '').trim();
  const code = String(data.code || '').trim();
  // Strip newlines (header-injection protection) and cap length.
  const shop = String(data.shop || '').replace(/[\r\n]+/g, ' ').slice(0, 100);

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    sendJson(res, 400, { ok: false, error: 'Invalid email' });
    return;
  }
  if (!/^\d{6}$/.test(code)) {
    sendJson(res, 400, { ok: false, error: 'Invalid code' });
    return;
  }

  const ip = clientIp(req);
  if (rateLimited('ip:' + ip, MAX_PER_IP) || rateLimited('em:' + email.toLowerCase(), MAX_PER_EMAIL)) {
    sendJson(res, 429, { ok: false, error: 'Too many requests, try later' });
    return;
  }

  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass) {
    sendJson(res, 500, { ok: false, error: 'Mail service is not configured' });
    return;
  }

  const subject = 'Password Reset Code' + (shop !== '' ? ' — ' + shop : '');
  const body =
    'Assalam-o-Alaikum,\n\n' +
    'Aap ne apne shop software ka password reset karne ki request ki hai.\n\n' +
    'Reset code: ' + code + '\n\n' +
    'Ye code 15 minute ke liye valid hai. Software mein ye code daal kar naya password set kar lein.\n\n' +
    'Agar aap ne ye request nahi ki to is email ko ignore kar dein.\n\n' +
    '— Hamza Tech Service\n0307-4347460 | sajanwebdevelper@gmail.com\n';

  try {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: { user, pass },
    });
    await transporter.sendMail({
      from: '"Hamza Tech Service" <' + user + '>',
      to: email,
      replyTo: REPLY_TO,
      subject,
      text: body,
    });
    sendJson(res, 200, { ok: true });
  } catch (e) {
    sendJson(res, 500, { ok: false, error: 'Mail send failed' });
  }
}

// Test-only: clear the in-memory rate-limit store between tests.
handler._resetRateLimit = () => rateLimit.clear();

module.exports = handler;
