require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');
const { OAuth2Client } = require('google-auth-library');

const { DATABASE_URL, JWT_SECRET, BREVO_API_KEY, MAIL_FROM, GOOGLE_CLIENT_ID, PORT = 3000 } = process.env;
const APP_URL = (process.env.APP_URL || '').replace(/\/$/, '');
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || 'Kite Shield';
if (!DATABASE_URL || !JWT_SECRET) { console.error('Set DATABASE_URL and JWT_SECRET'); process.exit(1); }

const db = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const gclient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

const app = express();
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", 'https://accounts.google.com/gsi/client'],
    styleSrc: ["'self'", "'unsafe-inline'", 'https://accounts.google.com/gsi/style'],
    frameSrc: ['https://accounts.google.com/gsi/'],
    connectSrc: ["'self'", 'https://accounts.google.com/gsi/'],
    imgSrc: ["'self'", 'data:', 'https:']
  } },
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' }
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/auth', rateLimit({
  windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in a few minutes.' }
}));

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const clean = s => String(s || '').trim();
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const pub = u => ({ id: u.id, name: u.name, email: u.email, phone: u.phone, verified: u.email_verified });

function setSession(res, user) {
  const token = jwt.sign({ sub: user.id }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '7d' });
  res.cookie('ks_session', token, {
    httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7 * 864e5
  });
}

async function sendMail(to, name, subject, html) {
  if (!BREVO_API_KEY || !MAIL_FROM) { console.log('[mail skipped: set BREVO_API_KEY and MAIL_FROM]', to, subject); return false; }
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { name: MAIL_FROM_NAME, email: MAIL_FROM }, to: [{ email: to, name }], subject, htmlContent: html })
  });
  if (!r.ok) console.error('Brevo error', r.status, await r.text());
  return r.ok;
}

async function issueVerification(user) {
  const raw = crypto.randomBytes(32).toString('hex');
  await db.query("update users set verify_hash=$1, verify_expires=now()+interval '24 hours' where id=$2", [sha(raw), user.id]);
  const link = `${APP_URL}/api/auth/verify?token=${raw}`;
  await sendMail(user.email, user.name, 'Verify your Kite Shield email',
    `<p>Hi ${esc(user.name)},</p><p>Confirm your email to activate your account:</p>` +
    `<p><a href="${link}">Verify my email</a></p>` +
    `<p>This link expires in 24 hours. If you did not sign up, you can ignore this message.</p>`);
}

app.get('/api/config', (req, res) => res.json({ googleClientId: GOOGLE_CLIENT_ID || null }));

app.post('/api/auth/signup', async (req, res) => {
  const name = clean(req.body.name), email = clean(req.body.email).toLowerCase();
  const phone = clean(req.body.phone), pw = String(req.body.password || '');
  if (name.length < 2 || name.length > 80) return res.status(400).json({ error: 'Enter your full name.' });
  if (!EMAIL.test(email) || email.length > 254) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (pw.length < 8 || pw.length > 72) return res.status(400).json({ error: 'Password must be 8 to 72 characters.' });
  if (phone && !/^\+?[0-9 ()-]{7,20}$/.test(phone)) return res.status(400).json({ error: 'Enter a valid phone number.' });
  try {
    const hash = await bcrypt.hash(pw, 12);
    const r = await db.query(
      'insert into users(name,email,phone,password_hash) values($1,$2,$3,$4) on conflict (email) do nothing returning *',
      [name, email, phone || null, hash]);
    if (r.rows[0]) await issueVerification(r.rows[0]);
    res.json({ message: 'Check your email for a verification link.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Something went wrong. Try again.' }); }
});

app.get('/api/auth/verify', async (req, res) => {
  const t = clean(req.query.token);
  try {
    const r = t && await db.query(
      'update users set email_verified=true, verify_hash=null, verify_expires=null where verify_hash=$1 and verify_expires>now() returning *', [sha(t)]);
    if (r && r.rows[0]) { setSession(res, r.rows[0]); return res.redirect('/?verified=1'); }
  } catch (e) { console.error(e); }
  res.redirect('/?verified=0');
});

app.post('/api/auth/resend', async (req, res) => {
  const email = clean(req.body.email).toLowerCase();
  try {
    const r = await db.query('select * from users where email=$1 and email_verified=false and password_hash is not null', [email]);
    if (r.rows[0]) await issueVerification(r.rows[0]);
  } catch (e) { console.error(e); }
  res.json({ message: 'If that account needs verification, a new link is on its way.' });
});

app.post('/api/auth/login', async (req, res) => {
  const email = clean(req.body.email).toLowerCase(), pw = String(req.body.password || '');
  try {
    const r = await db.query('select * from users where email=$1', [email]);
    const u = r.rows[0];
    const ok = u && u.password_hash && await bcrypt.compare(pw, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Incorrect email or password.' });
    if (!u.email_verified) return res.status(403).json({ error: 'Verify your email first. Check your inbox.', unverified: true });
    setSession(res, u);
    res.json({ user: pub(u) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Something went wrong. Try again.' }); }
});

app.post('/api/auth/google', async (req, res) => {
  if (!gclient) return res.status(503).json({ error: 'Google sign-in is not configured.' });
  try {
    const ticket = await gclient.verifyIdToken({ idToken: String(req.body.credential || ''), audience: GOOGLE_CLIENT_ID });
    const p = ticket.getPayload();
    if (!p.email || !p.email_verified) return res.status(400).json({ error: 'Your Google email is not verified.' });
    const email = p.email.toLowerCase();
    // If an unverified password account already used this email, drop its password so it cannot be used to take over.
    const r = await db.query(
      `insert into users(name,email,google_id,email_verified) values($1,$2,$3,true)
       on conflict (email) do update set
         google_id = coalesce(users.google_id, excluded.google_id),
         password_hash = case when users.email_verified then users.password_hash else null end,
         email_verified = true
       returning *`, [p.name || email.split('@')[0], email, p.sub]);
    setSession(res, r.rows[0]);
    res.json({ user: pub(r.rows[0]) });
  } catch (e) { console.error(e.message); res.status(401).json({ error: 'Google sign-in failed. Try again.' }); }
});

app.get('/api/me', async (req, res) => {
  try {
    const { sub } = jwt.verify(req.cookies.ks_session || '', JWT_SECRET, { algorithms: ['HS256'] });
    const r = await db.query('select * from users where id=$1', [sub]);
    if (!r.rows[0]) throw new Error('no user');
    res.json({ user: pub(r.rows[0]) });
  } catch (e) { res.status(401).json({ error: 'Not signed in.' }); }
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('ks_session'); res.json({ ok: true }); });

app.listen(PORT, () => console.log('Kite Shield auth listening on ' + PORT));
