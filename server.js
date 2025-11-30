// server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// allow your frontend origin and allow cookies
app.use(cors({
  origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
  credentials: true
}));

// simple rate limiter on auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: 'Too many requests, slow down.' }
});

// In-memory user store (demo). Replace with DB in prod.
// We will seed one user from env ADMIN_USER and ADMIN_PASSWORD (hashed on startup)
const users = new Map();

async function seedAdmin() {
  const adminUser = process.env.ADMIN_USER || 'admin';
  const adminPassword = process.env.ADMIN_PASSWORD || 'secret123'; // override in .env
  const saltRounds = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
  // Hash password on startup (do NOT store plain passwords in production)
  const hash = await bcrypt.hash(adminPassword, saltRounds);
  users.set(adminUser, { username: adminUser, passwordHash: hash });
  console.log(`Seeded admin user: ${adminUser}`);
}

seedAdmin().catch(err => {
  console.error('Failed to seed admin user', err);
  process.exit(1);
});

// helper: sign JWT
function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET || 'dev_jwt_secret', {
    expiresIn: process.env.JWT_EXPIRES || '1h'
  });
}

// middleware: protect route
function requireAuth(req, res, next) {
  const token = req.cookies['session_token'];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev_jwt_secret');
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// login route
app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  const user = users.get(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = signToken({ username });
  // set httpOnly cookie. secure:true in prod (requires HTTPS)
  res.cookie('session_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 // 1 hour
  });
  return res.json({ success: true });
});

// logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('session_token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  });
  return res.json({ success: true });
});

// protected endpoint example
app.get('/api/me', requireAuth, (req, res) => {
  return res.json({ username: req.user.username });
});

// optional: register route for testing (rate-limited)
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (users.has(username)) return res.status(409).json({ error: 'User exists' });
  const hash = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS || '12', 10));
  users.set(username, { username, passwordHash: hash });
  return res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Auth server running on http://localhost:${PORT}`);
});

