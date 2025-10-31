'use strict';
/**
 * PhongNews Backend — Fullstack Version
 * - Lưu trữ: Vercel KV (Upstash Redis)
 * - Gồm: /api/auth/* và /api/data/*
 * - Không phân quyền, dữ liệu dùng chung
 * - Export app cho Vercel (serverless)
 */

const express = require('express');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const { Redis } = require('@upstash/redis');

dotenv.config();
const app = express();

// ===== Cấu hình CORS tương thích Vercel =====
const allowedOrigin = "https://wingovn.netlify.app";

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }
  next();
});

app.use(express.json());
app.use(morgan('dev'));

// ===== Kết nối KV (Upstash Redis) =====
const redis = new Redis({
  url: process.env.KV_REST_API_URL,
  token: process.env.KV_REST_API_TOKEN
});

// ===== Helper =====
const JWT_SECRET = process.env.JWT_SECRET || 'change_me_secret';

function safeUser(u) {
  if (!u) return null;
  const { password, ...rest } = u;
  return rest;
}

function baseUrlFromReq(req) {
  const proto = (req.headers['x-forwarded-proto'] || 'https');
  const host = (req.headers['x-forwarded-host'] || req.headers['host']);
  return process.env.PUBLIC_BASE_URL || `${proto}://${host}`;
}

// ===== MAIL =====
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

async function sendMail(opts) {
  return mailer.sendMail({
    from: process.env.MAIL_FROM || 'PhongNews <no-reply@phongnews.local>',
    ...opts
  });
}

// ===== USERS =====
async function readUsers() {
  return (await redis.get('users')) || [];
}
async function saveUsers(data) {
  await redis.set('users', data);
}
async function readPending() {
  return (await redis.get('pending')) || {};
}
async function savePending(data) {
  await redis.set('pending', data);
}

// ===== AUTH API =====

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: 'Thiếu thông tin.' });

    const users = await readUsers();
    const existed = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (existed) return res.status(409).json({ message: 'Email đã tồn tại.' });

    const hash = await bcrypt.hash(password, 10);
    const userDraft = { name, email, password: hash, createdAt: new Date().toISOString(), approved: false };

    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '7d' });
    const pending = await readPending();
    pending[token] = userDraft;
    await savePending(pending);

    const approveUrl = `${baseUrlFromReq(req)}/api/auth/approve?token=${token}`;
    await sendMail({
      to: process.env.ADMIN_EMAIL,
      subject: 'Có tài khoản đăng ký mới cần duyệt',
      html: `<p>${name} (${email})</p><p>Duyệt: <a href="${approveUrl}">${approveUrl}</a></p>`
    });

    res.json({ message: 'Đăng ký thành công. Vui lòng chờ duyệt.' });
  } catch (e) {
    res.status(500).json({ message: 'Lỗi đăng ký', error: e.message });
  }
});

// Approve
app.get('/api/auth/approve', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Thiếu token.');

  const pending = await readPending();
  const draft = pending[token];
  if (!draft) return res.status(404).send('Token không hợp lệ.');

  const users = await readUsers();
  users.push({ ...draft, approved: true });
  await saveUsers(users);
  delete pending[token];
  await savePending(pending);
  res.send('Phê duyệt thành công.');
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const users = await readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) return res.status(404).json({ message: 'Không tìm thấy người dùng.' });
  if (!user.approved) return res.status(403).json({ message: 'Chưa được duyệt.' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ message: 'Sai mật khẩu.' });

  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: safeUser(user) });
});

// Forgot password
app.post('/api/auth/forgot', async (req, res) => {
  const { email } = req.body;
  const users = await readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) return res.status(404).json({ message: 'Không tìm thấy người dùng.' });

  const tmp = Math.random().toString(36).slice(2, 8);
  user.password = await bcrypt.hash(tmp, 10);
  await saveUsers(users);
  await sendMail({ to: email, subject: 'Mật khẩu tạm thời', text: `Mật khẩu tạm: ${tmp}` });
  res.json({ message: 'Đã gửi mật khẩu tạm thời.' });
});

// ===== DATA API (Dữ liệu resort) =====
const allowedTables = ['rooms', 'guests', 'bookings', 'invoices', 'settings'];

app.get('/api/data/:table', async (req, res) => {
  const { table } = req.params;
  if (!allowedTables.includes(table)) return res.status(400).json({ message: 'Table không hợp lệ' });
  const data = (await redis.get(`data_${table}`)) || [];
  res.json(data);
});

app.post('/api/data/:table', async (req, res) => {
  const { table } = req.params;
  if (!allowedTables.includes(table)) return res.status(400).json({ message: 'Table không hợp lệ' });
  const item = req.body;
  const list = (await redis.get(`data_${table}`)) || [];
  list.push({ ...item, id: Date.now() });
  await redis.set(`data_${table}`, list);
  res.json({ ok: true });
});

app.put('/api/data/:table/:id', async (req, res) => {
  const { table, id } = req.params;
  const list = (await redis.get(`data_${table}`)) || [];
  const idx = list.findIndex(i => String(i.id) === String(id));
  if (idx === -1) return res.status(404).json({ message: 'Không tìm thấy mục' });
  list[idx] = { ...list[idx], ...req.body };
  await redis.set(`data_${table}`, list);
  res.json({ ok: true });
});

app.delete('/api/data/:table/:id', async (req, res) => {
  const { table, id } = req.params;
  const list = (await redis.get(`data_${table}`)) || [];
  const newList = list.filter(i => String(i.id) !== String(id));
  await redis.set(`data_${table}`, newList);
  res.json({ ok: true });
});

// Health
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ===== Export cho Vercel =====
if (!process.env.VERCEL) {
  app.listen(3000, () => console.log('Running local at http://localhost:3000'));
} else {
  module.exports = app;
}
