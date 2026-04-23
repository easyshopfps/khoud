/**
 * Easy Store — Node.js / Express Backend
 * =======================================
 * Requires: npm install express cors helmet bcrypt jsonwebtoken cookie-parser @supabase/supabase-js dotenv
 *
 * Start: node server.js
 */

require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const bcrypt       = require('bcrypt');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

// ── Supabase (server-side only — Service Role key NEVER sent to browser) ──
const sb = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const app        = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION';
const SALT_ROUNDS = 12;
// ── WonDD API Config ──────────────────────────────────────────
const WONDD_URL  = 'https://www.wondd.com/member/bot-game.php';
const WONDD_USER = process.env.WONDD_USERNAME || '';
const WONDD_PASS = process.env.WONDD_PASSWORD || '';

async function wonddPost(params) {
  const body = new URLSearchParams({
    username: WONDD_USER,
    password: WONDD_PASS,
    ...params,
  });
  const res = await fetch(WONDD_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
    timeout: 15000,
  });
  return res.json();
}

// WonDD servicecode map (game id -> wondd service code)
const WONDD_SERVICE = {
  1: 'freefire',
  2: 'rov',
  3: 'undawn',
  4: 'rov',       // Honor of Kings — map to nearest or extend later
  5: 'blackcover',
};


app.use(helmet());
app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// ── Response Helpers ───────────────────────────────────────────────────────
const ok  = (res, data)          => res.json(data);
const err = (res, msg, code=400) => res.status(code).json({ error: msg });

function numParse(str) {
  if (typeof str === 'number') return str;
  return parseInt(String(str).replace(/[^0-9]/g, ''), 10) || 0;
}

// ── Auth Middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  try {
    const header = req.headers['authorization'] || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : req.cookies?.es_token;
    if (!token) return err(res, 'Unauthorised', 401);
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    err(res, 'Invalid or expired token', 401);
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return err(res, 'Forbidden', 403);
    next();
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || name.length < 5)         return err(res, 'ຊື່ຕ້ອງມີ 5 ຕົວຂຶ້ນໄປ');
  if (!email || !email.endsWith('@gmail.com')) return err(res, 'ຕ້ອງໃຊ້ @gmail.com');
  if (!password || password.length < 6) return err(res, 'ລະຫັດ 6 ຕົວຂຶ້ນໄປ');

  const { data: exist } = await sb
    .from('users').select('email').eq('email', email.toLowerCase()).maybeSingle();
  if (exist) return err(res, 'email_exists: ຖືກໃຊ້ແລ້ວ');

  const { data: last } = await sb
    .from('users').select('user_id').order('user_id', { ascending: false }).limit(1);
  const nextId = last?.length ? Math.max(100, last[0].user_id + 1) : 100;

  const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
  const newUser = {
    name, email: email.toLowerCase(), password_hash,
    role: 'user', wallet: 0, user_id: nextId,
    joined: new Date().toISOString(),
  };

  const { error } = await sb.from('users').insert(newUser);
  if (error) return err(res, error.message, 500);

  const token = jwt.sign(
    { email: newUser.email, role: 'user', user_id: nextId },
    JWT_SECRET, { expiresIn: '7d' }
  );
  res.cookie('es_token', token, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 7*24*3600*1000 });
  ok(res, { token, user: { name, email: newUser.email, role: 'user', wallet: 0, user_id: nextId } });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) return err(res, 'ກະລຸນາຕື່ມ');

  const isEmail = identifier.includes('@');
  const { data: users } = await sb
    .from('users').select('*')
    .eq(isEmail ? 'email' : 'name', isEmail ? identifier.toLowerCase() : identifier)
    .limit(1);

  if (!users?.length) return err(res, 'ຂໍ້ມູນບໍ່ຖືກຕ້ອງ', 401);
  const user = users[0];

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return err(res, 'ຂໍ້ມູນບໍ່ຖືກຕ້ອງ', 401);

  const token = jwt.sign(
    { email: user.email, role: user.role, user_id: user.user_id },
    JWT_SECRET, { expiresIn: '7d' }
  );
  res.cookie('es_token', token, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 7*24*3600*1000 });
  ok(res, {
    token,
    user: { name: user.name, email: user.email, role: user.role || 'user', wallet: user.wallet || 0, user_id: user.user_id },
  });
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('es_token');
  ok(res, { message: 'ok' });
});

// GET /api/user/profile
app.get('/api/user/profile', requireAuth, async (req, res) => {
  const { data: user, error } = await sb
    .from('users').select('name, email, role, wallet, user_id, joined')
    .eq('email', req.user.email).maybeSingle();
  if (error || !user) return err(res, 'User not found', 404);
  ok(res, user);
});

// ═══════════════════════════════════════════════════════════════════════════
//  STORE INIT
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/store/init
app.get('/api/store/init', async (req, res) => {
  try {
    const [gRes, pkRes, banRes, pupRes, ctRes, cpRes] = await Promise.all([
      sb.from('games').select('*').order('id'),
      sb.from('packages').select('*').order('id'),
      sb.from('banners').select('*').order('id'),
      sb.from('popups').select('*').order('order'),
      sb.from('settings').select('value').eq('key', 'contacts').maybeSingle(),
      sb.from('coupons').select('id, code, type, value, active, maxUses'), // no usedBy
    ]);
    ok(res, {
      games:    gRes.data   || [],
      packages: pkRes.data  || [],
      banners:  banRes.data || [],
      popups:   pupRes.data || [],
      contacts: ctRes.data?.value || { fb: '', tt: '', wa: '' },
      coupons:  cpRes.data  || [],
    });
  } catch (e) {
    err(res, 'Server error: ' + e.message, 500);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
//  COUPON VALIDATE
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/coupon/validate
app.post('/api/coupon/validate', requireAuth, async (req, res) => {
  const { code, base_price } = req.body;
  if (!code) return err(res, 'ໃສ່ໂຄ້ດ');

  const { data: coupon } = await sb
    .from('coupons').select('*').eq('code', code.toUpperCase()).maybeSingle();

  if (!coupon)         return err(res, 'ໂຄ້ດບໍ່ຖືກຕ້ອງ');
  if (!coupon.active)  return err(res, 'ໂຄ້ດນີ້ຖືກປິດໃຊ້ງານ');

  const usedBy = coupon.usedBy || coupon.used_by || [];
  if (coupon.maxUses > 0 && usedBy.length >= coupon.maxUses) return err(res, 'ໂຄ້ດໃຊ້ຫມົດສິດດ ​​ແລ້ວ');
  if (usedBy.includes(req.user.email)) return err(res, 'ທ່ານໃຊ້ໂຄ້ດນີ້ແລ້ວ');

  const base    = numParse(base_price);
  let discount  = 0;
  if (coupon.type === 'percent') discount = Math.round(base * coupon.value / 100);
  if (coupon.type === 'fixed')   discount = coupon.value;
  discount = Math.min(discount, base);

  ok(res, { valid: true, discount, final_price: base - discount, type: coupon.type, value: coupon.value });
});

// ═══════════════════════════════════════════════════════════════════════════
//  ORDER CREATE
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/order/create
app.post('/api/order/create', requireAuth, async (req, res) => {
  const { game_id, package_id, uid_game, zone, pay, coupon_code } = req.body;
  if (!game_id || !package_id || !uid_game) return err(res, 'ຂໍ້ມູນບໍ່ຄົບ');

  // Fetch from DB — never trust client-sent prices
  const [gameRes, pkgRes] = await Promise.all([
    sb.from('games').select('*').eq('id', game_id).maybeSingle(),
    sb.from('packages').select('*').eq('id', package_id).maybeSingle(),
  ]);
  if (!gameRes.data || !pkgRes.data) return err(res, 'ບໍ່ພົບສິນຄ້າ', 404);
  const game = gameRes.data;
  const pkg  = pkgRes.data;

  const base = numParse(pkg.price);
  let discount = 0;

  if (coupon_code) {
    const { data: coupon } = await sb
      .from('coupons').select('*').eq('code', coupon_code.toUpperCase()).maybeSingle();
    if (coupon?.active) {
      const usedBy = coupon.usedBy || coupon.used_by || [];
      const maxOk  = coupon.maxUses === 0 || usedBy.length < coupon.maxUses;
      if (maxOk && !usedBy.includes(req.user.email)) {
        if (coupon.type === 'percent') discount = Math.round(base * coupon.value / 100);
        if (coupon.type === 'fixed')   discount = coupon.value;
        discount = Math.min(discount, base);
      }
    }
  }

  const total = Math.max(0, base - discount);

  // Check & deduct wallet (server-side only)
  const { data: userData } = await sb
    .from('users').select('wallet').eq('email', req.user.email).maybeSingle();
  if (!userData) return err(res, 'User not found', 404);

  const currentWallet = userData.wallet || 0;
  if (currentWallet < total) return err(res, 'insufficient_funds: ຍອດເງິນບໍ່ພໍ');

  const newWallet = currentWallet - total;

  const { error: wErr } = await sb
    .from('users').update({ wallet: newWallet }).eq('email', req.user.email);
  if (wErr) return err(res, 'Wallet update failed', 500);

  const ord = {
    id: 'ES' + Date.now(),
    game: game.name, gid: game_id,
    pkg: pkg.name,  price: pkg.price,
    discount, total: String(total),
    uid_game, zone: zone || '', pay: pay || '',
    status: 'pending',
    time: new Date().toLocaleString('lo-LA'),
    userId: req.user.email,
    discCode: coupon_code || '',
  };

  const { error: oErr } = await sb.from('orders').insert(ord);
  if (oErr) {
    // Rollback wallet
    await sb.from('users').update({ wallet: currentWallet }).eq('email', req.user.email);
    return err(res, 'Order insert failed', 500);
  }

  // Mark coupon used
  if (coupon_code && discount > 0) {
    const { data: c } = await sb
      .from('coupons').select('usedBy').eq('code', coupon_code.toUpperCase()).maybeSingle();
    if (c) {
      const ub = c.usedBy || [];
      if (!ub.includes(req.user.email)) {
        await sb.from('coupons')
          .update({ usedBy: [...ub, req.user.email] })
          .eq('code', coupon_code.toUpperCase());
      }
    }
  }

  ok(res, { order: ord, new_wallet_balance: newWallet });
});

// ═══════════════════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/admin/dashboard
app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  const [ordRes, usrRes, gameRes] = await Promise.all([
    sb.from('orders').select('*').order('time', { ascending: false }),
    sb.from('users').select('*'),
    sb.from('games').select('id, name'),
  ]);
  const orders  = ordRes.data || [];
  const revenue = orders
    .filter(o => o.status === 'success')
    .reduce((s, o) => s + numParse(o.total), 0);
  ok(res, {
    total_orders:   orders.length,
    pending_orders: orders.filter(o => o.status === 'pending').length,
    total_users:    (usrRes.data || []).length,
    total_revenue:  revenue,
    recent_orders:  orders.slice(0, 20),
    games:          gameRes.data || [],
  });
});

// GET /api/admin/orders
app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  const { data, error } = await sb.from('orders').select('*').order('time', { ascending: false });
  if (error) return err(res, error.message, 500);
  ok(res, data || []);
});

// GET /api/admin/users
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { data, error } = await sb.from('users').select('name, email, role, wallet, user_id, joined');
  if (error) return err(res, error.message, 500);
  ok(res, data || []);
});

// PUT /api/admin/order/status
app.put('/api/admin/order/status', requireAdmin, async (req, res) => {
  const { id, status } = req.body;
  if (!id || !status) return err(res, 'ຂໍ້ມູນບໍ່ຄົບ');
  const { error } = await sb.from('orders').update({ status }).eq('id', id);
  if (error) return err(res, error.message, 500);
  ok(res, { updated: true });
});

app.delete('/api/admin/order/:id', requireAdmin, async (req, res) => {
  const { error } = await sb.from('orders').delete().eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { deleted: true });
});

// ── Games ──────────────────────────────────────────────────────────────────
app.post('/api/admin/game', requireAdmin, async (req, res) => {
  const { error } = await sb.from('games').insert(req.body);
  if (error) return err(res, error.message, 500);
  ok(res, { created: true });
});
app.put('/api/admin/game/:id', requireAdmin, async (req, res) => {
  const { error } = await sb.from('games').update(req.body).eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { updated: true });
});
app.delete('/api/admin/game/:id', requireAdmin, async (req, res) => {
  await sb.from('packages').delete().eq('game_id', req.params.id); // cascade
  const { error } = await sb.from('games').delete().eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { deleted: true });
});

// ── Packages ───────────────────────────────────────────────────────────────
app.post('/api/admin/package', requireAdmin, async (req, res) => {
  const { error } = await sb.from('packages').insert(req.body);
  if (error) return err(res, error.message, 500);
  ok(res, { created: true });
});
app.put('/api/admin/package/:id', requireAdmin, async (req, res) => {
  const { error } = await sb.from('packages').update(req.body).eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { updated: true });
});
app.delete('/api/admin/package/:id', requireAdmin, async (req, res) => {
  const { error } = await sb.from('packages').delete().eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { deleted: true });
});

// ── Banners ────────────────────────────────────────────────────────────────
app.post('/api/admin/banner', requireAdmin, async (req, res) => {
  const { error } = await sb.from('banners').insert(req.body);
  if (error) return err(res, error.message, 500);
  ok(res, { created: true });
});
app.put('/api/admin/banner/:id', requireAdmin, async (req, res) => {
  const { error } = await sb.from('banners').update(req.body).eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { updated: true });
});
app.delete('/api/admin/banner/:id', requireAdmin, async (req, res) => {
  const { error } = await sb.from('banners').delete().eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { deleted: true });
});

// ── Popups ─────────────────────────────────────────────────────────────────
app.post('/api/admin/popup', requireAdmin, async (req, res) => {
  const { error } = await sb.from('popups').insert(req.body);
  if (error) return err(res, error.message, 500);
  ok(res, { created: true });
});
app.put('/api/admin/popup/:id', requireAdmin, async (req, res) => {
  const { error } = await sb.from('popups').update(req.body).eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { updated: true });
});
app.delete('/api/admin/popup/:id', requireAdmin, async (req, res) => {
  const { error } = await sb.from('popups').delete().eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { deleted: true });
});

// ── Coupons ────────────────────────────────────────────────────────────────
app.post('/api/admin/coupon', requireAdmin, async (req, res) => {
  const { error } = await sb.from('coupons').insert(req.body);
  if (error) return err(res, error.message, 500);
  ok(res, { created: true });
});
app.put('/api/admin/coupon/:id', requireAdmin, async (req, res) => {
  const { error } = await sb.from('coupons').update(req.body).eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { updated: true });
});
app.delete('/api/admin/coupon/:id', requireAdmin, async (req, res) => {
  const { error } = await sb.from('coupons').delete().eq('id', req.params.id);
  if (error) return err(res, error.message, 500);
  ok(res, { deleted: true });
});

// ── Users (admin edit) ─────────────────────────────────────────────────────
app.put('/api/admin/user/:email', requireAdmin, async (req, res) => {
  const update = {};
  if (req.body.wallet   !== undefined) update.wallet = req.body.wallet;
  if (req.body.role     !== undefined) update.role   = req.body.role;
  if (req.body.name     !== undefined) update.name   = req.body.name;
  if (req.body.password !== undefined) {
    update.password_hash = await require('bcrypt').hash(req.body.password, 12);
  }
  const { error } = await sb.from('users').update(update).eq('email', req.params.email);
  if (error) return err(res, error.message, 500);
  ok(res, { updated: true });
});

// DELETE /api/admin/user/:email
app.delete('/api/admin/user/:email', requireAdmin, async (req, res) => {
  const { error } = await sb.from('users').delete().eq('email', req.params.email);
  if (error) return err(res, error.message, 500);
  ok(res, { deleted: true });
});


// ══════════════════════════════════════════════════════════════
//  WONDD API INTEGRATION
// ══════════════════════════════════════════════════════════════

// GET /api/wondd/packlist?game=rov
// Fetch packcode list from WonDD (admin use to sync)
app.get('/api/wondd/packlist', requireAdmin, async (req, res) => {
  try {
    const game = req.query.game || '';
    const url  = game
      ? `https://www.wondd.com/member/bot-game-packlist.php?game=${game}`
      : 'https://www.wondd.com/member/bot-game-packlist.php';
    const resp = await fetch(url, { timeout: 10000 });
    const data = await resp.json();
    ok(res, data);
  } catch (e) {
    err(res, 'WonDD packlist error: ' + e.message, 500);
  }
});

// POST /api/wondd/balance
// Check WonDD account balance
app.post('/api/wondd/balance', requireAdmin, async (req, res) => {
  try {
    const data = await wonddPost({ method: 'balance' });
    ok(res, data);
  } catch (e) {
    err(res, 'WonDD balance error: ' + e.message, 500);
  }
});

// POST /api/wondd/topup  — called internally by doOrder
// Body: { order_id, game_id, packcode, gameid_player, zone? }
app.post('/api/wondd/topup', requireAuth, async (req, res) => {
  const { order_id, game_id, packcode, gameid_player, zone } = req.body;
  if (!order_id || !game_id || !packcode || !gameid_player)
    return err(res, 'Missing required fields');

  const servicecode = WONDD_SERVICE[game_id];
  if (!servicecode) return err(res, 'Game not supported by WonDD auto-topup');

  try {
    const gameId = zone ? `${gameid_player}|${zone}` : gameid_player;
    const data = await wonddPost({
      method:      'topup',
      servicecode: servicecode,
      packcode:    packcode,
      gameid:      gameId,
      orderid:     order_id,
    });

    // data.errorcode === '00' means success
    if (data.errorcode === '00') {
      // Update order status to processing
      await sb.from('orders').update({
        status:        'processing',
        wondd_orderid: data.orderid,
      }).eq('id', order_id);
      ok(res, { success: true, wondd: data });
    } else {
      await sb.from('orders').update({ status: 'failed' }).eq('id', order_id);
      err(res, `WonDD Error ${data.errorcode}: ${data.errordetail}`, 400);
    }
  } catch (e) {
    err(res, 'WonDD topup error: ' + e.message, 500);
  }
});

// POST /api/wondd/checkstatus
// Body: { order_id, wondd_orderid }
app.post('/api/wondd/checkstatus', requireAdmin, async (req, res) => {
  const { wondd_orderid } = req.body;
  if (!wondd_orderid) return err(res, 'Missing wondd_orderid');
  try {
    const data = await wonddPost({
      method:  'checkstatus',
      orderid: wondd_orderid,
    });
    ok(res, data);
  } catch (e) {
    err(res, 'WonDD checkstatus error: ' + e.message, 500);
  }
});

// POST /api/wondd/callback  — WonDD posts back here on status change
app.post('/api/wondd/callback', async (req, res) => {
  const { orderid, status, remark } = req.body;
  if (!orderid) return res.sendStatus(400);

  const statusMap = {
    complete: 'success',
    process:  'processing',
    fail:     'failed',
  };
  const newStatus = statusMap[status] || 'processing';

  await sb.from('orders')
    .update({ status: newStatus, wondd_remark: remark || '' })
    .eq('wondd_orderid', orderid);

  res.sendStatus(200);
});

// ── Settings ───────────────────────────────────────────────────────────────
app.put('/api/admin/settings/contacts', requireAdmin, async (req, res) => {
  const { fb, tt, wa } = req.body;
  const { error } = await sb.from('settings').upsert({ key: 'contacts', value: { fb, tt, wa } });
  if (error) return err(res, error.message, 500);
  ok(res, { saved: true });
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅  Easy Store API  →  http://localhost:${PORT}`);
});
