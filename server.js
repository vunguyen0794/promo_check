// server.js — promo-check (Google Drive chung - không bắt user đăng nhập)
// ----------------------------------------------------------------------
// Env cần có (local & Vercel):
//  - SUPABASE_URL, SUPABASE_KEY (hoặc SERVICE_ROLE/ANON_KEY)
//  - SESSION_SECRET
//  - GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET
//  - GOOGLE_OAUTH_REDIRECT_URI
//  - PRICE_BATTLE_DRIVE_FOLDER_ID  (ID thư mục trên My Drive để lưu ảnh; có thể bỏ trống)
// ----------------------------------------------------------------------

require('dotenv').config();

const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const { google } = require('googleapis');
const { Readable } = require('stream');
const fs = require('fs');
const { BigQuery } = require('@google-cloud/bigquery');
const { sendNewPostEmail } = require('./utils/mailer');

const isVercel = !!process.env.VERCEL;

// ------------------------- Supabase -------------------------
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey =
  process.env.SUPABASE_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_ANON_KEY;

const supabase = createClient(supabaseUrl, supabaseKey);

const parseToArray = v => Array.isArray(v) ? v : (v==null || v==='' ? [] : [v]);
const parseSkus = v => {
      if (!v) return [];
      // Dùng regex /[,\n\r\s]+/ cho cả hai trường hợp
      if (Array.isArray(v)) return v.flatMap(x => String(x).split(/[,\n\r\s]+/)).map(s=>s.trim()).filter(Boolean);
      return String(v).split(/[,\n\r\s]+/).map(s=>s.trim()).filter(Boolean);
    };

// ------------------------- BigQuery Client -------------------------
let bigquery;
try {
    const keyFile = process.env.BIGQUERY_KEY_FILE;
    
    // 1. Dùng file key local (ví dụ: bigquery-key.json)
    if (keyFile && fs.existsSync(keyFile)) {
        console.log(`[INIT] Khởi tạo BigQuery bằng file key: ${keyFile}`);
        bigquery = new BigQuery({ keyFilename: keyFile });
    } 
    // 2. Dùng JSON dán trực tiếp (cho Vercel)
    else if (process.env.BIGQUERY_KEY_JSON) {
        console.log("[INIT] Khởi tạo BigQuery bằng biến môi trường JSON.");
        const credentials = JSON.parse(process.env.BIGQUERY_KEY_JSON);
        bigquery = new BigQuery({ credentials });
    } 
    // 3. Không có key
    else {
        console.warn("⚠️ CẢNH BÁO: Không tìm thấy BigQuery key. Sẽ sử dụng hàm giả lập.");
    }
} catch (e) {
    console.error("LỖI KHỞI TẠO BIGQUERY:", e.message);
}
// -------------------------------------------------------------------



// ------------------------- App & core middlewares -------------------------
const app = express();
if (isVercel) app.set('trust proxy', 1);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieSession({
  name: 'promo_sess',
  keys: [process.env.SESSION_SECRET || 'dev-secret'],
  secure: isVercel,        // true trên Vercel (https), false ở localhost
  sameSite: 'lax',
  httpOnly: true,
  maxAge: 24 * 60 * 60 * 1000,
}));

// ======================= MIDDLEWARE LẤY CÀI ĐẶT CHUNG =======================
// Middleware này sẽ chạy TRƯỚC TẤT CẢ các route (app.get, app.post)
app.use(async (req, res, next) => {
  // Gắn user (từ code cũ) và thời gian vào res.locals
  res.locals.user = req.session?.user || null;
  res.locals.time = new Date().toLocaleTimeString('vi-VN', {
    hour: '2-digit',
    minute: '2-digit',
  });

  // 1. Cập nhật 'last_seen' cho user hiện tại (nếu đã đăng nhập)
  // Chúng ta không 'await' để nó chạy ngầm, không làm chậm request

  if (res.locals.user) {
    supabase
      .from('users')
      .update({ last_seen: new Date().toISOString() })
      .eq('id', res.locals.user.id)
      .then(result => {
        if (result.error) {
          console.error('Lỗi cập nhật last_seen:', result.error.message);
        }
        // Cập nhật thành công, không cần làm gì
      })
      .catch(err => console.error('Lỗi nghiêm trọng last_seen:', err.message));
  }

  // 2. Lấy số user online (chỉ khi user là manager hoặc admin)
  res.locals.onlineUserCount = null; // Khởi tạo là null

  const isManagerOrAdmin = res.locals.user && (res.locals.user.role === 'manager' || res.locals.user.role === 'admin');

  if (isManagerOrAdmin) {
    try {
      // Định nghĩa "online" là 5 phút gần nhất
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();

      const { count, error } = await supabase
        .from('users')
        .select('*', { count: 'exact', head: true }) // Chỉ đếm
        .gt('last_seen', fiveMinutesAgo); // Lớn hơn 5 phút trước

      if (error) throw error;

      res.locals.onlineUserCount = count;

    } catch (e) {
      console.error("Lỗi đếm user online:", e.message);
    }
  }
  // --- KẾT THÚC PHẦN THÊM MỚI ---

  // Lấy dòng chữ chạy từ Supabase
  try {
    const { data } = await supabase
      .from('site_settings')
      .select('value')
      .eq('id', 'ticker_text')
      .single();

    // Lưu nó vào res.locals để TẤT CẢ file EJS đều dùng được
    res.locals.globalTickerText = data ? data.value : null;

  } catch (e) {
    console.error("Lỗi lấy global ticker:", e.message);
    res.locals.globalTickerText = null;
  }

  // Cho phép request đi tiếp đến các route (ví dụ: app.get('/'))
  next();
});
// ======================= END MIDDLEWARE =======================

// share user/time ra view
//app.use((req, res, next) => {
 // res.locals.user = req.session?.user || null;
 // res.locals.time = new Date().toLocaleTimeString('vi-VN', {
   // hour: '2-digit',
   // minute: '2-digit',
 // });
 // next();
//});

// ------------------------- Auth middlewares -------------------------
const wantsJSON = (req) =>
  req.xhr ||
  (req.headers.accept || '').includes('application/json') ||
  req.path.startsWith('/api');
const requireAuth = (req, res, next) => {
  if (req.session?.user) return next();
  if (wantsJSON(req)) return res.status(401).json({ error: 'UNAUTHORIZED' });
  req.session = req.session || {};
  req.session.returnTo = req.originalUrl;
  return res.redirect('/login');
};
const requireManager = (req, res, next) => {
  if (req.session?.user?.role === 'manager') return next();
  return res.status(403).send('Access denied. Manager role required.');
};

// ------------------------- Multer (ảnh) -------------------------
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 3 },
  fileFilter: (req, file, cb) => {
    const ok = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'].includes(
      file.mimetype
    );
    cb(ok ? null : new Error('Chỉ chấp nhận ảnh (jpg, png, webp, gif).'), ok);
  },
});




// So sánh thay đổi đơn giản cho một số field
function pick(obj, keys) {
  const out = {};
  keys.forEach(k => { out[k] = obj?.[k]; });
  return out;
}
function diffFields(oldObj, newObj, keys) {
  const changed = {};
  keys.forEach(k => {
    const a = oldObj?.[k];
    const b = newObj?.[k];
    // so sánh JSON để tránh case object
    if (JSON.stringify(a) !== JSON.stringify(b)) changed[k] = { from: a, to: b };
  });
  return changed;
}
function parseMulti(val) {
  if (Array.isArray(val)) return val.filter(Boolean);
  if (val == null || val === '') return [];
  return [String(val)];
}
// Helper mới
function toIdArray(val) {
  if (Array.isArray(val)) {
    return [...new Set(val.flatMap(v => String(v).split(',')).map(s => Number(s.trim())).filter(Boolean))];
  }
  if (val == null || val === '') return [];
  return [...new Set(String(val).split(',').map(s => Number(s.trim())).filter(Boolean))];
}


// ==== PROMO HELPERS ====
// Kiểm tra ngày hiệu lực
function inDateRange(now, start, end) {
  const s = start ? new Date(start) : null;
  const e = end ? new Date(end) : null;
  return (!s || now >= s) && (!e || now <= e);
}

// Tính số tiền giảm theo form setup:
//  - discount_value_type: 'amount' | 'percent'
//  - discount_amount     (₫)
//  - discount_percent    (%)
//  - max_discount_amount (₫, optional)
function calcDiscountAmt(promo, price) {
  const type = (promo.discount_value_type || '').toLowerCase(); // 'amount' | 'percent'
  const val = Number(promo.discount_value || 0);
  if (type === 'amount') {
    return Math.max(0, Math.round(val));
  }
  if (type === 'percent') {
    const cap = promo.max_discount_amount == null ? Infinity : Number(promo.max_discount_amount);
    const raw = Math.round(price * val / 100);
    return Math.max(0, Math.min(raw, isFinite(cap) ? cap : raw));
  }
  return 0;
}

function getMaxCouponDiscount(promo) {
  try {
    const list = promo?.coupon_list || [];
    if (!Array.isArray(list) || !list.length) return 0;
    // c.discount có thể là number hoặc '900,000' -> bóc số
    const nums = list.map(c =>
      typeof c.discount === 'number'
        ? c.discount
        : (parseFloat(String(c.discount).replace(/[^0-9]/g, '')) || 0)
    );
    return nums.length ? Math.max(...nums) : 0;
  } catch { return 0; }
}



// Hai CTKM có cộng chung được không?
function canStack(a, b) {
  const aId = a.id, bId = b.id;
  const aEx = new Set(a.exclude_with || []);
  const bEx = new Set(b.exclude_with || []);
  if (aEx.has(bId) || bEx.has(aId)) return false;

  // Nếu có danh sách "áp dụng cùng", phải nằm trong list đó
  const aAp = a.apply_with || [];
  const bAp = b.apply_with || [];
  if (aAp.length && !aAp.includes(bId)) return false;
  if (bAp.length && !bAp.includes(aId)) return false;

  return true;
}

// Chọn tập CTKM cộng được (greedy: ưu tiên giảm nhiều nhất)
function pickStackable(promosSortedDesc) {
  const chosen = [];
  promosSortedDesc.forEach(p => { if (chosen.every(c => canStack(c, p))) chosen.push(p); });
  return chosen;
}

// Chuẩn hoá list SKU từ chuỗi trong form (phân cách bằng dấu phẩy/xuống dòng/space)
function parseSkuList(s) {
  return String(s || '')
    .split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
}








// ========================= GOOGLE DRIVE (DRIVE CHUNG) =========================
// Bảng DB: app_google_tokens (id='global')
//
// create table if not exists app_google_tokens (
//   id text primary key default 'global',
//   access_token text,
//   refresh_token text,
//   scope text,
//   token_type text,
//   expiry_date bigint
// );
//
// 1) Admin bấm /google/drive/connect một lần -> nhận refresh_token
// 2) Mọi upload sau đó dùng token chung này (không cần user đăng nhập Google)

function getOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_OAUTH_CLIENT_ID,
    process.env.GOOGLE_OAUTH_CLIENT_SECRET,
    process.env.GOOGLE_OAUTH_REDIRECT_URI
  );
}

// Lấy Drive client từ token CHUNG (tự refresh & ghi lại DB nếu có token mới)
async function getGlobalDrive() {
  const { data: tok, error } = await supabase
    .from('app_google_tokens')
    .select('*')
    .eq('id', 'global')
    .single();

  if (error || !tok || !tok.refresh_token) {
    throw new Error('Drive chung chưa được kết nối (vào /google/drive/connect)');
  }

  const oauth2 = getOAuthClient();
  oauth2.setCredentials({
    access_token: tok.access_token || undefined,
    refresh_token: tok.refresh_token || undefined,
    expiry_date: tok.expiry_date || undefined,
    scope: tok.scope || undefined,
    token_type: tok.token_type || undefined,
  });

  // Khi googleapis refresh token, lưu lại DB
  oauth2.on('tokens', async (tokens) => {
    try {
      await supabase.from('app_google_tokens').upsert({
        id: 'global',
        access_token: tokens.access_token || tok.access_token || null,
        refresh_token: tokens.refresh_token || tok.refresh_token || null,
        scope: tokens.scope || tok.scope || null,
        token_type: tokens.token_type || tok.token_type || null,
        expiry_date: tokens.expiry_date || tok.expiry_date || null,
      });
    } catch (e) {
      console.warn('update global token failed:', e?.message || e);
    }
  });

  return google.drive({ version: 'v3', auth: oauth2 });
}

async function uploadBufferToDriveGlobal(buffer, filename, mimeType, parentId) {
  const drive = await getGlobalDrive();

  const parents = parentId ? [parentId] : undefined;
  const { data: created } = await drive.files.create({
    requestBody: { name: filename, parents },
    media: { mimeType, body: Readable.from(buffer) },
    fields: 'id,name,webViewLink',
  });

  // Tuỳ policy: nếu cho phép public link (anyone) thì mở quyền
  try {
    await drive.permissions.create({
      fileId: created.id,
      requestBody: { role: 'reader', type: 'anyone' },
    });
  } catch {
    // Nếu tổ chức chặn anonymous link: dùng webViewLink (yêu cầu đăng nhập để xem)
  }

  // URL xem ảnh tiện dụng
  return `https://drive.google.com/uc?export=view&id=${created.id}`;
}



// ------------------------- ROUTES OAUTH (DRIVE CHUNG) -------------------------
app.get('/google/drive/connect', requireAuth, (req, res) => {
  // Có thể chỉ cho manager thấy route này (tránh user thường bấm)
  // if (req.session.user.role !== 'manager') return res.status(403).send('Only manager can connect Drive chung');
  const oauth2 = getOAuthClient();
  const url = oauth2.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/drive.file'],
    state: 'global', // đánh dấu connect CHUNG
  });
  return res.redirect(url);
});

app.get('/google/oauth2/callback', async (req, res) => {
  try {
    const oauth2 = getOAuthClient();
    const { code, state } = req.query;
    const { tokens } = await oauth2.getToken({
      code,
      redirect_uri: process.env.GOOGLE_OAUTH_REDIRECT_URI,
    });

    await supabase.from('app_google_tokens').upsert({
      id: 'global',
      access_token: tokens.access_token || null,
      refresh_token: tokens.refresh_token || null,
      scope: tokens.scope || null,
      token_type: tokens.token_type || null,
      expiry_date: tokens.expiry_date || null,
    });

    res.send(`<script>alert('Đã kết nối Google Drive CHUNG thành công!'); window.location.href='/price-battle';</script>`);
  } catch (e) {
    console.error('OAuth callback error:', e);
    res.status(500).send('OAuth error: ' + (e.message || 'unknown'));
  }
});

// ------------------------- Locals (tối giản) -------------------------
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  next();
});

// tăng limit để nhận form/json lớn (Bảng chi tiết + 2000 SKU)
app.use(express.json({ limit: '8mb' }));
app.use(express.urlencoded({ extended: true, limit: '8mb' }));




// ------------------------- Health / debug -------------------------
app.get('/whoami', (req, res) => res.json({ user: req.session?.user || null }));

app.get('/healthz', async (req, res) => {
  try {
    const ping = await supabase.from('promotions').select('id').limit(1);
    res.json({
      ok: true,
      env: {
        SUPABASE_URL: !!supabaseUrl,
        SUPABASE_KEY: !!supabaseKey,
        SESSION_SECRET: !!process.env.SESSION_SECRET,
        VERCEL: !!process.env.VERCEL,
      },
      supabase_ok: !ping.error,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ------------------------- Auth pages -------------------------
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('login', {
    title: 'Đăng nhập',
    currentPage: 'login',
    error: null,
    time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
  });
});

app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('register', {
    title: 'Đăng ký',
    currentPage: 'register',
    error: null,
    time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
  });
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .eq('is_active', true)
      .single();

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.render('login', {
        title: 'Đăng nhập',
        currentPage: 'login',
        error: 'Email hoặc mật khẩu không đúng',
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      });
    }

    req.session = req.session || {};
    req.session.user = { id: user.id, email: user.email, full_name: user.full_name, role: user.role, branch_code: user.branch_code };
    const redirectTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    return res.redirect(redirectTo);
  } catch (error) {
    res.render('login', {
      title: 'Đăng nhập',
      currentPage: 'login',
      error: 'Lỗi hệ thống',
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  }
});

app.post('/register', async (req, res) => {
  try {
    const { email, password, full_name, branch_code } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const { data: user, error } = await supabase
      .from('users')
      .insert([{ email, password_hash: hashedPassword, full_name, role: 'staff', branch_code: (branch_code || 'DEFAULT').toUpperCase() }])
      .select()
      .single();

    if (error) throw error;

    req.session.user = user;
    res.redirect('/');
  } catch (error) {
    res.render('register', {
      title: 'Đăng ký',
      currentPage: 'register',
      error: 'Lỗi đăng ký: ' + error.message,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  }
});

app.post('/logout', (req, res) => { req.session = null; return res.redirect('/login'); });


// Thay thế toàn bộ route app.get('/', ...) bằng code này
app.get('/', requireAuth, async (req, res) => {
  try {
    const selectedGroup = req.query.group || '';
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const pageSize = 8; // Hiển thị 8 CTKM mỗi trang

    // === PHẦN 1: LẤY DỮ LIỆU CTKM NỔI BẬT (ĐÃ SỬA LỖI) ===
    const today = new Date().toISOString().slice(0, 10);
    const { data: allPromos, error: promosErr } = await supabase
      .from('promotions')
      .select('*')
      .eq('status', 'active')
      .lte('start_date', today)
      .gte('end_date', today);
    if (promosErr) throw promosErr;

    const promoIds = allPromos.map(p => p.id);
    const { data: compatRows } = await supabase.from('promotion_compat_allows').select('promotion_id').in('promotion_id', promoIds);
    const promosWithAllowRules = new Set((compatRows || []).map(r => r.promotion_id));

    const promosWithStackInfo = allPromos.map(p => {
      let displayDiscount = null;
      let displayPrefix = 'Giảm';
      let discountValueForSort = 0;

      if (p.coupon_list && p.coupon_list.length > 0) {
        // Lấy tất cả các mức giảm từ danh sách, chuyển đổi "500.000" thành số 500000
        const discounts = p.coupon_list.map(c => parseFloat(String(c.discount).replace(/[^0-9]/g, '')) || 0);
        const maxDiscount = Math.max(...discounts);
        if (maxDiscount > 0) {
          displayDiscount = maxDiscount;
          displayPrefix = 'Giảm đến';
          discountValueForSort = maxDiscount;
        }
      } else if (String(p.discount_value_type || '').toLowerCase() === 'amount') {
        displayDiscount = p.discount_value;
        discountValueForSort = p.discount_value || 0;
      } else if (String(p.discount_value_type || '').toLowerCase() === 'percent') {
        displayDiscount = `${p.discount_value}%`;
        // Ước tính giá trị giảm để sắp xếp
        discountValueForSort = (p.discount_value / 100) * 10000000; // Giả định giá trị SP là 10M để so sánh
        if (p.max_discount_amount) discountValueForSort = Math.min(discountValueForSort, p.max_discount_amount);
      }

      const isStackable = p.compatible_with_other_promos === true || promosWithAllowRules.has(p.id);

      return {
        ...p,
        __stackable: isStackable,
        __display_discount: displayDiscount,
        __display_prefix: displayPrefix,
        __sort_value: discountValueForSort, // Dùng giá trị này để sắp xếp
      };
    });

    // Cập nhật lại logic sắp xếp để dùng giá trị mới
    let filteredPromos = promosWithStackInfo;
    if (selectedGroup) {
      filteredPromos = promosWithStackInfo.filter(p => p.group_name === selectedGroup);
    }
    filteredPromos.sort((a, b) => b.__sort_value - a.__sort_value); // Sắp xếp theo mức giảm ước tính
    // ...

    const allGroups = [...new Set(promosWithStackInfo.map(p => p.group_name).filter(Boolean))].sort();

    const totalItems = filteredPromos.length;
    const totalPages = Math.ceil(totalItems / pageSize);
    const paginatedPromos = filteredPromos.slice((page - 1) * pageSize, page * pageSize);

    // === PHẦN 2: LẤY DỮ LIỆU SO SÁNH GIÁ (ĐÃ KHÔI PHỤC) ===
    const { data: pc } = await supabase.from('price_comparisons').select('sku, product_name, brand, competitor_name').order('created_at', { ascending: false }).limit(100);
    const bySku = {};
    const totalBySku = {};
    (pc || []).forEach(r => {
      if (!r.sku) return;
      if (!bySku[r.sku]) bySku[r.sku] = { product_name: r.product_name || '', brand: r.brand || '', counts: {} };
      bySku[r.sku].counts[r.competitor_name] = (bySku[r.sku].counts[r.competitor_name] || 0) + 1;
      totalBySku[r.sku] = (totalBySku[r.sku] || 0) + 1;
    });
    const topSkus = Object.keys(totalBySku).sort((a, b) => totalBySku[b] - totalBySku[a]).slice(0, 10);
    const compSet = {};
    topSkus.forEach(s => Object.keys(bySku[s].counts).forEach(c => { compSet[c] = (compSet[c] || 0) + bySku[s].counts[c]; }));
    const competitorCols = Object.keys(compSet).sort((a, b) => compSet[b] - compSet[a]).slice(0, 6);
    const matrixRows = topSkus.map(sku => {
      const row = bySku[sku];
      let topComp = '-'; let topCompCount = 0;
      Object.entries(row.counts).forEach(([c, n]) => { if (n > topCompCount) { topComp = c; topCompCount = n; } });
      return { sku, product_name: row.product_name, brand: row.brand, total: totalBySku[sku], top_competitor: topComp, cells: competitorCols.map(c => row.counts[c] || 0) };
    });

    // === PHẦN 3: LẤY SẢN PHẨM NGẪU NHIÊN ===
    const { data: randomSkus } = await supabase
  .from('skus')
  .select('*')
  .order('list_price', { ascending: false, nullsFirst: false }) // Sắp xếp giá giảm dần
  .limit(8);

    res.render('index', {
      title: 'Trang chủ', currentPage: 'home',
      featuredPromos: paginatedPromos, allGroups, selectedGroup, page, totalPages,
      matrixRows, competitorCols,
      randomSkus: randomSkus || [],
    });
  } catch (e) {
    console.error('Lỗi trang chủ:', e);
    res.render('index', { title: 'Trang chủ', currentPage: 'home', error: e.message });
  }
});


// Thêm route này vào file server.js
app.get('/api/featured-promos', requireAuth, async (req, res) => {
  try {
    const selectedGroup = req.query.group || '';
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const pageSize = 8;
    const today = new Date().toISOString().slice(0, 10);

    const { data: allPromos } = await supabase.from('promotions').select('*').eq('status', 'active').lte('start_date', today).gte('end_date', today);

    const promoIds = allPromos.map(p => p.id);
    const { data: compatRows } = await supabase.from('promotion_compat_allows').select('promotion_id').in('promotion_id', promoIds);
    const promosWithAllowRules = new Set((compatRows || []).map(r => r.promotion_id));
    const promosWithStackInfo = allPromos.map(p => {
      let displayDiscount = null;
      let displayPrefix = 'Giảm';
      let discountValueForSort = 0;

      if (p.coupon_list && p.coupon_list.length > 0) {
        // Lấy tất cả các mức giảm từ danh sách, chuyển đổi "500.000" thành số 500000
        const discounts = p.coupon_list.map(c => parseFloat(String(c.discount).replace(/[^0-9]/g, '')) || 0);
        const maxDiscount = Math.max(...discounts);
        if (maxDiscount > 0) {
          displayDiscount = maxDiscount;
          displayPrefix = 'Giảm đến';
          discountValueForSort = maxDiscount;
        }
      } else if (String(p.discount_value_type || '').toLowerCase() === 'amount') {
        displayDiscount = p.discount_value;
        discountValueForSort = p.discount_value || 0;
      } else if (String(p.discount_value_type || '').toLowerCase() === 'percent') {
        displayDiscount = `${p.discount_value}%`;
        // Ước tính giá trị giảm để sắp xếp
        discountValueForSort = (p.discount_value / 100) * 10000000; // Giả định giá trị SP là 10M để so sánh
        if (p.max_discount_amount) discountValueForSort = Math.min(discountValueForSort, p.max_discount_amount);
      }

      const isStackable = p.compatible_with_other_promos === true || promosWithAllowRules.has(p.id);

      return {
        ...p,
        __stackable: isStackable,
        __display_discount: displayDiscount,
        __display_prefix: displayPrefix,
        __sort_value: discountValueForSort, // Dùng giá trị này để sắp xếp
      };
    });

    // Cập nhật lại logic sắp xếp để dùng giá trị mới
    let filteredPromos = promosWithStackInfo;
    if (selectedGroup) {
      filteredPromos = promosWithStackInfo.filter(p => p.group_name === selectedGroup);
    }
    filteredPromos.sort((a, b) => b.__sort_value - a.__sort_value); // Sắp xếp theo mức giảm ước tính


    const totalPages = Math.ceil(filteredPromos.length / pageSize);
    const paginatedPromos = filteredPromos.slice((page - 1) * pageSize, page * pageSize);

    // Chỉ render và trả về file partial
    res.render('partials/_featured-promos', {
      featuredPromos: paginatedPromos,
      page,
      totalPages,
      selectedGroup
    });
  } catch (e) {
    res.status(500).send('<p>Lỗi khi tải dữ liệu.</p>');
  }
});

// ========================= PC BUILDER / BÁO GIÁ =========================
app.get('/pc-builder', requireAuth, (req, res) => {
  res.render('pc-builder', {
    title: 'Báo giá - Xây dựng cấu hình',
    currentPage: 'pc-builder', // Biến này dùng để active menu
    // time đã có sẵn từ middleware
  });
});



// =======================================================================

// ---- Trang tất cả sản phẩm (phiên bản mới có category) ----
app.get('/products', requireAuth, async (req, res) => {
  const q = (req.query.q || '').trim();
  const category = (req.query.category || '').trim(); // Tham số category mới
  const page = Math.max(parseInt(req.query.page || '1', 10), 1);
  const pageSize = 24;
  const sort = (req.query.sort || 'sku_asc');

  // 1. Lấy danh sách categories cho các tab
  const { data: catData } = await supabase.from('skus').select('category');
  const categories = [...new Set((catData || []).map(item => item.category).filter(Boolean))].sort();

  // 2. Query sản phẩm
  let query = supabase
    .from('skus')
    .select('sku, product_name, brand, list_price, category', { count: 'exact' });

  if (q) {
    query = query.or(`sku.ilike.%${q}%,product_name.ilike.%${q}%,brand.ilike.%${q}%`);
  }
  if (category) {
    query = query.eq('category', category); // Lọc theo category
  }

  let orderOptions = { ascending: true };
  let orderField = 'sku';

  if (sort === 'price_desc') {
    orderField = 'list_price';
    orderOptions = { ascending: false, nullsFirst: false }; // Giá null xuống cuối
  } else if (sort === 'price_asc') {
    orderField = 'list_price';
    orderOptions = { ascending: true, nullsFirst: false }; // Giá null xuống cuối
  }

  const { data: items, count } = await query
    .order(orderField, orderOptions) // <-- ĐÃ THAY ĐỔI
    .range((page - 1) * pageSize, page * pageSize - 1);

  res.render('products', {
    title: 'Tất cả sản phẩm',
    currentPage: 'home',
    q, items: items || [],
    page, total: count || 0, pageSize,
    categories, // Truyền danh sách categories ra view
    selectedCategory: category,
    sort: sort // Truyền category đang chọn ra view
  });

  
});


// Thêm route này vào server.js
app.post('/api/recalculate-price', requireAuth, async (req, res) => {
  try {
    const { sku, selectedPromoIds } = req.body;
    if (!sku || !selectedPromoIds) {
      return res.status(400).json({ error: 'Thiếu thông tin SKU hoặc CTKM.' });
    }

    const { data: product } = await supabase.from('skus').select('list_price').eq('sku', sku).single();
    const price = Number(product.list_price || 0);

    const { data: promotions } = await supabase.from('promotions').select('*').in('id', selectedPromoIds);

    const promosWithValues = promotions.map(p => ({
      ...p,
      discount_amount_calc: calcDiscountAmt(p, price)
    }));

    const chosenPromos = pickStackable(promosWithValues);
    const totalDiscount = chosenPromos.reduce((sum, p) => sum + p.discount_amount_calc, 0);
    const finalPrice = Math.max(0, price - totalDiscount);

    res.json({ success: true, totalDiscount, finalPrice });

  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});
// POST /api/skus/upsert  { sku, product_name, list_price, brand?, category?, subcat? }
app.post('/api/skus/upsert', requireAuth, async (req, res) => {
  try {
    const sku = String(req.body.sku || '').trim();
    if (!sku) return res.status(400).json({ ok: false, error: 'Thiếu SKU' });

    const row = {
      sku,
      product_name: (req.body.product_name || sku).trim(),
      brand: req.body.brand || null,
      category: req.body.category || null,
      subcat: req.body.subcat || null,
      list_price: req.body.list_price != null ? Number(req.body.list_price) : null,
    };

    const { data, error } = await supabase
      .from('skus')
      .upsert([row], { onConflict: 'sku' })
      .select()
      .single();

    if (error) throw error;
    return res.json({ ok: true, sku: data });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});




// POST cập nhật giá (ghi lịch sử)
app.post('/api/sku/:sku/price', requireAuth, async (req, res) => {
  try {
    const sku = req.params.sku;
    const newPrice = Number(req.body.new_price);
    if (!Number.isFinite(newPrice) || newPrice < 0) return res.status(400).json({ ok: false, error: 'Giá không hợp lệ' });

    const { data: curr } = await supabase.from('skus').select('list_price').eq('sku', sku).single();
    const old = Number(curr?.list_price || 0);

    // update giá
    const { error: upErr } = await supabase.from('skus').update({ list_price: newPrice }).eq('sku', sku);
    if (upErr) throw upErr;

    // ghi lịch sử
    await supabase.from('sku_price_history').insert([{
      sku, old_price: old, new_price: newPrice, changed_by: req.session.user.id
    }]);

    res.json({ ok: true, old_price: old, new_price: newPrice });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});


// GET lịch sử giá
app.get('/api/sku/:sku/price-history', requireAuth, async (req, res) => {
  try {
    const sku = req.params.sku;
    const { data, error } = await supabase
      .from('sku_price_history')
      .select(`*, users:changed_by(full_name, email)`)
      .eq('sku', sku)
      .order('changed_at', { ascending: false })
      .limit(50);
    if (error) throw error;
    const rows = (data || []).map(r => ({
      changed_at: r.changed_at,
      old_price: r.old_price,
      new_price: r.new_price,
      user: r.users ? (r.users.full_name || r.users.email) : 'Unknown'
    }));
    res.json({ ok: true, history: rows });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});


// ------------------------- API SKUs -------------------------
app.get('/api/skus', async (req, res) => {
  try {
    const searchTerm = req.query.q;
    let query = supabase
      .from('skus')
      .select('sku, product_name, brand, category, subcat, list_price')
      .order('sku')
      .limit(10);

    if (searchTerm && searchTerm.trim() !== '') {
      query = query.or(
        `sku.ilike.%${searchTerm}%,product_name.ilike.%${searchTerm}%,brand.ilike.%${searchTerm}%`
      );
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ------------------------- Chiến giá (UI + SAVE) -------------------------
app.get('/price-battle', requireAuth, async (req, res) => {
  try {
    const { data: gtok } = await supabase
      .from('app_google_tokens').select('refresh_token')
      .eq('id', 'global').single();
    const globalDriveReady = !!gtok?.refresh_token;

    const skuFilter = req.query.sku;
    let q = supabase
      .from('price_comparisons')
      .select(`*, users:user_id (full_name, email)`)
      .order('created_at', { ascending: false });

    if (skuFilter) q = q.eq('sku', skuFilter).limit(50);
    else q = q.limit(10);

    const { data: recentComparisons } = await q;
    const withCreator = (recentComparisons || []).map(c => ({
      ...c, created_by: c.users ? (c.users.full_name || c.users.email) : 'Unknown'
    }));

    res.render('price-battle', {
      title: 'Chiến giá',
      currentPage: 'price-battle',
      recentComparisons: withCreator,
      globalDriveReady,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      user: req.session.user,
    });
  } catch (error) {
    console.error('Price battle error:', error);
    res.render('price-battle', {
      title: 'Chiến giá',
      currentPage: 'price-battle',
      recentComparisons: [],
      globalDriveReady: false,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      user: req.session.user,
    });
  }
});

app.post('/price-battle/save', requireAuth, upload.array('images', 3), async (req, res) => {
  try {
    // Validate input bắt buộc
    if (!req.body.sku || !req.body.competitor_name || !req.body.competitor_price) {
      return res.status(400).json({
        success: false,
        error: 'Thiếu thông tin bắt buộc: SKU, tên đối thủ, giá đối thủ',
      });
    }
    // === Thêm/Upsert SKU mới nếu cần ===
    const rawSku = String(req.body.sku || '').trim();
    const isNewSku = String(req.body.is_new_sku || 'false') === 'true';
    const newName = (req.body.product_name || '').trim();
    const newListPrice = Number(req.body.list_price) || null;

    if (rawSku) {
      try {
        if (isNewSku) {
          await supabase.from('skus').upsert([{
            sku: rawSku,
            product_name: newName || rawSku,
            brand: req.body.brand || null,
            category: req.body.category || null,
            subcat: req.body.subcat || null,
            list_price: newListPrice
          }], { onConflict: 'sku' });
        } else {
          const { data: existed } = await supabase.from('skus').select('sku').eq('sku', rawSku).limit(1);
          if (!existed || existed.length === 0) {
            await supabase.from('skus').insert([{
              sku: rawSku,
              product_name: newName || rawSku,
              brand: req.body.brand || null,
              category: req.body.category || null,
              subcat: req.body.subcat || null,
              list_price: newListPrice
            }]);
          }
        }
      } catch (e) {
        console.warn('Insert new SKU warning:', e?.message || e);
      }
    }

    // Ảnh
    let imageUrls = [];
    if (Array.isArray(req.files) && req.files.length > 0) {
      const parentId = process.env.PRICE_BATTLE_DRIVE_FOLDER_ID || null;
      const tasks = req.files.map((f) =>
        uploadBufferToDriveGlobal(f.buffer, f.originalname, f.mimetype, parentId)
      );
      imageUrls = await Promise.all(tasks);
    }

    // Link dán tay (tuỳ chọn)
    if (req.body.image_urls) {
      const extra = String(req.body.image_urls)
        .split(/[\n,;]+/)
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, 3);
      imageUrls = imageUrls.concat(extra);
    }

    // Ghi DB
    const comparisonData = {
      user_id: req.session.user.id,
      sku: req.body.sku,
      product_name: req.body.product_name || 'Unknown',
      brand: req.body.brand || '',
      category: req.body.category || '',
      subcat: req.body.subcat || '',
      our_price: parseFloat(req.body.our_price) || 0,
      promo_price: parseFloat(req.body.promo_price) || 0,
      competitor_name: req.body.competitor_name,
      competitor_price: parseFloat(req.body.competitor_price) || 0,
      competitor_link: req.body.competitor_link || '',
      stock_status: req.body.stock_status || 'available',
      price_difference: parseFloat(req.body.price_difference) || 0,
      suggested_price: parseFloat(req.body.suggested_price) || 0,
      images: imageUrls,
    };

    const { data, error } = await supabase
      .from('price_comparisons')
      .insert([comparisonData])
      .select()
      .single();
    if (error) throw error;

    return res.json({ success: true, ok: true, id: data?.id, images: imageUrls });
  } catch (error) {
    console.error('Save comparison error:', error);
    return res.json({
      success: true,              // <-- thêm dòng này
      ok: true,                   // (để tương thích cũ)
      id: data?.id || (data && data[0]?.id),
      images: imageUrls || []     // trả lại list link Drive
    });
  }
});

// ------------------------- API khác (CTKM) -------------------------
app.get('/api/skus-with-comparisons', async (req, res) => {
  try {
    const searchTerm = req.query.q;
    let query = supabase
      .from('skus')
      .select(`*, price_comparisons:price_comparisons(count)`)
      .order('sku')
      .limit(10);

    if (searchTerm) {
      query = query
        .ilike('sku', `%${searchTerm}%`)
        .or(`product_name.ilike.%${searchTerm}%,brand.ilike.%${searchTerm}%`);
    }

    const { data, error } = await query;
    if (error) throw error;

    const formatted = (data || []).map((it) => ({
      ...it,
      comparison_count: it.price_comparisons[0]?.count || 0,
    }));

    res.json(formatted);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


async function getEligiblePromosForSku(skuCode) {
  // 1) Lấy giá SKU
  const { data: skuRow } = await supabase.from('skus')
    .select('sku, list_price, brand, category, subcat')
    .eq('sku', skuCode).maybeSingle();
  if (!skuRow) return { sku: null, price: 0, groups: new Map(), picked: [] };
  ///picked.forEach(p => { p.discount_amount_calc = calcDiscountAmt(p, price); });

  const price = Number(skuRow.list_price || 0);

  // 2) Lấy tất cả CTKM còn hiệu lực thời gian
  const today = new Date().toISOString().slice(0, 10);
  const { data: promos } = await supabase
    .from('promotions')
    .select('id, name, group_name, subgroup_name, discount_value_type, discount_value, max_discount_amount, min_order_value, start_date, end_date, apply_to_all_skus')
    .lte('start_date', today)
    .gte('end_date', today);

  const promoById = new Map((promos || []).map(p => [p.id, p]));

  const promoIds = Array.from(promoById.keys());

  // 3) Mapping include/exclude
  const { data: includeRows } = await supabase
    .from('promotion_skus')
    .select('promotion_id, sku')
    .in('promotion_id', promoIds);
  const { data: excludeRows } = await supabase
    .from('promotion_excluded_skus')
    .select('promotion_id, sku')
    .in('promotion_id', promoIds);

  const includeByPromo = new Map();
  (includeRows || []).forEach(r => {
    (includeByPromo.get(r.promotion_id) || includeByPromo.set(r.promotion_id, new Set()).get(r.promotion_id))
      .add(r.sku);
  });

  const excludeByPromo = new Map();
  (excludeRows || []).forEach(r => {
    (excludeByPromo.get(r.promotion_id) || excludeByPromo.set(r.promotion_id, new Set()).get(r.promotion_id))
      .add(r.sku);
  });

  // 4) Lọc “CTKM áp dụng cho SKU”
  const applicable = [];
  (promos || []).forEach(p => {
    const excl = excludeByPromo.get(p.id);
    if (excl && excl.has(skuCode)) return;

    if (p.apply_to_all_skus) {
      applicable.push(p);
    } else {
      const inc = includeByPromo.get(p.id);
      if (inc && inc.has(skuCode)) applicable.push(p);
    }
  });

  // 5) Group theo group_name → pick 1 biến thể theo tier min_order_value
  const groups = new Map();
  applicable.forEach(p => {
    const g = p.group_name || 'Khác';
    (groups.get(g) || groups.set(g, []).get(g)).push(p);
  });

  const picked = [];
  groups.forEach(list => {
    // chỉ giữ các p có min_order_value <= price, rồi lấy min_order_value lớn nhất
    const tiers = list.filter(p => Number(p.min_order_value || 0) <= price);
    if (tiers.length) {
      tiers.sort((a, b) => Number(b.min_order_value || 0) - Number(a.min_order_value || 0));
      picked.push(tiers[0]);
    }
  });

  return { sku: skuRow, price, groups, picked };
}

app.all('/search-promotion', requireAuth, async (req, res) => {
  const skuInput = (
    req.method === 'POST'
      ? (req.body?.sku || req.body?.query)
      : (req.query?.query || req.query?.sku)
      || ''
  ).toString().trim();

  try {
    console.log(`\n--- [DEBUG] BẮT ĐẦU TÌM KIẾM CHO SKU: ${skuInput} ---`);

    if (!skuInput) {
      return res.render('promotion', {
        title: 'CTKM theo SKU', currentPage: 'promotion', query: skuInput,
        product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
        error: 'Vui lòng nhập SKU.',
        internalContest: null,
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      });
    }

    // 1) Lấy sản phẩm
    const { data: product } = await supabase.from('skus').select('*').eq('sku', skuInput).single();
    if (!product) {
      return res.render('promotion', {
        title: 'CTKM theo SKU', currentPage: 'promotion', query: skuInput,
        product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
        error: 'Không tìm thấy thông tin cho SKU: ' + skuInput,
         internalContest: null,
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      });
    }
    const price = Number(product.list_price || 0);
    console.log(`[DEBUG] Bước 1: Đã tìm thấy sản phẩm - Tên: ${product.product_name}, Giá niêm yết: ${price}đ`);

    // 2) Lấy các CTKM đang active
    const today = new Date().toISOString().split('T')[0];
    const { data: promosRaw } = await supabase
      .from('promotions')
      .select('*, promotion_skus(*), promotion_excluded_skus(*), detail_fields, group_name, subgroup_name')
      .lte('start_date', today)
      .gte('end_date', today)
      .eq('status', 'active');
    console.log(`[DEBUG] Bước 2: Lấy được ${promosRaw?.length || 0} CTKM active từ database.`);

    // 3) Lọc theo SKU áp dụng / loại trừ
    let promotions = (promosRaw || []).filter(p => {

            // Chuẩn hóa dữ liệu sản phẩm (viết thường)
            const pBrand = (product.brand || '').toLowerCase();
            const pCategory = (product.category || '').toLowerCase();
            const pSubcat = (product.subcat || '').toLowerCase();

            // 1. Kiểm tra Loại trừ (Luôn ưu tiên)
            const isExcludedCheck = (p.promotion_excluded_skus || []).some(ex => ex.sku === product.sku);
            if (isExcludedCheck) {
                return false;
            }

            // 2. Áp dụng cho Tất cả SKU
            if (p.apply_to_all_skus) return true;

            // 3. Áp dụng theo Brand + Subcat (viết thường)
            if (p.apply_brand_subcats && p.apply_brand_subcats.length > 0) {
                const isMatch = p.apply_brand_subcats.some(rule => 
                    (rule.brand || '').toLowerCase() === pBrand && 
                    (rule.subcat_id || '').toLowerCase() === pSubcat
                );
                if (isMatch) return true; 
                // Quan trọng: Không return false vội, để check các rule khác
            }

            // 4. Áp dụng theo Brand (viết thường)
            if (p.apply_to_brands && p.apply_to_brands.length > 0) {
                const brandsLower = p.apply_to_brands.map(b => (b || '').toLowerCase());
                if (brandsLower.includes(pBrand)) return true;
            }

            // 5. Áp dụng theo Category (viết thường)
            if (p.apply_to_categories && p.apply_to_categories.length > 0) {
                const catsLower = p.apply_to_categories.map(c => (c || '').toLowerCase());
                if (catsLower.includes(pCategory)) return true;
            }

            // 6. Áp dụng theo Subcat (viết thường)
            if (p.apply_to_subcats && p.apply_to_subcats.length > 0) {
                const subcatsLower = p.apply_to_subcats.map(s => (s || '').toLowerCase());
                if (subcatsLower.includes(pSubcat)) return true;
            }

            // 7. Áp dụng theo danh sách SKU
            const isIncluded = (p.promotion_skus || []).some(ps => ps.sku === product.sku);
            if (isIncluded) return true;

            // Nếu không khớp rule nào
            return false;
        });
    console.log(`[DEBUG] Bước 3: Sau khi lọc theo SKU, còn lại ${promotions.length} CTKM.`);


    const internalContest = promotions.find(p => p.promo_type === 'Thi đua nội bộ') || null;
    const regularPromos = promotions.filter(p => p.promo_type !== 'Thi đua nội bộ');

    console.log(`[DEBUG]   => Tách ra: ${internalContest ? 1 : 0} Thi đua, ${regularPromos.length} CTKM thường.`);
    // 4) Map tên CTKM “áp dụng cùng/loại trừ”
    if (promotions.length) {
      const ids = promotions.map(p => p.id);
      const { data: allows } = await supabase.from('promotion_compat_allows').select('promotion_id, with_promotion_id').in('promotion_id', ids);
      const { data: excludes } = await supabase.from('promotion_compat_excludes').select('promotion_id, with_promotion_id').in('promotion_id', ids);
      const { data: allPromosLite } = await supabase.from('promotions').select('id, name, group_name');
      const promoInfoById = Object.fromEntries((allPromosLite || []).map(p => [p.id, p]));

      promotions.forEach(p => {
        const allowIds = (allows || []).filter(r => r.promotion_id === p.id).map(r => r.with_promotion_id);
        p.compat_allow_names = [...new Set(allowIds.map(id => promoInfoById[id]?.group_name).filter(Boolean))];
        const exclIds = (excludes || []).filter(r => r.promotion_id === p.id).map(r => r.with_promotion_id);
        p.compat_exclude_names = [...new Set(exclIds.map(id => promoInfoById[id]?.group_name).filter(Boolean))];
      });
    }

    // 5) Lọc cuối cùng và tính toán
    let availablePromos = (regularPromos || []).map(p => {
  const ruleDiscount   = calcDiscountAmt(p, price);   // amount/percent
  const couponDiscount = getMaxCouponDiscount(p);     // coupon lớn nhất
  const bestDiscount   = Math.max(ruleDiscount, couponDiscount);

  return {
    ...p,
    rule_discount: ruleDiscount,                 // (tuỳ chọn) để debug/hiển thị
    max_coupon_discount: couponDiscount,         // dùng khi cần show trong card
    discount_amount_calc: bestDiscount           // 👈 GIÁ TRỊ DÙNG ĐỂ CỘNG TỔNG
  };
});


    // === LỌC CÓ ĐIỀU KIỆN: Chỉ lọc theo `min_order_value` NẾU sản phẩm đã có giá > 0 ===
    if (price > 0) {
      console.log(`[DEBUG] Bước 4: Sản phẩm có giá (${price}đ > 0), TIẾN HÀNH lọc theo đơn hàng tối thiểu.`);
      availablePromos = availablePromos.filter(p => Number(p.min_order_value || 0) <= price);
    } else {
      console.log(`[DEBUG] Bước 4: Sản phẩm chưa có giá, BỎ QUA lọc theo đơn hàng tối thiểu.`);
    }
    console.log(`   => Sau Bước 4, còn lại ${availablePromos.length} CTKM.`);


    // --- Logic gộp theo Group ---
    const bestByGroup = {};
    for (const p of availablePromos) {
      const groupKey = p.group_name || `__no_group_${p.id}__`;
      if (!bestByGroup[groupKey] || p.discount_amount_calc > bestByGroup[groupKey].discount_amount_calc) {
        bestByGroup[groupKey] = p;
      }
    }
    const promosAfterGroupPick = Object.values(bestByGroup);
    console.log(`[DEBUG] Bước 5: Sau khi gộp theo nhóm, còn lại ${promosAfterGroupPick.length} CTKM để hiển thị.`);

    const chosenPromos = pickStackable([...promosAfterGroupPick].sort((a, b) => b.discount_amount_calc - a.discount_amount_calc));
    const totalDiscount = chosenPromos.reduce((s, p) => s + Number(p.discount_amount_calc || 0), 0);
    const finalPrice = Math.max(0, price - totalDiscount);

    let comparisonCount = 0;
    try {
      const cmp = await supabase.from('price_comparisons').select('*', { count: 'exact', head: true }).eq('sku', product.sku);
      comparisonCount = cmp?.count || 0;
    } catch { }

    console.log(`--- [DEBUG] KẾT THÚC TÌM KIẾM ---`);
    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion',
      query: skuInput, product, promotions: promosAfterGroupPick,
      internalContest: internalContest,
      chosenPromos, totalDiscount, finalPrice, comparisonCount, error: null,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });

  } catch (error) {
    console.error('SEARCH PROMO ERROR:', error);
    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion', query: skuInput,
      product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
      error: 'Lỗi hệ thống: ' + (error?.message || String(error)),
      internalContest: null,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  }
});





app.all('/search-promotion', requireAuth, async (req, res) => {
  const skuInput = (
    req.method === 'POST'
      ? (req.body?.sku || req.body?.query)
      : (req.query?.query || req.query?.sku)
      || ''
  ).toString().trim();

  try {
    console.log(`\n--- [DEBUG] BẮT ĐẦU TÌM KIẾM CHO SKU: ${skuInput} ---`);

    if (!skuInput) {
      return res.render('promotion', {
        title: 'CTKM theo SKU', currentPage: 'promotion', query: skuInput,
        product: null, promotions: promosAfterGroupPick,internalContest: internalContest, totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
        error: 'Vui lòng nhập SKU.',
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      });
    }

    const { data: product } = await supabase.from('skus').select('*').eq('sku', skuInput).single();
    if (!product) {
      console.log(`[DEBUG] Lỗi: Không tìm thấy sản phẩm với SKU "${skuInput}".`);
      return res.render('promotion', {
        title: 'CTKM theo SKU', currentPage: 'promotion', query: skuInput,
        product: null, promotions: promosAfterGroupPick,internalContest: internalContest, totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
        error: 'Không tìm thấy thông tin cho SKU: ' + skuInput,
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      });
    }
    const price = Number(product.list_price || 0);
    console.log(`[DEBUG] Bước 1: Đã tìm thấy sản phẩm - Tên: ${product.product_name}, Giá niêm yết: ${price}đ`);

    const today = new Date().toISOString().split('T')[0];
    const { data: promosRaw } = await supabase
      .from('promotions')
      .select('*, promotion_skus(*), promotion_excluded_skus(*), detail_fields, group_name, subgroup_name, apply_brand_subcats')
      .lte('start_date', today)
      .gte('end_date', today)
      .eq('status', 'active');
    console.log(`[DEBUG] Bước 2: Lấy được ${promosRaw?.length || 0} CTKM active từ database.`);

    let promotions = (promosRaw || []).filter(p => {
      const isExcluded = (p.promotion_excluded_skus || []).some(ex => ex.sku === product.sku);
      if (isExcluded) return false;
      if (p.apply_to_all_skus === true) return true;
      const isIncluded = (p.promotion_skus || []).some(ps => ps.sku === product.sku);
      return isIncluded;
    });
    console.log(`[DEBUG] Bước 3: Sau khi lọc theo SKU, còn lại ${promotions.length} CTKM.`);

    // ... (Phần logic map tên CTKM tương thích giữ nguyên)

    const todayStr = new Date().toISOString().slice(0, 10);
    let availablePromos = (promotions || [])

      .map(p => ({ ...p, discount_amount_calc: calcDiscountAmt(p, price) }));
    console.log(`[DEBUG] Bước 4: Sau khi lọc theo đơn hàng tối thiểu, còn lại ${availablePromos.length} CTKM.`);

    // --- LOGIC GỘP THEO GROUP ---
    const bestByGroup = {};
    for (const p of availablePromos) {
      const groupKey = p.group_name || `__no_group_${p.id}__`;
      if (!bestByGroup[groupKey] || p.discount_amount_calc > bestByGroup[groupKey].discount_amount_calc) {
        bestByGroup[groupKey] = p;
      }
    }
    const promosAfterGroupPick = Object.values(bestByGroup);
    console.log(`[DEBUG] Bước 5: Sau khi gộp theo nhóm, còn lại ${promosAfterGroupPick.length} CTKM để hiển thị.`);
    // --- KẾT THÚC LOGIC GỘP ---

    const chosenPromos = pickStackable([...promosAfterGroupPick].sort((a, b) => b.discount_amount_calc - a.discount_amount_calc));
    const totalDiscount = chosenPromos.reduce((s, p) => s + Number(p.discount_amount_calc || 0), 0);
    const finalPrice = Math.max(0, price - totalDiscount);

    let comparisonCount = 0;
    try {
      const cmp = await supabase.from('price_comparisons').select('*', { count: 'exact', head: true }).eq('sku', product.sku);
      comparisonCount = cmp?.count || 0;
    } catch { }

    console.log(`--- [DEBUG] KẾT THÚC TÌM KIẾM ---`);
    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion',
      query: skuInput,
      product,
      promotions: promosAfterGroupPick,internalContest: internalContest, // <-- Sử dụng kết quả đã gộp
      chosenPromos, totalDiscount, finalPrice, comparisonCount, error: null,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });

  } catch (error) {
    console.error('SEARCH PROMO ERROR:', error);
    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion', query: skuInput,
      product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
      error: 'Lỗi hệ thống: ' + (error?.message || String(error)),
      internalContest: null,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  }
});




app.get('/promotion-detail/:id', requireAuth, async (req, res) => {
  try {
    const currentUser = req.session?.user;
    const isManager = ['manager', 'admin'].includes(currentUser?.role);
    const promoId = req.params.id;
    // Lấy quan hệ áp dụng cùng / loại trừ
    const { data: allowRows } = await supabase
      .from('promotion_compat_allows')
      .select('with_promotion_id')
      .eq('promotion_id', promoId);

    const { data: exclRows } = await supabase
      .from('promotion_compat_excludes')
      .select('with_promotion_id')
      .eq('promotion_id', promoId);

    // Lấy tên/nhóm để hiển thị + đưa đúng format mà view đang cần
    const allIds = [
      ...(allowRows || []).map(r => r.with_promotion_id),
      ...(exclRows || []).map(r => r.with_promotion_id),
    ];
    let compatAllows = [], compatExcludes = [];

    if (allIds.length) {
      const { data: refPromos } = await supabase
        .from('promotions')
        .select('id, name, group_name, subgroup_name')
        .in('id', allIds);

      const byId = Object.fromEntries((refPromos || []).map(p => [p.id, p]));
      const toObj = (p) => p ? ({
        id: p.id,
        name: p.name,
        group_name: p.group_name || 'Khác',
        subgroup_name: p.subgroup_name || null
      }) : null;

      compatAllows = (allowRows || [])
        .map(r => toObj(byId[r.with_promotion_id]))
        .filter(Boolean);

      compatExcludes = (exclRows || [])
        .map(r => toObj(byId[r.with_promotion_id]))
        .filter(Boolean);
    }

    const { data: promotion, error } = await supabase
      .from('promotions')
      .select(`*, promotion_skus(*), promotion_excluded_skus(*), promotion_gifts(*)`)
      .eq('id', promoId)
      .single();
    if (error) throw error;

    const includedCodes = (promotion.promotion_skus || []).map(x => x.sku).filter(Boolean);
    const excludedCodes = (promotion.promotion_excluded_skus || []).map(x => x.sku).filter(Boolean);
    const allCodes = Array.from(new Set([...includedCodes, ...excludedCodes]));

    let skuMetaByCode = {};
    if (allCodes.length) {
      const { data: skuMeta } = await supabase
        .from('skus')
        .select('sku, product_name, brand, list_price')
        .in('sku', allCodes);

      skuMetaByCode = Object.fromEntries((skuMeta || []).map(s => [
        s.sku,
        {
          sku: s.sku,
          product_name: s.product_name || '',
          brand: s.brand || '',
          list_price: (typeof s.list_price === 'number') ? s.list_price : null,
        }
      ]));
    }

    const includedSkuDetails = includedCodes.map(code => ({
      sku: code,
      product_name: skuMetaByCode[code]?.product_name || '',
      brand: skuMetaByCode[code]?.brand || '',
      list_price: skuMetaByCode[code]?.list_price ?? null,
    }));
    const excludedSkuDetails = excludedCodes.map(code => ({
      sku: code,
      product_name: skuMetaByCode[code]?.product_name || '',
      brand: skuMetaByCode[code]?.brand || '',
      list_price: skuMetaByCode[code]?.list_price ?? null,
    }));

    promotion.compat_allows = compatAllows;
    promotion.compat_excludes = compatExcludes;

    let revisions = [];
    if (isManager) {
      // chỉ load khi là manager
      const { data, error } = await supabase
        .from('promotion_revisions')
        .select('*')
        .eq('promotion_id', req.params.id)
        .order('created_at', { ascending: false });
      if (!error) revisions = data || [];
    }

    if (promotion && promotion.coupon_list && promotion.coupon_list.length > 0) {
      const discounts = promotion.coupon_list.map(c => parseFloat(String(c.discount).replace(/[^0-9]/g, '')) || 0);
      promotion.max_coupon_discount = Math.max(...discounts);
    }

    return res.render('promotion-detail', {
      title: 'Chi tiết CTKM',
      currentPage: 'promotion-detail',
      promotion,
      includedSkuDetails,
      excludedSkuDetails,
      revisions,                 // non-manager sẽ là []
      currentUser,               // truyền cho view biết vai trò
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });

  } catch (error) {
    console.error(error);
    res.status(404).send('Không tìm thấy thông tin CTKM.');
  }

});
// Trang quản lý CTKM (đã loại bỏ cat/brand)
app.get('/promo-management', requireAuth, requireManager, async (req, res) => {
  try {
    const { q, group, subgroup, sku } = req.query;
    let query = supabase
      .from('promotions')
      .select('*, promotion_skus(count), promotion_excluded_skus(count)')
      .order('created_at', { ascending: false });
    if (q) query = query.ilike('name', `%${q}%`);
    if (group) query = query.eq('group_name', group);
    if (subgroup) query = query.eq('subgroup_name', subgroup);
    if (sku) query = query.eq('promotion_skus.sku', sku);

    let q2 = supabase
      .from('promotions')
      .select('*, promotion_skus(sku), promotion_excluded_skus(sku)')
      .order('created_at', { ascending: false })
      .eq('apply_to_all_skus', true);
    if (sku) q2 = q2.not('id', 'is', null); // giữ nguyên, lọc sau ở app

    const { data: allPromosForCompatRaw } = await supabase
      .from('promotions')
      .select('id, name, group_name, subgroup_name, status')
      .order('name', { ascending: true });

    const allPromosForCompat =
      (allPromosForCompatRaw || []).filter(p => (p.status || 'active') === 'active');

    const { data: promotions } = await query;
    // lấy danh sách group/subgroup duy nhất cho dropdown
    const { data: groups } = await supabase
      .from('promotions')
      .select('group_name, subgroup_name');
    const groupSet = new Set(); const subgroupSet = new Set();
    (groups || []).forEach(r => {
      if (r.group_name) groupSet.add(r.group_name);
      if (r.subgroup_name) subgroupSet.add(r.subgroup_name);
    });

    res.render('promo-management', {
      title: 'Quản lý CTKM',
      currentPage: 'promo-management',
      promotions: promotions || [],
      groups: Array.from(groupSet),
      subgroups: Array.from(subgroupSet),
      q: q || '', selectedGroup: group || '', selectedSubgroup: subgroup || '',
      user: req.session?.user || null,
      allPromosForCompat,
      compatAllowIds: [],
      compatExclIds: [],
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  } catch (err) {
    console.error('Promo management fatal:', err);
    res.status(500).send('Lỗi khi tải trang quản lý CTKM: ' + err.message);
  }
});


// Thay thế toàn bộ route app.post('/create-promotion', ...) bằng code này

    app.post('/create-promotion', requireAuth, async (req, res) => {
    try {
    const {
      name, description, start_date, end_date, channel, promo_type, coupon_code,
      group_name, apply_to_type, apply_brands, apply_categories, apply_subcats,
      skus, excluded_skus, has_coupon_list, coupons,
      detail
    } = req.body;
    
    const apply_with = req.body['apply_with[]'];
    const exclude_with = req.body['exclude_with[]'];

    // === XỬ LÝ GIÁ TRỊ GIẢM (PHẦN BỊ THIẾU) ===
    const discount_value_type = req.body.discount_value_type || null;
    let discount_value = null;
    if (discount_value_type === 'amount') {
        discount_value = Number(req.body.discount_amount) || 0;
    } else if (discount_value_type === 'percent') {
        discount_value = Number(req.body.discount_percent) || 0;
    }
    const max_discount_amount = req.body.max_discount_amount ? Number(req.body.max_discount_amount) : null;
    const min_order_value = req.body.min_order_value ? Number(req.body.min_order_value) : 0;
    // ===========================================

    let couponListData = null;
    if (has_coupon_list && coupons) {
    const list = Array.isArray(coupons) ? coupons : Object.values(coupons);
    couponListData = list
    .filter(c => c && c.code && String(c.code).trim() !== '')
    .map(c => {
      // bóc số cho discount nếu người dùng nhập "900,000"
      const raw = c.discount;
      const discount =
        typeof raw === 'number'
          ? raw
          : (raw == null || raw === '' ? null : (parseFloat(String(raw).replace(/[^0-9]/g, '')) || 0));
      return {
        name: (c.name || '').trim(),
        code: String(c.code).trim(),
        discount,                       // 👈 LƯU MỨC GIẢM
        note: (c.note || '').trim()     // 👈 LƯU GHI CHÚ/ĐIỀU KIỆN
      };
    });

  // sắp xếp ổn định để diff không ảo
  couponListData.sort((a, b) =>
    (a.code || '').localeCompare(b.code || '') ||
    (a.name || '').localeCompare(b.name || '')
  );

  if (!couponListData.length) couponListData = null;
}


    const uniq = arr => Array.from(new Set((arr||[]).filter(v => v !== '' && v != null)));

    // Xử lý Brand + Subcat
    const apply_brand_subcats_list = (apply_to_type === 'brand_subcat')
      ? ( () => {
            const brands = uniq(parseSkus(apply_brands));
            const subcats = uniq(parseSkus(apply_subcats));
            const bs = [];
            brands.forEach(b => subcats.forEach(s => bs.push({brand:String(b), subcat_id:String(s)})));
            return bs.length ? bs : null;
          })()
      : null;


    const insertPayload = {
      name, description, start_date, end_date, group_name, channel: channel || 'All', promo_type, 
      coupon_code: coupon_code || null, status: 'active',
      apply_to_all_skus: apply_to_type === 'all',
      apply_to_brands: apply_to_type === 'brand' ? uniq(parseSkus(apply_brands)) : null,
      apply_to_categories: apply_to_type === 'category' ? uniq(parseSkus(apply_categories)) : null,
      apply_to_subcats: apply_to_type === 'subcat' ? uniq(parseSkus(apply_subcats)) : null,
      apply_brand_subcats: apply_brand_subcats_list,
      coupon_list: couponListData, 
      created_by: req.session.user?.id,
      detail_fields: detail || {},
      // Bổ sung các trường giá trị giảm
      discount_value_type,
      discount_value,
      max_discount_amount,
      min_order_value
    };

    console.log("Dữ liệu chuẩn bị INSERT vào DB:", insertPayload);

    const { data: promotion, error } = await supabase.from('promotions').insert([insertPayload]).select('id').single();
    
    
    if (error) throw error;
    const newPromoId = promotion.id;

    if (apply_to_type === 'sku') {
      const includeList = [...new Set(parseSkus(skus))];
      if (includeList.length > 0) await supabase.from('promotion_skus').insert(includeList.map(sku => ({ promotion_id: newPromoId, sku })));
    }

    const excludeList = [...new Set(parseSkus(excluded_skus))];
    if (excludeList.length > 0) await supabase.from('promotion_excluded_skus').insert(excludeList.map(sku => ({ promotion_id: newPromoId, sku })));

    if (apply_brand_subcats_list && apply_brand_subcats_list.length > 0) {
      await supabase.from('promotion_brand_subcats').insert(
        apply_brand_subcats_list.map(p => ({ promotion_id: newPromoId, brand: p.brand, subcat_id: p.subcat_id }))
      );
    }

    if (apply_with && Array.isArray(apply_with) && apply_with.length > 0) await supabase.from('promotion_compat_allows').insert(apply_with.map(pid => ({ promotion_id: newPromoId, with_promotion_id: pid })));
    if (exclude_with && Array.isArray(exclude_with) && exclude_with.length > 0) await supabase.from('promotion_compat_excludes').insert(exclude_with.map(pid => ({ promotion_id: newPromoId, with_promotion_id: pid })));


    await supabase.from('promotion_revisions').insert({
      promotion_id: newPromoId,
      user_id: req.session.user?.id || null,
      action: 'create',
      snapshot: insertPayload
    });

    return res.json({ success: true, id: promotion.id });
  } catch (error) {
    console.error('Lỗi khi tạo CTKM:', error);
    res.status(500).json({ success: false, error: 'Lỗi khi tạo CTKM: ' + error.message });
  }
});

// Thay thế toàn bộ route sao chép bằng code này
app.post('/api/promotions/:id/clone', requireAuth, async (req, res) => {
  try {
    const srcId = req.params.id;

    // 1) Lấy bản gốc
    const { data: src, error: e1 } = await supabase.from('promotions').select('*').eq('id', srcId).single();
    if (e1 || !src) throw new Error('Không tìm thấy CTKM nguồn để sao chép.');

    // 2) Chuẩn bị dữ liệu cho bản sao
    const newRow = { ...src };
    delete newRow.id; // Xóa id cũ để database tự tạo id mới
    newRow.name = `Copy of ${src.name}`;
    newRow.created_at = new Date().toISOString();
    newRow.updated_at = new Date().toISOString();
    // Thêm hậu tố ngẫu nhiên vào mã coupon để tránh lỗi trùng lặp
    if (newRow.coupon_code) {
      const rand = Math.random().toString(36).slice(2, 6).toUpperCase();
      newRow.coupon_code = `${newRow.coupon_code}-COPY-${rand}`;
    }

    // 3) Chèn bản sao vào DB và lấy ID mới
    const { data: inserted, error: e2 } = await supabase.from('promotions').insert(newRow).select('id').single();
    if (e2) throw e2;
    const newId = inserted.id;

    // Helper để sao chép các bảng con
    const copyTable = async (tableName) => {
      const { data: rows, error } = await supabase.from(tableName).select('*').eq('promotion_id', srcId);
      if (error) { // Nếu bảng không tồn tại, bỏ qua và cảnh báo
        console.warn(`Cảnh báo: Không thể đọc bảng "${tableName}" khi sao chép. Bỏ qua.`);
        return;
      }
      if (!rows || !rows.length) return;

      const payload = rows.map(r => {
        const newRecord = { ...r, promotion_id: newId };
        delete newRecord.id; // Xóa id của dòng cũ
        return newRecord;
      });

      await supabase.from(tableName).insert(payload);
    };

    // 4) Chỉ sao chép các bảng LIÊN QUAN THỰC TẾ
    await copyTable('promotion_skus');
    await copyTable('promotion_excluded_skus');
    await copyTable('promotion_compat_allows');
    await copyTable('promotion_compat_excludes');

    // Trả về thành công
    return res.json({ ok: true, success: true, new_id: newId });

  } catch (err) {
    console.error('Lỗi khi sao chép CTKM:', err);
    return res.status(400).json({ ok: false, error: String(err.message || err) });
  }
});

// GET: trang edit
app.get('/edit-promotion/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const { data: promotion, error } = await supabase
      .from('promotions')
      .select('*, promotion_skus(*), promotion_excluded_skus(*)')
      .eq('id', id).single();
    if (error) throw error;

    // --- Ghép thông tin SKU từ bảng 'skus' ---
    const includedCodes = (promotion.promotion_skus || []).map(x => x.sku).filter(Boolean);
    const excludedCodes = (promotion.promotion_excluded_skus || []).map(x => x.sku).filter(Boolean);
    const allCodes = Array.from(new Set([...includedCodes, ...excludedCodes]));

    let skuMetaByCode = {};
    if (allCodes.length) {
      const { data: skuMeta } = await supabase
        .from('skus')
        .select('sku, product_name, brand, list_price')
        .in('sku', allCodes);

      skuMetaByCode = Object.fromEntries((skuMeta || []).map(s => [
        s.sku,
        {
          sku: s.sku,
          product_name: s.product_name || '',
          brand: s.brand || '',
          list_price: typeof s.list_price === 'number' ? s.list_price : null,
        }
      ]));
    }

    const includedSkuDetails = includedCodes.map(code => ({
      sku: code,
      product_name: skuMetaByCode[code]?.product_name || '',
      brand: skuMetaByCode[code]?.brand || '',
      list_price: skuMetaByCode[code]?.list_price ?? null,
    }));

    const excludedSkuDetails = excludedCodes.map(code => ({
      sku: code,
      product_name: skuMetaByCode[code]?.product_name || '',
      brand: skuMetaByCode[code]?.brand || '',
      list_price: skuMetaByCode[code]?.list_price ?? null,
    }));


    const { data: allPromos } = await supabase
      .from('promotions')
      .select('id, name, group_name, subgroup_name, status')
      .neq('id', id)
      .order('name', { ascending: true });

    const { data: allowRows } = await supabase
      .from('promotion_compat_allows')
      .select('with_promotion_id')
      .eq('promotion_id', id);

    const { data: exclRows } = await supabase
      .from('promotion_compat_excludes')
      .select('with_promotion_id')
      .eq('promotion_id', id);

    res.render('edit-promotion', {
      title: 'Sửa CTKM',
      currentPage: 'edit-promotion',
      promotion, error: null,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      allPromosForCompat: (allPromos || []).filter(p => (p.status || 'active') === 'active'),
      compatAllowIds: (allowRows || []).map(r => String(r.with_promotion_id)),
      compatExclIds: (exclRows || []).map(r => String(r.with_promotion_id)),
    });
  } catch (e) {
    res.render('edit-promotion', {
      title: 'Sửa CTKM', currentPage: 'edit-promotion',
      promotion: null, error: e.message || 'Không tải được CTKM',
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
    });
  }
});

// Thay thế toàn bộ route app.post('/edit-promotion/:id', ...) bằng code này
// ===== UPDATE PROMOTION (with full diff for history) =====
app.post('/edit-promotion/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  try {
    if (!id) throw new Error('Thiếu promotion id');

    // ===== 1) Lấy bản cũ (promotion + bảng phụ) =====
    const { data: oldPromotion, error: eOld } =
      await supabase.from('promotions').select('*').eq('id', id).single();
    if (eOld || !oldPromotion) throw new Error('Không tìm thấy CTKM để cập nhật.');

    const [
      oldSkusIncRes,
      oldSkusExcRes,
      oldAllowRes,
      oldExclRes,
      oldBrandSubRes // nếu bạn có bảng này; nếu không, trả về [] cũng OK
    ] = await Promise.all([
      supabase.from('promotion_skus').select('sku').eq('promotion_id', id),
      supabase.from('promotion_excluded_skus').select('sku').eq('promotion_id', id),
      supabase.from('promotion_compat_allows').select('with_promotion_id').eq('promotion_id', id),
      supabase.from('promotion_compat_excludes').select('with_promotion_id').eq('promotion_id', id),
      supabase.from('promotion_brand_subcats').select('brand, subcat_id').eq('promotion_id', id)
    ]);

    const oldSkusInc = (oldSkusIncRes.data || []).map(r => String(r.sku));
    const oldSkusExc = (oldSkusExcRes.data || []).map(r => String(r.sku));
    const oldAllows  = (oldAllowRes.data  || []).map(r => Number(r.with_promotion_id));
    const oldExcls   = (oldExclRes.data   || []).map(r => Number(r.with_promotion_id));
    const oldBrandSub= (oldBrandSubRes.data|| []).map(r => ({brand:String(r.brand), subcat_id:String(r.subcat_id)}));

    // ===== helpers =====
    const uniq = arr => Array.from(new Set((arr||[]).filter(v => v !== '' && v != null)));
    const sortStr = arr => uniq(arr).sort((a,b)=> String(a).localeCompare(String(b)));
    const sortNum = arr => uniq(arr.map(Number)).sort((a,b)=>a-b);
    const stableJson = obj => JSON.stringify(obj, Object.keys(obj||{}).sort());
    const sameArr = (a,b) => JSON.stringify(sortStr(a||[])) === JSON.stringify(sortStr(b||[]));
    const sameArrNum = (a,b)=> JSON.stringify(sortNum(a||[])) === JSON.stringify(sortNum(b||[]));
    const sameJson = (a,b) => JSON.stringify(a) === JSON.stringify(b);

    
    // ===== 2) Lấy dữ liệu mới từ form =====
    const {
      name, description, start_date, end_date, channel, promo_type, coupon_code,
      group_name, apply_to_type, apply_brands, apply_categories, apply_subcats,
      skus, excluded_skus, has_coupon_list, coupons,
      detail
    } = req.body;

    const apply_with   = parseToArray(req.body.apply_with);
    const exclude_with = parseToArray(req.body.exclude_with);

    // Coupon builder → chuẩn hoá danh sách để so sánh/lưu
    // Coupon builder → chuẩn hoá danh sách để so sánh/lưu (GIỮ FULL TRƯỜNG)
let couponListData = null;
if (has_coupon_list && coupons) {
  const list = Array.isArray(coupons) ? coupons : Object.values(coupons);
  couponListData = list
    .filter(c => c && c.code && String(c.code).trim() !== '')
    .map(c => {
      // bóc số cho discount nếu người dùng nhập "900,000"
      const raw = c.discount;
      const discount =
        typeof raw === 'number'
          ? raw
          : (raw == null || raw === '' ? null : (parseFloat(String(raw).replace(/[^0-9]/g, '')) || 0));
      return {
        name: (c.name || '').trim(),
        code: String(c.code).trim(),
        discount,                       // 👈 LƯU MỨC GIẢM
        note: (c.note || '').trim()     // 👈 LƯU GHI CHÚ/ĐIỀU KIỆN
      };
    });

  // sắp xếp ổn định để diff không ảo
  couponListData.sort((a, b) =>
    (a.code || '').localeCompare(b.code || '') ||
    (a.name || '').localeCompare(b.name || '')
  );

  if (!couponListData.length) couponListData = null;
}


    // ===== 3) Chuẩn bị payload update promotions =====
    const updatePayload = {
      name,
      description,
      start_date,
      end_date,
      group_name,
      channel: channel || 'ALL',
      promo_type,
      coupon_code: coupon_code || null,
      coupon_list: couponListData,           // 👈 sẽ được ghi lịch sử nếu đổi
      detail_fields: detail || {},
      // phạm vi áp dụng
      apply_to_all_skus: apply_to_type === 'all',
      apply_to_brands:   apply_to_type === 'brand'    ? uniq(parseSkus(apply_brands))    : null,
      apply_to_categories: apply_to_type === 'category'? uniq(parseSkus(apply_categories)) : null,
      apply_to_subcats:  apply_to_type === 'subcat'   ? uniq(parseSkus(apply_subcats))   : null,
      // tóm tắt scope mới (nếu bạn dùng Brand+Subcat)
      apply_brand_subcats: apply_to_type === 'brand_subcat'
        ? ( () => {
              const bs = [];
              uniq(parseToArray(apply_brands)).forEach(b =>
                uniq(parseToArray(apply_subcats)).forEach(s => bs.push({brand:String(b), subcat_id:String(s)}))
              );
              return bs.length ? bs : null;
            })()
        : null,
      updated_at: new Date().toISOString()
    };

    // ===== 4) Tính toán dữ liệu bảng phụ MỚI (trước khi ghi) =====
    const newSkusInc = uniq(parseSkus(skus));
    const newSkusExc = uniq(parseSkus(excluded_skus));
    const newAllows  = sortNum(apply_with);
    const newExcls   = sortNum(exclude_with);
    const newBrandSub= updatePayload.apply_brand_subcats ? updatePayload.apply_brand_subcats.map(x=>({brand:x.brand, subcat_id:x.subcat_id})) : [];

    // ===== 5) Tạo DIFF đầy đủ để ghi lịch sử =====
    const diff = {};

    // a) các field scalar/JSON chính, thêm cả apply_to_type & coupon_list
    const compareKeys = [
      'name','description','start_date','end_date','channel','promo_type','coupon_code','group_name',
      'apply_to_all_skus','apply_to_brands','apply_to_categories','apply_to_subcats',
      'apply_brand_subcats',   // 👈 scope mới
      'detail_fields','coupon_list'
    ];
    // thêm key “apply_to_type” riêng (không nằm trong bảng)
    if (String(oldPromotion.apply_to_type || '') !== String(apply_to_type || '')) {
      diff.apply_to_type = { from: oldPromotion.apply_to_type, to: apply_to_type };
    }

    compareKeys.forEach(k => {
      const oldVal = oldPromotion[k];
      const newVal = updatePayload[k];
      // so mảng: chuẩn hoá
      if (Array.isArray(oldVal) || Array.isArray(newVal)) {
        const norm = v => Array.isArray(v) ? v.slice() : (v==null?[]: [v]);
        const o = norm(oldVal); const n = norm(newVal);
        // riêng brand_subcats: sort theo brand+subcat_id
        if (k === 'apply_brand_subcats') {
          const sortPairs = arr => (arr||[]).map(x=>({brand:String(x.brand), subcat_id:String(x.subcat_id)}))
                                            .sort((a,b)=> a.brand.localeCompare(b.brand) || a.subcat_id.localeCompare(b.subcat_id));
          if (JSON.stringify(sortPairs(o)) !== JSON.stringify(sortPairs(n))) {
            diff[k] = { from: o, to: n };
          }
        } else {
          if (JSON.stringify(sortStr(o)) !== JSON.stringify(sortStr(n))) {
            diff[k] = { from: o, to: n };
          }
        }
      } else {
        // object/JSON khác
        if (!sameJson(oldVal, newVal)) diff[k] = { from: oldVal, to: newVal };
      }
    });

    // b) bảng phụ: SKU include/exclude, compat allows/excludes, brand_subcat
    if (!sameArr(oldSkusInc, newSkusInc)) diff.sku_includes = { from: sortStr(oldSkusInc), to: sortStr(newSkusInc) };
    if (!sameArr(oldSkusExc, newSkusExc)) diff.sku_excludes = { from: sortStr(oldSkusExc), to: sortStr(newSkusExc) };
    if (!sameArrNum(oldAllows,  newAllows)) diff.compat_allows   = { from: sortNum(oldAllows), to: sortNum(newAllows) };
    if (!sameArrNum(oldExcls,   newExcls))  diff.compat_excludes = { from: sortNum(oldExcls),  to: sortNum(newExcls) };
    // brand_subcat
    const sortPairs = arr => (arr||[]).map(x=>({brand:String(x.brand), subcat_id:String(x.subcat_id)}))
                                      .sort((a,b)=> a.brand.localeCompare(b.brand) || a.subcat_id.localeCompare(b.subcat_id));
    if (JSON.stringify(sortPairs(oldBrandSub)) !== JSON.stringify(sortPairs(newBrandSub))) {
      diff.brand_subcats_map = { from: sortPairs(oldBrandSub), to: sortPairs(newBrandSub) };
    }

    // ===== 6) Ghi UPDATE =====
    const { error: promoUpdateError } =
      await supabase.from('promotions').update(updatePayload).eq('id', id);
    if (promoUpdateError) throw promoUpdateError;

    // làm sạch + ghi lại bảng phụ
    await supabase.from('promotion_skus').delete().eq('promotion_id', id);
    if (newSkusInc.length) {
      await supabase.from('promotion_skus').insert(newSkusInc.map(sku => ({ promotion_id: id, sku })));
    }

    await supabase.from('promotion_excluded_skus').delete().eq('promotion_id', id);
    if (newSkusExc.length) {
      await supabase.from('promotion_excluded_skus').insert(newSkusExc.map(sku => ({ promotion_id: id, sku })));
    }

    await supabase.from('promotion_compat_allows').delete().eq('promotion_id', id);
    if (newAllows.length) {
      await supabase.from('promotion_compat_allows').insert(newAllows.map(pid => ({ promotion_id: id, with_promotion_id: pid })));
    }

    await supabase.from('promotion_compat_excludes').delete().eq('promotion_id', id);
    if (newExcls.length) {
      await supabase.from('promotion_compat_excludes').insert(newExcls.map(pid => ({ promotion_id: id, with_promotion_id: pid })));
    }

    // brand_subcat mapping + tóm tắt JSON
    await supabase.from('promotion_brand_subcats').delete().eq('promotion_id', id);
    if (newBrandSub.length) {
      await supabase.from('promotion_brand_subcats').insert(newBrandSub.map(p => ({ promotion_id: id, brand: p.brand, subcat_id: p.subcat_id })));
      await supabase.from('promotions').update({ apply_brand_subcats: newBrandSub }).eq('id', id);
    } else {
      await supabase.from('promotions').update({ apply_brand_subcats: null }).eq('id', id);
    }

    // ===== 7) Ghi lịch sử nếu có thay đổi =====
    if (Object.keys(diff).length > 0) {
      await supabase.from('promotion_revisions').insert({
        promotion_id: id,
        user_id: req.session.user?.id || null,
        action: 'update',
        diff,
        snapshot: { ...oldPromotion, ...updatePayload } // ảnh chụp sau cập nhật
      });
    }

    return res.redirect(`/promotion-detail/${id}`);
  } catch (e) {
    console.error(`Lỗi khi cập nhật CTKM #${id}:`, e);
    return res.status(500).send('Lỗi khi lưu CTKM: ' + e.message);
  }
});



// Xoá CTKM
app.delete('/api/promotions/:id', requireManager, async (req, res) => {
  try {
    const promoId = req.params.id;

    await supabase.from('promotion_skus').delete().eq('promotion_id', promoId);
    await supabase.from('promotion_excluded_skus').delete().eq('promotion_id', promoId);
    await supabase.from('promotion_gifts').delete().eq('promotion_id', promoId);

    const { error } = await supabase.from('promotions').delete().eq('id', promoId);
    if (error) throw error;

    res.json({ success: true, message: 'Xóa CTKM thành công' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Lỗi khi xóa CTKM: ' + error.message });
  }
});

// API: xem thử 1 file trong thư mục Drive chung
app.get('/drive-test', requireAuth, async (req, res) => {
  try {
    const drive = await getGlobalDrive();
    const parent = process.env.PRICE_BATTLE_DRIVE_FOLDER_ID;
    const list = await drive.files.list({
      q: parent ? `'${parent}' in parents` : undefined,
      pageSize: 3,
      fields: 'files(id,name)',
    });
    res.json({ ok: true, files: list.data.files || [] });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});


// Yêu cầu: đã có supabase client. Cần multer riêng cho CSV nếu bạn đã có filter ảnh.
const uploadCsv = multer({ storage: multer.memoryStorage() });

function parseCsvLines(buf) {
  const text = buf.toString('utf8').replace(/^\uFEFF/, '');
  return text.split(/\r?\n/).filter(l => l.trim().length);
}
function splitCsvLine(line) {
  const out = []; let cur = ''; let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; }
      else cur += c;
    } else {
      if (c === ',') { out.push(cur); cur = ''; }
      else if (c === '"') { q = true; }
      else cur += c;
    }
  }
  out.push(cur);
  return out.map(s => s.trim());
}

app.post('/api/inventories/import-csv', uploadCsv.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: 'Thiếu file CSV' });
    const lines = parseCsvLines(req.file.buffer);
    if (lines.length < 2) return res.status(400).json({ ok: false, error: 'CSV không có dữ liệu' });

    const header = splitCsvLine(lines[0]).map(h => h.toLowerCase());

    // Map header tiếng Việt -> field
    const idx = {
      sku: header.findIndex(h => ['mã sản phẩm', 'ma san pham', 'sku', 'mã'].includes(h)),
      product_name: header.findIndex(h => ['tên sản phẩm', 'ten san pham', 'product name'].includes(h)),
      brand: header.findIndex(h => ['thương hiệu', 'thuong hieu', 'brand'].includes(h)),
      category_code: header.findIndex(h => ['mã ngành hàng', 'ma nganh hang', 'category code'].includes(h)),
      category_name: header.findIndex(h => ['tên ngành hàng', 'ten nganh hang', 'category name'].includes(h)),
      group_code: header.findIndex(h => ['mã nhóm sản phẩm', 'ma nhom san pham', 'group code'].includes(h)),
      group_name: header.findIndex(h => ['tên nhóm sản phẩm', 'ten nhom san pham', 'group name'].includes(h)),
      branch_code: header.findIndex(h => ['mã chi nhánh', 'ma chi nhanh', 'branch code', 'mã cửa hàng'].includes(h)),
      branch_name: header.findIndex(h => ['tên chi nhánh', 'ten chi nhanh', 'branch name'].includes(h)),
      zone: header.findIndex(h => ['khu vực (zone)', 'khu vực', 'zone'].includes(h)),
      uom: header.findIndex(h => ['đvt', 'don vi tinh', 'uom', 'unit'].includes(h)),
      stock_qty: header.findIndex(h => ['số lượng tồn', 'so luong ton', 'stockqty', 'qty', 'stock'].includes(h)),
    };
    if (idx.sku < 0 || idx.branch_code < 0 || idx.stock_qty < 0) {
      return res.status(400).json({ ok: false, error: 'Header bắt buộc thiếu: Mã sản phẩm / Mã chi nhánh / Số lượng tồn' });
    }

    // Build payloads
    const rows = [];
    for (let i = 1; i < lines.length; i++) {
      const cols = splitCsvLine(lines[i]);
      const get = (k) => idx[k] >= 0 ? (cols[idx[k]] || '').toString().trim() : '';
      const stock = Number(String(get('stock_qty')).replace(/[^\d\-\.,]/g, '').replace('.', '').replace(',', '.')) || 0;

      const obj = {
        sku: get('sku'),
        product_name: get('product_name'),
        brand: get('brand'),
        category_code: get('category_code'),
        category_name: get('category_name'),
        group_code: get('group_code'),
        group_name: get('group_name'),
        branch_code: get('branch_code'),
        branch_name: get('branch_name'),
        zone: get('zone'),
        uom: get('uom'),
        stock_qty: stock,
        updated_at: new Date().toISOString(),
      };
      if (obj.sku && obj.branch_code) rows.push(obj);
    }

    // Upsert theo (sku, branch_code) — chia batch để tránh payload quá lớn
    const BATCH = 1000;
    let inserted = 0, failed = 0, lastError = null;
    for (let i = 0; i < rows.length; i += BATCH) {
      const part = rows.slice(i, i + BATCH);
      const { error, count } = await supabase
        .from('inventories')
        .upsert(part, { onConflict: 'sku,branch_code' });
      if (error) { failed += part.length; lastError = error.message; }
      else inserted += part.length;
    }
    res.json({ ok: true, upserted: inserted, failed, lastError });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/utils/bom/import', uploadCsv.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: 'Thiếu file CSV' });
    const lines = parseCsvLines(req.file.buffer);
    if (lines.length < 2) return res.status(400).json({ ok: false, error: 'CSV không có dữ liệu' });

    const header = splitCsvLine(lines[0]).map(h => h.toLowerCase());
    const idx = {
      final_sku: header.findIndex(h => ['finalsku', 'sku thành phẩm', 'sku thanh pham'].includes(h)),
      final_name: header.findIndex(h => ['finalname', 'tên thành phẩm', 'ten thanh pham', 'name'].includes(h)),
      component_sku: header.findIndex(h => ['componentsku', 'sku linh kiện', 'sku linh kien'].includes(h)),
      component_name: header.findIndex(h => ['componentname', 'tên linh kiện', 'ten linh kien'].includes(h)),
      qty_per: header.findIndex(h => ['qtyper', 'qty', 'số lượng', 'so luong', 'sl'].includes(h)),
    };
    if (idx.final_sku < 0 || idx.component_sku < 0)
      return res.status(400).json({ ok: false, error: 'Header bắt buộc thiếu: FinalSKU / ComponentSKU' });

    const rows = [];
    for (let i = 1; i < lines.length; i++) {
      const c = splitCsvLine(lines[i]);
      const get = (k) => idx[k] >= 0 ? (c[idx[k]] || '').toString().trim() : '';
      const qty = Number(String(get('qty_per')).replace(',', '.')) || 1;
      const obj = {
        final_sku: get('final_sku'),
        final_name: get('final_name'),
        component_sku: get('component_sku'),
        component_name: get('component_name'),
        qty_per: qty,
      };
      if (obj.final_sku && obj.component_sku) rows.push(obj);
    }

    // có thể xoá BOM cũ của các final_sku được import (tùy)
    // await supabase.from('bom_relations').delete().in('final_sku', Array.from(new Set(rows.map(r=>r.final_sku))));

    const BATCH = 1000;
    let inserted = 0, failed = 0, lastError = null;
    for (let i = 0; i < rows.length; i += BATCH) {
      const part = rows.slice(i, i + BATCH);
      const { error } = await supabase.from('bom_relations').insert(part);
      if (error) { failed += part.length; lastError = error.message; }
      else inserted += part.length;
    }
    res.json({ ok: true, inserted, failed, lastError });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/utils/bom/by-final', async (req, res) => {
  try {
    const sku = (req.query.sku || '').trim();
    if (!sku) return res.status(400).json({ ok: false, error: 'Thiếu sku' });

    // Lấy các dòng BOM của final_sku
    const { data: parts, error: e1 } = await supabase
      .from('bom_relations')
      .select('component_sku, component_name, qty_per, final_name')
      .eq('final_sku', sku);
    if (e1) throw e1;

    if (!parts || !parts.length) return res.json({ ok: true, final: { sku, name: null }, components: [], branches: [] });

    const finalName = parts[0]?.final_name || null;

    // Lấy tồn kho cho toàn bộ linh kiện liên quan
    const compSkus = Array.from(new Set(parts.map(p => p.component_sku)));
    const { data: inv, error: e2 } = await supabase
      .from('inventories')
      .select('sku, branch_code, branch_name, stock_qty')
      .in('sku', compSkus);
    if (e2) throw e2;

    // Gom theo branch
    const branches = {};
    for (const r of inv) {
      if (!branches[r.branch_code]) branches[r.branch_code] = { branch: r.branch_code, branch_name: r.branch_name, stockBySku: {} };
      branches[r.branch_code].stockBySku[r.sku] = (branches[r.branch_code].stockBySku[r.sku] || 0) + Number(r.stock_qty || 0);
    }

    // Tính buildable từng branch
    const out = [];
    const branchKeys = Object.keys(branches).sort();
    for (const b of branchKeys) {
      const ctx = branches[b];
      let minBuild = Infinity;
      const detail = [];
      for (const p of parts) {
        const have = ctx.stockBySku[p.component_sku] || 0;
        const need = Number(p.qty_per || 1);
        const can = Math.floor(have / need);
        detail.push({ compSKU: p.component_sku, compName: p.component_name, need, have, can });
        if (can < minBuild) minBuild = can;
      }
      if (minBuild === Infinity) minBuild = 0;
      out.push({ branch: b, branch_name: ctx.branch_name, buildable: minBuild, components: detail });
    }

    res.json({
      ok: true,
      final: { sku, name: finalName },
      components: parts.map(p => ({ compSKU: p.component_sku, compName: p.component_name, qtyPer: p.qty_per })),
      branches: out
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/utils/bom/by-component', async (req, res) => {
  try {
    const comp = (req.query.sku || '').trim();
    if (!comp) return res.status(400).json({ ok: false, error: 'Thiếu sku' });

    // Tìm các final có dùng linh kiện này
    const { data: finals, error: e1 } = await supabase
      .from('bom_relations')
      .select('final_sku, final_name')
      .eq('component_sku', comp);
    if (e1) throw e1;

    const uniqFinals = Array.from(new Map(finals.map(f => [f.final_sku, { sku: f.final_sku, name: f.final_name }])).values());
    const results = [];

    // Với mỗi final_sku, tính buildable như trên
    for (const f of uniqFinals) {
      const { data: parts, error: e2 } = await supabase
        .from('bom_relations')
        .select('component_sku, component_name, qty_per')
        .eq('final_sku', f.sku);
      if (e2) throw e2;

      const compSkus = Array.from(new Set(parts.map(p => p.component_sku)));
      const { data: inv, error: e3 } = await supabase
        .from('inventories')
        .select('sku, branch_code, branch_name, stock_qty')
        .in('sku', compSkus);
      if (e3) throw e3;

      const branches = {};
      for (const r of inv) {
        if (!branches[r.branch_code]) branches[r.branch_code] = { branch: r.branch_code, branch_name: r.branch_name, stockBySku: {} };
        branches[r.branch_code].stockBySku[r.sku] = (branches[r.branch_code].stockBySku[r.sku] || 0) + Number(r.stock_qty || 0);
      }

      const out = [];
      for (const b of Object.keys(branches).sort()) {
        const ctx = branches[b];
        let minBuild = Infinity;
        for (const p of parts) {
          const have = ctx.stockBySku[p.component_sku] || 0;
          const need = Number(p.qty_per || 1);
          const can = Math.floor(have / need);
          if (can < minBuild) minBuild = can;
        }
        if (minBuild === Infinity) minBuild = 0;
        out.push({ branch: b, branch_name: ctx.branch_name, buildable: minBuild });
      }

      results.push({ final: f, branches: out });
    }

    res.json({ ok: true, component: comp, results });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// app.get('/tien-ich', requireAuth, (req, res) => {
  // res.render('tien-ich', { user: req.user || null });
// });



// ========================= FIFO CHECKING ROUTES =========================
// server.js (THAY THẾ HÀM NÀY - bắt đầu từ dòng 256)
async function fetchInventoryFromBigQuery(branchCode, masterQuery, giftFilter, isAdminBranch, filters, page = 1, pageSize = 50) { // Thêm page, pageSize
    if (!bigquery) {
        console.warn("Sử dụng dữ liệu giả lập vì BigQuery chưa cấu hình.");
        // (Phần fallback mock data giữ nguyên, nhưng cần tính total giả lập)
        const mockData = [
            // ... (dữ liệu mock của bạn) ...
             { sku: '220902468', sku_name: 'HP AiO ProOne 400 G4', brand: 'HP', serial: '8CG8404MWW', location: 'TL-A-01-A', bin_zone: 'Lưu kho thanh lý', branch_id: 'CP01', subcategory_name: 'Máy tính bộ Văn phòng', date_in: '2025-10-24', days_old: 1 },
             { sku: '250804341', sku_name: 'Brother DCP-L2520D', brand: 'Brother', serial: 'E7380GTN330059', location: 'CD.03-VK5.01-a', bin_zone: 'Trung bày chính', branch_id: 'CP01', subcategory_name: 'Máy in', date_in: '2025-10-22', days_old: 3 },
             { sku: 'MOCK001', sku_name: 'Mock Product 1', brand: 'MockBrand', serial: 'MOCKSERIAL001', location: 'A1', bin_zone: 'Zone A', branch_id: 'CP01', subcategory_name: 'Mock Subcat', date_in: '2025-01-01', days_old: 200 },
             // Thêm nhiều dòng mock nếu cần test phân trang
        ];
        // Lọc giả lập
        let filteredData = mockData.filter(item => item.branch_id === branchCode);
        if (filters && filters.bin_zone) {
            filteredData = filteredData.filter(item => item.bin_zone === filters.bin_zone);
        }
        if (masterQuery) {
            const mqLower = masterQuery.toLowerCase();
             filteredData = filteredData.filter(item => 
                 (item.sku && String(item.sku).toLowerCase().includes(mqLower)) || 
                 (item.serial && String(item.serial).toLowerCase().includes(mqLower)) ||
                 (item.sku_name && String(item.sku_name).toLowerCase().includes(mqLower)) ||
                 (item.brand && String(item.brand).toLowerCase().includes(mqLower)) ||
                 (item.location && String(item.location).toLowerCase().includes(mqLower))
            );
        }
         const total = filteredData.length;
         const offset = (page - 1) * pageSize;
         const paginatedData = filteredData.slice(offset, offset + pageSize);
        
        return { 
            data: paginatedData, 
            total: total, // Trả về tổng số (sau lọc)
            searchedItem: (masterQuery ? filteredData.find(i => i.serial === masterQuery) : null) 
        };
    }

    const BIGQUERY_TABLE = '`nimble-volt-459313-b8.Inventory.inv_seri_1`';
    
    // --- Xử lý bộ lọc ---
    const params = { 
        branchCode: branchCode, 
        masterQuery: masterQuery, 
        likeQuery: `%${masterQuery}%` ,
        pageSize: pageSize, // Thêm pageSize vào params
        offset: (page - 1) * pageSize // Thêm offset vào params
    };
    
    let filterConditions = '';
    // Lọc chi nhánh (chỉ áp dụng nếu không phải admin)
    if (!isAdminBranch) {
        filterConditions += ' AND Branch_ID = @branchCode';
    }
    // Lọc quà tặng
    if (giftFilter === 'no') { 
        filterConditions += " AND (SubCategory_name NOT LIKE 'Quà tặng%' OR SubCategory_name IS NULL)"; 
    }
    // Lọc từ dropdowns (filters)
    if (filters) {
        if (filters.subcategory) {
            filterConditions += ` AND SubCategory_name = @subcategory`;
            params.subcategory = filters.subcategory;
        }
        if (filters.brand) {
            filterConditions += ` AND Brand = @brand`;
            params.brand = filters.brand;
        }
        if (filters.location) {
            filterConditions += ` AND Location = @location`;
            params.location = filters.location;
        }
        if (filters.bin_zone) {
            filterConditions += ` AND BIN_zone = @bin_zone`;
            params.bin_zone = filters.bin_zone;
        }
    }
     // Điều kiện tìm kiếm chính (ô input)
     const searchQueryCondition = `
         AND ( @masterQuery = '' OR CAST(SKU AS STRING) LIKE @likeQuery OR SKU_name LIKE @likeQuery
               OR Serial LIKE @likeQuery OR Location LIKE @likeQuery OR Brand LIKE @likeQuery )
     `;
    // --- Kết thúc xử lý bộ lọc ---

    const isLikelySerialSearch = masterQuery.length >= 8 && !/^\d+$/.test(masterQuery);

    // --- Query chính (lấy dữ liệu trang hiện tại) ---
    const query = `
        SELECT
            CAST(SKU AS STRING) AS sku, SKU_name AS sku_name, Brand AS brand, Serial AS serial,
            Location AS location, BIN_zone AS bin_zone, Branch_ID AS branch_id,
            SubCategory_name AS subcategory_name,
            FORMAT_DATE('%Y-%m-%d', Date_import_company) AS date_in,
            Aging_company AS days_old
        FROM ${BIGQUERY_TABLE}
        WHERE 1=1
            ${filterConditions} -- Áp dụng bộ lọc dropdown + branch
            ${searchQueryCondition} -- Áp dụng ô tìm kiếm
        ORDER BY Date_import_company ASC
        LIMIT @pageSize OFFSET @offset -- Áp dụng phân trang
    `;

    // --- Query đếm tổng số kết quả ---
    const countQuery = `
        SELECT COUNT(*) as total
        FROM ${BIGQUERY_TABLE}
        WHERE 1=1
            ${filterConditions} -- Áp dụng bộ lọc dropdown + branch
            ${searchQueryCondition} -- Áp dụng ô tìm kiếm
    `;

    // Bỏ pagination params khỏi query đếm
    const countParams = { ...params };
    delete countParams.pageSize;
    delete countParams.offset;

    const options = {
        query: query, 
        location: 'asia-southeast1',
        params: params, 
    };
     const countOptions = {
         query: countQuery,
         location: 'asia-southeast1',
         params: countParams, 
     };


    try {
        // Chạy song song 2 query
        const [[rows], [countResult]] = await Promise.all([
             bigquery.query(options),
             bigquery.query(countOptions)
        ]);

        const total = countResult[0]?.total || 0;
        const mappedRows = rows.map(r => ({ ...r, branch_id: String(r.branch_id), date_in: r.date_in || null, days_old: r.days_old || 0 }));

        let searchedItem = null;
        if (isLikelySerialSearch && masterQuery) {
            searchedItem = mappedRows.find(item => item.serial === masterQuery);
        }

        return { data: mappedRows, total: total, searchedItem: searchedItem }; // Trả về total

    } catch (e) {
        console.error("BIGQUERY QUERY ERROR:", e.message);
        throw new Error("BigQuery Query Error: " + e.message);
    }
}


// [1] Route hiển thị trang (THAY THẾ TOÀN BỘ HÀM NÀY)
app.get('/fifo-checking', requireAuth, async (req, res) => {
    // ⚠️ Lấy Branch Code của User
    const userBranch = req.session.user?.branch_code || 'CP01'; // Default cho dev
    
    // ⭐ SỬA LỖI: Tính toán quyền admin ở phía server
    const isGlobalAdmin = (req.session.user?.role === 'admin' || req.session.user?.branch_code === 'HCM.BD');

    res.render('fifo-checking', {
        title: 'FIFO Checking',
        currentPage: 'fifo-checking',
        userBranch,
        isGlobalAdmin: isGlobalAdmin, // ⭐ TRUYỀN BIẾN NÀY RA VIEW
        error: null,
        todayDate: new Date().toISOString().slice(0, 10),
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
});


// DÁN ĐOẠN CODE MỚI NÀY VÀO server.js (trước route /api/fifo/serials)

async function fetchFilterOptions(branchCode, giftFilter, isAdminBranch) {
    if (!bigquery) {
        console.warn("BQ chưa cấu hình, trả về filter giả lập.");
        return {
            subcategories: ['Mock Subcat', 'Máy in', 'Máy tính bộ Văn phòng'],
            brands: ['MockBrand', 'HP', 'Brother'],
            locations: ['A1', 'TL-A-01-A', 'CD.03-VK5.01-a'],
            bin_zones: ['Zone A', 'Lưu kho thanh lý', 'Trung bày chính'],
        };
    }

    const BIGQUERY_TABLE = '`nimble-volt-459313-b8.Inventory.inv_seri_1`';
    const params = { branchCode: branchCode };

    let filterConditions = '';
    // Lọc chi nhánh
    if (!isAdminBranch) {
        filterConditions += ' AND Branch_ID = @branchCode';
    }
    // Lọc quà tặng
    if (giftFilter === 'no') { 
        filterConditions += " AND (SubCategory_name NOT LIKE 'Quà tặng%' OR SubCategory_name IS NULL)"; 
    }

    const queryOptions = (field) => ({
        query: `
            SELECT DISTINCT ${field}
            FROM ${BIGQUERY_TABLE}
            WHERE ${field} IS NOT NULL AND ${field} != ''
            ${filterConditions}
            ORDER BY ${field} ASC
            LIMIT 1000
        `,
        location: 'asia-southeast1',
        params: params,
    });

    try {
        // Chạy song song 4 query
        const [
            [subcategories],
            [brands],
            [locations],
            [bin_zones]
        ] = await Promise.all([
            bigquery.query(queryOptions('SubCategory_name')),
            bigquery.query(queryOptions('Brand')),
            bigquery.query(queryOptions('Location')),
            bigquery.query(queryOptions('BIN_zone')),
        ]);

        return {
            subcategories: subcategories.map(r => r.SubCategory_name),
            brands: brands.map(r => r.Brand),
            locations: locations.map(r => r.Location),
            bin_zones: bin_zones.map(r => r.BIN_zone),
        };

    } catch (e) {
        console.error("BIGQUERY FILTER QUERY ERROR:", e.message);
        throw new Error("BigQuery Filter Query Error: " + e.message);
    }
}

app.get('/api/fifo/filters', requireAuth, async (req, res) => {
    try {
        const giftFilter = req.query.giftFilter || 'no';
        const userBranch = req.session.user?.branch_code || 'CP01';
        const isGlobalAdmin = req.session.user?.role === 'admin' || userBranch === 'HCM.BD';

        const filters = await fetchFilterOptions(userBranch, giftFilter, isGlobalAdmin);
        
        res.json({ ok: true, filters: filters });

    } catch (e) {
        console.error('API FIFO Filters error:', e);
        res.status(500).json({ ok: false, error: 'Lỗi hệ thống: ' + e.message });
    }
});


// server.js (THAY THẾ HÀM app.get('/api/fifo/serials', ...))
app.get('/api/fifo/serials', requireAuth, async (req, res) => {
    let totalBranchCount = 0;
    let rankInfo = null;

    try {
        // Lấy bộ lọc chính
        const masterQuery = req.query.q || '';
        const giftFilter = req.query.giftFilter || 'no';
        const userBranch = req.session.user?.branch_code || 'CP01';
        const isGlobalAdmin = req.session.user?.role === 'admin' || userBranch === 'HCM.BD';
        const todayDate = new Date().toISOString().slice(0, 10);

        // === SỬA LỖI: ĐỌC THAM SỐ PAGE ===
        const page = Math.max(parseInt(req.query.page || '1', 10), 1);
        // ==================================

        // [Req 3] Lấy các bộ lọc dropdown mới
        const filters = {
            subcategory: req.query.subcategory || null,
            brand: req.query.brand || null,
            location: req.query.location || null,
            bin_zone: req.query.bin_zone || null,
        };
        
        const hideCheckedOut = (req.query.hideCheckedOut === 'true');

        // --- BƯỚC 1: LẤY TRẠNG THÁI SUPABASE ---
        let checkedSerials = new Map();
        try {
            let statusQuery = supabase.from('serial_check_log').select('serial, checked_out').eq('check_date', todayDate);
            if (!isGlobalAdmin) { statusQuery = statusQuery.eq('branch_code', userBranch); }
            const { data: logData, error: statusError } = await statusQuery;
            if (statusError) { console.error("Lỗi lấy trạng thái Supabase:", statusError.message); }
            else { checkedSerials = new Map((logData || []).map(log => [log.serial, log.checked_out])); }
        } catch(e) { console.error("Lỗi nghiêm trọng khi lấy trạng thái Supabase:", e.message); }

        // --- BƯỚC 2: ĐẾM TỔNG SERIAL BIGQUERY (Giữ nguyên) ---
        if (bigquery) { /* ... logic đếm tổng ... */ }
        else { console.warn("Không thể đếm tổng serial."); }
        
        // --- BƯỚC 3: LẤY DỮ LIỆU CHI TIẾT BIGQUERY (Truyền 'filters' và 'page' vào) ---
        // === SỬA LỖI: TRUYỀN 'page' VÀO HÀM FETCH ===
        let fetchResult = await fetchInventoryFromBigQuery(userBranch, masterQuery, giftFilter, isGlobalAdmin, filters, page);
        // ==============================================
        
        let inventoryData = fetchResult.data;
        const totalItems = fetchResult.total; // Lấy tổng số item từ kết quả
        const searchedItem = fetchResult.searchedItem; // [Req 2] Lấy item đã tìm thấy

        // Trả về totalItems để JS render phân trang
        if (!inventoryData || !inventoryData.length) {
            return res.json({ ok: true, serials: [], total: 0, totalBranchCount: totalBranchCount, rankInfo: null });
        }

        // --- BƯỚC 4: MERGE VỚI TRẠNG THÁI SUPABASE & LỌC ĐÃ XUẤT ---
        let finalSerials = [];
        for (const item of inventoryData) {
            const isChecked = checkedSerials.get(item.serial) || false;
            
            if (hideCheckedOut && isChecked) {
                continue; 
            }
            
            finalSerials.push({
                ...item,
                date_in_ms: item.date_in ? new Date(item.date_in).getTime() : 0,
                is_checked_out: isChecked,
            });
        }

        // --- BƯỚC 5: [Req 2] TÍNH RANK ---
        if (searchedItem && !checkedSerials.get(searchedItem.serial) && bigquery) {
            const skuToRank = searchedItem.sku;
            console.log(`[DEBUG] Calculating rank for Serial ${masterQuery} (SKU: ${skuToRank})`);

            // Chỉ lấy các serial CÙNG SKU và CÙNG CHI NHÁNH (nếu ko phải admin)
            const rankQuery = `
                SELECT Serial, Date_import_company
                FROM \`nimble-volt-459313-b8.Inventory.inv_seri_1\`
                /* ⭐ SỬA LỖI: Ép kiểu @skuToRank thành INT64 */
                WHERE SKU = CAST(@skuToRank AS INT64) 
                  ${!isGlobalAdmin ? 'AND Branch_ID = @branchCode' : ''} 
                ORDER BY Date_import_company ASC
            `;
            const rankOptions = {
                query: rankQuery, location: 'asia-southeast1',
                params: { skuToRank: String(skuToRank), branchCode: userBranch }
            };

            try {
                const [allSkuSerials] = await bigquery.query(rankOptions);

                // Lấy trạng thái xuất của TẤT CẢ serial cùng SKU (để loại trừ)
                const skuSerialList = allSkuSerials.map(s => s.Serial);
                const { data: skuLogData } = await supabase
                    .from('serial_check_log')
                    .select('serial, checked_out')
                    .in('serial', skuSerialList)
                    // Lọc theo branch VÀ ngày
                    .eq(!isGlobalAdmin ? 'branch_code' : '1', !isGlobalAdmin ? userBranch : '1')
                    .eq('check_date', todayDate);
                
                // Map trạng thái checkout (merge map tổng và map của SKU)
                const skuCheckedSerialsMap = new Map([...checkedSerials, ...((skuLogData || []).map(log => [log.serial, log.checked_out]))]);

                // Lọc bỏ những serial đã xuất khỏi danh sách xếp hạng
                const activeSkuSerials = allSkuSerials.filter(s => !skuCheckedSerialsMap.get(s.Serial));
                
                // Tìm rank
                const rank = activeSkuSerials.findIndex(s => s.Serial === masterQuery) + 1; // Rank bắt đầu từ 1
                const totalActive = activeSkuSerials.length;

                if (rank > 0) {
                    rankInfo = { serial: masterQuery, rank: rank, total: totalActive, sku: skuToRank };
                    console.log(`[DEBUG] Rank calculated: ${rank}/${totalActive}`);
                } else { 
                    console.log(`[DEBUG] Searched serial ${masterQuery} not found in active list (maybe checked out).`); 
                }
            } catch (rankError) { console.error("LỖI TÍNH RANK:", rankError.message); }
        } else if (searchedItem) {
            console.log(`[DEBUG] Rank skipped (Item already checked out or BQ disabled)`);
        }

        // --- BƯỚC 6: SẮP XẾP KẾT QUẢ CUỐI CÙNG (FIFO) ---
        finalSerials.sort((a, b) => (a.date_in_ms || 0) - (b.date_in_ms || 0));

        // --- BƯỚC 7: TRẢ KẾT QUẢ ---
        // === SỬA LỖI: Trả về 'totalItems' để phân trang ===
        res.json({ ok: true, serials: finalSerials, total: totalItems, totalBranchCount: totalBranchCount, rankInfo: rankInfo });

    } catch (e) {
        console.error('API FIFO Serials error:', e);
        res.status(500).json({ ok: false, error: 'Lỗi hệ thống: ' + e.message, total: 0, totalBranchCount: 0, rankInfo: null });
    }
});

// [3] API lưu trạng thái check
app.post('/api/fifo/log', requireAuth, async (req, res) => {
    try {
        const { serial, branch_code, check_date, sku, is_checked_out } = req.body;
        
        if (!serial || !branch_code || !check_date || !sku) {
            return res.status(400).json({ ok: false, error: 'Thiếu thông tin bắt buộc.' });
        }
        
        const logPayload = {
            serial,
            sku,
            branch_code,
            check_date,
            checked_out: is_checked_out,
            checked_by: req.session.user.id,
            checked_at: new Date().toISOString(),
        };

        // Upsert theo (serial, check_date) để lưu trạng thái mới nhất cho serial đó
        const { data, error } = await supabase
            .from('serial_check_log')
            .upsert(logPayload, { onConflict: 'serial,check_date' })
            .select()
            .single();

        if (error) throw error;
        
        res.json({ ok: true, updated: data });
    } catch (e) {
        console.error('API FIFO Log error:', e);
        res.status(500).json({ ok: false, error: 'Lỗi khi lưu trạng thái: ' + e.message });
    }
});

// [4] API xem lịch sử check log
app.get('/api/fifo/history/:serial', requireAuth, async (req, res) => {
    try {
        const serial = req.params.serial;
        
        // Chỉ lấy các log "Đã xuất"
        const { data: history, error } = await supabase
            .from('serial_check_log')
            .select(`*, users:checked_by(full_name, email)`)
            .eq('serial', serial)
            .eq('checked_out', true)
            .order('checked_at', { ascending: false })
            .limit(50);
            
        if (error) throw error;

        res.json({ ok: true, history: history.map(r => ({
            ...r,
            checked_by_name: r.users?.full_name || r.users?.email || 'Unknown',
        })) });

    } catch (e) {
        console.error('API FIFO History error:', e);
        res.status(500).json({ ok: false, error: 'Lỗi khi tải lịch sử: ' + e.message });
    }
});


// ========================= NEWSFEED (BẢNG TIN) =========================
// ========================= NEWSFEED (BẢNG TIN - CÓ LỌC) =========================
app.get('/newsfeed', requireAuth, async (req, res) => {
  try {
    // === BƯỚC 1: LẤY CÁC THAM SỐ LỌC TỪ URL ===
    const selectedCategory = req.query.category || '';
    const searchQuery = req.query.q || '';
    const selectedPeriod = req.query.period || ''; // Sẽ dùng cho BXH

    const today = new Date().toISOString();

    // === BƯỚC 2: LẤY DANH SÁCH TÙY CHỌN CHO BỘ LỌC ===
    // Lấy tất cả Category (chủ đề) duy nhất từ DB
    const { data: categoriesData } = await supabase
      .from('newsfeed_posts')
      .select('category')
      .neq('category', null) // Bỏ qua các category rỗng
      .eq('status', 'published'); // Chỉ lấy category của tin đã đăng
    const allCategories = [...new Set((categoriesData || []).map(c => c.category))].sort();

    // Lấy tất cả Chu kỳ (period) duy nhất từ Bảng xếp hạng
    const { data: periodsData } = await supabase
      .from('newsfeed_ranking')
      .select('display_period')
      .neq('display_period', null);
    const allPeriods = [...new Set((periodsData || []).map(p => p.display_period))].sort((a,b) => b.localeCompare(a)); // Sắp xếp mới nhất

    // Xác định chu kỳ hiện tại để lọc BXH (ưu tiên cái user chọn, nếu không thì lấy cái mới nhất)
    // === LOGIC MỚI: Ưu tiên default về tháng hiện tại (NẾU CÓ) ===
    
    // 1. Tạo chuỗi tháng hiện tại (ví dụ: "Tháng 11.2025")
    const now = new Date();
    const currentMonthString = `Tháng ${now.getMonth() + 1}.${now.getFullYear()}`;

    const defaultPeriod = allPeriods.includes(currentMonthString) 
                          ? currentMonthString   // Nếu có, dùng tháng hiện tại
                          : (allPeriods.length > 0 ? allPeriods[0] : ''); // Nếu không, dùng chu kỳ mới nhất


    const currentPeriod = selectedPeriod || defaultPeriod;
    // === KẾT THÚC THAY ĐỔI ===

    // === BƯỚC 3: TRUY VẤN BÀI ĐĂNG (ĐÃ LỌC) ===

    // --- Xây dựng truy vấn cơ sở cho Bài Đăng ---
    const buildPostQuery = (isFeatured) => {
      let query = supabase
        .from('newsfeed_posts')
        .select('*')
        .eq('status', 'published')
        .eq('is_featured', isFeatured)
        .lte('published_at', today);

      // 1. Lọc theo Category (nếu user chọn)
      if (selectedCategory) {
        query = query.eq('category', selectedCategory);
      }

      // 2. Lọc theo Tìm kiếm 'q' (nếu user gõ)
      if (searchQuery) {
        // Tìm 'q' trong cả 'title' (tiêu đề) VÀ 'subtitle' (tiêu đề phụ)
        query = query.or(`title.ilike.%${searchQuery}%,subtitle.ilike.%${searchQuery}%`);
      }

      return query;
    };

    // --- Chạy truy vấn cho Tin Nổi Bật (Featured) ---
    const { data: featuredPostData, error: featuredError } = await buildPostQuery(true)
      .order('published_at', { ascending: false })
      .limit(1);
    if (featuredError) throw new Error(`Lỗi lấy tin nổi bật: ${featuredError.message}`);

    // --- Chạy truy vấn cho Tin Tức (News) ---
    const { data: newsPostData, error: newsError } = await buildPostQuery(false)
      .order('published_at', { ascending: false })
      .limit(5);
    if (newsError) throw new Error(`Lỗi lấy tin tức: ${newsError.message}`);


    // === BƯỚC 4: TRUY VẤN BẢNG XẾP HẠNG (ĐÃ LỌC) ===
    let rankingTop1 = null;
    let rankingOthers = [];

    if (currentPeriod) { // Chỉ lấy BXH nếu có chu kỳ
      const { data: rankingData, error: rankingError } = await supabase
        .from('newsfeed_ranking')
        .select('*')
        .eq('display_period', currentPeriod) // Lọc theo chu kỳ (user chọn hoặc mới nhất)
        .order('rank_order', { ascending: true })
        .limit(20);

      if (rankingError) throw new Error(`Lỗi lấy BXH: ${rankingError.message}`);

      rankingTop1 = (rankingData || []).find(r => r.rank_order === 1) || null;
      rankingOthers = (rankingData || []).filter(r => r.rank_order > 1);
    }

    // === BƯỚC 5: TRẢ KẾT QUẢ RA VIEW ===
    res.render('newsfeed', {
      title: 'Bảng tin',
      currentPage: 'newsfeed',
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      error: null,

      // Dữ liệu đã lọc
      featuredPost: (featuredPostData && featuredPostData.length > 0) ? featuredPostData[0] : null,
      newsPosts: newsPostData || [],
      rankingTop1: rankingTop1,
      rankingOthers: rankingOthers,

      // Dữ liệu cho bộ lọc "nhớ"
      allCategories: allCategories,     // Danh sách category
      allPeriods: allPeriods,         // Danh sách chu kỳ
      selectedCategory: selectedCategory, // Category user đã chọn
      selectedPeriod: currentPeriod,      // Chu kỳ user đã chọn (hoặc mới nhất)
      searchQuery: searchQuery          // Từ khóa user đã gõ
    });

  } catch (e) {
    console.error('Lỗi trang Bảng tin:', e);
    res.render('newsfeed', {
      title: 'Bảng tin', currentPage: 'newsfeed', error: e.message,
      featuredPost: null, newsPosts: [], rankingTop1: null, rankingOthers: [],
      allCategories: [], allPeriods: [], selectedCategory: '', selectedPeriod: '', searchQuery: ''
    });
  }
});
// ======================= END NEWSFEED ==========================

// ========================= NEWSFEED ADMIN (SOẠN BÀI) =========================

// Route 1 (GET): Hiển thị trang/form soạn thảo
// Dùng requireManager để chỉ Manager/Admin mới vào được
app.get('/admin/create-post', requireManager, (req, res) => {
  res.render('admin-create-post', {
    title: 'Soạn bài đăng mới',
    currentPage: 'newsfeed', // Vẫn tô sáng 'Bảng tin' trên menu
    time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    error: null,
    post: {} // Gửi một object rỗng
  });
});

// Route 2 (POST): Nhận dữ liệu từ form và LƯU vào Supabase
app.post('/admin/create-post', requireManager, async (req, res) => {
  try {
    const {
      title,
      subtitle,
      content_html, // Đây là nội dung HTML từ trình soạn thảo
      cover_image_url,
      category,
      status,
      published_at,
      is_featured,
      send_email, extra_emails,
    } = req.body;


    // --- Validation đơn giản ---
    if (!title || !content_html || !category) {
      throw new Error('Tiêu đề, Nội dung, và Chủ đề là bắt buộc.');
    }

    // --- Chuẩn bị dữ liệu để lưu ---
    const insertPayload = {
      title: title,
      subtitle: subtitle || null,
      content: content_html, // Lưu nội dung HTML
      cover_image_url: cover_image_url || null,
      category: category,
      status: status || 'published', // Mặc định là 'published'

      // Xử lý ngày hẹn giờ (nếu có)
      published_at: published_at ? new Date(published_at) : new Date(),

      // Chuyển 'on' (từ checkbox) thành true/false
      is_featured: is_featured === 'on', 

      // Lấy ID của user đang đăng bài
      author_id: req.session.user.id
    };

    // --- Ghi vào Supabase ---
    const { data, error } = await supabase
      .from('newsfeed_posts')
      .insert(insertPayload)
      .select('id')
      .single();

    if (error) throw error;

    const newPostId = data.id;

    if (status === 'published') { // 1. Chỉ gửi khi bài đã published
          
          // 2. Luôn lấy email bổ sung
          const extraEmails = (extra_emails || '')
            .split(',')
            .map(e => e.trim())
            .filter(e => e); // Lọc bỏ chuỗi rỗng

          let allEmails = [];

          if (send_email === 'on') {
            // 3a. User tick "Gửi email" -> Lấy user + email lẻ
            const { data: users } = await supabase
              .from('users')
              .select('email')
              .eq('is_active', true);
            
            const userEmails = (users || []).map(u => u.email);
            allEmails = [...new Set([...userEmails, ...extraEmails])];
            
          } else if (extraEmails.length > 0) {
            // 3b. User KHÔNG tick, NHƯNG có nhập email lẻ -> Chỉ gửi email lẻ (TEST)
            allEmails = extraEmails;
          }

          // 4. Gửi email nếu có danh sách nhận
          if (allEmails.length > 0) {
            const postData = { ...insertPayload, id: newPostId };
            sendNewPostEmail(postData, allEmails);
          }
        }
    // === HẾT LOGIC GỬI EMAIL ===

    // Lưu thành công, chuyển hướng về trang Bảng tin
    return res.redirect('/newsfeed');

  } catch (e) {
    // Có lỗi, render lại trang soạn thảo và báo lỗi
    console.error('Lỗi tạo bài đăng:', e);
    res.render('admin-create-post', {
      title: 'Soạn bài đăng mới',
      currentPage: 'newsfeed',
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      error: e.message,
      post: req.body // Gửi lại dữ liệu đã nhập để user không phải gõ lại
    });
  }
});

// ======================= END NEWSFEED ADMIN ==========================

// ========================= NEWSFEED (CHI TIẾT BÀI ĐĂNG) =========================

// Route 3 (GET): Hiển thị chi tiết 1 bài đăng
app.get('/newsfeed/post/:id', requireAuth, async (req, res) => {
  try {
    const postId = req.params.id; // Lấy ID từ URL (ví dụ: '6')

    // Lấy thông tin bài đăng từ Supabase
    const { data: post, error } = await supabase
      .from('newsfeed_posts')
      .select(`*, users:author_id (full_name, email)`) // Lấy cả tên người đăng
      .eq('id', postId)
      .single(); // Lấy 1 bài duy nhất

    if (error) throw new Error(`Không tìm thấy bài đăng: ${error.message}`);

    if (!post) {
       return res.status(404).send('Không tìm thấy bài đăng.');
    }

    res.render('post-detail', {
      title: post.title, // Tiêu đề trang sẽ là tiêu đề bài viết
      currentPage: 'newsfeed',
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      error: null,
      post: post // Gửi toàn bộ thông tin bài đăng ra view
    });

  } catch (e) {
    console.error('Lỗi trang chi tiết bài đăng:', e);
    // Chuyển về trang Bảng tin nếu có lỗi
    res.redirect('/newsfeed?error=' + encodeURIComponent(e.message));
  }
});

// ======================= END NEWSFEED (CHI TIẾT) ==========================

// ========================= NEWSFEED (SỬA / XOÁ BÀI) =========================

// Route 4 (DELETE): Xử lý yêu cầu Xoá bài
app.delete('/api/post/delete/:id', requireManager, async (req, res) => {
  try {
    const postId = req.params.id;

    const { error } = await supabase
      .from('newsfeed_posts')
      .delete() // Lệnh xoá
      .eq('id', postId); // Điều kiện là id = postId

    if (error) throw error;

    res.json({ ok: true, message: 'Xoá thành công' });

  } catch (e) {
    console.error('Lỗi khi xoá bài đăng:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});


// Route 5 (GET): Hiển thị trang Sửa bài
// (Giống hệt trang "Soạn bài mới" nhưng load dữ liệu cũ)
app.get('/admin/edit-post/:id', requireManager, async (req, res) => {
  try {
    const postId = req.params.id;

    // Lấy dữ liệu bài đăng cũ
    const { data: post, error } = await supabase
      .from('newsfeed_posts')
      .select('*')
      .eq('id', postId)
      .single();

    if (error) throw new Error(`Không tìm thấy bài đăng: ${error.message}`);

    res.render('admin-edit-post', { // Dùng 1 file view MỚI
      title: 'Sửa bài đăng',
      currentPage: 'newsfeed',
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      error: null,
      post: post // Gửi dữ liệu bài đăng cũ ra view
    });

  } catch (e) {
    console.error('Lỗi trang Sửa bài:', e);
    res.redirect('/newsfeed?error=' + encodeURIComponent(e.message));
  }
});

// Route 6 (POST): Nhận dữ liệu CẬP NHẬT từ trang Sửa bài
app.post('/admin/edit-post/:id', requireManager, async (req, res) => {
  const postId = req.params.id; // Lấy ID từ URL

  try {
    const {
      title,
      subtitle,
      content_html, // Đây là nội dung HTML từ trình soạn thảo
      cover_image_url,
      category,
      status,
      published_at,
      is_featured,
      send_email, extra_emails
    } = req.body;

    if (!title || !content_html || !category) {
      throw new Error('Tiêu đề, Nội dung, và Chủ đề là bắt buộc.');
    }

    // --- Chuẩn bị dữ liệu để CẬP NHẬT ---
    const updatePayload = {
      title: title,
      subtitle: subtitle || null,
      content: content_html,
      cover_image_url: cover_image_url || null,
      category: category,
      status: status || 'published',
      published_at: published_at ? new Date(published_at) : new Date(),
      is_featured: is_featured === 'on',
      // Không cần cập nhật author_id
    };

    // --- Ghi CẬP NHẬT vào Supabase ---
    const { data, error } = await supabase
      .from('newsfeed_posts')
      .update(updatePayload) // Lệnh cập nhật
      .eq('id', postId); // Điều kiện là id = postId

    if (error) throw error;

    // === LOGIC GỬI EMAIL MỚI KHI SỬA (ĐÃ SỬA ĐỂ TEST) ===
        if (status === 'published') {
          
          const extraEmails = (extra_emails || '').split(',').map(e => e.trim()).filter(e => e);
          let allEmails = [];

          if (send_email === 'on') {
            // Gửi cho tất cả user + email lẻ
            const { data: users } = await supabase.from('users').select('email').eq('is_active', true);
            const userEmails = (users || []).map(u => u.email);
            allEmails = [...new Set([...userEmails, ...extraEmails])];
          } else if (extraEmails.length > 0) {
            // Chỉ gửi cho email lẻ (TEST)
            allEmails = extraEmails;
          }

          if (allEmails.length > 0) {
            const postData = { ...updatePayload, id: postId };
            sendNewPostEmail(postData, allEmails);
          }
        }
        // === HẾT LOGIC GỬI EMAIL ===

    // Cập nhật thành công, chuyển về trang chi tiết bài viết
    return res.redirect(`/newsfeed/post/${postId}`);

  } catch (e) {
    // Có lỗi, render lại trang SỬA và báo lỗi
    console.error(`Lỗi khi cập nhật bài đăng #${postId}:`, e);
    // Tải lại dữ liệu cũ để hiển thị (vì req.body có thể không đủ)
    const { data: post } = await supabase.from('newsfeed_posts').select('*').eq('id', postId).single();

    res.render('admin-edit-post', {
      title: 'Sửa bài đăng',
      currentPage: 'newsfeed',
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      error: e.message,
      post: post || req.body // Ưu tiên dữ liệu post gốc
    });
  }
});

// ======================= END NEWSFEED (SỬA / XOÁ) ==========================


// ===============================================
// MODULE QUẢN LÝ BẢNG XẾP HẠNG (CRUD)
// ===============================================

// Route 1 (GET): Hiển thị trang danh sách (Read)
app.get('/admin/ranking', requireManager, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('newsfeed_ranking')
      .select('*')
      .order('display_period', { ascending: false }) // Sắp xếp theo chu kỳ
      .order('rank_order', { ascending: true }); // Sắp xếp theo hạng

    if (error) throw error;
    
    res.render('admin-ranking-list', {
      title: 'Quản lý Bảng xếp hạng',
      currentPage: 'newsfeed',
      time: res.locals.time,
      rankings: data || [],
      error: null
    });
  } catch (e) {
    res.render('admin-ranking-list', {
      title: 'Quản lý Bảng xếp hạng', currentPage: 'newsfeed', time: res.locals.time,
      rankings: [], error: e.message
    });
  }
});

// Route 2 (GET): Hiển thị form Thêm Mới (Create)
app.get('/admin/ranking/new', requireManager, (req, res) => {
  res.render('admin-ranking-form', {
    title: 'Thêm mục BXH',
    currentPage: 'newsfeed',
    time: res.locals.time,
    error: null,
    ranking: {}, // Gửi object rỗng
    action: '/admin/ranking/new' // Đường dẫn POST
  });
});

// Route 3 (GET): Hiển thị form Sửa (Update)
app.get('/admin/ranking/edit/:id', requireManager, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('newsfeed_ranking')
      .select('*')
      .eq('id', req.params.id)
      .single();
    if (error) throw error;
    
    res.render('admin-ranking-form', {
      title: 'Sửa mục BXH',
      currentPage: 'newsfeed',
      time: res.locals.time,
      error: null,
      ranking: data, // Gửi object có dữ liệu
      action: `/admin/ranking/edit/${req.params.id}` // Đường dẫn POST
    });
  } catch (e) {
    res.redirect('/admin/ranking?error=' + encodeURIComponent(e.message));
  }
});

// Route 4 (POST): Xử lý Thêm Mới (Create) hoặc Cập Nhật (Update)
app.post('/admin/ranking/:action/:id?', requireManager, async (req, res) => {
  const { action, id } = req.params;
  const {
    full_name,
    rank_order,
    display_period,
    birth_year,
    store,
    department,
    avatar_image_url
  } = req.body;

  try {
    if (!full_name || !rank_order || !display_period) {
      throw new Error('Tên, Hạng, và Chu kỳ là bắt buộc.');
    }
    
    const payload = {
      full_name,
      rank_order: parseInt(rank_order) || 0,
      display_period,
      birth_year: birth_year ? parseInt(birth_year) : null,
      store: store || null,
      department: department || null,
      avatar_image_url: avatar_image_url || null,
      sales_percentage: req.body.sales_percentage ? parseFloat(req.body.sales_percentage) : null
    };

    if (action === 'new') {
      // Thêm Mới
      const { error } = await supabase.from('newsfeed_ranking').insert(payload);
      if (error) throw error;
    } else if (action === 'edit' && id) {
      // Cập Nhật
      const { error } = await supabase.from('newsfeed_ranking').update(payload).eq('id', id);
      if (error) throw error;
    }

    res.redirect('/admin/ranking'); // Về trang danh sách
    
  } catch (e) {
    // Gửi lỗi lại form
    res.render('admin-ranking-form', {
      title: action === 'new' ? 'Thêm mục BXH' : 'Sửa mục BXH',
      currentPage: 'newsfeed',
      time: res.locals.time,
      error: e.message,
      ranking: req.body, // Gửi lại dữ liệu đã nhập
      action: action === 'new' ? '/admin/ranking/new' : `/admin/ranking/edit/${id}`
    });
  }
});


// Route 5 (DELETE): Xử lý Xoá (Delete)
app.delete('/api/ranking/delete/:id', requireManager, async (req, res) => {
  try {
    const { error } = await supabase
      .from('newsfeed_ranking')
      .delete()
      .eq('id', req.params.id);
      
    if (error) throw error;
    res.json({ ok: true, message: 'Xoá thành công' });
    
  } catch (e) {
    console.error('Lỗi khi xoá BXH:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ------------------------- Start server / export -------------------------
const PORT = Number(process.env.PORT) || 3000;
if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(PORT, () => console.log(`Local: http://localhost:${PORT}`));
}
