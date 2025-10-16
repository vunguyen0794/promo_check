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

const isVercel = !!process.env.VERCEL;

// ------------------------- Supabase -------------------------
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey =
  process.env.SUPABASE_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_ANON_KEY;

const supabase = createClient(supabaseUrl, supabaseKey);

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


// share user/time ra view
app.use((req, res, next) => {
  res.locals.user = req.session?.user || null;
  res.locals.time = new Date().toLocaleTimeString('vi-VN', {
    hour: '2-digit',
    minute: '2-digit',
  });
  next();
});

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


function parseSkuList(raw) {
  return String(raw || '')
    .split(/[,;\n\r\t ]+/)
    .map(s => s.trim())
    .filter(Boolean);
}

// Chuẩn hoá danh sách SKU: tách theo dấu phẩy / xuống dòng, bỏ trống
function parseSkus(input) {
  return String(input || '')
    .split(/[\s,]+/)
    .map(s => s.trim())
    .filter(Boolean);
}
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
    req.session.user = { id: user.id, email: user.email, full_name: user.full_name, role: user.role };
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
    const { email, password, full_name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const { data: user, error } = await supabase
      .from('users')
      .insert([{ email, password_hash: hashedPassword, full_name, role: 'staff' }])
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
        if(p.max_discount_amount) discountValueForSort = Math.min(discountValueForSort, p.max_discount_amount);
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
    const { data: randomSkus } = await supabase.from('skus').select('*').limit(8);

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
        if(p.max_discount_amount) discountValueForSort = Math.min(discountValueForSort, p.max_discount_amount);
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
// ---- Trang tất cả sản phẩm ----
// ---- Trang tất cả sản phẩm (phiên bản mới có category) ----
app.get('/products', requireAuth, async (req, res) => {
  const q = (req.query.q || '').trim();
  const category = (req.query.category || '').trim(); // Tham số category mới
  const page = Math.max(parseInt(req.query.page || '1', 10), 1);
  const pageSize = 24;

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

  const { data: items, count } = await query
    .order('sku', { ascending: true })
    .range((page - 1) * pageSize, page * pageSize - 1);

  res.render('products', {
    title: 'Tất cả sản phẩm',
    currentPage: 'home',
    q, items: items || [],
    page, total: count || 0, pageSize,
    categories, // Truyền danh sách categories ra view
    selectedCategory: category // Truyền category đang chọn ra view
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
    if (!sku) return res.status(400).json({ ok:false, error:'Thiếu SKU' });

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
    return res.json({ ok:true, sku: data });
  } catch (e) {
    return res.status(500).json({ ok:false, error: e.message });
  }
});




// POST cập nhật giá (ghi lịch sử)
app.post('/api/sku/:sku/price', requireAuth, async (req, res) => {
  try{
    const sku = req.params.sku;
    const newPrice = Number(req.body.new_price);
    if (!Number.isFinite(newPrice) || newPrice<0) return res.status(400).json({ ok:false, error:'Giá không hợp lệ' });

    const { data: curr } = await supabase.from('skus').select('list_price').eq('sku', sku).single();
    const old = Number(curr?.list_price || 0);

    // update giá
    const { error: upErr } = await supabase.from('skus').update({ list_price: newPrice }).eq('sku', sku);
    if (upErr) throw upErr;

    // ghi lịch sử
    await supabase.from('sku_price_history').insert([{
      sku, old_price: old, new_price: newPrice, changed_by: req.session.user.id
    }]);

    res.json({ ok:true, old_price: old, new_price: newPrice });
  }catch(e){ res.status(500).json({ ok:false, error:e.message }); }
});


// GET lịch sử giá
app.get('/api/sku/:sku/price-history', requireAuth, async (req, res) => {
  try{
    const sku = req.params.sku;
    const { data, error } = await supabase
      .from('sku_price_history')
      .select(`*, users:changed_by(full_name, email)`)
      .eq('sku', sku)
      .order('changed_at', { ascending:false })
      .limit(50);
    if (error) throw error;
    const rows = (data||[]).map(r=>({
      changed_at: r.changed_at,
      old_price: r.old_price,
      new_price: r.new_price,
      user: r.users ? (r.users.full_name || r.users.email) : 'Unknown'
    }));
    res.json({ ok:true, history: rows });
  }catch(e){ res.status(500).json({ ok:false, error:e.message }); }
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
        // Ưu tiên 1: SKU bị loại trừ -> Luôn loại
        const isExcluded = (p.promotion_excluded_skus || []).some(ex => ex.sku === product.sku);
        if (isExcluded) {
            return false;
        }

        // Ưu tiên 2: Áp dụng cho "Tất cả sản phẩm" -> Luôn áp dụng
        if (p.apply_to_all_skus) {
            return true;
        }

        // Ưu tiên 3: Áp dụng theo Brand/Category/Subcat
        if (p.apply_to_brands && p.apply_to_brands.includes(product.brand)) {
            return true;
        }
        if (p.apply_to_categories && p.apply_to_categories.includes(product.category)) {
            return true;
        }
        if (p.apply_to_subcats && p.apply_to_subcats.includes(product.subcat)) {
            return true;
        }

        // Ưu tiên 4: Áp dụng theo danh sách SKU chỉ định
        const isIncluded = (p.promotion_skus || []).some(ps => ps.sku === product.sku);
        if (isIncluded) {
            return true;
        }

        // Nếu không rơi vào các trường hợp trên -> Loại
        return false;
    });
    console.log(`[DEBUG] Bước 3: Sau khi lọc theo SKU, còn lại ${promotions.length} CTKM.`);
    
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
    let availablePromos = (promotions || []).map(p => ({ ...p, discount_amount_calc: calcDiscountAmt(p, price) }));

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
      chosenPromos, totalDiscount, finalPrice, comparisonCount, error: null,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });

  } catch (error) {
    console.error('SEARCH PROMO ERROR:', error);
    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion', query: skuInput,
      product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
      error: 'Lỗi hệ thống: ' + (error?.message || String(error)),
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
        product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
        error: 'Vui lòng nhập SKU.',
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      });
    }

    const { data: product } = await supabase.from('skus').select('*').eq('sku', skuInput).single();
    if (!product) {
      console.log(`[DEBUG] Lỗi: Không tìm thấy sản phẩm với SKU "${skuInput}".`);
      return res.render('promotion', {
        title: 'CTKM theo SKU', currentPage: 'promotion', query: skuInput,
        product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
        error: 'Không tìm thấy thông tin cho SKU: ' + skuInput,
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      });
    }
    const price = Number(product.list_price || 0);
    console.log(`[DEBUG] Bước 1: Đã tìm thấy sản phẩm - Tên: ${product.product_name}, Giá niêm yết: ${price}đ`);

    const today = new Date().toISOString().split('T')[0];
    const { data: promosRaw } = await supabase
      .from('promotions')
      .select('*, promotion_skus(*), promotion_excluded_skus(*), detail_fields, group_name, subgroup_name')
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
      promotions: promosAfterGroupPick, // <-- Sử dụng kết quả đã gộp
      chosenPromos, totalDiscount, finalPrice, comparisonCount, error: null,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });

  } catch (error) {
    console.error('SEARCH PROMO ERROR:', error);
    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion', query: skuInput,
      product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
      error: 'Lỗi hệ thống: ' + (error?.message || String(error)),
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  }
});




app.get('/promotion-detail/:id', requireAuth, async (req, res) => {
  try {
    const currentUser = req.session?.user;
    const isManager = ['manager','admin'].includes(currentUser?.role);
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
app.get('/promo-management', async (req, res) => {
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


// DÁN TOÀN BỘ KHỐI CODE NÀY VÀO FILE server.js

// Tạo CTKM mới
app.post('/create-promotion', requireAuth, async (req, res) => {
  try {
    // Helper functions
    const parseToArray = (str) => (str || '').split(',').map(s => s.trim()).filter(Boolean);
    const parseSkus = (input) => (input || '').split(/[\s,]+/).map(s => s.trim()).filter(Boolean);

    // Lấy dữ liệu từ form
    const {
      name, description, start_date, end_date, channel, promo_type, coupon_code,
      group_name, apply_to_type, apply_brands, apply_categories, apply_subcats,
      skus, excluded_skus, has_coupon_list, coupons
    } = req.body;
    
    // Xử lý giá trị giảm
    const discount_value_type = (req.body.discount_value_type || '').toLowerCase() || null;
    const discount_value = discount_value_type === 'amount'
        ? Number(req.body.discount_amount || 0)
        : (discount_value_type === 'percent' ? Number(req.body.discount_percent || 0) : null);
    const max_discount_amount = discount_value_type === 'percent'
        ? (req.body.max_discount_amount ? Number(req.body.max_discount_amount) : null)
        : null;
    const min_order_value = req.body.min_order_value ? Number(req.body.min_order_value) : 0;
    
    // Xử lý danh sách coupon
    let couponListData = null;
    if (has_coupon_list && coupons) {
        couponListData = Object.values(coupons).filter(c => c && c.code && c.code.trim() !== '');
    }

    // 1. Chuẩn bị dữ liệu để chèn
    const insertPayload = {
      name, description, start_date, end_date, group_name, channel: channel || 'All',
      promo_type, coupon_code: coupon_code || null, created_by: req.session.user?.id || null, status: 'active',
      discount_value_type, discount_value, max_discount_amount, min_order_value,
      apply_to_all_skus: apply_to_type === 'all',
      apply_to_brands: apply_to_type === 'brand' ? parseToArray(apply_brands) : null,
      apply_to_categories: apply_to_type === 'category' ? parseToArray(apply_categories) : null,
      apply_to_subcats: apply_to_type === 'subcat' ? parseToArray(apply_subcats) : null,
      coupon_list: couponListData,
    };

    // 2. Chèn CTKM mới và lấy ID
    const { data: promotion, error: promoError } = await supabase.from('promotions').insert([insertPayload]).select('id').single();
    if (promoError) throw promoError;
    const newPromoId = promotion.id;

    // 3. Cập nhật các bảng liên quan
    if (apply_to_type === 'sku') {
      const includeList = parseSkus(skus);
      if (includeList.length) await supabase.from('promotion_skus').insert(includeList.map(sku => ({ promotion_id: newPromoId, sku })));
    }
    const excludeList = parseSkus(excluded_skus);
    if (excludeList.length) await supabase.from('promotion_excluded_skus').insert(excludeList.map(sku => ({ promotion_id: newPromoId, sku })));
    
    const allowIds = req.body['apply_with[]'] || [];
    const exclIds = req.body['exclude_with[]'] || [];
    if (allowIds.length) await supabase.from('promotion_compat_allows').insert(allowIds.map(pid => ({ promotion_id: newPromoId, with_promotion_id: pid })));
    if (exclIds.length) await supabase.from('promotion_compat_excludes').insert(exclIds.map(pid => ({ promotion_id: newPromoId, with_promotion_id: pid })));

    // 4. Trả về thành công
    return res.json({ success: true, id: newPromoId });

  } catch (error) {
    console.error('❌ Lỗi khi tạo CTKM:', error);
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

// POST: lưu edit
app.post('/edit-promotion/:id', requireAuth, async (req, res) => {
  const id = req.params.id;
  try {
    // === Helper functions ===
    const parseToArray = (str) => (str || '').split(',').map(s => s.trim()).filter(Boolean);
    const parseSkus = (input) => (input || '').split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    const id = req.params.id;
    const { coupons, has_coupon_list, ...otherData } = req.body;
    // === Lấy dữ liệu từ form ===
    const {
      name, description, start_date, end_date, channel, promo_type, coupon_code,
      group_name, apply_to_type, apply_brands, apply_categories, apply_subcats,
      skus, excluded_skus
    } = req.body;
    
    let couponListData = null;
    if (has_coupon_list && coupons) {
        // Chuyển đổi dữ liệu từ form thành mảng các object sạch
        couponListData = Object.values(coupons).filter(c => c.code);
    }


    // === 1. Cập nhật bảng "promotions" ===
    const updatePayload = {
      name, description, start_date, end_date, group_name,
      channel: channel || 'All',
      promo_type,
      coupon_code: coupon_code || null,
      coupon_list: couponListData,
      updated_at: new Date().toISOString(),
      
      // Reset tất cả các quy tắc phạm vi
      apply_to_all_skus: apply_to_type === 'all',
      apply_to_brands: null,
      apply_to_categories: null,
      apply_to_subcats: null,
    };

    // Gán lại quy tắc phạm vi dựa trên lựa chọn từ form
    if (apply_to_type === 'brand') {
      updatePayload.apply_to_brands = parseToArray(apply_brands);
    } else if (apply_to_type === 'category') {
      updatePayload.apply_to_categories = parseToArray(apply_categories);
    } else if (apply_to_type === 'subcat') {
      updatePayload.apply_to_subcats = parseToArray(apply_subcats);
    }

    const { error: promoUpdateError } = await supabase.from('promotions').update(updatePayload).eq('id', id);
    if (promoUpdateError) throw promoUpdateError;

    // === 2. Cập nhật bảng "promotion_skus" (chỉ khi áp dụng theo SKU) ===
    await supabase.from('promotion_skus').delete().eq('promotion_id', id);
    if (apply_to_type === 'sku') {
      const includeList = parseSkus(skus);
      if (includeList.length) {
        await supabase.from('promotion_skus').insert(includeList.map(sku => ({ promotion_id: id, sku })));
      }
    }

    // === 3. Cập nhật bảng "promotion_excluded_skus" (luôn chạy) ===
    await supabase.from('promotion_excluded_skus').delete().eq('promotion_id', id);
    const excludeList = parseSkus(excluded_skus);
    if (excludeList.length) {
      await supabase.from('promotion_excluded_skus').insert(excludeList.map(sku => ({ promotion_id: id, sku })));
    }

    // === 4. Cập nhật các bảng quan hệ (áp dụng cùng / loại trừ) ===
    const allowIds = Array.isArray(req.body['apply_with[]']) ? req.body['apply_with[]'] : [];
    const exclIds = Array.isArray(req.body['exclude_with[]']) ? req.body['exclude_with[]'] : [];

    await supabase.from('promotion_compat_allows').delete().eq('promotion_id', id);
    if (allowIds.length) {
      await supabase.from('promotion_compat_allows').insert(allowIds.map(pid => ({ promotion_id: id, with_promotion_id: pid })));
    }

    await supabase.from('promotion_compat_excludes').delete().eq('promotion_id', id);
    if (exclIds.length) {
      await supabase.from('promotion_compat_excludes').insert(exclIds.map(pid => ({ promotion_id: id, with_promotion_id: pid })));
    }

    // === 5. Chuyển hướng về trang chi tiết sau khi lưu thành công ===
    return res.redirect(`/promotion-detail/${id}`);

  } catch (e) {
    console.error(`Lỗi khi cập nhật CTKM #${id}:`, e);
    // Có thể render lại trang edit với thông báo lỗi
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

// POST /api/promotions/:id/clone
app.post('/api/promotions/:id/clone', async (req, res) => {
  try {
    const srcId = req.params.id;

    // -- 1) Lấy bản gốc
    const { data: src, error: e1 } = await supabase
      .from('promotions')
      .select('*')
      .eq('id', srcId)
      .single();
    if (e1 || !src) throw new Error('Không tìm thấy CTKM nguồn');

    // (Tùy bạn: nếu muốn truyền tên mới từ client)
    const clientName = (req.body && req.body.name || '').trim();

    // -- 2) Tạo bản mới: map ĐẦY ĐỦ các cột bạn đã liệt kê
    //    (đặt default hợp lý để không dính NOT NULL)
    const rand4 = Math.random().toString(36).slice(2, 6).toUpperCase();

    const newRow = {
      // Khoá chính id là BIGINT tự tăng — ĐỪNG gán.
      name: clientName || `Copy of ${src.name}`,
      description: src.description ?? null,

      // === NGÀY (NOT NULL trong hệ của bạn trước đó): GIỮ NGUYÊN ===
      start_date: src.start_date,               // tránh NOT NULL
      end_date: src.end_date,                   // nếu bảng của bạn yêu cầu

      // === Thông tin “phạm vi áp dụng” ===
      channel: src.channel ?? null,
      promo_type: src.promo_type,               // tránh NOT NULL (báo lỗi bạn vừa gặp)
      // Nếu coupon_code là unique: thêm hậu tố để khỏi trùng; nếu muốn giữ nguyên, thay dòng dưới = src.coupon_code
      coupon_code: src.coupon_code ? `${src.coupon_code}-${rand4}` : null,
      
      // === Loại & giá trị giảm ===
      discount_type: src.discount_type ?? null,
      discount_value: src.discount_value ?? 0,
      min_order_value: src.min_order_value ?? 0,
      value_type: src.value_type ?? null,
      discount_mode: src.discount_mode ?? null,
      discount_value_type: src.discount_value_type ?? null,
      max_discount_amount: src.max_discount_amount ?? null,

      // === Áp dụng toàn bộ? (boolean) ===
      apply_to_all_categories: !!src.apply_to_all_categories,
      apply_to_all_brands: !!src.apply_to_all_brands,
      apply_to_all_skus: !!src.apply_to_all_skus,

      // === Tương thích/đặc biệt (boolean) ===
      compatible_with_other_promos: !!src.compatible_with_other_promos,
      compatible_with_other: !!src.compatible_with_other,
      is_special: !!src.is_special,

      // === JSON/HTML/ordering ===
      special_conditions: src.special_conditions ?? null,
      advanced_settings: src.advanced_settings ?? null,
      content_html: src.content_html ?? null,
      group_name: src.group_name ?? null,
      subgroup_name: src.subgroup_name ?? null,
      detail_fields: src.detail_fields ?? null,
      display_order: src.display_order ?? null,
      stack_rule: src.stack_rule ?? null,

      // === Trạng thái & audit ===
      status: src.status ?? 'draft',            // có thể giữ nguyên src.status
      created_by: src.created_by ?? null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Chèn bản mới
    const { data: inserted, error: e2 } = await supabase
      .from('promotions')
      .insert(newRow)
      .select('id')
      .single();
    if (e2) throw e2;

    const newId = inserted.id;

    // Helper copy 1 bảng con: bỏ cột id để DB tự sinh
    const copyTable = async (table, selectCols) => {
      const { data: rows, error } = await supabase
        .from(table)
        .select(selectCols.join(','))
        .eq('promotion_id', srcId);
      if (error) throw error;
      if (!rows || !rows.length) return;

      const payload = rows.map(r => {
        const obj = { ...r, promotion_id: newId };
        if ('id' in obj) delete obj.id;
        return obj;
      });
      const { error: eIns } = await supabase.from(table).insert(payload);
      if (eIns) throw eIns;
    };

    // 3) BẢNG CHI TIẾT (điền đúng tên cột bên bạn)
    // Ví dụ phổ biến:
    await copyTable('promotion_details', [
      'id','promotion_id','sku_id','rule_key','rule_value','note'
    ]);

    // 4) ĐIỀU KIỆN (nếu có)
    await copyTable('promotion_conditions', [
      'id','promotion_id','cond_type','cond_op','cond_value'
    ]);

    // 5) SKU áp dụng
    await copyTable('promotion_skus', [
      'id','promotion_id','sku_id'
    ]);

    // 6) Quan hệ áp dụng cùng / loại trừ
    await copyTable('promotion_compat_allows', [
      'id','promotion_id','with_promotion_id'
    ]);
    await copyTable('promotion_compat_excludes', [
      'id','promotion_id','with_promotion_id'
    ]);

    // 7) Quà tặng
    await copyTable('promotion_gifts', [
      'id','promotion_id','gift_id','qty','value'
    ]);
    
    // 8) Coupon ở bảng riêng (nếu bạn có thêm bảng promotion_coupons)
    //    — nếu chỉ dùng field coupon_code trong promotions thì bỏ qua mục này.
    await copyTable('promotion_coupons', [
      'id','promotion_id','code','usage_limit','expire_at','note'
    ]).catch(()=>{}); // bảng này có thể không tồn tại — ignore

    // 9) Audit log (tuỳ chọn)
    await supabase.from('promotion_audit_logs').insert({
      promotion_id: newId, action: 'clone', from_promotion_id: srcId
    }).catch(()=>{});

    //new 15.10
    await copyTable('promotion_skus', ['promotion_id', 'sku']);
    await copyTable('promotion_excluded_skus', ['promotion_id', 'sku']);
    await supabase.from('promotion_audit_logs').insert({
      promotion_id: newId, action: 'clone', from_promotion_id: srcId
    }).catch(()=>{});


    return res.json({ ok: true, new_id: newId });
  } catch (err) {
    console.error('clone error', err);
    return res.status(400).json({ ok: false, error: String(err.message || err) });
  }
});
// ==== IMPORT CSV tồn kho -> upsert vào public.inventories ====
// Yêu cầu: đã có supabase client. Cần multer riêng cho CSV nếu bạn đã có filter ảnh.

const uploadCsv = multer({ storage: multer.memoryStorage() });

function parseCsvLines(buf){
  const text = buf.toString('utf8').replace(/^\uFEFF/, '');
  return text.split(/\r?\n/).filter(l => l.trim().length);
}
function splitCsvLine(line){
  const out=[]; let cur=''; let q=false;
  for (let i=0;i<line.length;i++){
    const c=line[i];
    if(q){
      if(c==='"'){ if(line[i+1]==='"'){cur+='"'; i++;} else q=false; }
      else cur+=c;
    } else {
      if(c===','){ out.push(cur); cur=''; }
      else if(c==='"'){ q=true; }
      else cur+=c;
    }
  }
  out.push(cur);
  return out.map(s=>s.trim());
}

app.post('/api/inventories/import-csv', uploadCsv.single('file'), async (req, res) => {
  try{
    if(!req.file) return res.status(400).json({ ok:false, error:'Thiếu file CSV' });
    const lines = parseCsvLines(req.file.buffer);
    if(lines.length < 2) return res.status(400).json({ ok:false, error:'CSV không có dữ liệu' });

    const header = splitCsvLine(lines[0]).map(h => h.toLowerCase());

    // Map header tiếng Việt -> field
    const idx = {
      sku: header.findIndex(h => ['mã sản phẩm','ma san pham','sku','mã'].includes(h)),
      product_name: header.findIndex(h => ['tên sản phẩm','ten san pham','product name'].includes(h)),
      brand: header.findIndex(h => ['thương hiệu','thuong hieu','brand'].includes(h)),
      category_code: header.findIndex(h => ['mã ngành hàng','ma nganh hang','category code'].includes(h)),
      category_name: header.findIndex(h => ['tên ngành hàng','ten nganh hang','category name'].includes(h)),
      group_code: header.findIndex(h => ['mã nhóm sản phẩm','ma nhom san pham','group code'].includes(h)),
      group_name: header.findIndex(h => ['tên nhóm sản phẩm','ten nhom san pham','group name'].includes(h)),
      branch_code: header.findIndex(h => ['mã chi nhánh','ma chi nhanh','branch code','mã cửa hàng'].includes(h)),
      branch_name: header.findIndex(h => ['tên chi nhánh','ten chi nhanh','branch name'].includes(h)),
      zone: header.findIndex(h => ['khu vực (zone)','khu vực','zone'].includes(h)),
      uom: header.findIndex(h => ['đvt','don vi tinh','uom','unit'].includes(h)),
      stock_qty: header.findIndex(h => ['số lượng tồn','so luong ton','stockqty','qty','stock'].includes(h)),
    };
    if (idx.sku<0 || idx.branch_code<0 || idx.stock_qty<0){
      return res.status(400).json({ ok:false, error:'Header bắt buộc thiếu: Mã sản phẩm / Mã chi nhánh / Số lượng tồn' });
    }

    // Build payloads
    const rows = [];
    for (let i=1;i<lines.length;i++){
      const cols = splitCsvLine(lines[i]);
      const get = (k)=> idx[k]>=0 ? (cols[idx[k]]||'').toString().trim() : '';
      const stock = Number(String(get('stock_qty')).replace(/[^\d\-\.,]/g,'').replace('.','').replace(',','.')) || 0;

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
    let inserted = 0, failed = 0, lastError=null;
    for (let i=0;i<rows.length;i+=BATCH){
      const part = rows.slice(i, i+BATCH);
      const { error, count } = await supabase
        .from('inventories')
        .upsert(part, { onConflict: 'sku,branch_code' });
      if (error){ failed += part.length; lastError = error.message; }
      else inserted += part.length;
    }
    res.json({ ok:true, upserted: inserted, failed, lastError });
  } catch(e){
    res.status(500).json({ ok:false, error: e.message });
  }
});

app.post('/api/utils/bom/import', uploadCsv.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok:false, error:'Thiếu file CSV' });
    const lines = parseCsvLines(req.file.buffer);
    if (lines.length < 2) return res.status(400).json({ ok:false, error:'CSV không có dữ liệu' });

    const header = splitCsvLine(lines[0]).map(h => h.toLowerCase());
    const idx = {
      final_sku: header.findIndex(h => ['finalsku','sku thành phẩm','sku thanh pham'].includes(h)),
      final_name: header.findIndex(h => ['finalname','tên thành phẩm','ten thanh pham','name'].includes(h)),
      component_sku: header.findIndex(h => ['componentsku','sku linh kiện','sku linh kien'].includes(h)),
      component_name: header.findIndex(h => ['componentname','tên linh kiện','ten linh kien'].includes(h)),
      qty_per: header.findIndex(h => ['qtyper','qty','số lượng','so luong','sl'].includes(h)),
    };
    if (idx.final_sku<0 || idx.component_sku<0)
      return res.status(400).json({ ok:false, error:'Header bắt buộc thiếu: FinalSKU / ComponentSKU' });

    const rows=[];
    for (let i=1;i<lines.length;i++){
      const c = splitCsvLine(lines[i]);
      const get = (k)=> idx[k]>=0 ? (c[idx[k]]||'').toString().trim() : '';
      const qty = Number(String(get('qty_per')).replace(',','.')) || 1;
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
    let inserted=0, failed=0, lastError=null;
    for (let i=0;i<rows.length;i+=BATCH){
      const part = rows.slice(i, i+BATCH);
      const { error } = await supabase.from('bom_relations').insert(part);
      if (error){ failed+=part.length; lastError=error.message; }
      else inserted+=part.length;
    }
    res.json({ ok:true, inserted, failed, lastError });
  } catch(e){
    res.status(500).json({ ok:false, error: e.message });
  }
});

app.get('/api/utils/bom/by-final', async (req, res) => {
  try{
    const sku = (req.query.sku||'').trim();
    if(!sku) return res.status(400).json({ ok:false, error:'Thiếu sku' });

    // Lấy các dòng BOM của final_sku
    const { data: parts, error: e1 } = await supabase
      .from('bom_relations')
      .select('component_sku, component_name, qty_per, final_name')
      .eq('final_sku', sku);
    if (e1) throw e1;

    if (!parts || !parts.length) return res.json({ ok:true, final: { sku, name: null }, components: [], branches: [] });

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
    for (const r of inv){
      if (!branches[r.branch_code]) branches[r.branch_code] = { branch: r.branch_code, branch_name: r.branch_name, stockBySku: {} };
      branches[r.branch_code].stockBySku[r.sku] = (branches[r.branch_code].stockBySku[r.sku] || 0) + Number(r.stock_qty||0);
    }

    // Tính buildable từng branch
    const out = [];
    const branchKeys = Object.keys(branches).sort();
    for (const b of branchKeys){
      const ctx = branches[b];
      let minBuild = Infinity;
      const detail = [];
      for (const p of parts){
        const have = ctx.stockBySku[p.component_sku] || 0;
        const need = Number(p.qty_per||1);
        const can = Math.floor(have / need);
        detail.push({ compSKU: p.component_sku, compName: p.component_name, need, have, can });
        if (can < minBuild) minBuild = can;
      }
      if (minBuild === Infinity) minBuild = 0;
      out.push({ branch: b, branch_name: ctx.branch_name, buildable: minBuild, components: detail });
    }

    res.json({
      ok:true,
      final: { sku, name: finalName },
      components: parts.map(p => ({ compSKU: p.component_sku, compName: p.component_name, qtyPer: p.qty_per })),
      branches: out
    });
  } catch(e){
    res.status(500).json({ ok:false, error: e.message });
  }
});

app.get('/api/utils/bom/by-component', async (req, res) => {
  try{
    const comp = (req.query.sku||'').trim();
    if(!comp) return res.status(400).json({ ok:false, error:'Thiếu sku' });

    // Tìm các final có dùng linh kiện này
    const { data: finals, error: e1 } = await supabase
      .from('bom_relations')
      .select('final_sku, final_name')
      .eq('component_sku', comp);
    if (e1) throw e1;

    const uniqFinals = Array.from(new Map(finals.map(f => [f.final_sku, { sku: f.final_sku, name: f.final_name }])).values());
    const results = [];

    // Với mỗi final_sku, tính buildable như trên
    for (const f of uniqFinals){
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
      for (const r of inv){
        if (!branches[r.branch_code]) branches[r.branch_code] = { branch: r.branch_code, branch_name: r.branch_name, stockBySku: {} };
        branches[r.branch_code].stockBySku[r.sku] = (branches[r.branch_code].stockBySku[r.sku] || 0) + Number(r.stock_qty||0);
      }

      const out = [];
      for (const b of Object.keys(branches).sort()){
        const ctx = branches[b];
        let minBuild = Infinity;
        for (const p of parts){
          const have = ctx.stockBySku[p.component_sku] || 0;
          const need = Number(p.qty_per||1);
          const can = Math.floor(have / need);
          if (can < minBuild) minBuild = can;
        }
        if (minBuild === Infinity) minBuild = 0;
        out.push({ branch: b, branch_name: ctx.branch_name, buildable: minBuild });
      }

      results.push({ final: f, branches: out });
    }

    res.json({ ok:true, component: comp, results });
  } catch(e){
    res.status(500).json({ ok:false, error: e.message });
  }
});

app.get('/tien-ich', requireAuth, (req, res) => {
  res.render('tien-ich', { user: req.user || null });
});

// ------------------------- Start server / export -------------------------
const PORT = Number(process.env.PORT) || 3000;
if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(PORT, () => console.log(`Local: http://localhost:${PORT}`));
}
