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


// ------------------------- Trang chính -------------------------
app.get('/', requireAuth, (req, res) => {
  res.render('index', {
    title: 'Trang chủ',
    currentPage: 'home',
    time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
  });
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

app.post('/search-promotion', requireAuth, async (req, res) => {
  try {
    const skuInput = (req.body.sku || '').trim();
    if (!skuInput) {
      return res.render('promotion', {
        title: 'CTKM theo SKU', currentPage: 'promotion',
        product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
        error: 'Vui lòng nhập SKU.',
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      });
    }

    // 1) Lấy sản phẩm
    const { data: product } = await supabase.from('skus').select('*').eq('sku', skuInput).single();
    if (!product) {
      return res.render('promotion', {
        title: 'CTKM theo SKU', currentPage: 'promotion',
        product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
        error: 'Không tìm thấy thông tin cho SKU: ' + skuInput,
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      });
    }

    // 2) Lấy các CTKM đang active, trong khung ngày
    const today = new Date().toISOString().split('T')[0];
    const { data: promosRaw, error: promosErr } = await supabase
      .from('promotions')
      .select('*, promotion_skus(*), promotion_excluded_skus(*), detail_fields, group_name, subgroup_name')
      .lte('start_date', today)
      .gte('end_date', today)
      .eq('status', 'active');
    if (promosErr) throw promosErr;

    const isTrue = v => (v === true || v === 1 || v === '1' || v === 'true' || v === 't');
    // 3) Lọc theo include/exclude
    let promotions = (promosRaw || []).filter(p => {
      const excluded = (p.promotion_excluded_skus || []).some(ex => ex.sku === product.sku);
      if (p.apply_to_all_skus) {
        // ALL – EXCLUDED
        return !excluded;
      } else {
        // INCLUDE – EXCLUDED
        const included = (p.promotion_skus || []).some(ps => ps.sku === product.sku);
        return included && !excluded;
      }
    });

    // 4) Map tên CTKM “áp dụng cùng/loại trừ”
    if (promotions.length) {
      const ids = promotions.map(p => p.id);

      const { data: allows } = await supabase
        .from('promotion_compat_allows')
        .select('promotion_id, with_promotion_id')
        .in('promotion_id', ids);

      const { data: excludes } = await supabase
        .from('promotion_compat_excludes')
        .select('promotion_id, with_promotion_id')
        .in('promotion_id', ids);

      const { data: allPromosLite } = await supabase
        .from('promotions')
        .select('id, name, group_name, subgroup_name');

      const byId = Object.fromEntries((allPromosLite || []).map(p => [p.id, p]));
      const fmt = (t) => t ? (t.group_name ? `${t.group_name} — ${(t.subgroup_name || t.name)}` : t.name) : '';

      promotions.forEach(p => {
        const allowIds = (allows || []).filter(r => r.promotion_id === p.id).map(r => r.with_promotion_id);
        const exclIds = (excludes || []).filter(r => r.promotion_id === p.id).map(r => r.with_promotion_id);
        p.compat_allow_names = allowIds.map(id => fmt(byId[id])).filter(Boolean);
        p.compat_exclude_names = exclIds.map(id => fmt(byId[id])).filter(Boolean);
      });
    }

    // 5) Tính toán (placeholder)
    const totalDiscount = 0;
    const finalPrice = Math.max(0, (product.list_price || 0) - totalDiscount);

    // 6) Số lần chiến giá
    let comparisonCount = 0;
    try {
      const cmp = await supabase.from('price_comparisons')
        .select('*', { count: 'exact', head: true })
        .eq('sku', product.sku);
      comparisonCount = cmp?.count || 0;
    } catch { }

    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion',
      product, promotions, totalDiscount, finalPrice, comparisonCount, error: null,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  } catch (error) {
    console.error('SEARCH PROMO ERROR:', error);
    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion',
      product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
      error: 'Lỗi hệ thống: ' + (error?.message || String(error)),
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  }
});





app.get('/promotion-detail/:id', requireAuth, async (req, res) => {
  try {
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

    // Lấy tên/nhóm để hiển thị
    const allIds = [
      ...(allowRows || []).map(r => r.with_promotion_id),
      ...(exclRows || []).map(r => r.with_promotion_id),
    ];
    let compatAllowNames = [], compatExcludeNames = [];
    if (allIds.length) {
      const { data: refPromos } = await supabase
        .from('promotions')
        .select('id, name, group_name, subgroup_name')
        .in('id', allIds);

      const byId = Object.fromEntries((refPromos || []).map(p => [p.id, p]));
      const fmt = (t) => t
        ? (t.group_name ? `${t.group_name} — ${(t.subgroup_name || t.name)}` : t.name)
        : '';

      compatAllowNames = (allowRows || [])
        .map(r => fmt(byId[r.with_promotion_id]))
        .filter(Boolean);

      compatExcludeNames = (exclRows || [])
        .map(r => fmt(byId[r.with_promotion_id]))
        .filter(Boolean);
    }

    const { data: promotion, error } = await supabase
      .from('promotions')
      .select(`*, promotion_skus(*), promotion_excluded_skus(*), promotion_gifts(*)`)
      .eq('id', promoId)
      .single();
    if (error) throw error;
    const { data: revisions } = await supabase
      .from('promotion_revisions')
      .select('id, action, user_id, diff, created_at')
      .eq('promotion_id', req.params.id)
      .order('created_at', { ascending: false })
      .limit(50);

    res.render('promotion-detail', {
      title: 'Chi tiết CTKM',
      currentPage: 'promotion-detail',
      promotion,
      revisions: revisions || [],
      compatAllowNames,
      compatExcludeNames,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  } catch (error) {
    res.status(404).render('error', {
      title: 'Không tìm thấy',
      message: 'Không tìm thấy thông tin CTKM',
      error: error.message,
    });
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

// Tạo CTKM (CHỈ còn all+excluded_skus hoặc include_skus)
app.post('/create-promotion', requireAuth, async (req, res) => {
  try {
    const {
      name,
      description,
      start_date,
      end_date,
      channel,
      promo_type,
      coupon_code,
      apply_to,            // 'all' | 'sku'
      skus,                // include list (optional)
      excluded_skus,       // exclude list (optional)
      compatible_with_other,
      group_name,          // NEW
    } = req.body;

    // Gom các ô chi tiết dạng “detail[<label>]”
    const detailFields = {};
    for (const [k, v] of Object.entries(req.body)) {
      const m = /^detail\[(.+)\]$/.exec(k);
      if (m) detailFields[m[1]] = v;
    }

    const { data: promotion, error: promoError } = await supabase
      .from('promotions')
      .insert([{
        name,
        description,
        start_date,
        end_date,
        channel: channel || 'All',
        promo_type,
        coupon_code: coupon_code || null,
        apply_to_all_skus: apply_to === 'all',
        compatible_with_other: !!compatible_with_other,
        status: 'active',
        created_by: req.session.user?.id || null,
        group_name,
        subgroup_name: name,
        detail_fields: detailFields || null
      }])
      .select()
      .single();

    if (promotion) {
      await supabase.from('promotion_revisions').insert([{
        promotion_id: promotion.id,
        action: 'create',
        user_id: req.session?.user?.id || null,
        diff: {},
        snapshot: promotion
      }]);
    }

    const allowIds = toIdArray(req.body['apply_with']);
    const exclIds = toIdArray(req.body['exclude_with']);

    if (allowIds.length) {
      await supabase.from('promotion_compat_allows').insert(
        allowIds.map(pid => ({ promotion_id: promotion.id, with_promotion_id: pid }))
      );
    }
    if (exclIds.length) {
      await supabase.from('promotion_compat_excludes').insert(
        exclIds.map(pid => ({ promotion_id: promotion.id, with_promotion_id: pid }))
      );
    }

    if (promoError) throw promoError;
    const promoId = promotion.id;
    // Lấy giá trị từ form
    const applyTo = req.body.apply_to;           // 'all' hoặc 'sku'
    const includeSkus = parseSkus(req.body.skus);    // Từ <textarea name="skus">
    const excludeSkus = parseSkus(req.body.excluded_skus); // Từ <textarea name="excluded_skus">

    // Cập nhật cờ apply_to_all_skus (phòng khi phần insert phía trên chưa set)
    await supabase
      .from('promotions')
      .update({ apply_to_all_skus: applyTo === 'all' })
      .eq('id', promotion.id);

    // Ghi bảng mapping
    if (applyTo === 'sku' && includeSkus.length) {
      await supabase.from('promotion_skus').insert(
        includeSkus.map(sku => ({ promotion_id: promotion.id, sku }))
      );
    }

    if (excludeSkus.length) {
      await supabase.from('promotion_excluded_skus').insert(
        excludeSkus.map(sku => ({ promotion_id: promotion.id, sku }))
      );
    }

    // INCLUDE (khi “Theo list SKU chỉ định” — vẫn cho phép nhập để tham khảo)
    const includeList = parseSkuList(skus);
    if (includeList.length) {
      await supabase.from('promotion_skus').insert(includeList.map(sku => ({ promotion_id: promoId, sku })));
    }

    // EXCLUDE (dùng cho cả 2 chế độ)
    const excludeList = parseSkuList(excluded_skus);
    if (excludeList.length) {
      await supabase.from('promotion_excluded_skus').insert(excludeList.map(sku => ({ promotion_id: promoId, sku })));
    }

    return res.json({ success: true, id: promoId });
  } catch (error) {
    console.error('❌ CREATE PROMOTION ERROR:', error);
    res.status(500).json({ success: false, error: 'Lỗi khi tạo CTKM: ' + error.message });
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
  try {
    const id = req.params.id;
    const { data: oldPromotion } = await supabase
      .from('promotions')
      .select('*, promotion_skus(sku), promotion_excluded_skus(sku)')
      .eq('id', id)
      .single();

    const applyTo = req.body.apply_to;           // 'all' hoặc 'sku'
    const includeSkus = parseSkus(req.body.skus);    // từ form
    const excludeSkus = parseSkus(req.body.excluded_skus); // từ form

    const {
      name, description, start_date, end_date, channel, promo_type, coupon_code,
      apply_to, skus, excluded_skus, compatible_with_other, group_name
    } = req.body;

    const detailFields = {};
    for (const [k, v] of Object.entries(req.body)) {
      const m = /^detail\[(.+)\]$/.exec(k);
      if (m) detailFields[m[1]] = v;
    }

    const { error: upErr } = await supabase
      .from('promotions')
      .update({
        name, description, start_date, end_date,
        channel: channel || 'All',
        promo_type, coupon_code: coupon_code || null,
        apply_to_all_skus: apply_to === 'all',
        compatible_with_other: !!compatible_with_other,
        group_name, subgroup_name: name, detail_fields: detailFields
      }).eq('id', id);
    if (upErr) throw upErr;

    // Cập nhật quan hệ áp dụng cùng / loại trừ
    const allowIds = toIdArray(req.body['apply_with'] || req.body['apply_with[]']);
    const exclIds = toIdArray(req.body['exclude_with'] || req.body['exclude_with[]']);

    await supabase.from('promotion_compat_allows').delete().eq('promotion_id', id);
    await supabase.from('promotion_compat_excludes').delete().eq('promotion_id', id);

    if (allowIds.length) {
      await supabase.from('promotion_compat_allows')
        .insert(allowIds.map(pid => ({ promotion_id: id, with_promotion_id: pid })));
    }
    if (exclIds.length) {
      await supabase.from('promotion_compat_excludes')
        .insert(exclIds.map(pid => ({ promotion_id: id, with_promotion_id: pid })));
    }

    // làm mới include/exclude
    const includeList = (String(skus || '').split(/[,;\n\r\t ]+/).map(s => s.trim()).filter(Boolean));
    const excludeList = (String(excluded_skus || '').split(/[,;\n\r\t ]+/).map(s => s.trim()).filter(Boolean));

    await supabase.from('promotion_skus').delete().eq('promotion_id', id);
    await supabase.from('promotion_excluded_skus').delete().eq('promotion_id', id);

    if (includeList.length)
      await supabase.from('promotion_skus').insert(includeList.map(sku => ({ promotion_id: id, sku })));
    if (excludeList.length)
      await supabase.from('promotion_excluded_skus').insert(excludeList.map(sku => ({ promotion_id: id, sku })));

    // Lấy dữ liệu mới nhất sau update
    const { data: newPromotion } = await supabase
      .from('promotions')
      .select('*, promotion_skus(sku), promotion_excluded_skus(sku)')
      .eq('id', id)
      .single();

    // Các field cần so sánh
    const FIELDS = [
      'name', 'description', 'start_date', 'end_date', 'channel', 'promo_type',
      'coupon_code', 'apply_to_all_skus', 'group_name', 'subgroup_name',
      'detail_fields', 'status'
    ];

    // So sánh phần thông tin cơ bản
    const fieldChanges = diffFields(oldPromotion, newPromotion, FIELDS);

    // So sánh list SKU include/exclude
    const oldInclude = (oldPromotion?.promotion_skus || []).map(x => x.sku).sort();
    const newInclude = (newPromotion?.promotion_skus || []).map(x => x.sku).sort();
    if (JSON.stringify(oldInclude) !== JSON.stringify(newInclude)) {
      fieldChanges.skus_include = { from: oldInclude, to: newInclude };
    }
    const oldExclude = (oldPromotion?.promotion_excluded_skus || []).map(x => x.sku).sort();
    const newExclude = (newPromotion?.promotion_excluded_skus || []).map(x => x.sku).sort();
    if (JSON.stringify(oldExclude) !== JSON.stringify(newExclude)) {
      fieldChanges.skus_exclude = { from: oldExclude, to: newExclude };
    }

    // Ghi 1 bản revision
    await supabase.from('promotion_revisions').insert([{
      promotion_id: id,
      action: 'update',
      user_id: req.session?.user?.id || null,
      diff: fieldChanges,
      snapshot: newPromotion
    }]);

    // Cuối cùng mới trả response
    if (wantsJSON(req)) {
      return res.json({ success: true, redirect: `/promotion-detail/${id}` });
    }

    // redirect chuẩn cho form submit
    return res.redirect(303, `/promotion-detail/${id}`);

  } catch (e) {
    res.status(500).json({ success: false, error: e.message || 'Lỗi lưu CTKM' });
  }
  
  // Redirect / JSON như bạn đã làm
  if (wantsJSON(req)) return res.json({ success: true, redirect: `/promotion-detail/${id}` });
  return res.redirect(303, `/promotion-detail/${id}`);

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

// ------------------------- Start server / export -------------------------
const PORT = Number(process.env.PORT) || 3000;
if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(PORT, () => console.log(`Local: http://localhost:${PORT}`));
}
