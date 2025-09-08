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
const session = require('express-session');
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
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    proxy: isVercel,
    cookie: {
      secure: isVercel,
      sameSite: 'lax',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

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
const requireAuth = (req, res, next) => {
  if (req.session?.user) return next();
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

// ------------------------- Locals: brands/categories -------------------------
app.use(async (req, res, next) => {
  res.locals.user = req.session.user;
  try {
    const { data: brandRows } = await supabase
      .from('skus')
      .select('brand')
      .not('brand', 'is', null);

    const { data: catRows } = await supabase
      .from('skus')
      .select('category')
      .not('category', 'is', null);

    res.locals.brands = [...new Set((brandRows ?? []).map((r) => r.brand).filter(Boolean))];
    res.locals.categories = [...new Set((catRows ?? []).map((r) => r.category).filter(Boolean))];

    next();
  } catch (error) {
    console.error('locals middleware error:', error);
    res.locals.brands = [];
    res.locals.categories = [];
    next();
  }
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

    req.session.user = user;
    const redirectTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    req.session.save(() => res.redirect(redirectTo));
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

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

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
    // Check Drive chung đã sẵn sàng?
    const { data: gtok } = await supabase
      .from('app_google_tokens')
      .select('refresh_token')
      .eq('id', 'global')
      .single();
    const globalDriveReady = !!gtok?.refresh_token;

    // Lịch sử so sánh gần đây + thông tin người tạo
    const { data: recentComparisons } = await supabase
      .from('price_comparisons')
      .select(`*, users:user_id (full_name, email)`)
      .order('created_at', { ascending: false })
      .limit(10);

    const comparisonsWithCreator = (recentComparisons || []).map((c) => ({
      ...c,
      created_by: c.users ? c.users.full_name || c.users.email : 'Unknown',
    }));

    res.render('price-battle', {
      title: 'Chiến giá',
      currentPage: 'price-battle',
      recentComparisons: comparisonsWithCreator,
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
    const sku = req.body.sku;

    const { data: product, error: productError } = await supabase
      .from('skus')
      .select('*')
      .eq('sku', sku)
      .single();
    if (productError || !product) {
      return res.render('promotion', {
        title: 'CTKM theo SKU',
        currentPage: 'promotion',
        product: null,
        promotions: [],
        error: 'Không tìm thấy thông tin cho SKU: ' + sku,
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      });
    }

    const today = new Date().toISOString().split('T')[0];

    const { data: allPromotions } = await supabase
      .from('promotions')
      .select(`*, promotion_categories(*), promotion_brands(*), promotion_skus(*), promotion_gifts(*), special_promotion_rules(*)`)
      .eq('apply_to_all_skus', true)
      .gte('end_date', today)
      .lte('start_date', today);

    const { data: skuPromotions } = await supabase
      .from('promotions')
      .select(`*, promotion_categories(*), promotion_brands(*), promotion_skus(*), promotion_gifts(*), special_promotion_rules(*)`)
      .eq('promotion_skus.sku', sku)
      .gte('end_date', today)
      .lte('start_date', today);

    const { data: categoryPromotions } = await supabase
      .from('promotions')
      .select(`*, promotion_categories(*), promotion_brands(*), promotion_skus(*), promotion_gifts(*), special_promotion_rules(*)`)
      .eq('promotion_categories.category', product.category)
      .gte('end_date', today)
      .lte('start_date', today);

    const { data: brandPromotions } = await supabase
      .from('promotions')
      .select(`*, promotion_categories(*), promotion_brands(*), promotion_skus(*), promotion_gifts(*), special_promotion_rules(*)`)
      .eq('promotion_brands.brand', product.brand)
      .gte('end_date', today)
      .lte('start_date', today);

    const all = [
      ...(allPromotions || []),
      ...(skuPromotions || []),
      ...(categoryPromotions || []),
      ...(brandPromotions || []),
    ];

    const unique = all.filter((p, i, self) => i === self.findIndex((x) => x.id === p.id));

    res.render('promotion', {
      title: 'CTKM theo SKU',
      currentPage: 'promotion',
      product,
      promotions: unique,
      error: null,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  } catch (error) {
    res.render('promotion', {
      title: 'CTKM theo SKU',
      currentPage: 'promotion',
      product: null,
      promotions: [],
      error: 'Lỗi hệ thống: ' + error.message,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  }
});

app.get('/promotion-detail/:id', requireAuth, async (req, res) => {
  try {
    const promoId = req.params.id;

    const { data: promotion, error } = await supabase
      .from('promotions')
      .select(`*, promotion_categories(*), promotion_brands(*), promotion_skus(*), promotion_gifts(*), special_promotion_rules(*)`)
      .eq('id', promoId)
      .single();

    if (error) throw error;

    res.render('promotion-detail', {
      title: 'Chi tiết CTKM',
      currentPage: 'promotion-detail',
      promotion,
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

// Trang quản lý CTKM
app.get('/promo-management', async (req, res) => {
  try {
    const { data: promotions, error: pErr } = await supabase
      .from('promotions')
      .select('*')
      .order('created_at', { ascending: false });
    if (pErr) console.error('promotions error:', pErr);

    let categories = [],
      brands = [];
    const { data: catRows, error: catErr } = await supabase
      .from('skus')
      .select('category')
      .not('category', 'is', null);
    if (!catErr && catRows) categories = [...new Set(catRows.map((r) => r.category))];

    const { data: brandRows, error: brandErr } = await supabase
      .from('skus')
      .select('brand')
      .not('brand', 'is', null);
    if (!brandErr && brandRows) brands = [...new Set(brandRows.map((r) => r.brand))];

    return res.render('promo-management', {
      title: 'Quản lý CTKM',
      currentPage: 'promo-management',
      promotions: promotions || [],
      categories,
      brands,
      user: req.session?.user || null,
      time: res.locals.time,
    });
  } catch (err) {
    console.error('Promo management fatal:', err);
    return res.status(500).send('Lỗi khi tải trang quản lý CTKM: ' + err.message);
  }
});

// Tạo CTKM
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
      apply_to,
      categories,
      brands,
      skus,
      is_special,
      special_brand,
      special_subcat,
      special_discount,
      compatible_with_other,
    } = req.body;

    const { data: promotion, error: promoError } = await supabase
      .from('promotions')
      .insert([
        {
          name,
          description,
          start_date,
          end_date,
          channel: channel || 'All',
          promo_type,
          coupon_code: coupon_code || null,
          apply_to_all_skus: apply_to === 'all',
          is_special: is_special || false,
          compatible_with_other: compatible_with_other || false,
          status: 'active',
          created_by: req.session.user.id,
        },
      ])
      .select()
      .single();

    if (promoError) throw promoError;

    const promoId = promotion.id;

    if (apply_to === 'category' && categories) {
      const categoryData = Array.isArray(categories)
        ? categories.map((cat) => ({ promotion_id: promoId, category: cat }))
        : [{ promotion_id: promoId, category: categories }];
      await supabase.from('promotion_categories').insert(categoryData);
    }

    if (apply_to === 'brand' && brands) {
      const brandData = Array.isArray(brands)
        ? brands.map((brand) => ({ promotion_id: promoId, brand }))
        : [{ promotion_id: promoId, brand: brands }];
      await supabase.from('promotion_brands').insert(brandData);
    }

    if (apply_to === 'sku' && skus) {
      const skuList = skus
        .split(',')
        .map((sku) => sku.trim())
        .filter((sku) => sku);
      const skuData = skuList.map((sku) => ({ promotion_id: promoId, sku }));
      await supabase.from('promotion_skus').insert(skuData);
    }

    if (is_special && special_brand && special_subcat && special_discount) {
      const rulesData = [];
      const specialBrands = Array.isArray(special_brand) ? special_brand : [special_brand];
      const subcats = Array.isArray(special_subcat) ? special_subcat : [special_subcat];
      const discounts = Array.isArray(special_discount) ? special_discount : [special_discount];

      for (let i = 0; i < specialBrands.length; i++) {
        if (specialBrands[i] && subcats[i] && discounts[i]) {
          rulesData.push({
            promotion_id: promoId,
            brand: specialBrands[i],
            subcat: subcats[i],
            discount_value: parseFloat(discounts[i]),
            condition_description: `Giảm ${new Intl.NumberFormat('vi-VN').format(
              discounts[i]
            )} VNĐ cho ${specialBrands[i]} - ${subcats[i]}`,
          });
        }
      }

      if (rulesData.length > 0) {
        await supabase.from('special_promotion_rules').insert(rulesData);
      }
    }

    return res.json({ success: true, id: promoId });
  } catch (error) {
    console.error('❌ CREATE PROMOTION ERROR:', error);
    res.status(500).json({ success: false, error: 'Lỗi khi tạo CTKM: ' + error.message });
  }
});

// Xoá CTKM
app.delete('/api/promotions/:id', requireManager, async (req, res) => {
  try {
    const promoId = req.params.id;

    await supabase.from('promotion_categories').delete().eq('promotion_id', promoId);
    await supabase.from('promotion_brands').delete().eq('promotion_id', promoId);
    await supabase.from('promotion_skus').delete().eq('promotion_id', promoId);
    await supabase.from('promotion_gifts').delete().eq('promotion_id', promoId);
    await supabase.from('special_promotion_rules').delete().eq('promotion_id', promoId);

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
