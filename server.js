require('dotenv').config();
const fs = require('fs');
const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
// ----- Multer (upload) -----
const isVercel = !!process.env.VERCEL;
const uploadDir = path.join(__dirname, 'uploads');
if (!isVercel) {
  try { fs.mkdirSync(uploadDir, { recursive: true }); } catch (e) {}
}

// Vercel: dùng memoryStorage (không ghi đĩa). Local: diskStorage.
const storage = isVercel
  ? multer.memoryStorage()
  : multer.diskStorage({
      destination: (req, file, cb) => cb(null, uploadDir),
      filename: (req, file, cb) =>
        cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'))
    });

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024, files: 3 }
});


const { createClient } = require('@supabase/supabase-js');

// ⚠️ Dùng SERVICE_ROLE nếu có (only server-side), fallback ANON
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

console.log('SUPABASE_URL:', supabaseUrl ? 'OK' : 'MISSING');
console.log('SUPABASE_KEY :', supabaseKey ? 'OK' : 'MISSING');


const supabase = createClient(supabaseUrl, supabaseKey);
const app = express();
const port = 3000;

if (isVercel) app.set('trust proxy', 1);   // ✅ đặt sau khi đã có app

// Cấu hình ứng dụng
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  proxy: isVercel,                    // để express-session biết đang sau proxy
  cookie: {
    secure: isVercel,                 // bắt buộc HTTPS trên Vercel
    sameSite: 'lax',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use((req, res, next) => {
  res.locals.user = req.session?.user || null;
  res.locals.time = new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' });
  next();
});


// Middleware xác thực
const requireAuth = (req, res, next) => {
  if (req.session?.user) return next();
  // Lưu URL gốc để quay lại sau khi đăng nhập
  req.session.returnTo = req.originalUrl;
  return res.redirect('/login');
};

const requireManager = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'manager') {
    return res.status(403).send('Access denied. Manager role required.');
  }
  next();
};

app.get('/healthz', async (req, res) => {
  try {
    const ping = await supabase.from('promotions').select('id').limit(1);
    res.json({
      ok: true,
      env: {
        SUPABASE_URL: !!supabaseUrl,
        SUPABASE_ANON_KEY: !!supabaseKey,
        SESSION_SECRET: !!process.env.SESSION_SECRET,
        VERCEL: !!process.env.VERCEL
      },
      supabase_ok: !ping.error
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


// Middleware để chia sẻ dữ liệu chung
app.use(async (req, res, next) => {
  res.locals.user = req.session.user;
  try {
    const { data: brandRows, error: brandErr } = await supabase
      .from('skus')
      .select('brand')
      .not('brand', 'is', null);

    const { data: catRows, error: catErr } = await supabase
      .from('skus')
      .select('category')
      .not('category', 'is', null);

    if (brandErr) console.warn('brand query error:', brandErr);
    if (catErr) console.warn('category query error:', catErr);

    res.locals.brands = [...new Set((brandRows ?? []).map(r => r.brand).filter(Boolean))];
    res.locals.categories = [...new Set((catRows ?? []).map(r => r.category).filter(Boolean))];

    next();
  } catch (error) {
    console.error('locals middleware error:', error);
    // đừng làm sập app vì block này; cho đi tiếp với list rỗng
    res.locals.brands = [];
    res.locals.categories = [];
    next();
  }
});


// Routes xác thực
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('login', { 
    title: 'Đăng nhập', 
    currentPage: 'login',
    error: null,
    time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
  });
});

app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('register', { 
    title: 'Đăng ký', 
    currentPage: 'register',
    error: null,
    time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
  });
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .eq('is_active', true)
      .single();

    if (error || !user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.render('login', { 
        title: 'Đăng nhập', 
        currentPage: 'login',
        error: 'Email hoặc mật khẩu không đúng',
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
      });
    }
// Middleware để chia sẻ dữ liệu chung cho tất cả views
    req.session.user = user;
    const redirectTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    req.session.save(() => res.redirect(redirectTo));
  } catch (error) {
    res.render('login', { 
      title: 'Đăng nhập', 
      currentPage: 'login',
      error: 'Lỗi hệ thống',
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
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
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
    });
  }
});
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Routes chính (yêu cầu đăng nhập)
app.get('/', requireAuth, (req, res) => {
  res.render('index', { 
    title: 'Trang chủ',
    currentPage: 'home',
    time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
  });
});

// Trang quản lý CTKM
// API để lấy thông tin SKU
app.get('/api/skus', async (req, res) => {
  try {
    const searchTerm = req.query.q;
    console.log('Search term:', searchTerm); // Debug
    
    let query = supabase
      .from('skus')
      .select('sku, product_name, brand, category, subcat, list_price')
      .order('sku')
      .limit(10);
    
    if (searchTerm && searchTerm.trim() !== '') {
      query = query.or(`sku.ilike.%${searchTerm}%,product_name.ilike.%${searchTerm}%,brand.ilike.%${searchTerm}%`);
    }
    
    const { data, error } = await query;
    
    if (error) {
      console.error('Supabase error:', error);
      throw error;
    }
    
    console.log('Found data:', data); // Debug
    res.json(data || []);
  } catch (error) {
    console.error('API error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/price-battle', requireAuth, async (req, res) => {
  try {
    // Lấy lịch sử so sánh gần đây với thông tin user
    const { data: recentComparisons, error } = await supabase
      .from('price_comparisons')
      .select(`
        *,
        users:user_id (full_name, email)
      `)
      .order('created_at', { ascending: false })
      .limit(10);

    // Thêm tên người tạo vào mỗi comparison
    const comparisonsWithCreator = recentComparisons ? recentComparisons.map(comp => ({
      ...comp,
      created_by: comp.users ? comp.users.full_name || comp.users.email : 'Unknown'
    })) : [];

    res.render('price-battle', {
      title: 'Chiến giá',
      currentPage: 'price-battle',
      recentComparisons: comparisonsWithCreator,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      user: req.session.user
    });
  } catch (error) {
    console.error('Price battle error:', error);
    res.render('price-battle', {
      title: 'Chiến giá',
      currentPage: 'price-battle',
      recentComparisons: [],
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      user: req.session.user
    });
  }
});

app.post('/price-battle/save', requireAuth, upload.array('images', 3), async (req, res) => {
    try {
        // Kiểm tra dữ liệu bắt buộc
        if (!req.body.sku || !req.body.competitor_name || !req.body.competitor_price) {
            return res.status(400).json({
                success: false,
                error: 'Thiếu thông tin bắt buộc: SKU, tên đối thủ, giá đối thủ'
            });
        }

        // Xử lý file upload nếu có
        if (req.files && req.files.length > 0) {
          imageUrls = req.files.map(f => f.originalname);
        }
        
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
            images: imageUrls
        };
        
        const { data, error } = await supabase
            .from('price_comparisons')
            .insert([comparisonData])
            .select()
            .single();

        if (error) {
            console.error('Database error:', error);
            return res.status(500).json({ 
                success: false, 
                error: 'Lỗi database: ' + error.message 
            });
        }
        
        res.json({ success: true, data });
        
    } catch (error) {
        console.error('Save comparison error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Lỗi hệ thống: ' + error.message 
        });
    }
});

// API để lấy thông tin SKU với số lần so sánh giá
app.get('/api/skus-with-comparisons', async (req, res) => {
  try {
    const searchTerm = req.query.q;
    let query = supabase
      .from('skus')
      .select(`
        *,
        price_comparisons:price_comparisons(count)
      `)
      .order('sku')
      .limit(10);
    
    if (searchTerm) {
      query = query.ilike('sku', `%${searchTerm}%`)
                .or(`product_name.ilike.%${searchTerm}%,brand.ilike.%${searchTerm}%`);
    }
    
    const { data, error } = await query;
    
    if (error) throw error;
    
    // Format data để bao gồm số lần so sánh
    const formattedData = data.map(item => ({
      ...item,
      comparison_count: item.price_comparisons[0]?.count || 0
    }));
    
    res.json(formattedData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/search-promotion', requireAuth, async (req, res) => {
  try {
    const sku = req.body.sku;
    console.log('Searching promotions for SKU:', sku);
    
    // Lấy thông tin sản phẩm
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
        time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
      });
    }
    
    // Lấy các CTKM áp dụng cho SKU này - QUERY FIXED
    const { data: allPromotions, error: allError } = await supabase
      .from('promotions')
      .select(`
        *,
        promotion_categories(*),
        promotion_brands(*),
        promotion_skus(*),
        promotion_gifts(*),
        special_promotion_rules(*)
      `)
      .eq('apply_to_all_skus', true)
      .gte('end_date', new Date().toISOString().split('T')[0])
      .lte('start_date', new Date().toISOString().split('T')[0]);

    const { data: skuPromotions, error: skuError } = await supabase
      .from('promotions')
      .select(`
        *,
        promotion_categories(*),
        promotion_brands(*),
        promotion_skus(*),
        promotion_gifts(*),
        special_promotion_rules(*)
      `)
      .eq('promotion_skus.sku', sku)
      .gte('end_date', new Date().toISOString().split('T')[0])
      .lte('start_date', new Date().toISOString().split('T')[0]);

    const { data: categoryPromotions, error: categoryError } = await supabase
      .from('promotions')
      .select(`
        *,
        promotion_categories(*),
        promotion_brands(*),
        promotion_skus(*),
        promotion_gifts(*),
        special_promotion_rules(*)
      `)
      .eq('promotion_categories.category', product.category)
      .gte('end_date', new Date().toISOString().split('T')[0])
      .lte('start_date', new Date().toISOString().split('T')[0]);

    const { data: brandPromotions, error: brandError } = await supabase
      .from('promotions')
      .select(`
        *,
        promotion_categories(*),
        promotion_brands(*),
        promotion_skus(*),
        promotion_gifts(*),
        special_promotion_rules(*)
      `)
      .eq('promotion_brands.brand', product.brand)
      .gte('end_date', new Date().toISOString().split('T')[0])
      .lte('start_date', new Date().toISOString().split('T')[0]);

    // Kết hợp tất cả promotions và loại bỏ trùng lặp
    const allPromos = [
      ...(allPromotions || []),
      ...(skuPromotions || []),
      ...(categoryPromotions || []),
      ...(brandPromotions || [])
    ];

    // Loại bỏ trùng lặp bằng ID
    const uniquePromotions = allPromos.filter((promo, index, self) =>
      index === self.findIndex(p => p.id === promo.id)
    );

    console.log('Found promotions:', uniquePromotions.length);
    
    res.render('promotion', { 
      title: 'CTKM theo SKU',
      currentPage: 'promotion',
      product: product,
      promotions: uniquePromotions,
      error: null,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
    });
    
  } catch (error) {
    console.error('Search error:', error);
    res.render('promotion', { 
      title: 'CTKM theo SKU',
      currentPage: 'promotion',
      product: null,
      promotions: [],
      error: 'Lỗi hệ thống: ' + error.message,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
    });
  }
});

app.get('/promotion-detail/:id', requireAuth, async (req, res) => {
  try {
    const promoId = req.params.id;
    
    const { data: promotion, error } = await supabase
      .from('promotions')
      .select(`
        *,
        promotion_categories(*),
        promotion_brands(*),
        promotion_skus(*),
        promotion_gifts(*),
        special_promotion_rules(*)
      `)
      .eq('id', promoId)
      .single();
    
    if (error) throw error;
    
    res.render('promotion-detail', { 
      title: 'Chi tiết CTKM',
      currentPage: 'promotion-detail',
      promotion: promotion,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
    });
  } catch (error) {
    console.error('Promotion detail error:', error);
    res.status(404).render('error', {
      title: 'Không tìm thấy',
      message: 'Không tìm thấy thông tin CTKM',
      error: error.message
    });
  }
});

// server.js
// Thêm vào server.js tạm thời

// Route để lấy thông tin sản phẩm theo SKU
app.get('/api/sku-info', requireAuth, async (req, res) => {
    try {
        const sku = req.query.sku;
        if (!sku) {
            return res.json(null);
        }

        const { data: product, error } = await supabase
            .from('skus')
            .select('*')
            .eq('sku', sku)
            .single();

        if (error || !product) {
            return res.json(null);
        }

        res.json(product);
    } catch (error) {
        console.error('SKU info error:', error);
        res.json(null);
    }
});
// Route GET để hiển thị form tạo CTKM với dữ liệu danh mục, brand
// Trang quản lý CTKM
app.get('/promo-management', async (req, res) => {
  try {
    const { data: promotions, error: pErr } = await supabase
      .from('promotions').select('*')
      .order('created_at', { ascending: false });
    if (pErr) console.error('promotions error:', pErr);

    // ⭐ không làm app lỗi nếu thiếu bảng skus hoặc RLS chặn
    let categories = [], brands = [];
    const { data: catRows, error: catErr } = await supabase
      .from('skus').select('category').not('category', 'is', null);
    if (!catErr && catRows) categories = [...new Set(catRows.map(r => r.category))];
    else if (catErr) console.warn('skus.category error:', catErr.message);

    const { data: brandRows, error: brandErr } = await supabase
      .from('skus').select('brand').not('brand', 'is', null);
    if (!brandErr && brandRows) brands = [...new Set(brandRows.map(r => r.brand))];
    else if (brandErr) console.warn('skus.brand error:', brandErr.message);

    return res.render('promo-management', {
      title: 'Quản lý CTKM',
      currentPage: 'promo-management',
      promotions: promotions || [],
      categories, brands,
      user: req.session?.user || null,
      time: res.locals.time
    });
  } catch (err) {
    console.error('Promo management fatal:', err);
    return res.status(500).send('Lỗi khi tải trang quản lý CTKM: ' + err.message);
  }
});


// Route POST để tạo CTKM mới
app.post('/create-promotion', requireAuth, async (req, res) => {
    try {
        console.log('=== CREATE PROMOTION REQUEST ===');
        console.log('Request body:', req.body);
        console.log('Request headers:', req.headers);
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
            compatible_with_other
        } = req.body;
        
        // Tạo CTKM chính
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
                is_special: is_special || false,
                compatible_with_other: compatible_with_other || false,
                status: 'active',
                created_by: req.session.user.id
            }])
            .select()
            .single();

        if (promoError) throw promoError;

        const promoId = promotion.id;
        
        // Thêm phạm vi áp dụng
        if (apply_to === 'category' && categories) {
            const categoryData = Array.isArray(categories) 
                ? categories.map(cat => ({ promotion_id: promoId, category: cat }))
                : [{ promotion_id: promoId, category: categories }];
            
            await supabase.from('promotion_categories').insert(categoryData);
        }

        if (apply_to === 'brand' && brands) {
            const brandData = Array.isArray(brands)
                ? brands.map(brand => ({ promotion_id: promoId, brand: brand }))
                : [{ promotion_id: promoId, brand: brands }];
            
            await supabase.from('promotion_brands').insert(brandData);
        }

        if (apply_to === 'sku' && skus) {
            const skuList = skus.split(',').map(sku => sku.trim()).filter(sku => sku);
            const skuData = skuList.map(sku => ({ promotion_id: promoId, sku: sku }));
            
            await supabase.from('promotion_skus').insert(skuData);
        }

        // Thêm quy tắc đặc biệt nếu có
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
                        condition_description: `Giảm ${new Intl.NumberFormat('vi-VN').format(discounts[i])} VNĐ cho ${specialBrands[i]} - ${subcats[i]}`
                    });
                }
            }

            if (rulesData.length > 0) {
                await supabase.from('special_promotion_rules').insert(rulesData);
            }
        }

      return res.json({ success: true, id: promoId });
    }  catch (error) {
        console.error('❌ CREATE PROMOTION ERROR:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Lỗi khi tạo CTKM: ' + error.message 
        });
    }
});

// Route DELETE để xóa CTKM
app.delete('/api/promotions/:id', requireManager, async (req, res) => {
    try {
        const promoId = req.params.id;

        // Xóa các bảng liên quan trước
        await supabase.from('promotion_categories').delete().eq('promotion_id', promoId);
        await supabase.from('promotion_brands').delete().eq('promotion_id', promoId);
        await supabase.from('promotion_skus').delete().eq('promotion_id', promoId);
        await supabase.from('promotion_gifts').delete().eq('promotion_id', promoId);
        await supabase.from('special_promotion_rules').delete().eq('promotion_id', promoId);

        // Xóa CTKM chính
        const { error } = await supabase.from('promotions').delete().eq('id', promoId);

        if (error) throw error;

        res.json({ success: true, message: 'Xóa CTKM thành công' });
    } catch (error) {
        console.error('Delete promotion error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Lỗi khi xóa CTKM: ' + error.message 
        });
    }
});

// Route GET để lấy chi tiết CTKM (sửa)
app.get('/edit-promotion/:id', requireAuth, async (req, res) => {
    try {
        const promoId = req.params.id;

        const { data: promotion, error } = await supabase
            .from('promotions')
            .select(`
                *,
                promotion_categories(*),
                promotion_brands(*),
                promotion_skus(*),
                promotion_gifts(*),
                special_promotion_rules(*)
            `)
            .eq('id', promoId)
            .single();

        if (error) throw error;

        res.render('edit-promotion', {
            title: 'Sửa CTKM',
            currentPage: 'edit-promotion',
            promotion: promotion,
            time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })
        });
    } catch (error) {
        console.error('Edit promotion error:', error);
        res.status(404).render('error', {
            title: 'Không tìm thấy',
            message: 'Không tìm thấy CTKM để sửa',
            error: error.message
        });
    }
});
app.get('/api/promotions', requireAuth, async (req, res) => {
  try {
    const { data: promotions, error } = await supabase
      .from('promotions')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json({ success: true, promotions: promotions || [] });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Lỗi khi lấy danh sách CTKM: ' + err.message });
  }
});

app.get('/api/promotions/:id', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('promotions')
      .select(`
        *,
        promotion_categories(*),
        promotion_brands(*),
        promotion_skus(*),
        promotion_gifts(*),
        special_promotion_rules(*)
      `)
      .eq('id', req.params.id)
      .single();

    if (error) throw error;
    res.json({ success: true, promotion: data });
  } catch (err) {
    res.status(404).json({ success: false, error: 'Không tìm thấy CTKM: ' + err.message });
  }
});

if (process.env.VERCEL) {
  module.exports = app; // Vercel sẽ dùng export này làm handler
} else {
  app.listen(port, () => console.log(`Local: http://localhost:${port}`));
}