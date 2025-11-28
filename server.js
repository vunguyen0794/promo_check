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

const fs = require('fs');
const { BigQuery } = require('@google-cloud/bigquery');
const { sendNewPostEmail } = require('./utils/mailer');
const ejs = require('ejs');
const chromium = require('@sparticuz/chromium');
const puppeteerCore = require('puppeteer-core'); // Đổi tên thành puppeteerCore
const puppeteer = require('puppeteer'); // Đây là bản đầy đủ cho local
const { Readable, PassThrough } = require('stream');
const cron = require('node-cron');

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

const BRANCH_CONFIG = {
  // Đây là mục dự phòng nếu không tìm thấy branch
  'DEFAULT': {
    name: "PHONG VŨ (Trụ sở chính)",
    address: "677/2A Điện Biên Phủ, Phường Thạnh Mỹ Tây, Tp. Hồ Chí Minh",
    mst: "0304998335",
    hotline: "1800 6867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Á Châu (ACB)",
    bankHolder: "Công ty Cổ phần Thương mại - Dịch vụ Phong Vũ",
    bankAccount: "123456789"
  },
  
  // ----- ĐIỀN THÔNG TIN CHI NHÁNH CỦA BẠN VÀO ĐÂY -----
  'HCM.BD': {
    name: "PHONG VŨ (Chi nhánh HCM.BD)",
    address: "[ĐỊA CHỈ CỦA HCM.BD]",
    mst: "0304998335-XXX",
    hotline: "[SĐT CỦA HCM.BD]",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Á Châu (ACB)",
    bankHolder: "Tên chủ tài khoản của HCM.BD",
    bankAccount: "987654321"
  },
  
  'CP01': {
    name: "PHONG VŨ (Chi nhánh 264 NTMK)",
    address: "264A-264B-264C Nguyễn Thị Minh Khai, Phường Võ Thị Sáu, Quận 3, Thành phố Hồ Chí Minh",
    mst: "0304998358",
    hotline: "0287.301.6867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PVSFI"
  },

    'CP02': {
    name: "PHONG VŨ (Chi nhánh Bình Dương)",
    address: "408 Đại Lộ Bình Dương, Phường Phú Lợi, Tp. Hồ Chí Minh",
    mst: "0304998358",
    hotline: "0274.730.6867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PV158"
  },

      'CP05': {
    name: "PHONG VŨ (Chi nhánh Quận 6)",
    address: "1081A - 1081C Hậu Giang, Phường Bình Phú, TPHCM",
    mst: "0304998358",
    hotline: "0287.303.6867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PV670"
  },

        'CP07': {
    name: "PHONG VŨ (Chi nhánh Quận 7)",
    address: "Số 9-11 Nguyễn Thị Thập, Phường Tân Mỹ, TPHCM",
    mst: "0304998358",
    hotline: "0287.305.6867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PVDUT"
  },
          'CP08': {
    name: "PHONG VŨ (Chi nhánh Gò Vấp)",
    address: "2A Nguyễn Oanh, Phường Hạnh Thông, TPHCM",
    mst: "0304998358",
    hotline: "0287.309.6867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PVGOV"
  },

            'CP40': {
    name: "PHONG VŨ (Chi nhánh Tân Bình)",
    address: "02 Đường Hoàng Hoa Thám, Phường Bảy Hiền, Tp. Hồ Chí Minh",
    mst: "0304998358",
    hotline: "0287.302.6867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PVP2U"
  },

              'CP46': {
    name: "PHONG VŨ (Chi nhánh Thủ Đức 1)",
    address: "164 Lê Văn Việt, Phường Tăng Nhơn Phú, TPHCM",
    mst: "0304998358",
    hotline: "0287.304.6867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PV4TC"
  },

                'CP67': {
    name: "PHONG VŨ (Chi nhánh Thủ đức 2)",
    address: "269 - 271 Võ Văn Ngân, Phường Thủ Đức, TPHCM",
    mst: "0304998358",
    hotline: "02873.000.089",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PV124"
  },

                  'CP58': {
    name: "PHONG VŨ (Chi nhánh Cách mạng tháng tám)",
    address: "132E Cách Mạng Tháng Tám, Phường Nhiêu Lộc, Tp. Hồ Chí Minh",
    mst: "0304998358",
    hotline: "0287.305.8867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PVIJO"
  },

                    'CP62': {
    name: "PHONG VŨ (Chi nhánh Bình Thạnh)",
    address: "26 Phan Đăng Lưu, Phường Gia Định, Tp. Hồ Chí Minh",
    mst: "0304998358",
    hotline: "0287.308.8867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PVICU"
  },

                      'CP64': {
    name: "PHONG VŨ (Chi nhánh Quận 12)",
    address: "38M Đường Nguyễn Ảnh Thủ, Phường Trung Mỹ Tây, Tp. Hồ Chí Minh",
    mst: "0304998358",
    hotline: "0287.303.8699",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PVOLL"
  },

                        'CP69': {
    name: "PHONG VŨ (Chi nhánh Dĩ An)",
    address: "67 - 69 Nguyễn An Ninh, Phường Dĩ An, Thành phố Hồ Chí Minh",
    mst: "0304998358",
    hotline: "0287.300.0996",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PV124"
  },
  // (Thêm các chi nhánh khác ở đây)
};


// ======================= MIDDLEWARE LẤY CÀI ĐẶT CHUNG =======================
// Middleware này sẽ chạy TRƯỚC TẤT CẢ các route (app.get, app.post)
app.use(async (req, res, next) => {
  
  // === [THÊM MỚI] KIỂM TRA TRẠNG THÁI EVENT CỦA CHI NHÁNH ===
  res.locals.isBranchEventActive = false; // Mặc định là ẩn

  if (res.locals.user && res.locals.user.branch_code) {
    try {
      const { data: evStatus } = await supabase
        .from('branch_event_status')
        .select('is_event_active')
        .eq('branch_code', res.locals.user.branch_code)
        .maybeSingle(); // Dùng maybeSingle để không lỗi nếu chưa cấu hình

      if (evStatus && evStatus.is_event_active) {
        res.locals.isBranchEventActive = true;
      }
    } catch (e) {
      console.error("Lỗi check event active:", e.message);
    }
  }
  
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


  // === [THÊM MỚI] KIỂM TRA TRẠNG THÁI EVENT CỦA CHI NHÁNH ===
  res.locals.isBranchEventActive = false; // Mặc định là ẩn

  if (res.locals.user && res.locals.user.branch_code) {
    try {
      const { data: evStatus } = await supabase
        .from('branch_event_status')
        .select('is_event_active')
        .eq('branch_code', res.locals.user.branch_code)
        .maybeSingle(); // Dùng maybeSingle để không lỗi nếu chưa cấu hình

      if (evStatus && evStatus.is_event_active) {
        res.locals.isBranchEventActive = true;
      }
    } catch (e) {
      console.error("Lỗi check event active:", e.message);
    }
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

  // === SỬA LỖI: Tạo một PassThrough Stream ===
  // Đây là cách chuẩn để chuyển Buffer thành Stream cho googleapis
  const bufferStream = new PassThrough();
  bufferStream.end(buffer);
  // =======================================
  
  const { data: created } = await drive.files.create({
    requestBody: { name: filename, parents },
    media: { 
      mimeType: mimeType,
      body: bufferStream // <-- Gửi stream đã tạo
    },
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
    scope: ['https://www.googleapis.com/auth/drive.file',
      'https://www.googleapis.com/auth/spreadsheets.readonly'
    ],
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
    const { email, password, full_name } = req.body;
    const emailToRegister = email.toLowerCase().trim();

    // 1. Kiểm tra domain (vẫn giữ)
    const allowedDomains = ['@phongvu.vn', '@phongvu-mna.vn'];
    const emailDomain = emailToRegister.substring(emailToRegister.lastIndexOf('@'));
    if (!allowedDomains.includes(emailDomain)) {
      throw new Error('Chỉ cho phép đăng ký bằng email nội bộ (@phongvu.vn hoặc @phongvu-mna.vn).');
    }

    // 2. KIỂM TRA TÀI KHOẢN TỒN TẠI (LOGIC MỚI)
    // (Kiểm tra trước để đưa ra thông báo lỗi chính xác)
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', emailToRegister)
      .single();

    if (existingUser) {
      throw new Error(`Email "${emailToRegister}" đã được đăng ký. Vui lòng đăng nhập.`);
    }

    // 3. Tra cứu Google Sheets (Đã sửa ở Bước 1)
    const accessInfo = await getUserAccessInfo(emailToRegister);

    // 4. Validation
    if (!accessInfo) {
      throw new Error(`Email "${emailToRegister}" không có trong danh sách nhân sự được phép đăng ký.`);
    }

    // 5. Kiểm tra ngày hết hạn
    const today = new Date();
    const yyyy = today.getFullYear();
    const mm = String(today.getMonth() + 1).padStart(2, '0');
    const dd = String(today.getDate()).padStart(2, '0');
    const todayStr = `${yyyy}${mm}${dd}`;

    if (String(accessInfo.end_date) < todayStr) {
      throw new Error(`Tài khoản nhân sự "${emailToRegister}" đã hết hạn (End Date: ${accessInfo.end_date}).`);
    }

    // 6. Nếu mọi thứ OK, tiến hành tạo tài khoản
    const hashedPassword = await bcrypt.hash(password, 10);

    const { data: user, error: insertError } = await supabase
      .from('users')
      .insert([{ 
        email: emailToRegister, 
        password_hash: hashedPassword, 
        full_name,
        role: 'staff',
        branch_code: accessInfo.branch_id
      }])
      .select()
      .single();

    if (insertError) throw insertError;

    // 7. Đăng nhập và chuyển hướng
    req.session.user = { id: user.id, email: user.email, full_name: user.full_name, role: user.role, branch_code: user.branch_code };
    res.redirect('/');
    
  } catch (error) {
    // 8. Trả về lỗi
    res.render('register', {
      title: 'Đăng ký',
      currentPage: 'register',
      error: 'Lỗi đăng ký: ' + error.message,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  }
});


app.post('/logout', (req, res) => { req.session = null; return res.redirect('/login'); });

// --- ROUTE TRANG CHỦ (RENDER LẦN ĐẦU) ---
app.get('/', requireAuth, async (req, res) => {
  try {
    const selectedGroup = req.query.group || '';
    const searchQuery = (req.query.q || '').trim().toLowerCase();
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const pageSize = 8;
    const today = new Date().toISOString().slice(0, 10);

    // 1. Query DB (Lấy SKU để search)
    const { data: allPromos, error: promosErr } = await supabase
      .from('promotions')
      .select('*, promotion_skus(sku)')
      .eq('status', 'active')
      .lte('start_date', today)
      .gte('end_date', today);
    if (promosErr) throw promosErr;

    // 2. Tính toán Discount & Stack (Logic cũ giữ nguyên)
    const promoIds = allPromos.map(p => p.id);
    const { data: compatRows } = await supabase.from('promotion_compat_allows').select('promotion_id').in('promotion_id', promoIds);
    const promosWithAllowRules = new Set((compatRows || []).map(r => r.promotion_id));

    const promosWithStackInfo = allPromos.map(p => {
      let displayDiscount = null; let displayPrefix = 'Giảm'; let discountValueForSort = 0;
      if (p.coupon_list && p.coupon_list.length > 0) {
        const discounts = p.coupon_list.map(c => parseFloat(String(c.discount).replace(/[^0-9]/g, '')) || 0);
        const maxDiscount = Math.max(...discounts);
        if (maxDiscount > 0) { displayDiscount = maxDiscount; displayPrefix = 'Giảm đến'; discountValueForSort = maxDiscount; }
      } else if (String(p.discount_value_type || '').toLowerCase() === 'amount') {
        displayDiscount = p.discount_value; discountValueForSort = p.discount_value || 0;
      } else if (String(p.discount_value_type || '').toLowerCase() === 'percent') {
        displayDiscount = `${p.discount_value}%`;
        discountValueForSort = (p.discount_value / 100) * 10000000;
        if (p.max_discount_amount) discountValueForSort = Math.min(discountValueForSort, p.max_discount_amount);
      }
      const isStackable = p.compatible_with_other_promos === true || promosWithAllowRules.has(p.id);
      return { ...p, __stackable: isStackable, __display_discount: displayDiscount, __display_prefix: displayPrefix, __sort_value: discountValueForSort };
    });

    const userBranch = req.session.user?.branch_code; 

// Hàm kiểm tra xem User có được thấy Promo này không
const isVisibleToUser = (p) => {
    // Check Branch
    if (p.apply_branches && p.apply_branches.length > 0) {
        // Nếu user chưa đăng nhập hoặc branch user không nằm trong list cho phép
        if (!userBranch || !p.apply_branches.includes(userBranch)) {
            return false; 
        }
    }
    return true;
};

    // 3. --- LOGIC LỌC QUAN TRỌNG (Group -> Search) ---
    let filteredPromos = promosWithStackInfo;

    // BƯỚC A: Lọc theo Nhóm trước (nếu có) - "Khoanh vùng dữ liệu"
    if (selectedGroup) {
      filteredPromos = filteredPromos.filter(p => p.group_name === selectedGroup);
    }

    // BƯỚC B: Tìm kiếm trong vùng dữ liệu đã khoanh
    if (searchQuery) {
      filteredPromos = filteredPromos.filter(p => {
        const pName = (p.name || '').toLowerCase();
        const pGroup = (p.group_name || '').toLowerCase();
        const pDesc = (p.description || '').toLowerCase();
        // Tìm trong danh sách SKU áp dụng
        const hasSkuMatch = (p.promotion_skus || []).some(item => (item.sku || '').toLowerCase().includes(searchQuery));

        return pName.includes(searchQuery) || 
               pGroup.includes(searchQuery) || 
               pDesc.includes(searchQuery) || 
               hasSkuMatch;
      });
    }

    // 4. Sắp xếp & Phân trang
    filteredPromos.sort((a, b) => b.__sort_value - a.__sort_value);
    
    // Lấy danh sách nhóm (Sắp xếp A->Z)
    const allGroups = [...new Set(promosWithStackInfo.map(p => p.group_name).filter(Boolean))].sort((a, b) => a.localeCompare(b));

    const totalItems = filteredPromos.length;
    const totalPages = Math.ceil(totalItems / pageSize);
    const paginatedPromos = filteredPromos.slice((page - 1) * pageSize, page * pageSize);

    // 5. Các data phụ (Matrix, Random...) - Giữ nguyên code cũ của bạn
    const { data: pc } = await supabase.from('price_comparisons').select('sku, product_name, brand, competitor_name').order('created_at', { ascending: false }).limit(100);
    const bySku = {}; const totalBySku = {};
    (pc || []).forEach(r => { if (!r.sku) return; if (!bySku[r.sku]) bySku[r.sku] = { product_name: r.product_name || '', brand: r.brand || '', counts: {} }; bySku[r.sku].counts[r.competitor_name] = (bySku[r.sku].counts[r.competitor_name] || 0) + 1; totalBySku[r.sku] = (totalBySku[r.sku] || 0) + 1; });
    const topSkus = Object.keys(totalBySku).sort((a, b) => totalBySku[b] - totalBySku[a]).slice(0, 10);
    const compSet = {}; topSkus.forEach(s => Object.keys(bySku[s].counts).forEach(c => { compSet[c] = (compSet[c] || 0) + bySku[s].counts[c]; }));
    const competitorCols = Object.keys(compSet).sort((a, b) => compSet[b] - compSet[a]).slice(0, 6);
    const matrixRows = topSkus.map(sku => { const row = bySku[sku]; let topComp = '-'; let topCompCount = 0; Object.entries(row.counts).forEach(([c, n]) => { if (n > topCompCount) { topComp = c; topCompCount = n; } }); return { sku, product_name: row.product_name, brand: row.brand, total: totalBySku[sku], top_competitor: topComp, cells: competitorCols.map(c => row.counts[c] || 0) }; });
    
    const { data: randomSkus } = await supabase.from('skus').select('*').order('list_price', { ascending: false, nullsFirst: false }).limit(8);

    res.render('index', {
      title: 'Trang chủ', currentPage: 'home',
      featuredPromos: paginatedPromos, 
      allGroups, 
      selectedGroup, 
      searchQuery, // Truyền lại query để hiển thị trên ô input
      page, totalPages,
      matrixRows, competitorCols,
      randomSkus: randomSkus || [],
    });
  } catch (e) {
    console.error('Lỗi trang chủ:', e);
    res.render('index', { title: 'Trang chủ', currentPage: 'home', error: e.message });
  }
});

// --- API FEATURED PROMOS (DÙNG CHO AJAX) ---
app.get('/api/featured-promos', requireAuth, async (req, res) => {
  try {
    const selectedGroup = req.query.group || '';
    const searchQuery = (req.query.q || '').trim().toLowerCase();
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const pageSize = 8;
    const today = new Date().toISOString().slice(0, 10);

    const { data: allPromos } = await supabase
      .from('promotions')
      .select('*, promotion_skus(sku)')
      .eq('status', 'active')
      .lte('start_date', today)
      .gte('end_date', today);

    const promoIds = allPromos.map(p => p.id);
    const { data: compatRows } = await supabase.from('promotion_compat_allows').select('promotion_id').in('promotion_id', promoIds);
    const promosWithAllowRules = new Set((compatRows || []).map(r => r.promotion_id));

    const promosWithStackInfo = allPromos.map(p => {
       let displayDiscount = null; let displayPrefix = 'Giảm'; let discountValueForSort = 0;
       if (p.coupon_list && p.coupon_list.length > 0) {
         const discounts = p.coupon_list.map(c => parseFloat(String(c.discount).replace(/[^0-9]/g, '')) || 0);
         const maxDiscount = Math.max(...discounts);
         if (maxDiscount > 0) { displayDiscount = maxDiscount; displayPrefix = 'Giảm đến'; discountValueForSort = maxDiscount; }
       } else if (String(p.discount_value_type || '').toLowerCase() === 'amount') {
         displayDiscount = p.discount_value; discountValueForSort = p.discount_value || 0;
       } else if (String(p.discount_value_type || '').toLowerCase() === 'percent') {
         displayDiscount = `${p.discount_value}%`; discountValueForSort = (p.discount_value / 100) * 10000000; 
         if (p.max_discount_amount) discountValueForSort = Math.min(discountValueForSort, p.max_discount_amount);
       }
       const isStackable = p.compatible_with_other_promos === true || promosWithAllowRules.has(p.id);
       return { ...p, __stackable: isStackable, __display_discount: displayDiscount, __display_prefix: displayPrefix, __sort_value: discountValueForSort };
    });

    // --- LOGIC LỌC GIỐNG HỆT ROUTE TRANG CHỦ ---
    let filteredPromos = promosWithStackInfo;

    if (selectedGroup) {
      filteredPromos = filteredPromos.filter(p => p.group_name === selectedGroup);
    }

    if (searchQuery) {
      filteredPromos = filteredPromos.filter(p => {
        const pName = (p.name || '').toLowerCase();
        const pGroup = (p.group_name || '').toLowerCase();
        const pDesc = (p.description || '').toLowerCase();
        const hasSkuMatch = (p.promotion_skus || []).some(item => (item.sku || '').toLowerCase().includes(searchQuery));
        return pName.includes(searchQuery) || pGroup.includes(searchQuery) || pDesc.includes(searchQuery) || hasSkuMatch;
      });
    }

    filteredPromos.sort((a, b) => b.__sort_value - a.__sort_value);

    const totalPages = Math.ceil(filteredPromos.length / pageSize);
    const paginatedPromos = filteredPromos.slice((page - 1) * pageSize, page * pageSize);

    res.render('partials/_featured-promos', {
      featuredPromos: paginatedPromos,
      page,
      totalPages,
      selectedGroup // Không cần truyền searchQuery xuống partial
    });
  } catch (e) {
    console.error(e);
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

// ===== SỬA API COMPONENTS (DÙNG .eq() VÌ CLIENT ĐÃ SỬA) =====
app.get('/api/components', requireAuth, async (req, res) => {
  try {
    // Client đã gửi ID 3 phần (ví dụ: 'NH03-01-02')
    const subcatPrefix = req.query.subcat; 
    if (!subcatPrefix) {
      return res.status(400).json({ ok: false, error: 'Thiếu mã subcat' });
    }

    // 1. Lấy danh sách linh kiện (SKU) từ Supabase
    const { data: components, error: componentsError } = await supabase
      .from('skus')
      .select('sku, product_name, list_price, brand, subcat')
      
      // === SỬA LỖI: Dùng 'eq()' vì client đã gửi đúng ID 3 phần ===
      .like('subcat', `${subcatPrefix}%`)
      // =======================================================
      
      //.limit(100); 

    if (componentsError) throw componentsError;
    if (!components || components.length === 0) {
      console.warn(`[Build PC] Không tìm thấy SKU nào cho subcat: ${subcatPrefix}`);
      return res.json({ ok: true, components: [] });
    }

    const skuList = components.map(c => c.sku);

    // 2. Lấy tồn kho (Giữ nguyên logic)
    let stockMap = {};
    try {
        stockMap = await getSkuNewStockByBranch(skuList);
    } catch (bqError) {
        console.error("LỖI BIGQUERY (getSkuNewStockByBranch):", bqError.message);
    }

    // 3. Gộp dữ liệu (Giữ nguyên logic)
    const componentsWithStock = components.map(component => {
      const stock_by_branch = stockMap[component.sku] || {};
      const total_stock = Object.values(stock_by_branch).reduce((sum, qty) => sum + qty, 0);

      return {
        ...component,
        stock_by_branch: stock_by_branch,
        total_stock: total_stock
      };
    });

    // 4. Sắp xếp (Giữ nguyên logic)
    componentsWithStock.sort((a, b) => b.total_stock - a.total_stock);
    
    // 5. Trả về dữ liệu
    res.json({ ok: true, components: componentsWithStock });

  } catch (e) {
    console.error('Lỗi API /api/components:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});
// ===== KẾT THÚC SỬA API =====


// ===== BẮT ĐẦU: SỬA TOÀN BỘ API CHECK PROMOS (CÓ CẢNH BÁO) =====
app.post('/api/pc-builder/check-promos', requireAuth, async (req, res) => {
  try {
    const formatVND = (n) => {
      return new Intl.NumberFormat('vi-VN').format(Number(n || 0)) + ' VNĐ';
    };

    const { buildConfig, totalPrice } = req.body;
    
    if (!buildConfig || totalPrice === undefined) {
      return res.status(400).json({ ok: false, error: 'Thiếu dữ liệu cấu hình.' });
    }

    const items = Object.values(buildConfig);
    if (items.length === 0) {
      return res.json({ ok: true, success: false, reason: 'Vui lòng chọn linh kiện.' });
    }

    // --- BƯỚC 1: ĐỊNH NGHĨA CÁC ĐIỀU KIỆN TỪ HÌNH ẢNH ---
    
    // Helper: Ánh xạ Subcat ID sang Tên Tiếng Việt
    const subcatToName = (subcat) => {
      const map = {
        'NH03-01-02-01': 'Bo mạch chủ',
        'NH03-01-01-01': 'Bộ vi xử lý (CPU)',
        'NH03-01-03-01': 'Card màn hình (VGA)',
        'NH03-01-07-01': 'Nguồn máy tính',
        'NH03-01-04-01': 'Bộ nhớ trong (RAM)',
        'NH03-01-05-01': 'Ổ cứng SSD',
        'NH03-01-05-02': 'Ổ cứng HDD',
        'NH03-01-06-01': 'Thùng máy'
      };
      // Xử lý nhóm ổ cứng
      if (Array.isArray(subcat) && subcat.includes('NH03-01-05-01')) return 'Ổ cứng (SSD/HDD)';
      return map[subcat] || subcat;
    };

    const group1_MustHaveOne = [
      'NH03-01-02-01', // Bo mạch chủ
      'NH03-01-01-01', // Bộ vi xử lý (CPU)
      'NH03-01-03-01'  // Card màn hình (VGA)
    ];
    
    const group2_MinOne = [
      'NH03-01-07-01', // Nguồn máy tính
      'NH03-01-04-01', // Bộ nhớ trong (RAM)
      ['NH03-01-05-01', 'NH03-01-05-02'], // Ổ cứng (SSD hoặc HDD)
      'NH03-01-06-01'  // Thùng máy
    ];
    
    const tiers = [
      { min: 50000000, discount: 1000000, code: 'PVBUILDPC25114' },
      { min: 30000000, discount: 600000,  code: 'PVBUILDPC25113' },
      { min: 20000000, discount: 400000,  code: 'PVBUILDPC25112' },
      { min: 10000000, discount: 200000,  code: 'PVBUILDPC25111' }
    ];

    // --- BƯỚC 2: KIỂM TRA CÁC ĐIỀU KIỆN ---
    let failReasons = []; // Mảng chứa các lý do thất bại

    const countBySubcat = (subcat) => {
      return items.filter(item => item.subcat === subcat).reduce((sum, item) => sum + item.quantity, 0);
    };
    
    const hasSubcat = (subcatOrGroup) => {
      if (Array.isArray(subcatOrGroup)) {
        return items.some(item => subcatOrGroup.includes(item.subcat));
      }
      return items.some(item => item.subcat === subcatOrGroup);
    };

    // Kiểm tra Nhóm 1 (DUY NHẤT 1)
    let group1_Violations = [];
    for (const subcat of group1_MustHaveOne) {
      const count = countBySubcat(subcat);
      if (count === 0) {
        group1_Violations.push(`Thiếu ${subcatToName(subcat)}`);
      } else if (count > 1) {
        group1_Violations.push(`Dư ${subcatToName(subcat)} (chỉ được 1)`);
      }
    }
    if (group1_Violations.length > 0) {
      failReasons.push(`Nhóm 1 (CPU/Main/VGA): ${group1_Violations.join(', ')}.`);
    }

    // Kiểm tra Nhóm 2 (TỐI THIỂU 1)
    let group2_Violations = [];
    for (const subcatOrGroup of group2_MinOne) {
      if (!hasSubcat(subcatOrGroup)) {
        group2_Violations.push(`Thiếu ${subcatToName(subcatOrGroup)}`);
      }
    }
    if (group2_Violations.length > 0) {
      failReasons.push(`Nhóm 2 (Linh kiện khác): ${group2_Violations.join(', ')}.`);
    }

    // --- BƯỚC 3: KẾT LUẬN ---
    if (failReasons.length > 0) {
      // TH 1: Không đạt điều kiện linh kiện
      const reason = `Cấu hình chưa đạt: ${failReasons.join(' ')}`;
      console.log(`[Build PC] Không đạt: ${reason}`);
      return res.json({ ok: true, success: false, reason: reason });
    }
    
    // TH 2: Đạt điều kiện, check giá
    console.log("[Build PC] Cấu hình ĐẠT điều kiện linh kiện.");
    for (const tier of tiers) {
      if (totalPrice >= tier.min) {
        // Đã tìm thấy bậc cao nhất phù hợp!
        const promo = {
          id: 'BUILD_PC_2511',
          name: `Build PC - Giảm ${formatVND(tier.discount)} cho đơn từ ${formatVND(tier.min)}`,
          description: 'Khách hàng build PC có các sản phẩm thỏa điều kiện.',
          discount_amount: tier.discount,
          coupon: tier.code
        };
        return res.json({ ok: true, success: true, promo: promo });
      }
    }

    // TH 3: Đạt điều kiện, nhưng không đủ tiền
    const lowestTier = tiers[tiers.length - 1]; // Bậc 10tr
    const needed = lowestTier.min - totalPrice;
    const reason = `Cấu hình đã đạt. Cần thêm ${formatVND(needed)} để nhận KM ${formatVND(lowestTier.discount)}.`;
    console.log(`[Build PC] Đạt, nhưng không đủ ${lowestTier.min}.`);
    return res.json({ 
      ok: true, 
      success: false, 
      reason: reason
    });

  } catch (e) {
    console.error('Lỗi API /api/pc-builder/check-promos:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});
// ===== KẾT THÚC: SỬA TOÀN BỘ API =====
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

// --- ROUTE TÌM KIẾM SKU (ĐÃ SỬA LỖI SCOPE & THIẾU HÀM) ---
app.all('/search-promotion', requireAuth, async (req, res) => {
  // 1. Khai báo biến bên ngoài try/catch để tránh lỗi ReferenceError khi render lỗi
  let inventoryMap = null;
  let inventoryCounts = null;
  let oldestSerials = [];
  let isGlobalAdmin = false;
  let product = null;
  let promotions = [];
  let chosenPromos = [];
  let internalContest = null;
  let totalDiscount = 0;
  let finalPrice = 0;
  let comparisonCount = 0;

  const skuInput = (
    req.method === 'POST' ? (req.body?.sku || req.body?.query) : (req.query?.query || req.query?.sku) || ''
  ).toString().trim();

  try {
    console.log(`\n--- [DEBUG] BẮT ĐẦU TÌM KIẾM CHO SKU: ${skuInput} ---`);

    const userBranch = req.session.user?.branch_code || null;
    const userRole = req.session.user?.role || null;
    
    // --- ĐỊNH NGHĨA HÀM isVisibleToUser (SỬA LỖI 1) ---
    const isVisibleToUser = (p) => {
        // Check Branch
        if (p.apply_branches && p.apply_branches.length > 0) {
            // Nếu user chưa đăng nhập hoặc branch user không nằm trong list cho phép
            if (!userBranch || !p.apply_branches.includes(userBranch)) {
                return false; 
            }
        }
        return true;
    };
    // --------------------------------------------------

    if (!skuInput) {
      throw new Error('Vui lòng nhập SKU.');
    }

    // 1) Lấy sản phẩm
    const { data: productData } = await supabase.from('skus').select('*').eq('sku', skuInput).single();
    product = productData;

    if (!product) {
       throw new Error('Không tìm thấy thông tin cho SKU: ' + skuInput);
    }
    
    const price = Number(product.list_price || 0);
    console.log(`[DEBUG] Bước 1: Đã tìm thấy sản phẩm - Tên: ${product.product_name}, Giá niêm yết: ${price}đ`);

    // === LẤY TỒN KHO BIGQUERY ===
    try {
        const today = new Date().toISOString().split('T')[0];
        isGlobalAdmin = (userRole === 'admin' || userBranch === 'HCM.BD');

        if (userBranch && bigquery) {
            const skuList = [product.sku];
            inventoryMap = await getInventoryCounts(skuList, userBranch, isGlobalAdmin, today);

            if (inventoryMap.has(product.sku)) {
                const branchMap = inventoryMap.get(product.sku);
                if (!isGlobalAdmin) {
                    if (branchMap.has(userBranch)) {
                        inventoryCounts = branchMap.get(userBranch);
                    }
                }
            }
        }
    } catch (e) {
        console.error("Lỗi khi lấy tồn kho:", e.message);
    }

    // === LẤY TOP 5 SERIALS ===
    try {
        const today = new Date().toISOString().split('T')[0];
        if (userBranch && bigquery) {
            oldestSerials = await getOldestSerials(product.sku, userBranch, isGlobalAdmin, today, 5);
        }
    } catch (e_serial) {
        console.error("Lỗi khi lấy serials:", e_serial.message);
    }

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
    let filteredPromos = (promosRaw || []).filter(p => {
        const pBrand = (product.brand || '').toLowerCase();
        const pCategory = (product.category || '').toLowerCase();
        const pSubcat = (product.subcat || '').toLowerCase();

        // Check Branch ngay tại đây
        if (!isVisibleToUser(p)) return false;

        // Check Exclude
        if (p.exclude_brands && p.exclude_brands.length > 0) {
             if (p.exclude_brands.map(b=>b.toLowerCase()).includes(pBrand)) return false;
        }
        if (p.exclude_subcats && p.exclude_subcats.length > 0) {
             if (p.exclude_subcats.map(s=>s.toLowerCase()).some(ex => pSubcat.includes(ex))) return false;
        }
        const isExcludedCheck = (p.promotion_excluded_skus || []).some(ex => ex.sku === product.sku);
        if (isExcludedCheck) return false;

        // Check Include
        if (p.apply_to_all_skus) return true;
        if (p.apply_brand_subcats && p.apply_brand_subcats.length > 0) {
            const isMatch = p.apply_brand_subcats.some(rule => 
                (rule.brand || '').toLowerCase() === pBrand && (rule.subcat_id || '').toLowerCase() === pSubcat
            );
            if (isMatch) return true;
        }
        if (p.apply_to_brands && p.apply_to_brands.map(b=>b.toLowerCase()).includes(pBrand)) return true;
        if (p.apply_to_categories && p.apply_to_categories.map(c=>c.toLowerCase()).includes(pCategory)) return true;
        if (p.apply_to_subcats && p.apply_to_subcats.map(s=>s.toLowerCase()).includes(pSubcat)) return true;
        if ((p.promotion_skus || []).some(ps => ps.sku === product.sku)) return true;

        return false;
    });

    console.log(`[DEBUG] Bước 3: Sau khi lọc theo SKU/Branch, còn lại ${filteredPromos.length} CTKM.`);

    internalContest = filteredPromos.find(p => p.promo_type === 'Thi đua nội bộ') || null;
    const regularPromos = filteredPromos.filter(p => p.promo_type !== 'Thi đua nội bộ');

    // 4) Map tên CTKM tương thích
    if (filteredPromos.length) {
      const ids = filteredPromos.map(p => p.id);
      const { data: allows } = await supabase.from('promotion_compat_allows').select('promotion_id, with_promotion_id').in('promotion_id', ids);
      const { data: excludes } = await supabase.from('promotion_compat_excludes').select('promotion_id, with_promotion_id').in('promotion_id', ids);
      const { data: allPromosLite } = await supabase.from('promotions').select('id, name, group_name');
      const promoInfoById = Object.fromEntries((allPromosLite || []).map(p => [p.id, p]));

      filteredPromos.forEach(p => {
        const allowIds = (allows || []).filter(r => r.promotion_id === p.id).map(r => r.with_promotion_id);
        p.compat_allow_names = [...new Set(allowIds.map(id => promoInfoById[id]?.group_name).filter(Boolean))];
        const exclIds = (excludes || []).filter(r => r.promotion_id === p.id).map(r => r.with_promotion_id);
        p.compat_exclude_names = [...new Set(exclIds.map(id => promoInfoById[id]?.group_name).filter(Boolean))];
      });
    }

    // 5) Tính toán giá trị giảm
    let availablePromos = (regularPromos || []).map(p => {
        const ruleDiscount = calcDiscountAmt(p, price);
        const couponDiscount = getMaxCouponDiscount(p);
        const bestDiscount = Math.max(ruleDiscount, couponDiscount);
        return { ...p, discount_amount_calc: bestDiscount };
    });

    if (price > 0) {
        availablePromos = availablePromos.filter(p => Number(p.min_order_value || 0) <= price);
    }
    console.log(`[DEBUG] Bước 4: Sau khi lọc min_order_value, còn lại ${availablePromos.length} CTKM.`);

    // --- LOGIC GỘP NHÓM & DEBUG ---
    const bestByGroup = {};
    const listFinal = [];

    console.log("--- [DEBUG CHI TIẾT GỘP NHÓM] ---");
    for (const p of availablePromos) {
        // (Đã check isVisibleToUser ở trên rồi, nhưng check lại cho chắc nếu logic thay đổi)
        if (!isVisibleToUser(p)) continue;

        const groupKey = p.group_name || `__no_group_${p.id}__`;
        const discountVal = p.discount_amount_calc || 0;

        console.log(` >> Xét CTKM ID:${p.id} | Tên: ${p.name} | Nhóm: ${p.group_name} | Giảm: ${discountVal}`);
        console.log(`    Option 'Show Multiple': ${p.show_multiple_in_group}`);

        if (p.show_multiple_in_group) {
            listFinal.push(p);
            console.log(`    => ✅ LẤY LUÔN (Do có tick hiển thị cùng nhóm)`);
        } else {
            if (!bestByGroup[groupKey]) {
                bestByGroup[groupKey] = p;
                console.log(`    => 🔵 Tạm giữ (Là CTKM đầu tiên của nhóm này)`);
            } else {
                const currentBest = bestByGroup[groupKey];
                if (discountVal > currentBest.discount_amount_calc) {
                    console.log(`    => 🟢 Thay thế CTKM ID:${currentBest.id} (Vì giảm ${discountVal} > ${currentBest.discount_amount_calc})`);
                    bestByGroup[groupKey] = p;
                } else {
                    console.log(`    => 🔴 Bỏ qua (Thua CTKM ID:${currentBest.id} đang giữ)`);
                }
            }
        }
    }

    Object.values(bestByGroup).forEach(p => {
        listFinal.push(p);
    });
    console.log("-----------------------------------");

    // Gán vào biến promotions để render
    promotions = listFinal.sort((a, b) => b.discount_amount_calc - a.discount_amount_calc);
    
    // Tính toán Stackable (cộng dồn)
    chosenPromos = pickStackable(promotions);
    totalDiscount = chosenPromos.reduce((s, p) => s + Number(p.discount_amount_calc || 0), 0);
    finalPrice = Math.max(0, price - totalDiscount);

    try {
      const cmp = await supabase.from('price_comparisons').select('*', { count: 'exact', head: true }).eq('sku', product.sku);
      comparisonCount = cmp?.count || 0;
    } catch { }

    console.log(`--- [DEBUG] KẾT THÚC TÌM KIẾM ---`);

    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion',
      query: skuInput, product, promotions,
      internalContest, chosenPromos, totalDiscount, finalPrice, comparisonCount, error: null,
      inventoryCounts, inventoryMap, userBranch, isGlobalAdmin, oldestSerials,
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });

  } catch (error) {
    console.error('SEARCH PROMO ERROR:', error);
    // Sửa lỗi 2: Render lỗi nhưng vẫn truyền đủ biến (dù là null) để tránh ReferenceError
    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion', query: skuInput,
      product: null, promotions: [], totalDiscount: 0, finalPrice: 0, comparisonCount: 0,
      error: 'Lỗi hệ thống: ' + (error?.message || String(error)),
      internalContest: null, chosenPromos: [],
      inventoryCounts: null, // Truyền null thay vì undefined
      inventoryMap: null, 
      userBranch: req.session?.user?.branch_code || null,
      isGlobalAdmin: false, 
      oldestSerials: [],
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

    // === BƯỚC MỚI: LẤY TỒN KHO BIGQUERY CHO TẤT CẢ SKU LIÊN QUAN ===
let inventoryMap = new Map(); // Sẽ là Map<SKU, Map<Branch, Counts>>
let allBranchNames = []; // Sẽ chứa các cột chi nhánh (cho admin)
let isGlobalAdmin = false;

const userBranch = req.session.user?.branch_code || null;
const userRole = req.session.user?.role || null;

try {
    const today = new Date().toISOString().split('T')[0];
    isGlobalAdmin = (userRole === 'admin' || userBranch === 'HCM.BD');

    if (userBranch && bigquery && allCodes.length > 0) {
        // Truyền cờ isGlobalAdmin
        inventoryMap = await getInventoryCounts(allCodes, userBranch, isGlobalAdmin, today);

        // Nếu là admin, tạo danh sách các cột chi nhánh để hiển thị
        if (isGlobalAdmin) {
            const branchSet = new Set();
            inventoryMap.forEach(branchMap => {
                branchMap.forEach((counts, branchId) => {
                    branchSet.add(branchId);
                });
            });
            allBranchNames = [...branchSet].sort(); // Lấy list branchs có tồn
        }
    }
} catch (e) {
    console.error("Lỗi khi lấy tồn kho cho /promotion-detail:", e.message);
}
// === KẾT THÚC BƯỚC MỚI ===


    const includedSkuDetails = includedCodes.map(code => ({
      sku: code,
      product_name: skuMetaByCode[code]?.product_name || '',
      brand: skuMetaByCode[code]?.brand || '',
      list_price: skuMetaByCode[code]?.list_price ?? null,
      inventory: inventoryMap.get(code) || null, // SỬA: Giờ đây 'inventory' là Map<Branch, Counts>
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
      currentUser, 
      userBranch: userBranch,              // truyền cho view biết vai trò
      isGlobalAdmin: isGlobalAdmin, // <-- DÒNG MỚI
  allBranchNames: allBranchNames, // <-- DÒNG MỚI (list các cột branch cho admin)
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

// [MỚI] Route Tạo CTKM (Đã bao gồm Branch, Exclude Mở Rộng, Show Multiple)
app.post('/create-promotion', requireAuth, async (req, res) => {
    try {
        const {
            name, description, start_date, end_date, channel, promo_type, coupon_code,
            group_name, apply_to_type, apply_brands, apply_categories, apply_subcats,
            skus, excluded_skus, has_coupon_list, coupons, detail
        } = req.body;

        const apply_with = req.body['apply_with[]'];
        const exclude_with = req.body['exclude_with[]'];

        // --- HELPER ---
        const parseList = (str) => String(str || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
        const uniq = arr => [...new Set(arr)];
        const parseSkus = (v) => { // Helper parse SKU cũ của bạn
            if (!v) return [];
            if (Array.isArray(v)) return v.flatMap(x => String(x).split(/[,\n\r\s]+/)).map(s=>s.trim()).filter(Boolean);
            return String(v).split(/[,\n\r\s]+/).map(s=>s.trim()).filter(Boolean);
        };

        // Xử lý giá trị giảm
        const discount_value_type = req.body.discount_value_type || null;
        let discount_value = null;
        if (discount_value_type === 'amount') discount_value = Number(req.body.discount_amount) || 0;
        else if (discount_value_type === 'percent') discount_value = Number(req.body.discount_percent) || 0;
        const max_discount_amount = req.body.max_discount_amount ? Number(req.body.max_discount_amount) : null;
        const min_order_value = req.body.min_order_value ? Number(req.body.min_order_value) : 0;

        // Xử lý Coupon List
        let couponListData = null;
        if (has_coupon_list && coupons) {
            const list = Array.isArray(coupons) ? coupons : Object.values(coupons);
            couponListData = list.filter(c => c && c.code && String(c.code).trim() !== '').map(c => {
                const raw = c.discount;
                const discount = typeof raw === 'number' ? raw : (raw == null || raw === '' ? null : (parseFloat(String(raw).replace(/[^0-9]/g, '')) || 0));
                return { name: (c.name || '').trim(), code: String(c.code).trim(), discount, note: (c.note || '').trim() };
            });
            couponListData.sort((a, b) => (a.code || '').localeCompare(b.code || '') || (a.name || '').localeCompare(b.name || ''));
            if (!couponListData.length) couponListData = null;
        }

        // Xử lý Brand + Subcat
        const apply_brand_subcats_list = (apply_to_type === 'brand_subcat') ? (() => {
            const brands = uniq(parseSkus(apply_brands));
            const subcats = uniq(parseSkus(apply_subcats));
            const bs = [];
            brands.forEach(b => subcats.forEach(s => bs.push({ brand: String(b), subcat_id: String(s) })));
            return bs.length ? bs : null;
        })() : null;

        // [MỚI] Xử lý apply_branches
        let branchesInput = req.body['apply_branches[]'] || req.body.apply_branches;
        const applyBranches = branchesInput ? (Array.isArray(branchesInput) ? branchesInput : [branchesInput]) : null;

        const insertPayload = {
            name, description, start_date, end_date, group_name, 
            channel: channel || 'All', promo_type, coupon_code: coupon_code || null, status: 'active',
            apply_to_all_skus: apply_to_type === 'all',
            apply_to_brands: apply_to_type === 'brand' ? uniq(parseSkus(apply_brands)) : null,
            apply_to_categories: apply_to_type === 'category' ? uniq(parseSkus(apply_categories)) : null,
            apply_to_subcats: apply_to_type === 'subcat' ? uniq(parseSkus(apply_subcats)) : null,
            apply_brand_subcats: apply_brand_subcats_list,
            coupon_list: couponListData,
            created_by: req.session.user?.id,
            detail_fields: detail || {},
            discount_value_type, discount_value, max_discount_amount, min_order_value,

            // --- CÁC TRƯỜNG MỚI ---
            show_multiple_in_group: req.body.show_multiple_in_group === 'on',
            apply_branches: applyBranches,
            exclude_brands: uniq(parseList(req.body.exclude_brands)),
            exclude_subcats: uniq(parseList(req.body.exclude_subcats)),
        };

        const { data: promotion, error } = await supabase.from('promotions').insert([insertPayload]).select('id').single();
        if (error) throw error;
        const newPromoId = promotion.id;

        // Insert SKU Include/Exclude
        if (apply_to_type === 'sku') {
            const includeList = [...new Set(parseSkus(skus))];
            if (includeList.length > 0) await supabase.from('promotion_skus').insert(includeList.map(sku => ({ promotion_id: newPromoId, sku })));
        }
        const excludeList = [...new Set(parseSkus(excluded_skus))];
        if (excludeList.length > 0) await supabase.from('promotion_excluded_skus').insert(excludeList.map(sku => ({ promotion_id: newPromoId, sku })));

        // Insert Brand+Subcat
        if (apply_brand_subcats_list && apply_brand_subcats_list.length > 0) {
            await supabase.from('promotion_brand_subcats').insert(apply_brand_subcats_list.map(p => ({ promotion_id: newPromoId, brand: p.brand, subcat_id: p.subcat_id })));
        }

        // Insert Compat
        if (apply_with && Array.isArray(apply_with) && apply_with.length > 0) await supabase.from('promotion_compat_allows').insert(apply_with.map(pid => ({ promotion_id: newPromoId, with_promotion_id: pid })));
        if (exclude_with && Array.isArray(exclude_with) && exclude_with.length > 0) await supabase.from('promotion_compat_excludes').insert(exclude_with.map(pid => ({ promotion_id: newPromoId, with_promotion_id: pid })));

        // Log History
        await supabase.from('promotion_revisions').insert({ promotion_id: newPromoId, user_id: req.session.user?.id || null, action: 'create', snapshot: insertPayload });

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

// [MỚI] Route Sửa CTKM (Đã bao gồm Branch, Exclude Mở Rộng, Show Multiple)
app.post('/edit-promotion/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  // Helpers
  const parseList = (str) => String(str || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
  const parseSkus = (v) => { if (!v) return []; if (Array.isArray(v)) return v.flatMap(x => String(x).split(/[,\n\r\s]+/)).map(s=>s.trim()).filter(Boolean); return String(v).split(/[,\n\r\s]+/).map(s=>s.trim()).filter(Boolean); };
  const uniq = arr => Array.from(new Set((arr || []).filter(v => v !== '' && v != null)));
  const sortStr = arr => uniq(arr).sort((a, b) => String(a).localeCompare(String(b)));
  const sortNum = arr => uniq(arr.map(Number)).sort((a, b) => a - b);
  const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const sameArr = (a, b) => JSON.stringify(sortStr(a || [])) === JSON.stringify(sortStr(b || []));
  const sameArrNum = (a, b) => JSON.stringify(sortNum(a || [])) === JSON.stringify(sortNum(b || []));
  const parseToArray = v => Array.isArray(v) ? v : (v==null || v==='' ? [] : [v]);

  try {
    if (!id) throw new Error('Thiếu promotion id');

    // 1. Lấy dữ liệu CŨ
    const { data: oldPromotion, error: eOld } = await supabase.from('promotions').select('*').eq('id', id).single();
    if (eOld || !oldPromotion) throw new Error('Không tìm thấy CTKM để cập nhật.');

    const [oldSkusIncRes, oldSkusExcRes, oldAllowRes, oldExclRes, oldBrandSubRes] = await Promise.all([
      supabase.from('promotion_skus').select('sku').eq('promotion_id', id),
      supabase.from('promotion_excluded_skus').select('sku').eq('promotion_id', id),
      supabase.from('promotion_compat_allows').select('with_promotion_id').eq('promotion_id', id),
      supabase.from('promotion_compat_excludes').select('with_promotion_id').eq('promotion_id', id),
      supabase.from('promotion_brand_subcats').select('brand, subcat_id').eq('promotion_id', id)
    ]);

    const oldSkusInc = (oldSkusIncRes.data || []).map(r => String(r.sku));
    const oldSkusExc = (oldSkusExcRes.data || []).map(r => String(r.sku));
    const oldAllows = (oldAllowRes.data || []).map(r => Number(r.with_promotion_id));
    const oldExcls = (oldExclRes.data || []).map(r => Number(r.with_promotion_id));
    const oldBrandSub = (oldBrandSubRes.data || []).map(r => ({ brand: String(r.brand), subcat_id: String(r.subcat_id) }));

    // 2. Lấy dữ liệu MỚI
    const {
      name, description, start_date, end_date, channel, promo_type, coupon_code,
      group_name, apply_to_type, apply_brands, apply_categories, apply_subcats,
      skus, excluded_skus, has_coupon_list, coupons, detail
    } = req.body;

    const apply_with = parseToArray(req.body.apply_with);
    const exclude_with = parseToArray(req.body.exclude_with);

    // [MỚI] Xử lý Chi nhánh
    let branchesInput = req.body['apply_branches[]'] || req.body.apply_branches;
    const applyBranches = branchesInput ? (Array.isArray(branchesInput) ? branchesInput : [branchesInput]) : null;

    // Xử lý Coupon
    let couponListData = null;
    if (has_coupon_list && coupons) {
      const list = Array.isArray(coupons) ? coupons : Object.values(coupons);
      couponListData = list.filter(c => c && c.code && String(c.code).trim() !== '').map(c => {
          const raw = c.discount;
          const discount = typeof raw === 'number' ? raw : (raw == null || raw === '' ? null : (parseFloat(String(raw).replace(/[^0-9]/g, '')) || 0));
          return { name: (c.name || '').trim(), code: String(c.code).trim(), discount, note: (c.note || '').trim() };
        });
      couponListData.sort((a, b) => (a.code || '').localeCompare(b.code || '') || (a.name || '').localeCompare(b.name || ''));
      if (!couponListData.length) couponListData = null;
    }

    // Xử lý giá trị giảm (Đảm bảo không mất khi sửa)
    const discount_value_type = req.body.discount_value_type || null;
    let discount_value = null;
    if (discount_value_type === 'amount') discount_value = Number(req.body.discount_amount) || 0;
    else if (discount_value_type === 'percent') discount_value = Number(req.body.discount_percent) || 0;
    const max_discount_amount = req.body.max_discount_amount ? Number(req.body.max_discount_amount) : null;
    const min_order_value = req.body.min_order_value ? Number(req.body.min_order_value) : 0;


    // 3. Chuẩn bị payload UPDATE
    const updatePayload = {
      name, description, start_date, end_date, group_name,
      channel: channel || 'ALL', promo_type, coupon_code: coupon_code || null,
      coupon_list: couponListData, detail_fields: detail || {},
      
      // --- CÁC TRƯỜNG MỚI ---
      show_multiple_in_group: req.body.show_multiple_in_group === 'on',
      apply_branches: applyBranches,
      exclude_brands: uniq(parseList(req.body.exclude_brands)),
      exclude_subcats: uniq(parseList(req.body.exclude_subcats)),
      // ---------------------

      apply_to_all_skus: apply_to_type === 'all',
      apply_to_brands: apply_to_type === 'brand' ? uniq(parseSkus(apply_brands)) : null,
      apply_to_categories: apply_to_type === 'category' ? uniq(parseSkus(apply_categories)) : null,
      apply_to_subcats: apply_to_type === 'subcat' ? uniq(parseSkus(apply_subcats)) : null,
      
      apply_brand_subcats: apply_to_type === 'brand_subcat' ? (() => {
          const bs = [];
          uniq(parseSkus(apply_brands)).forEach(b => uniq(parseSkus(apply_subcats)).forEach(s => bs.push({ brand: String(b), subcat_id: String(s) })));
          return bs.length ? bs : null;
        })() : null,

      // Update giá trị giảm
      discount_value_type, discount_value, max_discount_amount, min_order_value,
      updated_at: new Date().toISOString()
    };

    // 4. Tính toán bảng phụ MỚI
    const newSkusInc = uniq(parseSkus(skus));
    const newSkusExc = uniq(parseSkus(excluded_skus));
    const newAllows = sortNum(apply_with);
    const newExcls = sortNum(exclude_with);
    const newBrandSub = updatePayload.apply_brand_subcats ? updatePayload.apply_brand_subcats.map(x => ({ brand: x.brand, subcat_id: x.subcat_id })) : [];

    // 5. Tạo DIFF (Lịch sử)
    const diff = {};
    const compareKeys = [
      'name', 'description', 'start_date', 'end_date', 'channel', 'promo_type', 'coupon_code', 'group_name',
      'apply_to_all_skus', 'apply_to_brands', 'apply_to_categories', 'apply_to_subcats', 'apply_brand_subcats', 'detail_fields', 'coupon_list',
      'discount_value_type', 'discount_value', 'max_discount_amount', 'min_order_value',
      // Keys mới
      'show_multiple_in_group', 'apply_branches', 'exclude_brands', 'exclude_subcats'
    ];

    if (String(oldPromotion.apply_to_type || '') !== String(apply_to_type || '')) diff.apply_to_type = { from: oldPromotion.apply_to_type, to: apply_to_type };

    compareKeys.forEach(k => {
      const oldVal = oldPromotion[k];
      const newVal = updatePayload[k];
      if (Array.isArray(oldVal) || Array.isArray(newVal)) {
        const norm = v => Array.isArray(v) ? v.slice() : (v == null ? [] : [v]);
        const o = norm(oldVal); const n = norm(newVal);
        if (k === 'apply_brand_subcats') {
          const sortPairs = arr => (arr || []).map(x => ({ brand: String(x.brand), subcat_id: String(x.subcat_id) })).sort((a, b) => a.brand.localeCompare(b.brand) || a.subcat_id.localeCompare(b.subcat_id));
          if (JSON.stringify(sortPairs(o)) !== JSON.stringify(sortPairs(n))) diff[k] = { from: o, to: n };
        } else {
          if (JSON.stringify(sortStr(o)) !== JSON.stringify(sortStr(n))) diff[k] = { from: o, to: n };
        }
      } else {
        if (!sameJson(oldVal, newVal)) diff[k] = { from: oldVal, to: newVal };
      }
    });

    if (!sameArr(oldSkusInc, newSkusInc)) diff.sku_includes = { from: sortStr(oldSkusInc), to: sortStr(newSkusInc) };
    if (!sameArr(oldSkusExc, newSkusExc)) diff.sku_excludes = { from: sortStr(oldSkusExc), to: sortStr(newSkusExc) };
    if (!sameArrNum(oldAllows, newAllows)) diff.compat_allows = { from: sortNum(oldAllows), to: sortNum(newAllows) };
    if (!sameArrNum(oldExcls, newExcls)) diff.compat_excludes = { from: sortNum(oldExcls), to: sortNum(newExcls) };
    const sortPairs = arr => (arr || []).map(x => ({ brand: String(x.brand), subcat_id: String(x.subcat_id) })).sort((a, b) => a.brand.localeCompare(b.brand) || a.subcat_id.localeCompare(b.subcat_id));
    if (JSON.stringify(sortPairs(oldBrandSub)) !== JSON.stringify(sortPairs(newBrandSub))) diff.brand_subcats_map = { from: sortPairs(oldBrandSub), to: sortPairs(newBrandSub) };

    // 6. Thực hiện UPDATE DB
    const { error: promoUpdateError } = await supabase.from('promotions').update(updatePayload).eq('id', id);
    if (promoUpdateError) throw promoUpdateError;

    // Cập nhật bảng phụ
    await supabase.from('promotion_skus').delete().eq('promotion_id', id);
    if (newSkusInc.length) await supabase.from('promotion_skus').insert(newSkusInc.map(sku => ({ promotion_id: id, sku })));

    await supabase.from('promotion_excluded_skus').delete().eq('promotion_id', id);
    if (newSkusExc.length) await supabase.from('promotion_excluded_skus').insert(newSkusExc.map(sku => ({ promotion_id: id, sku })));

    await supabase.from('promotion_compat_allows').delete().eq('promotion_id', id);
    if (newAllows.length) await supabase.from('promotion_compat_allows').insert(newAllows.map(pid => ({ promotion_id: id, with_promotion_id: pid })));

    await supabase.from('promotion_compat_excludes').delete().eq('promotion_id', id);
    if (newExcls.length) await supabase.from('promotion_compat_excludes').insert(newExcls.map(pid => ({ promotion_id: id, with_promotion_id: pid })));

    await supabase.from('promotion_brand_subcats').delete().eq('promotion_id', id);
    if (newBrandSub.length) await supabase.from('promotion_brand_subcats').insert(newBrandSub.map(p => ({ promotion_id: id, brand: p.brand, subcat_id: p.subcat_id })));

    // 7. Ghi lịch sử
    if (Object.keys(diff).length > 0) {
      await supabase.from('promotion_revisions').insert({
        promotion_id: id, user_id: req.session.user?.id || null, action: 'update', diff, snapshot: { ...oldPromotion, ...updatePayload }
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


// (TRONG server.js)

// --- (SỬA LẠI) Cấu hình Sheet Thanh Lý ---
const CLEARANCE_SHEET_ID = '1uvSNw6PL46896rOo0PIf67hP3BCmR6WnoR1zhthU_ts'; 
const CLEARANCE_SHEET_TAB = 'Sheet1'; // Tên Tab bạn đã cung cấp


async function getClearanceInfoFromSheet(sku) {
  try {
    const sheets = await getGlobalSheetsClient();
    const range = `${CLEARANCE_SHEET_TAB}!A2:Y`; // Đọc từ A2 để bỏ qua Header nếu cần, hoặc xử lý mảng
    
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: CLEARANCE_SHEET_ID,
      range: range,
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) return null;

    const results = [];
    // Duyệt qua các dòng
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      // Cột F (index 5) là SKU. So sánh chuỗi.
      if (row[5] && String(row[5]).trim() === String(sku).trim()) {
        const images = (row[24] || '').split(',').map(link => link.trim()).filter(Boolean);
        
        results.push({
          store_name: row[2] || 'N/A',
          serial: row[8] || 'N/A',
          images: images,
          warranty_end: row[10] || 'N/A',
          clearance_price: row[14] || '0',
          kfi: row[17] || 'N/A',
          tinh_trang: row[18] || 'Không có mô tả',
        });
      }
    }
    return (results.length > 0) ? results : null;

  } catch (err) {
    console.error(`[Google Sheets] Lỗi đọc chi tiết: ${err.message}`);
    return null;
  }
}


async function getAllClearanceItems(isSyncMode = false) {
  try {
    const sheets = await getGlobalSheetsClient();
    const range = `${CLEARANCE_SHEET_TAB}!A:Y`; 
    const response = await sheets.spreadsheets.values.get({ spreadsheetId: CLEARANCE_SHEET_ID, range });
    let rows = response.data.values;
    if (!rows || rows.length === 0) return [];

    const results = rows.map(row => {
      const skuVal = String(row[5] || '').trim();
      if (!skuVal || skuVal.toUpperCase().includes('SKU') || skuVal.includes('Timeline')) return null;

      const rawPriceString = row[14] || '0';
      const priceNumber = parseFloat(String(rawPriceString).replace(/[^0-9]/g, '')) || 0;
      const images = (row[24] || '').split(',').map(link => link.trim()).filter(Boolean);

      // Object trả về khớp với cột trong Supabase 'clearance_items'
      return {
        store_name: row[2] || 'N/A',
        category: row[4] || 'Khác',
        sku: skuVal,
        product_name: row[6] || 'Sản phẩm chưa có tên',
        serial: row[8] || 'N/A',
        price_raw: priceNumber,
        price_display: new Intl.NumberFormat('vi-VN').format(priceNumber),
        warranty_end: row[10] || 'N/A',
        kfi: row[17] || 'N/A',
        condition: row[18] || '', // Tình trạng
        images: images
      };
    }).filter(item => item !== null);

    return results;
  } catch (err) {
    console.error(`[Google Sheets] Lỗi lấy danh sách: ${err.message}`);
    return [];
  }
}


app.all('/clearance-check', requireAuth, async (req, res) => {
  const skuInput = (req.method === 'POST' ? req.body?.sku : req.query?.sku) || '';
  
  let allItems = [];
  let clearanceInfo = null; 

  try {
      // --- FETCH ALL DATA (VÒNG LẶP LẤY HẾT > 1000 DÒNG) ---
      let hasMore = true;
      let from = 0;
      const step = 1000; // Lấy mỗi lần 1000 dòng

      while (hasMore) {
          const { data: dbItems, error } = await supabase
              .from('clearance_items')
              .select('*')
              .order('price_raw', { ascending: true })
              .range(from, from + step - 1); // Range từ 0-999, 1000-1999...
          
          if (error) {
              console.error("Lỗi fetch Supabase:", error);
              break;
          }

          if (dbItems && dbItems.length > 0) {
              // [FIX] Map dữ liệu khớp với EJS
              const mappedItems = dbItems.map(item => ({
                  ...item,
                  // 1. Map 'condition' trong DB sang 'tinh_trang' cho EJS
                  tinh_trang: item.condition || 'Chưa cập nhật', 
                  clearance_price: item.price_raw || 0,
                  // 2. Xử lý hiển thị giá an toàn
                  priceDisplay: item.price_display 
                      ? item.price_display 
                      : new Intl.NumberFormat('vi-VN').format(item.price_raw || 0) + ' ₫',
                  
                  store_name: item.store_name,
                  product_name: item.product_name
              }));
              
              allItems = allItems.concat(mappedItems);
              
              if (dbItems.length < step) hasMore = false;
              else from += step;
          }
          else {
              hasMore = false;
          }
      }
      
      console.log(`[DEBUG] Đã tải tổng cộng ${allItems.length} sản phẩm thanh lý.`);
// 2. Nếu có SKU input, lọc chi tiết
      if (skuInput) {
          clearanceInfo = allItems.filter(item => item.sku === skuInput);
          
          const userBranch = req.session.user?.branch_code;
          const isGlobalAdmin = (req.session.user?.role === 'admin' || userBranch === 'HCM.BD');
          const today = new Date().toISOString().split('T')[0];

          const [productRes, inventoryMap] = await Promise.all([
              supabase.from('skus').select('*').eq('sku', skuInput).single(),
              getInventoryCounts([skuInput], userBranch, isGlobalAdmin, today)
          ]);

          const product = productRes.data;
          const inventoryCounts = inventoryMap.get(skuInput)?.get(userBranch);

           return res.render('clearance-check', {
              title: `Thanh lý: ${skuInput}`,
              currentPage: 'clearance-check',
              product, inventoryMap, inventoryCounts, isGlobalAdmin, userBranch,
              clearanceInfo, 
              allClearanceItems: allItems,
              error: null
          });
      }

  } catch (e) {
      console.error("Lỗi Clearance Check:", e);
  }

  res.render('clearance-check', { 
      title: 'Tra cứu hàng thanh lý', 
      currentPage: 'clearance-check', 
      error: null, product: null, clearanceInfo: null,
      allClearanceItems: allItems 
  });
});


// (THÊM HÀM NÀY VÀO server.js)
async function getEventStockByBranch(branchCode) {
  if (!bigquery) {
    console.warn("BigQuery chưa cấu hình, không thể lấy tồn kho Event.");
    return [];
  }
  
  // Lấy tồn kho tại BIN MKT của chi nhánh này
  const query = `
    SELECT
      CAST(SKU AS STRING) AS sku,
      MAX(SKU_name) AS sku_name,
      MAX(Brand) AS brand,
      COUNT(Serial) AS stock_qty
    FROM \`nimble-volt-459313-b8.Inventory.inv_seri_1\`
    WHERE Branch_ID = @branchCode
      AND BIN_zone = 'Hàng MKT' -- Chỉ lấy BIN MKT
      AND Serial IS NOT NULL AND Serial != ''
    GROUP BY 1
    ORDER BY stock_qty DESC
  `;

  try {
    const [rows] = await bigquery.query({
      query,
      params: { branchCode }
    });
    return rows;
  } catch (e) {
    console.error(`[Event Stock] Lỗi BQ: ${e.message}`);
    return [];
  }
}

// (THÊM ROUTE NÀY VÀO server.js)
app.get('/event-operations', requireAuth, async (req, res) => {
  const userBranch = req.session.user?.branch_code;
  
  // Kiểm tra xem chi nhánh có đang chạy Event không
  const { data: eventStatus } = await supabase
    .from('branch_event_status')
    .select('is_event_active, event_name')
    .eq('branch_code', userBranch)
    .single();
  
  let eventStock = [];
  if (eventStatus && eventStatus.is_event_active) {
    // Nếu có, tải tồn kho BIN MKT
    eventStock = await getEventStockByBranch(userBranch);
  }

  res.render('event-operations', {
    title: 'Vận hành Event',
    currentPage: 'event-operations',
    eventStatus: eventStatus, // { is_event_active, event_name }
    eventStock: eventStock // Danh sách tồn kho BIN MKT
  });
});

// HÀM MỚI 1: Tạo client Google Sheets
async function getGlobalSheetsClient() {
  const { data: tok, error } = await supabase
    .from('app_google_tokens')
    .select('*')
    .eq('id', 'global')
    .single();

  if (error || !tok || !tok.refresh_token) {
    throw new Error('Google Sheets/Drive chung chưa được kết nối (vào /google/drive/connect)');
  }

  const oauth2 = getOAuthClient();
  oauth2.setCredentials({
    access_token: tok.access_token || undefined,
    refresh_token: tok.refresh_token || undefined,
    expiry_date: tok.expiry_date || undefined,
    scope: tok.scope || undefined,
    token_type: tok.token_type || undefined,
  });

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

  return google.sheets({ version: 'v4', auth: oauth2 });
}   

// HÀM MỚI 2: Tra cứu thông tin nhân sự từ Google Sheet
async function getUserAccessInfo(email) {
  const emailToFind = email.toLowerCase().trim();
  const sheetId = process.env.GOOGLE_SHEET_ID_NHANSU;
  const range = 'Sheet1!A:G'; // Lấy từ cột A (Email) đến cột G (End Date)

  if (!sheetId) {
    throw new Error('Chưa cấu hình GOOGLE_SHEET_ID_NHANSU trong .env');
  }

  try {
    const sheets = await getGlobalSheetsClient();
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: sheetId,
      range: range,
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) {
      console.warn(`[Auth] Không tìm thấy dữ liệu nào trong Google Sheet.`);
      return null;
    }

    // Bỏ qua header, tìm email (Cột A = 0), lấy Branch (Cột D = 3), End Date (Cột G = 6)
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      const rowEmail = (row[1] || '').toLowerCase().trim();
      
      if (rowEmail === emailToFind) {
        // Đã tìm thấy!
        return {
          email: rowEmail,
          name: row[2] || '', // Cột C (name)
          branch_id: (row[3] || 'DEFAULT').trim(), // Cột D (branch_id)
          end_date: row[6] || '99991231' // Cột G (end_date)
        };
      }
    }

    // Không tìm thấy email
    return null;

  } catch (err) {
    console.error(`[Auth] Lỗi API Google Sheets: ${err.message}`);
    throw new Error(`Lỗi khi tra cứu Google Sheets: ${err.message}`);
  }
}



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

// (TRONG server.js)
// API TÍNH SỐ LƯỢNG RÁP ĐƯỢC (ĐÃ SỬA LẠI HOÀN CHỈNH)
app.get('/api/utils/bom/by-final', requireAuth, async (req, res) => {
  try {
    const sku = (req.query.sku || '').trim();
    if (!sku) {
      return res.status(400).json({ ok: false, error: 'Thiếu SKU thành phẩm' });
    }

    // 1. Lấy thông tin User (Phân quyền)
    const userBranch = req.session.user?.branch_code;
    const isGlobalAdmin = (req.session.user?.role === 'admin' || userBranch === 'HCM.BD');
    const today = new Date().toISOString().split('T')[0];

    // 2. Lấy danh sách linh kiện cần thiết từ BOM
    const { data: parts, error: e1 } = await supabase
      .from('bom_relations')
      .select('component_sku, component_name, qty_per, final_name')
      .eq('final_sku', sku);
    if (e1) throw e1;

    if (!parts || !parts.length) {
      return res.json({ 
        ok: true, 
        final: { sku, name: 'Không tìm thấy BOM' }, 
        buildableByBranch: [] 
      });
    }

    const finalName = parts[0]?.final_name || sku;
    const compSkus = Array.from(new Set(parts.map(p => p.component_sku)));

    // 3. Lấy tồn kho BigQuery cho TẤT CẢ linh kiện
    // Hàm getInventoryCounts đã xử lý phân quyền (isGlobalAdmin hay userBranch)
    const inventoryMap = await getInventoryCounts(compSkus, userBranch, isGlobalAdmin, today);

    // 4. Xác định các chi nhánh cần tính toán
    const branchesToProcess = isGlobalAdmin 
        ? ( () => {
              const allBranches = new Set();
              inventoryMap.forEach(branchMap => { // Map<SKU, Map<Branch, Counts>>
                branchMap.forEach((counts, branchId) => allBranches.add(branchId));
              });
              // Nếu admin, nhưng không có tồn kho ở đâu, hiển thị chi nhánh của admin
              if (allBranches.size === 0) return [userBranch]; 
              return [...allBranches].sort();
            })()
        : [userBranch]; // User thường chỉ thấy chi nhánh của mình

    // 5. Tính toán số lượng có thể ráp
    const branchResults = new Map();
    
    // Khởi tạo kết quả
    branchesToProcess.forEach(br => {
      branchResults.set(br, { 
        buildable: Infinity, // Bắt đầu với vô cực
        bottleneck: null,    // SKU gây nghẽn
        components: []       // Chi tiết tính toán
      });
    });

    // Duyệt qua TỪNG LINH KIỆN (parts)
    for (const part of parts) {
      const compSku = part.component_sku;
      const needQty = Number(part.qty_per || 1);
      
      const stockMapForSku = inventoryMap.get(compSku); // Map<Branch, Counts>
      
      // Duyệt qua TỪNG CHI NHÁNH (branches)
      for (const branch of branchesToProcess) {
        const branchCalc = branchResults.get(branch);
        
        const counts = stockMapForSku?.get(branch);
        // Chỉ tính "Hàng bán mới" (bao gồm Trưng bày và Lưu kho)
        const haveQty = counts?.hang_ban_moi || 0;
        
        const canBuild = Math.floor(haveQty / needQty);
        
        // Thêm chi tiết linh kiện
        branchCalc.components.push({
          sku: compSku,
          name: part.component_name || 'N/A',
          need: needQty,
          have: haveQty,
          can_build_this: canBuild
        });

        // Kiểm tra xem linh kiện này có phải là "nút thắt" mới không
        if (canBuild < branchCalc.buildable) {
          branchCalc.buildable = canBuild;
          branchCalc.bottleneck = compSku; // Ghi nhận SKU gây nghẽn
        }
      }
    }
    
    // 6. Chuyển Map thành Array để trả về JSON
    const buildableByBranch = [];
    branchResults.forEach((data, branch) => {
      // Nếu buildable vẫn là Infinity (do không có linh kiện nào), set về 0
      if (data.buildable === Infinity) data.buildable = 0;
      buildableByBranch.push({ branch, ...data });
    });

    // Sắp xếp theo số lượng ráp được (Req 2)
    buildableByBranch.sort((a, b) => b.buildable - a.buildable);

    res.json({
      ok: true,
      final: { sku, name: finalName },
      buildableByBranch: buildableByBranch
    });

  } catch (e) {
    console.error('Lỗi /api/utils/bom/by-final:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// (TRONG server.js)
// API TÌM PCPV BẰNG LINH KIỆN (ĐÃ SỬA)
app.get('/api/utils/bom/by-component', async (req, res) => {
  try {
    const comp = (req.query.sku || '').trim();
    if (!comp) {
      return res.status(400).json({ ok: false, error: 'Thiếu SKU linh kiện' });
    }

    // 1. Tìm tất cả các PCPV (final_sku) có dùng linh kiện này
    const { data: finals, error: e1 } = await supabase
      .from('bom_relations')
      .select('final_sku, final_name')
      .eq('component_sku', comp);
    if (e1) throw e1;

    // Lọc duy nhất
    const uniqFinals = Array.from(
      new Map(
        finals.map(f => [f.final_sku, { sku: f.final_sku, name: f.final_name }])
      ).values()
    );
    
    // 2. Trả về danh sách PCPV
    // (Chúng ta sẽ không tính toán tồn kho ở đây, vì nó quá nặng)
    // (User sẽ bấm vào 1 trong các PCPV này để gọi API 'by-final' ở trên)
    res.json({ 
      ok: true, 
      component: comp, 
      results: uniqFinals 
    });

  } catch (e) {
    console.error('Lỗi /api/utils/bom/by-component:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// (TRONG server.js)

// Route mới để render trang Check BOM
app.get('/bom-check', requireAuth, (req, res) => {
  res.render('bom-check', {
    title: 'Kiểm tra BOM PCPV',
    currentPage: 'pc-builder', // Giữ cho menu "Tiện ích" sáng lên
    time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    // Biến 'user' sẽ tự động được truyền vào từ middleware
  });
});

// (TRONG server.js)

// Route TỔNG HỢP (Dashboard) - BẢN CUỐI (Thêm Filter Type)
app.get('/bom-dashboard', requireAuth, async (req, res) => {
  try {
    // === (MỚI) Thêm Search Query + Filter Type ===
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const pageSize = 20; // 20 PCPV mỗi trang
    const searchQuery = (req.query.q || '').trim().toLowerCase(); // Lấy query 'q'
    const filterType = (req.query.type || '').trim(); // Lấy query 'type' (vanphong, gaming)
    
    // --- A. Lấy thông tin User (Phân quyền) ---
    const userBranch = req.session.user?.branch_code;
    const isGlobalAdmin = (req.session.user?.role === 'admin' || userBranch === 'HCM.BD');
    const today = new Date().toISOString().split('T')[0];

    // --- B. Lấy danh sách PCPV từ BigQuery (ĐÃ SỬA: Thêm bqFilterClause) ---
    
    // (MỚI) Xác định điều kiện lọc cho BigQuery
    let bqFilterClause = "WHERE SubCategory_name LIKE 'Máy tính bộ Phong Vũ%'"; // Mặc định (Tất cả)
    if (filterType === 'vanphong') {
      bqFilterClause = "WHERE SubCategory_name LIKE 'Máy tính bộ Phong Vũ văn phòng%'";
    } else if (filterType === 'gaming') {
      bqFilterClause = "WHERE SubCategory_name LIKE 'Máy tính bộ Phong Vũ gaming%'";
    }

    const bqPcpvQuery = `
      SELECT
        DISTINCT CAST(SKU AS STRING) AS sku,
        MAX(SKU_name) AS name
      FROM \`nimble-volt-459313-b8.Inventory.inv_seri_1\`
      ${bqFilterClause}
      GROUP BY 1
    `;
    
    let allFinalSkus = [];
    if (bigquery) {
      const [bqRows] = await bigquery.query({
        query: bqPcpvQuery,
        location: 'asia-southeast1'
      });
      allFinalSkus = bqRows.map(r => ({ sku: r.sku, name: r.name || r.sku }));
    } else {
      console.warn('BOM Dashboard: BigQuery chưa cấu hình, không thể lấy danh sách PCPV.');
      // (Fallback logic)
      const { data: allFinalsData } = await supabase.from('bom_relations').select('final_sku, final_name');
      allFinalSkus = Array.from(new Map((allFinalsData || []).map(f => [f.final_sku, { sku: f.final_sku, name: f.final_name || f.final_sku }])).values());
    }

    // === (MỚI) Lọc theo Search Query ===
    let filteredFinalSkus = allFinalSkus;
    if (searchQuery) {
      filteredFinalSkus = allFinalSkus.filter(f => 
        f.sku.toLowerCase().includes(searchQuery) || 
        f.name.toLowerCase().includes(searchQuery)
      );
    }
    // ===================================

    const totalItems = filteredFinalSkus.length; // Sửa: đếm trên danh sách đã lọc
    const totalPages = Math.ceil(totalItems / pageSize);
    // (SỬA LỖI LOGIC PAGE)
    let correctedPage = page;
    if (totalPages > 0 && correctedPage > totalPages) correctedPage = totalPages; 

    // === SỬA LOGIC: Lấy TẤT CẢ SKU đã lọc (không phân trang vội) ===
    const allFilteredSkuList = filteredFinalSkus.map(f => f.sku);

    if (allFilteredSkuList.length === 0) {
      // (Không tìm thấy kết quả hoặc không có BOM)
      return res.render('bom-dashboard', {
        title: 'Dashboard Lắp Ráp BOM', currentPage: 'pc-builder', time: res.locals.time,
        results: [], branches: [], page: 1, totalPages: 1, totalItems: 0,
        searchQuery: (req.query.q || ''), // Trả lại query
        filterType: filterType, // (MỚI) Trả lại filter
        isGlobalAdmin: isGlobalAdmin, userBranch: userBranch
      });
    }
    
    // --- C. Lấy BOM cho TẤT CẢ SKU đã lọc (từ Supabase) ---
    const { data: bomParts, error: e2 } = await supabase
      .from('bom_relations')
      .select('final_sku, component_sku, component_name, qty_per')
      .in('final_sku', allFilteredSkuList); // <-- SỬA: Dùng allFilteredSkuList
    if (e2) throw e2;
    
    // (Phần D và E - Lấy tồn kho và Tính toán giữ nguyên y hệt)
    
    // --- D. Lấy tồn kho ---
    const bomMap = new Map();
    filteredFinalSkus.forEach(f => bomMap.set(f.sku, [])); // <-- SỬA: Dùng filteredFinalSkus
    (bomParts || []).forEach(p => { bomMap.get(p.final_sku)?.push(p); });
    const allComponentSkus = Array.from(new Set((bomParts || []).map(p => p.component_sku)));
    const skusToFetchStock = [...new Set([...allFilteredSkuList, ...allComponentSkus])]; // <-- SỬA: Dùng allFilteredSkuList
    const inventoryMap = await getInventoryCounts(skusToFetchStock, userBranch, isGlobalAdmin, today);
    const allBranches = new Set();
    inventoryMap.forEach(branchMap => {
        branchMap.forEach((counts, branchId) => allBranches.add(branchId));
    });
    const sortedBranches = [...allBranches].sort();

    // --- E. Tính toán & Xây dựng dữ liệu render ---
    const allResults = []; // <-- SỬA: Đổi tên thành allResults
    for (const final of filteredFinalSkus) { // <-- SỬA: Lặp qua TẤT CẢ SKU
      const finalSku = final.sku;
      const components = bomMap.get(finalSku) || [];
      const finalProductStockMap = inventoryMap.get(finalSku);
      let totalFinalStock = 0;
      const finalStockByBranch = new Map();
      sortedBranches.forEach(br => {
        const stock = finalProductStockMap?.get(br)?.hang_ban_moi || 0;
        finalStockByBranch.set(br, stock);
        totalFinalStock += stock;
      });
      let totalBuildable = 0;
      const buildableByBranch = new Map();
      const componentDetails = new Map();
      components.forEach(c => {
        componentDetails.set(c.component_sku, { name: c.component_name || 'N/A', need: c.qty_per, branches: new Map() });
      });
      sortedBranches.forEach(br => {
        let buildableForBranch = Infinity;
        for (const comp of components) {
          const compSku = comp.component_sku;
          const needQty = Number(comp.qty_per || 1);
          const compStockMap = inventoryMap.get(compSku);
          const haveQty = compStockMap?.get(br)?.hang_ban_moi || 0;
          componentDetails.get(compSku).branches.set(br, { have: haveQty });
          const canBuild = Math.floor(haveQty / needQty);
          if (canBuild < buildableForBranch) buildableForBranch = canBuild;
        }
        const finalBuildable = (buildableForBranch === Infinity) ? 0 : buildableForBranch;
        buildableByBranch.set(br, finalBuildable);
        totalBuildable += finalBuildable;
      });
      allResults.push({ // <-- SỬA: Thêm vào allResults
        sku: finalSku, name: final.name,
        finalStock_Total: totalFinalStock, finalStock_ByBranch: Object.fromEntries(finalStockByBranch),
        buildable_Total: totalBuildable, buildable_ByBranch: Object.fromEntries(buildableByBranch),
        components: Array.from(componentDetails.entries()).map(([sku, data]) => ({ sku, ...data, branches: Object.fromEntries(data.branches) }))
      });
    }

    // === SỬA: Sắp xếp TẤT CẢ kết quả (theo Tồn kho Thành phẩm) ===
    allResults.sort((a, b) => b.finalStock_Total - a.finalStock_Total);
    
    // === SỬA: Phân trang SAU KHI SẮP XẾP ===
    const paginatedResults = allResults.slice((correctedPage - 1) * pageSize, correctedPage * pageSize);
    
    // 4. Render
    res.render('bom-dashboard', {
      title: 'Dashboard Lắp Ráp BOM',
      currentPage: 'pc-builder',
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      results: paginatedResults, // <-- SỬA: Gửi danh sách đã phân trang
      branches: sortedBranches,
      page: correctedPage, // <-- SỬA: Gửi trang đã sửa lỗi
      totalPages: totalPages,
      totalItems: totalItems,
      searchQuery: (req.query.q || ''), // (MỚI) Trả lại query
      filterType: filterType, // (MỚI) Trả lại filter
      isGlobalAdmin: isGlobalAdmin,
      userBranch: userBranch
    });

  } catch (e) {
    console.error('Lỗi /bom-dashboard:', e.message);
    res.redirect('/bom-check?error=' + encodeURIComponent(e.message));
  }
});


// (TRONG server.js)

// Route 1 (GET): Hiển thị form để tạo BOM
app.get('/admin/bom/create', requireAuth, async (req, res) => {
  const finalSku = req.query.final_sku || '';
  let finalName = 'SKU không rõ';

  if (finalSku) {
    // Lấy tên SKU để hiển thị
    const { data: skuData } = await supabase
      .from('skus')
      .select('product_name')
      .eq('sku', finalSku)
      .single();
    if (skuData) {
      finalName = skuData.product_name;
    }
  }

  res.render('admin-bom-form', {
    title: 'Tạo Định Mức (BOM)',
    currentPage: 'pc-builder',
    finalSku: finalSku,
    finalName: finalName,
    existingBom: [], // Dùng cho form rỗng
    error: null
  });
});

// (TRONG server.js)

// Route 2 (POST): Lưu BOM mới (ĐÃ NÂNG CẤP - TỰ TRA CỨU TÊN)
app.post('/admin/bom/create', requireAuth, async (req, res) => {
const { final_sku, components_list } = req.body;

  if (!final_sku || !components_list) {
    return res.status(400).send('Thiếu SKU Thành phẩm hoặc Danh sách Linh kiện.');
  }

  try {
    // 1. Phân tích danh sách linh kiện từ textarea (Lấy SKU và Qty)
    const lines = (components_list || '').split(/\r?\n/);
    const componentMap = new Map(); // Dùng Map để tránh trùng lặp

    lines.forEach(line => {
      const parts = line.split(/[,\s\t]+/); // Tách bằng dấu phẩy, space, hoặc tab
      const sku = parts[0] ? parts[0].trim() : null;
      const qty = (parts[1] ? parseInt(parts[1].trim(), 10) : 1) || 1;

      if (sku) {
        componentMap.set(sku, qty);
      }
    });

    const componentSkuList = Array.from(componentMap.keys());
    if (componentSkuList.length === 0) {
      throw new Error('Danh sách linh kiện rỗng hoặc không hợp lệ.');
    }

    // 2. (MỚI) Tra cứu tên linh kiện từ bảng 'skus'
    const { data: skuData, error: skuError } = await supabase
      .from('skus')
      .select('sku, product_name')
      .in('sku', componentSkuList);
    
    if (skuError) throw new Error(`Lỗi tra cứu tên SKU: ${skuError.message}`);

    const skuNameMap = new Map(
      (skuData || []).map(item => [item.sku, item.product_name])
    );

    // 3. (MỚI) Tạo payload hoàn chỉnh
    const componentsPayload = componentSkuList.map(sku => {
      return {
        final_sku: final_sku,
        component_sku: sku,
        qty_per: componentMap.get(sku) || 1,
        component_name: skuNameMap.get(sku) || null // Thêm tên vào đây
      };
    });

    // 4. Xóa BOM cũ (nếu có)
    await supabase
      .from('bom_relations')
      .delete()
      .eq('final_sku', final_sku);

    // 5. Chèn BOM mới
    const { error: insertError } = await supabase
      .from('bom_relations')
      .insert(componentsPayload);
    
    if (insertError) throw insertError;

    // 6. Thành công, chuyển về trang tra cứu
    res.redirect(`/bom-check?sku=${encodeURIComponent(final_sku)}&success=true`);

  } catch (err) {
    // (Tải lại thông tin để render lỗi)
    const { data: skuData } = await supabase.from('skus').select('product_name').eq('sku', final_sku).single();
    res.render('admin-bom-form', {
      title: 'Tạo Định Mức (BOM)',
      currentPage: 'pc-builder',
      finalSku: final_sku,
      finalName: skuData?.product_name || 'SKU không rõ',
      existingBom: [],
      error: 'Lỗi khi lưu: ' + err.message
    });
  }
});

// app.get('/tien-ich', requireAuth, (req, res) => {
  // res.render('tien-ich', { user: req.user || null });
// });

// ===== BẮT ĐẦU SỬA LẠI TOÀN BỘ HÀM (Build PC) - FIX LOGIC CHECKED_OUT =====
/**
 * Lấy tồn HÀNG BÁN MỚI theo branch cho nhiều SKU (ĐÃ SỬA LỖI LOGIC)
 * Dùng cho trang Build PC.
 */
async function getSkuNewStockByBranch(skus) {
  // 1. Kiểm tra BigQuery
  if (!bigquery) { 
    console.warn("BuildPC: Bỏ qua BQ vì chưa cấu hình.");
    return {};
  }
  if (!skus || !skus.length) return {};

  // 2. Sửa Query: Lấy 'Serial' thay vì COUNT(*)
  const query = `
    SELECT
      CAST(sku AS STRING) AS sku,
      branch_id,
      bin_zone,
      Serial  -- Lấy Serial để kiểm tra
    FROM \`nimble-volt-459313-b8.Inventory.inv_seri_1\`
    WHERE CAST(sku AS STRING) IN UNNEST(@skus)
      AND (Serial IS NOT NULL AND Serial != '') -- Chỉ lấy hàng có serial
    /* Xóa GROUP BY để lấy từng dòng serial */
  `;

  // 3. Gọi BigQuery
  let rows = [];
  try {
    const [bqRows] = await bigquery.query({
      query,
      params: { skus }
    });
    rows = bqRows;
  } catch (e) {
    console.error("Lỗi BQ (getSkuNewStockByBranch):", e.message);
    return {}; // Trả về rỗng nếu BQ lỗi
  }

  if (rows.length === 0) {
    return {}; // Không tìm thấy serial nào
  }

  // 4. Lấy danh sách serial "Đã xuất" từ SUPABASE (Giống FIFO)
  const allSerials = [...new Set(rows.map(r => r.Serial))];
  const today = new Date().toISOString().slice(0, 10);
  let checkedOutSerials = new Set();

  const BATCH_SIZE = 500;
  console.log(`[getSkuNewStockByBranch] Lấy ${allSerials.length} serials, chia thành các batch ${BATCH_SIZE}...`);
  
  try {
    for (let i = 0; i < allSerials.length; i += BATCH_SIZE) {
      const batch = allSerials.slice(i, i + BATCH_SIZE);
      
      const { data: logData, error } = await supabase
          .from('serial_check_log')
          .select('serial')
          .in('serial', batch) // Chỉ query 1 batch
          .eq('check_date', today)
          .eq('checked_out', true);
      
      if (error) {
        // Log lỗi của batch này nhưng vẫn tiếp tục
        console.error(`Lỗi Supabase batch ${i}:`, error.message);
      } else {
        (logData || []).forEach(log => checkedOutSerials.add(log.serial));
      }
    }
  } catch (e) {
      // Lỗi này là lỗi chung (như 'fetch failed' ban đầu)
      console.error("Lỗi Supabase (getSkuNewStockByBranch):", e.message);
  }

  console.log(`[getSkuNewStockByBranch] Đã tìm thấy ${checkedOutSerials.size} serial đã xuất hôm nay.`);

  // 5. Lọc bằng JavaScript (Lọc cả bin_zone và serial đã xuất)
  const result = {};
  const allowedZones = ['Trưng bày hàng bán mới', 'Lưu kho hàng bán mới'];
  
  for (const row of rows) {
    // LỌC 1: Bỏ qua nếu serial đã bị check out
    if (checkedOutSerials.has(row.Serial)) {
      continue;
    }
    
    // LỌC 2: Chỉ lấy 2 bin_zone bán hàng
    if (allowedZones.includes((row.bin_zone || '').trim())) { 
      const sku = row.sku;
      const br = row.branch_id;
      
      if (!result[sku]) result[sku] = {};
      
      // Cộng dồn
      result[sku][br] = (result[sku][br] || 0) + 1; // +1 cho mỗi serial hợp lệ
    }
  }
  return result;
}
// ===== KẾT THÚC SỬA LẠI TOÀN BỘ HÀM =====


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

// === HÀM HELPER LẤY TỒN KHO (ĐÃ SỬA ĐỂ HỖ TRỢ ADMIN XEM NHIỀU CHI NHÁNH) ===
async function getInventoryCounts(skuList, userBranch, isGlobalAdmin, checkDate) {
    // 1. Nếu không có SKU, không có chi nhánh, hoặc BQ không chạy -> trả về rỗng
    if (!bigquery || !Array.isArray(skuList) || skuList.length === 0 || !userBranch || !checkDate) {
        return new Map(); // Trả về Map rỗng
    }

    const BIGQUERY_TABLE = '`nimble-volt-459313-b8.Inventory.inv_seri_1`';
    const params = {
        skuList: skuList.map(String), // Đảm bảo SKU là chuỗi
        userBranch: userBranch,
    };

    let branchFilter = '';
    // Nếu không phải admin, mới lọc theo chi nhánh
    if (!isGlobalAdmin) {
        branchFilter = 'AND Branch_ID = @userBranch';
    }

    // 2. Query BigQuery để lấy TẤT CẢ serial/bin_zone/branch cho các SKU
    const bqQuery = `
        SELECT
            CAST(SKU AS STRING) AS sku,
            Serial AS serial,
            BIN_zone AS bin_zone,
            Branch_ID AS branch_id
        FROM ${BIGQUERY_TABLE}
        WHERE CAST(SKU AS STRING) IN UNNEST(@skuList)
          ${branchFilter} 
          AND Serial IS NOT NULL
          AND Serial != ''
    `;
    
    let bqRows = [];
    try {
        const [rows] = await bigquery.query({
            query: bqQuery,
            location: 'asia-southeast1',
            params: params,
        });
        bqRows = rows;
    } catch (e) {
        console.error("Lỗi query BQ (getInventoryCounts):", e.message);
        return new Map(); // Trả về rỗng nếu BQ lỗi
    }

    if (bqRows.length === 0) {
        return new Map(); // Không có tồn BQ
    }

    // 3. Lấy danh sách serial đã xuất TỪ SUPABASE
    const allSerials = bqRows.map(r => r.serial);
    let checkedOutSerials = new Set();
    try {
        // Lấy log của TẤT CẢ serials tìm thấy trong ngày
        const { data: logData, error } = await supabase
            .from('serial_check_log')
            .select('serial')
            .in('serial', allSerials)
            .eq('check_date', checkDate)
            .eq('checked_out', true); // Chỉ lấy serial đã tick "Đã xuất"
            
        if (error) throw error;
        
        (logData || []).forEach(log => {
            checkedOutSerials.add(log.serial);
        });
    } catch (e) {
        console.error("Lỗi query Supabase (getInventoryCounts):", e.message);
    }

    // 4. Lọc bỏ serial đã xuất và đếm theo SKU -> Branch -> Bin_zone
    // Cấu trúc mới: Map<SKU, Map<Branch, CountsObject>>
    const inventoryMap = new Map();

    // Khởi tạo Map cho tất cả SKU
    skuList.forEach(sku => {
        inventoryMap.set(sku, new Map());
    });

    // Lấy danh sách tất cả các chi nhánh xuất hiện trong kết quả BQ
    const allBranchesInResult = [...new Set(bqRows.map(r => r.branch_id))];

    // Khởi tạo cấu trúc đếm cho từng SKU, từng Branch
    skuList.forEach(sku => {
        const branchMap = inventoryMap.get(sku);
        allBranchesInResult.forEach(branchId => {
            branchMap.set(branchId, {
                hang_ban_moi: 0,
                trung_bay_chi_dinh: 0,
                luu_kho_tl: 0,
                trung_bay_tl: 0,
                hang_mkt: 0,
                ton_khac: 0,
            });
        });
    });

    // 5. Duyệt qua kết quả BQ để đếm
    bqRows.forEach(row => {
        // Bỏ qua nếu serial này đã bị tick "Đã xuất"
        if (checkedOutSerials.has(row.serial)) {
            return;
        }

        const sku = row.sku;
        const branchId = row.branch_id;
        const binZone = (row.bin_zone || '').trim();

        const branchMap = inventoryMap.get(sku);
        if (!branchMap) return; // SKU không có trong list

        const counts = branchMap.get(branchId);
        if (!counts) return; // Branch này không liên quan

        // Phân loại theo yêu cầu của user
        if (binZone === 'Trưng bày hàng bán mới' || binZone === 'Lưu kho hàng bán mới') {
            counts.hang_ban_moi += 1;
        } else if (binZone === 'Trưng bày chỉ định') {
            counts.trung_bay_chi_dinh += 1;
        } else if (binZone === 'Lưu kho thanh lý') {
            counts.luu_kho_tl += 1;
        } else if (binZone === 'Trưng bày thanh lý') {
            counts.trung_bay_tl += 1;
        } else if (binZone === 'Hàng MKT') { // <-- THÊM KHỐI NÀY
            counts.hang_mkt += 1;
        } else {
            counts.ton_khac += 1;
        }
    });

    // 6. Dọn dẹp: Xóa các Map rỗng (nếu tồn kho = 0)
    inventoryMap.forEach((branchMap, sku) => {
        branchMap.forEach((counts, branchId) => {
            const total = counts.hang_ban_moi + counts.trung_bay_chi_dinh + counts.luu_kho_tl + counts.trung_bay_tl + counts.hang_mkt + counts.ton_khac;
            if (total === 0) {
                branchMap.delete(branchId); // Xóa branch này nếu tồn = 0
            }
        });
        if (branchMap.size === 0) {
            inventoryMap.delete(sku); // Xóa SKU này nếu không có tồn ở đâu
        }
    });

    return inventoryMap;
}

// === HÀM HELPER MỚI: LẤY TOP 5 SERIAL CŨ NHẤT (ĐÃ CẬP NHẬT) ===
async function getOldestSerials(sku, userBranch, isGlobalAdmin, checkDate, limit = 5) {
    if (!bigquery || !sku || !userBranch || !checkDate) {
        return [];
    }

    const BIGQUERY_TABLE = '`nimble-volt-459313-b8.Inventory.inv_seri_1`';
    const params = {
        sku: String(sku),
        userBranch: userBranch,
        isGlobalAdmin: isGlobalAdmin, // Truyền cờ admin
    };

    // Lọc chi nhánh (nếu không phải admin)
    const branchFilter = isGlobalAdmin ? '' : 'AND Branch_ID = @userBranch';

    // 1. Query BQ để lấy serials cũ nhất
    const bqQuery = `
        SELECT
            Serial AS serial,
            Location AS location, -- YÊU CẦU MỚI: Lấy Location
            Aging_company AS days_old
        FROM ${BIGQUERY_TABLE}
        WHERE CAST(SKU AS STRING) = @sku
          ${branchFilter}
          AND BIN_zone IN ('Trưng bày hàng bán mới', 'Lưu kho hàng bán mới') -- YÊU CẦU MỚI: Lọc theo Bin_zone
          AND Serial IS NOT NULL AND Serial != ''
        ORDER BY Date_import_company ASC -- ASC = Cũ nhất trước
        LIMIT 50 -- Lấy dư 50 để lọc serial đã xuất
    `;

    let bqRows = [];
    try {
        const [rows] = await bigquery.query({
            query: bqQuery,
            location: 'asia-southeast1',
            params: params,
        });
        bqRows = rows;
    } catch (e) {
        console.error("Lỗi query BQ (getOldestSerials):", e.message);
        return [];
    }

    if (bqRows.length === 0) {
        return [];
    }

    // 2. Lấy danh sách serial đã xuất TỪ SUPABASE
    const allSerials = bqRows.map(r => r.serial);
    let checkedOutSerials = new Set();
    try {
        const { data: logData } = await supabase
            .from('serial_check_log')
            .select('serial')
            .in('serial', allSerials)
            .eq('check_date', checkDate)
            .eq('checked_out', true);
        
        (logData || []).forEach(log => {
            checkedOutSerials.add(log.serial);
        });
    } catch (e) {
        console.error("Lỗi query Supabase (getOldestSerials):", e.message);
    }

    // 3. Lọc bỏ serial đã xuất và lấy 5 serial đầu tiên
    const finalSerials = [];
    for (const row of bqRows) {
        if (!checkedOutSerials.has(row.serial)) {
            finalSerials.push({
                serial: row.serial,
                // YÊU CẦU MỚI: Trả về 'location' thay vì 'bin_zone'
                bin_zone: row.location || '-', // Dùng chung key 'bin_zone' để EJS không bị lỗi
                days_old: row.days_old || 0,
            });
        }
        // Dừng khi đã đủ 5 serial
        if (finalSerials.length >= limit) {
            break;
        }
    }

    return finalSerials;
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


app.post('/api/pc-builder/generate-quote', requireAuth, async (req, res) => {
  let browser = null;
  try {
    const { 
      buildConfig, customerName, contactInfo, customerPhone, 
      // 1. Phân biệt Build PC và Báo giá nhanh
      isGeneralQuote = false, 
      templateType = 'consumer', 
      globalDiscount = { value: 0, type: 'amount' },
      validityDays = 3
    } = req.body;

    console.log(`[Báo giá] KH: ${customerName} | Mode: ${isGeneralQuote ? 'Báo giá nhanh' : 'Build PC'}`);

    // 2. Tính tiền hàng (Trừ giảm giá từng món item_discount)
    const items = Object.values(buildConfig);
    let totalItemsPrice = 0; 
    
    items.forEach(item => {
      const price = item.edited_price !== undefined ? item.edited_price : (item.list_price || 0);
      const itemDiscount = item.item_discount || 0; // Giảm giá món
      const lineTotal = (price - itemDiscount) * item.quantity;
      totalItemsPrice += lineTotal;
    });

    // 3. Tính giảm giá toàn đơn (chỉ khi là Báo giá nhanh hoặc tùy ý bạn)
    let globalDiscountAmt = 0;
    if (globalDiscount.type === 'percent') {
        globalDiscountAmt = Math.round(totalItemsPrice * (globalDiscount.value / 100));
    } else {
        globalDiscountAmt = Number(globalDiscount.value) || 0;
    }
    if (globalDiscountAmt > totalItemsPrice) globalDiscountAmt = totalItemsPrice;
    
    // 4. LOGIC KHUYẾN MÃI BUILD PC (VẪN CÒN ĐÂY)
    // Logic này chỉ chạy khi isGeneralQuote = false (tức là từ trang Build PC)
    let appliedPromo = null;
    let promoDiscount = 0;

    if (!isGeneralQuote) {
      // Logic cũ: Tặng tiền theo mốc tổng giá trị
      const tiers = [
        { min: 50000000, discount: 1000000, code: 'PVBUILDPC25114' },
        { min: 30000000, discount: 600000,  code: 'PVBUILDPC25113' },
        { min: 20000000, discount: 400000,  code: 'PVBUILDPC25112' },
        { min: 10000000, discount: 200000,  code: 'PVBUILDPC25111' }
      ];
      for (const tier of tiers) {
        if (totalItemsPrice >= tier.min) {
          appliedPromo = {
            name: `Build PC - Giảm ${new Intl.NumberFormat('vi-VN').format(tier.discount)} VNĐ`,
            discount_amount: tier.discount,
            coupon: tier.code
          };
          promoDiscount = tier.discount;
          break; // Lấy mốc cao nhất
        }
      }
    } else {
        console.log("-> Báo giá nhanh: Bỏ qua Auto Promo của Build PC.");
    }

    // 5. Tổng thanh toán cuối cùng
    // Trừ giảm giá tổng (nhập tay) VÀ trừ khuyến mãi Build PC (tự động)
    const finalTotal = totalItemsPrice - globalDiscountAmt - promoDiscount;

    // 6. Render & PDF
    const userFullName = req.session.user?.full_name || 'Nhân viên Phong Vũ';
    const userBranchCode = req.session.user?.branch_code || 'DEFAULT';
    const branchInfo = BRANCH_CONFIG[userBranchCode] || BRANCH_CONFIG['DEFAULT'];
    const todayStr = new Date().toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric' });
    const quoteNum = `PV-${Date.now().toString().slice(-6)}`;

    const htmlString = await ejs.renderFile(
      path.join(__dirname, 'views/quote-template.ejs'),
      {
        branchInfo,
        salesName: userFullName, salesContact: contactInfo, salesEmail: req.session.user?.email,
        quoteDate: todayStr, quoteNumber: quoteNum,
        customerName, customerPhone, customerEmail: '',
        items, 
        
        templateType,
        totalItemsPrice,    
        globalDiscountAmt,  
        appliedPromo,       // Truyền promo xuống EJS để hiển thị
        finalTotal,         
        validityDays,
        
        formatVND: (n) => new Intl.NumberFormat('vi-VN').format(Number(n || 0))
      }
    );

    const puppeteerToUse = isVercel ? puppeteerCore : puppeteer;
    const launchOptions = isVercel ? {
        args: chromium.args,
        defaultViewport: chromium.defaultViewport,
        executablePath: await chromium.executablePath(),
        headless: chromium.headless,
        ignoreHTTPSErrors: true,
    } : { headless: true };

    browser = await puppeteerToUse.launch(launchOptions);
    const page = await browser.newPage();
    await page.setContent(htmlString, { waitUntil: 'networkidle0' });
    const pdfBufferRaw = await page.pdf({ format: 'A4', printBackground: true, margin: { top: '20px', right: '20px', bottom: '20px', left: '20px' } });
    await browser.close();
    browser = null;

    const safeName = customerName.normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/đ/g, "d").replace(/Đ/g, "D").replace(/[^a-zA-Z0-9]/g, '_');
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="BaoGia_${safeName}.pdf"`);
    res.send(Buffer.from(pdfBufferRaw));

  } catch (e) {
    console.error('Lỗi API Báo giá:', e);
    if (browser) await browser.close();
    if (!res.headersSent) res.status(500).json({ ok: false, error: e.message });
  }
});


// (Trong file server.js)
app.get('/quote-builder', requireAuth, (req, res) => {
  res.render('quote-builder', {
    title: 'Báo giá nhanh',
    currentPage: 'quote-builder', // Dùng để active menu (nếu cần)
  });
});


// (Trong file server.js)

// SỬA LẠI API NÀY: Thêm logic lọc và tải mặc định
app.get('/api/quote/search-products', requireAuth, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    const category = (req.query.category || '').trim();
    const subcat = (req.query.subcat || '').trim();
    const limit = 20;

    let query = supabase
      .from('skus')
      .select('sku, product_name, brand, list_price');

    // 1. Lọc theo từ khóa (nếu có)
    if (q) {
      query = query.or(`sku.ilike.%${q}%,product_name.ilike.%${q}%`);
    }
    
    // 2. Lọc theo Category (NHxx)
    if (category) {
      query = query.eq('category', category);
    }
    
    // 3. Lọc theo Subcat (Tên nhóm)
    if (subcat) {
      query = query.eq('subcat', subcat);
    }

    // 4. Sắp xếp và Tải mặc định
    if (!q && !category && !subcat) {
      // Nếu không tìm kiếm/lọc gì, tải 20 SP giá cao nhất
      query = query.order('list_price', { ascending: false, nullsFirst: false });
    } else {
      // Nếu có tìm kiếm, ưu tiên sắp xếp theo SKU
      query = query.order('sku', { ascending: true });
    }

    const { data, error } = await query.limit(limit);
    if (error) throw error;

    res.json({ ok: true, products: data || [] });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// API MỚI: Lấy các tùy chọn cho bộ lọc báo giá
app.get('/api/quote/filter-options', requireAuth, async (req, res) => {
  try {
    // Lấy Category (NHxx)
    const { data: categories, error: catError } = await supabase
      .from('skus')
      .select('category')
      .neq('category', null);
    if (catError) throw catError;
    
    // Lấy Subcat (Tên nhóm SP)
    const { data: subcats, error: subcatError } = await supabase
      .from('skus')
      .select('subcat')
      .neq('subcat', null);
    if (subcatError) throw subcatError;

    const uniqueCategories = [...new Set((categories || []).map(item => item.category))].sort();
    const uniqueSubcats = [...new Set((subcats || []).map(item => item.subcat))].sort();

    res.json({ 
      ok: true, 
      categories: uniqueCategories, 
      subcats: uniqueSubcats 
    });

  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// (Trong file server.js, gần cuối)

// (Trong file server.js)

// API MỚI: Đồng bộ SKUs từ BigQuery (ĐÃ SỬA LỖI PAGINATION LẦN CUỐI)
app.post('/api/admin/sync-bq-skus', requireAuth, requireManager, async (req, res) => {
  if (!bigquery) {
    return res.status(500).json({ ok: false, error: 'BigQuery client chưa được cấu hình trên server.' });
  }
  
  console.log('[SYNC] Bắt đầu đồng bộ SKUs từ BigQuery...');

  try {
    // 1. Query BigQuery (Đã tối ưu TRIM)
    const bqQuery = `
      SELECT
        TRIM(CAST(SKU AS STRING)) AS sku,
        MAX(SKU_name) AS product_name,
        MAX(Brand) AS brand,
        MAX(Category_ID) AS category,
        MAX(SubCategory_ID) AS subcat
      FROM \`nimble-volt-459313-b8.Inventory.inv_seri_1\`
      WHERE SKU IS NOT NULL AND TRIM(CAST(SKU AS STRING)) != ''
      GROUP BY 1
    `;
    
    const [bqRowsRaw] = await bigquery.query({
      query: bqQuery,
      location: 'asia-southeast1',
    });

    if (!bqRowsRaw || bqRowsRaw.length === 0) {
      return res.status(404).json({ ok: false, error: 'Không tìm thấy dữ liệu SKU nào từ BigQuery.' });
    }
    
    const bqRows = bqRowsRaw.map(row => ({
      sku: (row.sku || '').trim(),
      product_name: (row.product_name || '').trim(),
      brand: (row.brand || '').trim() || null,
      category: (row.category || '').trim() || null,
      subcat: (row.subcat || '').trim() || null
    })).filter(row => row.sku);

    console.log(`[SYNC] Lấy và dọn dẹp ${bqRows.length} SKU duy nhất từ BigQuery.`);

    // 2. Lấy *TẤT CẢ* SKUs hiện có trong Supabase (XỬ LÝ PAGINATION)
    const existingSkuSet = new Set();
    
    // === SỬA LỖI: ĐẶT PAGE_SIZE = 1000 (ĐÚNG THEO GIỚI HẠN CỦA SERVER) ===
    const PAGE_SIZE = 1000; 
    // ===================================================================
    
    let page = 0;
    let keepFetching = true;

    console.log(`[SYNC] Bắt đầu lấy SKUs hiện có từ Supabase (mỗi trang ${PAGE_SIZE} SKU)...`);
    
    while(keepFetching) {
      const { data: skuPage, error: supabaseError } = await supabase
        .from('skus')
        .select('sku')
        .range(page * PAGE_SIZE, (page + 1) * PAGE_SIZE - 1);

      if (supabaseError) throw supabaseError;

      if (!skuPage || skuPage.length === 0) {
        keepFetching = false; // Dừng lại khi không còn dữ liệu
      } else {
        skuPage.forEach(s => {
          if (s.sku) existingSkuSet.add(s.sku.trim()); 
        });
        
        // Logic đúng: Nếu server trả về *ít hơn* số ta yêu cầu, đó mới là trang cuối
        if (skuPage.length < PAGE_SIZE) { 
          keepFetching = false;
        }
        
        // Tăng trang để lấy lượt tiếp theo
        page++; 
      }
    }
    console.log(`[SYNC] Đã có tổng cộng ${existingSkuSet.size} SKU (đã dọn dẹp) trong Supabase.`);


    // 3. Lọc ra những SKU mới
    const newSkuPayloads = bqRows.filter(bqRow => !existingSkuSet.has(bqRow.sku));

    if (newSkuPayloads.length === 0) {
      const message = 'Đồng bộ hoàn tất. Không có SKU nào mới.';
      console.log(`[SYNC] ${message}`);
      return res.json({ ok: true, message: message, new_skus: 0 });
    }

    // 4. CHỈ INSERT những SKU mới
    console.log(`[SYNC] Chuẩn bị chèn ${newSkuPayloads.length} SKU mới...`);
    
    const BATCH_SIZE = 1000; // Giữ nguyên batch insert là 1000
    let totalInsertedCount = 0;

    for (let i = 0; i < newSkuPayloads.length; i += BATCH_SIZE) {
      const batch = newSkuPayloads.slice(i, i + BATCH_SIZE);
      const batchNum = Math.floor(i / BATCH_SIZE) + 1;
      
      const finalBatch = batch.map(b => ({
        ...b,
        product_name: b.product_name || b.sku
      }));

      const { error: insertError, count } = await supabase
        .from('skus')
        .insert(finalBatch);

      if (insertError) {
        console.error(`[SYNC] Lỗi khi chèn batch ${batchNum}:`, insertError.message);
        throw new Error(`Lỗi khi chèn batch ${batchNum}: ${insertError.message}`);
      }
      
      totalInsertedCount += (count || batch.length); 
    }
    
    const message = `Đồng bộ hoàn tất. Đã chèn ${totalInsertedCount} SKU mới.`;
    console.log(`[SYNC] ${message}`);
    res.json({ ok: true, message: message, new_skus: totalInsertedCount });

  } catch (e) {
    console.error('[SYNC] Lỗi đồng bộ BigQuery:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

/**
 * API [GET] /api/event/search-sku
 * Tìm SKU và trả về tồn kho BIN MKT của chi nhánh user
 */
app.get('/api/event/search-sku', requireAuth, async (req, res) => {
  try {
    const skuQuery = (req.query.q || '').trim();
    const userBranch = req.session.user?.branch_code;
    const searchMode = req.query.mode || 'mkt_only'; // 'mkt_only' hoặc 'all_bins'
    const today = new Date().toISOString().split('T')[0];

    if (!skuQuery || !userBranch) {
      return res.status(400).json({ ok: false, error: 'Thiếu SKU hoặc thông tin chi nhánh.' });
    }

    // 1. Lấy thông tin SKU (ĐÃ SỬA: Thêm join với event_sku_prices)
    const { data: skuData, error: skuError } = await supabase
      .from('skus')
      .select(`
        sku, product_name, brand, list_price,
        event_sku_prices ( event_price )
      `)
      .eq('event_sku_prices.branch_code', userBranch) // Lọc giá event của chi nhánh
      .or(`sku.ilike.%${skuQuery}%,product_name.ilike.%${skuQuery}%`)
      .limit(10);
      
    if (skuError) throw skuError;
    if (!skuData || skuData.length === 0) {
      return res.json({ ok: true, results: [] });
    }

    // 2. Lấy tồn kho (Hàm này đã được sửa ở Bước 2)
    const skus = skuData.map(s => s.sku);
    // (GỌI HÀM LỚN) Lấy TẤT CẢ tồn kho, phân quyền theo userBranch
    const inventoryMap = await getInventoryCounts(skus, userBranch, false, today); 
    
    // 3. Xử lý kết quả
    let results = [];
    for (const sku of skuData) {
      const branchMap = inventoryMap.get(sku.sku);
      const counts = branchMap ? branchMap.get(userBranch) : null;
      
      const bin_mkt_stock = counts?.hang_mkt || 0;
      const other_stock = (counts?.hang_ban_moi || 0) + (counts?.trung_bay_chi_dinh || 0) + (counts?.luu_kho_tl || 0) + (counts?.trung_bay_tl || 0) + (counts?.ton_khac || 0);
      
      let itemStock = 0;
      let badge = null;

      if (bin_mkt_stock > 0) {
        itemStock = bin_mkt_stock;
        badge = 'Hàng MKT';
      } else if (other_stock > 0) {
        itemStock = other_stock;
        badge = 'BIN Khác';
      }

      // Nếu mode "Chỉ MKT" và không có tồn MKT, bỏ qua
      if (searchMode === 'mkt_only' && badge !== 'Hàng MKT') {
        continue; 
      }
      
      // Nếu mode "All" nhưng hết sạch hàng, cũng bỏ qua
      if (itemStock === 0) {
        continue;
      }

      // (MỚI) Trích xuất giá event (nếu có)
      const eventPrice = (sku.event_sku_prices && sku.event_sku_prices.length > 0)
                        ? sku.event_sku_prices[0].event_price
                        : null;

      results.push({
        sku: sku.sku,
        product_name: sku.product_name,
        brand: sku.brand,
        list_price: sku.list_price, // Vẫn giữ giá gốc để tham khảo
        event_price: eventPrice, // (MỚI) Gửi giá event ra
        stock: itemStock,
        badge: badge // 'Hàng MKT' hoặc 'BIN Khác'
      });
    }

    // Sắp xếp: Ưu tiên Hàng MKT lên đầu
    results.sort((a, b) => {
      if (a.badge === 'Hàng MKT' && b.badge !== 'Hàng MKT') return -1;
      if (a.badge !== 'Hàng MKT' && b.badge === 'Hàng MKT') return 1;
      return b.stock - a.stock; // Phụ: Tồn nhiều lên đầu
    });

    res.json({ ok: true, results });

  } catch (e) {
    console.error('Lỗi API /api/event/search-sku:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});


/**
 * API [POST] /api/event/save-order
 * Nhận giỏ hàng, thông tin KH và lưu vào DB
 */
app.post('/api/event/save-order', requireAuth, async (req, res) => {
  try {
    const { cart, customerName, customerPhone, notes, totalAmount, paymentMethod } = req.body;
    const user = req.session.user;
    
    if (!cart || cart.length === 0 || !customerName || !customerPhone || !paymentMethod) {
      return res.status(400).json({ ok: false, error: 'Thiếu giỏ hàng, thông tin khách hàng, hoặc PTTT.' });
    }
    
    // Lấy thông tin Event đang chạy
    const { data: eventStatus } = await supabase
      .from('branch_event_status')
      .select('event_name')
      .eq('branch_code', user.branch_code)
      .eq('is_event_active', true)
      .single();

    // 1. Tạo đơn hàng chính (event_orders)
    const { data: newOrder, error: orderError } = await supabase
      .from('event_orders')
      .insert({
        branch_code: user.branch_code,
        event_name: eventStatus?.event_name || 'Event',
        total_amount: totalAmount,
        notes: notes,
        seller_id: user.id,
        seller_name: user.full_name,
        customer_name: customerName,
        customer_phone: customerPhone,
        payment_method: paymentMethod
      })
      .select('id')
      .single();
      
    if (orderError) throw orderError;
    const newOrderId = newOrder.id;

    // 2. Chuẩn bị các sản phẩm (event_order_items)
    const orderItemsPayload = cart.map(item => ({
      order_id: newOrderId,
      sku: item.sku,
      product_name: item.product_name,
      quantity: item.quantity,
      list_price: item.list_price,
      final_price: item.final_price // Giá đã điều chỉnh
      // (Bỏ qua KM ở bước này cho đơn giản)
    }));

    // 3. Insert các sản phẩm
    const { error: itemsError } = await supabase
      .from('event_order_items')
      .insert(orderItemsPayload);
      
    if (itemsError) throw itemsError;

    // 4. Trả về ID đơn hàng
    res.json({ ok: true, orderId: newOrderId, message: 'Tạo đơn hàng thành công!' });

  } catch (e) {
    console.error('Lỗi API /api/event/save-order:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ========================= YÊU CẦU 2: XEM LỊCH SỬ ĐƠN HÀNG =========================
app.get('/event-orders', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    const userRole = user.role;
    const userBranch = user.branch_code;

    let query = supabase
      .from('event_orders')
      .select(`
        id, created_at, customer_name, customer_phone, total_amount, notes, seller_name,
        event_order_items ( sku, product_name, quantity, final_price )
      `)
      .order('created_at', { ascending: false })
      .limit(100); // Giới hạn 100 đơn hàng gần nhất

    // Phân quyền
    if (userRole === 'admin' || userRole === 'manager') {
      // Manager/Admin thấy hết đơn của Chi nhánh
      query = query.eq('branch_code', userBranch);
    } else {
      // Staff chỉ thấy đơn của mình
      query = query.eq('seller_id', user.id);
    }

    const { data: orders, error } = await query;
    if (error) throw error;

    res.render('event-orders', {
      title: 'Lịch sử Đơn hàng Event',
      currentPage: 'event-operations', // Vẫn highlight menu "Vận hành Event"
      orders: orders || [],
      userRole: userRole,
      userBranch: userBranch
    });

  } catch (e) {
    console.error('Lỗi trang /event-orders:', e.message);
    res.render('event-orders', {
      title: 'Lỗi',
      currentPage: 'event-operations',
      orders: [],
      userRole: 'staff',
      userBranch: 'N/A',
      error: e.message
    });
  }
});


// (TRONG server.js)

// ========================= YÊU CẦU 3: IN BILL EVENT =========================
app.get('/event-bill/:id', requireAuth, async (req, res) => {
  try {
    const orderId = req.params.id;
    const user = req.session.user;
    
    // 1. Lấy thông tin đơn hàng
    const { data: order, error } = await supabase
      .from('event_orders')
      .select(`
        *,
        event_order_items ( * )
      `)
      .eq('id', orderId)
      .maybeSingle(); // Lấy 1 hoặc null

    if (error) throw error;
    if (!order) {
      return res.status(404).send('Không tìm thấy đơn hàng.');
    }

    // 2. Phân quyền: Chỉ cho phép admin/manager của chi nhánh đó,
    // hoặc chính người bán đã tạo đơn đó xem bill
    const isOwner = order.seller_id === user.id;
    const isManager = (user.role === 'admin' || user.role === 'manager') && order.branch_code === user.branch_code;

    if (!isOwner && !isManager) {
      return res.status(403).send('Bạn không có quyền xem hóa đơn này.');
    }

    // 3. Lấy thông tin chi nhánh (từ config đã có trong server.js)
    const branchInfo = BRANCH_CONFIG[order.branch_code] || BRANCH_CONFIG['DEFAULT'];
    const { data: eventStatus } = await supabase
      .from('branch_event_status')
      .select('event_name, event_address, event_lead, qr_link_prefix')
      .eq('branch_code', order.branch_code)
      .single();
    // 4. Render trang in (một file ejs mới)
    res.render('event-bill', {
      order: order,
      items: order.event_order_items || [],
      branchInfo: branchInfo,
      eventStatus: eventStatus || {},
      // Helper function (truyền cho EJS)
      formatVND: (n) => new Intl.NumberFormat('vi-VN').format(Number(n || 0))
    });

  } catch (e) {
    console.error(`Lỗi /event-bill/${req.params.id}:`, e.message);
    res.status(500).send('Lỗi máy chủ khi tạo bill: ' + e.message);
  }
});

// ========================= ADMIN CÀI ĐẶT EVENT =========================

// [GET] Trang hiển thị cài đặt
app.get('/admin/event-settings', requireAuth, requireManager, async (req, res) => {
  try {
    // 1. Lấy danh sách chi nhánh TĨNH từ config
    const allBranches = Object.keys(BRANCH_CONFIG).filter(b => b !== 'DEFAULT');

    // 2. Lấy cài đặt event ĐỘNG từ DB
    const { data: eventSettings, error } = await supabase
      .from('branch_event_status')
      .select('*');
    if (error) throw error;

    // 3. Map cài đặt (động) vào danh sách (tĩnh)
    const settingsMap = new Map(eventSettings.map(s => [s.branch_code, s]));
    
    const branchData = allBranches.map(branchCode => {
      const settings = settingsMap.get(branchCode);
      return {
        branch_code: branchCode,
        branch_name: BRANCH_CONFIG[branchCode]?.name || branchCode,
        is_event_active: settings?.is_event_active || false,
        event_name: settings?.event_name || '',
        event_address: settings?.event_address || '',
        event_lead: settings?.event_lead || '',
        qr_link_prefix: settings?.qr_link_prefix || ''
      };
    });

    res.render('admin-event-settings', {
      title: 'Cài đặt Event',
      currentPage: 'event-settings', // Để active menu
      branchData: branchData,
      error: null
    });

  } catch (e) {
    console.error('Lỗi /admin/event-settings:', e.message);
    res.render('admin-event-settings', {
      title: 'Lỗi',
      currentPage: 'event-settings',
      branchData: [],
      error: e.message
    });
  }
});

// [POST] API để lưu cài đặt
app.post('/api/admin/event-settings/update', requireAuth, requireManager, async (req, res) => {
  try {
    const {
      branch_code,
      is_event_active,
      event_name,
      event_address,
      event_lead,
      qr_link_prefix
    } = req.body;

    if (!branch_code) {
      return res.status(400).json({ ok: false, error: 'Thiếu mã chi nhánh.' });
    }

    const payload = {
      branch_code: branch_code,
      is_event_active: !!is_event_active, // Ép kiểu về boolean
      event_name: event_name || null,
      event_address: event_address || null,
      event_lead: event_lead || null,
      qr_link_prefix: qr_link_prefix || null
    };

    // Dùng UPSERT:
    // - Nếu branch_code đã tồn tại -> Cập nhật
    // - Nếu chưa -> Tạo mới
    const { error } = await supabase
      .from('branch_event_status')
      .upsert(payload, { onConflict: 'branch_code' });

    if (error) throw error;

    res.json({ ok: true, message: `Đã cập nhật cho ${branch_code}` });

  } catch (e) {
    console.error('Lỗi API /api/admin/event-settings/update:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});


// ============================================================
// 1. API WORKLIST (ĐÃ FIX LỖI "GROUP BY AGGREGATION")
// ============================================================
app.get('/api/cskh/worklist', requireAuth, async (req, res) => {
    try {
        const user = req.session.user;
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const pageSize = 20; 
        const offset = (page - 1) * pageSize;
        
        const { sort, tax, status, month, branch, q, type, emp } = req.query;

        if (!bigquery) return res.json({ ok: false, error: 'No BigQuery' });

        // --- 1. Xử lý Thời gian ---
        const now = new Date();
        const currentMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
        
        let filterMonth = month;
        // Nếu search hoặc lọc nhân viên thì mặc định xem All time, ngược lại xem tháng này
        if (!filterMonth) {
            filterMonth = (q || emp) ? 'all' : currentMonth; 
        }

        let whereClause = 'WHERE 1=1';
        const params = { limit: pageSize, offset: offset, filterMonth: filterMonth };

        if (filterMonth !== 'all') {
            whereClause += ` AND FORMAT_DATE('%Y-%m', Report_date) = @filterMonth`;
        } else {
            if(type !== 'order_code') {
                whereClause += ` AND Report_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 12 MONTH)`;
            }
        }

        // --- 2. Phân quyền & Lọc ---
        const isGlobalAdmin = user.branch_code === 'HCM.BD';
        const isManager = user.role === 'manager' || user.role === 'admin' || isGlobalAdmin;

        if (isGlobalAdmin) { 
            if (branch && branch !== 'all') { whereClause += ` AND Branch_code = @branch`; params.branch = branch; }
        } else if (isManager) { 
            whereClause += ` AND Branch_code = @branch`; params.branch = user.branch_code;
        } else { 
            whereClause += ` AND LOWER(Email) = LOWER(@email)`; params.email = user.email; 
        }

        if (isManager && emp && emp.trim() !== '') {
            const { data: uData } = await supabase.from('users').select('email').eq('id', emp).single();
            if (uData) {
                whereClause += ` AND LOWER(Email) = LOWER(@targetEmail)`;
                params.targetEmail = uData.email;
            }
        }

        if (q && q.trim() !== '') {
            const keyword = q.trim();
            if (type === 'order_code') { whereClause += ` AND Order_code = @keyword`; params.keyword = keyword; } 
            else if (type === 'tax_code') { whereClause += ` AND Billing_tax_code LIKE @keyword`; params.keyword = `%${keyword}%`; } 
            else { whereClause += ` AND LOWER(Customer_full_name) LIKE LOWER(@keyword)`; params.keyword = `%${keyword}%`; }
        }

        if (tax === 'has_tax') whereClause += ` AND Billing_tax_code IS NOT NULL AND Billing_tax_code != ''`;
        else if (tax === 'no_tax') whereClause += ` AND (Billing_tax_code IS NULL OR Billing_tax_code = '')`;

        let orderBy = 'ORDER BY Total_Revenue DESC';
        if (sort === 'date_desc') orderBy = 'ORDER BY Max_Date DESC';
        if (sort === 'price_asc') orderBy = 'ORDER BY Total_Revenue ASC';
        if (sort === 'date_asc') orderBy = 'ORDER BY Max_Date ASC';

        const tableName = '`nimble-volt-459313-b8.sales.raw_sales_orders`';
        
        // --- QUERY FIX LỖI GROUP BY ---
        const query = `
            WITH OrderSummary AS (
                SELECT 
                    Order_code,
                    MAX(Customer_full_name) as Customer_full_name,
                    MAX(Billing_tax_code) as Billing_tax_code,
                    MAX(Report_date) as Report_date,
                    MAX(Branch_code) as Branch_code,
                    MAX(Email) as Sales_Email,
                    SUM(Revenue_with_VAT) as Order_Total_Val,
                    STRING_AGG(CONCAT('<span style="color:#2563eb; font-weight:700;">', CAST(SKU AS STRING), '</span> - ', SKU_name, ' <span style="color:#64748b;">(x', CAST(Quantity AS STRING), ')</span>'), '<br>') as Full_Product_Info,
                    ANY_VALUE(CAST(SKU AS STRING)) as SKU_Rep
                FROM ${tableName}
                ${whereClause}
                GROUP BY Order_code
            )
            SELECT
                -- [FIX] Bỏ hàm MAX() đi, lấy trực tiếp tên cột
                COALESCE(Customer_full_name, 'Khách lẻ') as Customer_Name,
                IFNULL(Billing_tax_code, '') as Tax_Code,
                
                COUNT(Order_code) as Order_Count,
                CAST(SUM(Order_Total_Val) AS FLOAT64) as Total_Revenue,
                MAX(Report_date) as Max_Date,
                ARRAY_AGG(STRUCT(
                    Order_code,
                    Report_date,
                    Branch_code,
                    Sales_Email,
                    CAST(Order_Total_Val AS FLOAT64) as Revenue,
                    SKU_Rep as SKU,
                    Full_Product_Info as Product_Display_Html, 
                    1 as Quantity
                )) as Orders
            FROM OrderSummary
            -- [FIX] Group by theo số thứ tự cột (1=Name, 2=TaxCode) cho an toàn
            GROUP BY 1, 2
            ${orderBy}
            LIMIT @limit OFFSET @offset
        `;

        const [rows] = await bigquery.query({ query, params });

        // --- Xử lý trạng thái (Giữ nguyên) ---
        if (rows.length > 0) {
            let allOrderCodes = [];
            rows.forEach(row => { if(row.Orders) row.Orders.forEach(o => allOrderCodes.push(o.Order_code)); });

            const { data: logs } = await supabase
                .from('customer_care_logs')
                .select('order_code, result')
                .in('order_code', allOrderCodes)
                .order('created_at', { ascending: false });

            const logMap = new Map();
            (logs || []).forEach(l => { if (!logMap.has(l.order_code)) logMap.set(l.order_code, l); });

            rows.forEach(customer => {
                let caredCount = 0;
                let hasClosedOrder = false;
                if(customer.Orders) {
                    customer.Orders = customer.Orders.map(o => {
                        let d = o.Report_date;
                        if (d && d.value) d = d.value;
                        const log = logMap.get(o.Order_code);
                        if(log) { caredCount++; if ((log.result||'').toLowerCase().includes('chốt')) hasClosedOrder = true; }
                        const status = log ? 'Đã chăm sóc' : 'Chưa chăm sóc';
                        const result = log?.result || '';
                        return { ...o, Report_date: d, status, result };
                    });
                }
                if (hasClosedOrder) customer.Care_Status = 'done';
                else if (caredCount > 0) customer.Care_Status = 'partial';
                else customer.Care_Status = 'uncared';

                if (status && status !== 'all') {
                    if (status === 'done' && customer.Care_Status !== 'done') customer.hidden = true;
                    if (status === 'caring' && customer.Care_Status !== 'partial') customer.hidden = true;
                    if (status === 'uncared' && customer.Care_Status !== 'uncared') customer.hidden = true;
                }
            });
            const filteredRows = rows.filter(r => !r.hidden);
            return res.json({ ok: true, data: filteredRows, page: page, month: filterMonth });
        }

        res.json({ ok: true, data: [], page: page, month: filterMonth });

    } catch (e) {
        console.error('[Worklist Error]', e);
        res.status(500).json({ ok: false, error: e.message });
    }
});

// --- ROUTE HIỂN THỊ TRANG CRM (ĐÃ FIX LỖI BIẾN branchStaffs) ---
app.get('/customer-care', requireAuth, async (req, res) => {
    try {
        const user = req.session.user;
        
        // 1. XÁC ĐỊNH QUYỀN
        const isGlobalAdmin = user.branch_code === 'HCM.BD';
        const isManager = user.role === 'manager' || user.role === 'admin' || isGlobalAdmin;

        // 2. BỘ LỌC THỜI GIAN
        const now = new Date();
        const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);
        
        const startDateRaw = req.query.start || firstDay.toISOString().split('T')[0];
        const endDateRaw = req.query.end || now.toISOString().split('T')[0];

        const startISO = new Date(startDateRaw).toISOString();
        const endDateObj = new Date(endDateRaw);
        endDateObj.setHours(23, 59, 59, 999);
        const endISO = endDateObj.toISOString();

        // 3. BỘ LỌC ĐỐI TƯỢNG
        let filterBranch = user.branch_code;
        let filterEmpId = null;

        if (isGlobalAdmin) filterBranch = req.query.branch || null; 
        if (isManager) filterEmpId = req.query.emp || null;
        else filterEmpId = user.id;

        // 4. TRUY VẤN DỮ LIỆU
        let baseQuery = supabase
            .from('customer_care_logs')
            .select(`
                revenue_at_care, result, order_code, created_at,
                created_by,
                users!inner(id, full_name, email, branch_code)
            `)
            .gte('created_at', startISO)
            .lte('created_at', endISO);

        if (filterBranch) baseQuery = baseQuery.eq('users.branch_code', filterBranch);
        if (filterEmpId) baseQuery = baseQuery.eq('created_by', filterEmpId);

        const { data: rawData, error } = await baseQuery;
        if (error) throw error;

        // 5. TÍNH TOÁN CHỈ SỐ
        let totalRevenue = 0;
        let uniqueOrders = new Set();
        let closedCount = 0;
        let matrixData = {}; 
        let userTotalMap = {}; 
        let allResultTypes = new Set();

        (rawData || []).forEach(log => {
            const rev = Number(log.revenue_at_care) || 0;
            const result = log.result || 'Khác';
            const u = log.users;
            
            totalRevenue += rev;
            uniqueOrders.add(log.order_code);
            if (result.toLowerCase().includes('chốt')) closedCount++;

            const branch = u.branch_code || 'Unknown';
            const uid = u.id;

            // Ranking
            if (!userTotalMap[uid]) userTotalMap[uid] = { id: uid, name: u.full_name || u.email, branch: branch, total: 0 };
            userTotalMap[uid].total += rev;

            // Matrix
            if (!matrixData[branch]) matrixData[branch] = {};
            if (!matrixData[branch][uid]) matrixData[branch][uid] = { name: u.full_name || u.email, total_care: 0, total_revenue: 0, results: {} };
            
            const salesman = matrixData[branch][uid];
            salesman.total_care += 1;
            salesman.total_revenue += rev;
            salesman.results[result] = (salesman.results[result] || 0) + 1;
            allResultTypes.add(result);
        });

        const rankingList = Object.values(userTotalMap).sort((a, b) => b.total - a.total);
        
        let currentRank = '--';
        const targetRankId = filterEmpId || user.id;
        const rankIdx = rankingList.findIndex(x => x.id === targetRankId);
        if (rankIdx !== -1) currentRank = `#${rankIdx + 1}`;

        const resultColumns = Array.from(allResultTypes).sort((a, b) => {
            if (a.includes('Chốt')) return -1;
            return a.localeCompare(b);
        });

        // 6. LẤY DANH SÁCH NHÂN VIÊN
        let staffList = [];
        let branchList = [];

        if (isManager) {
            if (isGlobalAdmin) {
                const { data: branches } = await supabase.from('users').select('branch_code').neq('branch_code', null);
                branchList = [...new Set((branches||[]).map(b=>b.branch_code))].sort();
            }
            
            let staffQuery = supabase.from('users').select('id, email, full_name, branch_code').eq('role', 'staff');
            if (filterBranch) staffQuery = staffQuery.eq('branch_code', filterBranch);
            
            const { data: staffs } = await staffQuery;
            staffList = staffs || [];
        }

        // 7. RENDER (SỬA LỖI TẠI ĐÂY: mapping staffList -> branchStaffs)
        res.render('customer-care', {
            title: 'Chăm sóc khách hàng',
            currentPage: 'customer-care',
            user: user,
            
            isGlobalAdmin,
            isManager,
            branchList,
            branchStaffs: staffList, // <--- QUAN TRỌNG: Đổi tên biến này cho khớp với EJS
            
            filters: {
                start: startDateRaw,
                end: endDateRaw,
                branch: filterBranch,
                emp: filterEmpId
            },

            dashboard: {
                revenue: totalRevenue,
                cared_count: uniqueOrders.size,
                closed_count: closedCount,
                rank: currentRank,
                ranking_list: rankingList,
                matrix_data: matrixData,
                result_columns: resultColumns
            }
        });

    } catch (e) {
        console.error(e);
        res.render('customer-care', { 
            title: 'Lỗi', currentPage: 'customer-care', 
            user: req.session.user, isGlobalAdmin: false, isManager: false,
            branchList:[], branchStaffs: [], filters: {}, dashboard: {}, 
            error: e.message 
        });
    }
});



// ============================================================
// 2. API SEARCH (ĐÃ FIX LỖI GROUP BY)
// ============================================================
app.get('/api/cskh/search', requireAuth, async (req, res) => {
    try {
        const { q, type, filterEmail, page } = req.query;
        const user = req.session.user;
        
        const currentPage = Math.max(1, parseInt(page) || 1);
        const pageSize = 10;
        const offset = (currentPage - 1) * pageSize;

        if (!bigquery) return res.json({ ok: false, error: 'Chưa kết nối BigQuery' });

        const isManager = user.role === 'manager' || user.role === 'admin' || user.branch_code === 'HCM.BD';
        const isGlobalAdmin = user.branch_code === 'HCM.BD';
        
        let permissionClause = '';
        const params = { 
            query: type !== 'order_code' ? `%${q || ''}%` : (q || ''),
            userBranch: user.branch_code,
            limit: pageSize,
            offset: offset
        };

        if (!isGlobalAdmin) permissionClause += ` AND Branch_code = @userBranch`;

        if (isManager) {
            if (filterEmail && filterEmail.trim() !== '') {
                permissionClause += ` AND LOWER(Email) = LOWER(@targetEmail)`;
                params.targetEmail = filterEmail;
            }
        } else {
            permissionClause += ` AND LOWER(Email) = LOWER(@myEmail)`;
            params.myEmail = user.email;
        }

        let searchClause = '';
        if (q) {
            if (type === 'order_code') searchClause = `AND Order_code = @query`;
            else if (type === 'tax_code') searchClause = `AND Billing_tax_code LIKE @query`;
            else searchClause = `AND LOWER(Customer_full_name) LIKE LOWER(@query)`;
        }

        const tableName = '`nimble-volt-459313-b8.sales.raw_sales_orders`'; 
        
        const query = `
            WITH OrderSummary AS (
                SELECT 
                    Order_code,
                    MAX(Customer_full_name) as Customer_full_name,
                    MAX(Billing_tax_code) as Billing_tax_code,
                    MAX(Branch_code) as Branch_code,
                    MAX(Email) as Email,
                    MAX(Report_date) as Report_date,
                    MAX(Branch_code) as Branch_code,
                    MAX(Email) as Sales_Email,
                    SUM(Revenue_with_VAT) as Order_Total_Val,
                    STRING_AGG(CONCAT('<span style="color:#2563eb; font-weight:700;">', CAST(SKU AS STRING), '</span> - ', SKU_name, ' <span style="color:#64748b;">(x', CAST(Quantity AS STRING), ')</span>'), '<br>') as Full_Product_Info,
                    ANY_VALUE(CAST(SKU AS STRING)) as SKU_Rep
                FROM ${tableName}
                WHERE 1=1
                ${permissionClause} 
                ${searchClause}
                GROUP BY Order_code
            )
            SELECT
                -- [FIX] Bỏ MAX()
                COALESCE(Customer_full_name, 'Khách lẻ') as Customer_Name,
                IFNULL(Billing_tax_code, '') as Tax_Code,
                ANY_VALUE(Branch_code) as Branch_Code,
                ANY_VALUE(Email) as Sales_Email,
                
                COUNT(Order_code) as Order_Count,
                CAST(SUM(Order_Total_Val) AS FLOAT64) as Total_Revenue,
                MAX(Report_date) as Max_Date,
                
                ARRAY_AGG(STRUCT(
                    Order_code,
                    Report_date,
                    Branch_code,
                    Sales_Email,
                    CAST(Order_Total_Val AS FLOAT64) as Revenue,
                    SKU_Rep as SKU,
                    Full_Product_Info as Product_Display_Html, 
                    1 as Quantity
                )) as Orders
            FROM OrderSummary
            -- [FIX] Group by 1, 2 (Tên, MST)
            GROUP BY 1, 2
            ORDER BY Max_Date DESC
            LIMIT @limit OFFSET @offset
        `;

        const [rows] = await bigquery.query({ query, params });

        // Logic ghép trạng thái
        if (rows.length > 0) {
            let allOrderCodes = [];
            rows.forEach(row => { if(row.Orders) row.Orders.forEach(o => allOrderCodes.push(o.Order_code)); });

            const { data: logs } = await supabase
                .from('customer_care_logs')
                .select('order_code, result')
                .in('order_code', allOrderCodes)
                .order('created_at', { ascending: false });

            const logMap = new Map();
            (logs || []).forEach(l => { if (!logMap.has(l.order_code)) logMap.set(l.order_code, l); });

            rows.forEach(customer => {
                let caredCount = 0;
                if(customer.Orders) {
                    customer.Orders = customer.Orders.map(o => {
                        let d = o.Report_date;
                        if (d && d.value) d = d.value;
                        const log = logMap.get(o.Order_code);
                        if(log) caredCount++;
                        const status = log ? 'Đã chăm sóc' : 'Chưa chăm sóc';
                        const result = log?.result || '';
                        return { ...o, Report_date: d, status, result };
                    });
                }
                if (caredCount === 0) customer.Care_Status = 'uncared';
                else if (caredCount < customer.Order_Count) customer.Care_Status = 'partial';
                else customer.Care_Status = 'done';
            });
        }

        res.json({ ok: true, data: rows, page: currentPage });

    } catch (e) {
        console.error('Search Error:', e);
        res.status(500).json({ ok: false, error: e.message });
    }
});


// 3. API Lưu log chăm sóc (POST) - Chỉ lưu Supabase
app.post('/api/cskh/log', requireAuth, async (req, res) => {
    try {
        const { 
            order_code, customer_name, phone, care_stage, 
            contact_method, result, note, revenue, next_date 
        } = req.body;

        const { error } = await supabase.from('customer_care_logs').insert({
            order_code,
            customer_full_name: customer_name,
            phone_number: phone,
            care_stage,
            contact_method,
            result,
            sale_note: note,
            revenue_at_care: Number(revenue) || 0,
            next_action_date: next_date || null,
            created_by: req.session.user.id
        });

        if (error) throw error;
        res.json({ ok: true, message: 'Đã lưu thông tin chăm sóc!' });
    } catch (e) {
        res.status(500).json({ ok: false, error: e.message });
    }
});

// 4. API Lấy lịch sử chăm sóc (GET)
app.get('/api/cskh/history/:orderCode', requireAuth, async (req, res) => {
    try {
        const { data } = await supabase
            .from('customer_care_logs')
            .select(`*, users:created_by(full_name)`)
            .eq('order_code', req.params.orderCode)
            .order('created_at', { ascending: false });
        
        res.json({ ok: true, data: data || [] });
    } catch(e) {
        res.status(500).json({ ok: false, error: e.message });
    }
});

/* ==========================================================================
   MODULE: DASHBOARD PROFILE & PERFORMANCE
   ========================================================================== */
const HR_SPREADSHEET_ID = '1pUCXps6-p7_aJe9oMGpGLFM5oMuDiyiC5BXAZoOWxP0';

function getDateFilterCondition(period) {
    const now = new Date();
    let startDate, endDate;
    let label = '';
    
    const daysInCurrentMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate(); 

    // Regex kiểm tra định dạng YYYY-MM (Ví dụ: 2025-11)
    const monthRegex = /^\d{4}-\d{2}$/;

    if (monthRegex.test(period)) {
        // [FIX] Logic lọc theo tháng cụ thể từ Input Picker
        const [year, month] = period.split('-').map(Number);
        startDate = new Date(year, month - 1, 1); // Ngày đầu tháng
        endDate = new Date(year, month, 0);       // Ngày cuối tháng
        label = `Tháng ${month}/${year}`;
    } 
    else if (!period || period === 'month') {
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        label = `Tháng ${now.getMonth() + 1}/${now.getFullYear()}`;
    } 
    else if (period === 'today') {
        startDate = now;
        endDate = now;
        label = 'Hôm nay';
    } 
    else if (period === 'week') {
        const day = now.getDay() || 7; 
        if (day !== 1) now.setHours(-24 * (day - 1));
        startDate = new Date(now);
        endDate = new Date(now);
        endDate.setDate(startDate.getDate() + 6);
        label = 'Tuần này';
    } 
    else if (period === 'year') {
        startDate = new Date(now.getFullYear(), 0, 1);
        endDate = new Date(now.getFullYear(), 11, 31);
        label = `Năm ${now.getFullYear()}`;
    }

    const toSQLDate = (d) => {
        const offset = d.getTimezoneOffset() * 60000;
        return new Date(d.getTime() - offset).toISOString().slice(0, 10);
    };

    // Tính Scale Factor
    let scaleFactor = 1;
    if (period === 'year') {
        scaleFactor = 12;
    } else if (period === 'today' || period === 'week') {
        const diffTime = Math.abs(endDate - startDate);
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1; 
        scaleFactor = diffDays / daysInCurrentMonth;
    }

    return { 
        start: toSQLDate(startDate), 
        end: toSQLDate(endDate),
        label,
        scaleFactor
    };
}

// --- [HELPER QUAN TRỌNG] Lấy Target Chi Nhánh từ Sheet ---
async function getAllBranchTargets(periodInput) {
    try {
        const sheets = await getGlobalSheetsClient();
        const range = 'Sheet3!A:O'; 
        
        const response = await sheets.spreadsheets.values.get({ spreadsheetId: HR_SPREADSHEET_ID, range });
        const rows = response.data.values;
        if (!rows || rows.length === 0) return {};

        const targetMap = {}; 

        // Bỏ qua header, duyệt từng dòng
        for (let i = 1; i < rows.length; i++) {
            const row = rows[i];
            const branchCode = (row[0] || '').trim().toUpperCase();
            
            // [FIX QUAN TRỌNG] Bỏ qua dòng rỗng hoặc dòng TOTAL để tránh cộng gấp đôi
            if (!branchCode || branchCode === 'TOTAL' || branchCode === 'GRAND TOTAL') continue;

            const headcount = parseFloat((row[2] || '1').replace(',', '.')) || 1;
            let totalBranchTarget = 0;

            if (periodInput === 'year') {
                // Cộng dồn T1 -> T12
                for (let j = 3; j <= 14; j++) {
                    const rawVal = row[j] || '0';
                    const val = parseFloat(rawVal.replace(/\./g, '').replace(',', '.')) * 1_000_000_000;
                    totalBranchTarget += val;
                }
            } else {
                // Lấy theo tháng
                const monthIndex = parseInt(periodInput); 
                const targetColIndex = 3 + monthIndex;
                const rawVal = row[targetColIndex] || '0';
                totalBranchTarget = parseFloat(rawVal.replace(/\./g, '').replace(',', '.')) * 1_000_000_000;
            }

            targetMap[branchCode] = {
                branch_target: totalBranchTarget,
                headcount: headcount,
                individual_target: totalBranchTarget / headcount
            };
        }

        return targetMap; 

    } catch (e) {
        console.error("Lỗi Bulk Target:", e.message);
        return {};
    }
}


// --- [HELPER] Lấy toàn bộ nhân sự từ Google Sheet ---
async function getAllEmployeesFromSheet() {
    const range = 'Sheet1!A:J'; // Tab employee
    try {
        const sheets = await getGlobalSheetsClient();
        const response = await sheets.spreadsheets.values.get({ spreadsheetId: HR_SPREADSHEET_ID, range });
        const rows = response.data.values;
        if (!rows) return {};

        const map = {};
        for (let i = 1; i < rows.length; i++) {
            const row = rows[i];
            const email = (row[1] || '').toLowerCase().trim();
            if (email) {
                map[email] = {
                    hrm_id: row[0],
                    full_name: row[2],
                    branch: row[3], 
                    position: row[7],
                    dob: row[8],
                    join_date: row[9]
                };
            }
        }
        return map;
    } catch (e) { console.error("Sheet Error:", e.message); return {}; }
}

// --- [HELPER] BigQuery: Lấy số liệu (Core Logic) ---
async function getPerformanceStats(options) {
    const { email, branch, period, groupBy } = options; 
    const dateFilter = getDateFilterCondition(period);

    const queryParams = {
        startDate: dateFilter.start,
        endDate: dateFilter.end
    };

    let whereClause = `WHERE Report_date BETWEEN @startDate AND @endDate`;
    
    // 1. Lọc theo Email
    if (email) {
        whereClause += ` AND LOWER(Email) = LOWER(@email)`;
        queryParams.email = email;
    }

    // 2. Lọc theo Branch (HCM.BD xem all)
    if (branch && branch !== 'HCM.BD') {
        whereClause += ` AND Branch_code = @branch`;
        queryParams.branch = branch;
    }

    // 3. Select & Group By
    let selectClause = '';
    let groupByClause = '';
    
    if (groupBy === 'email') {
        selectClause = 'LOWER(Email) as key_id, ANY_VALUE(Customer_full_name) as name,'; 
        groupByClause = 'GROUP BY 1';
    } else if (groupBy === 'branch') {
        selectClause = 'Branch_code as key_id,';
        groupByClause = 'GROUP BY 1';
    } else {
        selectClause = "'Total' as key_id,";
        groupByClause = 'GROUP BY 1';
    }

    // 4. Query (Tổng đơn = Bán - Hoàn)
    const query = `
        SELECT 
            ${selectClause}
            
            (COUNT(DISTINCT CASE WHEN Revenue_with_VAT >= 0 THEN Order_code END) - 
             COUNT(DISTINCT CASE WHEN Revenue_with_VAT < 0 THEN Order_code END)) as total_orders,

            IFNULL(SUM(Revenue), 0) as total_revenue, 
            IFNULL(SUM(Sale_point), 0) as total_kfi
        FROM \`nimble-volt-459313-b8.sales.raw_sales_orders\`
        ${whereClause}
        ${groupByClause}
    `;

    try {
        // console.log(`[BQ] Querying: ${dateFilter.start} to ${dateFilter.end}`);
        const [rows] = await bigquery.query({ query, params: queryParams });
        
        if (!groupBy) return rows[0] || { total_revenue: 0, total_orders: 0, total_kfi: 0 };
        return rows;
    } catch (e) {
        console.error("BQ Error:", e.message);
        return !groupBy ? { total_revenue: 0, total_orders: 0, total_kfi: 0 } : [];
    }
}

// --- [HELPER] Tính toán Thưởng ---
function calculateBonusMetrics(stats, target, isSalesPerson) {
    const revenue = stats.total_revenue || 0;
    const kfi = stats.total_kfi || 0;
    let percent = 0;
    let missing = 0;
    let bonus_total = 0;
    let bonus_over = 0;

    if (target > 0) {
        percent = (revenue / target) * 100;
        missing = Math.max(0, target - revenue);

        if (isSalesPerson) {
            const cappedPercent = Math.min(percent, 120) / 100;
            
            // [FIX YÊU CẦU 2] Thưởng KPI: Nhân 1000 và làm tròn
            // KFI (điểm) * %HT * 1000 (quy đổi ra tiền)
            bonus_total = Math.round(kfi * cappedPercent * 1000);

            // [FIX YÊU CẦU 3] Thưởng Vượt: Làm tròn số nguyên
            if (percent > 120) {
                const overAmount = revenue - (target * 1.2);
                // 0.1% của doanh thu vượt
                bonus_over = Math.round(overAmount * 0.001); 
            }
        }
    }

    return {
        orders: stats.total_orders || 0,
        revenue,
        kfi,
        target,
        percent_completion: percent.toFixed(1),
        missing,
        bonus_total,
        bonus_over
    };
}

function calculateForecast(revenue, target, period) {
    const now = new Date();
    const currentDay = now.getDate();
    const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
    
    let revenueForecast = 0;
    let percentForecast = 0;

    // Chỉ dự báo nếu đang xem "Tháng này" và chưa hết tháng
    if (period === 'month' && currentDay < daysInMonth) {
        // Công thức: (Rev / Ngày hiện tại) * Tổng ngày
        revenueForecast = (revenue / currentDay) * daysInMonth;
    } else {
        revenueForecast = revenue; // Hết tháng hoặc xem quá khứ thì Forecast = Thực tế
    }

    if (target > 0) {
        percentForecast = (revenueForecast / target) * 100;
    }

    return {
        revenue_forecast: revenueForecast,
        percent_forecast: percentForecast.toFixed(1)
    };
}


// --- [ROUTE] PAGE PROFILE (FINAL) ---
app.get('/profile', requireAuth, async (req, res) => {
    try {
        const user = req.session.user;
        const period = req.query.period || 'month'; 
        const filterBranch = req.query.branch || ''; 
        const dateInfo = getDateFilterCondition(period);
        
        // Xác định tham số thời gian cho Target
        let targetPeriodParam = new Date().getMonth(); 
        if (period === 'year') targetPeriodParam = 'year';
        else if (/^\d{4}-\d{2}$/.test(period)) targetPeriodParam = parseInt(period.split('-')[1]) - 1;
        else if (period === 'today' || period === 'week') targetPeriodParam = new Date().getMonth(); 

        const isGlobalAdmin = (user.role === 'admin' || user.role === 'manager') && user.branch_code === 'HCM.BD';
        const isManager = user.role === 'manager' && !isGlobalAdmin;
        const isStaff = !isGlobalAdmin && !isManager;

        // 1. Lấy Info NV (1 Request)
        const empMap = await getAllEmployeesFromSheet();
        
        // 2. Lấy Info User (1 Request DB)
        const myProfile = empMap[user.email.toLowerCase()] || { full_name: user.full_name, branch: user.branch_code, hrm_id: '---', position: 'N/A' };
        const { data: userData } = await supabase.from('users').select('last_seen').eq('id', user.id).single();
        const lastSeen = userData?.last_seen ? new Date(userData.last_seen).toLocaleString('vi-VN') : 'N/A';
        
        // 3. Lấy Target TẤT CẢ Chi Nhánh (CHỈ 1 REQUEST DUY NHẤT)
        // Thay vì gọi nhiều lần, ta gọi 1 lần rồi tra cứu
        const allTargetsMap = await getAllBranchTargets(targetPeriodParam);

        // 4. Scale Target
        let scale = 1;
        if (period === 'today' || period === 'week') scale = dateInfo.scaleFactor;

        // 5. Xác định Target cơ sở cho Card Dashboard
        let baseTargetData = { branch_target: 0, individual_target: 0 };
        
        if (isGlobalAdmin && !filterBranch) {
            // Admin xem All: Cộng tổng từ Map
            let totalSystem = 0;
            Object.values(allTargetsMap).forEach(t => totalSystem += t.branch_target);
            baseTargetData.branch_target = totalSystem;
        } else {
            // Xem 1 Branch hoặc Cá nhân: Tra cứu từ Map
            let targetCode = filterBranch || user.branch_code;
            if (allTargetsMap[targetCode]) {
                baseTargetData = allTargetsMap[targetCode];
            }
        }

        const finalTarget = baseTargetData.branch_target * scale;
        const finalIndTarget = baseTargetData.individual_target * scale;

        // 6. Xử lý dữ liệu
        let dashboardData = {};
        let tableSales = [];
        let tableBranch = [];

        if (isStaff) {
            const stats = await getPerformanceStats({ email: user.email, period });
            dashboardData = calculateBonusMetrics(stats, finalIndTarget, true);
        } 
        else if (isManager || (isGlobalAdmin && filterBranch)) {
            let targetCode = filterBranch || user.branch_code;
            
            const branchStats = await getPerformanceStats({ branch: targetCode, period });
            dashboardData = calculateBonusMetrics(branchStats, finalTarget, false);

            const salesStats = await getPerformanceStats({ branch: targetCode, period, groupBy: 'email' });
            tableSales = salesStats.map(s => {
                const info = empMap[s.key_id] || { full_name: s.name, hrm_id: '' };
                if (!(info.position || '').toLowerCase().includes('bán hàng')) return null;
                return {
                    salesman: info.full_name, msnv: info.hrm_id,
                    ...calculateBonusMetrics(s, finalIndTarget, true)
                };
            }).filter(Boolean).sort((a,b) => b.revenue - a.revenue);
        } 
        else if (isGlobalAdmin && !filterBranch) {
            const globalStats = await getPerformanceStats({ branch: 'HCM.BD', period });
            dashboardData = calculateBonusMetrics(globalStats, finalTarget, false);

            // --- BẢNG BRANCH: TRA CỨU TỪ MAP (KHÔNG GỌI API) ---
            const branchStats = await getPerformanceStats({ branch: 'HCM.BD', period, groupBy: 'branch' });
            tableBranch = branchStats.map(b => {
                // Tra cứu target từ biến allTargetsMap đã lấy ở trên
                const tData = allTargetsMap[b.key_id]; 
                const bTarget = (tData ? tData.branch_target : 0) * scale;
                
                const metrics = calculateBonusMetrics(b, bTarget, false);
                const forecast = calculateForecast(metrics.revenue, bTarget, period);
                return { branch: b.key_id, ...metrics, ...forecast };
            }).sort((a,b) => b.revenue - a.revenue);

            // --- BẢNG SALES: TRA CỨU TỪ MAP ---
            const allSalesStats = await getPerformanceStats({ branch: 'HCM.BD', period, groupBy: 'email' });
            tableSales = allSalesStats.map(s => {
                const info = empMap[s.key_id] || {};
                if (!(info.position || '').toLowerCase().includes('bán hàng')) return null;
                
                // Tra cứu target cá nhân dựa theo Branch của nhân viên đó
                let sTarget = 0;
                if (info.branch && allTargetsMap[info.branch]) {
                    sTarget = allTargetsMap[info.branch].individual_target * scale;
                }

                return {
                    branch: info.branch, salesman: info.full_name, msnv: info.hrm_id,
                    ...calculateBonusMetrics(s, sTarget, true)
                };
            }).filter(Boolean).sort((a,b) => b.revenue - a.revenue).slice(0, 100);
        }

        const mainForecast = calculateForecast(dashboardData.revenue, finalTarget, period);
        dashboardData.revenue_forecast = mainForecast.revenue_forecast;
        dashboardData.percent_forecast = mainForecast.percent_forecast;

        // Format compact helper
        const formatCompact = (num) => {
            if (!num) return '0';
            const n = Number(num);
            if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(2).replace(/\.00$/, '') + ' Tỷ';
            if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + ' Tr';
            if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\.0$/, '') + ' K';
            return new Intl.NumberFormat('vi-VN').format(n);
        };

        res.render('profile', {
            title: 'Dashboard Hiệu Suất', currentPage: 'profile', user,
            role: { isStaff, isManager, isGlobalAdmin },
            period: { value: period, label: dateInfo.label },
            filterBranch, 
            // Chỉ lấy list branch có trong DB Target để hiển thị dropdown cho đẹp
            branchList: Object.keys(allTargetsMap).sort(), 
            profile: myProfile, onlineTime: lastSeen,
            dashboard: dashboardData, tableSales, tableBranch, formatCompact
        });

    } catch (e) { console.error("Profile Error:", e); res.status(500).send(e.message); }
});


async function syncClearanceData() {
    console.log('[CRON] Bắt đầu đồng bộ dữ liệu Thanh lý từ Sheet...');
    try {
        // 1. Lấy dữ liệu từ Sheet (Sử dụng hàm getAllClearanceItems cũ nhưng chỉnh lại chút để lấy raw data)
        const items = await getAllClearanceItems(true); // true = mode sync (raw data)
        
        if (!items || items.length === 0) {
            console.log('[CRON] Không có dữ liệu từ Sheet.');
            return;
        }

        // 2. Xóa dữ liệu cũ
        const { error: delError } = await supabase.from('clearance_items').delete().neq('id', 0); // Xóa hết
        if (delError) throw delError;

        // 3. Insert dữ liệu mới (Chia batch để tránh lỗi payload quá lớn)
        const BATCH_SIZE = 500;
        for (let i = 0; i < items.length; i += BATCH_SIZE) {
            const batch = items.slice(i, i + BATCH_SIZE);
            const { error: insError } = await supabase.from('clearance_items').insert(batch);
            if (insError) throw insError;
        }

        console.log(`[CRON] Đồng bộ thành công ${items.length} sản phẩm thanh lý vào Supabase lúc ${new Date().toLocaleString()}`);
    } catch (e) {
        console.error('[CRON] Lỗi đồng bộ thanh lý:', e.message);
    }
}

// --- LÊN LỊCH CRON (8h00 và 14h00 mỗi ngày) ---
// Format: Phút Giờ Ngày Tháng Thứ
cron.schedule('0 8 * * *', () => syncClearanceData(), { timezone: "Asia/Ho_Chi_Minh" });
cron.schedule('0 14 * * *', () => syncClearanceData(), { timezone: "Asia/Ho_Chi_Minh" });

// (Optional) Route để kích hoạt bằng tay nếu cần gấp: /api/admin/sync-clearance
app.get('/api/admin/sync-clearance', requireAuth, requireManager, async (req, res) => {
    await syncClearanceData();
    res.json({ ok: true, message: 'Đã kích hoạt đồng bộ ngầm.' });
});

// ============================================================
// ROUTE CRON JOB CHO VERCEL (KHÔNG CẦN LOGIN, CẦN KEY)
// ============================================================
app.get('/api/cron/sync-clearance', async (req, res) => {
    // 1. Bảo mật: Kiểm tra Cron Secret (Cấu hình trong Env Vercel)
    // Vercel sẽ tự động gửi header 'authorization' chứa CRON_SECRET
    const authHeader = req.headers['authorization'];
    const cronSecret = process.env.CRON_SECRET;

    // Nếu chạy test tay thì có thể dùng query param ?key=...
    const queryKey = req.query.key;

    if (
        (!authHeader || authHeader !== `Bearer ${cronSecret}`) && 
        (!queryKey || queryKey !== cronSecret)
    ) {
        return res.status(401).json({ ok: false, error: 'Unauthorized Cron Request' });
    }

    try {
        console.log('[VERCEL CRON] Bắt đầu đồng bộ Thanh lý...');
        await syncClearanceData(); // Gọi hàm đồng bộ có sẵn
        res.json({ ok: true, message: 'Đồng bộ thành công (Vercel Cron)' });
    } catch (e) {
        console.error('[VERCEL CRON] Lỗi:', e);
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
