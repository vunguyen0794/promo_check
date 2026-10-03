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
let _googleInstance = null;
const google = new Proxy({}, {
  get(target, prop) {
    if (!_googleInstance) {
      _googleInstance = require('googleapis').google;
    }
    return _googleInstance[prop];
  }
});

const fs = require('fs');
const { BigQuery } = require('@google-cloud/bigquery');
let _mailerModule = null;
function sendNewPostEmail(...args) {
  if (!_mailerModule) _mailerModule = require('./utils/mailer');
  return _mailerModule.sendNewPostEmail(...args);
}
const ejs = require('ejs');
let _chromiumInstance = null;
const chromium = new Proxy({}, {
  get(target, prop) {
    if (!_chromiumInstance) {
      _chromiumInstance = require('@sparticuz/chromium');
    }
    return _chromiumInstance[prop];
  }
});
let _puppeteerCoreInstance = null;
const puppeteerCore = new Proxy({}, {
  get(target, prop) {
    if (!_puppeteerCoreInstance) {
      _puppeteerCoreInstance = require('puppeteer-core');
    }
    return _puppeteerCoreInstance[prop];
  }
});

let _puppeteerInstance = null;
const puppeteer = new Proxy({}, {
  get(target, prop) {
    if (!_puppeteerInstance) {
      _puppeteerInstance = require('puppeteer');
    }
    return _puppeteerInstance[prop];
  }
});
const { Readable, PassThrough } = require('stream');
const cron = require('node-cron');
const { getOrSyncProductData } = require('./utils/teko_product_service');

let _nodemailerInstance = null;
const nodemailer = new Proxy({}, {
  get(target, prop) {
    if (!_nodemailerInstance) {
      _nodemailerInstance = require('nodemailer');
    }
    return _nodemailerInstance[prop];
  }
});
const crypto = require('crypto'); // Có sẵn trong Node.js
const { syncInventory } = require('./sync_inventory'); // IMPORT SCRIPT SYNC
const { syncPromotions } = require('./utils/sync_promotions'); // IMPORT GOOGLE SHEET SYNC

const isVercel = !!process.env.VERCEL;

// ------------------------- Supabase -------------------------
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey =
  process.env.SUPABASE_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_ANON_KEY;

const supabase = createClient(supabaseUrl, supabaseKey);

const parseToArray = v => Array.isArray(v) ? v : (v == null || v === '' ? [] : [v]);
const parseSkus = v => {
  if (!v) return [];
  // Dùng regex /[,\n\r\s]+/ cho cả hai trường hợp
  if (Array.isArray(v)) return v.flatMap(x => String(x).split(/[,\n\r\s]+/)).map(s => s.trim()).filter(Boolean);
  return String(v).split(/[,\n\r\s]+/).map(s => s.trim()).filter(Boolean);
};

// ------------------------- BigQuery Client -------------------------
let _bigqueryInstance = null;
function getBigQueryInstance() {
  if (!_bigqueryInstance) {
    try {
      const { BigQuery } = require('@google-cloud/bigquery');
      const keyFile = process.env.BIGQUERY_KEY_FILE;
      if (keyFile && fs.existsSync(keyFile)) {
        _bigqueryInstance = new BigQuery({ keyFilename: keyFile });
      } else if (process.env.BIGQUERY_KEY_JSON) {
        let jsonStr = String(process.env.BIGQUERY_KEY_JSON).replace(/\\n/g, '\n');
        _bigqueryInstance = new BigQuery({ credentials: JSON.parse(jsonStr) });
      }
    } catch (e) {
      console.error("LỖI KHỞI TẠO BIGQUERY:", e.message);
    }
  }
  return _bigqueryInstance;
}
const bigquery = new Proxy({}, {
  get(target, prop) {
    const instance = getBigQueryInstance();
    if (!instance) return undefined;
    return typeof instance[prop] === 'function' ? instance[prop].bind(instance) : instance[prop];
  }
});

// === CÀI ĐẶT LỊCH SYNC TỰ ĐỘNG (7:30 AM Giờ Việt Nam) ===
// '30 7 * * *' chạy vào 7:30 mỗi ngày. 
// Nếu server chạy giờ UTC (thường là vậy), 7:30 VN = 00:30 UTC. 
// Ta cấu hình linh hoạt hoặc dùng timezone.
cron.schedule('30 7 * * *', () => {
  console.log("[CRON] Bắt đầu đồng bộ định kỳ dữ liệu BQ -> Supabase (07:30 AM)...");
  syncInventory();
}, {
  scheduled: true,
  timezone: "Asia/Ho_Chi_Minh"
});

// -------------------------------------------------------------------

const CSI_BIGQUERY_SOURCES = (
  process.env.BIGQUERY_CSI_TABLES ||
  process.env.BIGQUERY_CSI_TABLE ||
  'nimble-volt-459313-b8.sales.view_csi_final'
)
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

let csiSourceCachePromise = null;

async function resolveCsiSourceTable() {
  if (!bigquery) return null;
  if (!csiSourceCachePromise) {
    csiSourceCachePromise = (async () => {
      for (const source of CSI_BIGQUERY_SOURCES) {
        const clean = source.replace(/`/g, '');
        const parts = clean.split('.');
        if (parts.length !== 3) continue;
        const [, datasetId, tableId] = parts;
        try {
          const [exists] = await bigquery.dataset(datasetId).table(tableId).exists();
          if (exists) return clean;
        } catch (_) {
          // Bỏ qua candidate lỗi và thử candidate tiếp theo.
        }
      }
      console.warn(`[CSI] Không tìm thấy nguồn BigQuery hợp lệ. Candidates: ${CSI_BIGQUERY_SOURCES.join(', ')}`);
      return null;
    })();
  }
  return csiSourceCachePromise;
}



// ------------------------- App & core middlewares -------------------------
const app = express();

// Safeguard: chuyển hướng nếu request trỏ nhầm file server
app.use((req, res, next) => {
  if (req.url === '/server.js' || req.path === '/server.js' || req.url === '/api/index.js' || req.path === '/api/index.js') {
    return res.redirect('/');
  }
  next();
});

function numberToWords(n) {
    if (n === 0) return 'không đồng';
    const numStr = n.toString();
    const th = ['','nghìn','triệu','tỷ','nghìn tỷ','triệu tỷ'];
    const units = ['không','một','hai','ba','bốn','năm','sáu','bảy','tám','chín'];
    
    function doc3So(n, docKhong) {
        let str = '';
        const tram = Math.floor(n / 100);
        const chuc = Math.floor((n % 100) / 10);
        const donvi = n % 10;
        
        if (tram > 0 || docKhong) {
            str += units[tram] + ' trăm ';
        }
        if (chuc === 0 && donvi > 0 && (tram > 0 || docKhong)) {
            str += 'lẻ ';
        }
        if (chuc > 1) {
            str += units[chuc] + ' mươi ';
            if (donvi === 1) str += 'mốt ';
        } else if (chuc === 1) {
            str += 'mười ';
            if (donvi === 1) str += 'một ';
        }
        
        if (chuc !== 1 && donvi === 1 && chuc !== 0) { }
        else if (donvi === 5 && chuc !== 0) str += 'lăm ';
        else if (donvi > 0 && !(chuc > 1 && donvi === 1)) str += units[donvi] + ' ';
        
        return str.trim();
    }
    
    let str = '';
    let blocks = [];
    let temp = n;
    while (temp > 0) {
        blocks.push(temp % 1000);
        temp = Math.floor(temp / 1000);
    }
    for (let i = blocks.length - 1; i >= 0; i--) {
        if (blocks[i] > 0 || i === blocks.length - 1) {
            const blockStr = doc3So(blocks[i], i < blocks.length - 1 && blocks[i] > 0 && blocks[blocks.length-1] > 0);
            if (blockStr) str += blockStr + ' ' + th[i] + ' ';
        }
    }
    str = str.trim() + ' đồng';
    return str.charAt(0).toUpperCase() + str.slice(1);
}
app.locals.numberToWords = numberToWords;

let logoBase64 = '';
try {
  logoBase64 = 'data:image/png;base64,' + fs.readFileSync(require('path').join(__dirname, 'public', 'images', 'logoo.png'), 'base64');
} catch(e) { console.error('Logo not found', e); }
app.locals.logoBase64 = logoBase64;

if (isVercel) app.set('trust proxy', 1);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(cookieSession({
  name: 'promo_sess',
  keys: [process.env.SESSION_SECRET || 'dev-secret'],
  secure: isVercel,        // true trên Vercel (https), false ở localhost
  sameSite: 'lax',
  httpOnly: true,
  maxAge: 24 * 60 * 60 * 1000,
}));

const REGIONAL_CONFIG = {
  'TD12': ['CP46', 'CP67'],
  'BD12': ['CP02', 'CP69']
};

/**
 * EXECUTIVE DASHBOARD CONFIG & HELPERS
 */
const EXECUTIVE_CATEGORIES = [
  { id: 'NH01', name: 'Laptop' }, { id: 'NH02', name: 'PC' }, { id: 'NH03', name: 'Linh kiện' },
  { id: 'NH05', name: 'Apple' }, { id: 'NH06', name: 'Phụ kiện' }, { id: 'NH07', name: 'Thiết bị VP' },
  { id: 'NH08', name: 'Thiết bị mạng' }, { id: 'NH09', name: 'Phần mềm' },
  { id: 'NH10', name: 'Giải trí KTS' }, { id: 'NH11', name: 'Phụ kiện khác' },
  { id: 'NH12', name: 'Điện máy' }, { id: 'NH13', name: 'Giải pháp DN' },
  { id: 'NH14', name: 'Gia dụng' }, { id: 'NH93', name: 'Linh kiện thay thế' },
  { id: 'NH94', name: 'Dịch vụ GTGT' }, { id: 'NH95', name: 'Dịch vụ' }, { id: 'NH99', name: 'Khác' }
];

const EXECUTIVE_BRANCH_LIST = [
  { id: 'CP01', name: '264 NTMK', region: '264' }, { id: 'CP02', name: 'Bình Dương', region: 'HCM2' },
  { id: 'CP05', name: 'Quận 6', region: 'HCM1' }, { id: 'CP07', name: 'Quận 7', region: 'HCM1' },
  { id: 'CP08', name: 'Gò Vấp', region: 'HCM1' }, { id: 'CP40', name: 'HHT', region: 'HCM1' },
  { id: 'CP46', name: 'Thủ Đức 1', region: 'HCM2' }, { id: 'CP58', name: 'CMT8', region: 'HCM1' },
  { id: 'CP62', name: 'PDL', region: 'HCM1' }, { id: 'CP64', name: 'Quận 12', region: 'HCM2' },
  { id: 'CP67', name: 'Thủ Đức 2', region: 'HCM2' }, { id: 'CP69', name: 'Dĩ An', region: 'HCM2' },
  { id: 'CP75', name: 'Bình Thạnh', region: 'HCM1' }
];

function parseLocalNoon(dStr) {
  if (!dStr) return new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Ho_Chi_Minh" }));
  if (dStr instanceof Date) return new Date(dStr.getFullYear(), dStr.getMonth(), dStr.getDate(), 12, 0, 0);
  const parts = dStr.split('-');
  if (parts.length === 3) return new Date(parseInt(parts[0]), parseInt(parts[1]) - 1, parseInt(parts[2]), 12, 0, 0);
  return new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Ho_Chi_Minh" }));
}

function formatVNDate(d) {
  const date = parseLocalNoon(d);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function getDashboardDateRange(period, anchorDateStr, endDateStr) {
  let anchor = parseLocalNoon(anchorDateStr);
  if (isNaN(anchor.getTime())) anchor = parseLocalNoon();

  let endAnchor = endDateStr ? parseLocalNoon(endDateStr) : anchor;
  if (isNaN(endAnchor.getTime())) endAnchor = anchor;
  // Ensure anchor <= endAnchor
  if (endAnchor < anchor) { const t = anchor; anchor = endAnchor; endAnchor = t; }

  let cS, cE;
  const year = anchor.getFullYear(), month = anchor.getMonth();
  const eYear = endAnchor.getFullYear(), eMonth = endAnchor.getMonth();

  if (period === 'day') {
    cS = formatVNDate(anchor);
    cE = formatVNDate(endAnchor);
  } else if (period === 'week') {
    const day = anchor.getDay();
    const diff = anchor.getDate() - day + (day === 0 ? -6 : 1);
    const monday = new Date(anchor); monday.setDate(diff);
    cS = formatVNDate(monday);

    if (endDateStr) {
      cE = formatVNDate(endAnchor);
    } else {
      const sunday = new Date(monday); sunday.setDate(monday.getDate() + 6);
      cE = formatVNDate(sunday);
    }
  } else if (period === 'month') {
    cS = formatVNDate(new Date(year, month, 1));
    if (endDateStr) {
      cE = formatVNDate(endAnchor);
    } else {
      cE = formatVNDate(new Date(year, month + 1, 0));
    }
  } else if (period === 'quarter') {
    const q = Math.floor(month / 3);
    cS = formatVNDate(new Date(year, q * 3, 1));
    if (endDateStr) {
      cE = formatVNDate(endAnchor);
    } else {
      cE = formatVNDate(new Date(year, (q + 1) * 3, 0));
    }
  } else if (period === 'year') {
    cS = formatVNDate(new Date(year, 0, 1));
    if (endDateStr) {
      cE = formatVNDate(endAnchor);
    } else {
      cE = formatVNDate(new Date(year, 11, 31));
    }
  }

  const rawS = parseLocalNoon(cS), rawE = parseLocalNoon(cE);
  const diffTime = rawE - rawS;
  const diffDays = Math.round(diffTime / 86400000);

  const getPrev = () => {
    const s = new Date(rawS); s.setDate(s.getDate() - (diffDays + 1));
    const e = new Date(rawE); e.setDate(e.getDate() - (diffDays + 1));
    return { s: formatVNDate(s), e: formatVNDate(e) };
  };

  const shiftMonth = (dStr, mDiff, yDiff = 0) => {
    const [y, m, d] = dStr.split('-').map(Number);
    let newM = (m - 1) + mDiff;
    let newY = y + yDiff;
    while (newM < 0) { newM += 12; newY--; }
    while (newM > 11) { newM -= 12; newY++; }
    const lastDay = new Date(newY, newM + 1, 0).getDate();
    return formatVNDate(new Date(newY, newM, Math.min(d, lastDay), 12, 0, 0));
  };

  const shiftDays = (dStr, dDiff) => {
    const [y, m, d] = dStr.split('-').map(Number);
    return formatVNDate(new Date(y, m - 1, d + dDiff, 12, 0, 0));
  };

  return {
    curr: { s: cS, e: cE, rawS, rawE },
    prev: getPrev(),
    lw: { s: shiftDays(cS, -7), e: shiftDays(cE, -7) },
    lm: { s: shiftMonth(cS, -1), e: shiftMonth(cE, -1) },
    lq: { s: shiftMonth(cS, -3), e: shiftMonth(cE, -3) },
    ly: { s: shiftMonth(cS, 0, -1), e: shiftMonth(cE, 0, -1) }
  };
}

async function fetchTrafficStats(ranges) {
  try {
    const sheetId = process.env.GOOGLE_TRAFFIC_SHEET_ID;
    if (!sheetId) return null;
    let authConfig = { scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'] };
    const fsLib = require('fs');
    if (process.env.BIGQUERY_KEY_FILE && fsLib.existsSync(process.env.BIGQUERY_KEY_FILE)) {
      authConfig.keyFile = process.env.BIGQUERY_KEY_FILE;
    } else if (process.env.BIGQUERY_KEY_JSON) {
      let jsonStr = String(process.env.BIGQUERY_KEY_JSON).replace(/\\n/g, '\n');
      authConfig.credentials = JSON.parse(jsonStr);
    }
    const auth = new google.auth.GoogleAuth(authConfig);
    const sheets = google.sheets({ version: 'v4', auth });
    const res = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: 'cctv!A:F' });
    const rows = res.data.values;
    console.log(`[Traffic] Total rows from sheet: ${(rows || []).length}, First row (header): ${JSON.stringify((rows || [[]])[0])}`);
    if (!rows || rows.length < 2) return null;

    const h = (rows[0] || []).map(val => (val || '').toString().toLowerCase().trim());
    const dI = h.indexOf('date');
    const bI = h.indexOf('branch_id');
    const vI = h.indexOf('visit_count');

    if (dI === -1 || bI === -1 || vI === -1) {
      console.error('Traffic Header Mismatch. Parsed Headers:', h);
      return null;
    }

    const normalizeDateStr = (d) => {
      if (!d) return '';
      // Try to handle both YYYY-MM-DD and DD/MM/YYYY
      if (d.includes('/')) {
        const p = d.split('/');
        // If p[0] is year (length 4)
        if (p[0].length === 4) return `${p[0]}-${p[1].padStart(2, '0')}-${p[2].padStart(2, '0')}`;
        // Else assume DD/MM/YYYY
        return `${p[2]}-${p[1].padStart(2, '0')}-${p[0].padStart(2, '0')}`;
      }
      if (d.includes('-')) {
        const p = d.split('-');
        if (p[0].length === 4) return d;
        return `${p[2]}-${p[1].padStart(2, '0')}-${p[0].padStart(2, '0')}`;
      }
      return d;
    };

    const map = { _debug: { headers: h, sampleRows: rows.slice(1, 4) } };
    for (let i = 1; i < rows.length; i++) {
      const r = rows[i];
      if (!r[bI]) continue;
      const dStr = normalizeDateStr(r[dI]), b = r[bI], v = parseInt(r[vI] || '0');

      if (!map[b]) map[b] = { curr: 0, prev: 0, lw: 0, lm: 0, lq: 0, ly: 0, _ts: {} };

      if (dStr >= ranges.curr.s && dStr <= ranges.curr.e) { map[b].curr += v; map[b]._ts[dStr] = (map[b]._ts[dStr] || 0) + v; }
      if (dStr >= ranges.prev.s && dStr <= ranges.prev.e) map[b].prev += v;
      if (dStr >= ranges.lw.s && dStr <= ranges.lw.e) map[b].lw += v;
      if (dStr >= ranges.lm.s && dStr <= ranges.lm.e) map[b].lm += v;
      if (dStr >= ranges.lq.s && dStr <= ranges.lq.e) map[b].lq += v;
      if (dStr >= ranges.ly.s && dStr <= ranges.ly.e) map[b].ly += v;
    }
    console.log(`[Executive] Fetched Traffic for ${Object.keys(map).length - 1} branches`);
    return map;
  } catch (e) {
    console.error('FETCH TRAFFIC ERROR:', e);
    return null;
  }
}

// Hàm helper để lấy danh sách chi nhánh được phép xem
const getAllowedBranches = (user) => {
  const userBranch = user.branch_code;
  // Nếu là Admin hoặc HCM.BD -> Xem hết (logic cũ) hoặc xử lý riêng
  if (userBranch === 'HCM.BD') return null; // Null nghĩa là không lọc branch (All)

  // Nếu thuộc nhóm Regional Manager
  if (REGIONAL_CONFIG[userBranch]) {
    return REGIONAL_CONFIG[userBranch];
  }

  // Mặc định: chỉ xem chi nhánh của chính mình
  return [userBranch];
};

const BRANCH_CONFIG = {
  // Đây là mục dự phòng nếu không tìm thấy branch
  'DEFAULT': {
    name: "PHONG VŨ (Trụ sở chính)",
    address: "677/2A Điện Biên Phủ, Phường Thạnh Mỹ Tây, Tp. Hồ Chí Minh",
    mst: "0304998335",
    hotline: "1800 6867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "Công ty Cổ phần Thương mại - Dịch vụ Phong Vũ",
    bankAccount: "112000093118"
  },

  // ----- ĐIỀN THÔNG TIN CHI NHÁNH CỦA BẠN VÀO ĐÂY -----
  'HCM.BD': {
    name: "PHONG VŨ (Chi nhánh HCM.BD)",
    address: "677/2A Điện Biên Phủ, Phường Thạnh Mỹ Tây, Tp. Hồ Chí Minh",
    mst: "0304998335",
    hotline: "1800 6865",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "112000093118"
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

  'CP75': {
    name: "PHONG VŨ (Chi nhánh Bình Thạnh)",
    address: "26B Phan Đăng Lưu, Phường Gia Định, Tp. Hồ Chí Minh",
    mst: "0304998358",
    hotline: "0287.308.8867",
    website: "phongvu.vn",
    bankName: "Ngân hàng TMCP Công Thương Việt Nam – Chi nhánh 2 TP.HCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PVC4T"
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
  'CP74': {
    name: "PHONG VŨ (Chi nhánh Khánh Hội)",
    address: "162 - 164 Khánh Hội, Phường Khánh Hội, Thành phố Hồ Chí Minh, Việt Nam",
    mst: "0304998358",
    hotline: "02873018388",
    website: "phongvu.vn",
    bankName: "Ngân Hàng TMCP Công Thương Việt Nam- CN2 TPHCM",
    bankHolder: "CTY CO PHAN THUONG MAI DV PHONG VU",
    bankAccount: "18PVSU4"
  },
  // (Thêm các chi nhánh khác ở đây)
};


// --- CACHE BIẾN TOÀN CỤC ĐỂ GIẢM TẢI CPU ---
let globalTickerCache = { value: null, lastFetched: 0 };
const TICKER_CACHE_TTL = 5 * 60 * 1000; // 5 phút

let branchEventCache = {}; // { 'BRANCH_CODE': { value: bool, lastFetched: 0 } }
const BRANCH_EVENT_TTL = 1 * 60 * 1000; // 1 phút

let lastSeenCache = {}; // { 'USER_ID': timestamp }
const LAST_SEEN_THROTTLE = 5 * 60 * 1000; // 5 phút

// ======================= MIDDLEWARE LẤY CÀI ĐẶT CHUNG & THÔNG BÁO (NÂNG CẤP) =======================
app.use(async (req, res, next) => {
  // 1. NGĂN CHẶN CHẠY MIDDLEWARE CHO CÁC FILE TĨNH VÀ API NGẦM ĐỂ TIẾT KIỆM CPU
  const skipPaths = ['/api/', '/public/', '/favicon.ico', '/_next/', '/scripts/'];
  const isExcluded = skipPaths.some(path => req.path.startsWith(path));

  res.locals.user = req.session?.user || null;
  res.locals.time = new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' });
  res.locals.isBranchEventActive = false;
  res.locals.globalTickerText = globalTickerCache.value; // Dùng cache ngay lập tức
  res.locals.onlineUserCount = null;

  res.locals.notifications = [];
  res.locals.unreadCount = 0;
  res.locals.supabaseUrl = process.env.SUPABASE_URL;
  res.locals.supabaseKey = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY;

  if (isExcluded) return next();

  // LOGIC LẤY THÔNG BÁO MỚI
  if (res.locals.user) {
    const userEmail = res.locals.user.email;
    const userBranch = res.locals.user.branch_code;

    try {
      // 1. Lấy 10 thông báo mới nhất (Của riêng User hoặc All)
      const { data: notifs, error: notifErr } = await supabase
        .from('notifications')
        .select('*')
        .or(`user_ref.eq.${userEmail},user_ref.eq.All`)
        .order('created_at', { ascending: false })
        .limit(10);

      if (!notifErr && notifs && notifs.length > 0) {

        // 2. Lấy danh sách ID các thông báo này
        const notifIds = notifs.map(n => n.id);

        // 3. Kiểm tra xem User hiện tại đã đọc những thông báo nào?
        const { data: readRecords } = await supabase
          .from('notification_reads')
          .select('notification_id')
          .eq('user_email', userEmail)
          .in('notification_id', notifIds);

        // Tạo Set chứa các ID đã đọc để tra cứu cho nhanh
        const readSet = new Set(readRecords ? readRecords.map(r => r.notification_id) : []);

        // 4. [TÍNH NĂNG MỚI] Đếm số lượt xem của từng thông báo
        // (Lấy tổng số dòng trong notification_reads theo ID)
        const { data: viewCounts } = await supabase
          .from('notification_reads')
          .select('notification_id')
          .in('notification_id', notifIds);

        // Map đếm số lượng: { '123': 5, '124': 10 ... }
        const countMap = {};
        if (viewCounts) {
          viewCounts.forEach(r => {
            countMap[r.notification_id] = (countMap[r.notification_id] || 0) + 1;
          });
        }

        // 5. Ghép dữ liệu lại
        res.locals.notifications = notifs.map(n => {
          return {
            ...n,
            // Ghi đè trạng thái is_read dựa trên bảng mới (bỏ qua cột is_read cũ trong bảng notifications)
            is_read: readSet.has(n.id),
            // Thêm trường view_count
            view_count: countMap[n.id] || 0
          };
        });

        // Đếm lại số chưa đọc thực tế
        res.locals.unreadCount = res.locals.notifications.filter(n => !n.is_read).length;

      }

      // ... (Giữ nguyên các logic Last seen, Online count, Event status cũ ở dưới) ...
      // --- B. CẬP NHẬT LAST SEEN (THROTTLE - CHỈ CẬP NHẬT MỖI 5 PHÚT) ---
      const userId = res.locals.user.id;
      const now = Date.now();
      if (!lastSeenCache[userId] || (now - lastSeenCache[userId] > LAST_SEEN_THROTTLE)) {
        lastSeenCache[userId] = now;
        supabase.from('users').update({ last_seen: new Date().toISOString() }).eq('id', userId).then();
      }

      // --- C. ĐẾM ONLINE USER ---
      if (res.locals.user.role === 'manager' || res.locals.user.role === 'admin') {
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
        const { count } = await supabase.from('users').select('*', { count: 'exact', head: true }).gt('last_seen', fiveMinutesAgo);
        res.locals.onlineUserCount = count;
      }

      // --- D. CHECK EVENT STATUS (CÓ CACHE) ---
      if (userBranch) {
        const cache = branchEventCache[userBranch];
        if (cache && (now - cache.lastFetched < BRANCH_EVENT_TTL)) {
          res.locals.isBranchEventActive = cache.value;
        } else {
          const { data: evStatus } = await supabase.from('branch_event_status').select('is_event_active').eq('branch_code', userBranch).maybeSingle();
          const isActive = !!(evStatus && evStatus.is_event_active);
          res.locals.isBranchEventActive = isActive;
          branchEventCache[userBranch] = { value: isActive, lastFetched: now };
        }
      }

    } catch (e) {
      console.error("Middleware Error:", e.message);
    }
  }

  // --- E. LOGIC GLOBAL TICKER (CÓ CACHE) ---
  const now = Date.now();
  if (!globalTickerCache.value || (now - globalTickerCache.lastFetched > TICKER_CACHE_TTL)) {
    try {
      const { data: ticker } = await supabase.from('site_settings').select('value').eq('id', 'ticker_text').single();
      if (ticker) {
        globalTickerCache.value = ticker.value;
        globalTickerCache.lastFetched = now;
        res.locals.globalTickerText = ticker.value;
      }
    } catch (e) { }
  }

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


const auth = new google.auth.GoogleAuth({
  scopes: [
    'https://www.googleapis.com/auth/spreadsheets', // Quyền ghi Sheet
    'https://www.googleapis.com/auth/drive'         // <--- QUAN TRỌNG: Quyền Upload Drive
  ],
  // Logic: Ưu tiên file json ở local, nếu không có thì tìm biến môi trường (Vercel)
  keyFile: fs.existsSync('service-account.json') ? 'service-account.json' : undefined,
  credentials: (process.env.VERCEL && process.env.GOOGLE_CREDENTIALS)
    ? JSON.parse(process.env.GOOGLE_CREDENTIALS)
    : undefined
});


const drive = google.drive({ version: 'v3', auth }); // <--- BẠN ĐANG THIẾU DÒNG NÀY


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
const IMAGE_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const imageFileFilter = (req, file, cb) => {
  const ok = IMAGE_MIME_TYPES.includes(file.mimetype);
  cb(ok ? null : new Error('Chỉ chấp nhận ảnh (jpg, png, webp, gif).'), ok);
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 3 },
  fileFilter: imageFileFilter,
});

const uploadQuoteImages = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 6 },
  fileFilter: imageFileFilter,
});

const uploadDoc = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024, files: 1 },
});


// --- CẤU HÌNH ID (Bạn thay ID thật vào đây nhé) ---
const LOGBOOK_SHEET_ID = '1XIcKVwK6OA5iuIYnFz0t34ItsSMqh3pkaDcyGlFBEnI'; // ID File Sheet lưu log


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

// ------------------------- Policy Portal -------------------------
app.get('/policy', requireAuth, async (req, res) => {
  try {
    const { data: policies, error } = await supabase
      .from('policies')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Error fetching policies:', error);
    }

    const totalDocs = policies ? policies.length : 0;
    const currentMonth = new Date().getMonth();
    const currentYear = new Date().getFullYear();
    const newUpdates = policies ? policies.filter(p => {
      const updatedDate = new Date(p.updated_at);
      return updatedDate.getMonth() === currentMonth && updatedDate.getFullYear() === currentYear;
    }).length : 0;

    res.render('policy', {
      title: 'Chính sách & Quy trình',
      currentPage: 'policy',
      error: null,
      policies: policies || [],
      stats: { totalDocs, newUpdates, pendingReviews: 0 },
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  } catch (error) {
    res.render('policy', {
      title: 'Chính sách & Quy trình',
      currentPage: 'policy',
      error: 'Error loading page',
      policies: [],
      stats: { totalDocs: 0, newUpdates: 0, pendingReviews: 0 },
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });
  }
});

app.post('/api/policy/upload', requireAuth, requireManager, uploadDoc.single('file'), async (req, res) => {
  try {
    const { title, doc_type, category, custom_category, issue_date, note, summary, upload_type, link_url } = req.body;

    // Choose the final category
    const finalCategory = category === 'Khác' ? custom_category || 'Khác' : category;

    let fileType = 'other';
    let fileUrl = '';

    if (upload_type === 'link') {
      if (!link_url) return res.status(400).send('Vui lòng nhập đường dẫn Link.');
      fileUrl = link_url;
      // Guess file type based on Google URL
      if (link_url.includes('docs.google.com/spreadsheets')) fileType = 'sheet';
      else if (link_url.includes('docs.google.com/document')) fileType = 'word';
      else if (link_url.includes('drive.google.com/file')) fileType = 'pdf';
      else fileType = 'external';
    } else {
      const file = req.file;
      if (!file) {
        return res.status(400).send('Vui lòng đính kèm file.');
      }

      // Determine file type
      const ext = path.extname(file.originalname).toLowerCase();
      if (ext === '.pdf') fileType = 'pdf';
      else if (ext === '.doc' || ext === '.docx') fileType = 'word';
      else if (ext === '.xls' || ext === '.xlsx' || ext === '.csv') fileType = 'sheet';
      else if (ext === '.png' || ext === '.jpg' || ext === '.jpeg' || ext === '.webp' || ext === '.gif') fileType = 'image';

      try {
        const drive = google.drive({ version: 'v3', auth });
        const LOGBOOK_FOLDER_ID = '1TJn-ZTCvJS96YOPK2G462gEVS6zhggHr';
        const folderId = process.env.POLICY_DRIVE_FOLDER_ID || process.env.PRICE_BATTLE_DRIVE_FOLDER_ID || LOGBOOK_FOLDER_ID;

        const fileMetadata = {
          name: `POLICY_${Date.now()}_${file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '')}`,
        };
        if (folderId) fileMetadata.parents = [folderId];

        const media = {
          mimeType: file.mimetype,
          body: Readable.from(file.buffer)
        };

        const uploadedFile = await drive.files.create({
          requestBody: fileMetadata,
          media: media,
          fields: 'id, webViewLink, webContentLink',
          supportsAllDrives: true,
        });

        await drive.permissions.create({
          fileId: uploadedFile.data.id,
          requestBody: { role: 'reader', type: 'anyone' },
          supportsAllDrives: true,
        });

        fileUrl = uploadedFile.data.webViewLink;
      } catch (uploadError) {
        console.error('Google Drive Upload Error:', uploadError);
        return res.status(500).send('Lỗi upload file: ' + uploadError.message);
      }
    }

    const initialHistory = [{
      action: 'Tạo mới',
      time: new Date().toISOString(),
      note: 'Upload lần đầu.',
      file_url: fileUrl,
      created_by: req.session.user.email,
      summary: summary || ''
    }];

    // Save to DB
    const { error: dbError } = await supabase.from('policies').insert([{
      title,
      doc_type: doc_type || 'policy',
      category_name: finalCategory,
      file_type: fileType,
      file_url: fileUrl,
      issue_date,
      note,
      summary,
      created_by: req.session.user.email,
      history: initialHistory
    }]);

    if (dbError) {
      console.error('DB Insert Error (Make sure policies table exists):', dbError);
      return res.status(500).send('Lỗi lưu thông tin vào DB: ' + dbError.message);
    }

    res.redirect('/policy?upload=success');
  } catch (e) {
    console.error('Upload catch error:', e);
    res.status(500).send('Lỗi server: ' + e.message);
  }
});

app.post('/api/policy/update', requireAuth, requireManager, uploadDoc.single('file'), async (req, res) => {
  try {
    const { policy_id, update_note, upload_type, link_url, summary } = req.body;

    if (!policy_id) return res.status(400).send('Thiếu ID tài liệu.');

    // Fetch existing policy to get history and OLD summary
    const { data: existingPolicy, error: fetchError } = await supabase
      .from('policies')
      .select('history, file_url, file_type, summary')
      .eq('id', policy_id)
      .single();

    if (fetchError || !existingPolicy) return res.status(404).send('Không tìm thấy tài liệu.');

    let fileUrl = existingPolicy.file_url || '';
    let newFileUrl = ''; // Track only the newly added URL for history
    let newFileAdded = false;

    // Handle new file upload or link
    if (upload_type === 'link' && link_url) {
      newFileUrl = link_url.trim();
      if (fileUrl) fileUrl = fileUrl + '\n' + newFileUrl;
      else fileUrl = newFileUrl;
      newFileAdded = true;
    } else if (upload_type === 'file' && req.file) {
      const file = req.file;

      const drive = google.drive({ version: 'v3', auth });
      const LOGBOOK_FOLDER_ID = '1TJn-ZTCvJS96YOPK2G462gEVS6zhggHr';
      const folderId = process.env.POLICY_DRIVE_FOLDER_ID || process.env.PRICE_BATTLE_DRIVE_FOLDER_ID || LOGBOOK_FOLDER_ID;

      const fileMetadata = {
        name: `POLICY_${Date.now()}_update_${file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '')}`,
      };
      if (folderId) fileMetadata.parents = [folderId];

      const media = {
        mimeType: file.mimetype,
        body: Readable.from(file.buffer)
      };

      const uploadedFile = await drive.files.create({
        requestBody: fileMetadata,
        media: media,
        fields: 'id, webViewLink, webContentLink',
        supportsAllDrives: true,
      });

      await drive.permissions.create({
        fileId: uploadedFile.data.id,
        requestBody: { role: 'reader', type: 'anyone' },
        supportsAllDrives: true,
      });

      newFileUrl = uploadedFile.data.webViewLink;

      if (fileUrl) fileUrl = fileUrl + '\n' + newFileUrl;
      else fileUrl = newFileUrl;
      newFileAdded = true;
    }

    // Prepare history array
    let history = existingPolicy.history || [];
    if (!Array.isArray(history)) history = [];

    // The event captures what was CHANGED, or rather saves a snapshot of the PREVIOUS version
    // so when you look at history, this event marks the transition. We will store the NEW event data,
    // but attach the NEW summary to it so it represents the feature of that version.
    const updateEvent = {
      action: 'Cập nhật',
      time: new Date().toISOString(),
      note: update_note || 'Cập nhật tài liệu',
      file_url: newFileUrl || '', // Only store the NEW url, not the full concatenated one
      created_by: req.session.user.email,
      summary: summary || '' // We store the NEW summary for this version event
    };

    history.push(updateEvent);

    let updateFields = {
      history: history,
      file_url: fileUrl,
      updated_at: new Date().toISOString()
    };
    if (summary !== undefined) {
      updateFields.summary = summary;
    }

    // Update DB
    const { error: updateError } = await supabase
      .from('policies')
      .update(updateFields)
      .eq('id', policy_id);

    if (updateError) throw updateError;

    res.redirect('/policy?update=success');

  } catch (error) {
    console.error('Update policy error:', error);
    res.status(500).send('Lỗi cập nhật: ' + error.message);
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

// --- HELPER GÁN ICON VÀ TÍNH NĂNG KẾT HỢP DÙNG CHUNG CHO CTKM ---
function enrichPromoForDisplay(p) {
  const name = p.name || p.program_name || p.sheet_name || '';
  const group = p.group_name || p.sheet_name || '';
  const type = p.promo_type || '';
  const desc = p.description || p.conditions || '';
  // QUAN TRỌNG: Chỉ dùng name, group, type để định danh CTKM
  // Không dùng mô tả thể lệ/conditions để định danh, vì trong điều kiện thường ghi "Không áp dụng đồng thời với VNPay / Quà tặng" sẽ gây nhận diện sai hoàn toàn!
  const identityStr = (name + ' ' + group + ' ' + type).toLowerCase();

  let icon = '🏷️';
  let iconBg = '#ecfdf5';
  let iconColor = '#047857';
  let categoryBadge = 'Giảm giá';
  let compatibleIcons = [];

  if (identityStr.includes('trả góp') || identityStr.includes('góp 0%') || identityStr.includes('homecredit') || identityStr.includes('shinhan') || identityStr.includes('payoo') || (identityStr.includes('góp') && !identityStr.includes('mở thẻ'))) {
    icon = '🏦';
    iconBg = '#f3e8ff';
    iconColor = '#7c3aed';
    categoryBadge = 'Trả góp';
    // Thể lệ: Không áp dụng quà tặng mặc định, không áp dụng cổng thanh toán. Chỉ áp dụng cùng Đổi điểm / HSSV (Tân SV).
    compatibleIcons = [
      { icon: '🎓', label: 'Đổi điểm / HSSV (chỉ Tân SV)' }
    ];
  } else if (identityStr.includes('mở thẻ') || identityStr.includes('tpbank') || identityStr.includes('vib')) {
    icon = '🏛️';
    iconBg = '#ede9fe';
    iconColor = '#6d28d9';
    categoryBadge = 'Mở thẻ TPBank/VIB';
    compatibleIcons = [
      { icon: '🏷️', label: 'Giảm trực tiếp' },
      { icon: '🎁', label: 'Quà tặng' }
    ];
  } else if (identityStr.includes('shopeepay')) {
    icon = '🛍️';
    iconBg = '#fff1ee';
    iconColor = '#ee4d2d';
    categoryBadge = 'ShopeePay';
    compatibleIcons = [
      { icon: '🏷️', label: 'Giảm trực tiếp' },
      { icon: '🎁', label: 'Quà tặng' },
      { icon: '🎓', label: 'HSSV / Đổi điểm' }
    ];
  } else if (identityStr.includes('vnpay')) {
    icon = '💳';
    iconBg = '#e6f4ff';
    iconColor = '#005baa';
    categoryBadge = 'VNPAY';
    compatibleIcons = [
      { icon: '🏷️', label: 'Giảm trực tiếp' },
      { icon: '🎁', label: 'Quà tặng' },
      { icon: '🎓', label: 'HSSV / Đổi điểm' }
    ];
  } else if (type === 'KFI' || identityStr.includes('kfi')) {
    icon = '🔥';
    iconBg = '#fef3c7';
    iconColor = '#ea580c';
    categoryBadge = 'KFI Thưởng';
    compatibleIcons = [
      { icon: '🏷️', label: 'Giảm trực tiếp' },
      { icon: '🛍️', label: 'ShopeePay' },
      { icon: '💳', label: 'VNPAY' },
      { icon: '🎁', label: 'Quà tặng' }
    ];
  } else if (identityStr.includes('đổi điểm thi') || identityStr.includes('điểm thi')) {
    icon = '🏅';
    iconBg = '#eff6ff';
    iconColor = '#1d4ed8';
    categoryBadge = 'Đổi điểm thi';
    compatibleIcons = [
      { icon: '🎁', label: 'Quà tặng' },
      { icon: '🏦', label: 'Trả góp (Tân SV)' },
      { icon: '🛍️', label: 'ShopeePay' },
      { icon: '💳', label: 'VNPAY' }
    ];
  } else if (identityStr.includes('hssv') || identityStr.includes('sinh viên') || identityStr.includes('học sinh')) {
    icon = '🎓';
    iconBg = '#d1fae5';
    iconColor = '#059669';
    categoryBadge = 'HSSV Quý 3';
    compatibleIcons = [
      { icon: '🎁', label: 'Quà tặng' },
      { icon: '🏦', label: 'Trả góp (Tân SV)' },
      { icon: '🛍️', label: 'ShopeePay' },
      { icon: '💳', label: 'VNPAY' }
    ];
  } else if (type === 'Gift' || type === 'Quà tặng (Gift)' || identityStr.includes('quà') || identityStr.includes('tặng') || p.gift_name) {
    icon = '🎁';
    iconBg = '#fce7f3';
    iconColor = '#db2777';
    categoryBadge = 'Quà tặng';
    compatibleIcons = [
      { icon: '🏷️', label: 'Giảm trực tiếp' },
      { icon: '🛍️', label: 'ShopeePay' },
      { icon: '💳', label: 'VNPAY' },
      { icon: '🎓', label: 'HSSV / Đổi điểm' }
    ];
  } else if (type === 'Combo' || identityStr.includes('combo')) {
    icon = '🧩';
    iconBg = '#e0e7ff';
    iconColor = '#4338ca';
    categoryBadge = 'Combo';
    compatibleIcons = [
      { icon: '🛍️', label: 'ShopeePay' },
      { icon: '💳', label: 'VNPAY' },
      { icon: '🎁', label: 'Quà tặng' }
    ];
  } else if (identityStr.includes('build pc') || identityStr.includes('pcpv')) {
    icon = '🖥️';
    iconBg = '#e0f2fe';
    iconColor = '#0369a1';
    categoryBadge = 'Build PC';
    compatibleIcons = [
      { icon: '🛍️', label: 'ShopeePay' },
      { icon: '💳', label: 'VNPAY' },
      { icon: '🎁', label: 'Quà tặng' }
    ];
  } else if (identityStr.includes('app') || identityStr.includes('loyalty')) {
    icon = '📱';
    iconBg = '#e0e7ff';
    iconColor = '#3730a3';
    categoryBadge = 'App & Loyalty';
    compatibleIcons = [
      { icon: '💳', label: 'VNPAY' },
      { icon: '🎁', label: 'Quà tặng' }
    ];
  } else {
    icon = '🏷️';
    iconBg = '#ecfdf5';
    iconColor = '#047857';
    categoryBadge = 'Giảm giá';
    compatibleIcons = [
      { icon: '🛍️', label: 'ShopeePay' },
      { icon: '💳', label: 'VNPAY' },
      { icon: '🎁', label: 'Quà tặng' }
    ];
  }

  // Parse discount amount / label
  let discountLabel = '';
  if (p.__display_discount) {
    if (String(p.__display_discount).includes('%')) {
      discountLabel = `-${p.__display_discount}`;
    } else if (Number(p.__display_discount) > 0) {
      discountLabel = `-${new Intl.NumberFormat('vi-VN').format(p.__display_discount)}₫`;
    }
  } else if (p.promo_price && p.list_price) {
    const diff = p.list_price - p.promo_price;
    if (diff > 0) discountLabel = `-${new Intl.NumberFormat('vi-VN').format(diff)}₫`;
  } else if (p.online_coupon) {
    const mMoney = p.online_coupon.match(/(\d+([.,]\d+)?)\s*(k|triệu|tr)/i);
    const mPct = p.online_coupon.match(/(\d+)%/);
    if (mPct) discountLabel = `-${mPct[1]}%`;
    else if (mMoney) discountLabel = `Giảm ${mMoney[0]}`;
    else discountLabel = 'Ưu đãi mã';
  } else if (categoryBadge === 'Quà tặng') {
    discountLabel = 'Tặng quà';
  } else if (categoryBadge === 'Trả góp & Thẻ') {
    discountLabel = 'Lãi 0%';
  } else if (categoryBadge === 'KFI Thưởng') {
    discountLabel = 'Thưởng KFI';
  } else if (categoryBadge === 'Đổi điểm thi') {
    discountLabel = 'Đến 5.000.000₫';
  } else if (categoryBadge === 'HSSV Quý 3') {
    discountLabel = 'Đến 500.000₫';
  }

  // Tạo short_desc ngắn gọn
  let shortDesc = desc.replace(/[\r\n]+/g, ' ').trim();
  if (shortDesc.length > 120) shortDesc = shortDesc.slice(0, 117) + '...';

  return {
    ...p,
    __icon: icon,
    __icon_bg: iconBg,
    __icon_color: iconColor,
    __category_badge: categoryBadge,
    __compatible_icons: compatibleIcons,
    __discount_label: discountLabel,
    __short_desc: shortDesc || 'Xem điều kiện chi tiết trong thể lệ',
    __promo_type: p.promo_type || categoryBadge,
    __apply_channels: p.channel || p.apply_channels || 'All channels (Showroom & Online)',
    __conditions: p.conditions || p.special_conditions || p.description || 'Áp dụng theo thể lệ chi tiết của chương trình.',
    __detail_link: p.detail_link || (p.id ? `/promotion-detail/${p.id}` : '#')
  };
}

// --- ROUTE TRANG CHỦ (RENDER LẦN ĐẦU) ---
app.get('/', requireAuth, async (req, res) => {
  try {
    const selectedGroup = req.query.group || '';
    const searchQuery = (req.query.q || '').trim().toLowerCase();
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const pageSize = 8;
    const today = new Date().toISOString().slice(0, 10);
    const userRole = req.session.user?.role || '';
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

    const promosWithStackInfoBase = allPromos.map(p => {
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

    // 1.1. Query active sheet promos (promo_sku_master)
    const { data: sheetPromosRaw } = await supabase
      .from('promo_sku_master')
      .select('id, sheet_name, program_name, sku, category, product_name, brand, list_price, promo_price, online_coupon, gift_sku, gift_name, limit_qty, kfi_value, start_date, end_date, detail_link, conditions')
      .lte('start_date', today)
      .gte('end_date', today);

    // Group or filter to unique ones in JS and collect SKUs
    const uniqueSheetPromosMap = {};
    (sheetPromosRaw || []).forEach(sp => {
      const key = sp.sheet_name + "_" + sp.program_name;
      if (!uniqueSheetPromosMap[key]) {
        uniqueSheetPromosMap[key] = {
          ...sp,
          skus: [sp.sku]
        };
      } else {
        uniqueSheetPromosMap[key].skus.push(sp.sku);
      }
    });

    const mappedSheetPromos = Object.values(uniqueSheetPromosMap).map(sp => {
      let displayDiscount = null;
      let displayPrefix = 'Giảm';
      let discountValueForSort = 0;

      if (sp.list_price && sp.promo_price) {
        const amt = sp.list_price - sp.promo_price;
        if (amt > 0) {
          displayDiscount = amt;
          discountValueForSort = amt;
        }
      } else if (sp.online_coupon) {
        const match = sp.online_coupon.match(/(\d+)\s*(k|K)/);
        if (match) {
          const parsed = parseInt(match[1], 10) * 1000;
          displayDiscount = parsed;
          discountValueForSort = parsed;
        }
      }

      const isGift = !!(sp.gift_name || sp.gift_sku);
      const isKFI = !!sp.kfi_value;

      let desc = sp.conditions || '';
      if (sp.gift_name) {
        desc = "🎁 Quà tặng: " + sp.gift_name + (desc ? ' | ' + desc : '');
      } else if (sp.online_coupon) {
        desc = "Coupon: " + sp.online_coupon + (desc ? ' | ' + desc : '');
      }

      return {
        id: "sheet_" + sp.id,
        name: sp.program_name || sp.sheet_name,
        group_name: sp.sheet_name,
        promo_type: isKFI ? 'KFI' : (isGift ? 'Gift' : 'Discount'),
        description: desc,
        start_date: sp.start_date,
        end_date: sp.end_date,
        is_sheet_promo: true,
        detail_link: sp.detail_link,
        conditions: sp.conditions,
        promotion_skus: (sp.skus || []).map(s => ({ sku: s })),
        __stackable: true,
        __display_discount: displayDiscount,
        __display_prefix: displayPrefix,
        __sort_value: discountValueForSort
      };
    });

    const promosWithStackInfo = [
      ...promosWithStackInfoBase,
      ...mappedSheetPromos
    ].map(enrichPromoForDisplay);

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

    // KFI chỉ dành cho manager
    if (userRole !== 'manager') {
      filteredPromos = filteredPromos.filter(p => p.promo_type !== 'KFI');
    }

    // 4. Sắp xếp & Phân trang
    filteredPromos.sort((a, b) => {
      // --- ƯU TIÊN 1: KFI LUÔN LÊN ĐẦU ---
      const isKfiA = (a.promo_type === 'KFI');
      const isKfiB = (b.promo_type === 'KFI');
      if (isKfiA && !isKfiB) return -1;
      if (!isKfiA && isKfiB) return 1;

      // --- ƯU TIÊN 2: SẮP THEO GIÁ TRỊ GIẢM ---
      const valA = a.__sort_value || 0;
      const valB = b.__sort_value || 0;
      if (valA !== valB) return valB - valA;

      // --- ƯU TIÊN 3: CÓ QUÀ TẶNG LÊN TRƯỚC ---
      const isGiftA = (a.promo_type === 'Gift' || a.promo_type === 'Quà tặng (Gift)');
      const isGiftB = (b.promo_type === 'Gift' || b.promo_type === 'Quà tặng (Gift)');
      if (isGiftA && !isGiftB) return -1;
      if (!isGiftA && isGiftB) return 1;

      // --- ƯU TIÊN 4: THỨ TỰ TRONG DOCS (dựa trên id nếu là sheet promo) ---
      const isSheetA = !!a.is_sheet_promo;
      const isSheetB = !!b.is_sheet_promo;
      if (isSheetA && isSheetB) {
        return a.id.localeCompare(b.id);
      }
      return 0;
    });

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

    // 5. Lấy dữ liệu Bảng tin & Bảng xếp hạng cho trang chủ
    const { data: newsfeedPosts } = await supabase
      .from('newsfeed_posts')
      .select('*')
      .eq('status', 'published')
      .order('published_at', { ascending: false })
      .limit(5);

    const { data: periodsData } = await supabase
      .from('newsfeed_ranking')
      .select('display_period')
      .neq('display_period', null);
    const allPeriods = [...new Set((periodsData || []).map(p => p.display_period).filter(Boolean))];

    // Ưu tiên chu kỳ tháng liền kề trước (vd: hiện tại 03/2026 => Tháng 02/2026)
    const nowForRanking = new Date();
    const prevMonthDate = new Date(nowForRanking.getFullYear(), nowForRanking.getMonth() - 1, 1);
    const targetMonth = String(prevMonthDate.getMonth() + 1).padStart(2, '0');
    const targetYear = String(prevMonthDate.getFullYear());
    const targetPeriodLabel = `Tháng ${targetMonth}/${targetYear}`;

    const normalizePeriod = (s) => String(s || '')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toUpperCase()
      .replace(/[.\-]/g, '/')
      .replace(/\s+/g, ' ')
      .trim();

    const normalizedTarget = normalizePeriod(targetPeriodLabel);
    const altTarget = normalizePeriod(`Tháng ${Number(targetMonth)}/${targetYear}`);

    const matchedTargetPeriod = allPeriods.find((p) => {
      const n = normalizePeriod(p);
      return n === normalizedTarget || n === altTarget || n.includes(`${Number(targetMonth)}/${targetYear}`) || n.includes(`${targetMonth}/${targetYear}`);
    }) || '';

    let rankingTop1 = null;
    let rankingOthers = [];
    const rankingQuery = supabase
      .from('newsfeed_ranking')
      .select('*')
      .order('rank_order', { ascending: true })
      .limit(10);

    let rankingData = [];
    if (matchedTargetPeriod) {
      const { data } = await rankingQuery.eq('display_period', matchedTargetPeriod);
      rankingData = data || [];
    } else {
      const fallbackToken = `${Number(targetMonth)}/${targetYear}`;
      const { data } = await rankingQuery.ilike('display_period', `%${fallbackToken}%`);
      rankingData = data || [];
    }

    if (rankingData.length > 0) {
      rankingTop1 = (rankingData || []).find(r => r.rank_order === 1) || null;
      rankingOthers = (rankingData || []).filter(r => r.rank_order > 1);
    }

    res.render('index', {
      title: 'Trang chủ', currentPage: 'home',
      featuredPromos: paginatedPromos,
      allGroups,
      selectedGroup,
      searchQuery,
      page, totalPages,
      totalItems,
      matrixRows, competitorCols,
      randomSkus: randomSkus || [],
      userRole: userRole,
      newsfeedPosts: newsfeedPosts || [],
      rankingTop1,
      rankingOthers,
      selectedPeriod: targetPeriodLabel,
    });
  } catch (e) {
    console.error('Lỗi trang chủ:', e);
    res.render('index', {
      title: 'Trang chủ', currentPage: 'home', error: e.message,
      featuredPromos: [], allGroups: [], selectedGroup: '', searchQuery: '',
      page: 1, totalPages: 1, totalItems: 0, matrixRows: [], competitorCols: [],
      randomSkus: [], userRole: 'branch', newsfeedPosts: [],
      rankingTop1: null, rankingOthers: [], selectedPeriod: ''
    });
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
    const userRole = req.session.user?.role || '';

    const { data: allPromos } = await supabase
      .from('promotions')
      .select('*, promotion_skus(sku)')
      .eq('status', 'active')
      .lte('start_date', today)
      .gte('end_date', today);

    const promoIds = allPromos.map(p => p.id);
    const { data: compatRows } = await supabase.from('promotion_compat_allows').select('promotion_id').in('promotion_id', promoIds);
    const promosWithAllowRules = new Set((compatRows || []).map(r => r.promotion_id));

    const promosWithStackInfoBase = allPromos.map(p => {
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

    // 1.1. Query active sheet promos (promo_sku_master)
    const { data: sheetPromosRaw } = await supabase
      .from('promo_sku_master')
      .select('id, sheet_name, program_name, sku, category, product_name, brand, list_price, promo_price, online_coupon, gift_sku, gift_name, limit_qty, kfi_value, start_date, end_date, detail_link, conditions')
      .lte('start_date', today)
      .gte('end_date', today);

    // Group or filter to unique ones in JS and collect SKUs
    const uniqueSheetPromosMap = {};
    (sheetPromosRaw || []).forEach(sp => {
      const key = sp.sheet_name + "_" + sp.program_name;
      if (!uniqueSheetPromosMap[key]) {
        uniqueSheetPromosMap[key] = {
          ...sp,
          skus: [sp.sku]
        };
      } else {
        uniqueSheetPromosMap[key].skus.push(sp.sku);
      }
    });

    const mappedSheetPromos = Object.values(uniqueSheetPromosMap).map(sp => {
      let displayDiscount = null;
      let displayPrefix = 'Giảm';
      let discountValueForSort = 0;

      if (sp.list_price && sp.promo_price) {
        const amt = sp.list_price - sp.promo_price;
        if (amt > 0) {
          displayDiscount = amt;
          discountValueForSort = amt;
        }
      } else if (sp.online_coupon) {
        const match = sp.online_coupon.match(/(\d+)\s*(k|K)/);
        if (match) {
          const parsed = parseInt(match[1], 10) * 1000;
          displayDiscount = parsed;
          discountValueForSort = parsed;
        }
      }

      const isGift = !!(sp.gift_name || sp.gift_sku);
      const isKFI = !!sp.kfi_value;

      let desc = sp.conditions || '';
      if (sp.gift_name) {
        desc = "🎁 Quà tặng: " + sp.gift_name + (desc ? ' | ' + desc : '');
      } else if (sp.online_coupon) {
        desc = "Coupon: " + sp.online_coupon + (desc ? ' | ' + desc : '');
      }

      return {
        id: "sheet_" + sp.id,
        name: sp.program_name || sp.sheet_name,
        group_name: sp.sheet_name,
        promo_type: isKFI ? 'KFI' : (isGift ? 'Gift' : 'Discount'),
        description: desc,
        start_date: sp.start_date,
        end_date: sp.end_date,
        is_sheet_promo: true,
        detail_link: sp.detail_link,
        conditions: sp.conditions,
        promotion_skus: (sp.skus || []).map(s => ({ sku: s })),
        __stackable: true,
        __display_discount: displayDiscount,
        __display_prefix: displayPrefix,
        __sort_value: discountValueForSort
      };
    });

    const promosWithStackInfo = [
      ...promosWithStackInfoBase,
      ...mappedSheetPromos
    ].map(enrichPromoForDisplay);

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

    if (userRole !== 'manager') {
      filteredPromos = filteredPromos.filter(p => p.promo_type !== 'KFI');
    }

    filteredPromos.sort((a, b) => {
      // --- ƯU TIÊN 1: KFI LUÔN LÊN ĐẦU ---
      const isKfiA = (a.promo_type === 'KFI');
      const isKfiB = (b.promo_type === 'KFI');
      if (isKfiA && !isKfiB) return -1;
      if (!isKfiA && isKfiB) return 1;

      // --- ƯU TIÊN 2: SẮP THEO GIÁ TRỊ GIẢM ---
      const valA = a.__sort_value || 0;
      const valB = b.__sort_value || 0;
      if (valA !== valB) return valB - valA;

      // --- ƯU TIÊN 3: CÓ QUÀ TẶNG LÊN TRƯỚC ---
      const isGiftA = (a.promo_type === 'Gift' || a.promo_type === 'Quà tặng (Gift)');
      const isGiftB = (b.promo_type === 'Gift' || b.promo_type === 'Quà tặng (Gift)');
      if (isGiftA && !isGiftB) return -1;
      if (!isGiftA && isGiftB) return 1;

      // --- ƯU TIÊN 4: THỨ TỰ TRONG DOCS (dựa trên id nếu là sheet promo) ---
      const isSheetA = !!a.is_sheet_promo;
      const isSheetB = !!b.is_sheet_promo;
      if (isSheetA && isSheetB) {
        return a.id.localeCompare(b.id);
      }
      return 0;
    });

    const totalItems = filteredPromos.length;
    const totalPages = Math.ceil(totalItems / pageSize);
    const paginatedPromos = filteredPromos.slice((page - 1) * pageSize, page * pageSize);

    res.render('partials/_featured-promos', {
      featuredPromos: paginatedPromos,
      page,
      totalPages,
      totalItems,
      userRole,
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

// POST /api/sku/:sku/refresh-spec: Đồng bộ thông số kỹ thuật, bảo hành, VAT và giá KM từ Teko vào Supabase (theo yêu cầu)
app.post('/api/sku/:sku/refresh-spec', requireAuth, async (req, res) => {
  try {
    const sku = (req.params.sku || req.body?.sku || '').trim();
    if (!sku) return res.status(400).json({ ok: false, error: 'Thiếu mã SKU.' });
    const userBranch = req.session?.user?.branch_code || 'CP01';
    const updated = await getOrSyncProductData(sku, userBranch, supabase, true);
    if (!updated) return res.status(404).json({ ok: false, error: 'Không tìm thấy thông tin sản phẩm.' });
    return res.json({
      ok: true,
      product: {
        sku: updated.sku,
        product_name: updated.product_name,
        brand: updated.brand,
        list_price: updated.list_price,
        promo_price: updated.promo_price,
        discount_amount: updated.discount_amount,
        vat_rate: updated.vat_rate,
        warranty: updated.warranty,
        specifications: updated.specifications,
        spec_updated_at: updated.spec_updated_at
      }
    });
  } catch (err) {
    console.error('[API REFRESH-SPEC] Lỗi:', err.message);
    return res.status(500).json({ ok: false, error: err.message || 'Lỗi hệ thống khi làm mới thông số.' });
  }
});

// GET /api/sku/:sku/details: Lấy thông số kỹ thuật, bảo hành, VAT và giá của SKU để xem hoặc so sánh
app.get('/api/sku/:sku/details', async (req, res) => {
  try {
    const sku = (req.params.sku || '').trim();
    if (!sku) return res.status(400).json({ ok: false, error: 'Thiếu mã SKU.' });
    const userBranch = req.session?.user?.branch_code || 'CP01';
    const product = await getOrSyncProductData(sku, userBranch, supabase, false);
    if (!product) return res.status(404).json({ ok: false, error: `Không tìm thấy sản phẩm với SKU: ${sku}` });
    return res.json({
      ok: true,
      product: {
        sku: product.sku,
        product_name: product.product_name,
        brand: product.brand,
        list_price: product.list_price,
        promo_price: product.promo_price,
        discount_amount: product.discount_amount,
        vat_rate: product.vat_rate,
        warranty: product.warranty,
        specifications: product.specifications,
        spec_updated_at: product.spec_updated_at
      }
    });
  } catch (err) {
    console.error('[API SKU-DETAILS] Lỗi:', err.message);
    return res.status(500).json({ ok: false, error: err.message || 'Lỗi hệ thống khi tải thông tin SKU.' });
  }
});


// ------------------------- API SKUs -------------------------
// --- [SERVER.JS] --- Fix logic tìm kiếm thông minh (AND Logic) ---

app.get('/api/skus', async (req, res) => {
  try {
    const rawQuery = (req.query.q || '').trim();
    if (!rawQuery) return res.json([]);

    // 1. Tách từ khóa và loại bỏ ký tự đặc biệt
    // Ví dụ: "Laptop   acer  i5" -> ["laptop", "acer", "i5"]
    const terms = rawQuery.replace(/[&|!():<]/g, '').split(/\s+/).filter(Boolean);

    let dbQuery = supabase
      .from('skus')
      .select('sku, product_name, brand, category, subcat, list_price, promo_price, warranty, vat_rate, specifications');

    // 2. [QUAN TRỌNG] Xây dựng bộ lọc "AND"
    // Với mỗi từ khóa, bắt buộc SKU hoặc Tên phải chứa từ đó.
    // Supabase: Chaining .or() sẽ hoạt động như AND giữa các nhóm điều kiện.
    // Logic: (SKU like term1 OR Name like term1) AND (SKU like term2 OR Name like term2)...
    terms.forEach(term => {
      dbQuery = dbQuery.or(`sku.ilike.%${term}%,product_name.ilike.%${term}%`);
    });

    // 3. Lấy dữ liệu (Tăng limit để có không gian sắp xếp)
    // Không sort giá ở DB nữa để tránh mất các sản phẩm khớp tên nhưng giá thấp/null
    const { data, error } = await dbQuery.limit(100);

    if (error) throw error;
    let results = data || [];

    // 4. THUẬT TOÁN CHẤM ĐIỂM & SẮP XẾP (Ranking)
    const lowerQuery = rawQuery.toLowerCase();

    results.forEach(item => {
      let score = 0;
      const sSku = String(item.sku).toLowerCase();
      const sName = String(item.product_name || '').toLowerCase();

      // Tiêu chí 1: Khớp chính xác SKU (Điểm cao nhất - Tuyệt đối)
      if (sSku === lowerQuery) score += 10000;
      else if (sSku.startsWith(lowerQuery)) score += 5000;

      // Tiêu chí 2: Có giá bán (Ưu tiên hàng đang kinh doanh)
      const hasPrice = (item.list_price !== null && item.list_price > 0);
      if (hasPrice) score += 2000;

      // Tiêu chí 3: Giá trị sản phẩm (Ưu tiên giá cao - thường là hàng chính)
      if (hasPrice) {
        // Cộng thêm 1 điểm cho mỗi 1 triệu đồng (để phân loại nhẹ)
        score += Math.floor(item.list_price / 1000000);
      }

      // Tiêu chí 4: Vị trí từ khóa trong tên (Khớp đầu câu điểm cao hơn)
      if (sName.startsWith(lowerQuery)) score += 500;

      item._score = score;
    });

    // 5. Sắp xếp dựa trên điểm số
    results.sort((a, b) => b._score - a._score);

    // Trả về kết quả (Bỏ trường _score trước khi gửi nếu muốn gọn, hoặc để nguyên cũng không sao)
    res.json(results);

  } catch (error) {
    console.error("Search API Error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ===== SỬA API COMPONENTS (DÙNG .eq() VÌ CLIENT ĐÃ SỬA) =====
app.get('/api/components', requireAuth, async (req, res) => {
  try {
    // Lấy thông tin User để phân quyền tồn kho
    const userBranch = req.session.user ? req.session.user.branch_code : '';
    const userRole = req.session.user ? req.session.user.role : '';
    const REGIONAL_MAP = {
      'TD-12': ['CP46', 'CP67'],
      'BD-DN': ['CP02', 'CP69']
    };

    const { subcat, skus } = req.query;

    // Logic Query
    let query = supabase.from('skus').select('sku, product_name, list_price, brand, subcat');

    // CASE 1: CÓ LIST SKU (Ưu tiên cao nhất)
    if (skus && skus.trim() !== '') {
      const skuArray = skus.toString().replace(/[\r\n]+/g, ',').split(',').map(s => s.trim()).filter(Boolean);
      if (skuArray.length > 0) {
        query = query.in('sku', skuArray);
      } else {
        return res.json({ ok: true, components: [] });
      }
    }
    // CASE 2: CÓ SUBCAT
    else if (subcat && subcat.trim() !== '') {
      const cleanSub = subcat.trim();

      // [SỬA LỖI] Dùng ilike để KHÔNG phân biệt hoa thường (nh11 = NH11)
      query = query.ilike('subcat', `${cleanSub}%`);
    }
    else {
      return res.json({ ok: true, components: [] });
    }

    // Thực thi query
    const { data: components, error } = await query.limit(1000);

    // [LOGIC MỚI - BACKUP] Nếu tìm Subcat không thấy -> Thử tìm chính xác SKU
    // (Phòng trường hợp bạn nhập nhầm mã SKU vào ô Subcat)
    if ((!components || components.length === 0) && subcat && !skus) {
      const { data: retryData } = await supabase
        .from('skus')
        .select('sku, product_name, list_price, brand, subcat')
        .eq('sku', subcat.trim()) // Tìm chính xác SKU
        .limit(1);

      if (retryData && retryData.length > 0) {
        // Nếu tìm thấy theo SKU thì gán lại dữ liệu để trả về
        return processResult(res, retryData, userBranch, userRole, REGIONAL_MAP);
      }
    }

    if (error) throw error;

    // Gọi hàm xử lý kết quả (để code gọn hơn)
    return processResult(res, components || [], userBranch, userRole, REGIONAL_MAP);

  } catch (e) {
    console.error('Lỗi API /api/components:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Thay thế hàm processResult trong server.js
async function processResult(res, components, userBranch, userRole, REGIONAL_MAP) {
  if (!components || components.length === 0) {
    return res.json({ ok: true, components: [] });
  }

  const skuList = components.map(c => String(c.sku).trim().toUpperCase());
  let stockMap = {};

  try {
    stockMap = await getSkuNewStockByBranch(skuList);
  } catch (e) { console.error("Lỗi Stock:", e.message); }

  const myBranchKey = userBranch ? String(userBranch).trim().toUpperCase() : '';

  const finalData = components.map(p => {
    const lookupKey = String(p.sku).trim().toUpperCase();
    const rawStocks = stockMap[lookupKey] || {};

    // Chuẩn hóa key stock
    const stocks = {};
    let absTotal = 0;
    Object.keys(rawStocks).forEach(k => {
      stocks[k] = rawStocks[k];
      absTotal += rawStocks[k];
    });

    // Tồn kho của chính User (để sort) - ÁP DỤNG CHO CẢ MANAGER
    const myStock = (myBranchKey && stocks[myBranchKey]) ? stocks[myBranchKey] : 0;

    // Tồn kho hiển thị
    let visible = 0;
    if (myBranchKey === 'HCM.BD') visible = absTotal; // Admin thấy hết
    else if (userRole === 'manager' && REGIONAL_MAP[userBranch]) {
      // Regional Manager thấy tổng các kho con
      REGIONAL_MAP[userBranch].forEach(br => {
        const brKey = String(br).trim().toUpperCase();
        visible += (stocks[brKey] || 0);
      });
    } else {
      // Còn lại thấy kho mình
      visible = myStock;
    }

    return {
      ...p,
      stock_by_branch: stocks,
      total_stock: visible,
      real_total_stock: absTotal,
      my_stock: myStock
    };
  });

  // SẮP XẾP ƯU TIÊN (Logic bạn yêu cầu)
  finalData.sort((a, b) => {
    // Ưu tiên 1: Tồn kho tại chi nhánh User giảm dần
    if (b.my_stock !== a.my_stock) {
      return b.my_stock - a.my_stock;
    }
    // Ưu tiên 2: Tổng tồn toàn hệ thống giảm dần
    return b.real_total_stock - a.real_total_stock;
  });

  res.json({ ok: true, components: finalData });
}


// ===== API CÀI ĐẶT BUILD PC TIERS =====
const DEFAULT_BUILD_PC_TIERS = [
  { min: 100000000, discount: 2000000, code: 'PVBPC26015' },
  { min: 50000000, discount: 1000000, code: 'PVBPC26014' },
  { min: 30000000, discount: 600000, code: 'PVBPC26013' },
  { min: 20000000, discount: 400000, code: 'PVBPC26012' },
  { min: 10000000, discount: 200000, code: 'PVBPC26011' }
];

// GET - Lấy cấu hình tiers hiện tại
app.get('/api/admin/build-pc-tiers', requireAuth, requireManager, async (req, res) => {
  try {
    const { data } = await supabase.from('site_settings').select('value').eq('id', 'build_pc_tiers').maybeSingle();
    const tiers = (data && data.value) ? JSON.parse(data.value) : DEFAULT_BUILD_PC_TIERS;
    res.json({ ok: true, tiers });
  } catch (e) {
    res.json({ ok: true, tiers: DEFAULT_BUILD_PC_TIERS });
  }
});

// POST - Lưu cấu hình tiers mới
app.post('/api/admin/build-pc-tiers', requireAuth, requireManager, async (req, res) => {
  try {
    const { tiers } = req.body;
    if (!Array.isArray(tiers) || tiers.length === 0) {
      return res.status(400).json({ ok: false, error: 'Dữ liệu không hợp lệ.' });
    }
    // Sắp xếp giảm dần theo min để luôn đúng thứ tự
    const sorted = [...tiers].sort((a, b) => b.min - a.min);
    await supabase.from('site_settings').upsert({ id: 'build_pc_tiers', value: JSON.stringify(sorted) }, { onConflict: 'id' });
    res.json({ ok: true, message: 'Đã lưu cấu hình Build PC Tiers.' });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});
// ===== KẾT THÚC: API CÀI ĐẶT BUILD PC TIERS =====

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

    const tiers_raw = await supabase.from('site_settings').select('value').eq('id', 'build_pc_tiers').maybeSingle();
    const tiers = (tiers_raw.data && tiers_raw.data.value) ? JSON.parse(tiers_raw.data.value) : DEFAULT_BUILD_PC_TIERS;

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

  // [FIXED] Dùng String() bao trọn cụm logic để tránh lỗi .toString() của undefined
  const rawInput = req.method === 'POST'
    ? (req.body?.sku || req.body?.query)
    : (req.query?.query || req.query?.sku);

  const skuInput = String(rawInput || '').trim();

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

    // Tự động kiểm tra: nếu chưa có specifications thì đồng bộ từ Teko và lưu Supabase (chỉ 1 lần duy nhất)
    try {
      const enrichedProduct = await getOrSyncProductData(product.sku, userBranch, supabase, false);
      if (enrichedProduct) {
        product = { ...product, ...enrichedProduct };
      }
    } catch (eSync) {
      console.warn('Lỗi lazy sync thông số SKU:', eSync.message);
    }

    try {
      const { count } = await supabase
        .from('price_comparisons')
        .select('*', { count: 'exact', head: true }) // Chỉ lấy số lượng (nhẹ server)
        .eq('sku', product.sku);

      comparisonCount = count || 0;
    } catch (errCount) {
      console.error("Lỗi đếm chiến giá:", errCount);
    }
    const price = Number(product.list_price || product.promo_price || 0);
    console.log(`[DEBUG] Bước 1: Đã tìm thấy sản phẩm - Tên: ${product.product_name}, Giá gốc: ${product.list_price || 0}đ, Giá KM: ${product.promo_price || 0}đ`);

    try {
      const { data: kfiData } = await supabase
        .from('kfi_list')
        .select('kfi_end_user, kfi_dealer')
        .eq('sku', product.sku)
        .single();

      // Gán dữ liệu KFI vào biến product để truyền xuống giao diện
      if (kfiData) {
        product.kfi_end_user = kfiData.kfi_end_user || 0;
        product.kfi_dealer = kfiData.kfi_dealer || 0;
      } else {
        product.kfi_end_user = 0;
        product.kfi_dealer = 0;
      }
    } catch (errKfi) {
      console.error("Lỗi lấy data KFI:", errKfi.message);
    }

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

    // 2) Lấy các CTKM đang active từ DB cũ
    const today = new Date().toISOString().split('T')[0];
    let { data: promosRaw } = await supabase
      .from('promotions')
      .select('*, promotion_skus(*), promotion_excluded_skus(*), detail_fields, group_name, subgroup_name')
      .lte('start_date', today)
      .gte('end_date', today)
      .eq('status', 'active');

    // 2.1) Lấy các CTKM từ Google Sheets (promo_sku_master) đang active
    // Hỗ trợ cả tra cứu theo SKU cụ thể và tra cứu theo Category/Subcat (nhóm sản phẩm) và CTKM dùng chung (All/ALL)
    let orConditions = "sku.eq." + product.sku;
    if (product.subcat) {
      const parts = product.subcat.split('-');
      let currentPrefix = '';
      parts.forEach((part, index) => {
        currentPrefix = index === 0 ? part : currentPrefix + '-' + part;
        orConditions += ",sku.eq." + currentPrefix;
      });
    } else if (product.category) {
      orConditions += ",sku.eq." + product.category;
    }
    orConditions += ",sku.eq.ALL,sku.eq.All";

    let { data: sheetPromosRaw } = await supabase
      .from('promo_sku_master')
      .select('*')
      .or(orConditions)
      .lte('start_date', today)
      .gte('end_date', today);

    // 2.2) Lọc các CTKM từ Sheet hợp lệ với sản phẩm hiện tại
    const validSheetPromos = (sheetPromosRaw || []).filter(sp => {
      // 1. Nếu khớp chính xác SKU: luôn hợp lệ
      if (sp.sku === product.sku) return true;

      // 2. Kiểm tra Hãng (Brand) nếu CTKM có quy định hãng
      if (sp.brand && sp.brand !== 'All' && sp.brand !== 'Toàn hệ thống') {
        const prodBrand = (product.brand || '').trim().toLowerCase();
        const promoBrand = (sp.brand || '').trim().toLowerCase();
        if (prodBrand && promoBrand && prodBrand !== promoBrand && !prodBrand.includes(promoBrand) && !promoBrand.includes(prodBrand)) {
          return false;
        }
      }

      // 3. Nếu SKU là mã ngành (NH01, NH02, NH05, NH11...)
      if (/^NH\d+/i.test(sp.sku)) {
        const prodCat = (product.category || '').toUpperCase();
        const prodSubcat = (product.subcat || '').toUpperCase();
        const spCat = (sp.sku || '').toUpperCase();
        const isCatMatch = prodCat.startsWith(spCat) || prodSubcat.startsWith(spCat) || 
          (spCat === 'NH01' && (prodCat === 'NH01' || prodCat === 'NH05')) ||
          (spCat === 'NH05' && (prodCat === 'NH05' || prodCat === 'NH01'));
        if (!isCatMatch) return false;
      }

      // 4. Nếu là ALL: Loại bỏ các chương trình không liên quan đến ngành hàng này
      if (sp.sku === 'ALL' || sp.sku === 'All') {
        const prodCat = (product.category || '').toUpperCase();
        const lowerName = ((sp.program_name || '') + ' ' + (sp.sheet_name || '')).toLowerCase();
        
        // CTKM Laptop/MacBook chỉ cho NH01/NH05
        if ((lowerName.includes('laptop') || lowerName.includes('macbook')) && !lowerName.includes('vệ sinh')) {
          if (prodCat !== 'NH01' && prodCat !== 'NH05') return false;
        }
        // CTKM Máy in / Mực in chỉ cho NH07
        if (lowerName.includes('máy in') || lowerName.includes('mực in')) {
          if (!prodCat.startsWith('NH07')) return false;
        }
        // CTKM Máy chiếu chỉ cho NH08
        if (lowerName.includes('máy chiếu') || lowerName.includes('màn chiếu')) {
          if (!prodCat.startsWith('NH08')) return false;
        }
      }

      return true;
    });

    // De-duplicate / merge promotions from Google Sheets (grouped by program_name/sheet_name)
    const groupedPromos = new Map();
    validSheetPromos.forEach(sp => {
      const key = sp.program_name || sp.sheet_name;
      if (!groupedPromos.has(key)) {
        groupedPromos.set(key, { ...sp });
      } else {
        const existing = groupedPromos.get(key);
        if (!existing.online_coupon && sp.online_coupon) {
          existing.online_coupon = sp.online_coupon;
        }
        if (!existing.promo_price && sp.promo_price) {
          existing.promo_price = sp.promo_price;
          existing.list_price = sp.list_price;
        }
        if (!existing.gift_name && sp.gift_name) {
          existing.gift_name = sp.gift_name;
          existing.gift_sku = sp.gift_sku;
        }
        if (!existing.kfi_value && sp.kfi_value) {
          existing.kfi_value = sp.kfi_value;
        }
        if (!existing.limit_qty && sp.limit_qty) {
          existing.limit_qty = sp.limit_qty;
        }
      }
    });

    const mappedSheetPromos = Array.from(groupedPromos.values()).map(sp => {
      let discount = 0;
      if (sp.list_price && sp.promo_price) {
        discount = Math.max(0, sp.list_price - sp.promo_price);
      }
      
      let detail_fields = null;
      if (sp.gift_name || sp.gift_sku) {
        detail_fields = {
          gift_options: [
            {
              code: sp.gift_sku || "QUATANG",
              name: sp.gift_name || "Quà tặng đính kèm",
              skus: sp.gift_sku ? [sp.gift_sku] : []
            }
          ]
        };
      }

      let descParts = [];
      if (sp.promo_price) {
        descParts.push(`Giá KM: ${new Intl.NumberFormat('vi-VN').format(sp.promo_price)}đ (Giá NY: ${new Intl.NumberFormat('vi-VN').format(sp.list_price || product.list_price)}đ)`);
      }
      if (sp.online_coupon) {
        descParts.push(`Giảm thêm online: ${sp.online_coupon}`);
      }
      if (sp.kfi_value) {
        descParts.push(`KFI thưởng thêm: ${new Intl.NumberFormat('vi-VN').format(sp.kfi_value)}đ`);
      }
      if (sp.gift_name) {
        descParts.push(`Quà tặng: ${sp.gift_name} (Mã: ${sp.gift_sku || 'N/A'})`);
      }
      if (sp.limit_qty) {
        descParts.push(`Số lượng: ${sp.limit_qty}`);
      }

      // Xác định chính xác loại CTKM (promo_type)
      let promoType = 'Discount';
      const upperSheet = (sp.sheet_name || '').toUpperCase();
      const upperProg = (sp.program_name || '').toUpperCase();
      const lowerAll = (upperSheet + ' ' + upperProg + ' ' + (sp.conditions || '')).toLowerCase();

      if (upperSheet.includes('HSSV') || upperProg.includes('HSSV')) {
        promoType = 'Học sinh - Sinh viên';
      } else if (upperSheet.includes('ĐỔI ĐIỂM') || upperProg.includes('ĐỔI ĐIỂM') || upperProg.includes('ĐIỂM THI')) {
        promoType = 'Đổi điểm thi';
      } else if (lowerAll.includes('shopeepay') || lowerAll.includes('vnpay')) {
        promoType = 'Ưu đãi thanh toán';
      } else if (lowerAll.includes('mở thẻ') || lowerAll.includes('tpbank') || lowerAll.includes('vib') || lowerAll.includes('trả góp') || lowerAll.includes('homecredit') || lowerAll.includes('shinhan')) {
        promoType = 'Trả góp & Thẻ';
      } else if (lowerAll.includes('combo')) {
        promoType = 'Combo';
      } else if (sp.gift_name || sp.gift_sku || lowerAll.includes('tặng') || lowerAll.includes('quà')) {
        promoType = 'Gift';
      } else if (sp.online_coupon) {
        promoType = 'Coupon';
      }

      return {
        id: `sheet_${sp.id}`,
        name: sp.program_name || sp.sheet_name,
        description: descParts.join(' | ') || sp.conditions || 'Xem chi tiết thể lệ chương trình',
        start_date: sp.start_date,
        end_date: sp.end_date,
        channel: sp.apply_channels || 'All channels',
        promo_type: promoType,
        group_name: sp.sheet_name,
        special_conditions: sp.conditions,
        conditions: sp.conditions,
        detail_link: sp.detail_link,
        is_sheet_promo: true,
        discount_amount_calc: discount,
        detail_fields: detail_fields,
        show_multiple_in_group: true,
      };
    });

    if (promosRaw && promosRaw.length > 0 && skuInput) {
      // 1. Tìm xem trong database KFI có thông tin SKU này không?
      const { data: kfiItem } = await supabase
        .from('kfi_list')
        .select('*')
        .eq('sku', skuInput) // skuInput là biến SKU người dùng đang tìm
        .single();

      // 2. Duyệt qua các CTKM, nếu gặp loại KFI thì xử lý
      promosRaw = promosRaw.filter(p => {
        if (p.promo_type === 'KFI') {
          // Nếu SKU này CÓ trong bảng KFI và có tiền thưởng -> Giữ lại & Cập nhật nội dung
          if (kfiItem && (kfiItem.kfi_end_user > 0 || kfiItem.kfi_dealer > 0)) {
            // Ghi đè mô tả CTKM bằng số tiền thực tế của SKU này
            const fmt = (n) => new Intl.NumberFormat('vi-VN').format(n);
            p.description = `🎁 Thưởng User: ${fmt(kfiItem.kfi_end_user)}đ  |  Dealer: ${fmt(kfiItem.kfi_dealer)}đ`;

            // Gắn cờ để giao diện biết mà tô màu
            p.is_kfi_sku = true;

            // Gắn tiền vào biến này để sorting nếu cần (đưa lên top)
            p.discount_amount_calc = kfiItem.kfi_end_user;

            return true; // Giữ lại hiển thị
          } else {
            // Nếu SKU này không nằm trong list KFI -> Ẩn CTKM KFI đi (đỡ rác)
            return false;
          }
        }
        return true; // Các loại khác giữ nguyên
      });
    }

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
        if (p.exclude_brands.map(b => b.toLowerCase()).includes(pBrand)) return false;
      }
      if (p.exclude_subcats && p.exclude_subcats.length > 0) {
        if (p.exclude_subcats.map(s => s.toLowerCase()).some(ex => pSubcat.includes(ex))) return false;
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
      if (p.apply_to_brands && p.apply_to_brands.map(b => b.toLowerCase()).includes(pBrand)) return true;
      if (p.apply_to_categories && p.apply_to_categories.map(c => c.toLowerCase()).includes(pCategory)) return true;
      if (p.apply_to_subcats && p.apply_to_subcats.map(s => s.toLowerCase()).includes(pSubcat)) return true;
      if ((p.promotion_skus || []).some(ps => ps.sku === product.sku)) return true;
      // [MỚI] Check xem SKU có nằm trong cấu hình Combo/Gift (detail_fields) không
      if (p.detail_fields) {
        // Check Combo
        if (p.detail_fields.combos) {
          const combos = typeof p.detail_fields.combos === 'object' ? Object.values(p.detail_fields.combos) : [];
          for (const c of combos) {
            if (c.skus && Array.isArray(c.skus)) {
              // Nếu SKU đang tìm nằm trong mảng skus của combo -> Lấy CTKM này
              if (c.skus.includes(product.sku)) return true;
            }
          }
        }
        // Check Gift (nếu muốn tìm "SKU này có được tặng không" thì bật logic này)
        if (p.detail_fields.gift_options) {
          const gifts = typeof p.detail_fields.gift_options === 'object' ? Object.values(p.detail_fields.gift_options) : [];
          for (const g of gifts) {
            if (g.skus && Array.isArray(g.skus)) {
              if (g.skus.includes(product.sku)) return true;
            }
          }
        }
      }
      return false;
    });

    console.log(`[DEBUG] Bước 3: Sau khi lọc theo SKU/Branch, còn lại ${filteredPromos.length} CTKM.`);

    internalContest = filteredPromos.find(p => p.promo_type === 'Thi đua nội bộ') || null;
    const regularPromos = [
      ...filteredPromos.filter(p => p.promo_type !== 'Thi đua nội bộ'),
      ...mappedSheetPromos
    ];

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
    //let availablePromos = (regularPromos || []).map(p => {
    //const ruleDiscount = calcDiscountAmt(p, price);
    //const couponDiscount = getMaxCouponDiscount(p);
    //const bestDiscount = Math.max(ruleDiscount, couponDiscount);
    //return { ...p, discount_amount_calc: bestDiscount };

    // [MỚI] Logic lấy thông tin phụ cho Gift/Combo (Tên & Tồn kho)
    let extraSkuInfoMap = {}; // Biến này sẽ được truyền xuống view
    let extraSkusToFetch = new Set();

    // Duyệt qua các CTKM đã lọc để gom tất cả SKU phụ (quà tặng, món trong combo)
    regularPromos.forEach(p => {
      if (p.detail_fields) {
        if (p.detail_fields.gift_options) {
          Object.values(p.detail_fields.gift_options).forEach(g => {
            if (Array.isArray(g.skus)) g.skus.forEach(s => extraSkusToFetch.add(s));
          });
        }
        if (p.detail_fields.combos) {
          Object.values(p.detail_fields.combos).forEach(c => {
            if (Array.isArray(c.skus)) c.skus.forEach(s => extraSkusToFetch.add(s));
          });
        }
        if (p.detail_fields.next_order_target_skus) {
          // Dùng hàm parseSkus (hoặc split string) để tách chuỗi thành mảng
          const list = String(p.detail_fields.next_order_target_skus)
            .split(/[,\n\r\s]+/)
            .map(s => s.trim())
            .filter(Boolean);

          list.forEach(s => extraSkusToFetch.add(s));
        }
      }
    });

    // Nếu có SKU phụ, gọi DB lấy Tên và BigQuery lấy Tồn
    if (extraSkusToFetch.size > 0) {
      const skuArray = Array.from(extraSkusToFetch);

      // 1. Lấy Tên sản phẩm từ Supabase
      const { data: extraInfos } = await supabase.from('skus').select('sku, product_name').in('sku', skuArray);
      (extraInfos || []).forEach(item => {
        if (!extraSkuInfoMap[item.sku]) extraSkuInfoMap[item.sku] = { name: item.product_name, stock: 0 };
      });

      // 2. Lấy Tồn kho từ BigQuery (Nếu có cấu hình)
      if (bigquery && userBranch) {
        try {
          // Tái sử dụng hàm getInventoryCounts có sẵn trong server.js
          // Hàm này trả về Map<SKU, Map<Branch, Counts>>
          const extraInventoryMap = await getInventoryCounts(skuArray, userBranch, isGlobalAdmin, new Date().toISOString().split('T')[0]);

          skuArray.forEach(sku => {
            const branchMap = extraInventoryMap.get(sku);

            let totalStock = 0;

            if (branchMap) {
              if (isGlobalAdmin) {
                // Nếu là Admin: Cộng tổng tồn kho của TẤT CẢ chi nhánh
                branchMap.forEach((counts, bId) => {
                  // Chỉ tính hàng bán mới (hoặc tùy logic bạn muốn cộng thêm)
                  totalStock += (counts.hang_ban_moi || 0) + (counts.trung_bay_chi_dinh || 0);
                });
              } else {
                // Nếu là User thường: Chỉ lấy tồn kho của chi nhánh user
                const counts = branchMap.get(userBranch);
                if (counts) {
                  totalStock = (counts.hang_ban_moi || 0) + (counts.trung_bay_chi_dinh || 0);
                }
              }
            }

            if (extraSkuInfoMap[sku]) {
              extraSkuInfoMap[sku].stock = totalStock;
            }
          });
        } catch (e) { console.error("Lỗi lấy tồn kho quà tặng:", e.message); }
      }
    }
    // 5) Tính toán giá trị giảm cho TẤT CẢ các CTKM hợp lệ ban đầu
    let candidates = (regularPromos || []).map(p => {
      let ruleDiscount = calcDiscountAmt(p, price);
      let couponDiscount = getMaxCouponDiscount(p);
      let bestDiscount = Math.max(ruleDiscount, couponDiscount);

      // Tính toán giá trị giảm cho các ưu đãi % hoặc coupon toàn sàn nếu chưa có
      if (bestDiscount === 0 && price > 0) {
        if (p.promo_percent && Number(p.promo_percent) > 0) {
          let calc = (price * Number(p.promo_percent)) / 100;
          if (p.max_discount_amount) calc = Math.min(calc, Number(p.max_discount_amount));
          if ((p.name || '').toLowerCase().includes('shopee')) calc = Math.min(calc, 500000);
          bestDiscount = Math.round(calc);
          if (lowerCoupon.includes('5 triệu') || lowerCoupon.includes('5tr') || lowerCoupon.includes('5.000.000')) {
            bestDiscount = 5000000;
          } else if (lowerCoupon.includes('3 triệu') || lowerCoupon.includes('3tr')) {
            bestDiscount = 3000000;
          } else if (lowerCoupon.includes('2 triệu') || lowerCoupon.includes('2tr')) {
            bestDiscount = 2000000;
          } else if (lowerCoupon.includes('1 triệu') || lowerCoupon.includes('1tr')) {
            bestDiscount = 1000000;
          } else if (lowerCoupon.includes('vnpay')) {
            if (price >= 70000000) bestDiscount = 1000000;
            else if (price >= 30000000) bestDiscount = 250000;
            else if (price >= 20000000) bestDiscount = 150000;
            else if (price >= 10000000) bestDiscount = 100000;
          } else if (lowerCoupon.includes('800k')) {
            bestDiscount = 800000;
          } else if (lowerCoupon.includes('600k')) {
            bestDiscount = 600000;
          } else if (lowerCoupon.includes('500k')) {
            bestDiscount = 500000;
          } else if (lowerCoupon.includes('200k')) {
            bestDiscount = 200000;
          } else if (lowerCoupon.includes('150k')) {
            bestDiscount = 150000;
          } else if (lowerCoupon.includes('100k')) {
            bestDiscount = 100000;
          } else if (lowerCoupon.includes('50k')) {
            bestDiscount = 50000;
          }
        }
      }

      // Nhận diện chương trình Đổi điểm thi và HSSV để gán giá trị giảm tối đa
      const lowerName = (p.name || '').toLowerCase();
      const lowerSheet = (p.sheet_name || '').toLowerCase();
      const lowerType = (p.promo_type || '').toLowerCase();

      if (lowerName.includes('đổi điểm thi') || lowerSheet.includes('đổi điểm thi') || lowerType.includes('đổi điểm thi')) {
        bestDiscount = 5000000;
      } else if (lowerName.includes('hssv') || lowerSheet.includes('hssv') || lowerType.includes('hssv')) {
        bestDiscount = 500000;
      }

      return { ...p, discount_amount_calc: bestDiscount };
    });

    // Lọc theo giá tối thiểu đơn hàng
    if (price > 0) {
      candidates = candidates.filter(p => Number(p.min_order_value || 0) <= price);
    }

    // --- BƯỚC QUAN TRỌNG: GỘP NHÓM & TÌM BEST DEAL ---
    const bestByGroup = {};
    const finalDisplayList = [];

    for (const p of candidates) {
      if (p.show_multiple_in_group) {
        finalDisplayList.push(p);
        continue;
      }

      const groupKey = p.group_name || `__no_group_${p.id}__`;

      if (!bestByGroup[groupKey]) {
        bestByGroup[groupKey] = p;
      } else {
        const currentBest = bestByGroup[groupKey];
        if (p.discount_amount_calc > currentBest.discount_amount_calc) {
          bestByGroup[groupKey] = p;
        }
      }
    }

    Object.values(bestByGroup).forEach(p => finalDisplayList.push(p));

    // Áp dụng gán icon nhận diện cho từng CTKM
    const enrichedDisplayList = finalDisplayList.map(enrichPromoForDisplay);

    // --- SẮP XẾP GIẢM DẦN THEO GIÁ TRỊ GIẢM ---
    const sortedPromosList = [...enrichedDisplayList].sort((a, b) => {
      const diff = (b.discount_amount_calc || 0) - (a.discount_amount_calc || 0);
      if (diff !== 0) return diff;
      
      // Khi bằng tiền: Ưu tiên các CTKM trọng điểm lớn (Đổi điểm thi -> HSSV)
      const isDiemThiA = (a.name || '').includes('Đổi điểm thi') ? 1 : 0;
      const isDiemThiB = (b.name || '').includes('Đổi điểm thi') ? 1 : 0;
      if (isDiemThiB !== isDiemThiA) return isDiemThiB - isDiemThiA;

      const isHssvA = (a.name || '').includes('HSSV') ? 1 : 0;
      const isHssvB = (b.name || '').includes('HSSV') ? 1 : 0;
      if (isHssvB !== isHssvA) return isHssvB - isHssvA;

      // Ưu tiên có quà
      const hasGiftA = a.promo_type === 'Gift' || a.gift_name ? 1 : 0;
      const hasGiftB = b.promo_type === 'Gift' || b.gift_name ? 1 : 0;
      return hasGiftB - hasGiftA;
    });

    // --- BẢNG MA TRẬN KẾT HỢP (COMPATIBILITY MATRIX) ---
    const matrixPromos = sortedPromosList.map((p, idx) => ({
      idx,
      id: p.id,
      name: p.name,
      shortName: (p.name || '').length > 30 ? (p.name || '').slice(0, 30) + '...' : p.name,
      icon: p.__icon || '🏷️',
      iconBg: p.__icon_bg || '#f1f5f9',
      iconColor: p.__icon_color || '#334155',
      categoryBadge: p.__category_badge || 'Khuyến mãi',
      discountLabel: p.__discount_label || (p.discount_amount_calc > 0 ? `-${new Intl.NumberFormat('vi-VN').format(p.discount_amount_calc)}₫` : 'Ưu đãi'),
      discount_amount_calc: p.discount_amount_calc || 0,
      detail_link: p.is_sheet_promo ? (p.detail_link || '#') : `/promotion-detail/${p.id}`,
      is_sheet_promo: !!p.is_sheet_promo,
      group: p.group_name || '',
      type: p.promo_type || ''
    }));

    const compatMatrix = {
      promos: matrixPromos,
      cells: []
    };

    for (let i = 0; i < matrixPromos.length; i++) {
      const row = [];
      const pA = sortedPromosList[i];
      for (let j = 0; j < matrixPromos.length; j++) {
        if (i === j) {
          row.push({ status: 'self', text: '➖', note: 'Chính nó' });
          continue;
        }
        const pB = sortedPromosList[j];

        const typeA = (pA.promo_type || '').toLowerCase();
        const typeB = (pB.promo_type || '').toLowerCase();
        const nameA = (pA.name || '').toLowerCase();
        const nameB = (pB.name || '').toLowerCase();
        const groupA = (pA.group_name || '').toLowerCase();
        const groupB = (pB.group_name || '').toLowerCase();

        // CHỈ DÙNG TÊN/NHÓM/TYPE ĐỂ PHÂN LOẠI DANH TÍNH CTKM
        const idA = (nameA + ' ' + groupA + ' ' + typeA).toLowerCase();
        const idB = (nameB + ' ' + groupB + ' ' + typeB).toLowerCase();

        const condA = (pA.conditions || pA.special_conditions || pA.description || '').toLowerCase();
        const condB = (pB.conditions || pB.special_conditions || pB.description || '').toLowerCase();

        // 1. Cổng thanh toán (ShopeePay, VNPAY...)
        const isPaymentA = idA.includes('thanh toán') || idA.includes('shopee') || idA.includes('vnpay');
        const isPaymentB = idB.includes('thanh toán') || idB.includes('shopee') || idB.includes('vnpay');

        // 2. Mở thẻ tín dụng (TPBank EVO, VIB...)
        const isCardA = idA.includes('mở thẻ') || idA.includes('tpbank') || idA.includes('vib');
        const isCardB = idB.includes('mở thẻ') || idB.includes('tpbank') || idB.includes('vib');

        // 3. Trả góp (Lãi ưu đãi, 0%, Home Credit, Shinhan, Payoo...)
        const isInstallmentA = idA.includes('trả góp') || idA.includes('góp 0%') || idA.includes('homecredit') || idA.includes('shinhan') || idA.includes('payoo') || (idA.includes('góp') && !idA.includes('mở thẻ'));
        const isInstallmentB = idB.includes('trả góp') || idB.includes('góp 0%') || idB.includes('homecredit') || idB.includes('shinhan') || idB.includes('payoo') || (idB.includes('góp') && !idB.includes('mở thẻ'));

        // 4. Quà tặng (Gift)
        const isGiftA = typeA === 'gift' || idA.includes('quà') || idA.includes('tặng') || !!pA.gift_name;
        const isGiftB = typeB === 'gift' || idB.includes('quà') || idB.includes('tặng') || !!pB.gift_name;

        // 5. Combo
        const isComboA = typeA.includes('combo') || idA.includes('combo');
        const isComboB = typeB.includes('combo') || idB.includes('combo');

        // 6. Học sinh - Sinh viên
        const isHssvA = idA.includes('hssv') || idA.includes('sinh viên') || idA.includes('học sinh');
        const isHssvB = idB.includes('hssv') || idB.includes('sinh viên') || idB.includes('học sinh');

        // 7. Đổi điểm thi THPT
        const isDiemThiA = idA.includes('điểm thi') || idA.includes('đổi điểm');
        const isDiemThiB = idB.includes('điểm thi') || idB.includes('đổi điểm');

        // 8. Coupon / Voucher giảm giá trực tiếp khác
        const isCouponA = typeA.includes('coupon') || typeA.includes('voucher') || idA.includes('coupon') || idA.includes('voucher');
        const isCouponB = typeB.includes('coupon') || typeB.includes('voucher') || idB.includes('coupon') || idB.includes('voucher');

        // --- RULE 1: Trả góp vs Trả góp (Chỉ chọn 1 chương trình trả góp trên 1 đơn hàng) ---
        if (isInstallmentA && isInstallmentB) {
          row.push({ status: 'deny', text: '❌', note: 'Chỉ áp dụng 1 hình thức trả góp/đơn hàng' });
          continue;
        }

        // --- RULE 2: Trả góp vs Quà tặng (Gift) ---
        // Thể lệ: "Không áp dụng đồng thời với chương trình khuyến mãi, kể cả QUÀ TẶNG MẶC ĐỊNH"
        if ((isInstallmentA && isGiftB) || (isInstallmentB && isGiftA)) {
          row.push({ status: 'deny', text: '❌', note: 'Trả góp không áp dụng cùng CTKM quà tặng (kể cả quà mặc định)' });
          continue;
        }

        // --- RULE 3: Trả góp vs Cổng thanh toán (ShopeePay, VNPAY, ZaloPay...) ---
        // Thể lệ: "Không áp dụng đồng thời ưu đãi thanh toán khác như Zalopay hay VNPay"
        if ((isInstallmentA && isPaymentB) || (isInstallmentB && isPaymentA)) {
          row.push({ status: 'deny', text: '❌', note: 'Trả góp không áp dụng cùng cổng thanh toán' });
          continue;
        }

        // --- RULE 4: Trả góp vs Mở thẻ tín dụng (TPBank EVO, VIB...) ---
        if ((isInstallmentA && isCardB) || (isInstallmentB && isCardA)) {
          row.push({ status: 'deny', text: '❌', note: 'Không áp dụng đồng thời Trả góp và Mở thẻ tín dụng' });
          continue;
        }

        // --- RULE 5: Trả góp vs Combo ---
        if ((isInstallmentA && isComboB) || (isInstallmentB && isComboA)) {
          row.push({ status: 'deny', text: '❌', note: 'Trả góp không áp dụng cùng CTKM Combo' });
          continue;
        }

        // --- RULE 6: Trả góp vs Coupon giảm giá khác (ngoại trừ Đổi điểm / HSSV dành cho Tân SV) ---
        if (((isInstallmentA && isCouponB && !isDiemThiB && !isHssvB) || (isInstallmentB && isCouponA && !isDiemThiA && !isHssvA))) {
          row.push({ status: 'deny', text: '❌', note: 'Trả góp không áp dụng cùng Coupon giảm giá khác' });
          continue;
        }

        // --- RULE 7: Trả góp vs Đổi điểm thi / HSSV ---
        // Thể lệ: "Lưu ý: Đối với Tân SV, được áp dụng đồng thời với chương trình Đổi điểm / HSSV"
        if ((isInstallmentA && (isDiemThiB || isHssvB)) || (isInstallmentB && (isDiemThiA || isHssvA))) {
          row.push({ status: 'allow', text: '✅', note: 'Áp dụng đồng thời cho Tân SV / HSSV' });
          continue;
        }

        // --- RULE 8: Cổng thanh toán vs Cổng thanh toán (ShopeePay vs VNPAY) ---
        if (isPaymentA && isPaymentB) {
          row.push({ status: 'deny', text: '❌', note: 'Chỉ áp dụng 1 hình thức thanh toán/đơn' });
          continue;
        }

        // --- RULE 9: Cổng thanh toán vs Mở thẻ tín dụng ---
        if ((isPaymentA && isCardB) || (isPaymentB && isCardA)) {
          row.push({ status: 'deny', text: '❌', note: 'Không áp dụng đồng thời Cổng thanh toán và Mở thẻ' });
          continue;
        }

        // --- RULE 10: Mở thẻ vs Mở thẻ ---
        if (isCardA && isCardB) {
          row.push({ status: 'deny', text: '❌', note: 'Chỉ áp dụng 1 ưu đãi mở thẻ/đơn' });
          continue;
        }

        // --- RULE 11: HSSV vs Đổi điểm thi (Không cộng dồn 2 gói HSSV) ---
        if ((isHssvA && isDiemThiB) || (isHssvB && isDiemThiA)) {
          row.push({ status: 'deny', text: '❌', note: 'Không áp dụng đồng thời HSSV và Đổi điểm thi' });
          continue;
        }

        // --- RULE 12: HSSV / Đổi điểm thi vs Coupon giảm giá khác ---
        if (((isHssvA || isDiemThiA) && (isCouponB && !isPaymentB)) || ((isHssvB || isDiemThiB) && (isCouponA && !isPaymentA))) {
          row.push({ status: 'deny', text: '❌', note: 'Không áp dụng cùng Coupon giảm giá khác' });
          continue;
        }

        // --- RULE 13: Thể lệ ghi rõ loại trừ (Dynamic Conditions Text Check) ---
        if (condA.includes('không áp dụng đồng thời với chương trình khuyến mãi') || condA.includes('kể cả quà tặng')) {
          if (isGiftB || isComboB || isPaymentB) {
            row.push({ status: 'deny', text: '❌', note: 'Thể lệ quy định không áp dụng đồng thời' });
            continue;
          }
        }
        if (condB.includes('không áp dụng đồng thời với chương trình khuyến mãi') || condB.includes('kể cả quà tặng')) {
          if (isGiftA || isComboA || isPaymentA) {
            row.push({ status: 'deny', text: '❌', note: 'Thể lệ quy định không áp dụng đồng thời' });
            continue;
          }
        }

        if (pA.compat_exclude_names && pA.compat_exclude_names.includes(pB.group_name)) {
          row.push({ status: 'deny', text: '❌', note: 'Quy định loại trừ nhau' });
          continue;
        }
        if (pB.compat_exclude_names && pB.compat_exclude_names.includes(pA.group_name)) {
          row.push({ status: 'deny', text: '❌', note: 'Quy định loại trừ nhau' });
          continue;
        }

        row.push({ status: 'allow', text: '✅', note: 'Áp dụng đồng thời' });
      }
      compatMatrix.cells.push(row);
    }
    compatMatrix.promoList = compatMatrix.promos;
    compatMatrix.matrix = compatMatrix.cells.map(row => row.map(cell => (typeof cell === 'object' ? cell.status : cell)));

    // Gán danh sách các CTKM CỤ THỂ có thể dùng chung cho từng CTKM trong sortedPromosList
    for (let i = 0; i < sortedPromosList.length; i++) {
      const allowedSpecific = [];
      for (let j = 0; j < sortedPromosList.length; j++) {
        if (i === j) continue;
        const cell = compatMatrix.cells[i] && compatMatrix.cells[i][j];
        if (cell && (cell === 'allow' || cell.status === 'allow')) {
          const target = sortedPromosList[j];
          let shortLabel = target.name || '';
          if (shortLabel.length > 20) {
            shortLabel = shortLabel.substring(0, 18) + '…';
          }
          allowedSpecific.push({
            id: target.id,
            name: target.name,
            shortLabel: shortLabel,
            icon: target.__icon || '🏷️',
            badge: target.__category_badge || '',
            discount_label: target.__discount_label || '',
            end_date: target.end_date || '',
            apply_channels: target.__apply_channels || target.channel || target.apply_channels || 'All channels',
            conditions: target.__conditions || target.conditions || target.special_conditions || target.description || '',
            detail_link: target.__detail_link || target.detail_link || '',
            sku: target.sku || '',
            source_sheet: target.source_sheet || '',
            compatible_icons: target.__compatible_icons || []
          });
        }
      }
      sortedPromosList[i].__compatible_specific_promos = allowedSpecific;
      if (matrixPromos[i]) {
        matrixPromos[i].__compatible_specific_promos = allowedSpecific;
      }
    }


    // --- BƯỚC PHÂN LOẠI UI (HOT, PAYMENT, FUTURE...) ---
    const promoGroups = {
      hot: [],
      future: [],
      payment: [],
      installment: [],
      other: []
    };

    sortedPromosList.forEach(p => {
      const type = p.promo_type || '';
      const lowerName = (p.name || '').toLowerCase();

      if (type === 'Combo' || type === 'Gift' || type === 'Quà tặng (Gift)') {
        promoGroups.other.push(p);
      } else if (type === 'Tặng mã giảm đơn hàng sau') {
        promoGroups.future.push(p);
      } else if (type === 'Ưu đãi thanh toán' || lowerName.includes('shopee') || lowerName.includes('vnpay')) {
        promoGroups.payment.push(p);
      } else if (type.includes('Trả góp') || lowerName.includes('góp') || lowerName.includes('mở thẻ')) {
        promoGroups.installment.push(p);
      } else if (p.discount_value_type === 'amount' || p.discount_value_type === 'percent' || type === 'Coupon' || type === 'Voucher' || p.discount_amount_calc > 0) {
        promoGroups.hot.push(p);
      } else {
        promoGroups.other.push(p);
      }
    });

    // Sắp xếp lại nhóm HOT
    promoGroups.hot.sort((a, b) => b.discount_amount_calc - a.discount_amount_calc);

    const chosenHotPromos = pickStackable(promoGroups.hot);
    totalDiscount = chosenHotPromos.reduce((s, p) => s + Number(p.discount_amount_calc || 0), 0);
    finalPrice = Math.max(0, price - totalDiscount);

    promotions = sortedPromosList;

    return res.render('promotion', {
      title: 'CTKM theo SKU', currentPage: 'promotion',
      query: skuInput, product,
      promotions,
      sortedPromosList,
      compatMatrix,
      promoGroups,
      extraSkuInfoMap,
      internalContest, chosenPromos: chosenHotPromos,
      totalDiscount, finalPrice, comparisonCount, error: null,
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


// --- Thay thế toàn bộ đoạn app.get('/promo-management') cũ bằng đoạn này ---
app.get('/promo-management', requireAuth, requireManager, async (req, res) => {
  try {
    const user = req.session.user;

    // 1. Cấu hình Phân trang (Pagination)
    const page = parseInt(req.query.page) || 1;
    const limit = 20; // Số lượng hiển thị mỗi trang
    const offset = (page - 1) * limit;

    // 2. Lấy tham số Filter từ URL
    const { q, group, subgroup, sku, status, tab } = req.query;
    const activeTab = tab || 'db';

    // 3. Khởi tạo Query chính
    // count: 'exact' để đếm tổng số dòng phục vụ phân trang
    let query = supabase
      .from('promotions')
      .select('*, promotion_skus(count), promotion_excluded_skus(count)', { count: 'exact' });

    // --- Áp dụng các bộ lọc ---

    // Tìm kiếm theo tên
    if (q) {
      const { data: skuMatches } = await supabase
        .from('promotion_skus')
        .select('promotion_id')
        .ilike('sku', '%' + q + '%');
      
      const matchedPromoIds = (skuMatches || []).map(m => m.promotion_id).filter(Boolean);

      if (matchedPromoIds.length > 0) {
        query = query.or('name.ilike.%' + q + '%,id.in.(' + matchedPromoIds.join(',') + ')');
      } else {
        query = query.ilike('name', '%' + q + '%');
      }
    }

    // Lọc theo Group
    if (group) {
      query = query.eq('group_name', group);
    }

    // Lọc theo Biến thể (tên CTKM cụ thể trong nhóm)
    if (subgroup) {
      query = query.ilike('name', `%${subgroup}%`);
    }

    // [MỚI] Lọc theo Trạng thái (Active / Expired)
    const now = new Date().toISOString(); // Lấy thời gian hiện tại chuẩn ISO
    if (status === 'active') {
      // Đang hoạt động: Ngày kết thúc >= Hiện tại
      query = query.gte('end_date', now);
    } else if (status === 'expired') {
      // Đã hết hạn: Ngày kết thúc < Hiện tại
      query = query.lt('end_date', now);
    }

    // Sắp xếp & Phân trang
    query = query.order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    // Thực thi Query
    const { data: promotions, count, error } = await query;

    if (error) throw error;

    // 4. Lấy dữ liệu hỗ trợ (Groups, Compatibility) cho Modal tạo mới
    // Lấy list CTKM để làm chức năng "Áp dụng cùng / Loại trừ"
    const { data: allPromosForCompatRaw } = await supabase
      .from('promotions')
      .select('id, name, group_name, subgroup_name, status')
      .order('name', { ascending: true });

    const allPromosForCompat = (allPromosForCompatRaw || []).filter(p => (p.status || 'active') === 'active');

    // Lấy danh sách Group/Subgroup duy nhất để hiển thị Dropdown lọc
    // (Cách này hơi thủ công nhưng an toàn với code cũ của bạn)
    const { data: allGroupsData } = await supabase
      .from('promotions')
      .select('group_name, subgroup_name, name');

    const groupSet = new Set();
    const subgroupSet = new Set();
    const groupSubgroupMap = {}; // { groupName: [promoName1, promoName2] }
    (allGroupsData || []).forEach(r => {
      if (r.group_name) {
        groupSet.add(r.group_name);
        if (r.name) {
          if (!groupSubgroupMap[r.group_name]) groupSubgroupMap[r.group_name] = new Set();
          groupSubgroupMap[r.group_name].add(r.name);
        }
      }
      // Keep subgroupSet for backward compat (subgroup_name)
      if (r.subgroup_name) subgroupSet.add(r.subgroup_name);
    });
    // Convert Sets to sorted Arrays for JSON serialization
    Object.keys(groupSubgroupMap).forEach(k => {
      groupSubgroupMap[k] = Array.from(groupSubgroupMap[k]).sort();
    });

    // --- FETCH GOOGLE SHEET PROMOTIONS ---
    const { data: sheetPromosRaw } = await supabase
      .from('promo_sku_master')
      .select('id, sheet_name, program_name, sku, category, product_name, brand, start_date, end_date, detail_link, conditions, online_coupon, gift_name, gift_sku')
      .order('created_at', { ascending: false });

    const uniqueSheetPromosMap = {};
    (sheetPromosRaw || []).forEach(sp => {
      const key = sp.sheet_name + "_" + (sp.program_name || 'Chung');
      if (!uniqueSheetPromosMap[key]) {
        uniqueSheetPromosMap[key] = {
          ...sp,
          sku_count: sp.sku ? 1 : 0,
          skus: [sp.sku].filter(Boolean)
        };
      } else {
        if (sp.sku) {
          uniqueSheetPromosMap[key].sku_count++;
          uniqueSheetPromosMap[key].skus.push(sp.sku);
        }
      }
    });

    let sheetPromotions = Object.values(uniqueSheetPromosMap);

    // Apply filters to Google Sheet promotions
    if (q) {
      const searchLower = q.toLowerCase();
      sheetPromotions = sheetPromotions.filter(sp => {
        const nameMatch = (sp.program_name || '').toLowerCase().includes(searchLower) || (sp.sheet_name || '').toLowerCase().includes(searchLower);
        const condMatch = (sp.conditions || '').toLowerCase().includes(searchLower);
        const skuMatch = (sp.skus || []).some(s => s.toLowerCase().includes(searchLower));
        return nameMatch || condMatch || skuMatch;
      });
    }

    if (group) {
      sheetPromotions = sheetPromotions.filter(sp => sp.sheet_name === group);
    }

    const todayStrOnly = new Date().toISOString().slice(0, 10);
    if (status === 'active') {
      sheetPromotions = sheetPromotions.filter(sp => sp.end_date >= todayStrOnly);
    } else if (status === 'expired') {
      sheetPromotions = sheetPromotions.filter(sp => sp.end_date < todayStrOnly);
    }

    // 5. Render View
    res.render('promo-management', {
      title: 'Quản lý CTKM',
      currentPage: 'promo-management',
      promotions: promotions || [],
      sheetPromotions: sheetPromotions || [],
      activeTab: activeTab || 'db',

      // Dữ liệu lọc
      groups: Array.from(groupSet).sort(),
      subgroups: Array.from(subgroupSet).sort(),
      groupSubgroupMap,

      // Trạng thái hiện tại của bộ lọc
      q: q || '',
      selectedGroup: group || '',
      selectedSubgroup: subgroup || '',
      selectedStatus: status || '', // [MỚI] Truyền status xuống EJS

      // Dữ liệu phân trang
      page,
      totalPages: Math.ceil((count || 0) / limit),
      totalItems: count,

      // User & Auth
      user: req.session?.user || null,

      // Dữ liệu cho Modal tạo mới
      allPromosForCompat,
      compatAllowIds: [],
      compatExclIds: [],

      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
    });

  } catch (err) {
    console.error('Promo management fatal error:', err);
    res.status(500).send('Lỗi khi tải trang quản lý CTKM: ' + err.message);
  }
});

// [MỚI] API Xóa nhiều CTKM cùng lúc
app.post('/api/promotions/bulk-delete', requireAuth, requireManager, async (req, res) => {
  try {
    const { ids } = req.body; // Nhận mảng ID từ client: [1, 5, 8]

    // Validate dữ liệu
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ ok: false, error: 'Chưa chọn CTKM nào để xóa.' });
    }

    // Thực hiện xóa trong Database
    // Lưu ý: Nếu DB của bạn có ràng buộc khóa ngoại (Foreign Key) chưa set ON DELETE CASCADE,
    // bạn có thể cần xóa các bảng con (promotion_skus, v.v.) trước.
    // Tuy nhiên Supabase thường xử lý tốt nếu setup đúng.

    const { error } = await supabase
      .from('promotions')
      .delete()
      .in('id', ids);

    if (error) throw error;

    res.json({
      ok: true,
      message: `Đã xóa vĩnh viễn ${ids.length} chương trình khuyến mãi.`
    });

  } catch (e) {
    console.error("Lỗi Bulk Delete:", e);
    res.status(500).json({ ok: false, error: e.message });
  }
});
// [MỚI] Route Tạo CTKM (Đã bao gồm Branch, Exclude Mở Rộng, Show Multiple)
app.post('/create-promotion', requireAuth, async (req, res) => {
  try {
    const {
      name, description, start_date, end_date, channel, promo_type, coupon_code,
      group_name, apply_to_type, apply_brands, apply_categories, apply_subcats,
      skus, excluded_skus, has_coupon_list, coupons,
      // LƯU Ý: Lấy trực tiếp biến detail từ body, Express đã tự parse thành Object
      detail
    } = req.body;

    if (typeof detail === 'string') {
      try {
        detail = JSON.parse(detail);
      } catch (e) {
        detail = {}; // Parse lỗi thì để rỗng
      }
    }
    let cleanedDetail = {};
    if (detail && typeof detail === 'object') {
      Object.keys(detail).forEach(key => {
        const val = detail[key];
        // Nếu là Gift/Combo (Object/Array), giữ nguyên nếu có dữ liệu
        if (typeof val === 'object' && val !== null) {
          // Kiểm tra sơ bộ nếu object rỗng
          if (Object.keys(val).length > 0) cleanedDetail[key] = val;
        }
        // Nếu là String (HTML RTE), giữ lại nếu không rỗng
        else if (typeof val === 'string' && val.trim() !== '') {
          cleanedDetail[key] = val.trim();
        }
      });
    }
    // const apply_with = req.body['apply_with[]'];
    //const exclude_with = req.body['exclude_with[]'];
    const getArrayParams = (source, key) => {
      let val = source[key] || source[key + '[]'];
      if (!val) return [];
      return Array.isArray(val) ? val : [val];
    };

    const apply_with = getArrayParams(req.body, 'apply_with');
    const exclude_with = getArrayParams(req.body, 'exclude_with');
    // --- HELPER ---
    const parseList = (str) => String(str || '').split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
    const uniq = arr => [...new Set(arr)];
    const parseSkus = (v) => { // Helper parse SKU cũ của bạn
      if (!v) return [];
      if (Array.isArray(v)) return v.flatMap(x => String(x).split(/[,\n\r\s]+/)).map(s => s.trim()).filter(Boolean);
      return String(v).split(/[,\n\r\s]+/).map(s => s.trim()).filter(Boolean);
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
      detail_fields: cleanedDetail,
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
  const parseSkus = (v) => { if (!v) return []; if (Array.isArray(v)) return v.flatMap(x => String(x).split(/[,\n\r\s]+/)).map(s => s.trim()).filter(Boolean); return String(v).split(/[,\n\r\s]+/).map(s => s.trim()).filter(Boolean); };
  const uniq = arr => Array.from(new Set((arr || []).filter(v => v !== '' && v != null)));
  const sortStr = arr => uniq(arr).sort((a, b) => String(a).localeCompare(String(b)));
  const sortNum = arr => uniq(arr.map(Number)).sort((a, b) => a - b);
  const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const sameArr = (a, b) => JSON.stringify(sortStr(a || [])) === JSON.stringify(sortStr(b || []));
  const sameArrNum = (a, b) => JSON.stringify(sortNum(a || [])) === JSON.stringify(sortNum(b || []));
  const parseToArray = v => Array.isArray(v) ? v : (v == null || v === '' ? [] : [v]);

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
    let finalDetail = req.body.detail || {};

    // 2. Xử lý riêng Tier Price (vì nó gửi lên dạng JSON string riêng biệt)
    if (req.body.tiers_json) {
      try {
        const tiersObj = JSON.parse(req.body.tiers_json); // Parse chuỗi '{"tiers": [...]}'
        // Gộp vào object finalDetail
        finalDetail = { ...finalDetail, ...tiersObj };
      } catch (err) {
        console.error('Lỗi parse JSON tiers:', err);
      }
    }
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
      coupon_list: couponListData, detail_fields: finalDetail || {},

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

// Hàm đồng bộ dữ liệu thanh lý từ Google Sheets sang Supabase
async function syncClearanceData() {
  try {
    console.log('[SYNC CLEARANCE] Bắt đầu đồng bộ dữ liệu thanh lý...');

    // 1. Lấy dữ liệu mới nhất từ GSheet
    const allItems = await getAllClearanceItems(true);
    if (!allItems || allItems.length === 0) {
      console.log('[SYNC CLEARANCE] Không có dữ liệu để đồng bộ. Bỏ qua.');
      return;
    }

    console.log(`[SYNC CLEARANCE] Đã tải ${allItems.length} sản phẩm từ Sheet. Bắt đầu cập nhật Supabase...`);

    // 2. Xóa toàn bộ dữ liệu cũ trong Supabase
    // Lưu ý: requireAuth không cần thiết ở đây vì cron/job chạy server-side
    const { error: deleteError } = await supabase
      .from('clearance_items')
      .delete()
      .neq('sku', 'DUMMY_NEVER_MATCH'); // Hack nhỏ để xóa toàn bộ table

    if (deleteError) {
      console.error('[SYNC CLEARANCE] Lỗi khi xóa dữ liệu cũ:', deleteError);
      throw deleteError;
    }

    console.log('[SYNC CLEARANCE] Đã xóa dữ liệu cũ.');

    // 3. Insert dữ liệu mới theo batch (từng đợt) để tránh lỗi timeout/payload size
    const batchSize = 500;
    let insertedCount = 0;

    for (let i = 0; i < allItems.length; i += batchSize) {
      const batch = allItems.slice(i, i + batchSize);

      const { error: insertError } = await supabase
        .from('clearance_items')
        .insert(batch);

      if (insertError) {
        console.error(`[SYNC CLEARANCE] Lỗi khi thêm dữ liệu đợt ${i / batchSize + 1}:`, insertError);
        throw insertError;
      }
      insertedCount += batch.length;
      console.log(`[SYNC CLEARANCE] Tiến độ: Đã insert ${insertedCount}/${allItems.length} sản phẩm.`);
    }

    console.log('[SYNC CLEARANCE] Đồng bộ HOÀN TẤT thành công!');
  } catch (error) {
    console.error('[SYNC CLEARANCE] Đã xảy ra lỗi nghiêm trọng:', error);
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
      // Dù không có BOM, vẫn thử lấy tên trong bảng skus
      let finalNameFallback = 'Không tìm thấy BOM';
      const { data: realFinal } = await supabase.from('skus').select('product_name').eq('sku', sku).maybeSingle();
      if (realFinal && realFinal.product_name) finalNameFallback = realFinal.product_name + ' (Chưa có định mức BOM)';

      return res.json({
        ok: true,
        final: { sku, name: finalNameFallback },
        buildableByBranch: []
      });
    }

    // 2.5. Lấy tên thực tế của PCPV từ bảng skus
    let finalName = parts[0]?.final_name || sku;
    const { data: realFinalObj } = await supabase.from('skus').select('product_name').eq('sku', sku).maybeSingle();
    if (realFinalObj && realFinalObj.product_name) {
      finalName = realFinalObj.product_name;
    }

    const compSkus = Array.from(new Set(parts.map(p => p.component_sku)));

    // 3. Lấy tồn kho BigQuery cho TẤT CẢ linh kiện
    // Hàm getInventoryCounts đã xử lý phân quyền (isGlobalAdmin hay userBranch)
    const inventoryMap = await getInventoryCounts(compSkus, userBranch, isGlobalAdmin, today);

    // 4. Xác định các chi nhánh cần tính toán
    const branchesToProcess = isGlobalAdmin
      ? (() => {
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

    // 2. Lấy tên thực tế từ bảng skus (vì bom_relations có thể thiếu tên)
    const finalSkusArray = uniqFinals.map(f => f.sku);

    // Thêm chính comp vào danh sách này để lấy tên của linh kiện gốc luôn
    const querySkus = [...finalSkusArray, comp];

    let compName = '';

    if (querySkus.length > 0) {
      const { data: realProducts, error: e2 } = await supabase
        .from('skus')
        .select('sku, product_name')
        .in('sku', querySkus);

      if (!e2 && realProducts) {
        const productMap = new Map((realProducts).map(p => [p.sku, p.product_name]));

        // Gán tên cho danh sách Thành phẩm
        uniqFinals.forEach(f => {
          if (productMap.has(f.sku) && productMap.get(f.sku)) {
            f.name = productMap.get(f.sku);
          }
        });

        // Gán tên cho Linh kiện
        compName = productMap.get(comp) || '';
      }
    }

    // 3. Trả về danh sách PCPV
    // (Chúng ta sẽ không tính toán tồn kho ở đây, vì nó quá nặng)
    // (User sẽ bấm vào 1 trong các PCPV này để gọi API 'by-final' ở trên)
    res.json({
      ok: true,
      component: comp,
      componentName: compName,
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
// Cache dữ liệu doanh số PCPV
let pcpvSalesCache = {};

// Hàm lấy dữ liệu doanh số bán hàng của SKU PCPV
async function getPcpvSalesData(timeframe, userBranch, isGlobalAdmin, reqBranch, actualSkus = []) {
  const selectedBranch = isGlobalAdmin ? (reqBranch || 'all') : userBranch;
  const cacheKey = `${timeframe}_${selectedBranch}_v2`;
  const nowMs = Date.now();

  // Kiểm tra cache (15 phút)
  if (pcpvSalesCache[cacheKey] && (nowMs - pcpvSalesCache[cacheKey].timestamp < 15 * 60 * 1000)) {
    console.log(`[CACHE HIT] Sử dụng dữ liệu Sales PCPV từ cache cho key: ${cacheKey}`);
    return pcpvSalesCache[cacheKey].data;
  }

  // Tính toán thời gian theo múi giờ Việt Nam
  const now = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Ho_Chi_Minh" }));
  let startDate, endDate;
  endDate = now.toISOString().split('T')[0]; // Hôm nay

  if (timeframe === 'today') {
    startDate = endDate;
  } else if (timeframe === 'week') {
    const day = now.getDay();
    const diff = now.getDate() - day + (day === 0 ? -6 : 1);
    const monday = new Date(now.setDate(diff));
    startDate = monday.toISOString().split('T')[0];
  } else if (timeframe === 'quarter') {
    const currentMonth = now.getMonth();
    const quarterStartMonth = Math.floor(currentMonth / 3) * 3;
    const firstDayOfQuarter = new Date(now.getFullYear(), quarterStartMonth, 1);
    startDate = firstDayOfQuarter.toISOString().split('T')[0];
  } else if (timeframe === 'year') {
    startDate = `${now.getFullYear()}-01-01`;
  } else {
    startDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;
  }

  console.log(`[SALES QUERY] Truy vấn sales PCPV (by branch) từ ${startDate} đến ${endDate} cho branch: ${selectedBranch}`);

  // salesMap: SKU -> total qty (tổng), salesByBranch: SKU -> { branch: qty }
  const salesMap = new Map();
  const salesByBranch = new Map();

  // Kiểm tra nếu bigquery client được khởi tạo
  if (bigquery) {
    let branchFilter = '';
    const queryParams = { startDate, endDate };

    if (selectedBranch && selectedBranch !== 'all') {
      branchFilter = 'AND Branch_Code = @branch';
      queryParams.branch = selectedBranch;
    }

    // Query mới: GROUP BY cả SKU và Branch_Code để lấy doanh số theo chi nhánh
    const bqQuery = `
      SELECT 
          CAST(SKU AS STRING) as sku,
          CAST(Branch_Code AS STRING) as branch_code,
          CAST(SUM(CASE WHEN Order_type = 'don_xuat_ban' THEN Quantity WHEN Order_type = 'don_nhap_hoan_ban' THEN -Quantity ELSE 0 END) AS INT64) as qty_sold
      FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
      WHERE (SKU LIKE 'PCPV%' OR SKU LIKE 'pcpv%')
        AND CAST(Report_date AS DATE) >= CAST(@startDate AS DATE)
        AND CAST(Report_date AS DATE) <= CAST(@endDate AS DATE)
        ${branchFilter}
      GROUP BY SKU, Branch_Code
      ORDER BY qty_sold DESC
    `;

    try {
      const [rows] = await bigquery.query({ query: bqQuery, params: queryParams });
      (rows || []).forEach(r => {
        if (r.sku) {
          const skuKey = r.sku.trim().toUpperCase();
          const branch = (r.branch_code || 'UNKNOWN').trim();
          const qty = Number(r.qty_sold || 0);

          // Cộng dồn tổng
          salesMap.set(skuKey, (salesMap.get(skuKey) || 0) + qty);

          // Cộng dồn theo branch
          if (!salesByBranch.has(skuKey)) salesByBranch.set(skuKey, {});
          const branchData = salesByBranch.get(skuKey);
          branchData[branch] = (branchData[branch] || 0) + qty;
        }
      });

      const result = { salesMap, salesByBranch };
      pcpvSalesCache[cacheKey] = { data: result, timestamp: Date.now() };
      return result;
    } catch (e) {
      console.warn(`⚠️ getPcpvSalesData: BigQuery Query failed (${e.message}). Switching to Supabase Fallback...`);
    }
  } else {
    console.warn(`⚠️ getPcpvSalesData: BigQuery client is not initialized. Switching to Supabase Fallback...`);
  }

  // --- FALLBACK SUPABASE ---
  console.log(`[FALLBACK] getPcpvSalesData: Thử lấy dữ liệu Sales từ Supabase cho kỳ ${timeframe} của branch: ${selectedBranch}`);
  try {
    let query = supabase
      .from('raw_sales_orders_all')
      .select('SKU, Quantity, Order_type, Report_date, Branch_Code');

    query = query.gte('Report_date', startDate).lte('Report_date', endDate);

    if (selectedBranch && selectedBranch !== 'all') {
      query = query.eq('Branch_Code', selectedBranch);
    }

    const { data: spRows, error: spErr } = await query;
    if (spErr) throw spErr;

    (spRows || []).forEach(r => {
      const sku = (r.SKU || r.sku || '').trim().toUpperCase();
      if (sku && (sku.startsWith('PCPV') || actualSkus.includes(sku))) {
        const qty = Number(r.Quantity || r.quantity || 0);
        const type = r.Order_type || r.order_type;
        const branch = (r.Branch_Code || r.branch_code || 'UNKNOWN').trim();

        let delta = 0;
        if (type === 'don_xuat_ban') delta = qty;
        else if (type === 'don_nhap_hoan_ban') delta = -qty;
        else delta = qty;

        // Tổng
        salesMap.set(sku, (salesMap.get(sku) || 0) + delta);

        // Theo branch
        if (!salesByBranch.has(sku)) salesByBranch.set(sku, {});
        const branchData = salesByBranch.get(sku);
        branchData[branch] = (branchData[branch] || 0) + delta;
      }
    });
    console.log(`[FALLBACK SUCCESS] Lấy thành công dữ liệu Sales từ Supabase (by branch).`);
  } catch (err) {
    console.warn(`⚠️ SUPABASE FALLBACK ERROR (getPcpvSalesData): Không thể lấy dữ liệu Sales từ Supabase (${err.message}). Gán doanh số bằng 0.`);
    actualSkus.forEach(sku => {
      salesMap.set(sku.trim().toUpperCase(), 0);
      salesByBranch.set(sku.trim().toUpperCase(), {});
    });
  }

  const result = { salesMap, salesByBranch };
  pcpvSalesCache[cacheKey] = { data: result, timestamp: Date.now() };
  return result;
}

// Route TỔNG HỢP (Dashboard) - BẢN CUỐI (Thêm Filter Type)
app.get('/bom-dashboard', requireAuth, async (req, res) => {
  try {
    // === (MỚI) Thêm Search Query + Filter Type ===
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const pageSize = 20; // 20 PCPV mỗi trang
    const searchQuery = (req.query.q || '').trim().toLowerCase(); // Lấy query 'q'
    const filterType = (req.query.type || '').trim(); // Lấy query 'type' (vanphong, gaming)
    const timeframe = (req.query.timeframe || 'month').trim(); // 'today', 'week', 'month', 'quarter', 'year'
    const reqBranch = (req.query.branch || 'all').trim(); // Lấy chi nhánh cần lọc

    // --- A. Lấy thông tin User (Phân quyền) ---
    const userBranch = req.session.user?.branch_code;
    const isGlobalAdmin = (req.session.user?.role === 'admin' || userBranch === 'HCM.BD');
    const today = new Date().toISOString().split('T')[0];

    // --- B. Lấy danh sách PCPV từ Supabase (bảng skus) ---
    let subcatPattern = 'Máy tính bộ Phong Vũ%'; // Mặc định (Tất cả)
    if (filterType === 'vanphong') {
      subcatPattern = 'Máy tính bộ Phong Vũ văn phòng%';
    } else if (filterType === 'gaming') {
      subcatPattern = 'Máy tính bộ Phong Vũ gaming%';
    }

    let allFinalSkus = [];
    // Lấy từ bảng skus của Supabase, lọc theo subcat
    const { data: spSkus, error: spSkusErr } = await supabase
      .from('skus')
      .select('sku, product_name, subcat')
      .ilike('subcat', subcatPattern);

    if (spSkusErr) {
      console.error('BOM Dashboard: Lỗi lấy SKU từ Supabase:', spSkusErr.message);
    }

    if (spSkus && spSkus.length > 0) {
      // Lấy được từ bảng skus → dùng product_name
      const skuMap = new Map();
      spSkus.forEach(r => {
        if (!skuMap.has(r.sku)) skuMap.set(r.sku, r.product_name || null);
      });
      allFinalSkus = Array.from(skuMap.entries()).map(([sku, name]) => ({ sku, name: name || sku }));
    } else {
      // Fallback: lấy danh sách SKU từ bom_relations
      console.warn('BOM Dashboard: Không có SKU từ Supabase.skus, fallback sang bom_relations.');
      const { data: allFinalsData } = await supabase.from('bom_relations').select('final_sku');
      const uniqueSkus = [...new Set((allFinalsData || []).map(f => f.final_sku))];
      allFinalSkus = uniqueSkus.map(sku => ({ sku, name: sku })); // tạm thời dùng SKU làm name
    }

    // === Enrich tên sản phẩm từ bảng skus (áp dụng cho cả 2 path) ===
    if (allFinalSkus.some(f => f.name === f.sku)) {
      const missingNameSkus = allFinalSkus.filter(f => f.name === f.sku).map(f => f.sku);
      if (missingNameSkus.length > 0) {
        const { data: nameData } = await supabase
          .from('skus')
          .select('sku, product_name')
          .in('sku', missingNameSkus);
        const nameMap = new Map((nameData || []).map(r => [r.sku, r.product_name]));
        allFinalSkus = allFinalSkus.map(f => ({
          sku: f.sku,
          name: (f.name !== f.sku ? f.name : (nameMap.get(f.sku) || f.sku))
        }));
      }
    }

    // === Lọc theo Search Query ===
    let filteredFinalSkus = allFinalSkus;
    if (searchQuery) {
      filteredFinalSkus = allFinalSkus.filter(f =>
        f.sku.toLowerCase().includes(searchQuery) ||
        f.name.toLowerCase().includes(searchQuery)
      );
    }

    const totalItems = filteredFinalSkus.length;
    const totalPages = Math.ceil(totalItems / pageSize);
    let correctedPage = page;
    if (totalPages > 0 && correctedPage > totalPages) correctedPage = totalPages;

    const allFilteredSkuList = filteredFinalSkus.map(f => f.sku);

    if (allFilteredSkuList.length === 0) {
      return res.render('bom-dashboard', {
        title: 'Dashboard Lắp Ráp BOM', currentPage: 'bom-dashboard', time: res.locals.time,
        results: [], branches: [], page: 1, totalPages: 1, totalItems: 0,
        searchQuery: (req.query.q || ''),
        filterType: filterType,
        timeframe: timeframe,
        selectedBranch: reqBranch,
        isGlobalAdmin: isGlobalAdmin, userBranch: userBranch
      });
    }

    // --- C. Lấy Sales Data cho các PCPV SKU (kèm chi tiết theo branch) ---
    const { salesMap, salesByBranch } = await getPcpvSalesData(timeframe, userBranch, isGlobalAdmin, reqBranch, allFilteredSkuList);

    // --- D. Lấy BOM cho TẤT CẢ SKU đã lọc (từ Supabase) ---
    const { data: bomParts, error: e2 } = await supabase
      .from('bom_relations')
      .select('final_sku, component_sku, component_name, qty_per')
      .in('final_sku', allFilteredSkuList);
    if (e2) throw e2;

    // --- E. Lấy tồn kho ---
    const bomMap = new Map();
    filteredFinalSkus.forEach(f => bomMap.set(f.sku, []));
    (bomParts || []).forEach(p => { bomMap.get(p.final_sku)?.push(p); });
    const allComponentSkus = Array.from(new Set((bomParts || []).map(p => p.component_sku)));
    const skusToFetchStock = [...new Set([...allFilteredSkuList, ...allComponentSkus])];
    const inventoryMap = await getInventoryCounts(skusToFetchStock, userBranch, isGlobalAdmin, today);
    const allBranches = new Set();
    inventoryMap.forEach(branchMap => {
      branchMap.forEach((counts, branchId) => allBranches.add(branchId));
    });
    const sortedBranches = [...allBranches].sort();

    // --- F. Tính toán & Xây dựng dữ liệu render ---
    const allResults = [];
    for (const final of filteredFinalSkus) {
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

      // Lấy số lượng đã bán (tổng + theo chi nhánh)
      const skuKey = finalSku.trim().toUpperCase();
      const qtySold = salesMap.get(skuKey) || salesMap.get(finalSku) || 0;
      const qtySoldByBranch = salesByBranch.get(skuKey) || salesByBranch.get(finalSku) || {};

      // Tính số lượng linh kiện thiếu ở chi nhánh lọc (hoặc toàn quốc)
      let missingComponentsCount = 0;
      components.forEach(c => {
        const compSku = c.component_sku;
        const needQty = Number(c.qty_per || 1);
        const compStockMap = inventoryMap.get(compSku);

        let isMissing = false;
        if (isGlobalAdmin && reqBranch === 'all') {
          let hasShortage = false;
          sortedBranches.forEach(br => {
            const haveQty = compStockMap?.get(br)?.hang_ban_moi || 0;
            if (haveQty < needQty) hasShortage = true;
          });
          if (hasShortage) isMissing = true;
        } else {
          const targetBr = isGlobalAdmin ? reqBranch : userBranch;
          const haveQty = compStockMap?.get(targetBr)?.hang_ban_moi || 0;
          if (haveQty < needQty) isMissing = true;
        }

        if (isMissing) {
          missingComponentsCount++;
        }
      });

      allResults.push({
        sku: finalSku, name: final.name,
        finalStock_Total: totalFinalStock, finalStock_ByBranch: Object.fromEntries(finalStockByBranch),
        buildable_Total: totalBuildable, buildable_ByBranch: Object.fromEntries(buildableByBranch),
        qty_sold: qtySold,
        qty_sold_by_branch: qtySoldByBranch,
        missing_components_count: missingComponentsCount,
        components: Array.from(componentDetails.entries()).map(([sku, data]) => ({ sku, ...data, branches: Object.fromEntries(data.branches) }))
      });
    }

    // === Sắp xếp kết quả theo Doanh số bán chạy giảm dần, sau đó theo Tồn kho Thành phẩm ===
    allResults.sort((a, b) => {
      if (b.qty_sold !== a.qty_sold) {
        return b.qty_sold - a.qty_sold; // Doanh số cao xếp trước
      }
      return b.finalStock_Total - a.finalStock_Total; // Tồn kho nhiều xếp trước
    });

    // === Phân trang SAU KHI SẮP XẾP ===
    const paginatedResults = allResults.slice((correctedPage - 1) * pageSize, correctedPage * pageSize);

    // 4. Render
    res.render('bom-dashboard', {
      title: 'Dashboard Lắp Ráp BOM',
      currentPage: 'bom-dashboard',
      time: new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }),
      results: paginatedResults,
      branches: sortedBranches,
      page: correctedPage,
      totalPages: totalPages,
      totalItems: totalItems,
      searchQuery: (req.query.q || ''),
      filterType: filterType,
      timeframe: timeframe,
      selectedBranch: reqBranch,
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

/**
 * Lấy tồn HÀNG BÁN MỚI (Phiên bản An Toàn - Fix lỗi mất tồn)
 */
async function getSkuNewStockByBranch(skus) {
  // Chuẩn hóa SKU đầu vào
  const cleanSkus = (skus || []).map(s => String(s).trim().toUpperCase()).filter(Boolean);
  if (cleanSkus.length === 0) return {};

  let rows = [];

  // --- THỬ BIGQUERY ---
  if (bigquery) {
    const query = `
      SELECT UPPER(TRIM(CAST(sku AS STRING))) AS sku, branch_id, bin_zone, Serial
      FROM \`nimble-volt-459313-b8.Inventory.inv_seri_1\`
      WHERE UPPER(TRIM(CAST(sku AS STRING))) IN UNNEST(@skus)
        AND Serial IS NOT NULL AND Serial != ''
    `;
    try {
      const [bqRows] = await bigquery.query({ query, params: { skus: cleanSkus } });
      rows = bqRows;
    } catch (e) {
      if (e.message.includes('Quota exceeded')) {
        console.warn("⚠️ getSkuNewStockByBranch: BQ Quota Exceeded! Switching to Supabase Fallback...");
      } else {
        console.error("Lỗi BQ (getSkuNewStockByBranch):", e.message);
      }
    }
  }

  // --- FALLBACK SUPABASE ---
  if (rows.length === 0) {
    console.log("[FALLBACK] getSkuNewStockByBranch: Fetching from Supabase...");
    try {
      // Map c?t m?i: sku -> "SKU", branch_id -> "Branch ID", bin_zone -> "BIN zone", serial -> "Serial"
      const { data, error } = await supabase.from('inventory_serials')
        .select('"SKU", "Branch ID", "BIN zone", "Serial"')
        .in('SKU', cleanSkus);
      if (error) throw error;
      rows = (data || []).map(r => ({
        sku: r.SKU,
        branch_id: r["Branch ID"],
        bin_zone: r["BIN zone"],
        Serial: r.Serial
      }));
    } catch (err) {
      console.error("SUPABASE FALLBACK ERROR (getSkuNewStockByBranch):", err.message);
    }
  }

  if (rows.length === 0) return {};

  // Check serial đã xuất (FIFO)
  const allSerials = [...new Set(rows.map(r => r.Serial))];
  const today = new Date().toISOString().slice(0, 10);
  let checkedOutSerials = new Set();

  try {
    // Chia nhỏ batch để query không bị lỗi
    const BATCH_SIZE = 500;
    for (let i = 0; i < allSerials.length; i += BATCH_SIZE) {
      const batch = allSerials.slice(i, i + BATCH_SIZE);
      const { data } = await supabase.from('serial_check_log')
        .select('serial').in('serial', batch).eq('check_date', today).eq('checked_out', true);
      (data || []).forEach(log => checkedOutSerials.add(log.serial));
    }
  } catch (e) { }

  // Tổng hợp kết quả
  const result = {};
  // Danh sách các khu vực được phép bán (So sánh linh hoạt)
  const allowedZones = ['trưng bày hàng bán mới', 'lưu kho hàng bán mới', 'hàng mkt'];

  for (const row of rows) {
    if (checkedOutSerials.has(row.Serial)) continue;

    // Chuẩn hóa zone về chữ thường để so sánh
    const currentZone = String(row.bin_zone || '').trim().toLowerCase();

    if (allowedZones.includes(currentZone)) {
      const sku = row.sku;
      const br = String(row.branch_id || '').trim().toUpperCase(); // Chuẩn hóa mã chi nhánh

      if (!result[sku]) result[sku] = {};
      result[sku][br] = (result[sku][br] || 0) + 1;
    }
  }
  return result;
}
// ===== KẾT THÚC SỬA LẠI TOÀN BỘ HÀM =====


// ========================= FIFO CHECKING ROUTES =========================
// server.js (THAY THẾ HÀM NÀY - bắt đầu từ dòng 256)
async function fetchInventoryFromBigQuery(branchCode, masterQuery, giftFilter, isAdminBranch, filters, page = 1, pageSize = 50) {
  // --- THỬ BIGQUERY TRƯỚC ---
  if (false) {
    const BIGQUERY_TABLE = '`nimble-volt-459313-b8.Inventory.inv_seri_1`';
    const params = {
      branchCode: branchCode,
      masterQuery: masterQuery,
      likeQuery: `%${masterQuery}%`,
      pageSize: pageSize,
      offset: (page - 1) * pageSize
    };

    let filterConditions = '';
    if (!isAdminBranch) filterConditions += ' AND Branch_ID = @branchCode';
    if (giftFilter === 'no') filterConditions += " AND (SubCategory_name NOT LIKE 'Quà tặng%' OR SubCategory_name IS NULL)";

    if (filters) {
      if (filters.subcategory) { filterConditions += ` AND SubCategory_name = @subcategory`; params.subcategory = filters.subcategory; }
      if (filters.brand) { filterConditions += ` AND Brand = @brand`; params.brand = filters.brand; }
      if (filters.location) { filterConditions += ` AND Location = @location`; params.location = filters.location; }
      if (filters.bin_zone) { filterConditions += ` AND BIN_zone = @bin_zone`; params.bin_zone = filters.bin_zone; }
    }

    const searchQueryCondition = `
           AND ( @masterQuery = '' OR CAST(SKU AS STRING) LIKE @likeQuery OR SKU_name LIKE @likeQuery
                 OR Serial LIKE @likeQuery OR Location LIKE @likeQuery OR Brand LIKE @likeQuery )
       `;

    const query = `
          SELECT
              CAST(SKU AS STRING) AS sku, SKU_name AS sku_name, Brand AS brand, Serial AS serial,
              Location AS location, BIN_zone AS bin_zone, Branch_ID AS branch_id,
              SubCategory_name AS subcategory_name,
              FORMAT_DATE('%Y-%m-%d', Date_import_company) AS date_in,
              Aging_company AS days_old
          FROM ${BIGQUERY_TABLE}
          WHERE 1=1 ${filterConditions} ${searchQueryCondition}
          ORDER BY Date_import_company ASC
          LIMIT @pageSize OFFSET @offset
      `;

    const countQuery = `SELECT COUNT(*) as total FROM ${BIGQUERY_TABLE} WHERE 1=1 ${filterConditions} ${searchQueryCondition}`;

    try {
      const [[rows], [countResult]] = await Promise.all([
        bigquery.query({ query, location: 'asia-southeast1', params }),
        bigquery.query({ query: countQuery, location: 'asia-southeast1', params })
      ]);

      const total = countResult[0]?.total || 0;
      const mappedRows = rows.map(r => ({ ...r, branch_id: String(r.branch_id), date_in: r.date_in || null, days_old: r.days_old || 0 }));
      const isLikelySerialSearch = masterQuery.length >= 8 && !/^\d+$/.test(masterQuery);
      let searchedItem = (isLikelySerialSearch && masterQuery) ? mappedRows.find(item => item.serial === masterQuery) : null;

      return { data: mappedRows, total: total, searchedItem: searchedItem };

    } catch (e) {
      if (e.message.includes('Quota exceeded')) {
        console.warn("⚠️ BIGQUERY QUOTA EXCEEDED! Switching to Supabase Fallback...");
      } else {
        console.error("BIGQUERY QUERY ERROR:", e.message);
        throw e;
      }
    }
  }

  // --- FALLBACK S? D?NG SUPABASE (inventory_serials) ---
  console.log(`[FALLBACK] Fetching inventory from Supabase (Page ${page})...`);
  try {
    // Map c?t m?i
    let query = supabase.from('inventory_serials').select('*', { count: 'exact' });

    if (!isAdminBranch) query = query.eq('"Branch ID"', branchCode);
    if (giftFilter === 'no') query = query.not('"SubCategory name"', 'like', 'Quà tặng%');

    if (filters) {
      if (filters.subcategory) query = query.eq('"SubCategory name"', filters.subcategory);
      if (filters.brand) query = query.eq('"Brand"', filters.brand);
      if (filters.location) query = query.eq('"Location"', filters.location);
      if (filters.bin_zone) query = query.eq('"BIN zone"', filters.bin_zone);
    }

    if (masterQuery) {
      query = query.or(`"SKU".ilike.%${masterQuery}%,"SKU name".ilike.%${masterQuery}%,"Serial".ilike.%${masterQuery}%,"Location".ilike.%${masterQuery}%,"Brand".ilike.%${masterQuery}%`);
    }

    const { data, count, error } = await query
      .order('"Date import company "', { ascending: true }) // Dùng ngo?c kép k? c? d?u cách th?a
      .range((page - 1) * pageSize, page * pageSize - 1);

    if (error) throw error;

    const mappedRows = (data || []).map(r => ({
      ...r,
      sku: r.SKU,
      sku_name: r["SKU name"],
      serial: r.Serial,
      brand: r.Brand,
      location: r.Location,
      bin_zone: r["BIN zone"],
      branch_id: r["Branch ID"],
      subcategory_name: r["SubCategory name"],
      date_in: r["Date import company "],
      days_old: parseInt(r["Aging company"] || 0)
    }));

    const isLikelySerialSearch = masterQuery.length >= 8 && !/^\d+$/.test(masterQuery);
    let searchedItem = (isLikelySerialSearch && masterQuery) ? mappedRows.find(item => item.serial === masterQuery) : null;

    return { data: mappedRows, total: count || 0, searchedItem: searchedItem };

  } catch (err) {
    console.error("SUPABASE FALLBACK ERROR:", err.message);
    // Nếu cả 2 đều lỗi thì mới trả về rỗng
    return { data: [], total: 0, searchedItem: null };
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

  // 2. Query BigQuery d? l?y T?T C? serial/bin_zone/branch cho các SKU
  let bqRows = [];

  if (bigquery) {
    let bqBranchFilter = isGlobalAdmin ? '' : 'AND Branch_ID = @userBranch';

    const bqQuery = `SELECT CAST(SKU AS STRING) AS sku, Serial AS serial, BIN_zone AS bin_zone, Branch_ID AS branch_id
                    FROM ${BIGQUERY_TABLE} WHERE CAST(SKU AS STRING) IN UNNEST(@skuList) ${bqBranchFilter} 
                    AND Serial IS NOT NULL AND Serial != ''`;

    try {
      const [rows] = await bigquery.query({ query: bqQuery, location: 'asia-southeast1', params });
      bqRows = rows;
    } catch (e) {
      if (e.message.includes('Quota exceeded')) {
        console.warn("⚠️ getInventoryCounts: BQ Quota Exceeded! Switching to Supabase Fallback...");
      } else {
        console.error("Lỗi query BQ (getInventoryCounts):", e.message);
      }
    }
  }

  // --- FALLBACK SUPABASE ---
  if (bqRows.length === 0) {
    console.log("[FALLBACK] getInventoryCounts: Fetching from Supabase...");
    try {
      let query = supabase.from('inventory_serials').select('"SKU", "Serial", "BIN zone", "Branch ID"').in('"SKU"', skuList);
      if (!isGlobalAdmin) query = query.eq('"Branch ID"', userBranch);

      const { data, error } = await query;
      if (error) throw error;
      bqRows = (data || []).map(r => ({
        sku: r.SKU,
        serial: r.Serial,
        bin_zone: r["BIN zone"],
        branch_id: r["Branch ID"],
        Serial: r.Serial,
        BIN_zone: r["BIN zone"],
        Branch_ID: r["Branch ID"]
      }));
    } catch (err) {
      console.error("SUPABASE FALLBACK ERROR (getInventoryCounts):", err.message);
    }
  }

  if (bqRows.length === 0) {
    return new Map(); // Không có t?n BQ ho?c fallback
  }

  // 3. L?y danh sách serial dã xu?t T? SUPABASE
  const allSerials = bqRows.map(r => r.serial || r.Serial);
  let checkedOutSerials = new Set();

  if (allSerials.length > 0) {
    try {
      // Chia nh? m?ng allSerials thành các batch
      const batchSize = 500;
      for (let i = 0; i < allSerials.length; i += batchSize) {
        const batchSerials = allSerials.slice(i, i + batchSize);

        const { data: logData, error } = await supabase
          .from('serial_check_log')
          .select('serial')
          .in('serial', batchSerials)
          .eq('check_date', checkDate)
          .eq('checked_out', true);

        if (error) throw error;
        (logData || []).forEach(log => {
          checkedOutSerials.add(log.serial);
        });
      }
    } catch (e) {
      console.error("L?i query Supabase (getInventoryCounts):", e.message);
    }
  }

  // 4. L?c b? serial dã xu?t và d?m theo SKU -> Branch -> Bin_zone
  const inventoryMap = new Map();

  skuList.forEach(sku => {
    inventoryMap.set(sku, new Map());
  });

  const allBranchesInResult = [...new Set(bqRows.map(r => r.branch_id))];

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

  bqRows.forEach(row => {
    if (checkedOutSerials.has(row.serial)) return;

    const sku = row.sku;
    const branchId = row.branch_id;
    const binZone = (row.bin_zone || '').trim();

    const branchMap = inventoryMap.get(sku);
    if (!branchMap) return;

    const counts = branchMap.get(branchId);
    if (!counts) return;

    if (binZone === 'Trưng bày hàng bán mới' || binZone === 'Lưu kho hàng bán mới') {
      counts.hang_ban_moi += 1;
    } else if (binZone === 'Trưng bày chỉ định') {
      counts.trung_bay_chi_dinh += 1;
    } else if (binZone === 'Lưu kho thanh lý') {
      counts.luu_kho_tl += 1;
    } else if (binZone === 'Trưng bày thanh lý') {
      counts.trung_bay_tl += 1;
    } else if (binZone === 'Hàng MKT') {
      counts.hang_mkt += 1;
    } else {
      counts.ton_khac += 1;
    }
  });

  inventoryMap.forEach((branchMap, sku) => {
    branchMap.forEach((counts, branchId) => {
      const total = counts.hang_ban_moi + counts.trung_bay_chi_dinh + counts.luu_kho_tl + counts.trung_bay_tl + counts.hang_mkt + counts.ton_khac;
      if (total === 0) branchMap.delete(branchId);
    });
    if (branchMap.size === 0) inventoryMap.delete(sku);
  });

  return inventoryMap;
}

// === HÀM HELPER M?I: L?Y TOP 5 SERIAL C? NH?T (DÃ C?P NH?T) ===
async function getOldestSerials(sku, userBranch, isGlobalAdmin, checkDate, limit = 5) {
  if (!bigquery || !sku || !userBranch || !checkDate) {
    return [];
  }

  const BIGQUERY_TABLE = '`nimble-volt-459313-b8.Inventory.inv_seri_1`';
  let bqRows = [];

  if (bigquery) {
    const params = { sku: String(sku), userBranch: userBranch };
    const branchFilter = isGlobalAdmin ? '' : 'AND Branch_ID = @userBranch';

    const bqQuery = `SELECT Serial AS serial, Location AS location, Aging_company AS days_old, Date_import_company
                    FROM ${BIGQUERY_TABLE} WHERE CAST(SKU AS STRING) = @sku ${branchFilter}
                    AND BIN_zone IN ('Trưng bày hàng bán mới', 'Lưu kho hàng bán mới')
                    AND Serial IS NOT NULL AND Serial != '' ORDER BY Date_import_company ASC LIMIT 50`;

    try {
      const [rows] = await bigquery.query({ query: bqQuery, location: 'asia-southeast1', params });
      bqRows = rows;
    } catch (e) {
      if (e.message.includes('Quota exceeded')) {
        console.warn("⚠️ getOldestSerials: BQ Quota Exceeded! Switching to Supabase Fallback...");
      } else {
        console.error("Lỗi query BQ (getOldestSerials):", e.message);
      }
    }
  }

  // --- FALLBACK SUPABASE ---
  if (bqRows.length === 0) {
    console.log("[FALLBACK] getOldestSerials: Fetching from Supabase...");
    try {
      let query = supabase.from('inventory_serials')
        .select('"Serial", "Location", "Aging company", "Date import company "')
        .eq('"SKU"', sku)
        .in('"BIN zone"', ['Trưng bày hàng bán mới', 'Lưu kho hàng bán mới']);

      if (!isGlobalAdmin) query = query.eq('"Branch ID"', userBranch);

      const { data, error } = await query.order('"Date import company "', { ascending: true }).limit(50);
      if (error) throw error;
      bqRows = (data || []).map(r => ({
        serial: r.Serial,
        location: r.Location,
        days_old: r["Aging company"],
        date_in: r["Date import company "]
      }));
    } catch (err) {
      console.error("SUPABASE FALLBACK ERROR (getOldestSerials):", err.message);
    }
  }

  if (bqRows.length === 0) return [];

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
  // --- THỬ BIGQUERY TRƯỚC ---
  if (false) {
    const BIGQUERY_TABLE = '`nimble-volt-459313-b8.Inventory.inv_seri_1`';
    const params = { branchCode: branchCode };
    let filterConditions = '';
    if (!isAdminBranch) filterConditions += ' AND Branch_ID = @branchCode';
    if (giftFilter === 'no') filterConditions += " AND (SubCategory_name NOT LIKE 'Quà tặng%' OR SubCategory_name IS NULL)";

    const qOpts = (f) => ({
      query: `SELECT DISTINCT ${f} FROM ${BIGQUERY_TABLE} WHERE ${f} IS NOT NULL AND ${f} != '' ${filterConditions} ORDER BY ${f} ASC LIMIT 1000`,
      location: 'asia-southeast1', params
    });

    try {
      const [[sc], [br], [loc], [bz]] = await Promise.all([
        bigquery.query(qOpts('SubCategory_name')),
        bigquery.query(qOpts('Brand')),
        bigquery.query(qOpts('Location')),
        bigquery.query(qOpts('BIN_zone')),
      ]);
      return { subcategories: sc.map(r => r.SubCategory_name), brands: br.map(r => r.Brand), locations: loc.map(r => r.Location), bin_zones: bz.map(r => r.BIN_zone) };
    } catch (e) {
      if (e.message.includes('Quota exceeded')) {
        console.warn("⚠️ BIGQUERY FILTER QUOTA EXCEEDED! Switching to Supabase Fallback...");
      } else {
        console.error("BIGQUERY FILTER QUERY ERROR:", e.message);
        throw e;
      }
    }
  }

  // --- FALLBACK S? D?NG SUPABASE ---
  console.log("[FALLBACK] Fetching filters from Supabase...");
  try {
    const fieldsMap = {
      'subcategory_name': 'SubCategory name',
      'brand': 'Brand',
      'location': 'Location',
      'bin_zone': 'BIN zone'
    };
    const results = {};

    for (const [key, field] of Object.entries(fieldsMap)) {
      // Nh? d?t tên c?t trong d?u ngo?c kép d? Supabase hi?u
      const quotedField = `"${field}"`;
      let query = supabase.from('inventory_serials').select(quotedField).not(quotedField, 'is', null).neq(quotedField, '');
      if (!isAdminBranch) query = query.eq('"Branch ID"', branchCode);
      if (giftFilter === 'no') query = query.not('"SubCategory name"', 'like', 'Quà tặng%');

      const { data, error } = await query;
      if (error) throw error;

      results[key] = [...new Set(data.map(item => item[field]))].sort();
    }

    return {
      subcategories: results.subcategory_name,
      brands: results.brand,
      locations: results.location,
      bin_zones: results.bin_zone
    };
  } catch (err) {
    console.error("SUPABASE FILTER FALLBACK ERROR:", err.message);
    return { subcategories: [], brands: [], locations: [], bin_zones: [] };
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
    } catch (e) { console.error("Lỗi nghiêm trọng khi lấy trạng thái Supabase:", e.message); }

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
    // --- BƯỚC 5: [Req 2] TÍNH RANK & FIFO (ĐÃ FIX: ÉP KIỂU NGÀY TUYỆT ĐỐI) ---
    if (searchedItem && !checkedSerials.get(searchedItem.serial) && bigquery) {
      const skuToRank = searchedItem.sku;

      // 1. QUERY: Đã kiểm tra -> Đang lấy đúng 2 kho bán mới
      const rankQuery = `
                SELECT Serial, Date_import_company
                FROM \`nimble-volt-459313-b8.Inventory.inv_seri_1\`
                WHERE SKU = CAST(@skuToRank AS INT64) 
                  ${!isGlobalAdmin ? 'AND Branch_ID = @branchCode' : ''}
                  
                  -- [XÁC NHẬN] Code đang lọc đúng 2 kho này
                  AND BIN_zone IN ('Trưng bày hàng bán mới', 'Lưu kho hàng bán mới') 
                  
                ORDER BY Date_import_company ASC
            `;

      const rankOptions = {
        query: rankQuery, location: 'asia-southeast1',
        params: { skuToRank: String(skuToRank), branchCode: userBranch }
      };

      try {
        let allSkuSerials = [];
        try {
          const [bqSerials] = await bigquery.query(rankOptions);
          allSkuSerials = bqSerials;
        } catch (e) {
          if (e.message.includes('Quota exceeded')) {
            console.warn("⚠️ RANK BQ QUOTA EXCEEDED! Switching to Supabase Fallback...");
            let query = supabase.from('inventory_serials')
              .select('"Serial", "Date import company "')
              .eq('"SKU"', skuToRank).in('"BIN zone"', ['Trưng bày hàng bán mới', 'Lưu kho hàng bán mới']);

            if (!isGlobalAdmin) query = query.eq('"Branch ID"', userBranch);
            const { data, error } = await query;
            if (error) throw error;
            allSkuSerials = (data || []).map(r => ({ Serial: r.Serial, Date_import_company: r["Date import company "] }));
          } else {
            throw e;
          }
        }

        // Lấy log đã xuất
        const skuSerialList = allSkuSerials.map(s => s.Serial);
        const { data: skuLogData } = await supabase
          .from('serial_check_log')
          .select('serial, checked_out')
          .in('serial', skuSerialList)
          .eq(!isGlobalAdmin ? 'branch_code' : '1', !isGlobalAdmin ? userBranch : '1')
          .eq('check_date', todayDate);

        const skuCheckedMap = new Map([...checkedSerials, ...((skuLogData || []).map(log => [log.serial, log.checked_out]))]);

        // Lọc serial còn tồn (Active)
        const activeSkuSerials = allSkuSerials.filter(s => !skuCheckedMap.get(s.Serial));

        if (activeSkuSerials.length > 0) {

          // --- [FIX] HÀM CHUẨN HÓA NGÀY "CỨNG" ---
          // Mục đích: Biến mọi định dạng (Object, Date, String) thành chuỗi "YYYY-MM-DD" duy nhất
          const normalizeDate = (input) => {
            if (!input) return null;

            let strVal = '';
            // TH1: BigQuery trả về Object { value: '2023-08-29' }
            if (typeof input === 'object' && input.value) {
              strVal = String(input.value);
            }
            // TH2: BigQuery trả về Date Object Javascript
            else if (input instanceof Date) {
              // Tự format thủ công để tránh lệch múi giờ
              const y = input.getFullYear();
              const m = String(input.getMonth() + 1).padStart(2, '0');
              const d = String(input.getDate()).padStart(2, '0');
              strVal = `${y}-${m}-${d}`;
            }
            // TH3: Là String thuần
            else {
              strVal = String(input);
            }

            // Dùng Regex bắt chính xác chuỗi ngày tháng năm đầu tiên
            const match = strVal.match(/(\d{4}-\d{2}-\d{2})/);
            return match ? match[1] : null; // Trả về "2023-08-29"
          };

          // 2. TẠO DANH SÁCH LÔ (Unique Dates)
          // Set sẽ tự loại bỏ trùng lặp nếu chuỗi giống hệt nhau
          const uniqueDates = [...new Set(activeSkuSerials.map(s => normalizeDate(s.Date_import_company)))]
            .filter(Boolean)
            .sort(); // Sắp xếp tăng dần theo ngày

          // 3. TÍNH RANK
          const targetDateStr = normalizeDate(searchedItem.date_in);
          const rank = uniqueDates.indexOf(targetDateStr) + 1;

          // 4. TÍNH FIFO
          const oldestDateStr = uniqueDates[0];

          // Format hiển thị UI (DD/MM/YYYY)
          let oldestDateDisplay = oldestDateStr;
          if (oldestDateStr && oldestDateStr.includes('-')) {
            const [y, m, d] = oldestDateStr.split('-');
            oldestDateDisplay = `${d}/${m}/${y}`;
          }

          // Tính chênh lệch ngày
          const d1 = new Date(targetDateStr);
          const d2 = new Date(oldestDateStr);
          const diffTime = Math.abs(d1 - d2);
          const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

          let fifoStatus = 'UNK';
          let fifoClass = '';

          if (diffDays <= 30) {
            fifoStatus = 'Đạt FIFO';
            fifoClass = 'text-success';
          } else {
            fifoStatus = 'Không đạt FIFO';
            fifoClass = 'text-danger';
          }

          rankInfo = {
            serial: masterQuery,
            rank: rank > 0 ? rank : '?',
            total: uniqueDates.length, // Sẽ trả về đúng số lượng lô (Ví dụ: 3)
            totalSerials: activeSkuSerials.length,
            sku: skuToRank,
            diffDays, fifoStatus, fifoClass,
            oldestDate: oldestDateDisplay
          };
        }
      } catch (rankError) { console.error("Lỗi tính Rank:", rankError.message); }
    }


    else if (searchedItem) {
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

    res.json({
      ok: true, history: history.map(r => ({
        ...r,
        checked_by_name: r.users?.full_name || r.users?.email || 'Unknown',
      }))
    });

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
    const allPeriods = [...new Set((periodsData || []).map(p => p.display_period).filter(Boolean))];

    // Mặc định chọn chu kỳ tháng liền kề trước (vd: hiện tại 03/2026 => Tháng 02/2026)
    const nowForRanking = new Date();
    const prevMonthDate = new Date(nowForRanking.getFullYear(), nowForRanking.getMonth() - 1, 1);
    const targetMonth = String(prevMonthDate.getMonth() + 1).padStart(2, '0');
    const targetYear = String(prevMonthDate.getFullYear());
    const targetPeriodLabel = `Tháng ${targetMonth}/${targetYear}`;

    const normalizePeriod = (s) => String(s || '')
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toUpperCase()
      .replace(/[.\-]/g, '/')
      .replace(/\s+/g, ' ')
      .trim();

    const normalizedTarget = normalizePeriod(targetPeriodLabel);
    const altTarget = normalizePeriod(`Tháng ${Number(targetMonth)}/${targetYear}`);

    const defaultPeriod = allPeriods.find((p) => {
      const n = normalizePeriod(p);
      return n === normalizedTarget || n === altTarget || n.includes(`${Number(targetMonth)}/${targetYear}`) || n.includes(`${targetMonth}/${targetYear}`);
    }) || targetPeriodLabel;

    const currentPeriod = selectedPeriod || defaultPeriod;

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

      // --- [NEW] TẠO THÔNG BÁO CHO TOÀN HỆ THỐNG ('All') ---
      try {
        await supabase.from('notifications').insert({
          title: `📰 Bảng tin mới: ${title}`,
          content: subtitle || 'Xem chi tiết tại mục Bảng tin.',
          type: 'info',
          user_ref: 'All',
          is_read: false,
          created_at: new Date(),
          link: `/newsfeed/post/${newPostId}` // <--- THÊM DÒNG NÀY (Link đến bài viết)
        });
      } catch (notifErr) {
        console.error('Lỗi tạo thông báo bảng tin:', notifErr.message);
      }

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

// ==========================================
// BÁO GIÁ NHANH - LỊCH SỬ
// ==========================================

app.post('/api/quote-history', requireAuth, async (req, res) => {
  try {
    const { customerName, customerPhone, contactInfo, buildConfig, totalAmount, templateType, notes, globalDiscount, validityDays, itemOrder } = req.body;
    const userId = req.session.user?.id || req.session.user?.uid || req.session.user?.email || 'unknown';
    const userName = req.session.user?.full_name || req.session.user?.email || 'Nhân viên';

    const buildConfigWithNotes = {
      ...(buildConfig && typeof buildConfig === 'object' ? buildConfig : {}),
      _notes: notes || '',
      _global_discount: globalDiscount || { value: 0, type: 'amount' },
      _validity_days: validityDays || 3,
      _item_order: itemOrder || []
    };

    const { data, error } = await supabase
      .from('quote_history')
      .insert([{
        user_id: userId,
        user_name: userName,
        customer_name: customerName,
        customer_phone: customerPhone,
        contact_info: contactInfo,
        build_config: buildConfigWithNotes,
        total_amount: totalAmount || 0,
        template_type: templateType
      }])
      .select();

    if (error) throw error;
    res.json({ ok: true, data: data[0] });
  } catch (error) {
    console.error('Lỗi lưu lịch sử báo giá:', error);
    res.status(500).json({ ok: false, error: 'Không thể lưu lịch sử báo giá: ' + error.message });
  }
});

app.get('/api/quote-history/my-quotes', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user?.id || req.session.user?.uid || req.session.user?.email || 'unknown';

    // Lấy 50 báo giá gần nhất của User này
    const { data, error } = await supabase
      .from('quote_history')
      .select('id, customer_name, customer_phone, total_amount, created_at, build_config, template_type, contact_info')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;
    res.json({ ok: true, quotes: data || [] });
  } catch (error) {
    console.error('Lỗi tải lịch sử báo giá:', error);
    res.status(500).json({ ok: false, error: 'Lỗi tải lịch sử báo giá: ' + error.message });
  }
});


app.post('/api/pc-builder/generate-quote', requireAuth, async (req, res) => {
  let browser = null;
  try {
    const {
      buildConfig, customerName, contactInfo, customerPhone, deliveryDays,
      // 1. Phân biệt Build PC và Báo giá nhanh
      isGeneralQuote = false,
      templateType = 'consumer',
      globalDiscount = { value: 0, type: 'amount' },
      validityDays,
      notes = '',
      itemOrder,
      show_warranty = true,
      show_specs = true,
      show_images = true
    } = req.body;
    const showWarranty = show_warranty === true || show_warranty === 'true' || show_warranty === undefined;
    const showSpecs = show_specs === true || show_specs === 'true' || show_specs === undefined;
    const showImages = show_images === true || show_images === 'true' || show_images === undefined;
    const validityDaysSafe = (validityDays !== undefined && validityDays !== null && validityDays !== '') ? Number(validityDays) : null;
    const deliveryDaysSafe = (deliveryDays !== undefined && deliveryDays !== null && deliveryDays !== '') ? Number(deliveryDays) : 1;

    console.log(`[Báo giá] KH: ${customerName} | Mode: ${isGeneralQuote ? 'Báo giá nhanh' : 'Build PC'}`);

    // 2. Tính tiền hàng (Trừ giảm giá từng món item_discount)
    const buildConfigSafe = buildConfig && typeof buildConfig === 'object' ? buildConfig : {};
    const items = Object.entries(buildConfigSafe)
      .filter(([key, val]) => !key.startsWith('_') && val && typeof val === 'object')
      .map(([key, rawItem]) => {
        const item = { ...rawItem };
        item.quantity = Math.max(1, Number(item.quantity) || 1);
        item.item_discount = Math.max(0, Number(item.item_discount) || 0);
        item.list_price = Number(item.list_price) || 0;
        if (item.edited_price !== undefined && item.edited_price !== null && item.edited_price !== '') {
          item.edited_price = Number(item.edited_price) || 0;
        }

        item.quote_detailed_specs = String(item.quote_detailed_specs || '')
          .replace(/\r\n/g, '\n')
          .slice(0, 12000);

        item.quote_image_urls = (Array.isArray(item.quote_image_urls) ? item.quote_image_urls : [item.quote_image_urls])
          .flatMap((value) => String(value || '').split(/[\n,;]+/))
          .map((value) => value.trim())
          .filter((value) => /^https?:\/\//i.test(value))
          .slice(0, 6);

        return item;
      });

    if (Array.isArray(itemOrder)) {
      items.sort((a, b) => {
        const idxA = itemOrder.indexOf(a.sku);
        const idxB = itemOrder.indexOf(b.sku);
        if (idxA === -1 && idxB === -1) return 0;
        if (idxA === -1) return 1;
        if (idxB === -1) return -1;
        return idxA - idxB;
      });
    }

    if (items.length === 0) {
      return res.status(400).json({ ok: false, error: 'Không có sản phẩm để tạo báo giá.' });
    }

    const missingDetailsSkus = items.filter(it => !it.warranty || it.vat_rate === undefined).map(it => it.sku);
    if (missingDetailsSkus.length > 0) {
      try {
        const { data: dbDetails } = await supabase
          .from('skus')
          .select('sku, warranty, vat_rate')
          .in('sku', missingDetailsSkus);
        if (dbDetails && dbDetails.length > 0) {
          const dMap = {};
          dbDetails.forEach(d => { dMap[d.sku] = d; });
          items.forEach(it => {
            if (dMap[it.sku]) {
              if (!it.warranty && dMap[it.sku].warranty) it.warranty = dMap[it.sku].warranty;
              if (it.vat_rate === undefined && dMap[it.sku].vat_rate !== undefined) it.vat_rate = dMap[it.sku].vat_rate;
            }
          });
        }
      } catch (err) {
        console.warn('[Báo giá] Lỗi query warranty/vat_rate:', err.message);
      }
    }

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
        { min: 30000000, discount: 600000, code: 'PVBUILDPC25113' },
        { min: 20000000, discount: 400000, code: 'PVBUILDPC25112' },
        { min: 10000000, discount: 200000, code: 'PVBUILDPC25111' }
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
    const taxFreeSubcats = ['NH09-02-01-01', 'NH09-02-01-02', 'NH09-01-01'];

    // 6. Render & PDF
    const userFullName = req.session.user?.full_name || 'Nhân viên Phong Vũ';
    const userBranchCode = req.session.user?.branch_code || 'DEFAULT';
    const branchInfo = BRANCH_CONFIG[userBranchCode] || BRANCH_CONFIG['DEFAULT'];
    const todayStr = new Date().toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric' });
    const quoteNum = `PV-${Date.now().toString().slice(-6)}`;

    const htmlString = await ejs.renderFile(
      path.join(__dirname, 'views/quote-template.ejs'),
      {
        headerBannerBase64: 'data:image/png;base64,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',
        logoBase64: app.locals.logoBase64 || 'data:image/png;base64,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',
        numberToWords: app.locals.numberToWords || ((n) => ''),
        deliveryDays: deliveryDaysSafe,
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
        validityDays: validityDaysSafe,
        deliveryDays: deliveryDaysSafe,
        notes,
        taxFreeSubcats: taxFreeSubcats,
        show_warranty: showWarranty,
        show_specs: showSpecs,
        show_images: showImages,

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
    await page.setViewport({ width: 1200, height: 800 });
    await page.setContent(htmlString, { waitUntil: 'networkidle0' });
    const pdfBufferRaw = await page.pdf({ format: 'A4', printBackground: true, margin: { top: '10mm', right: '10mm', bottom: '10mm', left: '10mm' } });
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


app.post('/api/pc-builder/preview-quote', requireAuth, async (req, res) => {
  try {
    const {
      buildConfig, customerName, contactInfo, customerPhone, deliveryDays,
      isGeneralQuote = false,
      templateType = 'consumer',
      globalDiscount = { value: 0, type: 'amount' },
      validityDays,
      notes = '',
      itemOrder,
      show_warranty = true,
      show_specs = true,
      show_images = true
    } = req.body;
    const showWarranty = show_warranty === true || show_warranty === 'true' || show_warranty === undefined;
    const showSpecs = show_specs === true || show_specs === 'true' || show_specs === undefined;
    const showImages = show_images === true || show_images === 'true' || show_images === undefined;
    const validityDaysSafe = (validityDays !== undefined && validityDays !== null && validityDays !== '') ? Number(validityDays) : null;
    const deliveryDaysSafe = (deliveryDays !== undefined && deliveryDays !== null && deliveryDays !== '') ? Number(deliveryDays) : 1;

    const buildConfigSafe = buildConfig && typeof buildConfig === 'object' ? buildConfig : {};
    const items = Object.entries(buildConfigSafe)
      .filter(([key, val]) => !key.startsWith('_') && val && typeof val === 'object')
      .map(([key, rawItem]) => {
        const item = { ...rawItem };
        item.quantity = Math.max(1, Number(item.quantity) || 1);
        item.item_discount = Math.max(0, Number(item.item_discount) || 0);
        item.list_price = Number(item.list_price) || 0;
        if (item.edited_price !== undefined && item.edited_price !== null && item.edited_price !== '') {
          item.edited_price = Number(item.edited_price) || 0;
        }

        item.quote_detailed_specs = String(item.quote_detailed_specs || '')
          .replace(/\r\n/g, '\n')
          .slice(0, 12000);

        item.quote_image_urls = (Array.isArray(item.quote_image_urls) ? item.quote_image_urls : [item.quote_image_urls])
          .flatMap((value) => String(value || '').split(/[\n,;]+/))
          .map((value) => value.trim())
          .filter((value) => /^https?:\/\//i.test(value))
          .slice(0, 6);

        return item;
      });

    if (Array.isArray(itemOrder)) {
      items.sort((a, b) => {
        const idxA = itemOrder.indexOf(a.sku);
        const idxB = itemOrder.indexOf(b.sku);
        if (idxA === -1 && idxB === -1) return 0;
        if (idxA === -1) return 1;
        if (idxB === -1) return -1;
        return idxA - idxB;
      });
    }

    if (items.length === 0) {
      return res.status(400).json({ ok: false, error: 'Không có sản phẩm để xem trước.' });
    }

    const missingDetailsSkus = items.filter(it => !it.warranty || it.vat_rate === undefined).map(it => it.sku);
    if (missingDetailsSkus.length > 0) {
      try {
        const { data: dbDetails } = await supabase
          .from('skus')
          .select('sku, warranty, vat_rate')
          .in('sku', missingDetailsSkus);
        if (dbDetails && dbDetails.length > 0) {
          const dMap = {};
          dbDetails.forEach(d => { dMap[d.sku] = d; });
          items.forEach(it => {
            if (dMap[it.sku]) {
              if (!it.warranty && dMap[it.sku].warranty) it.warranty = dMap[it.sku].warranty;
              if (it.vat_rate === undefined && dMap[it.sku].vat_rate !== undefined) it.vat_rate = dMap[it.sku].vat_rate;
            }
          });
        }
      } catch (err) {
        console.warn('[Preview Báo giá] Lỗi query warranty/vat_rate:', err.message);
      }
    }

    let totalItemsPrice = 0;
    items.forEach(item => {
      const price = item.edited_price !== undefined ? item.edited_price : (item.list_price || 0);
      const itemDiscount = item.item_discount || 0;
      const lineTotal = (price - itemDiscount) * item.quantity;
      totalItemsPrice += lineTotal;
    });

    let globalDiscountAmt = 0;
    if (globalDiscount.type === 'percent') {
      globalDiscountAmt = Math.round(totalItemsPrice * (globalDiscount.value / 100));
    } else {
      globalDiscountAmt = Number(globalDiscount.value) || 0;
    }
    if (globalDiscountAmt > totalItemsPrice) globalDiscountAmt = totalItemsPrice;

    let appliedPromo = null;
    let promoDiscount = 0;

    if (!isGeneralQuote) {
      const tiers = [
        { min: 50000000, discount: 1000000, code: 'PVBUILDPC25114' },
        { min: 30000000, discount: 600000, code: 'PVBUILDPC25113' },
        { min: 20000000, discount: 400000, code: 'PVBUILDPC25112' },
        { min: 10000000, discount: 200000, code: 'PVBUILDPC25111' }
      ];
      for (const tier of tiers) {
        if (totalItemsPrice >= tier.min) {
          appliedPromo = {
            name: `Build PC - Giảm ${new Intl.NumberFormat('vi-VN').format(tier.discount)} VNĐ`,
            discount_amount: tier.discount,
            coupon: tier.code
          };
          promoDiscount = tier.discount;
          break;
        }
      }
    }

    const finalTotal = totalItemsPrice - globalDiscountAmt - promoDiscount;
    const taxFreeSubcats = ['NH09-02-01-01', 'NH09-02-01-02', 'NH09-01-01'];

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
        appliedPromo,
        finalTotal,
        validityDays: validityDaysSafe,
        deliveryDays: deliveryDaysSafe,
        notes,
        taxFreeSubcats: taxFreeSubcats,
        show_warranty: showWarranty,
        show_specs: showSpecs,
        show_images: showImages,
        formatVND: (n) => new Intl.NumberFormat('vi-VN').format(Number(n || 0))
      }
    );

    res.setHeader('Content-Type', 'text/html');
    res.send(htmlString);
  } catch (e) {
    console.error('Lỗi API Preview Báo giá:', e);
    if (!res.headersSent) res.status(500).json({ ok: false, error: e.message });
  }
});


app.post('/api/pc-builder/generate-quote-excel', requireAuth, async (req, res) => {
  try {
    const {
      buildConfig, customerName, contactInfo, customerPhone,
      isGeneralQuote = false,
      templateType = 'consumer',
      globalDiscount = { value: 0, type: 'amount' },
      validityDays,
      deliveryDays,
      notes = '',
      itemOrder,
      show_warranty = true,
      show_specs = true,
      show_images = true
    } = req.body;

    const showWarranty = show_warranty === true || show_warranty === 'true' || show_warranty === undefined;
    const showSpecs = show_specs === true || show_specs === 'true' || show_specs === undefined;
    const showImages = show_images === true || show_images === 'true' || show_images === undefined;
    const validityDaysSafe = (validityDays !== undefined && validityDays !== null && validityDays !== '') ? Number(validityDays) : null;
    const deliveryDaysSafe = (deliveryDays !== undefined && deliveryDays !== null && deliveryDays !== '') ? Number(deliveryDays) : 1;

    const buildConfigSafe = buildConfig && typeof buildConfig === 'object' ? buildConfig : {};
    const items = Object.entries(buildConfigSafe)
      .filter(([key, val]) => !key.startsWith('_') && val && typeof val === 'object')
      .map(([key, rawItem]) => {
        const item = { ...rawItem };
        item.quantity = Math.max(1, Number(item.quantity) || 1);
        item.item_discount = Math.max(0, Number(item.item_discount) || 0);
        item.list_price = Number(item.list_price) || 0;
        if (item.edited_price !== undefined && item.edited_price !== null && item.edited_price !== '') {
          item.edited_price = Number(item.edited_price) || 0;
        }
        item.quote_detailed_specs = String(item.quote_detailed_specs || '').replace(/\r\n/g, '\n').slice(0, 12000);
        return item;
      });

    if (Array.isArray(itemOrder)) {
      items.sort((a, b) => {
        const idxA = itemOrder.indexOf(a.sku);
        const idxB = itemOrder.indexOf(b.sku);
        if (idxA === -1 && idxB === -1) return 0;
        if (idxA === -1) return 1;
        if (idxB === -1) return -1;
        return idxA - idxB;
      });
    }

    if (items.length === 0) {
      return res.status(400).json({ ok: false, error: 'Không có sản phẩm để tạo báo giá.' });
    }

    const missingDetailsSkus = items.filter(it => !it.warranty || it.vat_rate === undefined).map(it => it.sku);
    if (missingDetailsSkus.length > 0) {
      try {
        const { data: dbDetails } = await supabase
          .from('skus')
          .select('sku, warranty, vat_rate')
          .in('sku', missingDetailsSkus);
        if (dbDetails && dbDetails.length > 0) {
          const dMap = {};
          dbDetails.forEach(d => { dMap[d.sku] = d; });
          items.forEach(it => {
            if (dMap[it.sku]) {
              if (!it.warranty && dMap[it.sku].warranty) it.warranty = dMap[it.sku].warranty;
              if (it.vat_rate === undefined && dMap[it.sku].vat_rate !== undefined) it.vat_rate = dMap[it.sku].vat_rate;
            }
          });
        }
      } catch (err) {
        console.warn('[Excel Báo giá] Lỗi query warranty/vat_rate:', err.message);
      }
    }

    let totalItemsPrice = 0;
    items.forEach(item => {
      const price = item.edited_price !== undefined ? item.edited_price : (item.list_price || 0);
      const itemDiscount = item.item_discount || 0;
      totalItemsPrice += (price - itemDiscount) * item.quantity;
    });

    let globalDiscountAmt = 0;
    if (globalDiscount.type === 'percent') {
      globalDiscountAmt = Math.round(totalItemsPrice * (globalDiscount.value / 100));
    } else {
      globalDiscountAmt = Number(globalDiscount.value) || 0;
    }
    if (globalDiscountAmt > totalItemsPrice) globalDiscountAmt = totalItemsPrice;

    let appliedPromo = null;
    let promoDiscount = 0;
    let promoName = '';

    if (!isGeneralQuote) {
      const tiers = [
        { min: 50000000, discount: 1000000, code: 'PVBUILDPC25114' },
        { min: 30000000, discount: 600000, code: 'PVBUILDPC25113' },
        { min: 20000000, discount: 400000, code: 'PVBUILDPC25112' },
        { min: 10000000, discount: 200000, code: 'PVBUILDPC25111' }
      ];
      for (const tier of tiers) {
        if (totalItemsPrice >= tier.min) {
          promoDiscount = tier.discount;
          promoName = `Build PC - Giảm ${new Intl.NumberFormat('vi-VN').format(tier.discount)} VNĐ`;
          break;
        }
      }
    }

    const finalTotal = totalItemsPrice - globalDiscountAmt - promoDiscount;
    const taxFreeSubcats = ['NH09-02-01-01', 'NH09-02-01-02', 'NH09-01-01'];

    const userFullName = req.session.user?.full_name || 'Nhân viên Phong Vũ';
    const userBranchCode = req.session.user?.branch_code || 'DEFAULT';
    const branchInfo = BRANCH_CONFIG[userBranchCode] || BRANCH_CONFIG['DEFAULT'];
    const todayStr = new Date().toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric' });

    // ─── BUILD EXCEL WORKBOOK ──────────────────────────────────────────────────
    const ExcelJS = require('exceljs');
    const path = require('path');
    const fs = require('fs');

    const wb = new ExcelJS.Workbook();
    wb.creator = 'Phong Vũ';
    wb.created = new Date();

    const ws = wb.addWorksheet('Báo giá', {
      pageSetup: { paperSize: 9, orientation: 'portrait', fitToPage: true, fitToWidth: 1, fitToHeight: 0 },
      views: [{ showGridLines: true }]
    });

    const hasDiscount = items.some(i => (i.item_discount || 0) > 0);
    const hasSpecs    = showSpecs && items.some(i => String(i.quote_detailed_specs || '').trim().length > 0);

    let cols = [];
    if (templateType === 'b2b') {
      cols = [
        { key: 'stt',      header: 'STT',                         width: 5 },
        { key: 'sku',      header: 'Mã SP',                       width: 13 },
        { key: 'name',     header: 'Tên sản phẩm',                 width: hasSpecs ? 28 : 42 },
        ...(hasSpecs ? [{ key: 'specs', header: 'Thông số chi tiết', width: 34 }] : []),
        { key: 'dvt',      header: 'ĐVT',                         width: 6 },
        { key: 'sl',       header: 'SL',                          width: 6 },
        { key: 'price',    header: 'Đơn giá\n(Chưa VAT)',          width: 14 },
        ...(hasDiscount ? [{ key: 'discount', header: 'Giảm giá\n(Chi tiết)', width: 13 }] : []),
        { key: 'total',    header: 'Thành tiền\n(Chưa VAT)',      width: 16 },
        { key: 'vat',      header: 'VAT\n(%)',                   width: 7 },
        { key: 'final',    header: 'Tổng cộng\n(Gồm VAT)',       width: 16 }
      ];
    } else {
      cols = [
        { key: 'stt',      header: 'STT',                         width: 5 },
        { key: 'sku',      header: 'Mã SP',                       width: 13 },
        { key: 'name',     header: 'Tên sản phẩm',                 width: hasSpecs ? 32 : 46 },
        ...(hasSpecs ? [{ key: 'specs', header: 'Thông số chi tiết', width: 36 }] : []),
        { key: 'dvt',      header: 'ĐVT',                         width: 6 },
        { key: 'sl',       header: 'SL',                          width: 6 },
        { key: 'price',    header: 'Đơn giá\n(Gồm VAT)',          width: 15 },
        ...(hasDiscount ? [{ key: 'discount', header: 'Giảm giá\n(Chi tiết)', width: 14 }] : []),
        { key: 'final',    header: 'Thành tiền\n(Gồm VAT)',      width: 17 }
      ];
    }

    ws.columns = cols.map(c => ({ key: c.key, width: c.width }));

    const nCols   = cols.length;
    const lastCol = ws.getColumn(nCols).letter;
    const midIdx = Math.floor(nCols / 2);
    const midLetter = ws.getColumn(midIdx).letter;
    const afterMidLetter = ws.getColumn(midIdx + 1).letter;

    // Styles
    const fHeader = { name: 'Arial', size: 9.5, bold: true, color: { argb: 'FFFFFFFF' } };
    const fTitle  = { name: 'Arial', size: 15, bold: true, color: { argb: 'FF0C65CE' } };
    const fSubTitle = { name: 'Arial', size: 12, bold: true, italic: true, color: { argb: 'FF0C65CE' } };
    const fBold   = { name: 'Arial', size: 10, bold: true };
    const fNormal = { name: 'Arial', size: 9.5 };
    const fSmall  = { name: 'Arial', size: 9 };
    const fSmallBold = { name: 'Arial', size: 9, bold: true };
    const fRed    = { name: 'Arial', size: 9.5, color: { argb: 'FFCC0000' } };
    const fBlue   = { name: 'Arial', size: 11, bold: true, color: { argb: 'FF0C65CE' } };

    const fillHdr = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF0C65CE' } };
    const bdrAll  = {
      top:    { style: 'thin', color: { argb: 'FFB0C4DE' } },
      left:   { style: 'thin', color: { argb: 'FFB0C4DE' } },
      bottom: { style: 'thin', color: { argb: 'FFB0C4DE' } },
      right:  { style: 'thin', color: { argb: 'FFB0C4DE' } }
    };
    const VND = '#,##0" đ"';

    // ─── 1. HEADER BANNER IMAGE (CHÈN HÌNH ẢNH GỐC CHUẨN ĐẸP) ────────────────
    const bannerPath = path.join(__dirname, 'public/images/sample_header_banner.png');
    if (fs.existsSync(bannerPath)) {
      const imgId = wb.addImage({
        filename: bannerPath,
        extension: 'png'
      });
      // Tạo 4 dòng cho banner
      ws.addRow([]);
      ws.addRow([]);
      ws.addRow([]);
      ws.addRow([]);
      ws.getRow(1).height = 24;
      ws.getRow(2).height = 24;
      ws.getRow(3).height = 24;
      ws.getRow(4).height = 24;

      ws.addImage(imgId, {
        tl: { col: 0, row: 0 },
        br: { col: nCols, row: 4 },
        editAs: 'oneCell'
      });
    } else {
      const r1 = ws.addRow([]);
      r1.height = 18;
      ws.mergeCells(`A1:${lastCol}1`);
      ws.getCell('A1').value = `CÔNG TY CỔ PHẦN THƯƠNG MẠI DỊCH VỤ PHONG VŨ - ${branchInfo.name.toUpperCase()}`;
      ws.getCell('A1').font  = { name: 'Arial', size: 11, bold: true, color: { argb: 'FF0C65CE' } };
      ws.getCell('A1').alignment = { vertical: 'middle' };

      const r2 = ws.addRow([]);
      r2.height = 16;
      ws.mergeCells(`A2:${lastCol}2`);
      ws.getCell('A2').value = `Địa chỉ/ Address: ${branchInfo.address}`;
      ws.getCell('A2').font  = fSmall;

      const r3 = ws.addRow([]);
      r3.height = 16;
      ws.mergeCells(`A3:${lastCol}3`);
      ws.getCell('A3').value = `MST/ Tax code: ${branchInfo.mst} | Hotline: ${branchInfo.hotline} | Website: www.phongvu.vn`;
      ws.getCell('A3').font  = fSmall;
    }

    // ROW 4: blank separator
    const rSep = ws.addRow([]);
    rSep.height = 10;

    // ROW 5: Title
    const titleRow = ws.addRow(['BẢNG BÁO GIÁ']);
    titleRow.height = 24;
    ws.mergeCells(`A${titleRow.number}:${lastCol}${titleRow.number}`);
    titleRow.getCell(1).font      = fTitle;
    titleRow.getCell(1).alignment = { horizontal: 'center', vertical: 'middle' };

    // ROW 6: SubTitle English
    const subTitleRow = ws.addRow(['QUOTATION']);
    subTitleRow.height = 18;
    ws.mergeCells(`A${subTitleRow.number}:${lastCol}${subTitleRow.number}`);
    subTitleRow.getCell(1).font      = fSubTitle;
    subTitleRow.getCell(1).alignment = { horizontal: 'center', vertical: 'middle' };

    // ROW 7: Date
    const dateRow = ws.addRow([`Ngày/ Date: ${todayStr}`]);
    ws.mergeCells(`A${dateRow.number}:${lastCol}${dateRow.number}`);
    dateRow.getCell(1).font      = { name:'Arial', size:9.5, italic:true, color:{ argb:'FF555555' } };
    dateRow.getCell(1).alignment = { horizontal: 'center' };

    // ROW 8: blank
    const rSep2 = ws.addRow([]);
    rSep2.height = 8;

    // ─── 2. CUSTOMER & INTRO SECTION (CHUẨN 100% THEO FILE MẪU) ─────────────
    const rCust = ws.addRow([]);
    ws.mergeCells(`A${rCust.number}:${lastCol}${rCust.number}`);
    rCust.getCell(1).value = `Kính gửi/ Respectfully to: Quý khách hàng ${customerName}`;
    rCust.getCell(1).font  = fBold;

    const rIntro = ws.addRow([]);
    ws.mergeCells(`A${rIntro.number}:${lastCol}${rIntro.number}`);
    rIntro.getCell(1).value = 'Chúng tôi xin trân trọng gởi đến Quý khách hàng bảng báo giá thiết bị như sau/ We would like to send to you the quotation of equipments as follows:';
    rIntro.getCell(1).font  = { name:'Arial', size:9, italic:true, color:{ argb:'FF444444' } };

    const rDetail = ws.addRow([]);
    ws.mergeCells(`A${rDetail.number}:${lastCol}${rDetail.number}`);
    rDetail.getCell(1).value = 'Chi tiết sản phẩm và đơn giá/ Equipments - Details and Price :';
    rDetail.getCell(1).font  = { name:'Arial', size:9.5, bold:true, color:{ argb:'FF0C65CE' } };

    // ─── 3. TABLE HEADER ──────────────────────────────────────────────────────
    const hdrLabels = {
      b2b: {
        stt:'STT\nNO.', sku:'Mã SP\nSKU', name:'Tên sản phẩm\nEQUIPMENTS', specs:'Thông số chi tiết\nDETAILS',
        dvt:'ĐVT\nUNIT', sl:'SL\nQTY.', price:'Đơn giá\n(Chưa VAT)', discount:'Giảm giá\n(Chi tiết)',
        total:'Thành tiền\n(Chưa VAT)', vat:'VAT\n(%)', final:'Tổng cộng\n(Gồm VAT)'
      },
      consumer: {
        stt:'STT\nNO.', sku:'Mã SP\nSKU', name:'Tên sản phẩm\nEQUIPMENTS', specs:'Thông số chi tiết\nDETAILS',
        dvt:'ĐVT\nUNIT', sl:'SL\nQTY.', price:'Đơn giá\n(Gồm VAT)', discount:'Giảm giá\n(Chi tiết)',
        final:'Thành tiền\n(Gồm VAT)'
      }
    };
    const labels = hdrLabels[templateType] || hdrLabels.consumer;

    const hdrValues = cols.map(c => labels[c.key] || c.key);
    const hdrRow = ws.addRow(hdrValues);
    hdrRow.height = 32;
    hdrRow.eachCell(cell => {
      cell.font      = fHeader;
      cell.fill      = fillHdr;
      cell.border    = bdrAll;
      cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
    });

    // ─── 4. TABLE DATA ────────────────────────────────────────────────────────
    let grandExVat = 0, grandVat = 0;

    items.forEach((item, idx) => {
      const isSoftware = (item.subcat && (item.subcat.toLowerCase().includes('phần mềm') || item.subcat.toLowerCase().includes('phan mem'))) || (item.product_name && item.product_name.toLowerCase().includes('phần mềm'));
      const isTaxFree   = taxFreeSubcats.includes(item.subcat) || isSoftware;
      const taxDivisor  = isTaxFree ? 1 : 1.08;
      const taxRate     = isTaxFree ? 0 : 0.08;

      const uPriceInc   = item.edited_price !== undefined ? item.edited_price : (item.list_price || 0);
      const uDiscInc    = item.item_discount || 0;
      const lineTotalInc= (uPriceInc - uDiscInc) * item.quantity;
      const uPriceEx    = Math.round(uPriceInc / taxDivisor);
      const uDiscEx     = Math.round(uDiscInc / taxDivisor);
      const lineTotalEx = (uPriceEx - uDiscEx) * item.quantity;
      const vatAmt      = lineTotalInc - lineTotalEx;

      grandExVat += lineTotalEx;
      grandVat   += vatAmt;

      let pName = item.product_name || item.name || '';
      if (showWarranty && item.warranty) {
        const cleanW = String(item.warranty).replace(/\s*chính\s*hãng/gi, '').trim();
        if (cleanW) pName += `\n(Bảo hành: ${cleanW})`;
      }

      const rd = {
        stt:  idx + 1,
        sku:  item.sku,
        name: pName,
        dvt: 'Cái',
        sl:   item.quantity
      };
      if (hasSpecs) rd.specs = item.quote_detailed_specs || '';

      if (templateType === 'b2b') {
        rd.price    = uPriceEx;
        if (hasDiscount) rd.discount = uDiscEx;
        rd.total    = lineTotalEx;
        rd.vat      = taxRate > 0 ? '8%' : '0%';
        rd.final    = lineTotalInc;
      } else {
        rd.price    = uPriceInc;
        if (hasDiscount) rd.discount = uDiscInc;
        rd.final    = lineTotalInc;
      }

      const row = ws.addRow(rd);
      row.eachCell((cell, cNum) => {
        const colKey = cols[cNum - 1]?.key;
        cell.font    = fNormal;
        cell.border  = bdrAll;
        if (['stt','dvt','sl','vat'].includes(colKey)) {
          cell.alignment = { horizontal: 'center', vertical: 'top', wrapText: true };
        } else if (['price','discount','total','final'].includes(colKey)) {
          cell.alignment = { horizontal: 'right', vertical: 'top', wrapText: true };
          cell.numFmt    = VND;
        } else {
          cell.alignment = { vertical: 'top', wrapText: true };
        }
      });
    });

    // ─── 5. TOTALS SECTION ────────────────────────────────────────────────────
    const colMergeEnd = ws.getColumn(nCols - 1).letter;

    function addTotalRow(label, value, fontStyle, bgColor) {
      const row = ws.addRow([]);
      ws.mergeCells(`A${row.number}:${colMergeEnd}${row.number}`);
      row.getCell(1).value     = label;
      row.getCell(1).font      = fontStyle || fBold;
      row.getCell(1).alignment = { horizontal: 'right', vertical: 'middle', wrapText: true };
      row.getCell(nCols).value  = value;
      row.getCell(nCols).numFmt = VND;
      row.getCell(nCols).font   = fontStyle || fBold;
      row.getCell(nCols).border = bdrAll;
      row.getCell(nCols).alignment = { horizontal: 'right', vertical: 'middle' };
      if (bgColor) {
        row.getCell(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: bgColor } };
        row.getCell(nCols).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: bgColor } };
      }
      return row;
    }

    if (templateType === 'b2b') {
      addTotalRow('Tổng tiền chưa thuế (Tạm tính):', grandExVat, fSmall);
      addTotalRow('Tổng tiền thuế VAT (Tạm tính):', grandVat, fSmall);
    }

    if (globalDiscountAmt > 0 || promoDiscount > 0) {
      addTotalRow('TỔNG GIÁ TRỊ HÀNG HÓA TRƯỚC GIẢM GIÁ/ TOTAL BEFORE DISCOUNT:', totalItemsPrice, fBold);
      if (globalDiscountAmt > 0) addTotalRow('GIẢM GIÁ/ DISCOUNT:', -globalDiscountAmt, fRed);
      if (promoDiscount > 0)     addTotalRow(`${promoName}:`, -promoDiscount, fRed);
      const grandRow = addTotalRow('TỔNG GIÁ TRỊ HÀNG HÓA SAU GIẢM GIÁ/ TOTAL AFTER DISCOUNT:', finalTotal, fBlue, 'FFFFF2CC');
      grandRow.height = 24;
    } else {
      const grandRow = addTotalRow('TỔNG GIÁ TRỊ HÀNG HÓA SAU GIẢM GIÁ/ TOTAL AFTER DISCOUNT:', finalTotal, fBlue, 'FFFFF2CC');
      grandRow.height = 24;
    }

    // Amount in words row
    const wordsRow = ws.addRow([]);
    ws.mergeCells(`A${wordsRow.number}:${lastCol}${wordsRow.number}`);
    wordsRow.getCell(1).value = {
      richText: [
        { font: { bold: true, name: 'Arial', size: 10 }, text: 'Bằng chữ/ In words: ' },
        { font: { italic: true, name: 'Arial', size: 10 }, text: typeof numberToWords === 'function' ? numberToWords(Math.round(finalTotal)) : '' }
      ]
    };
    wordsRow.height = 22;

    // ─── 6. FOOTER TERMS (MỖI DÒNG 1 ROW RIÊNG BIỆT KHÔNG BỊ TRÀN CHỮ) ────────
    ws.addRow([]); // Dòng trống

    function addTermRow(text, isBold, isItalic, customHeight) {
      const row = ws.addRow([]);
      ws.mergeCells(`A${row.number}:${lastCol}${row.number}`);
      row.getCell(1).value = text;
      row.getCell(1).font  = { name: 'Arial', size: 9, bold: !!isBold, italic: !!isItalic };
      row.getCell(1).alignment = { vertical: 'middle', wrapText: true };
      if (customHeight) {
        row.height = customHeight;
      } else if (text) {
        row.height = 15;
      } else {
        row.height = 5;
      }
      return row;
    }

    addTermRow('1. Lưu ý/ Notes:', true);
    addTermRow('- Đơn vị tiền tệ được sử dụng trong báo giá là Việt Nam Đồng (VNĐ)/ Vietnam Dong (VND) is applied for this quotation.');
    addTermRow('- Báo giá đã bao gồm thuế GTGT/ The quotation included VAT');
    if (validityDaysSafe && validityDaysSafe > 0) {
      addTermRow(`- Báo giá có hiệu lực trong vòng ${String(validityDaysSafe).padStart(2, '0')} ngày kể từ ngày báo giá/ The price is valid within ${String(validityDaysSafe).padStart(2, '0')} days from the date of quotation.`);
    }

    addTermRow(''); // khoảng trống
    addTermRow('2. Phương thức giao hàng/ Delivery terms:', true);
    addTermRow('- Địa chỉ giao hàng/ Delivery place: Giao hàng tại kho Phong Vũ.');
    addTermRow(`- Thời gian giao hàng/ Delivery time: Trong vòng ${String(deliveryDaysSafe || 1).padStart(2, '0')} ngày làm việc kể từ ngày xác nhận đặt hàng/ Estimated time ${String(deliveryDaysSafe || 1).padStart(2, '0')} working days from the date of confirming order.`);

    addTermRow(''); // khoảng trống
    addTermRow('3. Điều khoản bảo hành/ Warranty Terms:', true);
    addTermRow('- Bảo hành theo tiêu chuẩn Nhà sản xuất/ Warranty based on Manufacturer standards.');
    addTermRow('- Địa điểm bảo hành/ Warranty address: tham khảo website phongvu.vn để biết thêm chi tiết/ kindly refer to phongvu.vn for details.');

    addTermRow(''); // khoảng trống
    addTermRow('4. Phương thức thanh toán/ Payment terms:', true);
    addTermRow('- Phương thức thanh toán: tiền mặt hoặc chuyển khoản/ Payment method: Cash or Bank transfer.');
    addTermRow(`Tên tài khoản: ${branchInfo.bankHolder}`);
    addTermRow(`Account holder: ${branchInfo.bankHolder}`, false, true);
    addTermRow(`- Số tài khoản/ Account Number: ${branchInfo.bankAccount} - ${branchInfo.bankName}`);

    if (notes && notes.trim()) {
      addTermRow('');
      const noteLines = notes.split('\n');
      noteLines.forEach((nLine, idx) => {
        const fullNote = (idx === 0 ? 'Ghi chú bổ sung: ' : '') + nLine;
        const lineCount = Math.max(1, Math.ceil(fullNote.length / 115));
        addTermRow(fullNote, true, false, lineCount > 1 ? lineCount * 16 : 16);
      });
    }

    addTermRow('');
    addTermRow('Xin cảm ơn Quý khách/ Thank you and best regards!', true, true);

    // ─── 7. SIGNATURE SECTION ─────────────────────────────────────────────────
    ws.addRow([]);
    ws.addRow([]);

    const sigRow = ws.addRow([]);
    sigRow.height = 36;
    ws.mergeCells(`A${sigRow.number}:${midLetter}${sigRow.number}`);
    ws.getCell(`A${sigRow.number}`).value     = 'XÁC NHẬN MUA HÀNG\nORDER CONFIRMATION';
    ws.getCell(`A${sigRow.number}`).font      = fBold;
    ws.getCell(`A${sigRow.number}`).alignment = { wrapText: true, horizontal: 'center' };

    ws.mergeCells(`${afterMidLetter}${sigRow.number}:${lastCol}${sigRow.number}`);
    ws.getCell(`${afterMidLetter}${sigRow.number}`).value     = 'ĐẠI DIỆN KINH DOANH\nBUSINESS REPRESENTATIVE';
    ws.getCell(`${afterMidLetter}${sigRow.number}`).font      = fBold;
    ws.getCell(`${afterMidLetter}${sigRow.number}`).alignment = { wrapText: true, horizontal: 'center' };

    const sigSub = ws.addRow([]);
    ws.mergeCells(`A${sigSub.number}:${midLetter}${sigSub.number}`);
    ws.getCell(`A${sigSub.number}`).value     = '';

    ws.mergeCells(`${afterMidLetter}${sigSub.number}:${lastCol}${sigSub.number}`);
    ws.getCell(`${afterMidLetter}${sigSub.number}`).value     = '(Ký, ghi rõ họ tên)';
    ws.getCell(`${afterMidLetter}${sigSub.number}`).font      = { name:'Arial', size:9, italic:true };
    ws.getCell(`${afterMidLetter}${sigSub.number}`).alignment = { horizontal: 'center' };

    // Blank rows for signature space
    for (let i = 0; i < 4; i++) {
      const sr = ws.addRow([]);
      sr.height = 14;
    }

    const sigName = ws.addRow([]);
    ws.mergeCells(`${afterMidLetter}${sigName.number}:${lastCol}${sigName.number}`);
    ws.getCell(`${afterMidLetter}${sigName.number}`).value     = userFullName;
    ws.getCell(`${afterMidLetter}${sigName.number}`).font      = fBold;
    ws.getCell(`${afterMidLetter}${sigName.number}`).alignment = { horizontal: 'center' };

    if (contactInfo) {
      const sigPhone = ws.addRow([]);
      ws.mergeCells(`${afterMidLetter}${sigPhone.number}:${lastCol}${sigPhone.number}`);
      ws.getCell(`${afterMidLetter}${sigPhone.number}`).value     = `SĐT: ${contactInfo}`;
      ws.getCell(`${afterMidLetter}${sigPhone.number}`).font      = fSmall;
      ws.getCell(`${afterMidLetter}${sigPhone.number}`).alignment = { horizontal: 'center' };
    }

    // ─── SEND ─────────────────────────────────────────────────────────────────
    const safeName = customerName.normalize("NFD").replace(/[\u0300-\u036f]/g,"").replace(/đ/g,"d").replace(/Đ/g,"D").replace(/[^a-zA-Z0-9]/g,'_');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="BaoGia_${safeName}.xlsx"`);
    await wb.xlsx.write(res);
    res.end();

  } catch (e) {
    console.error('Lỗi API Báo giá Excel:', e);
    if (!res.headersSent) res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/quote-builder', requireAuth, (req, res) => {
  res.render('quote-builder', {
    title: 'Báo giá nhanh',
    currentPage: 'quote-builder', // Dùng để active menu (nếu cần)
  });
});


// (Trong file server.js)

app.post('/api/quote/upload-images', requireAuth, uploadQuoteImages.array('images', 6), async (req, res) => {
  try {
    const files = Array.isArray(req.files) ? req.files : [];
    if (files.length === 0) {
      return res.status(400).json({ ok: false, error: 'Không có ảnh để tải lên.' });
    }

    const parentId = process.env.PRICE_BATTLE_DRIVE_FOLDER_ID || process.env.QUOTE_BUILDER_DRIVE_FOLDER_ID || null;
    const urls = await Promise.all(
      files.map((file) => uploadBufferToDriveGlobal(file.buffer, file.originalname, file.mimetype, parentId))
    );

    return res.json({ ok: true, urls });
  } catch (e) {
    console.error('Lỗi upload ảnh báo giá:', e);
    return res.status(500).json({ ok: false, error: e.message || 'Upload ảnh thất bại.' });
  }
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
      .select('sku, product_name, brand, list_price, subcat');

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

// --- [REFACTORED] HÀM CHẠY ĐỒNG BỘ SKU TỪ BIGQUERY ---
async function runBqSkuSync(triggeredByEmail = 'System Automation') {
  const bqClient = global.bigquery || bigquery;
  if (!bqClient) {
    throw new Error('BigQuery client chưa được cấu hình.');
  }

  console.log(`[SYNC] [By: ${triggeredByEmail}] Bắt đầu đồng bộ SKUs từ BigQuery...`);

  // 1. Query BigQuery
  const bqQuery = `
        SELECT
            TRIM(CAST(SKU AS STRING)) AS sku,
            MAX(SKU_name) AS product_name,
            MAX(Brand) AS brand,
            MAX(Category_ID) AS category,
            MAX(Subcat_ID_lowest_level) AS subcat
        FROM \`nimble-volt-459313-b8.Inventory.inv_seri_1\`
        WHERE SKU IS NOT NULL AND TRIM(CAST(SKU AS STRING)) != ''
        GROUP BY 1
    `;

  const [bqRowsRaw] = await bqClient.query({
    query: bqQuery,
    location: 'asia-southeast1',
  });

  if (!bqRowsRaw || bqRowsRaw.length === 0) {
    throw new Error('Không tìm thấy dữ liệu SKU nào từ BigQuery.');
  }

  const bqRows = bqRowsRaw.map(row => ({
    sku: (row.sku || '').trim(),
    product_name: (row.product_name || '').trim(),
    brand: (row.brand || '').trim() || null,
    category: (row.category || '').trim() || null,
    subcat: (row.subcat || '').trim() || null
  })).filter(row => row.sku);

  // 2. Lấy SKUs hiện có (Pagination Logic)
  const existingSkuSet = new Set();
  const PAGE_SIZE = 1000;
  let page = 0;
  let keepFetching = true;

  while (keepFetching) {
    const { data: skuPage, error: supabaseError } = await supabase
      .from('skus')
      .select('sku')
      .range(page * PAGE_SIZE, (page + 1) * PAGE_SIZE - 1);

    if (supabaseError) throw supabaseError;

    if (!skuPage || skuPage.length === 0) {
      keepFetching = false;
    } else {
      skuPage.forEach(s => {
        if (s.sku) existingSkuSet.add(s.sku.trim());
      });
      if (skuPage.length < PAGE_SIZE) keepFetching = false;
      page++;
    }
  }

  // 3. Lọc SKU mới
  const newSkuPayloads = bqRows.filter(bqRow => !existingSkuSet.has(bqRow.sku));
  let totalInsertedCount = 0;

  // 4. Insert nếu có mới
  if (newSkuPayloads.length > 0) {
    const BATCH_SIZE = 1000;
    for (let i = 0; i < newSkuPayloads.length; i += BATCH_SIZE) {
      const batch = newSkuPayloads.slice(i, i + BATCH_SIZE);
      const finalBatch = batch.map(b => ({
        sku: b.sku,
        product_name: b.product_name || b.sku,
        brand: b.brand,
        category: b.category,
        subcat: b.subcat
      }));

      const { error: insertError } = await supabase.from('skus').insert(finalBatch);
      if (insertError) throw new Error(`Lỗi insert batch ${i}: ${insertError.message}`);
      totalInsertedCount += batch.length;
    }
  }

  const resultMessage = totalInsertedCount > 0
    ? `Đồng bộ hoàn tất. Đã thêm ${totalInsertedCount} SKU mới.`
    : `Đồng bộ hoàn tất. Không có SKU mới nào.`;

  // 5. TẠO THÔNG BÁO (NOTIFICATION)
  try {
    await supabase.from('notifications').insert({
      title: 'Kết quả đồng bộ BigQuery',
      content: resultMessage,
      type: 'update',
      user_ref: triggeredByEmail,
      is_read: false,
      created_at: new Date()
    });
  } catch (notifErr) {
    console.error('[SYNC] Không thể tạo notification:', notifErr.message);
  }

  return { message: resultMessage, new_skus: totalInsertedCount };
}

// API MỚI: Đồng bộ SKUs từ BigQuery (Manual Trigger)
app.post('/api/admin/sync-bq-skus', requireAuth, requireManager, async (req, res) => {
  try {
    const result = await runBqSkuSync(req.session.user.email);
    res.json({ ok: true, ...result });
  } catch (e) {
    console.error('[SYNC] Lỗi:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Thêm endpoint manual sync inventory cho nút bấm Admin
app.post('/api/admin/sync-inventory', requireAuth, requireManager, async (req, res) => {
  try {
    const { syncInventory } = require('./sync_inventory');
    await syncInventory();
    res.json({ ok: true, message: 'Inventory synced successfully' });
  } catch (e) {
    console.error('[SYNC INV] Lỗi:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ROUTE CRON T? D?NG: Ch?y h?ng ngày (Trigger b?i Vercel)
// G?p chung SKU Sync và Inventory Sync d? ti?t ki?m Slot Cron (Vercel Hobby ch? cho 2 cái)
// Thêm endpoint manual sync promotions cho nút bấm Admin
app.post('/api/admin/sync-promotions', requireAuth, requireManager, async (req, res) => {
  try {
    await syncPromotions();
    res.json({ ok: true, message: 'Đồng bộ CTKM từ Google Sheets thành công!' });
  } catch (e) {
    console.error('[SYNC PROMOTIONS] Lỗi:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/cron/sync-promotions', async (req, res) => {
  const authHeader = req.headers.authorization || req.query.secret;
  const secret = process.env.CRON_SECRET;
  if (secret && authHeader !== secret && authHeader !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  console.log('[CRON] Starting promotions-only sync...');
  try {
    await syncPromotions();
    res.json({ ok: true, source: 'cron-sync-promotions', message: 'Promotions synced successfully!' });
  } catch (e) {
    console.error('[CRON PROMOTIONS] Lỗi:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/cron/sync-all', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (process.env.CRON_SECRET && authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  console.log('[CRON] Starting combined sync (SKUs + Inventory + Promotions)...');
  const results = { skus: null, inventory: null, promotions: null };

  try {
    // 1. Sync SKUs
    results.skus = await runBqSkuSync('Automation System');
    console.log('[CRON] SKU Sync OK');

    // 2. Sync Inventory
    const { syncInventory } = require('./sync_inventory');
    await syncInventory();
    results.inventory = { ok: true };
    console.log('[CRON] Inventory Sync OK');

    // 3. Sync Clearance
    await syncClearanceData();
    results.clearance = { ok: true };
    console.log('[CRON] Clearance Sync OK');

    // 4. Sync Promotions from Google Sheets
    await syncPromotions();
    results.promotions = { ok: true };
    console.log('[CRON] Promotions Sync OK');

    res.json({ ok: true, source: 'cron-sync-all', ...results });
  } catch (e) {
    console.error('[CRON SYNC ALL] Fail:', e.message);
    res.status(500).json({ ok: false, error: e.message, partial_results: results });
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

    // Params
    const { sort, tax, status, month, branch, q, type, emp, excludeGrab, showAssigned } = req.query;

    const shouldHideGrab = excludeGrab !== 'false';
    const isFilterAssignedOnly = showAssigned === 'true';

    if (!bigquery) return res.json({ ok: false, error: 'No BigQuery' });

    // 1. PHÂN QUYỀN
    const isGlobalAdmin = user.branch_code === 'HCM.BD';
    const isManager = user.role === 'manager' || user.role === 'admin' || isGlobalAdmin;

    // Lấy danh sách branch được phép (cho Manager/Regional)
    const allowedBranches = getAllowedBranches(user);

    // 2. CHUẨN BỊ QUERY
    let whereClause = 'WHERE 1=1';
    const params = { limit: pageSize, offset: offset };

    // --- LẤY DANH SÁCH ĐƠN ĐƯỢC GÁN (TỪ SUPABASE) ---
    let assignedOrderCodes = [];
    let assignQuery = supabase.from('customer_assignments').select('order_code');

    if (emp) { // Nếu lọc theo nhân viên cụ thể
      assignQuery = assignQuery.eq('assigned_to', emp);
    } else if (!isManager) { // Staff chỉ xem của mình
      assignQuery = assignQuery.eq('assigned_to', user.id);
    }
    // Manager xem All thì không filter assigned_to

    const { data: assignData } = await assignQuery;
    assignedOrderCodes = (assignData || []).map(r => r.order_code);

    // NẾU TICK CHỌN "Được phân bổ" -> Lọc cứng ngay lập tức
    if (isFilterAssignedOnly) {
      if (assignedOrderCodes.length === 0) {
        return res.json({ ok: true, data: [], page: page, month: month });
      }
      whereClause += ` AND Order_code IN UNNEST(@assignedCodes)`;
      params.assignedCodes = assignedOrderCodes;
    }

    // --- LỌC THỜI GIAN ---
    const now = new Date();
    const currentMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    let filterMonth = (month === 'undefined' || month === 'null') ? undefined : month;
    if (!filterMonth) filterMonth = (q || emp) ? 'all' : currentMonth;
    params.filterMonth = filterMonth;

    // [FIX] Xử lý filter theo Ngày / Tuần / Tháng / Năm
    const isYearFilter = /^\d{4}$/.test(filterMonth);

    if (filterMonth === 'today') {
      const todayStr = now.toISOString().split('T')[0];
      const tomorrow = new Date(now); tomorrow.setDate(tomorrow.getDate() + 1);
      params.monthStart = todayStr;
      params.monthEnd = tomorrow.toISOString().split('T')[0];
      whereClause += ` AND Report_date >= @monthStart AND Report_date < @monthEnd`;
    } else if (filterMonth === 'yesterday') {
      const yesterday = new Date(now); yesterday.setDate(yesterday.getDate() - 1);
      params.monthStart = yesterday.toISOString().split('T')[0];
      params.monthEnd = now.toISOString().split('T')[0];
      whereClause += ` AND Report_date >= @monthStart AND Report_date < @monthEnd`;
    } else if (filterMonth === 'this_week') {
      const currDate = new Date(now);
      const first = currDate.getDate() - currDate.getDay() + (currDate.getDay() === 0 ? -6 : 1); // Monday
      const monday = new Date(currDate.setDate(first));
      params.monthStart = monday.toISOString().split('T')[0];
      const nextMonday = new Date(monday); nextMonday.setDate(nextMonday.getDate() + 7);
      params.monthEnd = nextMonday.toISOString().split('T')[0];
      whereClause += ` AND Report_date >= @monthStart AND Report_date < @monthEnd`;
    } else if (isYearFilter) {
      // Cả năm: Report_date từ YYYY-01-01 đến YYYY-12-31
      params.monthStart = `${filterMonth}-01-01`;
      params.monthEnd = `${parseInt(filterMonth) + 1}-01-01`;
      whereClause += ` AND Report_date >= @monthStart AND Report_date < @monthEnd`;
    } else if (filterMonth !== 'all') {
      // Tháng cụ thể: YYYY-MM
      whereClause += ` AND Report_date >= @monthStart AND Report_date < @monthEnd`;
      params.monthStart = filterMonth + '-01';
      const [yy, mm] = filterMonth.split('-');
      const d = new Date(parseInt(yy), parseInt(mm), 1); // First day of NEXT month
      params.monthEnd = d.toISOString().split('T')[0];
    } else {
      if (type !== 'order_code') {
        whereClause += ` AND Report_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 24 MONTH)`;
      }
    }

    // --- [QUAN TRỌNG] PHÂN QUYỀN DATA ---

    // CASE 1: GLOBAL ADMIN
    if (isGlobalAdmin) {
      if (branch && branch !== 'all') {
        whereClause += ` AND Branch_code = @branch`;
        params.branch = branch;
      }
    }
    // CASE 2: MANAGER (Regional hoặc Store Manager)
    else if (isManager) {
      // Nếu Regional Manager lọc theo 1 branch con cụ thể
      if (branch && branch !== 'all' && allowedBranches && allowedBranches.includes(branch)) {
        whereClause += ` AND Branch_code = @branch`;
        params.branch = branch;
      } else if (allowedBranches) {
        // Mặc định: Xem tất cả branch mình quản lý (VD: TD12 xem CP46+CP67)
        whereClause += ` AND Branch_code IN UNNEST(@regionalBranches)`;
        params.regionalBranches = allowedBranches;
      } else {
        // Fallback: Xem branch của chính mình
        whereClause += ` AND Branch_code = @branch`;
        params.branch = user.branch_code;
      }


      // Manager lọc theo nhân viên (emp)
      if (emp && emp.trim() !== '') {
        const { data: uData } = await supabase.from('users').select('email').eq('id', emp).single();
        if (uData && !isFilterAssignedOnly) {
          whereClause += ` AND LOWER(Email) = LOWER(@targetEmail)`;
          params.targetEmail = uData.email;
        }
      }
    }
    // CASE 3: STAFF (NHÂN VIÊN) - PHẢI CHẶT CHẼ NHẤT
    else {
      if (!isFilterAssignedOnly) {
        if (assignedOrderCodes.length > 0) {
          whereClause += ` AND (LOWER(Email) = LOWER(@userEmail) OR Order_code IN UNNEST(@assignedCodes))`;
          params.assignedCodes = assignedOrderCodes;
        } else {
          whereClause += ` AND LOWER(Email) = LOWER(@userEmail)`;
        }
        params.userEmail = user.email;
      }
    }

    // --- TÌM KIẾM ---
    if (q && q.trim() !== '') {
      const keyword = q.trim();
      if (type === 'order_code') {
        whereClause += ` AND Order_code LIKE @keyword`;
        params.keyword = `${keyword}%`;
      } else if (type === 'tax_code') {
        const cleanKey = keyword.replace(/^0+/, '');
        whereClause += ` AND (Billing_tax_code LIKE @keyRaw OR Billing_tax_code LIKE @keyNoZero OR Billing_tax_code LIKE @keyWithZero)`;
        params.keyRaw = `%${keyword}%`; params.keyNoZero = `%${cleanKey}%`; params.keyWithZero = `%0${cleanKey}%`;
      } else {
        whereClause += ` AND LOWER(Customer_full_name) LIKE LOWER(@keyword)`;
        params.keyword = `%${keyword}%`;
      }
    }


    // --- CÁC BỘ LỌC KHÁC ---
    if (tax === 'has_tax') whereClause += ` AND Billing_tax_code IS NOT NULL AND TRIM(CAST(Billing_tax_code AS STRING)) != '' AND LENGTH(TRIM(CAST(Billing_tax_code AS STRING))) > 5`;
    // [FIX] KH Cá nhân: Tax code rỗng, null hoặc quá ngắn (GRAB MST: 0316032128 dài hơn 5)
    else if (tax === 'no_tax') whereClause += ` AND (Billing_tax_code IS NULL OR TRIM(CAST(Billing_tax_code AS STRING)) = '' OR LENGTH(TRIM(CAST(Billing_tax_code AS STRING))) <= 5)`;
    if (shouldHideGrab) whereClause += ` AND (Billing_tax_code IS NULL OR TRIM(CAST(Billing_tax_code AS STRING)) != '0316032128')`;

    // --- SORTING ---
    let orderBy = 'ORDER BY Total_Revenue DESC';
    if (sort === 'date_desc') orderBy = 'ORDER BY Max_Date DESC';
    if (sort === 'price_asc') orderBy = 'ORDER BY Total_Revenue ASC';
    if (sort === 'date_asc') orderBy = 'ORDER BY Max_Date ASC';

    const tableName = '`nimble-volt-459313-b8.sales.raw_sales_orders_all`';

    // --- QUERY CHÍNH ---
    const query = `
            WITH OrderSummary AS (
                SELECT 
                    Order_code,
                    MAX(Customer_full_name) as Customer_full_name,
                    MAX(Billing_tax_code) as Billing_tax_code,
                    CAST(MAX(Report_date) AS STRING) as Report_date,
                    MAX(Branch_code) as Branch_code,
                    MAX(Email) as Sales_Email,
                    SUM(Revenue_with_VAT) as Order_Total_Val,
                    '' as Full_Product_Info
                FROM ${tableName}
                ${whereClause}
                GROUP BY Order_code
            )
            SELECT
                COALESCE(Customer_full_name, 'Khách lẻ') as Customer_Name,
                IFNULL(Billing_tax_code, '') as Tax_Code,
                COUNT(Order_code) as Order_Count,
                CAST(SUM(Order_Total_Val) AS FLOAT64) as Total_Revenue,
                CAST(MAX(Report_date) AS STRING) as Max_Date,
                ARRAY_AGG(STRUCT(
                    Order_code,
                    Report_date,
                    Branch_code,
                    Sales_Email,
                    CAST(Order_Total_Val AS FLOAT64) as Revenue,
                    Full_Product_Info as Product_Display_Html, 
                    1 as Quantity
                )) as Orders
            FROM OrderSummary
            GROUP BY 1, 2
            ${orderBy}
            LIMIT @limit OFFSET @offset
        `;

    const [rows] = await bigquery.query({ query, params });

    // --- XỬ LÝ DỮ LIỆU TRẢ VỀ (LOGS + ASSIGNMENT) ---
    if (rows.length > 0) {
      let allOrderCodes = [];
      rows.forEach(row => { if (row.Orders) row.Orders.forEach(o => allOrderCodes.push(o.Order_code)); });

      // Fetch logs with carer name (for MST grouping display)
      const { data: logs } = await supabase
        .from('customer_care_logs')
        .select('order_code, result, created_at, users!inner(full_name, email)')
        .in('order_code', allOrderCodes)
        .order('created_at', { ascending: true }); // ascending = người care đầu tiên


      // Lấy danh sách gán để tô màu UI (cho dù là manager hay staff)
      const { data: assignments } = await supabase.from('customer_assignments').select('order_code').in('order_code', allOrderCodes);
      const assignedSet = new Set((assignments || []).map(a => a.order_code));

      const logMap = new Map();
      (logs || []).forEach(l => {
        if (!logMap.has(l.order_code)) {
          logMap.set(l.order_code, {
            ...l,
            carer_name: l.users?.full_name || l.users?.email || 'N/A'
          });
        }
      });

      rows.forEach(customer => {
        let caredCount = 0;
        let hasClosedOrder = false;
        let isAssignedCustomer = false;

        if (customer.Orders) {
          customer.Orders = customer.Orders.map(o => {
            let d = o.Report_date; if (d && d.value) d = d.value;
            const log = logMap.get(o.Order_code);
            if (log) { caredCount++; if ((log.result || '').toLowerCase().includes('chốt')) hasClosedOrder = true; }

            const isAssigned = assignedSet.has(o.Order_code);
            if (isAssigned) isAssignedCustomer = true;

            return { ...o, Report_date: d, status: log ? 'Đã chăm sóc' : 'Chưa chăm sóc', result: log?.result || '', carer_name: log?.carer_name || '', is_assigned: isAssigned };
          });
        }
        if (hasClosedOrder) customer.Care_Status = 'done';
        else if (caredCount > 0) customer.Care_Status = 'partial';
        else customer.Care_Status = 'uncared';

        customer.is_assigned_group = isAssignedCustomer;

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

// GET /api/cskh/customer-orders (Load details logic inside worklist breakdown)
app.get('/api/cskh/customer-orders', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    const { taxCode, customerName, month, branch } = req.query;
    if (!bigquery) return res.json({ ok: false, error: 'No BigQuery' });

    let whereClause = 'WHERE 1=1';
    const params = {};

    // [FIX] Xử lý filter theo NĂM hoặc NGÀY
    let filterMonth = (month === 'undefined' || month === 'null') ? undefined : month;
    const isYearFilter = filterMonth && /^\d{4}$/.test(filterMonth);
    const now = new Date();

    if (filterMonth === 'today') {
      const todayStr = now.toISOString().split('T')[0];
      const tomorrow = new Date(now); tomorrow.setDate(tomorrow.getDate() + 1);
      params.monthStart = todayStr;
      params.monthEnd = tomorrow.toISOString().split('T')[0];
      whereClause += ` AND Report_date >= @monthStart AND Report_date < @monthEnd`;
    } else if (filterMonth === 'yesterday') {
      const yesterday = new Date(now); yesterday.setDate(yesterday.getDate() - 1);
      params.monthStart = yesterday.toISOString().split('T')[0];
      params.monthEnd = now.toISOString().split('T')[0];
      whereClause += ` AND Report_date >= @monthStart AND Report_date < @monthEnd`;
    } else if (filterMonth === 'this_week') {
      const currDate = new Date(now);
      const first = currDate.getDate() - currDate.getDay() + (currDate.getDay() === 0 ? -6 : 1); // Monday
      const monday = new Date(currDate.setDate(first));
      params.monthStart = monday.toISOString().split('T')[0];
      const nextMonday = new Date(monday); nextMonday.setDate(nextMonday.getDate() + 7);
      params.monthEnd = nextMonday.toISOString().split('T')[0];
      whereClause += ` AND Report_date >= @monthStart AND Report_date < @monthEnd`;
    } else if (isYearFilter) {
      whereClause += ` AND Report_date >= @monthStart AND Report_date < @monthEnd`;
      params.monthStart = `${filterMonth}-01-01`;
      params.monthEnd = `${parseInt(filterMonth) + 1}-01-01`;
    } else if (filterMonth && filterMonth !== 'all') {
      whereClause += ` AND Report_date >= @monthStart AND Report_date < @monthEnd`;
      params.monthStart = filterMonth + '-01';
      const [yy, mm] = filterMonth.split('-');
      const d = new Date(parseInt(yy), parseInt(mm), 0);
      d.setDate(d.getDate() + 1);
      params.monthEnd = d.toISOString().split('T')[0];
    } else {
      whereClause += ` AND Report_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 24 MONTH)`;
    }

    // Tax Code or Name filter
    if (taxCode) {
      whereClause += ` AND Billing_tax_code = @taxCode`;
      params.taxCode = taxCode;
    } else if (customerName) {
      whereClause += ` AND Customer_full_name = @customerName AND (Billing_tax_code IS NULL OR Billing_tax_code = '')`;
      params.customerName = customerName;
    }

    // Role filters
    const isGlobalAdmin = user.branch_code === 'HCM.BD';
    const isManager = user.role === 'manager' || user.role === 'admin' || isGlobalAdmin;
    const allowedBranches = typeof getAllowedBranches === 'function' ? getAllowedBranches(user) : [user.branch_code];

    if (isGlobalAdmin) {
      if (branch && branch !== 'all') { whereClause += ' AND Branch_code = @branch'; params.branch = branch; }
    } else if (isManager) {
      if (branch && branch !== 'all' && allowedBranches && allowedBranches.includes(branch)) {
        whereClause += ' AND Branch_code = @branch'; params.branch = branch;
      } else if (allowedBranches) {
        whereClause += ' AND Branch_code IN UNNEST(@regionalBranches)'; params.regionalBranches = allowedBranches;
      } else {
        whereClause += ' AND Branch_code = @branch'; params.branch = user.branch_code;
      }
    } else {
      // Support assigned lookup implicitly? Staff can only see their branch orders
      whereClause += ' AND LOWER(Email) = LOWER(@userEmail)'; params.userEmail = user.email;
    }

    const query = `
      WITH OrderSummary AS (
          SELECT 
              Order_code,
              CAST(MAX(Report_date) AS STRING) as Report_date,
              MAX(Branch_code) as Branch_code,
              MAX(Email) as Sales_Email,
              SUM(Revenue_with_VAT) as Order_Total_Val,
              STRING_AGG(CONCAT('<span style="color:#2563eb; font-weight:700;">', CAST(SKU AS STRING), '</span> - ', SKU_name, ' <span style="color:#64748b;">(x', CAST(Quantity AS STRING), ')</span>'), '<br>') as Full_Product_Info
          FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
          ${whereClause}
          GROUP BY Order_code
      )
      SELECT
          Order_code,
          Report_date,
          Branch_code,
          Sales_Email,
          CAST(Order_Total_Val AS FLOAT64) as Revenue,
          Full_Product_Info as Product_Display_Html, 
          1 as Quantity
      FROM OrderSummary
      ORDER BY Report_date DESC
    `;

    const [rows] = await bigquery.query({ query, params });

    // Fetch carer names for these orders
    if (rows.length > 0) {
      const allOrderCodes = rows.map(r => r.Order_code);
      const { data: logs } = await supabase.from('customer_care_logs').select('order_code, result, users!inner(full_name, email)').in('order_code', allOrderCodes).order('created_at', { ascending: true });
      const logMap = new Map();
      (logs || []).forEach(l => {
        if (!logMap.has(l.order_code)) {
          logMap.set(l.order_code, { ...l, carer_name: l.users?.full_name || l.users?.email || 'N/A' });
        }
      });
      rows.forEach(r => {
        if (logMap.has(r.Order_code)) {
          const log = logMap.get(r.Order_code);
          r.status = 'Đã chăm sóc'; r.result = log.result; r.carer_name = log.carer_name;
        } else {
          r.status = 'Chưa chăm sóc'; r.result = ''; r.carer_name = '';
        }
      });
    }

    res.json({ ok: true, data: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/cskh/assign', requireAuth, requireManager, async (req, res) => {
  try {
    const { order_codes, target_user_id } = req.body;

    if (!order_codes || !Array.isArray(order_codes) || order_codes.length === 0) {
      return res.status(400).json({ ok: false, error: 'Chưa chọn khách hàng nào.' });
    }
    if (!target_user_id) {
      return res.status(400).json({ ok: false, error: 'Chưa chọn nhân viên tiếp nhận.' });
    }

    // Chuẩn bị dữ liệu upsert
    const assignments = order_codes.map(code => ({
      order_code: code,
      assigned_to: target_user_id,
      assigned_by: req.session.user.id,
      created_at: new Date()
    }));

    const { error } = await supabase
      .from('customer_assignments')
      .upsert(assignments, { onConflict: 'order_code' });

    if (error) throw error;

    res.json({ ok: true, message: `Đã phân bổ ${order_codes.length} đơn hàng.` });

  } catch (e) {
    console.error('Assign Error:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// --- FAVORITE (GẮN SAO) ---
// POST /api/cskh/favorite — toggle yêu thích
app.post('/api/cskh/favorite', requireAuth, async (req, res) => {
  try {
    const { tax_code, customer_name, action } = req.body; // action: 'add' | 'remove'
    const userId = req.session.user.id;
    if (!tax_code) return res.status(400).json({ ok: false, error: 'Thiếu tax_code' });

    if (action === 'remove') {
      await supabase.from('customer_favorites').delete().eq('user_id', userId).eq('tax_code', tax_code);
    } else {
      await supabase.from('customer_favorites').upsert(
        { user_id: userId, tax_code, customer_name: customer_name || '', created_at: new Date() },
        { onConflict: 'user_id,tax_code' }
      );
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/cskh/favorites — danh sách tax_code đã lưu
app.get('/api/cskh/favorites', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { data } = await supabase.from('customer_favorites').select('tax_code, customer_name').eq('user_id', userId);
    res.json({ ok: true, data: data || [] });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// --- DASHBOARD CHĂM SÓC KHÁCH HÀNG (LOGIC CŨ + FIX REGIONAL) ---
app.get('/customer-care', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;

    // 1. XÁC ĐỊNH QUYỀN
    const isGlobalAdmin = user.branch_code === 'HCM.BD';
    const isManager = user.role === 'manager' || user.role === 'admin' || isGlobalAdmin;

    // Lấy danh sách chi nhánh được phép xem (Regional Logic)
    // Ví dụ: TD12 -> ['CP46', 'CP67']
    const allowedBranches = getAllowedBranches(user);

    // 2. BỘ LỌC THỜI GIAN
    const now = new Date();
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);

    const startDateRaw = req.query.start || firstDay.toISOString().split('T')[0];
    const endDateRaw = req.query.end || now.toISOString().split('T')[0];

    const startISO = new Date(startDateRaw).toISOString();
    const endDateObj = new Date(endDateRaw);
    endDateObj.setHours(23, 59, 59, 999);
    const endISO = endDateObj.toISOString();

    // 3. XỬ LÝ LỌC BRANCH & EMP TRÊN GIAO DIỆN
    let filterBranch = req.query.branch || null;
    let filterEmpId = req.query.emp || null;

    // Nếu là Manager/User thường, ép buộc filterEmpId nếu họ tự lọc
    if (!isManager) filterEmpId = user.id;

    // 4. TRUY VẤN DỮ LIỆU - BATCH FETCH để vượt giới hạn 1000 dòng Supabase Free
    const buildDashQuery = (from, to) => {
      let q = supabase
        .from('customer_care_logs')
        .select(`revenue_at_care, result, order_code, created_at, created_by, users!inner(id, full_name, email, branch_code)`)
        .gte('created_at', startISO)
        .lte('created_at', endISO)
        .range(from, to);

      if (isGlobalAdmin) {
        if (filterBranch && filterBranch !== 'all') q = q.eq('users.branch_code', filterBranch);
      } else if (allowedBranches) {
        if (filterBranch && allowedBranches.includes(filterBranch)) q = q.eq('users.branch_code', filterBranch);
        else q = q.in('users.branch_code', allowedBranches);
      } else {
        q = q.eq('users.branch_code', user.branch_code);
      }
      if (filterEmpId) q = q.eq('created_by', filterEmpId);
      return q;
    };

    let rawData = [];
    const DASH_BATCH = 1000;
    let dashFrom = 0;
    while (true) {
      const { data: batch, error: batchErr } = await buildDashQuery(dashFrom, dashFrom + DASH_BATCH - 1);
      if (batchErr) throw batchErr;
      if (!batch || batch.length === 0) break;
      rawData = rawData.concat(batch);
      if (batch.length < DASH_BATCH) break;
      dashFrom += DASH_BATCH;
    }



    // 5. TÍNH TOÁN CHỈ SỐ (GIỮ NGUYÊN LOGIC CŨ CỦA BẠN)
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

      // Matrix (Tự động gom nhóm theo Branch lấy được từ Logs)
      if (!matrixData[branch]) matrixData[branch] = {};
      if (!matrixData[branch][uid]) matrixData[branch][uid] = { name: u.full_name || u.email, total_care: 0, total_revenue: 0, results: {} };

      const salesman = matrixData[branch][uid];
      salesman.total_care += 1;
      salesman.total_revenue += rev;
      salesman.results[result] = (salesman.results[result] || 0) + 1;
      allResultTypes.add(result);
    });

    // ... Các phần sort ranking giữ nguyên ...
    const rankingList = Object.values(userTotalMap).sort((a, b) => b.total - a.total);
    let currentRank = '--';
    const targetRankId = filterEmpId || user.id;
    const rankIdx = rankingList.findIndex(x => x.id === targetRankId);
    if (rankIdx !== -1) currentRank = `#${rankIdx + 1}`;

    const resultColumns = Array.from(allResultTypes).sort((a, b) => {
      if (a.includes('Chốt')) return -1;
      return a.localeCompare(b);
    });

    // 6. LẤY DANH SÁCH NHÂN VIÊN (ĐỂ FILL DROPDOWN)
    let staffList = [];
    let branchList = [];

    if (isManager) {
      // Lấy danh sách Branch Dropdown
      if (isGlobalAdmin) {
        const { data: branches } = await supabase.from('users').select('branch_code').neq('branch_code', null);
        branchList = [...new Set((branches || []).map(b => b.branch_code))].sort();
      } else if (allowedBranches) {
        branchList = allowedBranches.sort();
      } else {
        branchList = [user.branch_code];
      }

      // Lấy danh sách Staff Dropdown
      let staffQuery = supabase.from('users').select('id, email, full_name, branch_code').eq('role', 'staff');

      if (isGlobalAdmin) {
        if (filterBranch) staffQuery = staffQuery.eq('branch_code', filterBranch);
      } else if (allowedBranches) {
        // Regional: Nếu filter 1 branch thì lấy staff branch đó, ko thì lấy hết staff của region
        if (filterBranch && allowedBranches.includes(filterBranch)) {
          staffQuery = staffQuery.eq('branch_code', filterBranch);
        } else {
          staffQuery = staffQuery.in('branch_code', allowedBranches);
        }
      }
      const { data: staffs } = await staffQuery;
      staffList = staffs || [];
    }

    // 7. RENDER
    res.render('customer-care', {
      title: 'Chăm sóc khách hàng',
      currentPage: 'customer-care',
      user: user,
      isGlobalAdmin, isManager,
      branchList,
      branchStaffs: staffList, // Danh sách nhân viên (đã lọc theo Region)
      filters: {
        start: startDateRaw, end: endDateRaw,
        branch: filterBranch, emp: filterEmpId,
        excludeGrab: req.query.excludeGrab
      },
      dashboard: {
        revenue: totalRevenue,
        cared_count: uniqueOrders.size,
        closed_count: closedCount,
        rank: currentRank,
        ranking_list: rankingList,
        matrix_data: matrixData, // Data này sẽ tự chia thành 2 bảng nếu logs có cả CP46 và CP67
        result_columns: resultColumns
      }
    });

  } catch (e) {
    console.error(e);
    res.render('customer-care', {
      title: 'Lỗi', currentPage: 'customer-care', user: req.session.user,
      isGlobalAdmin: false, isManager: false, branchList: [], branchStaffs: [], filters: {}, dashboard: {},
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

    const tableName = '`nimble-volt-459313-b8.sales.raw_sales_orders_all`';

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
      rows.forEach(row => { if (row.Orders) row.Orders.forEach(o => allOrderCodes.push(o.Order_code)); });

      const { data: logs } = await supabase
        .from('customer_care_logs')
        .select('order_code, result')
        .in('order_code', allOrderCodes)
        .order('created_at', { ascending: false });

      const logMap = new Map();
      (logs || []).forEach(l => { if (!logMap.has(l.order_code)) logMap.set(l.order_code, l); });

      rows.forEach(customer => {
        let caredCount = 0;
        if (customer.Orders) {
          customer.Orders = customer.Orders.map(o => {
            let d = o.Report_date;
            if (d && d.value) d = d.value;
            const log = logMap.get(o.Order_code);
            if (log) caredCount++;
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

    const rawRevenue = String(revenue || '').replace(/,/g, '');
    const cleanRevenue = parseFloat(rawRevenue) || 0;

    // 2. Validate cơ bản
    if (!order_code) return res.status(400).json({ ok: false, error: 'Thiếu mã đơn hàng' });

    const { error } = await supabase.from('customer_care_logs').insert({
      order_code,
      customer_full_name: customer_name,
      phone_number: phone,
      care_stage,
      contact_method,
      result,
      sale_note: note,
      revenue_at_care: cleanRevenue,
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
  } catch (e) {
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
  // [THÊM MỚI] Logic Năm trước
  else if (period === 'last_year') {
    startDate = new Date(now.getFullYear() - 1, 0, 1);
    endDate = new Date(now.getFullYear() - 1, 11, 31);
    label = `Năm ${now.getFullYear() - 1}`;
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


// --- [HELPER] Lấy Target Chi Nhánh từ Sheet ---
// [NÂNG CẤP] Hỗ trợ thêm tham số yearInput để lấy cột theo năm
async function getAllBranchTargets(periodInput, yearInput = null) {
  try {
    const sheets = await getGlobalSheetsClient();

    // [THAY ĐỔI 1] Mở rộng Range đọc đến cột AA để lấy đủ data 2026
    const range = 'Sheet3!A:AA';

    const response = await sheets.spreadsheets.values.get({ spreadsheetId: HR_SPREADSHEET_ID, range });
    const rows = response.data.values;
    if (!rows || rows.length === 0) return {};

    const targetMap = {};

    // [THAY ĐỔI 2] Xác định cột bắt đầu dựa vào năm
    // Mặc định năm hiện tại nếu không truyền
    const currentYear = yearInput || new Date().getFullYear();

    // Nam 2025: Bat dau tu cot D (Index 3)
    // Nam 2026: Bat dau tu cot P (Index 15)
    let startColIndex = 3;
    if (currentYear === 2026) {
      startColIndex = 15;
    }

    // Bỏ qua header, duyệt từng dòng
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      const branchCode = (row[0] || '').trim().toUpperCase();

      if (!branchCode || branchCode === 'TOTAL' || branchCode === 'GRAND TOTAL') continue;

      // Logic Headcount giữ nguyên (Cột C - Index 2)
      const headcount = parseFloat((row[2] || '1').replace(',', '.')) || 1;

      const monthlyTargets = [];
      let totalYearTarget = 0;

      // [THAY ĐỔI 3] Vòng lặp động: Quét 12 tháng từ vị trí startColIndex
      for (let m = 0; m < 12; m++) {
        const colIndex = startColIndex + m; // Ví dụ 2026: 15 + 0 = 15 (Cột P)

        const rawVal = row[colIndex] || '0';

        // Logic tính toán giữ nguyên (xử lý dấu chấm phẩy, nhân 1 tỷ)
        const val = parseFloat(rawVal.replace(/\./g, '').replace(',', '.')) * 1_000_000_000;

        monthlyTargets.push(val);
        totalYearTarget += val;
      }

      // Tính target cho periodInput (Logic cũ giữ nguyên)
      let currentPeriodTarget = 0;
      if (periodInput === 'year') {
        currentPeriodTarget = totalYearTarget;
      } else {
        const monthIndex = parseInt(periodInput) - 1;
        // Đảm bảo index nằm trong 0-11
        if (monthIndex >= 0 && monthIndex < 12) {
          currentPeriodTarget = monthlyTargets[monthIndex];
        }
      }

      targetMap[branchCode] = {
        branch_target: currentPeriodTarget,
        headcount: headcount,
        individual_target: currentPeriodTarget / headcount,

        // Mảng chi tiết cho biểu đồ (giữ nguyên logic)
        monthly_targets_arr: monthlyTargets
      };
    }

    // Programmatically add CP75 and update CP62 for year 2026
    if (currentYear === 2026 && targetMap['CP62']) {
      const cp62Orig = targetMap['CP62'];
      const origArr = cp62Orig.monthly_targets_arr || [];
      
      const origJune = origArr[5] || 0;
      const splitJune = Math.round(origJune / 2);
      
      const cp62Arr = [
        origArr[0] || 0,
        origArr[1] || 0,
        origArr[2] || 0,
        origArr[3] || 0,
        origArr[4] || 0,
        splitJune,
        0, 0, 0, 0, 0, 0
      ];
      
      const cp75Arr = [
        0, 0, 0, 0, 0,
        splitJune,
        origArr[6] || 0,
        origArr[7] || 0,
        origArr[8] || 0,
        origArr[9] || 0,
        origArr[10] || 0,
        origArr[11] || 0
      ];
      
      let cp62CurrentPeriodTarget = 0;
      if (periodInput === 'year') {
        cp62CurrentPeriodTarget = cp62Arr.reduce((a, b) => a + b, 0);
      } else {
        const monthIndex = parseInt(periodInput) - 1;
        if (monthIndex >= 0 && monthIndex < 12) cp62CurrentPeriodTarget = cp62Arr[monthIndex];
      }
      
      targetMap['CP62'] = {
        branch_target: cp62CurrentPeriodTarget,
        headcount: cp62Orig.headcount,
        individual_target: cp62CurrentPeriodTarget / cp62Orig.headcount,
        monthly_targets_arr: cp62Arr
      };

      let cp75CurrentPeriodTarget = 0;
      if (periodInput === 'year') {
        cp75CurrentPeriodTarget = cp75Arr.reduce((a, b) => a + b, 0);
      } else {
        const monthIndex = parseInt(periodInput) - 1;
        if (monthIndex >= 0 && monthIndex < 12) cp75CurrentPeriodTarget = cp75Arr[monthIndex];
      }
      
      let cp75Headcount = cp62Orig.headcount || 6;
      
      targetMap['CP75'] = {
        branch_target: cp75CurrentPeriodTarget,
        headcount: cp75Headcount,
        individual_target: cp75CurrentPeriodTarget / cp75Headcount,
        monthly_targets_arr: cp75Arr
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
            
            -- Tách doanh thu iPhone (ID: NH05-02-01-01)
            IFNULL(SUM(CASE WHEN Subcat_ID_lowest_level = 'NH05-02-01-01' THEN Revenue ELSE 0 END), 0) as iphone_revenue,

            IFNULL(SUM(Sale_point), 0) as total_kfi,
            MAX(Report_date) as max_date
        FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
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
// --- [HELPER] Tính toán Thưởng & Doanh thu quy đổi ---
function calculateBonusMetrics(stats, target, isSalesPerson) {
  const rawRevenue = stats.total_revenue || 0;
  const iphoneRevenue = stats.iphone_revenue || 0;
  const kfi = stats.total_kfi || 0;

  // [THAY ĐỔI] Công thức: iPhone tính 60% + Doanh thu khác (trừ iPhone)
  const otherRevenue = rawRevenue - iphoneRevenue;
  const calculatedRevenue = otherRevenue + (iphoneRevenue * 0.6);

  let percent = 0;
  let missing = 0;
  let bonus_total = 0;
  let bonus_over = 0;

  if (target > 0) {
    percent = (calculatedRevenue / target) * 100; // Tính % dựa trên doanh thu quy đổi
    missing = Math.max(0, target - calculatedRevenue);

    if (isSalesPerson) {
      const cappedPercent = Math.min(percent, 120) / 100;
      bonus_total = Math.round(kfi * cappedPercent * 1000);
      if (percent > 120) {
        const overAmount = calculatedRevenue - (target * 1.2);
        bonus_over = Math.round(overAmount * 0.001);
      }
    }
  }

  return {
    orders: stats.total_orders || 0,
    revenue: calculatedRevenue, // Trả về doanh thu ĐÃ QUY ĐỔI
    raw_revenue: rawRevenue,    // Trả về doanh thu THỰC (để hiển thị tooltip nếu cần)
    iphone_revenue: iphoneRevenue, // Trả về doanh thu iPhone để hiển thị
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

  // Variables for current Month
  const currentDayMonth = now.getDate();
  const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();

  // Variables for current Year
  const startOfYear = new Date(now.getFullYear(), 0, 1);
  const msInDay = 1000 * 60 * 60 * 24;
  const currentDayYear = Math.floor((now - startOfYear) / msInDay) + 1;
  const daysInYear = (now.getFullYear() % 4 === 0 && (now.getFullYear() % 100 !== 0 || now.getFullYear() % 400 === 0)) ? 366 : 365;

  let revenueForecast = 0;
  let percentForecast = 0;

  // Dự đoán nếu dùng "Tháng này" (hay 'month') và chưa hết tháng
  if (period === 'month' && currentDayMonth < daysInMonth) {
    revenueForecast = (revenue / currentDayMonth) * daysInMonth;
  }
  // Dự đoán nếu dùng "Năm nay" ('year') và năm chưa kết thúc
  else if (period === 'year' && currentDayYear < daysInYear) {
    revenueForecast = (revenue / currentDayYear) * daysInYear;
  }
  // Nếu hết tháng, hết năm, coi năm trước hoặc các khoảng cụ thể khác (today, week, v.v)
  else {
    revenueForecast = revenue; // Forecast = Thực tế
  }

  if (target > 0) {
    percentForecast = (revenueForecast / target) * 100;
  }

  return {
    revenue_forecast: revenueForecast,
    percent_forecast: percentForecast.toFixed(1)
  };
}

// --- [HELPER MỚI] Lấy dữ liệu biểu đồ cho Staff ---
async function getStaffMonthlyChart(email, branchCode) {
  // [FIX] Lấy từ Supabase salesman_performance thay vì BigQuery (đã có sẵn data)
  try {
    const currentYear = new Date().getFullYear();
    const { data: rows, error } = await supabase
      .from('salesman_performance')
      .select('month, revenue, iphone_revenue, orders, kfi')
      .eq('email', email.toLowerCase().trim())
      .ilike('month', `${currentYear}-%`)
      .order('month', { ascending: true });
    if (error) throw error;

    // Lấy target của năm để tính target từng tháng
    let hcTargets = {};
    let headcount = 1;
    try {
      hcTargets = await getAllBranchTargets('year', currentYear);
      if (hcTargets && hcTargets[branchCode] && hcTargets[branchCode].headcount) {
        headcount = hcTargets[branchCode].headcount;
      } else {
        const { count: branchStaffCount } = await supabase
          .from('users')
          .select('*', { count: 'exact', head: true })
          .eq('branch_code', branchCode)
          .eq('role', 'staff');
        if (branchStaffCount > 0) headcount = branchStaffCount;
      }
    } catch (e) { }

    return (rows || []).map(r => {
      const iphone = r.iphone_revenue || 0;
      const raw = r.revenue || 0;
      const calculated_revenue = (raw - iphone) + (iphone * 0.6);

      let target = 0;
      const mIndex = parseInt(r.month.split('-')[1], 10) - 1;

      if (branchCode === 'CP75' && currentYear === 2026) {
        if (mIndex < 5) {
          // Jan-May: use CP62 target and headcount
          const cp62Hc = (hcTargets && hcTargets['CP62']) ? (hcTargets['CP62'].headcount || 6) : 6;
          if (hcTargets && hcTargets['CP62'] && hcTargets['CP62'].monthly_targets_arr) {
            target = (hcTargets['CP62'].monthly_targets_arr[mIndex] || 0) / cp62Hc;
          }
        } else if (mIndex === 5) {
          // June: combined target (CP62 + CP75) divided by CP75 headcount
          let target62 = 0;
          let target75 = 0;
          if (hcTargets && hcTargets['CP62'] && hcTargets['CP62'].monthly_targets_arr) {
            target62 = hcTargets['CP62'].monthly_targets_arr[mIndex] || 0;
          }
          if (hcTargets && hcTargets['CP75'] && hcTargets['CP75'].monthly_targets_arr) {
            target75 = hcTargets['CP75'].monthly_targets_arr[mIndex] || 0;
          }
          target = (target62 + target75) / headcount;
        } else {
          // Jul-Dec: use CP75 target
          if (hcTargets && hcTargets['CP75'] && hcTargets['CP75'].monthly_targets_arr) {
            target = (hcTargets['CP75'].monthly_targets_arr[mIndex] || 0) / headcount;
          }
        }
      } else {
        if (hcTargets && hcTargets[branchCode] && hcTargets[branchCode].monthly_targets_arr) {
          target = (hcTargets[branchCode].monthly_targets_arr[mIndex] || 0) / headcount;
        }
      }

      let percent = 0;
      if (target > 0) {
        percent = parseFloat(((calculated_revenue / target) * 100).toFixed(1));
      }

      return {
        month_str: r.month,
        calculated_revenue: calculated_revenue,
        target: target,
        percent: percent,
        orders: r.orders || 0,
        kfi: r.kfi || 0
      };
    });
  } catch (e) {
    console.error('Chart Error:', e.message);
    return [];
  }
}


// --- [ROUTE] PAGE PROFILE (FINAL) ---
app.get('/profile', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    const periodValue = req.query.period || 'month';
    const filterBranch = req.query.branch || '';
    const isGlobalAdmin = user.role === 'admin' || user.branch_code === 'HCM.BD';
    const isManager = user.role === 'manager';
    const isStaff = !isGlobalAdmin && !isManager;

    // Date Condition
    const now = new Date();
    let targetMonthStr = '';

    if (periodValue === 'month' || periodValue === 'today' || periodValue === 'week') {
      const y = now.getFullYear();
      const m = (now.getMonth() + 1).toString().padStart(2, '0');
      targetMonthStr = `${y}-${m}`;
    } else if (/^\d{4}-\d{2}$/.test(periodValue)) {
      targetMonthStr = periodValue;
    } else if (periodValue === 'year' || periodValue === 'last_year') {
      const baseYear = periodValue === 'last_year' ? now.getFullYear() - 1 : now.getFullYear();
      targetMonthStr = `${baseYear}-`;
    }

    // Branch visibility filter
    let qBranch = null;
    if (isStaff) {
      // none, handles below
    } else if (!isGlobalAdmin) {
      qBranch = user.branch_code;
    } else if (filterBranch) {
      qBranch = filterBranch;
    }

    // [FIX] Normalize email về lowercase để tránh lệch case (VD: Hong.lx vs hong.lx)
    const userEmail = (user.email || '').toLowerCase().trim();

    const { getLocalSalesRows } = require('./local_sales_query');
    let salesRows = [];

    if (periodValue === 'today' || periodValue === 'week') {
      const targetEmail = isStaff ? userEmail : null;
      salesRows = await getLocalSalesRows(periodValue, targetEmail, qBranch);
    } else if (targetMonthStr.endsWith('-')) {
      // yearly — targetMonthStr format: "2025-" => ilike "2025-%"
      const yearPrefix = targetMonthStr.replace(/-$/, ''); // "2025"
      let q = supabase.from('salesman_performance').select('*').ilike('month', `${yearPrefix}-%`);
      if (qBranch) {
        if (qBranch === 'CP75' && yearPrefix === '2026') {
          q = q.in('branch_code', ['CP62', 'CP75']);
        } else {
          q = q.eq('branch_code', qBranch);
        }
      } else if (isStaff) {
        q = q.eq('email', userEmail);
      }
      const { data } = await q;
      salesRows = data || [];
    } else {
      // monthly
      let q = supabase.from('salesman_performance').select('*').eq('month', targetMonthStr);
      if (qBranch) {
        if (qBranch === 'CP75' && targetMonthStr === '2026-06') {
          q = q.in('branch_code', ['CP62', 'CP75']);
        } else if (qBranch === 'CP75' && /^2026-0[1-5]$/.test(targetMonthStr)) {
          q = q.eq('branch_code', 'CP62');
        } else {
          q = q.eq('branch_code', qBranch);
        }
      } else if (isStaff) {
        q = q.eq('email', userEmail);
      }
      const { data } = await q;
      salesRows = data || [];
    }



    const { data: fullUser } = await supabase.from('users').select('*').eq('id', user.id).maybeSingle();
    let myProfile = {
      ...(fullUser || user),
      branch: (fullUser || user)?.branch_code || '-',
      position: (fullUser || user)?.role || '-',
      hrm_id: '-',
      dob: '-',
      join_date: '-',
      rank: '-', total_revenue: 0,
      total_orders: 0, results_summary: 'Chưa có data'
    };

    // Enrich profile from HR Google Sheet
    try {
      const hrSheets = await getGlobalSheetsClient();
      const hrRes = await hrSheets.spreadsheets.values.get({
        spreadsheetId: HR_SPREADSHEET_ID, range: 'A2:J'
      });
      const hrRows = hrRes.data.values || [];
      const hrMatch = hrRows.find(r => (r[1] || '').toLowerCase().trim() === userEmail);
      if (hrMatch) {
        myProfile.hrm_id = hrMatch[0] || '-';
        myProfile.position = hrMatch[7] || myProfile.position;  // Position col
        myProfile.branch = hrMatch[3] || myProfile.branch;       // branch_id col
        myProfile.dob = hrMatch[8] || '-';                       // Birthday col
        myProfile.join_date = hrMatch[9] || '-';                  // Firts_day col
      }
    } catch (hrErr) {
      console.error('HR enrichment error:', hrErr.message);
    }

    let lastSeen = 'Trống';
    if (isStaff && salesRows.length > 0) {
      const sumRev = salesRows.reduce((a, b) => a + (b.revenue || 0), 0);
      const sumOrders = salesRows.reduce((a, b) => a + (b.orders || 0), 0);
      // [FIX] KFI = tổng Sale_point (sum của kfi field trong từng tháng)
      const sumKfi = salesRows.reduce((a, b) => a + (b.kfi || 0), 0);
      myProfile.total_revenue = sumRev;
      myProfile.total_orders = sumOrders;
      myProfile.total_kfi = sumKfi;
      if (!myProfile.hrm_id || myProfile.hrm_id === '-') {
        myProfile.hrm_id = salesRows[0].hrm_id || '-';
      }

      const userLogs = await supabase.from('customer_care_logs').select('created_at').eq('staff_id', user.id).order('created_at', { ascending: false }).limit(1);
      if (userLogs.data && userLogs.data.length > 0) {
        const d = new Date(userLogs.data[0].created_at);
        lastSeen = d.toLocaleString('vi-VN');
      }
    }

    // Targets
    const monthCol = targetMonthStr.endsWith('-') ? null : 'm' + targetMonthStr.split('-')[1];
    // Xác định năm cần lấy target
    const targetYear = targetMonthStr.endsWith('-')
      ? parseInt(targetMonthStr.replace(/-$/, ''), 10)
      : parseInt(targetMonthStr.split('-')[0], 10);
    let dashboard = { revenue: 0, raw_revenue: 0, iphone_revenue: 0, revenue_forecast: 0, orders: 0, kfi: 0, target: 0, percent_completion: '0.0', missing: 0 };

    salesRows.forEach(r => {
      const iphone = r.iphone_revenue || 0;
      const raw = r.revenue || 0;
      dashboard.raw_revenue += raw;
      dashboard.iphone_revenue += iphone;
      dashboard.revenue += (raw - iphone + (iphone * 0.6));
      dashboard.orders += (r.orders || 0);
      dashboard.kfi += (r.kfi || 0);
    });

    // [FIX] Filter theo year để tránh cộng target 2 năm khi bảng có nhiều năm
    let targetQuery = supabase.from('pv_terminal_monthly_targets').select('*').eq('year', targetYear);
    const targetBranchCode = qBranch || (isStaff ? myProfile.branch : null);
    if (targetBranchCode) {
      if (targetBranchCode === 'CP75' && targetYear === 2026) {
        if (targetMonthStr === '2026-06' || targetMonthStr === '2026-') {
          targetQuery = targetQuery.in('terminal_code', ['CP62', 'CP75']);
        } else if (/^2026-0[1-5]$/.test(targetMonthStr)) {
          targetQuery = targetQuery.eq('terminal_code', 'CP62');
        } else {
          targetQuery = targetQuery.eq('terminal_code', 'CP75');
        }
      } else {
        targetQuery = targetQuery.eq('terminal_code', targetBranchCode);
      }
    }

    const { data: targetRows } = await targetQuery;

    let targetRatio = 1;
    if (periodValue === 'today') {
      const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
      targetRatio = 1 / daysInMonth;
    } else if (periodValue === 'week') {
      const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
      targetRatio = 7 / daysInMonth;
    }

    if (monthCol) {
      dashboard.target = (targetRows || []).reduce((sum, r) => sum + Number(r[monthCol] || 0), 0) * 1000000 * targetRatio;
    } else {
      dashboard.target = (targetRows || []).reduce((sum, r) => {
        let ySum = 0;
        for (let i = 1; i <= 12; i++) {
          const mc = 'm' + i.toString().padStart(2, '0');
          ySum += Number(r[mc] || 0);
        }
        return sum + ySum;
      }, 0) * 1000000 * targetRatio;
    }

    // [FIX] Nếu là staff, chia target của chi nhánh cho định biên (số lượng sale)
    if (isStaff && dashboard.target > 0) {
      let headcount = 1;
      try {
        let hcTargets = {};
        if (!targetMonthStr.endsWith('-')) {
          const monthParts = targetMonthStr.split('-');
          hcTargets = await getAllBranchTargets(parseInt(monthParts[1], 10), parseInt(monthParts[0], 10));
        } else {
          const yearPrefix = targetMonthStr.replace(/-$/, '');
          hcTargets = await getAllBranchTargets('year', parseInt(yearPrefix, 10));
        }
        let targetBranchForHeadcount = myProfile.branch;
        if (myProfile.branch === 'CP75' && targetYear === 2026) {
          if (/^2026-0[1-5]$/.test(targetMonthStr)) {
            targetBranchForHeadcount = 'CP62';
          }
        }
        if (hcTargets && hcTargets[targetBranchForHeadcount] && hcTargets[targetBranchForHeadcount].headcount) {
          headcount = hcTargets[targetBranchForHeadcount].headcount;
        } else {
          // Fallback: đếm số lượng nhân viên thực tế có role = staff trong chi nhánh
          const { count: branchStaffCount } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true })
            .eq('branch_code', targetBranchForHeadcount)
            .eq('role', 'staff');
          if (branchStaffCount > 0) headcount = branchStaffCount;
        }
      } catch (e) {
        console.error("Lỗi lấy định biên cho staff:", e.message);
      }
      dashboard.target = dashboard.target / headcount;
    }

    if (dashboard.target > 0) {
      dashboard.percent_completion = ((dashboard.revenue / dashboard.target) * 100).toFixed(1);
      dashboard.missing = Math.max(0, dashboard.target - dashboard.revenue);
      if (isStaff) {
        const statsD = { total_revenue: dashboard.revenue, iphone_revenue: salesRows.reduce((s, r) => s + (r.iphone_revenue || 0), 0), total_kfi: dashboard.kfi };
        const bMetrics = calculateBonusMetrics(statsD, dashboard.target, true);
        dashboard.bonus_total = bMetrics.bonus_total;
        dashboard.bonus_over = bMetrics.bonus_over;
      }
    }

    const dayOfMonth = now.getDate();
    const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
    if (periodValue === 'month' && dayOfMonth > 0) {
      dashboard.revenue_forecast = Math.round((dashboard.revenue / dayOfMonth) * daysInMonth);
      if (dashboard.target > 0) dashboard.percent_forecast = ((dashboard.revenue_forecast / dashboard.target) * 100).toFixed(1);
    }

    const allTargetRows = (await supabase.from('pv_terminal_monthly_targets').select('*')).data || [];
    const targetMap = {};
    const branchDedup = new Map(); // Dùng Map để loại bỏ trùng lặp branch
    allTargetRows.forEach(r => {
      if (monthCol) {
        targetMap[r.terminal_code] = Number(r[monthCol] || 0) * 1000000 * targetRatio;
      } else {
        // Yearly target: sum of all 12 months
        let ySum = 0;
        for (let i = 1; i <= 12; i++) {
          const mc = 'm' + i.toString().padStart(2, '0');
          ySum += Number(r[mc] || 0);
        }
        targetMap[r.terminal_code] = ySum * 1000000 * targetRatio;
      }
      // Chỉ thêm mỗi terminal_code 1 lần vào danh sách chi nhánh
      if (!branchDedup.has(r.terminal_code)) {
        let brName = 'Chi Nhánh ' + r.terminal_code;
        for (const [name, code] of Object.entries(TERMINAL_CODE_MAP)) {
          if (code === r.terminal_code) {
            brName = name.split(',')[0].trim();
            break;
          }
        }
        branchDedup.set(r.terminal_code, { id: r.terminal_code, name: brName });
      }
    });
    const globalBranchList = Array.from(branchDedup.values());

    let tableSales = [];
    let tableBranch = [];

    if (!isStaff) {
      let hcTargets = {};
      if (!targetMonthStr.endsWith('-')) {
        const monthParts = targetMonthStr.split('-');
        hcTargets = await getAllBranchTargets(parseInt(monthParts[1], 10), parseInt(monthParts[0], 10));
      } else {
        const yearPrefix = targetMonthStr.replace(/-$/, '');
        hcTargets = await getAllBranchTargets('year', parseInt(yearPrefix, 10));
      }

      // Group salesRows by email to combine salesperson performance (e.g. CP62 and CP75 sales in June 2026)
      const groupedSales = {};
      (salesRows || []).forEach(r => {
        const email = (r.email || '').toLowerCase().trim();
        if (!email) return;
        if (!groupedSales[email]) {
          groupedSales[email] = {
            ...r,
            revenue: 0,
            iphone_revenue: 0,
            orders: 0,
            kfi: 0
          };
        }
        groupedSales[email].revenue += (r.revenue || 0);
        groupedSales[email].iphone_revenue += (r.iphone_revenue || 0);
        groupedSales[email].orders += (r.orders || 0);
        groupedSales[email].kfi += (r.kfi || 0);
      });

      // Fetch users table to exclude manager/admin and showroom accounts from salesman leaderboard tableSales
      const allGroupedEmails = Object.keys(groupedSales);
      let nonStaffEmailSet = new Set();
      if (allGroupedEmails.length > 0) {
        const { data: nonStaffUsers } = await supabase
          .from('users')
          .select('email, role')
          .in('email', allGroupedEmails)
          .in('role', ['manager', 'admin']);
        nonStaffEmailSet = new Set((nonStaffUsers || []).map(u => (u.email || '').toLowerCase().trim()));
      }

      tableSales = Object.values(groupedSales)
        .filter(r => {
          const em = (r.email || '').toLowerCase().trim();
          return !em.startsWith('sr.') && !em.startsWith('showroom') && !nonStaffEmailSet.has(em);
        })
        .map(r => {
        const salesmanBranch = r.branch_code;
        const branchTarget = targetMap[salesmanBranch] || 0;
        let indTarget = 0;

        if ((salesmanBranch === 'CP62' || salesmanBranch === 'CP75') && targetYear === 2026) {
          if (targetMonthStr === '2026-06') {
            const target62 = (targetMap['CP62'] || 0);
            const target75 = (targetMap['CP75'] || 0);
            const cp62Hc = (hcTargets && hcTargets['CP62']) ? (hcTargets['CP62'].headcount || 6) : 6;
            const headcount = (hcTargets && hcTargets['CP75']) ? (hcTargets['CP75'].headcount || cp62Hc) : cp62Hc;
            indTarget = (target62 + target75) / headcount;
          } else if (/^2026-0[1-5]$/.test(targetMonthStr)) {
            const target62 = (targetMap['CP62'] || 0);
            const headcount = (hcTargets && hcTargets['CP62']) ? (hcTargets['CP62'].headcount || 6) : 6;
            indTarget = target62 / headcount;
          } else if (targetMonthStr.endsWith('-')) {
            // Yearly 2026 combined targets for CP62/CP75 staff
            let yIndSum = 0;
            const cp62Hc = (hcTargets && hcTargets['CP62']) ? (hcTargets['CP62'].headcount || 6) : 6;
            const cp75Hc = (hcTargets && hcTargets['CP75']) ? (hcTargets['CP75'].headcount || cp62Hc) : cp62Hc;
            const cp62TargetsArr = (hcTargets && hcTargets['CP62']) ? (hcTargets['CP62'].monthly_targets_arr || []) : [];
            const cp75TargetsArr = (hcTargets && hcTargets['CP75']) ? (hcTargets['CP75'].monthly_targets_arr || []) : [];
            
            for (let m = 0; m < 12; m++) {
              if (m < 5) {
                yIndSum += (cp62TargetsArr[m] || 0) / cp62Hc;
              } else if (m === 5) {
                yIndSum += ((cp62TargetsArr[m] || 0) + (cp75TargetsArr[m] || 0)) / cp75Hc;
              } else {
                yIndSum += (cp75TargetsArr[m] || 0) / cp75Hc;
              }
            }
            indTarget = yIndSum;
          } else {
            // T7-T12 monthly
            const target75 = (targetMap['CP75'] || 0);
            const cp62Hc = (hcTargets && hcTargets['CP62']) ? (hcTargets['CP62'].headcount || 6) : 6;
            const headcount = (hcTargets && hcTargets['CP75']) ? (hcTargets['CP75'].headcount || cp62Hc) : cp62Hc;
            indTarget = target75 / headcount;
          }
        } else {
          // Normal branch target calculation
          if (hcTargets && hcTargets[salesmanBranch]) {
            const headcount = hcTargets[salesmanBranch].headcount || 1;
            indTarget = branchTarget / headcount;
          } else {
            const branchStaffCount = (salesRows || []).filter(s => s.branch_code === salesmanBranch).length || 1;
            indTarget = branchTarget / branchStaffCount;
          }
        }

        const smIphone = r.iphone_revenue || 0;
        const smRevenue = (r.revenue || 0) - smIphone + (smIphone * 0.6);
        const pctObj = indTarget > 0 ? (smRevenue / indTarget) * 100 : 0;
        const pct = pctObj !== 0 ? pctObj.toFixed(1) : '0.0';

        let bonus_total = 0; let bonus_over = 0;
        if (indTarget > 0) {
          const numPct = parseFloat(pct);
          const cappedPct = Math.min(numPct, 120) / 100;
          const kfi = r.kfi || 0;
          bonus_total = Math.round(kfi * cappedPct * 1000);
          if (numPct > 120) bonus_over = Math.round((smRevenue - indTarget * 1.2) * 0.001);
        }
        return {
          salesman: r.full_name || r.email, msnv: r.hrm_id || '',
          branch: r.branch_code, email: r.email,
          revenue: smRevenue, iphone_revenue: smIphone,
          target: indTarget, percent_completion: pct,
          missing: Math.max(0, indTarget - smRevenue),
          kfi: r.kfi || 0, bonus_total, bonus_over
        };
      }).sort((a, b) => parseFloat(b.percent_completion || 0) - parseFloat(a.percent_completion || 0));

      const branchMap = {};
      salesRows.forEach(r => {
        if (!branchMap[r.branch_code]) branchMap[r.branch_code] = { branch: r.branch_code, revenue: 0, iphone_revenue: 0, orders: 0, kfi: 0 };
        branchMap[r.branch_code].revenue += (r.revenue || 0);
        branchMap[r.branch_code].iphone_revenue += (r.iphone_revenue || 0);
        branchMap[r.branch_code].orders += (r.orders || 0);
        branchMap[r.branch_code].kfi += (r.kfi || 0);
      });

      tableBranch = Object.values(branchMap).map(b => {
        const bt = targetMap[b.branch] || 0;
        const bIphone = b.iphone_revenue || 0;
        const bRevenue = (b.revenue - bIphone) + (bIphone * 0.6);
        const pctObj = bt > 0 ? (bRevenue / bt) * 100 : 0;
        const pct = pctObj !== 0 ? pctObj.toFixed(1) : '0.0';
        const forecast = dayOfMonth > 0 ? Math.round((bRevenue / dayOfMonth) * daysInMonth) : 0;
        const pfObj = bt > 0 ? (forecast / bt) * 100 : 0;
        const pf = pfObj !== 0 ? pfObj.toFixed(1) : '0.0';
        return { ...b, revenue: bRevenue, iphone_revenue: bIphone, target: bt, percent_completion: pct, missing: Math.max(0, bt - bRevenue), revenue_forecast: forecast, percent_forecast: pf };
      }).sort((a, b) => parseFloat(b.percent_completion || 0) - parseFloat(a.percent_completion || 0));

      // Fetch %CSI cho từng nhân viên trong bảng xếp hạng (batch, 1 lần fetch cache)
      try {
        const staffForCsi = tableSales.map(r => ({ email: r.email, full_name: r.salesman }));
        const csiPerStaffMap = await getCsiPerStaff(staffForCsi, targetMonthStr);
        tableSales = tableSales.map(r => ({
          ...r,
          csi_percent: csiPerStaffMap[(r.email || '').toLowerCase().trim()] ?? null
        }));
      } catch (csiErr) {
        console.error('[CSI/Leaderboard] Error fetching per-staff CSI:', csiErr.message);
      }
    }

    let displayDate = targetMonthStr;
    if (!targetMonthStr.endsWith('-')) {
      const [yStr, mStr] = targetMonthStr.split('-');
      const maxD = new Date(parseInt(yStr, 10), parseInt(mStr, 10), 0).getDate();
      const { data: latestKp } = await supabase
        .from('daily_kpi_summaries')
        .select('report_date')
        .gte('report_date', `${targetMonthStr}-01`)
        .lte('report_date', `${targetMonthStr}-${maxD}`)
        .order('report_date', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (latestKp && latestKp.report_date) displayDate = latestKp.report_date;
    }

    let csiParams = { period: targetMonthStr };
    if (isStaff) {
      csiParams.email = userEmail;  // [FIX] CSI filter by email (lowercase) for staff
      // Fallback: staff name for CSI matching if email column not available
      csiParams._staffName = myProfile.full_name || user.full_name || '';
      csiParams.branch = myProfile.branch; // [FIX] Gán branch code chuẩn của staff từ DB để lọc CSI
    } else if (qBranch) csiParams.branch = qBranch;

    let csiData = { csi_percent: 0, feedback_count: 0, unavailable: false };
    let feedbackList = [];
    try {
      const [csi, fbList] = await Promise.all([getCsiStats(csiParams), getFeedbackList(csiParams)]);
      csiData = csi; feedbackList = fbList;
    } catch (csiErr) {
      csiData = { unavailable: true, quotaExceeded: false };
    }

    // [FIX] Biểu đồ 12 tháng cho Staff
    let staffChartData = [];
    if (isStaff) {
      staffChartData = await getStaffMonthlyChart(userEmail, myProfile.branch);
    }
    const noSalesData = isStaff && salesRows.length === 0;

    res.render('profile', {
      title: 'Dashboard Hiệu Suất', currentPage: 'profile', user,
      role: { isStaff, isManager, isGlobalAdmin },
      period: { value: periodValue, label: periodValue },
      filterBranch,
      branchList: globalBranchList.sort(),
      profile: myProfile,
      onlineTime: lastSeen,
      staffChartData,
      dashboard, tableSales, tableBranch,
      noSalesData,
      formatCompact: (num) => {
        if (!num) return '0';
        const n = Number(num);
        if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(2).replace(/\.00$/, '') + ' Tỷ';
        if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\\.0$/, '') + ' Tr ₫';
        if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\\.0$/, '') + ' K ₫';
        return new Intl.NumberFormat('vi-VN').format(n);
      },
      dataDate: displayDate,
      csiData, feedbackList
    });

  } catch (e) {
    console.error("Profile Error:", e);
    res.status(500).render('profile', { error: 'Có lỗi xảy ra: ' + e.message, profile: req.session.user });
  }
});

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
// Endpoint /api/cron/sync-clearance đã được gộp vào /api/cron/sync-all để tiết kiệm Slot Cron Vercel Hobby

app.get('/api/admin/search-sku-stock', requireAuth, async (req, res) => {
  try {
    const skuQuery = (req.query.q || '').trim();
    if (!skuQuery) return res.json({ ok: true, results: [] });

    // 1. Tìm thông tin sản phẩm trong Supabase
    const { data: products, error } = await supabase
      .from('skus')
      .select('sku, product_name, list_price')
      .or(`sku.ilike.%${skuQuery}%,product_name.ilike.%${skuQuery}%`)
      .limit(10); // Lấy 10 kết quả

    if (error) throw error;
    if (!products || products.length === 0) return res.json({ ok: true, results: [] });

    // 2. Chuẩn bị tham số lấy tồn kho
    const skuList = products.map(p => p.sku);
    const userBranch = req.session.user?.branch_code;
    // Nếu là Admin hoặc HCM.BD thì coi là Global Admin (lấy tồn all chi nhánh)
    const isGlobalAdmin = (req.session.user?.role === 'admin' || userBranch === 'HCM.BD');
    const today = new Date().toISOString().split('T')[0];

    // 3. Gọi hàm lấy tồn kho CHUẨN (đã có trong server.js)
    let inventoryMap = new Map();
    try {
      if (bigquery) {
        inventoryMap = await getInventoryCounts(skuList, userBranch, isGlobalAdmin, today);
      }
    } catch (bqError) {
      console.warn("Lỗi BigQuery:", bqError.message);
    }

    // 4. Ghép dữ liệu & Tính tổng tồn
    const results = products.map(p => {
      let totalStock = 0;
      const branchMap = inventoryMap.get(p.sku);

      if (branchMap) {
        // Duyệt qua tất cả chi nhánh trả về để cộng dồn
        branchMap.forEach((counts) => {
          // Chỉ tính hàng bán được: Bán mới + Trưng bày chỉ định
          totalStock += (counts.hang_ban_moi || 0) + (counts.trung_bay_chi_dinh || 0);
        });
      }

      return {
        sku: p.sku,
        product_name: p.product_name,
        list_price: p.list_price,
        stock: totalStock
      };
    });

    // Sắp xếp: Ưu tiên khớp chính xác SKU -> Tồn nhiều
    results.sort((a, b) => {
      if (a.sku === skuQuery) return -1;
      if (b.sku === skuQuery) return 1;
      return b.stock - a.stock;
    });

    res.json({ ok: true, results });

  } catch (e) {
    console.error('Lỗi API /api/admin/search-sku-stock:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// API: Lấy chi tiết danh sách đơn hàng từ Matrix (Popup)
// --- API LẤY CHI TIẾT MATRIX (Đã Fix quyền cho Regional Manager) ---
app.get('/api/cskh/matrix-detail', requireAuth, async (req, res) => {
  try {
    const { userId, resultType, start, end, branch } = req.query;
    const currentUser = req.session.user;

    // ============================================================
    // 1. PHÂN QUYỀN (FIX LỖI: Hỗ trợ Regional Manager xem branch con)
    // ============================================================

    const isGlobalAdmin = currentUser.branch_code === 'HCM.BD';
    // Lấy danh sách các chi nhánh được phép (VD: TD12 -> ['CP46', 'CP67'])
    const allowedBranches = getAllowedBranches(currentUser);

    let hasAccess = false;

    if (currentUser.role === 'staff') {
      // Staff: Chỉ được xem của chính mình
      if (currentUser.id === userId) hasAccess = true;
    }
    else if (isGlobalAdmin) {
      // Admin: Xem tất cả
      hasAccess = true;
    }
    else if (currentUser.role === 'manager' || currentUser.role === 'admin') {
      // Manager/Regional Check
      if (allowedBranches) {
        // Nếu là Regional (TD12), check xem branch đang xem (CP46) có nằm trong list cho phép không
        if (allowedBranches.includes(branch)) {
          hasAccess = true;
        }
      }

      // Trường hợp fallback: Xem chính branch của mình
      if (currentUser.branch_code === branch) {
        hasAccess = true;
      }
    }

    if (!hasAccess) {
      console.log(`[Access Denied] User: ${currentUser.branch_code}, Target: ${branch}`);
      return res.status(403).json({ ok: false, error: 'Không có quyền truy cập branch này.' });
    }

    // ============================================================
    // 2. LOGIC LẤY DỮ LIỆU (Giữ nguyên code của bạn)
    // ============================================================

    // Lọc theo khoảng thời gian thực tế từ Dashboard
    const startObj = new Date(start || new Date().toISOString().split('T')[0]);
    const startOfMonth = startObj.toISOString();

    let endOfMonth;
    if (end) {
      const dEnd = new Date(end);
      dEnd.setHours(23, 59, 59, 999);
      endOfMonth = dEnd.toISOString();
    } else {
      const dEnd = new Date();
      dEnd.setHours(23, 59, 59, 999);
      endOfMonth = dEnd.toISOString();
    }

    let logQuery = supabase
      .from('customer_care_logs')
      .select(`
                order_code, result, revenue_at_care, created_at, 
                phone_number,
                sale_note,
                users:created_by (full_name, branch_code)
            `)
      .eq('created_by', userId)
      .gte('created_at', startOfMonth)
      .lte('created_at', endOfMonth);

    if (resultType) {
      logQuery = logQuery.eq('result', resultType);
    }

    const { data: logs, error: logError } = await logQuery;
    if (logError) throw logError;

    if (!logs || logs.length === 0) {
      return res.json({ ok: true, data: [] });
    }

    const orderCodes = logs.map(l => l.order_code);

    // 3. Lấy thông tin chi tiết (MST, Tên KH) từ BigQuery
    if (!bigquery) {
      // Fallback nếu không có BQ
      return res.json({
        ok: true, data: logs.map((l, idx) => ({
          stt: idx + 1,
          branch: l.users?.branch_code,
          salesman: l.users?.full_name,
          order_code: l.order_code,
          customer_name: 'N/A (No BQ)',
          phone: l.phone_number || 'N/A',
          tax_code: '',
          revenue: l.revenue_at_care,
          note: l.sale_note
        }))
      });
    }

    // Query BigQuery để lấy tên khách chuẩn và MST
    const bqQuery = `
            SELECT 
                Order_code, 
                MAX(Customer_full_name) as Customer_Name,
                MAX(Billing_tax_code) as Tax_Code,
                MAX(Branch_code) as Branch
            FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
            WHERE Order_code IN UNNEST(@codes)
            GROUP BY 1
        `;

    const [bqRows] = await bigquery.query({
      query: bqQuery,
      params: { codes: orderCodes }
    });

    const bqMap = new Map();
    bqRows.forEach(r => bqMap.set(r.Order_code, r));

    // 4. Ghép dữ liệu trả về
    const finalData = logs.map((log, index) => {
      const bqInfo = bqMap.get(log.order_code) || {};
      return {
        stt: index + 1,
        branch: log.users?.branch_code || bqInfo.Branch || '',
        salesman: log.users?.full_name || '',
        order_code: log.order_code,
        customer_name: bqInfo.Customer_Name || 'Khách lẻ',
        phone: log.phone_number || '', // Ưu tiên lấy SĐT nhân viên nhập lúc care
        tax_code: bqInfo.Tax_Code || '',
        note: log.sale_note || '',
        revenue: log.revenue_at_care
      };
    });

    res.json({ ok: true, data: finalData });

  } catch (e) {
    console.error("Matrix Detail Error:", e);
    res.status(500).json({ ok: false, error: e.message });
  }
});


// --- CẤU HÌNH GỬI MAIL ---
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// --- ROUTE QUÊN MẬT KHẨU ---

// 1. Hiển thị form nhập email
app.get('/forgot-password', (req, res) => {
  // Tận dụng header/footer cũ
  res.render('forgot-password', {
    title: 'Quên mật khẩu',
    currentPage: 'login',
    error: null,
    success: null,
    time: ''
  });
});

// 2. Xử lý gửi mail
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    // Kiểm tra email
    const { data: user } = await supabase
      .from('users')
      .select('id, email')
      .eq('email', email)
      .single();

    // Bảo mật: Nếu email không tồn tại, vẫn báo thành công để tránh hacker dò email
    if (!user) {
      return res.render('forgot-password', {
        title: 'Quên mật khẩu', currentPage: 'login', time: '',
        error: null,
        success: 'Nếu email tồn tại, link khôi phục đã được gửi. Vui lòng kiểm tra hộp thư (cả mục Spam).'
      });
    }

    // Tạo token ngẫu nhiên & Hạn dùng 1 tiếng
    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 3600000); // +1 giờ

    // Lưu vào DB
    await supabase
      .from('users')
      .update({ reset_token: token, reset_token_expiry: expiry })
      .eq('id', user.id);

    // Tạo link (Tự động nhận diện localhost hay vercel)
    const resetLink = `${req.protocol}://${req.get('host')}/reset-password?token=${token}`;

    // Gửi mail
    await transporter.sendMail({
      from: '"Phong Vu System" <no-reply@phongvu.vn>',
      to: email,
      subject: 'Yêu cầu đặt lại mật khẩu',
      html: `
                <h3>Yêu cầu đặt lại mật khẩu</h3>
                <p>Bạn (hoặc ai đó) đã yêu cầu lấy lại mật khẩu cho tài khoản: <b>${email}</b></p>
                <p>Vui lòng bấm vào link dưới đây để đặt mật khẩu mới (Link hết hạn sau 1 giờ):</p>
                <a href="${resetLink}" style="background:#0d6efd; color:white; padding:10px 20px; text-decoration:none; border-radius:5px;">Đặt lại mật khẩu</a>
                <p>Nếu bạn không yêu cầu, vui lòng bỏ qua email này.</p>
            `
    });

    res.render('forgot-password', {
      title: 'Quên mật khẩu', currentPage: 'login', time: '',
      error: null,
      success: 'Đã gửi link khôi phục. Vui lòng kiểm tra email!'
    });

  } catch (err) {
    console.error("Mail Error:", err);
    res.render('forgot-password', {
      title: 'Quên mật khẩu', currentPage: 'login', time: '',
      error: 'Lỗi khi gửi mail. Vui lòng thử lại sau.',
      success: null
    });
  }
});

// 3. Link từ Email bấm vào -> Hiện form đổi pass
app.get('/reset-password', async (req, res) => {
  const { token } = req.query;

  // Check token hợp lệ & còn hạn
  const { data: user } = await supabase
    .from('users')
    .select('id')
    .eq('reset_token', token)
    .gt('reset_token_expiry', new Date().toISOString()) // Expiry > Thời gian hiện tại
    .single();

  if (!user) {
    return res.render('login', {
      title: 'Đăng nhập', currentPage: 'login', time: '',
      error: 'Link không hợp lệ hoặc đã hết hạn. Vui lòng thử lại.'
    });
  }

  res.render('reset-password', {
    title: 'Đặt lại mật khẩu', currentPage: 'login', time: '',
    token, error: null
  });
});

// 4. Xử lý đổi pass mới
app.post('/reset-password', async (req, res) => {
  const { token, password, confirm_password } = req.body;

  if (password !== confirm_password) {
    return res.render('reset-password', {
      title: 'Đặt lại mật khẩu', currentPage: 'login', time: '',
      token, error: 'Mật khẩu nhập lại không khớp!'
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update pass & Xóa token
    const { error } = await supabase
      .from('users')
      .update({
        password_hash: hashedPassword,
        reset_token: null,
        reset_token_expiry: null
      })
      .eq('reset_token', token)
      .gt('reset_token_expiry', new Date().toISOString());

    if (error) throw error;

    // Render trang login với thông báo thành công
    res.render('login', {
      title: 'Đăng nhập', currentPage: 'login', time: '',
      error: null, // Không có lỗi
      successMessage: 'Đổi mật khẩu thành công! Hãy đăng nhập ngay.' // Cần sửa login.ejs để hiện cái này
    });

  } catch (err) {
    console.error(err);
    res.render('reset-password', {
      title: 'Đặt lại mật khẩu', currentPage: 'login', time: '',
      token, error: 'Lỗi hệ thống. Vui lòng thử lại.'
    });
  }
});

// ========================= MODULE HÀNG ĐỢI (QUEUE SYSTEM - NEW) =========================
// 1. MÀN HÌNH TV (Hiển thị cho khách)
app.get('/queue/tv', requireAuth, (req, res) => {
  const user = req.session.user;

  if (user && user.branch_code) {
    // Nếu user có chi nhánh -> Chuyển sang URL có chi nhánh
    res.redirect(`/queue/tv/${user.branch_code}`);
  } else {
    // Nếu user chưa set chi nhánh -> Báo lỗi hoặc chuyển về Admin
    res.send(`
            <div style="text-align:center; padding:50px;">
                <h2>⚠️ Tài khoản chưa gán Chi nhánh</h2>
                <p>Vui lòng liên hệ Admin để cập nhật branch_code cho user <b>${user.username}</b></p>
                <a href="/queue/admin">Quay lại Admin</a>
            </div>
        `);
  }
});


app.get('/queue/tv/:branch', requireAuth, async (req, res) => {
  try {
    // Lấy chi nhánh từ URL (ưu tiên)
    const branchCode = req.params.branch.toUpperCase();

    // Lấy cấu hình Video Global
    const { data: globalConfig } = await supabase
      .from('branch_queue_config')
      .select('tvc_video_url')
      .eq('branch_code', 'GLOBAL')
      .maybeSingle();

    // Tạo mã QR (Link đăng ký cũng phải theo branch này)
    const registerUrl = `${req.protocol}://${req.get('host')}/queue/register/${branchCode}`;
    const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(registerUrl)}`;

    res.render('queue-tv', {
      title: `Màn hình - ${branchCode}`,
      config: { tvc_video_url: globalConfig?.tvc_video_url || '' },
      branchCode: branchCode, // Truyền mã chi nhánh xuống View
      qrCodeUrl
    });
  } catch (e) { res.status(500).send("Lỗi TV: " + e.message); }
});

// 2. FORM ĐĂNG KÝ (Khách hàng)
app.get('/queue/register/:branch', async (req, res) => {
  res.render('queue-form', {
    title: 'Lấy số thứ tự',
    branchCode: req.params.branch,
    error: null
  });
});

// 3. API: XỬ LÝ ĐĂNG KÝ VÉ (Sửa chữa: S-xxx, Bảo hành: B-xxx)
app.post('/api/queue/register', async (req, res) => {
  try {
    const { branch_code, customer_name, customer_phone, service_type, error_description } = req.body;
    const today = new Date().toISOString().slice(0, 10);

    let prefix = 'S'; // Mặc định

    if (service_type === 'WARRANTY') prefix = 'B';      // Bảo hành
    else if (service_type === 'SALES') prefix = 'N';    // Mua mới
    else if (service_type === 'PICKUP') prefix = 'L';   // Lấy máy (L)
    else if (service_type === 'CHECK') prefix = 'K';    // Khách không rõ (K)

    // Đếm số vé trong ngày
    const { count } = await supabase.from('queue_tickets').select('*', { count: 'exact', head: true })
      .eq('branch_code', branch_code)
      .eq('service_type', service_type)
      .gte('created_at', today);

    const ticketNumber = `${prefix}-${String((count || 0) + 1).padStart(3, '0')}`;

    const { data, error } = await supabase.from('queue_tickets').insert({
      branch_code,
      ticket_number: ticketNumber,
      customer_name,
      customer_phone,
      service_type, // Lưu lại loại (REPAIR, WARRANTY, PICKUP, hoặc CHECK)
      error_description,
      status: 'WAITING',
      process_status: service_type === 'SALES' ? 'ASSEMBLING' : 'PENDING'
    }).select().single();

    if (error) throw error;
    res.redirect(`/queue/status/${data.id}`);
  } catch (e) {
    res.render('queue-form', { title: 'Lỗi', branchCode: req.body.branch_code, error: e.message });
  }
});



// 4. TRANG THEO DÕI CÁ NHÂN (Cho khách xem trên điện thoại)
app.get('/queue/status/:ticketId', async (req, res) => {
  try {
    // 1. Lấy thông tin vé hiện tại
    const { data: ticket } = await supabase
      .from('queue_tickets')
      .select('*')
      .eq('id', req.params.ticketId)
      .single();

    if (!ticket) return res.send("Vé không tồn tại");

    // 2. Đếm tổng số người đang chờ phía trước (BẤT KỂ LOẠI DỊCH VỤ)
    // Logic: Cùng chi nhánh + Đang chờ + Có ID nhỏ hơn (đến trước)
    const { count } = await supabase
      .from('queue_tickets')
      .select('*', { count: 'exact', head: true })
      .eq('branch_code', ticket.branch_code)
      // .eq('service_type', ticket.service_type) <--- ĐÃ BỎ DÒNG NÀY ĐỂ ĐẾM TỔNG
      .eq('status', 'WAITING')
      .lt('id', ticket.id);

    res.render('queue-my-status', {
      title: 'Số thứ tự của bạn',
      ticket,
      peopleAhead: count || 0
    });
  } catch (e) {
    res.status(500).send(e.message);
  }
});

// 5. GIAO DIỆN KHO (Tạo đơn lắp máy)
app.get('/queue/warehouse', requireAuth, (req, res) => {
  const user = req.session.user;

  // Kiểm tra kỹ: Nếu user không có branch_code -> Chặn ngay
  if (!user.branch_code) {
    return res.send(`
            <h1 style="color:red; text-align:center; margin-top:50px;">
                LỖI: Tài khoản "${user.username}" chưa được gán Chi nhánh (Branch Code)!
            </h1>
            <p style="text-align:center;">Vui lòng liên hệ Admin set branch_code trong bảng users.</p>
        `);
  }

  res.render('queue-warehouse', {
    title: 'Kho xuất hàng',
    branchCode: user.branch_code, // Truyền mã chi nhánh xuống để hiện
    username: user.full_name || user.username,
    success: null
  });
});
// 6. API: KHO ĐẨY ĐƠN (Tạo vé SALES: NEW-xxx)
app.post('/api/queue/warehouse-push', requireAuth, async (req, res) => {
  try {
    const { order_id, customer_name, product_name } = req.body;
    const branchCode = req.session.user.branch_code; // Lấy từ session

    if (!branchCode) return res.status(400).send("Lỗi: Mất session chi nhánh!");

    const today = new Date().toISOString().slice(0, 10);

    // QUAN TRỌNG: Đếm số vé NEW trong ngày CỦA RIÊNG CHI NHÁNH ĐÓ
    const { count } = await supabase.from('queue_tickets')
      .select('*', { count: 'exact', head: true })
      .eq('branch_code', branchCode) // <--- LỌC THEO CHI NHÁNH
      .eq('service_type', 'SALES')
      .gte('created_at', today);

    // Tạo số: NEW-001, NEW-002...
    const ticketNumber = `N-${String((count || 0) + 1).padStart(3, '0')}`;

    // Insert vào DB đúng chi nhánh
    const { error } = await supabase.from('queue_tickets').insert({
      branch_code: branchCode,
      ticket_number: ticketNumber,
      customer_name,
      service_type: 'SALES',
      status: 'WAITING',
      process_status: 'ASSEMBLING', // Mặc định vào là chờ Lắp ráp ngay (để hiện lên Admin)
      order_id,
      product_name,
      counter_name: 'Kho chuyển'
    });

    if (error) throw error;

    res.render('queue-warehouse', {
      title: 'Kho chuyển đơn',
      branchCode,
      username: req.session.user.full_name || req.session.user.username,
      success: `Đã chuyển đơn ${order_id} (Số: ${ticketNumber}) sang Kỹ thuật!`
    });

  } catch (e) { res.status(500).send("Lỗi kho: " + e.message); }
});

// 7. TRANG ADMIN (KTV ĐIỀU PHỐI)
app.get('/queue/admin', requireAuth, async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    const branchCode = req.session.user.branch_code;

    // 1. Lấy vé đang chờ/phục vụ
    const { data: tickets } = await supabase.from('queue_tickets')
      .select('*')
      .eq('branch_code', branchCode)
      .in('status', ['WAITING', 'SERVING'])
      .order('id', { ascending: true });

    // 2. Lấy link TVC
    const { data: globalConfig } = await supabase.from('branch_queue_config')
      .select('tvc_video_url').eq('branch_code', 'GLOBAL').maybeSingle();

    // 3. LẤY DANH SÁCH KTV TỪ BẢNG USERS (Theo hình ảnh bạn gửi)
    // Điều kiện: Cùng chi nhánh + Đang hoạt động (is_active = true)
    const { data: staffList } = await supabase.from('users')
      .select('full_name, email')
      .eq('branch_code', branchCode)
      .eq('is_active', true)
      .order('full_name', { ascending: true });

    res.render('queue-admin', {
      title: 'Điều phối Kỹ thuật', branchCode,
      tickets: tickets || [],
      currentTvcUrl: globalConfig?.tvc_video_url || '',
      staffList: staffList || [] // Truyền danh sách xuống View
    });
  } catch (e) { res.status(500).send("Lỗi Admin: " + e.message); }
});

// 8. API: ĐIỀU KHIỂN (GỌI SỐ, CHUYỂN BƯỚC, HOÀN THÀNH)
app.post('/api/queue/control', requireAuth, async (req, res) => {
  try {
    const { action, ticket_id, service_type, process_step, counter_name, new_service_type } = req.body;
    const branchCode = req.session.user.branch_code;
    let updateData = { updated_at: new Date().toISOString() };
    if (action === 'DELETE') {
      const { error } = await supabase
        .from('queue_tickets')
        .update({ status: 'CANCELLED' }) // Không xóa hẳn, chỉ đổi trạng thái hủy
        .eq('id', ticket_id);

      if (error) throw error;
      return res.json({ ok: true });
    }

    if (action === 'TRANSFER') {
      if (!ticket_id || !counter_name) return res.json({ ok: false, message: 'Thiếu thông tin bàn giao' });

      const { error } = await supabase.from('queue_tickets').update({
        status: 'SERVING',
        counter_name: counter_name,
        updated_at: new Date().toISOString()
      }).eq('id', ticket_id);

      if (error) throw error;
      return res.json({ ok: true });
    }

    if (action === 'CALL_SPECIFIC') {
      if (!ticket_id) return res.json({ ok: false, message: 'Thiếu ID vé' });

      const updatePayload = {
        status: 'SERVING',
        updated_at: new Date().toISOString(),
        counter_name: counter_name || 'KTV Chỉ định'
      };

      // Nếu KTV chọn lại loại dịch vụ (cho vé "Tôi không rõ") thì cập nhật luôn
      if (new_service_type) {
        updatePayload.service_type = new_service_type;
      }

      const { error } = await supabase.from('queue_tickets')
        .update(updatePayload)
        .eq('id', ticket_id);

      if (error) return res.status(500).json({ ok: false, message: error.message });
      return res.json({ ok: true });
    }
    // --- GỌI SỐ TIẾP THEO ---
    if (action === 'CALL_NEXT') {
      let query = supabase.from('queue_tickets').select('id')
        .eq('branch_code', branchCode)
        .eq('status', 'WAITING')
        .order('id', { ascending: true }) // FIFO
        .limit(1);

      // Xử lý gọi chung (SERVICE_MIX) cho Sửa chữa & Bảo hành
      if (service_type === 'SERVICE_MIX') {
        query = query.in('service_type', ['REPAIR', 'WARRANTY']);
      } else {
        query = query.eq('service_type', service_type);
      }

      const { data: next } = await query.maybeSingle();

      if (!next) return res.json({ ok: false, message: 'Hết khách chờ!' });

      // Cập nhật trạng thái và tên KTV
      await supabase.from('queue_tickets').update({
        status: 'SERVING',
        updated_at: new Date().toISOString(),
        counter_name: counter_name || 'Quầy phục vụ'
      }).eq('id', next.id);

      return res.json({ ok: true });
    }

    // --- CẬP NHẬT QUY TRÌNH (LẮP MÁY) ---
    if (action === 'UPDATE_PROCESS') {
      updateData.process_status = process_step;
      if (process_step === 'ASSEMBLING') updateData.status = 'SERVING';
    }
    // --- HOÀN THÀNH ---
    else if (action === 'COMPLETE') {
      updateData.status = 'COMPLETED';
      if (service_type === 'SALES') updateData.process_status = 'DONE';
    }
    // --- BỎ QUA ---
    else if (action === 'SKIP') updateData.status = 'SKIPPED';

    await supabase.from('queue_tickets').update(updateData).eq('id', ticket_id);
    res.json({ ok: true });

  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

// 9. API: UPDATE TVC (Bất kỳ ai login đều đổi được)
app.post('/api/queue/update-tvc', requireAuth, async (req, res) => {
  try {
    await supabase.from('branch_queue_config').upsert({
      branch_code: 'GLOBAL',
      tvc_video_url: req.body.tvc_url
    }, { onConflict: 'branch_code' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});

// 10. API: LIVE DATA CHO TV
app.get('/api/queue/live-data', async (req, res) => {
  // Không bắt buộc login cứng nếu muốn TV chạy độc lập (tùy nhu cầu), 
  // nhưng ở đây ta giữ check login để bảo mật cơ bản.
  // if (!req.session.user) return res.json({ ok: false }); 

  try {
    res.setHeader('Cache-Control', 'public, max-age=10');
    // Ưu tiên lấy từ Query Param (?branch=HCM), nếu không có mới lấy từ Session
    let branchCode = req.query.branch;

    if (!branchCode && req.session.user) {
      branchCode = req.session.user.branch_code;
    }

    if (!branchCode) return res.json({ ok: false, message: "Thiếu mã chi nhánh" });

    // Lọc dữ liệu ĐÚNG THEO CHI NHÁNH ĐÓ
    const { data: serving } = await supabase.from('queue_tickets')
      .select('*')
      .eq('branch_code', branchCode) // <--- QUAN TRỌNG
      .eq('status', 'SERVING')
      .order('updated_at', { ascending: false });

    const { data: waiting } = await supabase.from('queue_tickets')
      .select('*')
      .eq('branch_code', branchCode) // <--- QUAN TRỌNG
      .eq('status', 'WAITING')
      .order('id', { ascending: true });

    return res.json({ ok: true, serving, waiting }); // Code mới
  } catch (e) { res.status(500).json({ ok: false }); }
});


// ========================= MODULE BÁO CÁO (QUEUE REPORT) =========================

app.get('/queue/report', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;

    // --- 1. KHỞI TẠO BIẾN branchList ĐỂ TRÁNH LỖI UNDEFINED ---
    let branchList = [];

    // --- 2. LOGIC LẤY DANH SÁCH CHI NHÁNH (CHỈ CHO HCM.BD) ---
    if (user.branch_code === 'HCM.BD') {
      const { data: usersData, error } = await supabase
        .from('users')
        .select('branch_code')
        .not('branch_code', 'is', null); // Lấy tất cả user có mã chi nhánh

      if (!error && usersData) {
        // Lọc trùng lặp và sắp xếp A-Z
        let uniqueSet = new Set(usersData.map(u => u.branch_code));
        branchList = Array.from(uniqueSet).sort();
      }
    }

    // --- 3. RENDER GIAO DIỆN VÀ TRUYỀN BIẾN ---
    res.render('queue-report', {
      title: 'Báo cáo Thống kê',
      user: user,                   // Truyền user
      branchList: branchList,       // <--- QUAN TRỌNG: Truyền danh sách chi nhánh sang EJS
      userBranch: user.branch_code,
      isSuperAdmin: (user.branch_code === 'HCM.BD')
    });

  } catch (e) {
    console.error("Lỗi trang report:", e);
    res.status(500).send("Lỗi server: " + e.message);
  }
});
// ----------------------------------------------------------------------
// 1. API: LẤY DỮ LIỆU BÁO CÁO (Đã bao gồm Feedback & BranchStats)
// ----------------------------------------------------------------------
// --- API: Lấy dữ liệu Báo cáo & So sánh (CHẾ ĐỘ DEBUG) ---
// [SERVER.JS] - Tìm và thay thế route này

app.get('/api/queue/report-data', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    const { startDate, endDate, branchFilter, keyword } = req.query;
    const normalizeRating = (value) => {
      const numeric = Number(value || 0);
      if (!Number.isFinite(numeric) || numeric <= 0) return 0;
      return Math.min(numeric, 5);
    };

    // 1. Phân quyền
    let targetBranch = user.branch_code;
    if (user.branch_code === 'HCM.BD') {
      targetBranch = (branchFilter && branchFilter !== 'ALL') ? branchFilter : null;
    }

    // 2. Tính kỳ trước
    const dStart = new Date(startDate);
    const dEnd = new Date(endDate);
    const timeDiff = dEnd.getTime() - dStart.getTime();
    const dPrevEnd = new Date(dStart.getTime() - 86400000);
    const dPrevStart = new Date(dPrevEnd.getTime() - timeDiff);
    const prevStartStr = dPrevStart.toISOString().split('T')[0];
    const prevEndStr = dPrevEnd.toISOString().split('T')[0];

    // 3. Hàm Query (Đã sửa để lấy hết data > 1000 row)
    const queryData = async (s, e) => {
      let allData = [];
      let from = 0;
      const step = 1000;

      while (true) {
        let query = supabase
          .from('queue_tickets')
          .select(`*, service_feedback(service_score, technician_score, comment)`)
          .gte('created_at', s + 'T00:00:00')
          .lte('created_at', e + 'T23:59:59')
          .order('created_at', { ascending: false })
          .range(from, from + step - 1);

        if (targetBranch) query = query.eq('branch_code', targetBranch);

        if (keyword && keyword.trim() !== '') {
          const k = keyword.trim();
          query = query.or(`customer_phone.ilike.%${k}%,ticket_number.ilike.%${k}%,order_id.ilike.%${k}%`);
        }

        const { data, error } = await query;
        if (error) throw error;
        if (!data || data.length === 0) break;

        allData = allData.concat(data);
        if (data.length < step) break; // Hết data
        from += step;
      }
      return { data: allData, error: null };
    };

    const [currRes, prevRes] = await Promise.all([
      queryData(startDate, endDate),
      queryData(prevStartStr, prevEndStr)
    ]);

    if (currRes.error) throw currRes.error;

    const tickets = currRes.data || [];
    const prevTickets = prevRes.data || [];

    // 4. [UPDATE] TÍNH STATS (Thêm PICKUP)
    const calcStats = (list) => {
      // Khởi tạo biến đếm
      const s = { REPAIR: 0, WARRANTY: 0, SALES: 0, PICKUP: 0, TOTAL: 0 };

      list.forEach(t => {
        if (t.status === 'COMPLETED') { // Chỉ đếm vé hoàn thành
          s.TOTAL++;
          // Cộng dồn theo loại
          if (s[t.service_type] !== undefined) s[t.service_type]++;
        }
      });
      return s;
    };

    const stats = calcStats(tickets);
    const prevStats = calcStats(prevTickets);

    const feedbackTotals = {
      serviceStars: 0,
      serviceRatedCount: 0,
      techStars: 0,
      techRatedCount: 0,
      avgServiceStars: 0,
      avgTechStars: 0
    };

    // 5. [UPDATE] XỬ LÝ BIỂU ĐỒ & LEADERBOARD (Thêm PICKUP)
    let dailyStats = {};
    let branchStats = {};
    let ktvMap = {};

    tickets.forEach(t => {
      if (t.status === 'COMPLETED') {

        // A. Daily Stats
        const day = t.created_at.split('T')[0];
        if (!dailyStats[day]) dailyStats[day] = { REPAIR: 0, WARRANTY: 0, SALES: 0, PICKUP: 0 };
        if (dailyStats[day][t.service_type] !== undefined) dailyStats[day][t.service_type]++;

        // B. Branch Stats
        const br = t.branch_code || 'N/A';
        if (!branchStats[br]) branchStats[br] = { REPAIR: 0, WARRANTY: 0, SALES: 0, PICKUP: 0 };
        if (branchStats[br][t.service_type] !== undefined) branchStats[br][t.service_type]++;

        // C. [UPDATE QUAN TRỌNG] Leaderboard - Gộp nhóm theo tên
        if (t.counter_name) {
          // Xử lý chuỗi: "Huy (Bàn 1)" -> "Huy"
          let rawName = t.counter_name;
          // Regex: Tìm mở ngoặc, nội dung bên trong, đóng ngoặc và xóa đi
          let cleanName = rawName.replace(/\s*\(.*?\)\s*/g, '').trim();

          // Nếu sau khi xóa mà rỗng (trường hợp lỗi nhập liệu), lấy lại tên gốc
          if (!cleanName) cleanName = rawName;

          if (!ktvMap[cleanName]) {
            ktvMap[cleanName] = {
              name: cleanName,
              branch: t.branch_code,
              totalTech: 0, totalService: 0, count: 0, ratedCount: 0, latestComment: ''
            };
          }

          ktvMap[cleanName].count++;

          if (t.service_feedback && t.service_feedback.length > 0) {
            const fb = t.service_feedback[0];
            const techScore = normalizeRating(fb.technician_score);
            const serviceScore = normalizeRating(fb.service_score);
            ktvMap[cleanName].ratedCount++;
            ktvMap[cleanName].totalTech += techScore;
            ktvMap[cleanName].totalService += serviceScore;
            if (fb.comment) ktvMap[cleanName].latestComment = fb.comment;
          }
        }

        if (t.service_feedback && t.service_feedback.length > 0) {
          const fb = t.service_feedback[0];
          const serviceScore = normalizeRating(fb.service_score);
          const techScore = normalizeRating(fb.technician_score);

          if (serviceScore > 0) {
            feedbackTotals.serviceStars += serviceScore;
            feedbackTotals.serviceRatedCount++;
          }
          if (techScore > 0) {
            feedbackTotals.techStars += techScore;
            feedbackTotals.techRatedCount++;
          }
        }
      }
    });

    // Tính trung bình điểm
    feedbackTotals.avgServiceStars = feedbackTotals.serviceRatedCount > 0
      ? Number((feedbackTotals.serviceStars / feedbackTotals.serviceRatedCount).toFixed(1))
      : 0;
    feedbackTotals.avgTechStars = feedbackTotals.techRatedCount > 0
      ? Number((feedbackTotals.techStars / feedbackTotals.techRatedCount).toFixed(1))
      : 0;

    let leaderboard = Object.values(ktvMap).map(k => ({
      name: k.name,
      branch: k.branch,
      count: k.count,
      avgTech: k.ratedCount > 0 ? (k.totalTech / k.ratedCount).toFixed(1) : '---',
      avgService: k.ratedCount > 0 ? (k.totalService / k.ratedCount).toFixed(1) : '---',
      latestComment: k.latestComment
    })).sort((a, b) => b.count - a.count); // Sắp xếp theo số lượng vé

    res.json({ ok: true, stats, prevStats, dailyStats, branchStats, leaderboard, feedbackTotals, details: tickets });

  } catch (e) {
    console.error("Report API Error:", e);
    res.status(500).json({ ok: false, message: e.message });
  }
});


// ----------------------------------------------------------------------
// 2. API: EXPORT EXCEL (ĐÃ CẬP NHẬT FEEDBACK)
// ----------------------------------------------------------------------
app.get('/queue/export', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    const { startDate, endDate, branchFilter, keyword } = req.query;

    // [QUAN TRỌNG] Phải select thêm bảng service_feedback để lấy điểm đánh giá
    let query = supabase
      .from('queue_tickets')
      .select(`
                *,
                service_feedback (
                    service_score,
                    technician_score,
                    comment
                )
            `);

    // --- Filter Logic ---
    if (startDate) query = query.gte('created_at', startDate + 'T00:00:00');
    if (endDate) query = query.lte('created_at', endDate + 'T23:59:59');

    if (user.branch_code === 'HCM.BD') {
      if (branchFilter && branchFilter !== 'ALL') query = query.eq('branch_code', branchFilter);
    } else {
      query = query.eq('branch_code', user.branch_code);
    }

    if (keyword && keyword.trim() !== '') {
      const k = keyword.trim();
      // Đồng bộ logic tìm kiếm cho cả xuất file
      query = query.or(`customer_phone.ilike.%${k}%,ticket_number.ilike.%${k}%,order_id.ilike.%${k}%`);
    }

    const { data, error } = await query.order('created_at', { ascending: false });
    if (error) throw error;

    // --- Tạo nội dung CSV ---
    let csv = '\uFEFF';
    // Header: Thêm cột Điểm KTV, Điểm DV, Góp ý
    csv += "Chi Nhánh,Mã Vé,Tên Khách,SĐT,Dịch Vụ,Trạng Thái,KTV/Quầy,Ngày Tạo,Giờ Xử Lý,Tổng Thời Gian (Phút),Điểm KTV,Điểm DV,Góp ý\n";

    data.forEach(t => {
      const typeName = t.service_type === 'SALES' ? 'Lắp máy' : (t.service_type === 'WARRANTY' ? 'Bảo hành' : 'Sửa chữa');
      const date = new Date(t.created_at).toLocaleString('vi-VN');
      const updateTime = t.updated_at ? new Date(t.updated_at).toLocaleTimeString('vi-VN') : '--';

      // Tính tổng thời gian
      let duration = 0;
      if (t.created_at && t.updated_at && t.status === 'COMPLETED') {
        duration = Math.floor((new Date(t.updated_at) - new Date(t.created_at)) / 60000);
      }

      // Xử lý thông tin khách
      const cleanName = (t.customer_name || '').replace(/,/g, ' ');
      const cleanCounter = (t.counter_name || '').replace(/,/g, ' ');
      const phone = t.customer_phone || '';

      // [MỚI] Xử lý Feedback
      let fKtv = '', fDv = '', fCmt = '';
      if (t.service_feedback && t.service_feedback.length > 0) {
        const fb = t.service_feedback[0];
        fKtv = fb.technician_score || '';
        fDv = fb.service_score || '';
        // Xóa dấu phẩy hoặc xuống dòng trong comment để tránh vỡ file CSV
        fCmt = (fb.comment || '').replace(/,/g, '.').replace(/\n/g, ' ');
      }

      // Ghi dòng CSV
      csv += `${t.branch_code},${t.ticket_number},${cleanName},'${phone},${typeName},${t.status},${cleanCounter},${date},${updateTime},${duration},${fKtv},${fDv},${fCmt}\n`;
    });

    res.header('Content-Type', 'text/csv; charset=utf-8');
    res.attachment(`Bao_cao_Chi_tiet_${Date.now()}.csv`);
    res.send(csv);

  } catch (e) { res.status(500).send("Lỗi xuất file: " + e.message); }
});

// 2. API: LƯU ĐÁNH GIÁ (FEEDBACK)
app.post('/api/queue/feedback', async (req, res) => {
  try {
    const { ticket_id, service_score, technician_score, comment } = req.body;

    await supabase.from('service_feedback').insert({
      ticket_id, service_score, technician_score, comment
    });

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, message: e.message }); }
});


app.get('/api/queue/check-status/:id', async (req, res) => {
  try {
    const { data } = await supabase
      .from('queue_tickets')
      .select('status, counter_name')
      .eq('id', req.params.id)
      .single();
    res.json(data);
  } catch (e) { res.status(500).json(null); }
});

// API Tra cứu phiếu theo số điện thoại
app.post('/api/queue/lookup', async (req, res) => {
  try {
    const { branch_code, customer_phone } = req.body;
    if (!customer_phone) return res.json({ ok: false, message: 'Vui lòng nhập số điện thoại' });

    const { data, error } = await supabase
      .from('queue_tickets')
      .select('id, status')
      .eq('branch_code', branch_code)
      .eq('customer_phone', customer_phone)
      .in('status', ['WAITING', 'SERVING'])
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) throw error;
    if (!data) return res.json({ ok: false, message: 'Không tìm thấy phiếu nào đang hoạt động với số điện thoại này.' });

    res.json({ ok: true, ticket_id: data.id });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// [THÊM VÀO server.js] API lấy lịch sử phục vụ trong ngày (kèm đánh giá)
app.get('/api/queue/history', requireAuth, async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'public, max-age=30');
    const branchCode = req.query.branch || req.session.user.branch_code;
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;

    const today = new Date().toISOString().slice(0, 10);

    // Lấy danh sách vé đã hoàn thành (COMPLETED) trong ngày
    // Kèm theo thông tin đánh giá từ bảng service_feedback
    const { data: history, count, error } = await supabase
      .from('queue_tickets')
      .select(`
                *,
                service_feedback(service_score, technician_score, comment)
            `, { count: 'exact' })
      .eq('branch_code', branchCode)
      .eq('status', 'COMPLETED') // Chỉ lấy khách đã xong
      .gte('updated_at', today + 'T00:00:00') // Trong ngày hôm nay
      .order('updated_at', { ascending: false }) // Mới nhất lên đầu
      .range(offset, offset + limit - 1);

    if (error) throw error;

    res.json({
      ok: true,
      data: history,
      pagination: { page, limit, total: count, totalPages: Math.ceil(count / limit) }
    });

  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: e.message });
  }
});


// --- API: Ghi Log công việc vào Sheets & Hoàn thành vé ---
app.post('/api/queue/log-and-complete', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false, message: 'Unauthorized' });

  const { ticket_id, msnv, customer_info, action_desc, other_action, new_service_type } = req.body;
  const userEmail = req.session.user.email;
  const SHEET_ID = '1CBPQph9ShcNmOZNh5-1B2HBd8ctJ5spArpIEUEvSI8o'; // ID Sheet của bạn

  try {
    // 1. Lấy Key bảo mật từ Vercel Env
    let auth;
    let credentials;
    // Ưu tiên 1: Chạy trên Vercel (Biến môi trường)
    if (process.env.GOOGLE_CREDENTIALS) {
      const credentials = JSON.parse(process.env.GOOGLE_CREDENTIALS);
      auth = new google.auth.GoogleAuth({
        credentials,
        scopes: ['https://www.googleapis.com/auth/spreadsheets'],
      });
    }
    // Ưu tiên 2: Chạy Local (File service-account.json)
    else if (fs.existsSync('service-account.json')) {
      console.log("[Local] Đang dùng file service-account.json");
      auth = new google.auth.GoogleAuth({
        keyFile: 'service-account.json',
        scopes: ['https://www.googleapis.com/auth/spreadsheets'],
      });
    }
    // Lỗi: Không tìm thấy cả 2
    else {
      throw new Error("Thiếu cấu hình: Cần GOOGLE_CREDENTIALS (Vercel) hoặc file service-account.json (Local)");
    }

    // 3. KHỞI TẠO SERVICE SHEETS (⚠️ Bạn đang thiếu dòng này)
    const sheets = google.sheets({ version: 'v4', auth });

    // 4. Chuẩn bị dữ liệu
    const d = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Ho_Chi_Minh' }));
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');

    // Kết quả sẽ là: 2025-12-28 08:26:12 (Đúng chuẩn để sort)
    const now = `${yyyy}-${mm}-${dd} ${h}:${m}:${s}`;
    // ID Sheet của bạn (Lấy từ URL)
    const SHEET_ID = '1CBPQph9ShcNmOZNh5-1B2HBd8ctJ5spArpIEUEvSI8o';

    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID,
      range: 'Sheet1!A:F', // Giả sử ghi vào Sheet1
      valueInputOption: 'USER_ENTERED',
      requestBody: {
        values: [[
          now,            // Dấu thời gian
          userEmail,      // Địa chỉ email
          msnv,           // MSNV
          customer_info,  // Tên KH / Mã ĐH
          action_desc,    // Bạn đã làm gì...
          other_action    // Các hành động khác
        ]]
      }
    });
    if (ticket_id && ticket_id !== 'null' && ticket_id !== 'undefined' && ticket_id !== '') {
      const updatePayload = {
        status: 'COMPLETED',
        process_status: 'DONE',
        updated_at: new Date()
      };

      if (new_service_type) {
        updatePayload.service_type = new_service_type;
      }

      const { error } = await supabase
        .from('queue_tickets')
        .update(updatePayload)
        .eq('id', ticket_id);

      if (error) throw error;
    }

    res.json({ ok: true });

  } catch (e) {
    console.error("Log Work Error:", e);
    res.status(500).json({ ok: false, message: e.message });
  }
});



// --- ROUTE 1: HIỂN THỊ TRANG LOGBOOK ---
app.get('/store-logbook', requireAuth, (req, res) => {
  // Render trang ejs mới tạo
  res.render('store-logbook', {
    user: req.session.user
  });
});
// --- CẤU HÌNH ID THƯ MỤC LOGBOOK ---
// Bạn hãy thay ID thư mục thật vào đây (Thư mục đã Share quyền cho Bot)
const LOGBOOK_FOLDER_ID = '1TJn-ZTCvJS96YOPK2G462gEVS6zhggHr';

// --- ROUTE: XỬ LÝ SUBMIT FORM LOGBOOK (CHUẨN HÓA THEO CHIẾN GIÁ) ---
app.post('/api/store-logbook/submit', requireAuth, upload.single('imageFile'), async (req, res) => {
  try {
    const user = req.session.user;
    const { vm_check, vm_note, ops_check, stock_count, serial_list } = req.body;

    let fileUrl = '';

    // 1. UPLOAD ẢNH LÊN GOOGLE DRIVE (Logic Stream giống Chiến Giá)
    if (req.file) {
      // Khởi tạo Drive
      const drive = google.drive({ version: 'v3', auth });

      // [QUAN TRỌNG] Tạo luồng đọc file từ buffer (RAM)
      const fileStream = Readable.from(req.file.buffer);

      const fileMetadata = {
        name: `LOG_${user.branch_code}_${Date.now()}.jpg`,
        parents: [LOGBOOK_FOLDER_ID] // Lưu vào thư mục đã cấu hình
      };

      const media = {
        mimeType: req.file.mimetype,
        body: fileStream
      };

      // Thực hiện Upload
      const file = await drive.files.create({
        requestBody: fileMetadata,
        media: media,
        fields: 'id, webViewLink',
        supportsAllDrives: true, // Hỗ trợ thư mục Share
      });

      // Set quyền Public (Anyone can read) để hiển thị ảnh trên Web
      await drive.permissions.create({
        fileId: file.data.id,
        requestBody: {
          role: 'reader',
          type: 'anyone',
        },
        supportsAllDrives: true
      });

      fileUrl = file.data.webViewLink;
    }

    // 2. TÍNH ĐIỂM (Logic cũ)
    let score = 0;
    if (vm_check === 'Đạt') score += 50;
    if (ops_check === 'Đạt') score += 50;

    // 3. GHI VÀO GOOGLE SHEETS
    const now = new Date().toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh' });

    // Đảm bảo biến LOGBOOK_SHEET_ID đã được khai báo hoặc thay trực tiếp ID Sheet vào đây
    const TARGET_SHEET_ID = '1CBPQph9ShcNmOZNh5-1B2HBd8ctJ5spArpIEUEvSI8o'; // ID Sheet Logbook của bạn

    await sheets.spreadsheets.values.append({
      spreadsheetId: TARGET_SHEET_ID,
      range: 'db_logs!A:I', // Đảm bảo tên Tab là db_logs
      valueInputOption: 'USER_ENTERED',
      requestBody: {
        values: [[
          now,
          user.branch_code,
          user.username,
          vm_check,
          vm_note,
          fileUrl, // Link ảnh từ Drive
          ops_check,
          stock_count,
          serial_list,
          score
        ]]
      }
    });

    res.json({ ok: true, message: 'Đã lưu báo cáo thành công' });

  } catch (e) {
    console.error("❌ Logbook Upload Error:", e);
    // Trả về lỗi chi tiết để dễ debug
    res.status(500).json({ ok: false, message: e.message });
  }
});

const REFUND_SPREADSHEET_ID = '1uKAVBdZtXXRSQoD8GK05awJB-pClcbnhVhyohGGQBwM'; // ID từ code cũ
const REFUND_SHEET_NAME = 'Refunds';

const REFUND_HEADERS = [
  'ID',               // Cột A
  'RequestDate',      // Cột B
  'CustomerName',     // Cột C
  'Phone',            // Cột D
  'OrderID',          // Cột E
  'Product',          // Cột F
  'Reason',           // Cột G
  'RefundMethod',     // Cột H
  'RefundAmount',     // Cột I
  'OrderTotal',       // Cột J
  'BankName',         // Cột K
  'Branch',           // Cột L
  'AccountName',      // Cột M
  'AccountNumber',    // Cột N
  'RequestedBy',      // Cột O
  'ApprovedBy',       // Cột P
  'Status',           // Cột Q
  'Notes',            // Cột R
  'CreatedBy',        // Cột S
  'CreatedAt',        // Cột T
  'UpdatedBy',        // Cột U
  'UpdatedAt',        // Cột V (Nguyên nhân lỗi ngày tháng nằm ở đây)
  'OldOrderID',       // Cột W
  'NewOrderID',       // Cột X
  'SRApprover',       // Cột Y
  'OldOrderValue',    // Cột Z
  'OldBeforeKM',      // Cột AA
  'OldKM',            // Cột AB
  'OldAfterKM',       // Cột AC
  'NewOrderValue',    // Cột AD
  'NewBeforeKM',      // Cột AE
  'NewKM',            // Cột AF
  'NewAfterKM',       // Cột AG
  'Bank',             // Cột AH (Thông tin NH gộp)
  'OffsetToNewOrder'  // Cột AI
];

// Map tên cột hiển thị khi in
const COL_NAMES_VN = {
  ID: 'Số chứng từ',          // UUID hệ thống
  OrderID: 'Mã đơn hàng',     // Mã đơn user nhập (VD: 1212124)
  RequestDate: 'Ngày yêu cầu',
  CustomerName: 'Khách hàng',
  Phone: 'SĐT',
  Product: 'Sản phẩm',
  Reason: 'Lý do',
  RefundMethod: 'Phương thức',
  RefundAmount: 'Số tiền hoàn',
  OrderTotal: 'Giá trị đơn',
  Bank: 'Thông tin NH',
  Status: 'Trạng thái',
  RequestedBy: 'Người yêu cầu',
  ApprovedBy: 'Người duyệt',
  Notes: 'Ghi chú',
  // --- Các cột thường ---
  ApprovedBy: 'Người duyệt (SM)',

  // --- Các cột Cấn Trừ (Thêm mới vào đây) ---
  SRApprover: 'Người duyệt (SR)',
  NewOrderID: 'Mã đơn mới',
  NewOrderValue: 'Giá trị mới',
  NewKM: 'Tiền KM',
  NewAfterKM: 'Sau KM'
};

// Hàm Helper: Lấy dữ liệu
// Hàm Helper: Lấy dữ liệu
async function fetchRefunds() {
  try {
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: REFUND_SPREADSHEET_ID,
      range: `${REFUND_SHEET_NAME}!A:AZ`,
    });

    const rows = response.data.values;
    if (!rows || rows.length === 0) return [];

    // Lấy header từ dòng 1 và xóa khoảng trắng thừa
    const headers = rows[0].map(h => String(h).trim());
    const data = [];

    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      const obj = {};
      // Map dữ liệu vào object
      headers.forEach((h, index) => {
        obj[h] = row[index] || '';
      });

      // LOGIC FIX: Tự động gộp Bank nếu cột Bank rỗng
      if (!obj.Bank || obj.Bank.trim() === '') {
        const parts = [obj.BankName, obj.Branch, obj.AccountNumber, obj.AccountName]
          .filter(p => p && String(p).trim() !== '');
        if (parts.length > 0) obj.Bank = parts.join(' - ');
      }
      data.push(obj);
    }
    return data.reverse(); // Mới nhất lên đầu
  } catch (error) {
    console.error('Fetch Refund Error:', error);
    throw error;
  }
}

// Khởi tạo sheets client toàn cục
const sheets = google.sheets({ version: 'v4', auth });


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public')); // Để load file css/refund.css

// --- ROUTES ---
app.delete('/api/refunds/delete/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Bước 1: Tìm rowIndex của ID cần xóa
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: REFUND_SPREADSHEET_ID,
      range: `${REFUND_SHEET_NAME}!A:A` // Chỉ cần đọc cột ID để tìm dòng
    });

    const rows = response.data.values || [];
    let rowIndex = -1;

    // Giả sử cột ID nằm đầu tiên (A). Nếu không phải thì cần logic tìm index
    // Ở đây REFUND_HEADERS[0] === 'ID' nên cột A là chuẩn.
    for (let i = 1; i < rows.length; i++) {
      if (rows[i][0] === id) {
        rowIndex = i; // Index trong mảng (0-based)
        break;
      }
    }

    if (rowIndex === -1) return res.status(404).json({ ok: false, message: 'Không tìm thấy phiếu' });

    // Bước 2: Xóa dòng bằng lệnh batchUpdate (deleteDimension)
    // Lưu ý: Sheet API dùng index 0-based. rowIndex=1 (dòng 2 trong Excel)

    // Trước tiên cần lấy sheetId (GID) của tab 'Refunds'
    const meta = await sheets.spreadsheets.get({ spreadsheetId: REFUND_SPREADSHEET_ID });
    const sheetObj = meta.data.sheets.find(s => s.properties.title === REFUND_SHEET_NAME);
    const sheetId = sheetObj.properties.sheetId;

    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: REFUND_SPREADSHEET_ID,
      requestBody: {
        requests: [{
          deleteDimension: {
            range: {
              sheetId: sheetId,
              dimension: 'ROWS',
              startIndex: rowIndex,     // Bắt đầu từ dòng này
              endIndex: rowIndex + 1    // Đến trước dòng này (xóa 1 dòng)
            }
          }
        }]
      }
    });

    res.json({ ok: true, message: 'Đã xóa thành công' });

  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// 5. Route UI
app.get('/refunds', (req, res) => res.render('refund_dashboard'));

// 2. Trang In Phiếu
app.get('/refunds/print/:id', async (req, res) => {
  // Biến mặc định để tránh lỗi EJS nếu crash
  const safePayload = {
    data: null,
    cols: [],
    colNames: COL_NAMES_VN
  };

  try {
    const { id } = req.params;
    const { cols } = req.query; // Lấy danh sách cột từ URL

    // 1. Lấy dữ liệu
    const allData = await fetchRefunds();
    const rec = allData.find(r => r.ID === id);

    // 2. Nếu không tìm thấy phiếu -> Render trang lỗi
    if (!rec) {
      return res.render('refund_print', safePayload);
    }

    // 3. Xác định các cột cần in
    // Nếu URL có ?cols=A,B,C thì dùng, không thì dùng mặc định
    let colsToPrint = [];
    if (cols) {
      colsToPrint = cols.split(',');
    } else {
      colsToPrint = ['ID', 'RequestDate', 'CustomerName', 'OrderID', 'RefundAmount', 'Reason', 'Bank', 'Status'];
    }

    // 4. Render và truyền ĐỦ biến
    res.render('refund_print', {
      data: rec,
      cols: colsToPrint,       // <--- QUAN TRỌNG: Biến này sửa lỗi cols is not defined
      colNames: COL_NAMES_VN   // <--- QUAN TRỌNG: Biến này sửa lỗi colNames
    });

  } catch (e) {
    console.error("Print Error:", e);
    // Trường hợp lỗi Server vẫn truyền biến rỗng để không sập trang
    res.render('refund_print', safePayload);
  }
});
app.get('/api/refunds/list', async (req, res) => {
  try {
    const data = await fetchRefunds();
    // Filter đơn giản nếu cần
    const { q } = req.query;
    let result = data;
    if (q) {
      const lowerQ = q.toLowerCase();
      result = data.filter(r => JSON.stringify(r).toLowerCase().includes(lowerQ));
    }
    // Luôn trả về JSON
    res.json({ ok: true, data: result.slice(0, 100) });
  } catch (e) {
    res.status(500).json({ ok: false, message: e.message });
  }
});

// 2. API Tạo phiếu mới (thay thế createRefund)
app.post('/api/refunds/create', async (req, res) => {
  try {
    const payload = req.body;
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const refund = Number(payload.RefundAmount || 0);
    const orderTotal = Number(payload.OrderTotal || 0);
    const isOffset = payload.OffsetToNewOrder === true || payload.OffsetToNewOrder === 'true';

    if (!isOffset && orderTotal > 0 && refund > orderTotal) {
      return res.status(400).json({
        ok: false,
        message: 'Số tiền hoàn không được lớn hơn tổng giá trị đơn'
      });
    }
    // 1. Chuẩn bị dữ liệu
    // Tự động gộp Bank từ các trường con
    const bankCombined = [
      payload.BankName,
      payload.Branch,
      payload.AccountNumber,
      payload.AccountName
    ].filter(p => p && String(p).trim() !== '').join(' - ');

    const newRec = {
      ...payload,
      ID: id,
      CreatedAt: now,
      UpdatedAt: now,
      CreatedBy: 'system',
      Bank: bankCombined // Gán vào cột Bank
    };

    // 2. Map dữ liệu ra mảng theo đúng thứ tự REFUND_HEADERS
    const row = REFUND_HEADERS.map(h => {
      // Lấy giá trị từ newRec, nếu không có thì để trống
      return newRec[h] !== undefined ? newRec[h] : '';
    });

    // 3. Ghi vào Sheet
    await sheets.spreadsheets.values.append({
      spreadsheetId: REFUND_SPREADSHEET_ID,
      range: `${REFUND_SHEET_NAME}!A:A`, // Tự động tìm dòng trống
      valueInputOption: 'USER_ENTERED',
      requestBody: { values: [row] }
    });

    res.json({ ok: true, id: id, message: 'Đã lưu thành công' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: e.message });
  }
});

// 3. API In phiếu (Render HTML để in)
app.get('/refunds/print/:id', async (req, res) => {
  const safePayload = { data: null, cols: [], colNames: COL_NAMES_VN };
  try {
    const { id } = req.params;
    const { cols } = req.query;

    const allData = await fetchRefunds();
    const rec = allData.find(r => r.ID === id);

    if (!rec) return res.render('refund_print', safePayload);

    // Xử lý danh sách cột cần in
    let colsToPrint = [];
    if (cols && cols.trim() !== '') {
      colsToPrint = cols.split(',');
    } else {
      // Mặc định nếu không chọn gì
      colsToPrint = ['OrderID', 'RequestDate', 'CustomerName', 'Reason', 'RefundAmount', 'Bank'];
    }

    res.render('refund_print', {
      data: rec,
      cols: colsToPrint,
      colNames: COL_NAMES_VN
    });

  } catch (e) {
    console.error("Print Error:", e);
    res.render('refund_print', safePayload);
  }
});


app.post('/api/refunds/update/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const payload = req.body;

    // 1. Tìm dòng chứa ID
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: REFUND_SPREADSHEET_ID,
      range: `${REFUND_SHEET_NAME}!A:AZ`, // Đọc rộng ra để bao hết cột
    });
    const rows = response.data.values;
    if (!rows || rows.length < 2) return res.status(404).json({ ok: false, message: 'Sheet trống' });

    // Giả định dòng 1 là Header theo đúng thứ tự REFUND_HEADERS
    // Tìm vị trí cột ID (Cột đầu tiên = index 0)
    const idColumnIndex = REFUND_HEADERS.indexOf('ID');

    let rowIndex = -1;
    // Duyệt tìm dòng
    for (let i = 1; i < rows.length; i++) {
      // rows[i][idColumnIndex] chính là ô ID
      if (rows[i][idColumnIndex] === id) {
        rowIndex = i;
        break;
      }
    }

    if (rowIndex === -1) return res.status(404).json({ ok: false, message: 'Không tìm thấy phiếu #' + id });

    // 2. Lấy dữ liệu cũ
    const oldRowData = rows[rowIndex];
    const currentData = {};

    // Map dữ liệu cũ vào object
    REFUND_HEADERS.forEach((h, index) => {
      currentData[h] = oldRowData[index] || '';
    });

    // 3. Merge dữ liệu mới
    const merged = { ...currentData, ...payload, UpdatedAt: new Date().toISOString() };

    // Cập nhật lại Bank gộp nếu user có sửa thông tin bank
    merged.Bank = [
      merged.BankName, merged.Branch, merged.AccountNumber, merged.AccountName
    ].filter(p => p && String(p).trim() !== '').join(' - ');

    // 4. Map lại thành mảng để ghi đè
    const newRowValues = REFUND_HEADERS.map(h => merged[h] !== undefined ? merged[h] : '');

    // 5. Ghi đè vào Sheet
    await sheets.spreadsheets.values.update({
      spreadsheetId: REFUND_SPREADSHEET_ID,
      range: `${REFUND_SHEET_NAME}!A${rowIndex + 1}`,
      valueInputOption: 'USER_ENTERED',
      requestBody: { values: [newRowValues] }
    });

    res.json({ ok: true, message: 'Đã cập nhật' });

  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: e.message });
  }
});



const requireAdmin = (req, res, next) => {
  // 1. Kiểm tra đã đăng nhập chưa
  if (!req.session || !req.session.user) {
    return res.status(401).json({ ok: false, error: 'Vui lòng đăng nhập!' });
  }
  // 2. Kiểm tra quyền (Admin hoặc Manager đều được)
  const role = req.session.user.role;
  if (role === 'admin' || role === 'manager') {
    return next(); // Cho phép đi tiếp
  }
  // 3. Nếu không phải admin thì chặn lại
  return res.status(403).json({ ok: false, error: 'Bạn không có quyền thực hiện thao tác này!' });
};

// === API IMPORT KFI (Dùng cho trang quản lý CTKM) ===
// === API IMPORT KFI (PHIÊN BẢN FIX LỖI) ===
app.post('/api/admin/import-kfi', requireAdmin, async (req, res) => {
  try {
    const { rawData } = req.body;
    if (!rawData) return res.json({ ok: false, error: 'Chưa nhập dữ liệu' });

    const rows = rawData.trim().split('\n');
    const upsertData = [];

    console.log(`[DEBUG] Đang xử lý ${rows.length} dòng...`);

    for (const row of rows) {
      const cols = row.split('\t');
      // Check đủ cột (SKU | Tên | Ngành | Hãng | User | Dealer)
      if (cols.length >= 6) {
        // Hàm làm sạch số tiền (Bỏ hết chữ, dấu chấm, phẩy -> chỉ lấy số)
        const cleanMoney = (str) => {
          if (!str) return 0;
          // Giữ lại số và dấu chấm/phẩy, sau đó loại bỏ ký tự không phải số
          // Cách đơn giản nhất cho tiền VNĐ: Bỏ hết tất cả ký tự không phải số
          return parseFloat(String(str).replace(/[^0-9]/g, '')) || 0;
        };

        upsertData.push({
          sku: cols[0].trim(),
          product_name: cols[1].trim(),
          category: cols[2].trim(),
          brand: cols[3].trim(),
          kfi_end_user: cleanMoney(cols[4]),
          kfi_dealer: cleanMoney(cols[5]),
          updated_at: new Date()
        });
      }
    }

    if (upsertData.length === 0) {
      return res.json({ ok: false, error: 'Không đọc được dòng nào. Hãy chắc chắn bạn copy từ Excel.' });
    }

    // Lưu vào Supabase
    const { error } = await supabase.from('kfi_list').upsert(upsertData);

    if (error) {
      console.error('Lỗi Supabase:', error);
      throw new Error(error.message);
    }

    console.log(`[SUCCESS] Đã import ${upsertData.length} SKU.`);
    res.json({ ok: true, count: upsertData.length });

  } catch (e) {
    console.error('Lỗi Import:', e);
    res.status(500).json({ ok: false, error: e.message });
  }
});


// ==================================================================
// === [UPDATE] KFI PROGRAM (PHÂN TRANG + SEARCH CHÍNH XÁC) ===
app.get('/kfi-program', requireAuth, async (req, res) => {
  try {
    const userBranch = req.session.user.branch_code;
    const userRole = req.session.user.role || ''; // Lấy role để check admin

    // 1. NHẬN THAM SỐ TỪ URL (Search & Sort & Page)
    const searchQuery = (req.query.q || '').trim().toLowerCase();

    // Logic Sort: Mặc định sắp xếp theo kfi_end_user giảm dần
    const sortField = req.query.sort || 'kfi_end_user';
    const sortOrder = req.query.order || 'desc';
    const isAsc = sortOrder === 'asc';

    // Chỉ cho phép sort các cột an toàn để bảo mật DB
    const allowedSorts = ['sku', 'product_name', 'brand', 'kfi_end_user', 'kfi_dealer'];
    const finalSortField = allowedSorts.includes(sortField) ? sortField : 'kfi_end_user';

    // Logic Phân trang
    const page = parseInt(req.query.page || '1');
    const pageSize = 50;
    const from = (page - 1) * pageSize;
    const to = from + pageSize - 1;

    // 2. TẠO QUERY SUPABASE
    let query = supabase.from('kfi_list').select('*', { count: 'exact' });

    // --- NÂNG CẤP SEARCH: Tìm trong SKU HOẶC Tên HOẶC Hãng ---
    if (searchQuery) {
      query = query.or(`sku.ilike.%${searchQuery}%,product_name.ilike.%${searchQuery}%,brand.ilike.%${searchQuery}%`);
    }

    // --- NÂNG CẤP SORT: Sắp xếp động theo cột click ---
    // Lưu ý: Cột Tồn kho không sort được ở đây vì nó nằm ở BigQuery
    query = query.order(finalSortField, { ascending: isAsc });

    // Thực thi query với phân trang
    const { data: kfiList, count, error } = await query.range(from, to);
    if (error) throw error;

    const totalItems = count || 0;
    const totalPages = Math.ceil(totalItems / pageSize);

    // 3. LẤY TỒN KHO BIGQUERY (LOGIC CŨ GIỮ NGUYÊN)
    let stockMap = {};

    if (kfiList && kfiList.length > 0) {
      const skuList = kfiList.map(i => i.sku);

      try {
        // a. Chuẩn bị tham số
        const today = new Date().toISOString().split('T')[0];
        const isGlobalAdmin = (userRole === 'admin' || userBranch === 'HCM.BD');

        // b. Khởi tạo mặc định 0
        skuList.forEach(sku => stockMap[sku] = 0);

        // c. Gọi hàm BigQuery chuẩn (Hàm này đã có trong server.js)
        if (typeof getInventoryCounts === 'function') {
          const inventoryMap = await getInventoryCounts(skuList, userBranch, isGlobalAdmin, today);

          // d. Xử lý dữ liệu trả về từ Map
          skuList.forEach(sku => {
            if (inventoryMap.has(sku)) {
              const branchMap = inventoryMap.get(sku); // Map<Branch, Data>

              if (isGlobalAdmin) {
                // --- LOGIC CHO ADMIN/HCM.BD: CỘNG TỔNG TOÀN BỘ ---
                let totalStock = 0;
                branchMap.forEach((val) => {
                  totalStock += (val.hang_ban_moi || 0);
                });
                stockMap[sku] = totalStock;
              } else {
                // --- LOGIC CHO USER THƯỜNG: LẤY ĐÚNG KHO MÌNH ---
                if (branchMap.has(userBranch)) {
                  const counts = branchMap.get(userBranch);
                  stockMap[sku] = counts.hang_ban_moi || 0;
                }
              }
            }
          });
        } else {
          console.warn('Hàm getInventoryCounts chưa được định nghĩa hoặc BigQuery chưa sẵn sàng.');
        }

      } catch (errBQ) {
        console.error('Lỗi lấy tồn kho BigQuery (KFI):', errBQ.message);
      }
    }

    // 4. RENDER VIEW
    res.render('kfi-program', {
      title: 'Chương trình KFI Focus',
      currentPage: 'kfi-program',

      kfiList: kfiList || [],
      stockMap,
      userBranch,
      branchCode: userBranch,

      page,
      totalPages,
      totalItems,

      qrCodeUrl: '',

      // Truyền lại các tham số lọc/sort để EJS hiển thị đúng trạng thái
      searchQuery,
      currentSort: finalSortField,
      currentOrder: sortOrder,

      time: new Date().toLocaleTimeString('vi-VN')
    });

  } catch (e) {
    console.error('Lỗi route /kfi-program:', e);
    res.status(500).send('Lỗi hệ thống: ' + e.message);
  }
});


// [THÊM VÀO server.js]

// 1. API Xoá nhiều (Bulk Delete)
app.post('/api/promotions/bulk-delete', requireAuth, requireManager, async (req, res) => {
  try {
    const { ids } = req.body; // Mảng id: [1, 2, 3]
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ ok: false, error: 'Chưa chọn CTKM nào.' });
    }

    // Xoá các bảng phụ trước (nếu không setup CASCADE ở DB)
    await supabase.from('promotion_skus').delete().in('promotion_id', ids);
    await supabase.from('promotion_excluded_skus').delete().in('promotion_id', ids);

    // Xoá bảng chính
    const { error } = await supabase.from('promotions').delete().in('id', ids);
    if (error) throw error;

    res.json({ ok: true, message: `Đã xoá ${ids.length} CTKM.` });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// --- [UPDATED] MIDDLEWARE: Lấy thông báo (Có Log Debug & Lấy tin chung) ---
app.use(async (req, res, next) => {
  res.locals.notifications = [];
  res.locals.unreadCount = 0;

  // Chỉ chạy nếu user đã đăng nhập
  if (req.session && req.session.user) {
    const userEmail = req.session.user.email;

    // [DEBUG LOG] Xem server đang lọc theo user nào
    console.log(`>>> Checking notifications for: ${userEmail}`);

    try {
      // 1. Đếm số lượng chưa đọc
      // Logic: user_ref là email của user HOẶC là 'All' (tin chung)
      const { count, error: countError } = await supabase
        .from('notifications')
        .select('*', { count: 'exact', head: true })
        .or(`user_ref.eq.${userEmail},user_ref.eq.All`) // <--- QUAN TRỌNG: Lấy cả tin cho 'All'
        .eq('is_read', false);

      if (countError) console.error('Lỗi đếm notif:', countError.message);

      // 2. Lấy danh sách 4 thông báo mới nhất
      const { data: notifs, error: listError } = await supabase
        .from('notifications')
        .select('*')
        .or(`user_ref.eq.${userEmail},user_ref.eq.All`) // <--- QUAN TRỌNG
        .order('created_at', { ascending: false })
        .limit(4);

      if (listError) console.error('Lỗi lấy list notif:', listError.message);

      // [DEBUG LOG] Xem kết quả trả về có gì không
      if (notifs) {
        console.log(`>>> Found ${notifs.length} notifications. Unread: ${count}`);
      }

      if (!countError && !listError) {
        res.locals.unreadCount = count || 0;
        res.locals.notifications = notifs || [];
      }
    } catch (err) {
      console.error('CRITICAL ERROR Notif Middleware:', err.message);
    }
  }
  next();
});
// ------------------------- NOTIFICATION APIS -------------------------

// API: Đánh dấu 1 tin là đã đọc
// API: Đánh dấu 1 tin là đã đọc (Logic Mới)
app.post('/api/notifications/mark-read', requireAuth, async (req, res) => {
  const { id } = req.body;
  const userEmail = req.session.user.email;

  if (!id) return res.status(400).json({ error: 'Missing ID' });

  try {
    // Insert vào bảng lịch sử đọc
    // Dùng upsert để nếu đã có rồi thì không báo lỗi
    const { error } = await supabase
      .from('notification_reads')
      .upsert({
        notification_id: id,
        user_email: userEmail
      }, { onConflict: 'notification_id, user_email' });

    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    console.error("Lỗi mark read:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// API: Đánh dấu TẤT CẢ (Logic Mới - Hơi phức tạp hơn chút)
// --- [FIXED] API ĐÁNH DẤU TẤT CẢ LÀ ĐÃ ĐỌC ---
app.post('/api/notifications/mark-all-read', requireAuth, async (req, res) => {
  const userEmail = req.session.user.email;

  try {
    // 1. Lấy ID của TẤT CẢ thông báo dành cho user này (Riêng + All)
    const { data: allNotifs, error: fetchError } = await supabase
      .from('notifications')
      .select('id')
      .or(`user_ref.eq.${userEmail},user_ref.eq.All`);

    if (fetchError) throw fetchError;

    if (allNotifs && allNotifs.length > 0) {
      // 2. Chuẩn bị dữ liệu để Insert hàng loạt
      const readRecords = allNotifs.map(n => ({
        notification_id: n.id,
        user_email: userEmail,
        read_at: new Date()
      }));

      // 3. Thực hiện UPSERT (Chèn nếu chưa có, Bỏ qua nếu đã có)
      // Yêu cầu: DB phải có Constraint Unique(notification_id, user_email)
      const { error: insertError } = await supabase
        .from('notification_reads')
        .upsert(readRecords, {
          onConflict: 'notification_id, user_email', // Cột dùng để check trùng
          ignoreDuplicates: true // Nếu trùng thì bỏ qua, không báo lỗi
        });

      if (insertError) throw insertError;
    }

    res.json({ success: true });

  } catch (err) {
    console.error('Lỗi Mark All Read:', err.message);
    res.status(500).json({ error: err.message });
  }
});


// --- [NEW] Trang Xem Tất Cả Thông Báo ---
// --- [FIXED] Trang Tất Cả Thông Báo (Có đếm View Count) ---
app.get('/notifications', requireAuth, async (req, res) => {
  try {
    const userEmail = req.session.user.email;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 20;
    const from = (page - 1) * limit;
    const to = from + limit - 1;

    // Lấy tham số bộ lọc
    const filterStatus = req.query.status || 'all';
    const filterType = req.query.type || 'all';
    const filterTarget = req.query.target || 'all';

    // Lấy danh sách đã đọc của user
    const { data: readIdsData } = await supabase
      .from('notification_reads')
      .select('notification_id')
      .eq('user_email', userEmail);
    const readIds = readIdsData ? readIdsData.map(r => r.notification_id) : [];

    // Query chính
    let query = supabase.from('notifications').select('*', { count: 'exact' });

    // Áp dụng bộ lọc (Giữ nguyên logic cũ của bạn)
    if (filterTarget === 'mine') query = query.eq('user_ref', userEmail);
    else if (filterTarget === 'global') query = query.eq('user_ref', 'All');
    else query = query.or(`user_ref.eq.${userEmail},user_ref.eq.All`);

    if (filterType !== 'all') query = query.eq('type', filterType);

    if (filterStatus === 'read') {
      if (readIds.length === 0) query = query.in('id', [-1]);
      else query = query.in('id', readIds);
    } else if (filterStatus === 'unread') {
      if (readIds.length > 0) query = query.not('id', 'in', `(${readIds.join(',')})`);
    }

    // Thực thi query
    const { data: notifs, count, error } = await query
      .order('created_at', { ascending: false })
      .range(from, to);

    if (error) throw error;

    // [NEW] LOGIC ĐẾM VIEW CHO DANH SÁCH NÀY
    let notifsFinal = [];
    if (notifs && notifs.length > 0) {
      const notifIds = notifs.map(n => n.id);

      // Lấy tổng lượt đọc từ DB
      const { data: viewCounts } = await supabase
        .from('notification_reads')
        .select('notification_id')
        .in('notification_id', notifIds);

      const countMap = {};
      if (viewCounts) {
        viewCounts.forEach(r => {
          countMap[r.notification_id] = (countMap[r.notification_id] || 0) + 1;
        });
      }

      // Map dữ liệu view_count vào kết quả
      notifsFinal = notifs.map(n => ({
        ...n,
        is_read: readIds.includes(n.id),
        view_count: countMap[n.id] || 0 // <--- Có biến này thì EJS mới hiện mắt
      }));
    }

    res.render('notifications', {
      title: 'Tất cả thông báo',
      currentPage: 'notifications',
      notifications: notifsFinal,
      page,
      totalPages: Math.ceil((count || 0) / limit),
      time: res.locals.time,
      query: req.query
    });

  } catch (e) {
    console.error('Lỗi trang notifications:', e);
    res.redirect('/');
  }
});
// --- [NEW] TRANG GỬI THÔNG BÁO NHANH (ADMIN/MANAGER) ---

// 1. Hiển thị form soạn thông báo
app.get('/admin/send-notification', requireAuth, async (req, res) => {
  // Check quyền: Chỉ Admin hoặc Manager HCM.BD
  const user = req.session.user;
  if (user.role !== 'admin' && (user.role !== 'manager' || user.branch_code !== 'HCM.BD')) {
    return res.status(403).send('Bạn không có quyền truy cập.');
  }

  res.render('admin/send-notification', {
    title: 'Gửi thông báo hệ thống',
    currentPage: 'admin-tools',
    time: res.locals.time,
    user: user,
    error: null,
    success: null
  });
});

// 2. Xử lý gửi thông báo
app.post('/admin/send-notification', requireAuth, async (req, res) => {
  // Lấy thêm target_mode và target_emails từ form
  const { title, content, type, link, target_mode, target_emails } = req.body;

  try {
    if (!title || !content) throw new Error('Vui lòng nhập tiêu đề và nội dung.');

    // [FIXED] CHUYỂN ĐỔI DẤU XUỐNG DÒNG (\n) THÀNH THẺ <br>
    // Regex này bắt cả 3 kiểu xuống dòng: \r\n (Windows), \r (Mac cũ), \n (Linux/Unix)
    const formattedContent = content.replace(/\r\n|\r|\n/g, '<br>');

    let notificationsToInsert = [];

    // TRƯỜNG HỢP 1: Gửi cho Tất cả (All)
    if (target_mode === 'all') {
      notificationsToInsert.push({
        title,
        content: formattedContent, // <--- LƯU BIẾN ĐÃ FORMAT VÀO ĐÂY
        type: type || 'info',
        user_ref: 'All',
        link: link || null,
        is_read: false,
        created_at: new Date()
      });
    }

    // TRƯỜNG HỢP 2: Gửi theo Danh sách Email
    else if (target_mode === 'list') {
      if (!target_emails || target_emails.trim() === '') {
        throw new Error('Bạn chưa nhập danh sách email.');
      }

      // 1. Tách chuỗi thành mảng (hỗ trợ dấu phẩy, chấm phẩy, xuống dòng, khoảng trắng)
      const emailList = target_emails
        .split(/[\n,;\s]+/)            // Regex tách ký tự phân cách
        .map(e => e.trim())            // Xóa khoảng trắng thừa
        .filter(e => e.includes('@')); // Chỉ lấy chuỗi có chứ @ (là email)

      if (emailList.length === 0) {
        throw new Error('Danh sách email không hợp lệ.');
      }

      // 2. Tạo mảng object để insert 1 lần (Bulk Insert)
      notificationsToInsert = emailList.map(email => ({
        title,
        content: formattedContent,
        content,
        type: type || 'info',
        user_ref: email, // Gửi riêng cho email này
        link: link || null,
        is_read: false,
        created_at: new Date()
      }));
    }

    // THỰC HIỆN INSERT VÀO DB
    if (notificationsToInsert.length > 0) {
      const { error } = await supabase
        .from('notifications')
        .insert(notificationsToInsert);

      if (error) throw error;
    }

    // Render lại trang thành công
    const successMsg = target_mode === 'list'
      ? `Đã gửi thông báo đến ${notificationsToInsert.length} người dùng.`
      : 'Đã gửi thông báo toàn hệ thống thành công!';

    res.render('admin/send-notification', {
      title: 'Gửi thông báo hệ thống',
      currentPage: 'admin-tools',
      time: res.locals.time,
      user: req.session.user,
      error: null,
      success: successMsg
    });

  } catch (err) {
    res.render('admin/send-notification', {
      title: 'Gửi thông báo hệ thống',
      currentPage: 'admin-tools',
      time: res.locals.time,
      user: req.session.user,
      error: err.message,
      success: null
    });
  }
});



// --- [HELPER] Lấy chỉ số CSI từ View đã Map (CẬP NHẬT LOGIC VALUE MỚI) ---
// --- [HELPER] Lấy chỉ số CSI (PHIÊN BẢN FIX LỖI DATA RÁC) ---
// ==========================================
// GOOGLE SHEETS CSI FALLBACK
// ==========================================
const CSI_SHEET_ID = '1ArSb_yXETKWKdXfODGSFzBh24RISwrpg5C0asWVxhwg';
const CSI_RANGE = 'A2:AB';
let csiSheetCache = null;
let csiSheetCacheTime = 0;

async function fetchCSISheetData() {
  if (csiSheetCache && Date.now() - csiSheetCacheTime < 3600000) return csiSheetCache;
  const sheets = await getGlobalSheetsClient();
  const meta = await sheets.spreadsheets.get({ spreadsheetId: CSI_SHEET_ID });
  let dataRows = [];

  for (let s of meta.data.sheets) {
    const sheetName = s.properties.title;
    try {
      const res = await sheets.spreadsheets.values.get({ spreadsheetId: CSI_SHEET_ID, range: `'${sheetName}'!${CSI_RANGE}` });
      if (res.data.values) {
        dataRows = dataRows.concat(res.data.values);
      }
    } catch (e) {
      console.error("Error reading sheet:", sheetName, e);
    }
  }
  csiSheetCache = dataRows;
  csiSheetCacheTime = Date.now();
  return csiSheetCache;
}

function checkBranchMatch(rowBranch, filterBranch, period) {
  if (!filterBranch) return true;
  if (!rowBranch) return false;
  const rB = rowBranch.toLowerCase().trim();
  const fB = filterBranch.toLowerCase().trim();
  if (rB === fB) return true;

  if (fB === 'cp75') {
    if (period) {
      const periodStr = String(period).trim();
      const monthMatch = periodStr.match(/^2026-(\d{2})$/);
      if (monthMatch) {
        const monthVal = parseInt(monthMatch[1], 10);
        if (monthVal <= 5) {
          return rB === 'cp62';
        } else if (monthVal === 6) {
          return rB === 'cp62' || rB === 'cp75';
        } else {
          return rB === 'cp75';
        }
      } else if (periodStr === '2026-' || periodStr === '2026') {
        return rB === 'cp62' || rB === 'cp75';
      }
    }
    const currentMonth = new Date().getMonth() + 1;
    const currentYear = new Date().getFullYear();
    if (currentYear === 2026) {
      if (currentMonth <= 5) {
        return rB === 'cp62';
      } else if (currentMonth === 6) {
        return rB === 'cp62' || rB === 'cp75';
      }
    }
  }
  return false;
}

async function getCsiStats(options) {
  const data = await fetchCSISheetData();
  let totalBonusScore = 0;
  let standardScore = 0;
  let feedbackCount = 0;

  data.forEach((row) => {
    if (!row[1]) return;
    const dateStr = (row[1] || '').trim();

    // Date filter
    if (options.period) {
      if (options.period === 'today') {
        const d = new Date().toISOString().split('T')[0];
        if (dateStr !== d) return;
      } else if (/^\d{4}-\d{2}$/.test(options.period)) {
        const [py, pm] = options.period.split('-');
        const tSub = pm + '/' + py;
        if (!dateStr.includes(tSub)) return;
      }
    }

    // [FIX] Email filter cho staff - so khớp theo cột email (cột 6) hoặc tên NV (cột 5)
    // Khi có email filter (staff cá nhân), bỏ qua branch filter vì email đã đủ identify
    if (options.email) {
      const rowEmail = (row[6] || '').toLowerCase().trim();
      const rowName = (row[5] || '').toLowerCase().trim();
      const filterEmail = options.email.toLowerCase().trim();
      // Nếu cột 6 có dấu '@' → đây là cột email, so sánh trực tiếp
      if (rowEmail.includes('@')) {
        if (rowEmail !== filterEmail) return;
      } else if (options._staffName) {
        // Fallback: so sánh theo tên nhân viên
        if (!rowName.includes(options._staffName.toLowerCase())) return;
      }
    } else {
      // Branch filter chỉ áp dụng khi KHÔNG có email filter (xem theo chi nhánh)
      const branch = (row[4] || '').trim();
      if (options.branch) {
        if (!checkBranchMatch(branch, options.branch, options.period)) return;
      }
    }

    // Count feedback (col 19 = Góp ý)
    const fb = (row[19] || '').trim();
    if (fb !== '') {
      feedbackCount++;
    }

    // Valid survey: col[12] starts with "1.Đồng ý KS" AND col[24] = "6"
    const callRecord = (row[12] || '').trim();
    const checkCol = (row[24] || '').trim();
    if (!callRecord.startsWith('1.Đồng ý KS') || checkCol !== '6') return;

    // This is a valid survey — add base score of 3
    standardScore += 3;

    // Weighted scoring per question
    const q13 = (row[13] || '').trim(); // Chào hỏi
    const q14 = (row[14] || '').trim(); // Tư vấn
    const q15 = (row[15] || '').trim(); // Lựa chọn
    const q16 = (row[16] || '').trim(); // Sản phẩm
    const q17 = (row[17] || '').trim(); // Giới thiệu
    const q18 = (row[18] || '').trim(); // Zalo/App

    // Score per question: positive=+3, negative=-3, neutral=+1
    function scoreQ(val, pos, neg) {
      if (val.startsWith(pos)) return 3;
      if (val.startsWith(neg)) return -3;
      return 1;
    }

    const s_greeting = scoreQ(q13, 'Có', 'Không') * 0.05;
    const s_advice = (q14.includes('Tốt') ? 3 : q14.startsWith('Tệ') ? -3 : 1) * 0.30;
    const s_choice = scoreQ(q15, 'Có', 'Không') * 0.15;
    const s_satisfaction = scoreQ(q16, 'Có', 'Không') * 0.30;
    const s_referral = (q17.startsWith('Sẵn sàng') ? 3 : q17.startsWith('Không') ? -3 : 1) * 0.15;
    const s_zalo = scoreQ(q18, 'Có', 'Không') * 0.05;

    totalBonusScore += s_greeting + s_advice + s_choice + s_satisfaction + s_referral + s_zalo;
  });

  const csi_percent = standardScore > 0 ? (totalBonusScore / standardScore) * 100 : 0;
  return { csi_percent: csi_percent.toFixed(1), feedback_count: feedbackCount };
}

// Helper: tính %CSI cho danh sách nhiều nhân viên (batch, 1 lần fetch cache)
async function getCsiPerStaff(staffList, period) {
  const data = await fetchCSISheetData();

  // Build lookup: email -> { totalBonus, standard }
  const perStaff = {};
  staffList.forEach(s => {
    const key = (s.email || '').toLowerCase().trim();
    if (key) perStaff[key] = { totalBonusScore: 0, standardScore: 0, name: (s.full_name || '').toLowerCase().trim() };
  });

  // Period filter helper
  function matchPeriod(dateStr) {
    if (!period) return true;
    if (period === 'today') return dateStr === new Date().toISOString().split('T')[0];
    if (/^\d{4}-\d{2}$/.test(period)) {
      const [py, pm] = period.split('-');
      return dateStr.includes(pm + '/' + py);
    }
    if (period.endsWith('-')) {
      const yr = period.replace(/-$/, '');
      return dateStr.includes('/' + yr);
    }
    return true;
  }

  data.forEach(row => {
    if (!row[1]) return;
    if (!matchPeriod((row[1] || '').trim())) return;

    // Valid survey check
    const callRecord = (row[12] || '').trim();
    const checkCol = (row[24] || '').trim();

    const rowEmail = (row[6] || '').toLowerCase().trim();
    const rowName = (row[5] || '').toLowerCase().trim();

    // Match to staff
    let staffKey = null;
    if (rowEmail.includes('@')) {
      if (perStaff[rowEmail]) staffKey = rowEmail;
    } else {
      // fallback by name
      for (const [k, v] of Object.entries(perStaff)) {
        if (v.name && rowName.includes(v.name)) { staffKey = k; break; }
      }
    }
    if (!staffKey) return;

    // Count all rows toward feedback (col 19)
    // Only count valid surveys for score
    if (!callRecord.startsWith('1.Đồng ý KS') || checkCol !== '6') return;

    perStaff[staffKey].standardScore += 3;

    const q13 = (row[13] || '').trim();
    const q14 = (row[14] || '').trim();
    const q15 = (row[15] || '').trim();
    const q16 = (row[16] || '').trim();
    const q17 = (row[17] || '').trim();
    const q18 = (row[18] || '').trim();

    function scoreQ(val, pos, neg) {
      if (val.startsWith(pos)) return 3;
      if (val.startsWith(neg)) return -3;
      return 1;
    }

    perStaff[staffKey].totalBonusScore +=
      scoreQ(q13, 'Có', 'Không') * 0.05 +
      (q14.includes('Tốt') ? 3 : q14.startsWith('Tệ') ? -3 : 1) * 0.30 +
      scoreQ(q15, 'Có', 'Không') * 0.15 +
      scoreQ(q16, 'Có', 'Không') * 0.30 +
      (q17.startsWith('Sẵn sàng') ? 3 : q17.startsWith('Không') ? -3 : 1) * 0.15 +
      scoreQ(q18, 'Có', 'Không') * 0.05;
  });

  // Build result map: email -> csi_percent string
  const result = {};
  for (const [email, s] of Object.entries(perStaff)) {
    result[email] = s.standardScore > 0
      ? ((s.totalBonusScore / s.standardScore) * 100).toFixed(1)
      : null;
  }
  return result;
}

async function getFeedbackList(options) {
  const data = await fetchCSISheetData();
  const list = [];
  data.forEach((row) => {
    if (!row[1]) return;
    const dateStr = row[1];

    if (options.period) {
      if (options.period === 'today') {
        const d = new Date().toISOString().split('T')[0];
        if (dateStr !== d) return;
      } else if (/^\d{4}-\d{2}$/.test(options.period)) {
        const [py, pm] = options.period.split('-');
        const tSub = pm + '/' + py;
        if (!dateStr.includes(tSub)) return;
      }
    }

    // [FIX] Email filter cho staff - khi có email, bỏ qua branch filter vì email đã đủ identify
    if (options.email) {
      const rowEmail = (row[6] || '').toLowerCase().trim();
      const filterEmail = options.email.toLowerCase().trim();
      if (rowEmail.includes('@')) {
        if (rowEmail !== filterEmail) return;
      } else if (options._staffName) {
        const rowName = (row[5] || '').toLowerCase().trim();
        if (!rowName.includes(options._staffName.toLowerCase())) return;
      }
    } else {
      // Branch filter chỉ áp dụng khi KHÔNG có email filter
      const branch = row[4];
      if (options.branch) {
        if (!checkBranchMatch(branch, options.branch, options.period)) return;
      }
    }

    const fb = (row[19] || '').trim();
    if (fb.length > 1) {
      list.push({
        Ngay_mua_hang: row[7] || row[1] || '',
        Nguoi_mua: row[8] || 'Khách',
        SDT: row[9] || '',
        Ma_SR: row[4] || '',
        Ten_NV_Ban_hang: row[5] || '',
        Gop_y: fb,
        Ghi_chu: row[22] || ''
      });
    }
  });

  // [FIX] Sort theo ngày mua giảm dần (mới nhất trước)
  list.sort((a, b) => {
    const parseDate = (s) => {
      if (!s) return new Date(0);
      // Format DD/MM/YYYY
      if (s.includes('/')) {
        const parts = s.split('/');
        if (parts.length === 3) return new Date(parts[2], parts[1] - 1, parts[0]);
      }
      // Format YYYY-MM-DD
      return new Date(s);
    };
    return parseDate(b.Ngay_mua_hang) - parseDate(a.Ngay_mua_hang);
  });

  return list;
}
// ======================= SALES DASHBOARD =======================

// Helper: determine which terminal_codes a user can see
function getAllowedTerminals(user, allTerminals) {
  if (!user) return [];
  if (user.role !== 'manager' && user.role !== 'admin') return [];
  const branch = user.branch_code;
  if (!branch || branch === 'HCM.BD') return null; // null = all
  // Map branch_code → terminal codes (e.g. CP01, CP02…)
  // terminals whose terminal_code starts with the branch_code or equals it
  return allTerminals.filter(t => t === branch || t.startsWith(branch));
}

// GET /sales-dashboard — render page (manager/admin only)
app.get('/sales-dashboard', requireAuth, (req, res) => {
  const user = req.session.user;
  if (user.role !== 'manager' && user.role !== 'admin') {
    return res.status(403).send('Chỉ Manager/Admin mới có quyền xem trang này.');
  }
  res.render('sales-dashboard', {
    title: 'Dashboard Doanh Thu Realtime',
    currentPage: 'sales-dashboard',
  });
});

// ===================== TERMINAL MAPPINGS =====================
// terminal_code column is NULL in Supabase; map by terminal_name
const TERMINAL_CODE_MAP = {
  '264A-264B-264C Nguyễn Thị Minh Khai,Phường 6': 'CP01',
  'Số 408 đại lộ Bình Dương, Phường Phú Lợi': 'CP02',
  '1081C Hậu Giang, Phường 11': 'CP05',
  'Số 9-11 Nguyễn Thị Thập, Phường Tân Phú': 'CP07',
  'Số 2A, Đường Nguyễn Oanh, Phường 7': 'CP08',
  'Showroom Hoàng Hoa Thám': 'CP40',
  '164 Lê Văn Việt, Tăng Nhơn Phú B, TP.Thủ Đức': 'CP46',
  'ĐỊA ĐIỂM KINH DOANH 52 - CÔNG TY CỔ PHẦN THƯƠNG MẠI - DỊCH VỤ PHONG VŨ': 'CP58',
  'ĐỊA ĐIỂM KINH DOANH 39 - CÔNG TY CỔ PHẦN THƯƠNG MẠI - DỊCH VỤ PHONG VŨ': 'CP62',
  'ĐỊA ĐIỂM KINH DOANH 54 - CÔNG TY CỔ PHẦN THƯƠNG MẠI - DỊCH VỤ PHONG VŨ': 'CP64',
  'ĐỊA ĐIỂM KINH DOANH 57 - CÔNG TY CỔ PHẦN THƯƠNG MẠI - DỊCH VỤ PHONG VŨ': 'CP67',
  'CH Bình Dương 2': 'CP69',
  'ĐỊA ĐIỂM KINH DOANH 63 - CÔNG TY CỔ PHẦN THƯƠNG MẠI - DỊCH VỤ PHONG VŨ': 'CP75',
};
// Mapping từ branch_code/terminal_code → terminal_names mà branch đó quản lý
// Admin và HCM.BD xem tất cả; các branch khác chỉ xem cửa hàng của mình
const BRANCH_TERMINALS = {
  'CP01': ['264A-264B-264C Nguyễn Thị Minh Khai,Phường 6'],
  'CP02': ['Số 408 đại lộ Bình Dương, Phường Phú Lợi'],
  'CP05': ['1081C Hậu Giang, Phường 11'],
  'CP07': ['Số 9-11 Nguyễn Thị Thập, Phường Tân Phú'],
  'CP08': ['Số 2A, Đường Nguyễn Oanh, Phường 7'],
  'CP40': ['Showroom Hoàng Hoa Thám'],
  'CP46': ['164 Lê Văn Việt, Tăng Nhơn Phú B, TP.Thủ Đức'],
  'CP58': ['ĐỊA ĐIỂM KINH DOANH 52 - CÔNG TY CỔ PHẦN THƯƠNG MẠI - DỊCH VỤ PHONG VŨ'],
  'CP62': ['ĐỊA ĐIỂM KINH DOANH 39 - CÔNG TY CỔ PHẦN THƯƠNG MẠI - DỊCH VỤ PHONG VŨ'],
  'CP64': ['ĐỊA ĐIỂM KINH DOANH 54 - CÔNG TY CỔ PHẦN THƯƠNG MẠI - DỊCH VỤ PHONG VŨ'],
  'CP67': ['ĐỊA ĐIỂM KINH DOANH 57 - CÔNG TY CỔ PHẦN THƯƠNG MẠI - DỊCH VỤ PHONG VŨ'],
  'CP69': ['CH Bình Dương 2'],
  'CP75': ['ĐỊA ĐIỂM KINH DOANH 63 - CÔNG TY CỔ PHẦN THƯƠNG MẠI - DỊCH VỤ PHONG VŨ'],
};
// Helper: apply terminal_name filter cho non-admin/non-allbranch queries
function applyTerminalFilter(query, branch, isAllBranch) {
  if (isAllBranch) return query;
  const names = BRANCH_TERMINALS[branch];
  if (names && names.length === 1) return query.eq('terminal_name', names[0]);
  if (names && names.length > 1) return query.in('terminal_name', names);
  // Unknown branch → return nothing by filtering impossible value
  return query.eq('terminal_name', '__NO_MATCH__');
}

// GET /api/sales/summary — today totals + yesterday + last-week-same-day comparisons
app.get('/api/sales/summary', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    if (user.role !== 'manager' && user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

    const now = new Date();
    // Business dates (Vietnam timezone +7)
    const localNow = new Date(now.getTime() + 7 * 3600000);
    const todayStr = localNow.toISOString().slice(0, 10);
    const yestDate = new Date(localNow); yestDate.setDate(yestDate.getDate() - 1);
    const yestStr = yestDate.toISOString().slice(0, 10);
    const lwDate = new Date(localNow); lwDate.setDate(lwDate.getDate() - 7);
    const lwStr = lwDate.toISOString().slice(0, 10);

    const branch = user.branch_code;
    const isAllBranch = user.role === 'admin' || !branch || branch === 'HCM.BD';

    // --- TODAY: pv_terminal_sales_snapshots compare_bucket='today' ---
    // Loại bỏ row tổng hợp 'Tất cả điểm bán'
    let snapQuery = supabase
      .from('pv_terminal_sales_snapshots')
      .select('terminal_name, order_count, revenue_k, snapshot_at')
      .eq('business_date', todayStr)
      .eq('compare_bucket', 'today')
      .neq('terminal_name', 'Tất cả điểm bán')
      .order('snapshot_at', { ascending: false });
    snapQuery = applyTerminalFilter(snapQuery, branch, isAllBranch);

    const { data: snapAll, error: snapErr } = await snapQuery;
    if (snapErr) console.error('[sales/summary] snapErr:', snapErr.message);

    // Key by terminal_name (terminal_code is NULL in Supabase)
    const latestSnap = {};
    (snapAll || []).forEach(r => {
      if (!latestSnap[r.terminal_name] || r.snapshot_at > latestSnap[r.terminal_name].snapshot_at) {
        latestSnap[r.terminal_name] = r;
      }
    });
    const todayRows = Object.values(latestSnap);
    // revenue_k lưu VND thô, chia 1,000,000 ra triệu VND
    const today_revenue_m = todayRows.reduce((s, r) => s + (Number(r.revenue_k) / 1000000), 0);
    const today_orders = todayRows.reduce((s, r) => s + Number(r.order_count || 0), 0);
    console.log(`[sales/summary] today=${todayStr} stores=${todayRows.length} rev_m=${today_revenue_m.toFixed(1)} orders=${today_orders}`);

    // --- YESTERDAY: pv_terminal_sales_snapshots compare_bucket='yesterday' ---
    // Cùng bảng snapshot, cùng business_date=today, nhưng bucket='yesterday'
    let yestQuery = supabase
      .from('pv_terminal_sales_snapshots')
      .select('terminal_name, order_count, revenue_k, snapshot_at')
      .eq('business_date', todayStr)
      .eq('compare_bucket', 'yesterday')
      .neq('terminal_name', 'Tất cả điểm bán')
      .order('snapshot_at', { ascending: false });
    yestQuery = applyTerminalFilter(yestQuery, branch, isAllBranch);
    const { data: yestSnapAll, error: yestErr } = await yestQuery;
    if (yestErr) console.error('[sales/summary] yestErr:', yestErr.message);
    // Latest snapshot per terminal for yesterday bucket
    const yestLatest = {};
    (yestSnapAll || []).forEach(r => {
      if (!yestLatest[r.terminal_name] || r.snapshot_at > yestLatest[r.terminal_name].snapshot_at) yestLatest[r.terminal_name] = r;
    });
    const yestRows2 = Object.values(yestLatest);
    const yest_revenue_m = yestRows2.reduce((s, r) => s + (Number(r.revenue_k) / 1000000), 0);
    const yest_orders = yestRows2.reduce((s, r) => s + Number(r.order_count || 0), 0);
    console.log(`[sales/summary] yesterday stores=${yestRows2.length} rev_m=${yest_revenue_m.toFixed(1)}`);

    // --- LAST WEEK SAME DAY: pv_terminal_sales_snapshots compare_bucket='last_week_same_day' ---
    let lwQuery = supabase
      .from('pv_terminal_sales_snapshots')
      .select('terminal_name, order_count, revenue_k, snapshot_at')
      .eq('business_date', todayStr)
      .eq('compare_bucket', 'last_week_same_day')
      .neq('terminal_name', 'Tất cả điểm bán')
      .order('snapshot_at', { ascending: false });
    lwQuery = applyTerminalFilter(lwQuery, branch, isAllBranch);
    const { data: lwSnapAll, error: lwErr } = await lwQuery;
    if (lwErr) console.error('[sales/summary] lwErr:', lwErr.message);
    const lwLatest = {};
    (lwSnapAll || []).forEach(r => {
      if (!lwLatest[r.terminal_name] || r.snapshot_at > lwLatest[r.terminal_name].snapshot_at) lwLatest[r.terminal_name] = r;
    });
    const lwRows2 = Object.values(lwLatest);
    const lw_revenue_m = lwRows2.reduce((s, r) => s + (Number(r.revenue_k) / 1000000), 0);
    const lw_orders = lwRows2.reduce((s, r) => s + Number(r.order_count || 0), 0);
    console.log(`[sales/summary] lw_same_day stores=${lwRows2.length} rev_m=${lw_revenue_m.toFixed(1)}`);

    // --- MONTHLY TARGET ---
    const monthCol = `m${String(localNow.getMonth() + 1).padStart(2, '0')}`;
    let tgtQuery = supabase.from('pv_terminal_monthly_targets').select(`terminal_code, ${monthCol}`);
    if (!isAllBranch) tgtQuery = tgtQuery.eq('terminal_code', branch);
    const { data: tgtRows } = await tgtQuery;
    const daysInMonth = new Date(localNow.getFullYear(), localNow.getMonth() + 1, 0).getDate();
    const totalMonthlyTarget = (tgtRows || []).reduce((s, r) => s + Number(r[monthCol] || 0), 0);
    const today_target_m = totalMonthlyTarget > 0 ? totalMonthlyTarget / daysInMonth : null;

    res.json({
      today_revenue_m: Math.round(today_revenue_m * 10) / 10,
      today_orders,
      today_target_m: today_target_m ? Math.round(today_target_m * 10) / 10 : null,
      yest_revenue_m: Math.round(yest_revenue_m * 10) / 10,
      yest_orders,
      yest_target_m: today_target_m ? Math.round(today_target_m * 10) / 10 : null,
      yest_date: yestDate.toLocaleDateString('vi-VN'),
      lw_revenue_m: Math.round(lw_revenue_m * 10) / 10,
      lw_orders,
      lw_target_m: today_target_m ? Math.round(today_target_m * 10) / 10 : null,
      lw_date: lwDate.toLocaleDateString('vi-VN'),
      _debug: { todayStr, todayStores: todayRows.length, yestStores: yestRows2.length, lwStores: lwRows2.length, monthCol, totalMonthlyTarget, branch, isAllBranch }
    });
  } catch (e) {
    console.error('[sales/summary]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/sales/chart — per-store daily revenue for selected period
app.get('/api/sales/chart', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    if (user.role !== 'manager' && user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

    const period = req.query.period || '1w';
    const now = new Date();
    const localNow = new Date(now.getTime() + 7 * 3600000);
    const todayStr = localNow.toISOString().slice(0, 10);
    const yestStr = new Date(localNow.getTime() - 86400000).toISOString().slice(0, 10);

    let daysBack = 7;
    if (period === '2w') daysBack = 14;
    else if (period === '1m') daysBack = 30;
    else if (period === '1q') daysBack = 90;
    else if (period === '1y') daysBack = 365;

    const fromDate = new Date(localNow);
    fromDate.setDate(fromDate.getDate() - daysBack + 1);
    const fromStr = fromDate.toISOString().slice(0, 10);

    const branch = user.branch_code;
    const isAllBranch = user.role === 'admin' || !branch || branch === 'HCM.BD';

    // daily_final: lấy data chốt của từng ngày (compare_bucket='today' = data thực của ngày đó)
    let query = supabase
      .from('pv_terminal_sales_daily_final')
      .select('business_date, terminal_name, revenue_k')
      .eq('compare_bucket', 'today')
      .gte('business_date', fromStr)
      .lte('business_date', yestStr)
      .neq('terminal_name', 'Tất cả điểm bán')
      .order('business_date', { ascending: true });
    query = applyTerminalFilter(query, branch, isAllBranch);

    const { data: finalRows, error: chartErr } = await query;
    if (chartErr) console.error('[sales/chart] err:', chartErr.message);

    // Hôm nay → lấy từ snapshots compare_bucket='today'
    let todayByTerminal = {};
    if (fromStr <= todayStr) {
      let snapQ = supabase
        .from('pv_terminal_sales_snapshots')
        .select('terminal_name, revenue_k, snapshot_at')
        .eq('business_date', todayStr)
        .eq('compare_bucket', 'today')
        .neq('terminal_name', 'Tất cả điểm bán')
        .order('snapshot_at', { ascending: false });
      snapQ = applyTerminalFilter(snapQ, branch, isAllBranch);
      const { data: todaySnaps } = await snapQ;
      (todaySnaps || []).forEach(r => {
        if (!todayByTerminal[r.terminal_name] || r.snapshot_at > todayByTerminal[r.terminal_name].snapshot_at) {
          todayByTerminal[r.terminal_name] = r;
        }
      });
    }

    // Build date labels
    const labels = [];
    const cur = new Date(fromDate);
    while (cur.toISOString().slice(0, 10) <= todayStr) {
      labels.push(cur.toISOString().slice(0, 10));
      cur.setDate(cur.getDate() + 1);
    }

    // Group by terminal_name from daily_final (terminal_code may be valid here)
    const storeMap = {};
    (finalRows || []).forEach(r => {
      const key = r.terminal_name || r.terminal_code || '?';
      if (!storeMap[key]) {
        storeMap[key] = { name: key, byDate: {} };
      }
      storeMap[key].byDate[r.business_date] = Math.round(Number(r.revenue_k) / 1000000 * 10) / 10;
    });

    // Merge today's snapshot data (keyed by terminal_name)
    Object.entries(todayByTerminal).forEach(([name, r]) => {
      if (!storeMap[name]) storeMap[name] = { name, byDate: {} };
      storeMap[name].byDate[todayStr] = Math.round(Number(r.revenue_k) / 1000000 * 10) / 10;
    });

    const stores = Object.values(storeMap).map(s => ({
      name: TERMINAL_CODE_MAP[s.name] || s.name,
      data: labels.map(d => s.byDate[d] ?? null),
    }));

    const displayLabels = labels.map(d => {
      const dt = new Date(d + 'T00:00:00');
      return dt.toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit' });
    });

    res.json({ labels: displayLabels, stores });
  } catch (e) {
    console.error('[sales/chart]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/sales/stores — per-store table with today data + target
app.get('/api/sales/stores', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    if (user.role !== 'manager' && user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

    const now = new Date();
    const localNow = new Date(now.getTime() + 7 * 3600000);
    const todayStr = localNow.toISOString().slice(0, 10);
    const branch = user.branch_code;
    const isAllBranch = user.role === 'admin' || !branch || branch === 'HCM.BD';

    // Snapshot mới nhất của từng terminal, compare_bucket='today'
    // Loại bỏ row tổng hợp 'Tất cả điểm bán'
    let snapQuery = supabase
      .from('pv_terminal_sales_snapshots')
      .select('terminal_name, order_count, revenue_k, snapshot_at')
      .eq('business_date', todayStr)
      .eq('compare_bucket', 'today')
      .neq('terminal_name', 'Tất cả điểm bán')
      .order('snapshot_at', { ascending: false });
    snapQuery = applyTerminalFilter(snapQuery, branch, isAllBranch);

    const { data: snapAll, error: storeSnapErr } = await snapQuery;
    if (storeSnapErr) console.error('[sales/stores] snapErr:', storeSnapErr.message);

    // Dedup by terminal_name (terminal_code is NULL in snapshots table)
    const latestSnap = {};
    (snapAll || []).forEach(r => {
      if (!latestSnap[r.terminal_name] || r.snapshot_at > latestSnap[r.terminal_name].snapshot_at) {
        latestSnap[r.terminal_name] = r;
      }
    });
    console.log(`[sales/stores] today=${todayStr} terminals=${Object.keys(latestSnap).length}`);

    // Monthly targets (đơn vị triệu VND)
    const monthCol = `m${String(localNow.getMonth() + 1).padStart(2, '0')}`;
    // Lấy terminal_name từ targets để join với snapshot bằng tên (terminal_code NULL trong snapshots)
    let tgtQuery = supabase.from('pv_terminal_monthly_targets').select(`terminal_code, terminal_name, ${monthCol}`);
    // Không filter theo branch ở đây – filter đã được xử lý ở snapshot
    const { data: tgtRows } = await tgtQuery;
    const daysInMonth = new Date(localNow.getFullYear(), localNow.getMonth() + 1, 0).getDate();
    // tgtMap keyed by terminal_name để join với snapshot
    const tgtMap = {};
    // codeMap: terminal_name → terminal_code (từ bảng targets – nguồn chính xác)
    const codeFromTargets = {};
    (tgtRows || []).forEach(r => {
      const monthly = Number(r[monthCol] || 0);
      tgtMap[r.terminal_name] = monthly > 0 ? Math.round(monthly / daysInMonth * 10) / 10 : null;
      if (r.terminal_code) codeFromTargets[r.terminal_name] = r.terminal_code;
    });

    const stores = Object.values(latestSnap).map(r => {
      // Lấy terminal_code: ưu tiên từ bảng targets (chính xác), fallback từ TERMINAL_CODE_MAP
      const code = codeFromTargets[r.terminal_name] || TERMINAL_CODE_MAP[r.terminal_name] || '?';
      return {
        terminal_code: code,
        terminal_name: r.terminal_name,
        order_count: Number(r.order_count || 0),
        revenue_m: Math.round(Number(r.revenue_k) / 1000000 * 10) / 10,
        target_m: tgtMap[r.terminal_name] ?? null,
      };
    }).sort((a, b) => b.revenue_m - a.revenue_m);

    res.json({ stores, updated_at: new Date().toISOString() });
  } catch (e) {
    console.error('[sales/stores]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ======================= END SALES DASHBOARD =======================

// ------------------------- EXECUTIVE DASHBOARD -------------------------
app.get('/executive-dashboard', requireAuth, async (req, res) => {
  const user = req.session.user;
  if (user.role !== 'manager' && user.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
  const isGlobalAdmin = user.role === 'admin' || user.branch_code === 'HCM.BD';
  const userRegion = EXECUTIVE_BRANCH_LIST.find(b => b.id === user.branch_code)?.region || 'ALL';

  res.render('executive-dashboard', {
    user: req.session.user,
    isGlobalAdmin,
    userRegion,
    userBranch: user.branch_code
  });
});

// GET /api/executive/sales-data - Dynamic logic with Traffic, 4-Delta, and Trend Generation
app.get('/api/executive/sales-data', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    if (user.role !== 'manager' && user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

    const { period = 'month', category = 'ALL', region = 'ALL', branch = 'ALL', date = null, endDate = null, tableCategory = 'ALL' } = req.query;
    const ranges = getDashboardDateRange(period, date, endDate);

    const minS = ranges.ly.s, currE = ranges.curr.e;
    let globalWhere = `WHERE (CAST(Report_date AS DATE) BETWEEN '${minS}' AND '${currE}')`;
    if (category !== 'ALL') globalWhere += ` AND Category_Code = '${category}'`;

    // FIX: tableCategory uses Cat_group_ID column (format NHxx)
    let tableWhere = `WHERE (CAST(Report_date AS DATE) BETWEEN '${minS}' AND '${currE}')`;
    if (tableCategory === 'CUSTOM_1') {
      tableWhere += ` AND Cat_group_ID IN ('NH01', 'NH02', 'NH03', 'NH05')`;
    } else if (tableCategory !== 'ALL') {
      tableWhere += ` AND Cat_group_ID = '${tableCategory}'`;
    }

    // Explicit Branch or Region Filter applied to both
    let filterBranches = EXECUTIVE_BRANCH_LIST.map(b => b.id);
    // Role-based branch restriction: manager only sees their own branch
    const isGlobalAdmin = user.role === 'admin' || user.branch_code === 'HCM.BD';
    if (!isGlobalAdmin && user.branch_code) {
      // Manager can only see their branch; override region/branch params
      filterBranches = [user.branch_code];
      globalWhere += ` AND Branch_Code = '${user.branch_code}'`;
      tableWhere += ` AND Branch_Code = '${user.branch_code}'`;
    } else if (branch !== 'ALL') {
      globalWhere += ` AND Branch_Code = '${branch}'`;
      tableWhere += ` AND Branch_Code = '${branch}'`;
      filterBranches = [branch];
    } else if (region !== 'ALL') {
      const regB = EXECUTIVE_BRANCH_LIST.filter(b => b.region === region).map(b => b.id);
      globalWhere += ` AND Branch_Code IN (${regB.map(id => `'${id}'`).join(',')})`;
      tableWhere += ` AND Branch_Code IN (${regB.map(id => `'${id}'`).join(',')})`;
      filterBranches = regB;
    } else {
      globalWhere += ` AND Branch_Code IN (${filterBranches.map(id => `'${id}'`).join(',')})`;
      tableWhere += ` AND Branch_Code IN (${filterBranches.map(id => `'${id}'`).join(',')})`;
    }

    const bqQueryGlobal = `SELECT Branch_Code as branch, CAST(Report_date AS DATE) as date, SUM(Revenue) as revenue, SUM(Quantity) as quantity, COUNT(DISTINCT CASE WHEN Order_type = 'don_xuat_ban' THEN Order_code END) - COUNT(DISTINCT CASE WHEN Order_type = 'don_nhap_hoan_ban' THEN Order_code END) as orders FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\` ${globalWhere} GROUP BY branch, date ORDER BY date ASC`;
    const bqQueryTable = `SELECT Branch_Code as branch, CAST(Report_date AS DATE) as date, SUM(Revenue) as revenue, SUM(Quantity) as quantity, COUNT(DISTINCT CASE WHEN Order_type = 'don_xuat_ban' THEN Order_code END) - COUNT(DISTINCT CASE WHEN Order_type = 'don_nhap_hoan_ban' THEN Order_code END) as orders FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\` ${tableWhere} GROUP BY branch, date ORDER BY date ASC`;

    // FIX: always run table query separately when tableCategory differs from category
    const needSeparateTableQuery = tableCategory !== category || tableCategory !== 'ALL';
    const [globalRes, tableRes, traffic] = await Promise.all([
      bigquery.query({ query: bqQueryGlobal }),
      needSeparateTableQuery ? bigquery.query({ query: bqQueryTable }) : Promise.resolve(null),
      fetchTrafficStats(ranges)
    ]);

    const globalRows = globalRes[0];
    const tableRows = tableRes ? tableRes[0] : globalRows;

    // Fetch master targets mapping globally 
    const monthCol = `m${String(new Date(ranges.curr.rawS).getMonth() + 1).padStart(2, '0')}`;
    const { data: tgtRows } = await supabase.from('pv_terminal_monthly_targets').select(`terminal_code, ${monthCol}`);
    const targets = {};
    const currDiffDays = Math.round((ranges.curr.rawE - ranges.curr.rawS) / 86400000) + 1;
    const daysInMonth = new Date(ranges.curr.rawS.getFullYear(), ranges.curr.rawS.getMonth() + 1, 0).getDate();
    const periodProportion = currDiffDays / daysInMonth; // Scale target proportionally
    (tgtRows || []).forEach(r => targets[r.terminal_code] = Number(r[monthCol] || 0) * 1000000 * periodProportion);

    // Create parsing helper for creating branch structures
    const processRows = (rowsData) => {
      const struct = filterBranches.map(code => {
        const inf = EXECUTIVE_BRANCH_LIST.find(b => b.id === code) || {};
        const trMap = traffic && traffic[code] ? traffic[code] : { curr: 0, prev: 0, lw: 0, lm: 0, lq: 0, ly: 0 };
        const m = { r: 0, o: 0, q: 0, t: trMap.curr };
        return {
          id: code, name: inf.name, region: inf.region, target: targets[code],
          data: {
            curr: { ...m }, prev: { ...m, t: trMap.prev, q: 0 },
            lw: { ...m, t: trMap.lw, q: 0 }, lm: { ...m, t: trMap.lm, q: 0 },
            lq: { ...m, t: trMap.lq, q: 0 }, ly: { ...m, t: trMap.ly, q: 0 }
          },
          _ts: {} // For trends
        };
      });

      rowsData.forEach(r => {
        const b = struct.find(x => x.id === r.branch);
        if (!b) return;
        const ds = r.date.value;
        const rev = r.revenue || 0, ord = r.orders || 0, qty = r.quantity || 0;

        if (!b._ts[ds]) b._ts[ds] = { r: 0, o: 0, q: 0 };
        b._ts[ds].r += rev; b._ts[ds].o += ord; b._ts[ds].q += qty;

        if (ds >= ranges.curr.s && ds <= ranges.curr.e) { b.data.curr.r += rev; b.data.curr.o += ord; b.data.curr.q += qty; }
        if (ds >= ranges.prev.s && ds <= ranges.prev.e) { b.data.prev.r += rev; b.data.prev.o += ord; b.data.prev.q += qty; }
        if (ds >= ranges.lw.s && ds <= ranges.lw.e) { b.data.lw.r += rev; b.data.lw.o += ord; b.data.lw.q += qty; }
        if (ds >= ranges.lm.s && ds <= ranges.lm.e) { b.data.lm.r += rev; b.data.lm.o += ord; b.data.lm.q += qty; }
        if (ds >= ranges.lq.s && ds <= ranges.lq.e) { b.data.lq.r += rev; b.data.lq.o += ord; b.data.lq.q += qty; }
        if (ds >= ranges.ly.s && ds <= ranges.ly.e) { b.data.ly.r += rev; b.data.ly.o += ord; b.data.ly.q += qty; }
      });
      return struct;
    };

    const globalBranches = processRows(globalRows);
    const tableBranches = processRows(tableRows);

    // Rollup from Global Branches to Global Level KPIs
    const roll = (periodKey) => globalBranches.reduce((acc, b) => {
      acc.r += b.data[periodKey].r; acc.o += b.data[periodKey].o; acc.t += b.data[periodKey].t;
      return acc;
    }, { r: 0, o: 0, t: 0, a: 0 });

    const currentMap = roll('curr');
    currentMap.a = currentMap.o > 0 ? currentMap.r / currentMap.o : 0;

    // Sums 4-periods
    const sums = ['prev', 'lw', 'lm', 'lq', 'ly'].reduce((acc, k) => {
      const obj = roll(k);
      obj.a = obj.o > 0 ? obj.r / obj.o : 0;
      acc[k] = obj;
      return acc;
    }, {});

    // Target total
    const current = {
      revenue: currentMap.r, orders: currentMap.o, traffic: currentMap.t, aov: currentMap.a,
      target: globalBranches.reduce((a, b) => a + (b.target || 0), 0)
    };

    if (traffic && traffic._debug) {
      console.log("=== TRAFFIC DEBUG INFO ===");
      console.log("Headers:", traffic._debug.headers);
      console.log("Sample Rows:", traffic._debug.sampleRows);
      console.log("==========================");
    }

    // Trend Generator from Global Branches
    const trendData = { labels: [], revenue: [], orders: [], traffic: [], aov: [] };
    const nowLocal = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Ho_Chi_Minh" }));
    const currSObj = parseLocalNoon(ranges.curr.rawS);
    while (currSObj <= parseLocalNoon(ranges.curr.rawE)) {
      if (currSObj > nowLocal) break;
      const ds = formatVNDate(currSObj);
      trendData.labels.push(ds.substring(5)); // MM-DD
      let dR = 0, dO = 0, dT = 0;
      globalBranches.forEach(b => {
        if (b._ts[ds]) { dR += b._ts[ds].r; dO += b._ts[ds].o; }
        const trafficSource = traffic && traffic[b.id] && traffic[b.id]._ts ? traffic[b.id]._ts[ds] : 0;
        dT += trafficSource || 0;
      });
      trendData.revenue.push(dR); trendData.orders.push(dO);
      trendData.traffic.push(dT); trendData.aov.push(dO > 0 ? dR / dO : 0);
      currSObj.setDate(currSObj.getDate() + 1);
    }

    const elapsed = ranges.curr.rawE > ranges.curr.rawS ? Math.min(100, Math.max(0, ((nowLocal - ranges.curr.rawS) / (ranges.curr.rawE - ranges.curr.rawS)) * 100)) : 0;
    const daysLeft = Math.max(0, Math.ceil((ranges.curr.rawE - nowLocal) / 86400000));

    res.json({
      startDate: ranges.curr.s, endDate: ranges.curr.e,
      daysLeft, elapsedPercent: elapsed.toFixed(0),
      current,
      sums,
      branches: tableBranches,
      globalBranches,
      trends: trendData,
      trafficDebug: traffic ? traffic._debug : null
    });
  } catch (e) {
    console.error('EXECUTIVE API CRITICAL ERROR:', e);
    res.status(500).json({ error: e.message || 'Internal Server Error' });
  }
});

// GET /api/executive/salesman-data - Salesman Revenue by Category
app.get('/api/executive/salesman-data', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    if (user.role !== 'manager' && user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

    const { period = 'month', region = 'ALL', branch = 'ALL', date = null, endDate = null, tableCategory = 'ALL' } = req.query;
    const ranges = getDashboardDateRange(period, date, endDate);

    let where = `WHERE (CAST(Report_date AS DATE) BETWEEN '${ranges.curr.s}' AND '${ranges.curr.e}')`;

    // Category filter using Cat_group_ID
    if (tableCategory === 'CUSTOM_1') {
      where += ` AND Cat_group_ID IN ('NH01', 'NH02', 'NH03', 'NH05')`;
    } else if (tableCategory !== 'ALL') {
      where += ` AND Cat_group_ID = '${tableCategory}'`;
    }

    // Role-based branch restriction — BQ sales table uses Branch_code (lowercase c)
    const isGlobalAdmin = user.role === 'admin' || user.branch_code === 'HCM.BD';
    if (!isGlobalAdmin && user.branch_code) {
      where += ` AND Branch_code = '${user.branch_code}'`;
    } else if (branch !== 'ALL') {
      where += ` AND Branch_code = '${branch}'`;
    } else if (region !== 'ALL') {
      const regB = EXECUTIVE_BRANCH_LIST.filter(b => b.region === region).map(b => b.id);
      where += ` AND Branch_code IN (${regB.map(id => `'${id}'`).join(',')})`;
    } else {
      const allBranches = EXECUTIVE_BRANCH_LIST.map(b => b.id);
      where += ` AND Branch_code IN (${allBranches.map(id => `'${id}'`).join(',')})`;
    }

    // BQ: Group by Email (salesperson's login email = Email column in BQ table)
    const bqQuery = `
      SELECT 
        LOWER(Email) as email,
        MAX(Branch_code) as branch_code,
        MAX(Salesman) as salesman_name,
        SUM(Revenue) as Revenue
      FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
      ${where}
        AND Order_type = 'don_xuat_ban'
        AND Email IS NOT NULL
        AND TRIM(Email) != ''
      GROUP BY LOWER(Email)
      ORDER BY Revenue DESC
      LIMIT 200
    `;

    const [bqRows] = await bigquery.query({ query: bqQuery });

    // Enrich with Supabase users table to get full_name and hrm_id
    const emails = (bqRows || []).map(r => (r.email || '').trim().toLowerCase()).filter(Boolean);
    let userMap = {};
    if (emails.length > 0) {
      const allSearchEmails = [...new Set([
        ...emails,
        ...emails.map(e => e.replace('@phongvu-mna.vn', '@phongvu.vn')),
        ...emails.map(e => e.replace('@phongvu.vn', '@phongvu-mna.vn'))
      ])].map(e => e.toLowerCase());

      const { data: usersData } = await supabase
        .from('users')
        .select('email, full_name, hrm_id')
        .in('email', allSearchEmails);
      (usersData || []).forEach(u => {
        if (u.email) {
          const ue = u.email.toLowerCase();
          userMap[ue] = u;
          if (ue.endsWith('@phongvu.vn')) {
            userMap[ue.replace('@phongvu.vn', '@phongvu-mna.vn')] = u;
          }
        }
      });
    }

    const rows = (bqRows || []).map(r => {
      const email = (r.email || '').trim().toLowerCase();
      const u = userMap[email] || {};
      return {
        Salesman: u.full_name || r.salesman_name || email,
        Email: email,
        Branch_code: r.branch_code || '—',
        HRM_ID: u.hrm_id || '—',
        Revenue: r.Revenue || 0
      };
    });

    res.json({ rows });
  } catch (e) {
    console.error('SALESMAN API ERROR:', e);
    res.status(500).json({ error: e.message || 'Internal Server Error' });
  }
});

// ------------------------- END EXECUTIVE DASHBOARD -------------------------

// =========================================================================
// --- [TÍNH NĂNG] XUẤT KHO NHANH (QUICK EXPORT / SMART PICKING) ---
// =========================================================================
const quickExportService = require('./utils/quick_export_service');

const SITE_ID_TO_BRANCH = {
  7: 'CP01',
  8: 'CP02',
  9: 'CP07',
  46: 'CP05',
  54: 'CP08',
  85: 'CP40',
  628: 'CP46',
  763: 'CP58',
  779: 'CP62',
  1600: 'CP64',
  3480: 'CP67',
  29499: 'CP69',
  53019: 'CP74',
};

const BRANCH_TO_SITE_ID = {
  'CP01': 7,
  'CP02': 8,
  'CP07': 9,
  'CP05': 46,
  'CP08': 54,
  'CP40': 85,
  'CP46': 628,
  'CP58': 763,
  'CP62': 779,
  'CP64': 1600,
  'CP67': 3480,
  'CP69': 29499,
  'CP74': 53019,
};

function extractBranchCode(text) {
  if (!text) return '';
  const m = String(text).match(/\b(CP\d+)\b/i);
  return m ? m[1].toUpperCase() : '';
}

// 1. Giao diện trang Xuất kho nhanh
app.use(['/quick-export', '/api/quick-export'], (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

app.get('/quick-export', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    res.render('quick-export', {
      title: '⚡ Xuất kho nhanh',
      currentPage: 'quick-export',
      user,
    });
  } catch (err) {
    console.error('Error rendering quick-export:', err);
    res.status(500).send('Lỗi máy chủ khi tải trang Xuất kho nhanh');
  }
});

// Helper lấy token cho user (chỉ dùng token cá nhân để bảo mật, chống mạo danh và kiểm soát thu hồi)
async function resolveUserExportToken(req) {
  let token = req.headers['x-teko-token'] || req.headers['authorization'];
  if (token) return token;

  if (req.session?.quickExportSettings?.tekoToken) {
    return req.session.quickExportSettings.tekoToken;
  }

  // Kiểm tra cấu hình cá nhân của user
  if (req.session?.user?.id) {
    const settingKey = `quick_export_${req.session.user.id}`;
    const { data } = await supabase.from('site_settings').select('value').eq('id', settingKey).maybeSingle();
    if (data && data.value) {
      try {
        const parsed = JSON.parse(data.value);
        if (parsed.tekoToken) return parsed.tekoToken;
      } catch (e) {}
    }
  }

  return '';
}

// 1b. Tải Chrome Extension (.zip)
app.get('/api/quick-export/download-extension', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'phongvu-erp-sync.zip');
  if (fs.existsSync(filePath)) {
    return res.download(filePath, 'phongvu-erp-sync.zip');
  }
  res.status(404).send('Không tìm thấy file cài đặt Extension');
});

// 2. Lấy cài đặt cá nhân (chỉ dùng token riêng của user, không dùng chung)
app.get('/api/quick-export/settings', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const branchCode = req.session.user.branch_code;
    const settingKey = `quick_export_${userId}`;
    const { data } = await supabase.from('site_settings').select('value').eq('id', settingKey).maybeSingle();
    let settings = {};
    if (data && data.value) {
      try { settings = JSON.parse(data.value); } catch (e) {}
    }

    const effectiveToken = settings.tekoToken || '';

    res.json({
      success: true,
      _userId: userId,
      _branchCode: branchCode,
      settings: {
        pickingBinName: settings.pickingBinName || '',
        pickingBinId: settings.pickingBinId || '',
        hasToken: Boolean(effectiveToken),
        tekoToken: effectiveToken,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 3. Lưu cài đặt cá nhân
app.post('/api/quick-export/settings', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const branchCode = req.session.user.branch_code;
    const { pickingBinName, pickingBinId, tekoToken } = req.body;
    const settingKey = `quick_export_${userId}`;

    const valueObj = {
      pickingBinName: pickingBinName || '',
      pickingBinId: pickingBinId || '',
      tekoToken: tekoToken || '',
      branchCode: branchCode || '',
      updatedAt: new Date().toISOString(),
    };

    req.session.quickExportSettings = valueObj;

    // Lưu cài đặt cá nhân
    await supabase.from('site_settings').upsert({
      id: settingKey,
      value: JSON.stringify(valueObj),
      updated_at: new Date().toISOString(),
    });

    res.json({ success: true, message: 'Đã lưu cấu hình tài khoản thành công!' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 3b. Endpoint đồng bộ token từ tab ERP (hỗ trợ CORS cho bookmarklet / Extension 1-click)
app.options('/api/quick-export/sync-token', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.sendStatus(200);
});

app.post('/api/quick-export/sync-token', async (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  try {
    const { token, branchCode, userId } = req.body;
    if (!token) return res.status(400).json({ success: false, message: 'Thiếu token' });

    const cleanToken = token.startsWith('Bearer ') ? token.slice(7).trim() : token.trim();
    const tokenObj = { tekoToken: cleanToken, branchCode: branchCode || '', updatedAt: new Date().toISOString() };

    // Ưu tiên lưu trực tiếp theo userId
    if (userId) {
      await supabase.from('site_settings').upsert({
        id: `quick_export_${userId}`,
        value: JSON.stringify(tokenObj),
        updated_at: new Date().toISOString()
      });
    } else {
      // Fallback nếu không có userId (ví dụ bookmarklet chung)
      await supabase.from('site_settings').upsert({
        id: 'quick_export_global_token',
        value: JSON.stringify(tokenObj),
        updated_at: new Date().toISOString()
      });
    }

    res.json({ success: true, message: 'Đã tự động đồng bộ token ERP thành công!' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/api/quick-export/sync-token', async (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  try {
    const token = req.query.token;
    const branchCode = req.query.branchCode;
    const userId = req.query.userId;
    if (!token) return res.status(400).json({ success: false, message: 'Thiếu token' });

    const cleanToken = token.startsWith('Bearer ') ? token.slice(7).trim() : token.trim();
    const tokenObj = { tekoToken: cleanToken, branchCode: branchCode || '', updatedAt: new Date().toISOString() };

    if (userId) {
      await supabase.from('site_settings').upsert({
        id: `quick_export_${userId}`,
        value: JSON.stringify(tokenObj),
        updated_at: new Date().toISOString()
      });
    } else {
      await supabase.from('site_settings').upsert({
        id: 'quick_export_global_token',
        value: JSON.stringify(tokenObj),
        updated_at: new Date().toISOString()
      });
    }

    res.json({ success: true, message: 'Đã tự động đồng bộ token ERP thành công!' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// =========================================================================
// --- ADMIN TOKEN MANAGEMENT (Dành riêng cho vu.nt1@phongvu-mna.vn & Admin) ---
// =========================================================================
function decodeJwtPayload(token) {
  try {
    if (!token) return null;
    const clean = String(token).replace(/^Bearer\s+/i, '').trim();
    const parts = clean.split('.');
    if (parts.length < 2) return null;
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
}

function checkIsTokenAdmin(req) {
  const u = req.session?.user;
  if (!u) return false;
  return u.email === 'vu.nt1@phongvu-mna.vn' || u.role === 'admin';
}

// Lấy danh sách tất cả token đang có trong hệ thống
app.get('/api/quick-export/admin/tokens', requireAuth, async (req, res) => {
  if (!checkIsTokenAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Bạn không có quyền truy cập trang quản lý token!' });
  }

  try {
    const { data: rows, error } = await supabase
      .from('site_settings')
      .select('id, value, updated_at')
      .like('id', 'quick_export_%');

    if (error) throw error;

    const { data: allUsers } = await supabase
      .from('users')
      .select('id, email, full_name, branch_code, role');
    const userMap = {};
    (allUsers || []).forEach(u => { userMap[u.id] = u; });

    const tokenList = [];
    const nowSec = Math.floor(Date.now() / 1000);

    for (const r of (rows || [])) {
      let val = {};
      try { val = JSON.parse(r.value); } catch (e) { val = { tekoToken: r.value }; }

      const rawToken = val.tekoToken || '';
      if (!rawToken) continue;

      const jwt = decodeJwtPayload(rawToken);
      const expSec = jwt?.exp ? Number(jwt.exp) : null;
      const isExpired = expSec ? (expSec < nowSec) : false;

      let type = 'user';
      let title = r.id;
      let userObj = null;

      if (r.id === 'quick_export_global_token') {
        type = 'global';
        title = 'Token dùng chung toàn hệ thống';
      } else if (r.id.startsWith('quick_export_branch_')) {
        type = 'branch';
        const bCode = r.id.replace('quick_export_branch_', '');
        title = `Token dùng chung chi nhánh [${bCode}]`;
      } else {
        const uId = r.id.replace('quick_export_', '');
        userObj = userMap[uId] || null;
        title = userObj ? `${userObj.full_name || userObj.email} (${userObj.branch_code || 'Chưa gán'})` : `User #${uId}`;
      }

      tokenList.push({
        key: r.id,
        type,
        title,
        userId: userObj?.id || null,
        userEmail: userObj?.email || null,
        userName: userObj?.full_name || null,
        branchCode: userObj?.branch_code || val.branchCode || null,
        tokenMasked: rawToken.length > 25 ? `${rawToken.slice(0, 12)}...${rawToken.slice(-8)}` : '***',
        jwtSubject: jwt?.sub || jwt?.name || jwt?.email || null,
        expiresAt: expSec ? new Date(expSec * 1000).toISOString() : null,
        isExpired,
        updatedAt: r.updated_at || val.updatedAt || null,
      });
    }

    tokenList.sort((a, b) => {
      if (a.type !== b.type) return a.type === 'user' ? -1 : 1;
      return new Date(b.updatedAt || 0) - new Date(a.updatedAt || 0);
    });

    res.json({ success: true, tokens: tokenList });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Xóa 1 token cụ thể của user hoặc chi nhánh
app.delete('/api/quick-export/admin/tokens/:key', requireAuth, async (req, res) => {
  if (!checkIsTokenAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Bạn không có quyền xoá token!' });
  }

  try {
    const key = req.params.key;
    if (!key || !key.startsWith('quick_export_')) {
      return res.status(400).json({ success: false, message: 'Mã token không hợp lệ' });
    }

    const { error } = await supabase.from('site_settings').delete().eq('id', key);
    if (error) throw error;

    res.json({ success: true, message: `Đã xoá token [${key}] thành công. User sẽ phải xác thực ERP lại!` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Xóa sạch toàn bộ token ERP trên hệ thống (buộc tất cả nhân viên re-auth)
app.post('/api/quick-export/admin/tokens/purge-all', requireAuth, async (req, res) => {
  if (!checkIsTokenAdmin(req)) {
    return res.status(403).json({ success: false, message: 'Bạn không có quyền xoá token!' });
  }

  try {
    const { error } = await supabase.from('site_settings').delete().like('id', 'quick_export_%');
    if (error) throw error;

    res.json({ success: true, message: 'Đã xoá sạch toàn bộ token ERP trên hệ thống! Mọi nhân viên sẽ phải xác thực lại.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 3b. Lấy danh sách kho / sites của user từ Teko ERP (Chỉ trả về chi nhánh được gán nếu là staff)
app.get('/api/quick-export/sites', requireAuth, async (req, res) => {
  try {
    const token = await resolveUserExportToken(req);
    let sites = await quickExportService.getUserSites(token);
    const userBranch = (req.session.user?.branch_code || '').toUpperCase().trim();
    const isGlobalAdmin = (req.session.user?.role === 'admin' || userBranch === 'HCM.BD');

    if (!isGlobalAdmin && userBranch) {
      const filtered = sites.filter(s => {
        const sName = (s.name || '').toUpperCase();
        return sName.includes(userBranch) || (BRANCH_TO_SITE_ID[userBranch] && Number(s.id) === BRANCH_TO_SITE_ID[userBranch]);
      });
      if (filtered.length > 0) {
        sites = filtered;
      }
    }

    res.json({ success: true, sites });
  } catch (err) {
    res.json({ success: true, sites: [] });
  }
});

// 4. Kiểm tra BIN hợp lệ trên ERP
app.post('/api/quick-export/verify-bin', requireAuth, async (req, res) => {
  try {
    const { binName, siteId: reqSiteId } = req.body;
    const token = req.body.token || await resolveUserExportToken(req);
    const userBranch = (req.session.user?.branch_code || '').toUpperCase().trim();
    const isGlobalAdmin = (req.session.user?.role === 'admin' || userBranch === 'HCM.BD');

    let siteId = reqSiteId;
    if (!isGlobalAdmin && userBranch) {
      siteId = BRANCH_TO_SITE_ID[userBranch] || reqSiteId || userBranch;
    } else if (!siteId) {
      siteId = BRANCH_TO_SITE_ID[userBranch] || userBranch;
    }

    const bin = await quickExportService.getBinByBinName(binName, token, siteId);
    res.json({ success: true, bin });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// 5. Tải thông tin đơn hàng / yêu cầu xuất kho (Kiểm tra đối chiếu Kho bán và Kho xuất)
app.get('/api/quick-export/order', requireAuth, async (req, res) => {
  try {
    const code = req.query.code;
    const binId = req.query.binId;
    const token = await resolveUserExportToken(req);
    const userBranch = (req.session.user?.branch_code || '').toUpperCase().trim();
    const isGlobalAdmin = (req.session.user?.role === 'admin' || userBranch === 'HCM.BD');

    let siteId = req.query.siteId;
    if (!siteId) {
      siteId = BRANCH_TO_SITE_ID[userBranch] || userBranch;
    }

    const orderData = await quickExportService.loadExportRequest(code, binId, token, siteId);

    // Kiểm tra phân quyền: Sale được gán ở CPxx nào thì chỉ thấy data của CPxx đó (đối chiếu theo kho bán và kho xuất)
    if (!isGlobalAdmin && userBranch) {
      const sellBranch = extractBranchCode(orderData.branchCode) || (orderData.branchCode || '').toUpperCase().trim();
      const exportBranch = extractBranchCode(orderData.exportBranch || orderData.siteName) 
        || SITE_ID_TO_BRANCH[Number(orderData.siteId)] 
        || '';

      const isSellMatch = (sellBranch === userBranch);
      const isExportMatch = (exportBranch === userBranch) 
        || (BRANCH_TO_SITE_ID[userBranch] && Number(orderData.siteId) === BRANCH_TO_SITE_ID[userBranch])
        || ((orderData.siteName || '').toUpperCase().includes(userBranch));

      if (!isSellMatch && !isExportMatch) {
        return res.status(403).json({
          success: false,
          message: `Bạn được gán tại chi nhánh [${userBranch}], không có quyền xem thông tin đơn hàng của chi nhánh khác! (Đơn thuộc Kho bán: ${sellBranch || 'N/A'}, Kho xuất: ${exportBranch || orderData.siteName || 'N/A'})`
        });
      }
    }

    res.json({ success: true, data: orderData });
  } catch (err) {
    const statusCode = err.status === 403 ? 403 : 400;
    res.status(statusCode).json({ success: false, message: err.message });
  }
});

// 6. Xử lý quét Serial: tự nhận diện SKU, tự tra cứu BIN hiện tại, tự luân chuyển về BIN soạn hàng
app.post('/api/quick-export/process-serial', requireAuth, async (req, res) => {
  try {
    const { serial, pickingBinId, pickingBinName, orderItems, scannedSerials = {}, siteId: reqSiteId } = req.body;
    if (!serial) throw new Error('Thiếu số Serial');
    if (!pickingBinId) throw new Error('Thiếu mã BIN soạn hàng');
    if (!Array.isArray(orderItems) || orderItems.length === 0) throw new Error('Không có thông tin sản phẩm đơn hàng');

    const token = await resolveUserExportToken(req);
    const siteId = reqSiteId || req.session.user?.branch_code;

    // B1: Tra cứu vị trí Serial thời gian thực từ Teko
    const track = await quickExportService.getSerialTracking(serial, token, siteId);

    // B2: Xác thực Serial nghiêm ngặt - KHÔNG BAO GIỜ GÁN BỪA KHI SERIAL SAI KÝ TỰ HOẶC KHÔNG TỒN TẠI
    let targetSku = track.sku ? String(track.sku).trim() : '';
    let matchedItem = null;

    if (targetSku) {
      // Trường hợp 1: Teko WMS nhận diện đúng Serial
      matchedItem = orderItems.find(it => String(it.sku) === targetSku);
      if (!matchedItem) {
        throw new Error(`Serial "${serial}" thuộc sản phẩm [${track.productName || targetSku}], không nằm trong danh sách đơn hàng này!`);
      }
    } else {
      // Trường hợp 2: Teko WMS chưa nhận diện, kiểm tra chéo trong cơ sở dữ liệu Supabase inventory_serials
      const { data: invRow } = await supabase
        .from('inventory_serials')
        .select('SKU, "SKU name", Location, "BIN zone"')
        .eq('Serial', serial.trim())
        .maybeSingle();

      if (invRow && invRow.SKU) {
        targetSku = String(invRow.SKU).trim();
        matchedItem = orderItems.find(it => String(it.sku) === targetSku);
        if (!matchedItem) {
          throw new Error(`Serial "${serial}" thuộc sản phẩm [${invRow['SKU name'] || targetSku}], không nằm trong danh sách đơn hàng này!`);
        }
        if (!track.binName && invRow['BIN zone']) track.binName = invRow['BIN zone'];
      } else {
        // CẢ TEKO VÀ SUPABASE ĐỀU KHÔNG TÌM THẤY -> SERIAL SAI KÝ TỰ HOẶC HOÀN TOÀN KHÔNG TỒN TẠI
        throw new Error(`Mã Serial "${serial}" không tồn tại trên hệ thống hoặc bị quét sai ký tự! Vui lòng kiểm tra lại tem sản phẩm.`);
      }
    }

    // B2.1: Kiểm tra xem SKU này đã quét đủ số lượng yêu cầu trong đơn chưa
    const reqQty = Number(matchedItem.requestQuantity) || 1;
    const currentScanned = (scannedSerials[matchedItem.sku] || []).length;
    if (currentScanned >= reqQty) {
      throw new Error(`Sản phẩm [${matchedItem.skuName || matchedItem.sku}] đã quét đủ số lượng yêu cầu (${currentScanned}/${reqQty})!`);
    }

    // B2.2: Kiểm tra serial trùng lặp trong phiên quét hiện tại
    for (const [skuKey, list] of Object.entries(scannedSerials)) {
      if (Array.isArray(list) && list.includes(serial.trim())) {
        throw new Error(`Serial "${serial.trim()}" đã được quét trước đó trong đơn hàng!`);
      }
    }

    // B3: Kiểm tra vị trí BIN và tự động luân chuyển nếu khác BIN soạn hàng
    let moved = false;
    let actualBinId = track.binId || pickingBinId;
    let fromBinName = track.binName || 'Kho';

    if (track.binId && pickingBinId && Number(track.binId) !== Number(pickingBinId)) {
      try {
        // Thử gọi API luân chuyển BIN của Teko
        await quickExportService.moveBin({
          fromBinId: track.binId,
          toBinId: pickingBinId,
          sku: targetSku,
          quantity: 1,
          siteId,
        }, token, siteId);
        moved = true;
        actualBinId = pickingBinId;
      } catch (moveErr) {
        // Nếu Teko chặn chuyển lẻ do BIN có nhiều hơn 1 sp (lỗi 400003),
        // tự động giữ nguyên BIN thực tế để xuất thẳng từ BIN này trên ERP mà không báo lỗi
        console.warn(`[QuickExport] Không thể chuyển lẻ serial ${serial} (BIN ${track.binId}): ${moveErr.message}. Sẽ xuất thẳng từ BIN này.`);
        moved = false;
        actualBinId = track.binId;
      }
    }

    // B4: Kiểm tra FIFO thời gian thực dựa trên Supabase inventory_serials & serial_check_log
    let fifoInfo = {
      status: 'Đạt FIFO',
      pass: true,
      rank: 1,
      totalLots: 1,
      totalAvailable: 1,
      diffDays: 0,
      targetDate: '',
      oldestDate: '',
      message: 'Serial hợp lệ'
    };

    try {
      const { data: invRow } = await supabase
        .from('inventory_serials')
        .select('*')
        .eq('Serial', serial.trim())
        .maybeSingle();

      const targetDate = invRow ? (invRow['Date import company '] || invRow['Date import site']) : null;
      const effectiveBranch = (invRow && invRow['Branch ID']) ? invRow['Branch ID'] : (req.session.user?.branch_code || 'CP01');

      if (targetDate) {
        const { data: skuItems } = await supabase
          .from('inventory_serials')
          .select('"Serial", "Date import company ", "Date import site"')
          .eq('SKU', String(targetSku))
          .eq('"Branch ID"', effectiveBranch);

        const allSerials = (skuItems || []).map(s => s.Serial);
        let checkedSet = new Set();
        if (allSerials.length > 0) {
          const { data: checkedLogs } = await supabase
            .from('serial_check_log')
            .select('serial')
            .eq('checked_out', true)
            .in('serial', allSerials);
          checkedSet = new Set((checkedLogs || []).map(l => l.serial));
        }

        const activeSiblings = (skuItems || []).filter(s => !checkedSet.has(s.Serial));
        const uniqueDates = [...new Set(activeSiblings.map(s => s['Date import company '] || s['Date import site']))]
          .filter(Boolean)
          .sort();

        const oldestDate = uniqueDates[0] || targetDate;
        const rank = uniqueDates.indexOf(targetDate) + 1;

        let diffDays = 0;
        if (targetDate && oldestDate) {
          const d1 = new Date(targetDate);
          const d2 = new Date(oldestDate);
          diffDays = Math.max(0, Math.ceil(Math.abs(d1 - d2) / (1000 * 60 * 60 * 24)));
        }

        const isFifoPass = (diffDays <= 30) || (rank <= 1);
        fifoInfo = {
          status: isFifoPass ? 'Đạt FIFO' : 'Cảnh báo FIFO',
          pass: isFifoPass,
          rank: rank > 0 ? rank : 1,
          totalLots: uniqueDates.length || 1,
          totalAvailable: activeSiblings.length || 1,
          targetDate: targetDate || '',
          oldestDate: oldestDate || '',
          diffDays,
          location: invRow?.Location || fromBinName,
          message: isFifoPass
            ? (rank === 1 ? 'Serial thuộc lô cũ nhất (Chuẩn FIFO)' : `Serial chênh lệch ${diffDays} ngày (Trong hạn cho phép)`)
            : `Cảnh báo: Có serial lô cũ hơn (${oldestDate}) chưa xuất (Lệch ${diffDays} ngày)!`
        };
      }
    } catch (fifoErr) {
      console.warn('[QuickExport] Lỗi kiểm tra FIFO Supabase:', fifoErr.message);
    }

    res.json({
      success: true,
      sku: targetSku,
      skuName: matchedItem.skuName,
      serial: serial.trim(),
      moved,
      binId: actualBinId,
      binName: moved ? (pickingBinName || `BIN #${pickingBinId}`) : fromBinName,
      fromBinName,
      toBinName: moved ? (pickingBinName || `BIN #${pickingBinId}`) : fromBinName,
      fifo: fifoInfo
    });

  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// 6b. Lấy danh sách gợi ý Serial tồn lâu nhất (Chuẩn FIFO) cho các SKU trong đơn hàng
app.post('/api/quick-export/fifo-recommendation', requireAuth, async (req, res) => {
  try {
    const { skus = [], branchCode: reqBranch } = req.body;
    if (!Array.isArray(skus) || skus.length === 0) {
      return res.json({ success: true, skusData: {} });
    }

    const userBranch = (req.session.user?.branch_code || '').toUpperCase().trim();
    const isGlobalAdmin = (req.session.user?.role === 'admin' || userBranch === 'HCM.BD');

    // Sale được gán ở CPxx nào thì chỉ thấy data của CPxx đó (bao gồm FIFO)
    let branch = userBranch || 'CP01';
    if (isGlobalAdmin && reqBranch) {
      branch = reqBranch.toUpperCase().trim();
    }
    const cleanSkus = skus.map(s => String(s).trim());

    // 1. Lấy tất cả serial tồn của các SKU tại chi nhánh từ inventory_serials
    const { data: rows, error } = await supabase
      .from('inventory_serials')
      .select('*')
      .in('SKU', cleanSkus)
      .eq('Branch ID', branch);

    if (error) throw error;

    // 2. Lấy danh sách serial đã xuất trong serial_check_log để loại trừ
    const allSerials = (rows || []).map(r => r.Serial).filter(Boolean);
    let checkedSet = new Set();
    if (allSerials.length > 0) {
      const { data: checkedLogs } = await supabase
        .from('serial_check_log')
        .select('serial')
        .eq('checked_out', true)
        .in('serial', allSerials);
      checkedSet = new Set((checkedLogs || []).map(l => l.serial));
    }

    // 3. Gom nhóm theo SKU và sắp xếp tồn lâu nhất (nhập sớm nhất) lên đầu
    const skusData = {};
    cleanSkus.forEach(sku => { skusData[sku] = []; });

    (rows || []).forEach(row => {
      const sn = row.Serial;
      if (!sn || checkedSet.has(sn)) return; // Bỏ qua nếu đã xuất

      const sku = String(row.SKU);
      if (!skusData[sku]) skusData[sku] = [];

      const rawDate = row['Date import company '] || row['Date import site'] || '';
      let dateFormatted = '-';
      if (rawDate) {
        const parts = rawDate.split('-');
        if (parts.length === 3) dateFormatted = `${parts[2]}/${parts[1]}/${parts[0]}`;
        else dateFormatted = rawDate;
      }

      const daysOld = Number(row['Aging company'] || row['Aging site'] || 0);

      skusData[sku].push({
        serial: sn,
        sku,
        skuName: row['SKU name'] || '',
        rawDate,
        dateFormatted,
        daysOld,
        location: row.Location || 'Kho',
        binZone: row['BIN zone'] || '',
        binType: row['BIN type'] || '',
      });
    });

    // Sắp xếp ngày nhập ASC (cũ nhất lên đầu) và gán rank
    for (const [sku, list] of Object.entries(skusData)) {
      list.sort((a, b) => {
        if (!a.rawDate) return 1;
        if (!b.rawDate) return -1;
        return a.rawDate.localeCompare(b.rawDate);
      });

      list.forEach((item, idx) => {
        item.rank = idx + 1;
        item.isOldest = (idx === 0);
      });
    }

    res.json({
      success: true,
      branch,
      skusData
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 7. Xác nhận hoàn tất xuất kho (Confirm Packing) & Cập nhật FIFO "Đã xuất"
app.post('/api/quick-export/confirm-export', requireAuth, async (req, res) => {
  let token = null;
  try {
    const { requestId, documentId, pickingBinId, items, receiverName, siteId: reqSiteId, serialBinMap = {}, isAutoHandover = false } = req.body;
    token = await resolveUserExportToken(req);
    const siteId = reqSiteId || req.session.user?.branch_code;
    const autoHandover = Boolean(isAutoHandover);
    const effectiveRequestId = String(requestId || documentId || '').trim();

    // Gom nhóm items và serials theo từng binId thực tế
    const binGroups = {};
    for (const item of (items || [])) {
      const serials = Array.isArray(item.serials) ? item.serials : [];
      if (serials.length > 0) {
        for (const sn of serials) {
          const bId = String(serialBinMap[sn] || pickingBinId);
          if (!binGroups[bId]) binGroups[bId] = {};
          if (!binGroups[bId][item.sku]) binGroups[bId][item.sku] = [];
          binGroups[bId][item.sku].push(sn);
        }
      } else {
        // Sản phẩm không quản lý serial
        const bId = String(pickingBinId);
        if (!binGroups[bId]) binGroups[bId] = {};
        if (!binGroups[bId][item.sku]) binGroups[bId][item.sku] = [];
      }
    }

    // Nếu không gom được bin nào, fallback về pickingBinId
    if (Object.keys(binGroups).length === 0 && pickingBinId) {
      binGroups[String(pickingBinId)] = {};
      for (const item of (items || [])) {
        binGroups[String(pickingBinId)][item.sku] = item.serials || [];
      }
    }

    const binEntries = Object.entries(binGroups);
    let lastResult = null;
    for (let i = 0; i < binEntries.length; i++) {
      const [bId, skuMap] = binEntries[i];
      const isLast = (i === binEntries.length - 1);
      const binItems = Object.entries(skuMap).map(([sku, serials]) => ({
        sku,
        serials,
        lots: []
      }));

      // QUAN TRỌNG: Chỉ bàn giao (isAutoHandover) ở lần gọi cuối cùng!
      // Nếu bàn giao ở lần đầu, Teko WMS sẽ đổi đơn sang EXPORTED ngay, khiến lần gọi tiếp theo bị lỗi "State of request is not valid".
      const handoverThisStep = isLast ? autoHandover : false;

      lastResult = await quickExportService.confirmPacking({
        requestId: effectiveRequestId,
        binId: Number(bId),
        items: binItems,
        isAutoHandover: handoverThisStep,
        receiverName: handoverThisStep ? receiverName : undefined,
        siteId,
      }, token, siteId);
    }

    // ĐỒNG THỜI ĐÁNH DẤU "ĐÃ XUẤT" VÀO BẢNG serial_check_log TRÊN SUPABASE (FIFO)
    const todayDate = new Date().toISOString().slice(0, 10);
    const nowIso = new Date().toISOString();
    const branchCode = req.session.user?.branch_code || 'CP01';
    const userId = req.session.user?.id;

    let updatedFifoCount = 0;
    for (const item of (items || [])) {
      const sku = item.sku;
      for (const sn of (item.serials || [])) {
        try {
          await supabase.from('serial_check_log').upsert({
            serial: sn,
            sku,
            branch_code: branchCode,
            check_date: todayDate,
            checked_out: true,
            checked_by: userId,
            checked_at: nowIso,
          }, { onConflict: 'serial,check_date' });
          updatedFifoCount++;
        } catch (fifoLogErr) {
          console.warn('[QuickExport] Lỗi cập nhật FIFO log cho serial', sn, fifoLogErr.message);
        }
      }
    }

    res.json({
      success: true,
      data: lastResult,
      updatedFifoCount,
      isAutoHandover: autoHandover,
      message: autoHandover
        ? `Hoàn tất xuất kho thành công trên ERP! Đã tick "Đã xuất" cho ${updatedFifoCount} serial vào bảng FIFO.`
        : `Xác nhận soạn hàng (Đã đóng gói) thành công trên ERP! Đã tick "Đã xuất" cho ${updatedFifoCount} serial vào bảng FIFO.`
    });
  } catch (err) {
    // Nếu gặp lỗi "State of request is not valid", kiểm tra xem đơn hàng thực tế đã được xuất kho / đóng gói thành công trước đó chưa
    if (err.message && err.message.toLowerCase().includes('state of request is not valid')) {
      try {
        const { documentId, requestId, siteId: reqSiteId, items } = req.body;
        const siteId = reqSiteId || req.session.user?.branch_code;
        if (!token) token = await resolveUserExportToken(req);
        const checkStatus = await quickExportService.loadExportRequest(documentId || requestId, null, token, siteId);
        const st = String(checkStatus?.status || '').toUpperCase();
        if (st === 'EXPORTED' || st === 'COMPLETED' || st === 'PACKED') {
          const todayDate = new Date().toISOString().slice(0, 10);
          const nowIso = new Date().toISOString();
          const branchCode = req.session.user?.branch_code || 'CP01';
          const userId = req.session.user?.id;
          let updatedFifoCount = 0;
          for (const item of (items || [])) {
            const sku = item.sku;
            for (const sn of (item.serials || [])) {
              try {
                await supabase.from('serial_check_log').upsert({
                  serial: sn,
                  sku,
                  branch_code: branchCode,
                  check_date: todayDate,
                  checked_out: true,
                  checked_by: userId,
                  checked_at: nowIso,
                }, { onConflict: 'serial,check_date' });
                updatedFifoCount++;
              } catch (e) {}
            }
          }
          return res.json({
            success: true,
            isAlreadyDone: true,
            status: st,
            updatedFifoCount,
            message: `Đơn hàng #${documentId || requestId} thực tế ĐÃ HOÀN TẤT XUẤT KHO (${st === 'PACKED' ? 'ĐÃ ĐÓNG GÓI' : 'ĐÃ BÀN GIAO'}) trên ERP trước đó! Hệ thống đã tự động đồng bộ và tick "Đã xuất" cho ${updatedFifoCount} serial vào bảng FIFO.`
          });
        }
      } catch (checkErr) {
        console.warn('[QuickExport] Lỗi kiểm tra lại trạng thái đơn khi gặp State of request is not valid:', checkErr.message);
      }
    }
    res.status(400).json({ success: false, message: err.message });
  }
});

// 8. Tra cứu tồn kho vật lý theo BIN (cho sản phẩm không quản lý serial hoặc tra cứu nhanh)
app.get('/api/quick-export/stock-by-bin', requireAuth, async (req, res) => {
  try {
    const sku = req.query.sku;
    let siteId = req.query.siteId;
    const userBranch = (req.session.user?.branch_code || '').toUpperCase().trim();
    if (!siteId) {
      siteId = BRANCH_TO_SITE_ID[userBranch] || userBranch;
    }
    const token = await resolveUserExportToken(req);
    const data = await quickExportService.getStockQuantityByBin(sku, siteId, token);
    res.json({ success: true, data });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// ------------------------- Start server / export -------------------------
const PORT = Number(process.env.PORT) || 3000;
if (process.env.VERCEL || require.main !== module) {
  module.exports = app;
} else {
  app.listen(PORT, () => {
    process.stdout.write(`Local: http://localhost:${PORT}\n`);
    console.log(`Local: http://localhost:${PORT}`);
  });
}

 