let _googleInstance = null;
const google = new Proxy({}, {
  get(target, prop) {
    if (!_googleInstance) {
      _googleInstance = require('googleapis').google;
    }
    return _googleInstance[prop];
  }
});
require('dotenv').config();
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

// Read credentials
const keyFile = path.resolve(__dirname, '../bigquery-key.json');
const PROMO_SPREADSHEET_ID = '1OHu6fDU-9IdHuvNFQfSoc1KUSFjvkOXjsGJixgSjnME';

// Initialize Supabase Client lazily
let _supabaseClient = null;
function getSupabase() {
  if (!_supabaseClient) {
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY;
    if (!supabaseUrl || !supabaseKey) {
      throw new Error("Missing Supabase credentials in process.env");
    }
    _supabaseClient = createClient(supabaseUrl, supabaseKey);
  }
  return _supabaseClient;
}
const supabase = new Proxy({}, {
  get(target, prop) {
    return getSupabase()[prop];
  }
});

/**
 * Robust parser to extract date range from a string.
 * Supports DD/MM - DD/MM/YYYY, DD.MM - DD.MM.YYYY, typos like 2926 -> 2026,
 * single-ended deadlines like "đến hết 31.10.2026" or "01/06 đến khi có thông báo mới".
 */
function parseDateRange(text) {
  if (!text) return { startDate: null, endDate: null };

  let raw = String(text).trim();

  // 1. Loại bỏ các chuỗi tiền tệ (3.990K, 4.990.000đ...), tỷ lệ phần trăm (0.49%...)
  // Dùng unicode flag để không nuốt chữ cái 'đ' trong 'đến'
  let clean = raw
    .replace(/\d+([.,]\d+)?\s*(k|triệu|tr|vnđ|vnd|đồng)\b/giu, ' ')
    .replace(/\d+([.,]\d+)?\s*đ(?!\p{L})/giu, ' ')
    .replace(/\d+([.,]\d+)?%/g, ' ')
    .replace(/2926/g, '2026') // Sửa lỗi gõ nhầm năm 2926 thành 2026
    .replace(/\s+/g, ' ')
    .trim();

  // Chuẩn hóa dấu chấm giữa các số ngày tháng thành dấu gạch chéo: DD.MM.YYYY hoặc DD.MM
  clean = clean.replace(/(\d{1,2})\.(\d{1,2})(?:\.(\d{2,4}))?/g, (m, d, mo, y) => {
    return y ? `${d}/${mo}/${y}` : `${d}/${mo}`;
  });

  const dateRegex = /(\d{1,2})\/(\d{1,2})(?:\/(\d{2,4}))?/g;
  const matches = [];
  let match;
  while ((match = dateRegex.exec(clean)) !== null) {
    const d = parseInt(match[1], 10);
    const m = parseInt(match[2], 10);
    let y = match[3] ? parseInt(match[3], 10) : 2026;
    if (y < 100) y += 2000;

    // Validate ngày tháng hợp lệ
    if (d >= 1 && d <= 31 && m >= 1 && m <= 12) {
      matches.push({ day: d, month: m, year: y });
    }
  }

  if (matches.length >= 2) {
    if (matches[0].year === 2026 && matches[1].year !== 2026) {
      matches[0].year = matches[1].year;
    } else if (matches[0].year !== 2026 && matches[1].year === 2026) {
      matches[1].year = matches[0].year;
    }
    const startDate = `${matches[0].year}-${String(matches[0].month).padStart(2, '0')}-${String(matches[0].day).padStart(2, '0')}`;
    const endDate = `${matches[1].year}-${String(matches[1].month).padStart(2, '0')}-${String(matches[1].day).padStart(2, '0')}`;
    return { startDate, endDate };
  } else if (matches.length === 1) {
    const isStartOnly = /từ|bắt đầu|kể từ|đến khi|thông báo mới/i.test(raw);
    const isEndOnly = /đến hết|hạn sử dụng|hsd|kết thúc/i.test(raw);
    const formatted = `${matches[0].year}-${String(matches[0].month).padStart(2, '0')}-${String(matches[0].day).padStart(2, '0')}`;
    if (isStartOnly) {
      return { startDate: formatted, endDate: '2026-12-31' };
    }
    if (isEndOnly) {
      const startMonth = String(matches[0].month).padStart(2, '0');
      return { startDate: `${matches[0].year}-${startMonth}-01`, endDate: formatted };
    }
    return { startDate: '2026-01-01', endDate: formatted };
  }
  return { startDate: null, endDate: null };
}

/**
 * Kiểm tra xem một ô có phải tiêu đề cột SKU không
 */
function isSkuHeaderCell(cell) {
  const val = String(cell || '').trim().toLowerCase();
  if (!val) return false;
  if (val === 'sku' || val === 'sku id' || val === 'mã sp' || val === 'mã hàng' || val === 'mã sku' || val === 'sku bán' || val === 'sku laptop') return true;
  // Bắt các trường hợp như "sku máy in", "sku laptop", "sku mực in", "sku giấy in"
  if (val.startsWith('sku') && !val.includes('quà') && !val.includes('tặng') && !val.includes('gift') && !val.includes('lắp đặt') && !val.includes('áp dụng:')) {
    return true;
  }
  return false;
}

/**
 * Phân giải quà tặng và coupon tương ứng cho từng dòng Laptop trong sheet "Bộ quà Laptop Q3"
 */
function resolveBoQuaGift(segment, brand, sku) {
  // 1. Các SKU cấu hình đặc biệt Acer Predator (tặng trọn gói 3 - 4 món)
  if (sku === '251202421') {
    return {
      giftSku: '251209873, 240705064, 250909708, 251205715',
      giftName: 'Bộ 4 món: Chuột Predator Cestus 353 + Balo Predator + Phím Predator Aethon 330 + Màn hình Acer 23.8" Nitro',
      coupon: 'Giảm 300K cho đơn hàng từ 700K mua phụ kiện/gear',
      cleanBrand: 'Acer'
    };
  }
  if (sku === '250800203' || sku === '240702562') {
    return {
      giftSku: '240705064, 19070073, 250909708',
      giftName: 'Bộ 3 món: Balo Predator + Tai nghe Predator + Phím Predator Aethon 330',
      coupon: 'Giảm 300K cho đơn hàng từ 700K mua phụ kiện/gear',
      cleanBrand: 'Acer'
    };
  }

  const b = (brand || '').toLowerCase().trim();
  const seg = (segment || '').toLowerCase().trim();
  const isGaming = (seg === 'gaming' || b.includes('gaming')) && !seg.includes('non') && !b.includes('non');

  if (b.includes('asus')) {
    if (isGaming) {
      return {
        giftSku: '251001173',
        giftName: 'Balo Asus BP1800 ROG BACKPACK',
        coupon: 'Giảm 300K cho đơn từ 700K mua phụ kiện/gear',
        cleanBrand: 'Asus'
      };
    } else {
      return {
        giftSku: '230402215',
        giftName: 'Túi đeo lưng/ Balo laptop Targus 15.6 TSB883 Black (logo Phong Vũ)',
        coupon: 'Giảm 300K cho đơn từ 700K mua phụ kiện/gear',
        cleanBrand: 'Asus'
      };
    }
  }

  if (b.includes('acer')) {
    if (b.includes('gaming 3') || b.includes('suv')) {
      return {
        giftSku: '19070052',
        giftName: 'Ba lô Acer Gaming SUV (Quà tặng)',
        coupon: 'Giảm 300K cho đơn từ 700K mua phụ kiện/gear',
        cleanBrand: 'Acer'
      };
    }
    if (b.includes('gaming 4') || b.includes('predator')) {
      return {
        giftSku: '240705064',
        giftName: 'BALO ACER PBG591/PREDATOR GAMING BACKPACK 15"/17"',
        coupon: 'Giảm 300K cho đơn từ 700K mua phụ kiện/gear',
        cleanBrand: 'Acer'
      };
    }
    if (b.includes('non-gaming 1')) {
      return {
        giftSku: '1200237',
        giftName: 'Ba lô Acer (Quà tặng)',
        coupon: 'Giảm 300K cho đơn từ 700K mua phụ kiện/gear',
        cleanBrand: 'Acer'
      };
    }
    return {
      giftSku: '1200237',
      giftName: 'Ba lô Acer (Quà tặng)',
      coupon: null,
      cleanBrand: 'Acer'
    };
  }

  if (b.includes('dell')) {
    return {
      giftSku: '230402215',
      giftName: 'Túi đeo lưng/ Balo laptop Targus 15.6 TSB883 Black (logo Phong Vũ)',
      coupon: null,
      cleanBrand: 'Dell'
    };
  }

  if (b.includes('lenovo')) {
    if (b.includes('gaming 1')) {
      return {
        giftSku: '231003262',
        giftName: 'Túi đeo lưng/ Balo Ideapad Gaming - Đen',
        coupon: null,
        cleanBrand: 'Lenovo'
      };
    }
    if (b.includes('gaming 2') || b.includes('legion')) {
      return {
        giftSku: '220609559',
        giftName: 'Ba lô máy tính Lenovo Legion Active Gaming Backpack',
        coupon: null,
        cleanBrand: 'Lenovo'
      };
    }
    return {
      giftSku: '230402215',
      giftName: 'Túi đeo lưng/ Balo laptop Targus 15.6 TSB883 Black (logo Phong Vũ)',
      coupon: null,
      cleanBrand: 'Lenovo'
    };
  }

  if (b.includes('msi')) {
    return {
      giftSku: isGaming ? '240804241' : '-',
      giftName: isGaming ? 'Balo MSI (sẵn trong thùng) + Chuột MSI Gaming M99 Pro Box 20th' : 'Balo MSI (sẵn trong thùng)',
      coupon: b.includes('seri 5') ? 'Giảm 300K cho đơn từ 700K mua phụ kiện/gear' : null,
      cleanBrand: 'MSI'
    };
  }

  if (b.includes('gigabyte')) {
    return {
      giftSku: '250415967',
      giftName: 'Ba lô Laptop Gigabyte (BALOGGB)',
      coupon: null,
      cleanBrand: 'Gigabyte'
    };
  }

  if (b.includes('hp')) {
    return {
      giftSku: '230402215',
      giftName: 'Túi đeo lưng/ Balo laptop Targus 15.6 TSB883 Black (logo Phong Vũ)',
      coupon: 'Giảm 300K cho đơn từ 700K mua phụ kiện/gear',
      cleanBrand: 'HP'
    };
  }

  return {
    giftSku: '230402215',
    giftName: 'Balo quà tặng Phong Vũ',
    coupon: null,
    cleanBrand: brand || 'All'
  };
}

/**
 * Main function to sync promotions from Google Sheets into Supabase promo_sku_master
 */
async function syncPromotions() {
  console.log("[Sync CTKM] Bắt đầu kết nối Google Sheets...");
  const auth = new google.auth.GoogleAuth({
    keyFile,
    scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
  });
  const sheets = google.sheets({ version: 'v4', auth });

  // 1. Get Spreadsheet metadata
  const meta = await sheets.spreadsheets.get({
    spreadsheetId: PROMO_SPREADSHEET_ID,
  });

  // BẢO VỆ CHẶT CHẼ: CHỈ LẤY CÁC SHEET ĐANG HIỂN THỊ (KHÔNG BỊ ẨN)
  // Loại bỏ các sheet cũ đã bị ẩn đi (như FS Laptop 2/9, Đổi điểm T8...) để tránh link nhảy nhầm tab
  const visibleSheets = meta.data.sheets.filter(s => !s.properties.hidden);
  console.log(`[Sync CTKM] Tìm thấy ${visibleSheets.length} sheet đang hiển thị (bỏ qua ${meta.data.sheets.length - visibleSheets.length} sheet ẩn).`);

  const sheetsToProcess = visibleSheets.filter(s => {
    const t = s.properties.title;
    if (t === 'Template' || t === 'Overview') return false;
    if (/^sheet\d+$/i.test(t)) return false; // Bỏ qua sheet rỗng tạo tự động
    return true;
  });

  const ranges = sheetsToProcess.map(s => `'${s.properties.title}'!A1:AZ250`);

  console.log(`[Sync CTKM] Đang tải ${ranges.length} sheets bằng batchGet...`);
  const batchRes = await sheets.spreadsheets.values.batchGet({
    spreadsheetId: PROMO_SPREADSHEET_ID,
    ranges: ranges
  });

  const valueRanges = batchRes.data.valueRanges || [];
  const allRecords = [];

  for (let idx = 0; idx < sheetsToProcess.length; idx++) {
    const sheetObj = sheetsToProcess[idx];
    const title = sheetObj.properties.title;
    const sheetId = String(sheetObj.properties.sheetId);
    const rows = valueRanges[idx]?.values || [];
    
    if (rows.length < 3) {
      console.log(`[Sync CTKM] Bỏ qua sheet rỗng/không đủ dữ liệu: "${title}".`);
      continue;
    }

    // Link trực tiếp đến đúng tab của sheet này
    const defaultLink = `https://docs.google.com/spreadsheets/d/${PROMO_SPREADSHEET_ID}/edit#gid=${sheetId}`;
    const upperTitle = title.toUpperCase();

    // =========================================================================
    // XỬ LÝ ĐẶC THÙ 1: BỘ QUÀ LAPTOP (QUÝ 3 / 2026)
    // Ma trận quà phức tạp gồm 2 block: Block định nghĩa quà (row 16-44) và Block Laptop (row 48+)
    // =========================================================================
    if (upperTitle.includes('BỘ QUÀ LAPTOP')) {
      console.log(`[Sync CTKM] Xử lý ma trận phức tạp BỘ QUÀ LAPTOP: "${title}"...`);
      const pName = rows[1]?.[1] || "Ưu đãi Bộ quà Laptop đến 3 Triệu Q3'2026";
      const conditions = [rows[7]?.[1], rows[9]?.[1]].filter(Boolean).join('\n\n') || 'Áp dụng theo danh sách chỉ định.';
      let countBoQua = 0;

      for (let i = 48; i < rows.length; i++) {
        const r = rows[i] || [];
        
        // 1. Nhánh Non Gaming (Col C=Brand/Group, Col D=SKU, Col E=Name)
        const s1 = String(r[3] || '').replace(/[,.\s]/g, '');
        if (/^\d{6,12}$/.test(s1)) {
          const gift = resolveBoQuaGift('Non Gaming', r[2], s1);
          allRecords.push({
            sheet_name: title,
            program_name: pName,
            time_range: 'Thời gian: 07.07 - 31.10.2026',
            start_date: '2026-07-07',
            end_date: '2026-10-31',
            apply_channels: 'All channels',
            conditions,
            detail_link: defaultLink,
            sku: s1,
            category: 'Máy tính xách tay / Laptop',
            product_name: String(r[4] || '').trim(),
            brand: gift.cleanBrand,
            list_price: null,
            promo_price: null,
            promo_percent: null,
            limit_qty: null,
            online_coupon: gift.coupon,
            no_gift_price: null,
            gift_sku: gift.giftSku,
            gift_name: gift.giftName,
            kfi_value: null,
          });
          countBoQua++;
        }

        // 2. Nhánh Gaming (Col K=Brand/Group, Col L=SKU, Col M=Name)
        const s2 = String(r[11] || '').replace(/[,.\s]/g, '');
        if (/^\d{6,12}$/.test(s2)) {
          const gift = resolveBoQuaGift('Gaming', r[10], s2);
          allRecords.push({
            sheet_name: title,
            program_name: pName,
            time_range: 'Thời gian: 07.07 - 31.10.2026',
            start_date: '2026-07-07',
            end_date: '2026-10-31',
            apply_channels: 'All channels',
            conditions,
            detail_link: defaultLink,
            sku: s2,
            category: 'Máy tính xách tay / Laptop',
            product_name: String(r[12] || '').trim(),
            brand: gift.cleanBrand,
            list_price: null,
            promo_price: null,
            promo_percent: null,
            limit_qty: null,
            online_coupon: gift.coupon,
            no_gift_price: null,
            gift_sku: gift.giftSku,
            gift_name: gift.giftName,
            kfi_value: null,
          });
          countBoQua++;
        }
      }

      console.log(`[Sync CTKM] Đã gắn đúng Quà tặng & Coupon cho ${countBoQua} SKU laptop trong "${title}".`);
      continue;
    }

    // =========================================================================
    // XỬ LÝ ĐẶC THÙ 2: ĐỔI ĐIỂM THI THPT (T10 & T9)
    // =========================================================================
    if (upperTitle.includes('ĐỔI ĐIỂM') || upperTitle.includes('ĐIỂM THI')) {
      const isT10 = upperTitle.includes('T10') || upperTitle.includes('THÁNG 10');
      const startDate = isT10 ? '2026-10-01' : '2026-09-01';
      const endDate = isT10 ? '2026-10-31' : '2026-09-30';
      const pName = isT10 
        ? 'Đổi điểm thi THPT - Giảm đến 5 Triệu (Tháng 10)' 
        : 'Đổi điểm thi THPT - Giảm đến 5 Triệu (Tháng 9)';
      const cond = `* THỂ LỆ & ĐIỀU KIỆN CHƯƠNG TRÌNH ĐỔI ĐIỂM THI THPT 2026:
- Đối tượng: Tân sinh viên 2K8 tham dự kỳ thi THPT 2026.
- Mức 5 Triệu & 3 Triệu: Áp dụng cho các SKU laptop chỉ định (Điểm >= 9.0).
- Mức 2 Triệu & 1 Triệu: Áp dụng cho Laptop Dell, HP, Gigabyte, Asus.
- Lưu ý: Laptop Acer hết ngân sách từ 5/9, Laptop MSI & Lenovo hết ngân sách từ 28/9.`;

      let countExam = 0;
      // Trích xuất SKU 5 Tr (col A) và 3 Tr (col H) từ row 68 trở đi
      for (let i = 68; i < rows.length; i++) {
        const r = rows[i] || [];
        const s5 = String(r[0] || '').replace(/[,.\s]/g, '');
        const n5 = String(r[1] || '').trim();
        if (/^\d{6,12}$/.test(s5)) {
          allRecords.push({
            sheet_name: title,
            program_name: pName,
            time_range: `Thời gian: ${startDate} - ${endDate}`,
            start_date: startDate,
            end_date: endDate,
            apply_channels: 'All channels',
            conditions: cond,
            detail_link: defaultLink,
            sku: s5,
            category: 'Máy tính xách tay / Laptop',
            product_name: n5 || 'Laptop chỉ định mức 5 Triệu',
            brand: 'All',
            list_price: null,
            promo_price: 5000000,
            promo_percent: null,
            limit_qty: '1 voucher/khách hàng',
            online_coupon: 'Voucher Đổi điểm 5.000.000đ (Điểm >= 9.0)',
            no_gift_price: null,
            gift_sku: null,
            gift_name: null,
            kfi_value: null,
          });
          countExam++;
        }

        const s3 = String(r[7] || '').replace(/[,.\s]/g, '');
        const b3 = String(r[5] || '').trim();
        if (/^\d{6,12}$/.test(s3)) {
          allRecords.push({
            sheet_name: title,
            program_name: pName,
            time_range: `Thời gian: ${startDate} - ${endDate}`,
            start_date: startDate,
            end_date: endDate,
            apply_channels: 'All channels',
            conditions: cond,
            detail_link: defaultLink,
            sku: s3,
            category: 'Máy tính xách tay / Laptop',
            product_name: 'Laptop chỉ định mức 3 Triệu',
            brand: b3 || 'All',
            list_price: null,
            promo_price: 3000000,
            promo_percent: null,
            limit_qty: '1 voucher/khách hàng',
            online_coupon: 'Voucher Đổi điểm 3.000.000đ (Điểm >= 9.0)',
            no_gift_price: null,
            gift_sku: null,
            gift_name: null,
            kfi_value: null,
          });
          countExam++;
        }
      }

      // Add general brand records for 1Tr and 2Tr
      const activeBrands = ['HP', 'Dell', 'Asus', 'Gigabyte'];
      activeBrands.forEach(b => {
        allRecords.push({
          sheet_name: title,
          program_name: pName,
          time_range: `Thời gian: ${startDate} - ${endDate}`,
          start_date: startDate,
          end_date: endDate,
          apply_channels: 'All channels',
          conditions: cond,
          detail_link: defaultLink,
          sku: 'NH01',
          category: 'Máy tính xách tay / Laptop',
          brand: b,
          product_name: `Toàn bộ Laptop ${b} | Ưu đãi Đổi điểm thi THPT (1Tr - 2Tr)`,
          list_price: null,
          promo_price: 2000000,
          promo_percent: null,
          limit_qty: null,
          online_coupon: 'Voucher Đổi điểm 1Tr - 2Tr',
          no_gift_price: null,
          gift_sku: null,
          gift_name: null,
          kfi_value: null,
        });
        countExam++;
      });

      console.log(`[Sync CTKM] Đã xử lý ${countExam} dòng Đổi điểm thi cho "${title}" (${startDate} -> ${endDate}).`);
      continue;
    }

    // =========================================================================
    // XỬ LÝ ĐẶC THÙ 3: HSSV
    // =========================================================================
    if (upperTitle.includes('HSSV')) {
      console.log(`[Sync CTKM] Xử lý sheet đặc thù HSSV: "${title}"...`);
      const hssvCats = [
        { sku: 'NH01', name: 'Máy tính xách tay / Laptop' },
        { sku: 'NH05', name: 'Apple Laptop / MacBook' }
      ];
      hssvCats.forEach(cat => {
        allRecords.push({
          sheet_name: title,
          program_name: 'Ưu đãi Học sinh - Sinh viên (HSSV) Quý 3',
          time_range: 'Thời gian: 12/07/2026 - 04/10/2026',
          start_date: '2026-07-12',
          end_date: '2026-10-04',
          apply_channels: 'All channels',
          conditions: 'Ưu đãi dành riêng cho HSSV xác thực qua App Phong Vũ. Giảm thêm đến 500.000đ.',
          detail_link: defaultLink,
          sku: cat.sku,
          category: cat.name,
          product_name: `Toàn bộ ${cat.name} | Ưu đãi HSSV`,
          brand: 'All',
          list_price: null,
          promo_price: null,
          promo_percent: null,
          limit_qty: '1 mã/khách hàng',
          online_coupon: 'Giảm đến 500K qua App Phong Vũ',
          no_gift_price: null,
          gift_sku: null,
          gift_name: null,
          kfi_value: null,
        });
      });
      continue;
    }

    // =========================================================================
    // TÌM HEADER & DATE TRONG SHEET THƯỜNG
    // =========================================================================
    const headerPositions = [];
    for (let i = 0; i < Math.min(rows.length, 35); i++) {
      const row = rows[i] || [];
      const hasSku = row.some(isSkuHeaderCell);
      if (hasSku) {
        headerPositions.push({ idx: i, type: 'sku' });
        continue;
      }
      const hasCatName = row.some(cell => {
        const val = String(cell || '').trim().toLowerCase();
        return val === 'product name' || val === 'category' || val === 'ngành hàng' || val === 'cat' || val === 'ngành';
      });
      if (hasCatName && row.filter(Boolean).length >= 2) {
        headerPositions.push({ idx: i, type: 'cat' });
      }
    }

    // NÂNG CẤP ĐẶC BIỆT: VÒNG LẶP QUÉT NGÀY CHUẨN XÁC, KHÔNG BAO GIỜ BREAK SỚM KHI NGÀY NULL
    let startDate = null;
    let endDate = null;
    let timeRangeText = '';
    const maxDateSearchRow = headerPositions.length > 0 ? headerPositions[0].idx : Math.min(rows.length, 25);
    for (let i = 0; i < maxDateSearchRow; i++) {
      const row = rows[i] || [];
      const rowText = row.filter(Boolean).join(' ');
      if (!rowText) continue;

      if (/thời gian|hiệu lực|áp dụng|timeline|từ ngày|hạn|hsd|đến hết/i.test(rowText) || /\d{1,2}[./]\d{1,2}/.test(rowText)) {
        const parsed = parseDateRange(rowText);
        if (parsed.startDate && parsed.endDate) {
          startDate = parsed.startDate;
          endDate = parsed.endDate;
          timeRangeText = rowText;
          break; // Chỉ break khi THỰC SỰ tìm thấy ngày hợp lệ!
        }
      }
    }

    if (!startDate || !endDate) {
      startDate = '2026-01-01';
      endDate = '2026-12-31';
    }

    let programName = title;
    if (rows[1]) {
      const nameCell = rows[1].find(c => String(c || '').trim().length > 3 && !/thời gian|kênh|lưu ý/i.test(String(c)));
      if (nameCell) programName = String(nameCell).trim();
    }

    // =========================================================================
    // SHEET TOÀN SÀN / THANH TOÁN (SKU=ALL)
    // =========================================================================
    if (headerPositions.length === 0) {
      const isUniversalSheet = /shopeepay|vnpay|tpbank|vib|payoo|homecredit|shinhan|mở thẻ|loyalty|app quý|vệ sinh miễn phí/i.test(title);
      if (isUniversalSheet) {
        let couponInfo = '';
        let percentVal = null;
        const lowerTitle = title.toLowerCase();
        if (lowerTitle.includes('shopeepay')) {
          couponInfo = 'Giảm 5% tối đa 500.000đ khi quét QR ShopeePay/SPayLater';
          percentVal = 5;
        } else if (lowerTitle.includes('vnpay')) {
          couponInfo = 'Giảm 100K (đơn 10Tr), 150K (đơn 20Tr), 250K (đơn 30Tr), 1Tr (đơn 70Tr) qua VNPAY-QR';
        } else if (lowerTitle.includes('tpbank')) {
          couponInfo = 'Giảm 20% tối đa 500K - 800K khi mở thẻ TPBank EVO hoặc Trả góp 0%';
          percentVal = 20;
        } else if (lowerTitle.includes('vib')) {
          couponInfo = 'Voucher giảm 20% tối đa 600K - 1.000.000đ khi mở thẻ tín dụng VIB';
          percentVal = 20;
        } else if (lowerTitle.includes('app')) {
          couponInfo = 'Giảm 5% tối đa 150.000đ khi mua qua App Phong Vũ';
          percentVal = 5;
        } else if (lowerTitle.includes('loyalty')) {
          couponInfo = 'Giảm 10% - 20% khi đổi điểm Loyalty trên App Phong Vũ';
        } else if (lowerTitle.includes('vệ sinh')) {
          couponInfo = 'Miễn phí 100% dịch vụ vệ sinh Laptop / PC tại showroom';
        }

        allRecords.push({
          sheet_name: title,
          program_name: programName,
          time_range: timeRangeText || `Hiệu lực: ${startDate} - ${endDate}`,
          start_date: startDate,
          end_date: endDate,
          apply_channels: 'All channels',
          conditions: 'Áp dụng cho toàn bộ sản phẩm kinh doanh tại Phong Vũ theo thể lệ chương trình.',
          detail_link: defaultLink,
          sku: 'ALL',
          category: 'Ưu đãi thanh toán & Toàn sàn',
          product_name: programName,
          brand: 'Toàn hệ thống',
          list_price: null,
          promo_price: null,
          promo_percent: percentVal,
          limit_qty: null,
          online_coupon: couponInfo || 'Xem chi tiết thể lệ chương trình',
          no_gift_price: null,
          gift_sku: null,
          gift_name: null,
          kfi_value: null,
        });
        console.log(`[Sync CTKM] Đã tạo record toàn sàn (SKU=ALL) cho "${title}" (${startDate} -> ${endDate}).`);
        continue;
      }
      continue;
    }

    // =========================================================================
    // SHEET CÓ HEADER SKU BÌNH THƯỜNG
    // =========================================================================
    let countSheetRows = 0;
    for (let hIdx = 0; hIdx < headerPositions.length; hIdx++) {
      const headerPos = headerPositions[hIdx];
      const headerIdx = headerPos.idx;
      const nextHeaderIdx = headerPositions[hIdx + 1] ? headerPositions[hIdx + 1].idx : rows.length;
      const headerRow = rows[headerIdx];

      const skuIndexes = [];
      headerRow.forEach((cell, cIdx) => {
        if (isSkuHeaderCell(cell)) {
          skuIndexes.push(cIdx);
        } else if (headerPos.type === 'cat') {
          const val = String(cell || '').trim().toLowerCase();
          if (val === 'product name' || val === 'category' || val === 'ngành hàng' || val === 'cat' || val === 'ngành') {
            skuIndexes.push(cIdx);
          }
        }
      });

      const colMaps = [];
      skuIndexes.forEach((skuColIdx, sIdx) => {
        const nextSkuColIdx = skuIndexes[sIdx + 1];
        const endIdx = nextSkuColIdx || headerRow.length;
        const colMap = { sku: skuColIdx, programName };

        // Kiểm tra xem cột trước đó có phải là Brand không (như Brand ở cột C, SKU ở cột D)
        if (skuColIdx > 0) {
          const prevVal = String(headerRow[skuColIdx - 1] || '').trim().toLowerCase();
          if (prevVal.includes('brand') || prevVal.includes('hãng') || prevVal.includes('thương hiệu')) {
            colMap.brand = skuColIdx - 1;
          }
        }

        for (let c = skuColIdx + 1; c < endIdx; c++) {
          const cell = headerRow[c];
          const val = String(cell || '').trim().toLowerCase();
          if (!val) continue;

          if (val.includes('category') || val.includes('ngành hàng') || val.includes('nhóm hàng') || val === 'cat' || val === 'ngành') {
            colMap.category = c;
          } else if (val.includes('name') || val === 'tên' || val === 'sản phẩm' || val.includes('tên sản phẩm') || val === 'model') {
            colMap.name = c;
          } else if (val.includes('brand') || val.includes('hãng') || val.includes('thương hiệu')) {
            colMap.brand = c;
          } else if (val.includes('ny') || val.includes('niêm yết') || val.includes('bán lẻ') || val === 'list price') {
            colMap.list_price = c;
          } else if (val.includes('giá km') || val.includes('khuyến mãi') || val.includes('flash sale') || val === 'km' || val === 'giá') {
            colMap.promo_price = c;
          } else if (val.includes('%') || val.includes('%discount') || val.includes('%km')) {
            colMap.promo_percent = c;
          } else if (val.includes('giới hạn') || val.includes('số lượng') || val.includes('limit') || val.includes('qty')) {
            colMap.limit_qty = c;
          } else if (val.includes('online') || val.includes('coupon') || val.includes('mã') || val.includes('giảm thêm')) {
            colMap.online_coupon = c;
          } else if (val.includes('không lấy quà') || val.includes('no gift')) {
            colMap.no_gift_price = c;
          } else if (val.includes('sku quà') || val.includes('mã quà') || val.includes('sku tặng')) {
            colMap.gift_sku = c;
          } else if ((val.includes('quà') || val.includes('tặng')) && !val.includes('sku')) {
            colMap.gift_name = c;
          } else if (val.startsWith('kfi') || val === 'end user') {
            colMap.kfi_value = c;
          }
        }
        colMaps.push(colMap);
      });

      for (let j = headerIdx + 1; j < nextHeaderIdx; j++) {
        const r = rows[j];
        if (!r || r.length === 0 || r.filter(Boolean).length === 0) continue;

        for (const colMap of colMaps) {
          const skuRaw = String(r[colMap.sku] || '').trim();
          if (!skuRaw || skuRaw === '-' || skuRaw.toLowerCase() === 'sku' || skuRaw.toLowerCase() === 'tên') continue;

          let sku = skuRaw.replace(/[,.\s]/g, '');
          if (!/^\d+$/.test(sku) && !/^NH\d+/i.test(skuRaw)) {
            const matchSubcat = skuRaw.match(/^(NH\d+-\d+(?:-\d+)?)/i);
            if (matchSubcat) {
              sku = matchSubcat[1].toUpperCase();
            } else {
              continue;
            }
          }

          const parseMoney = (val) => {
            if (!val) return null;
            const num = parseFloat(String(val).replace(/[^0-9.-]/g, ''));
            return isNaN(num) ? null : num;
          };

          const parsePercent = (val) => {
            if (!val) return null;
            const num = parseFloat(String(val).replace(/[^0-9.-]/g, ''));
            return isNaN(num) ? null : num;
          };

          allRecords.push({
            sheet_name: title,
            program_name: colMap.programName || programName,
            time_range: timeRangeText || `Hiệu lực: ${startDate} - ${endDate}`,
            start_date: startDate,
            end_date: endDate,
            apply_channels: 'All channels',
            conditions: 'Áp dụng theo danh sách sản phẩm chỉ định.',
            detail_link: defaultLink,
            sku: sku,
            category: colMap.category !== undefined ? String(r[colMap.category] || '').trim() : null,
            product_name: colMap.name !== undefined ? String(r[colMap.name] || '').trim() : null,
            brand: colMap.brand !== undefined ? String(r[colMap.brand] || '').trim() : null,
            list_price: colMap.list_price !== undefined ? parseMoney(r[colMap.list_price]) : null,
            promo_price: colMap.promo_price !== undefined ? parseMoney(r[colMap.promo_price]) : null,
            promo_percent: colMap.promo_percent !== undefined ? parsePercent(r[colMap.promo_percent]) : null,
            limit_qty: colMap.limit_qty !== undefined ? String(r[colMap.limit_qty] || '').trim() : null,
            online_coupon: colMap.online_coupon !== undefined ? String(r[colMap.online_coupon] || '').trim() : null,
            no_gift_price: colMap.no_gift_price !== undefined ? parseMoney(r[colMap.no_gift_price]) : null,
            gift_sku: colMap.gift_sku !== undefined ? String(r[colMap.gift_sku] || '').trim() : null,
            gift_name: colMap.gift_name !== undefined ? String(r[colMap.gift_name] || '').trim() : null,
            kfi_value: colMap.kfi_value !== undefined ? parseMoney(r[colMap.kfi_value]) : null,
          });
          countSheetRows++;
        }
      }
    }
    console.log(`[Sync CTKM] Đã bóc tách được ${countSheetRows} sản phẩm từ sheet "${title}".`);
  }

  // 4. Update Database Supabase
  if (allRecords.length > 0) {
    console.log(`[Sync CTKM] Tổng cộng có ${allRecords.length} records. Tiến hành cập nhật Database Supabase...`);
    
    // Clear old data
    const { error: deleteErr } = await supabase.from('promo_sku_master').delete().neq('id', 0);
    if (deleteErr) {
      throw new Error("Không thể xóa dữ liệu cũ trong promo_sku_master: " + deleteErr.message);
    }

    // Insert new data in batches of 200
    const batchSize = 200;
    for (let i = 0; i < allRecords.length; i += batchSize) {
      const batch = allRecords.slice(i, i + batchSize);
      const { error: insertErr } = await supabase.from('promo_sku_master').insert(batch);
      if (insertErr) {
        throw new Error("Lỗi chèn dữ liệu đồng bộ vào promo_sku_master: " + insertErr.message);
      }
    }
    console.log(`[Sync CTKM] Đồng bộ thành công ${allRecords.length} records vào database.`);
  } else {
    console.log("[Sync CTKM] Không có dữ liệu để đồng bộ.");
  }
}

module.exports = { syncPromotions, parseDateRange, resolveBoQuaGift };
