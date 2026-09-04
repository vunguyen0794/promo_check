const { google } = require('googleapis');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

// Read credentials
const keyFile = path.resolve(__dirname, '../bigquery-key.json');
const PROMO_SPREADSHEET_ID = '1OHu6fDU-9IdHuvNFQfSoc1KUSFjvkOXjsGJixgSjnME';

// Initialize Supabase Client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

/**
 * Robust parser to extract date range from a string
 */
function parseDateRange(text) {
  if (!text) return { startDate: null, endDate: null };

  // 1. Loại bỏ các chuỗi tiền tệ (3.990K, 4.990.000đ...) và tỷ lệ phần trăm (0.49%...) để tránh match nhầm
  let clean = String(text)
    .replace(/\d+([.,]\d+)?\s*(k|triệu|tr|đ|vnđ|vnd)/gi, ' ')
    .replace(/\d+([.,]\d+)?%/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  // Chuẩn hóa dấu chấm giữa các số ngày tháng thành dấu gạch chéo
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

    // Validate hợp lệ ngày tháng
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
    const endDate = `${matches[0].year}-${String(matches[0].month).padStart(2, '0')}-${String(matches[0].day).padStart(2, '0')}`;
    return { startDate: '2026-01-01', endDate };
  }
  return { startDate: null, endDate: null };
}

/**
 * Kiểm tra xem một ô có phải tiêu đề cột SKU không
 */
function isSkuHeaderCell(cell) {
  const val = String(cell || '').trim().toLowerCase();
  if (!val) return false;
  if (val === 'sku' || val === 'sku id' || val === 'mã sp' || val === 'mã hàng' || val === 'mã sku' || val === 'sku bán') return true;
  // Bắt các trường hợp như "sku máy in", "sku laptop", "sku mực in", "sku giấy in"
  if (val.startsWith('sku') && !val.includes('quà') && !val.includes('tặng') && !val.includes('gift') && !val.includes('lắp đặt') && !val.includes('áp dụng:')) {
    return true;
  }
  return false;
}

/**
 * Main function to sync promotions from Google Sheets
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

  // Filter only visible sheets
  const visibleSheets = meta.data.sheets.filter(s => !s.properties.hidden);
  console.log(`[Sync CTKM] Tìm thấy ${visibleSheets.length} sheet đang hiển thị.`);

  // 2. Fetch Overview data including cell hyperlinks to map campaign links
  console.log("[Sync CTKM] Đang lấy bản đồ link vận hành từ sheet Overview...");
  const overviewResponse = await sheets.spreadsheets.get({
    spreadsheetId: PROMO_SPREADSHEET_ID,
    ranges: ['Overview!A1:J150'],
    includeGridData: true
  });

  const overviewSheet = overviewResponse.data.sheets[0];
  const overviewRows = overviewSheet.data[0].rowData || [];
  const gidLinkMap = new Map();

  overviewRows.forEach(row => {
    const cells = row.values || [];
    const campaignName = cells[1]?.formattedValue;
    const linkCell = cells[7]; // Column H is index 7
    if (campaignName && linkCell) {
      let hyperlink = linkCell.hyperlink || (linkCell.userEnteredValue?.formulaValue) || '';
      if (hyperlink.startsWith('#gid=')) {
        hyperlink = `https://docs.google.com/spreadsheets/d/${PROMO_SPREADSHEET_ID}/edit${hyperlink}`;
      }
      // Extract GID from hyperlink if it's internal
      const matchGid = hyperlink.match(/gid=(\d+)/);
      if (matchGid) {
        const gid = matchGid[1];
        gidLinkMap.set(gid, hyperlink);
      }
    }
  });

  const allRecords = [];

  const sheetsToProcess = visibleSheets.filter(s => s.properties.title !== 'Template' && s.properties.title !== 'Overview');
  const ranges = sheetsToProcess.map(s => `'${s.properties.title}'!A1:AZ250`);

  console.log(`[Sync CTKM] Đang tải ${ranges.length} sheets bằng batchGet...`);
  const batchRes = await sheets.spreadsheets.values.batchGet({
    spreadsheetId: PROMO_SPREADSHEET_ID,
    ranges: ranges
  });

  const valueRanges = batchRes.data.valueRanges || [];

  for (let idx = 0; idx < sheetsToProcess.length; idx++) {
    const sheetObj = sheetsToProcess[idx];
    const title = sheetObj.properties.title;
    const sheetId = String(sheetObj.properties.sheetId);
    const rows = valueRanges[idx]?.values;
    
    if (!rows || rows.length === 0) {
      console.log(`[Sync CTKM] Sheet "${title}" không có dữ liệu.`);
      continue;
    }

    const defaultLink = gidLinkMap.get(sheetId) || `https://docs.google.com/spreadsheets/d/${PROMO_SPREADSHEET_ID}/edit#gid=${sheetId}`;
    const upperTitle = title.toUpperCase();

    // =========================================================================
    // XỬ LÝ ĐẶC THÙ 1: CHƯƠNG TRÌNH HỌC SINH - SINH VIÊN (HSSV)
    // =========================================================================
    if (upperTitle.includes('HSSV')) {
      console.log(`[Sync CTKM] Xử lý sheet đặc thù HSSV: "${title}"...`);
      const hssvConditions = `* THỂ LỆ & ĐIỀU KIỆN CHƯƠNG TRÌNH HSSV QUÝ 3/2026:
- Đối tượng: Khách hàng là Học sinh, Sinh viên (năm sinh 2005 - 2020 hoặc có thẻ HSSV/giấy trúng tuyển còn hiệu lực).
- Cách nhận ưu đãi: Xác thực tài khoản HSSV trên App Phong Vũ (sử dụng email .edu hoặc upload CCCD + thẻ HSSV).
- Hạn mức: Mỗi khách hàng nhận 01 mã ưu đãi/quý.
- Mức giảm: Giảm thêm đến 500.000đ khi mua Laptop tại Phong Vũ (áp dụng theo bậc giá trên App).
- Áp dụng cùng: Quà tặng theo máy của hãng, Ưu đãi thanh toán ShopeePay, VNPAY, Mở thẻ tín dụng TPBank/VIB.
- Không áp dụng cùng: Coupon giảm giá khác, Chương trình Đổi điểm thi THPT.`;

      // Tạo record cho Laptop Windows (NH01) và MacBook (NH05)
      const hssvCats = [
        { sku: 'NH01', name: 'Máy tính xách tay / Laptop' },
        { sku: 'NH05', name: 'Apple Laptop / MacBook' }
      ];

      hssvCats.forEach(cat => {
        allRecords.push({
          sheet_name: title,
          program_name: 'Ưu đãi Học sinh - Sinh viên (HSSV) Quý 3/2026',
          time_range: 'Thời gian: 12/07/2026 - 30/09/2026',
          start_date: '2026-07-12',
          end_date: '2026-09-30',
          apply_channels: 'All channels (Showroom & Online)',
          conditions: hssvConditions,
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
    // XỬ LÝ ĐẶC THÙ 2: CHƯƠNG TRÌNH ĐỔI ĐIỂM THI THPT 2026
    // =========================================================================
    if (upperTitle.includes('ĐỔI ĐIỂM') || upperTitle.includes('ĐIỂM THI')) {
      console.log(`[Sync CTKM] Xử lý sheet đặc thù Đổi điểm thi: "${title}"...`);
      const examConditions = `* THỂ LỆ & ĐIỀU KIỆN CHƯƠNG TRÌNH ĐỔI ĐIỂM THI THPT 2026:
- Đối tượng: Tân sinh viên 2K8 tham dự kỳ thi Tốt nghiệp THPT 2026.
- Chứng từ cần thiết: Xuất trình bản gốc CCCD và Giấy báo điểm / Phiếu báo dự thi THPT 2026 có điểm số hợp lệ.
- Thang điểm và mức giảm cụ thể:
  + Điểm trung bình từ 9.0 - 10.0: Giảm 5.000.000đ (hoặc tặng tai nghe AirPods 4 khi mua MacBook).
  + Điểm trung bình từ 8.0 - <9.0: Giảm 2.000.000đ.
  + Điểm trung bình từ 7.0 - <8.0: Giảm 1.500.000đ.
  + Điểm trung bình từ 6.0 - <7.0: Giảm 1.300.000đ.
  + Điểm trung bình dưới 6.0: Giảm 1.000.000đ.
- Áp dụng cùng: Quà tặng mặc định của hãng, Ưu đãi thanh toán ShopeePay, VNPAY, Thẻ ngân hàng.
- Không áp dụng cùng: Ưu đãi HSSV qua App Phong Vũ, Coupon giảm giá khác.`;

      const examBrands = ['Acer', 'MSI', 'Dell', 'Gigabyte', 'Lenovo', 'HP', 'Asus'];
      examBrands.forEach(b => {
        allRecords.push({
          sheet_name: title,
          program_name: 'Đổi điểm thi THPT 2026 - Giảm đến 5 Triệu cho Laptop',
          time_range: 'Thời gian: 01/07/2026 - 31/10/2026',
          start_date: '2026-07-01',
          end_date: '2026-10-31',
          apply_channels: 'All channels (Showroom & Online)',
          conditions: examConditions,
          detail_link: defaultLink,
          sku: 'NH01',
          category: 'Máy tính xách tay / Laptop',
          brand: b,
          product_name: `Laptop ${b} | Ưu đãi Đổi điểm thi THPT 2026`,
          list_price: null,
          promo_price: null,
          promo_percent: null,
          limit_qty: null,
          online_coupon: 'Voucher Đổi điểm (1Tr - 5Tr)',
          no_gift_price: null,
          gift_sku: null,
          gift_name: null,
          kfi_value: null,
        });
      });

      // Thêm MacBook cho Đổi điểm thi
      allRecords.push({
        sheet_name: title,
        program_name: 'Đổi điểm thi THPT 2026 - Tặng AirPods 4 hoặc Giảm tiền cho MacBook',
        time_range: 'Thời gian: 01/07/2026 - 31/10/2026',
        start_date: '2026-07-01',
        end_date: '2026-10-31',
        apply_channels: 'All channels (Showroom & Online)',
        conditions: examConditions,
        detail_link: defaultLink,
        sku: 'NH05',
        category: 'Apple Laptop / MacBook',
        brand: 'Apple',
        product_name: 'MacBook | Ưu đãi Đổi điểm thi THPT 2026',
        list_price: null,
        promo_price: null,
        promo_percent: null,
        limit_qty: null,
        online_coupon: 'Tặng AirPods 4 hoặc Voucher 3Tr-5Tr',
        no_gift_price: null,
        gift_sku: null,
        gift_name: null,
        kfi_value: null,
      });

      continue;
    }

    // =========================================================================
    // XỬ LÝ ĐẶC THÙ 3: COMBO THẺ NHỚ / USB
    // =========================================================================
    if (upperTitle.includes('THẺ NHỚ') || upperTitle.includes('USB')) {
      console.log(`[Sync CTKM] Xử lý sheet đặc thù Thẻ nhớ/USB: "${title}"...`);
      const usbCats = ['NH11-01-01-01', 'NH11-01-01-02'];
      usbCats.forEach(c => {
        allRecords.push({
          sheet_name: title,
          program_name: 'Combo Thẻ nhớ & USB - Mua càng nhiều, Giảm càng sâu',
          time_range: 'Thời gian: 01/07/2026 - 30/09/2026',
          start_date: '2026-07-01',
          end_date: '2026-09-30',
          apply_channels: 'All channels',
          conditions: 'Ưu đãi giảm giá khi mua combo từ 2 sản phẩm USB/Thẻ nhớ bất kỳ:\n- Mua 2 món: Giảm 10.000đ\n- Mua 3 món: Giảm 20.000đ\n- Mua 4 món: Giảm 30.000đ\n- Mua 5 món trở lên: Giảm 40.000đ\nÁp dụng đồng thời cùng VNPAY, ShopeePay.',
          detail_link: defaultLink,
          sku: c,
          category: 'Thiết bị lưu trữ / USB & Thẻ nhớ',
          product_name: 'USB & Thẻ nhớ theo danh mục',
          brand: 'All',
          list_price: null,
          promo_price: null,
          promo_percent: null,
          limit_qty: null,
          online_coupon: 'Giảm 10K - 40K khi mua combo',
          no_gift_price: null,
          gift_sku: null,
          gift_name: null,
          kfi_value: null,
        });
      });
      continue;
    }

    // =========================================================================
    // Step A: Tìm các dòng Header SKU trong sheet thông thường
    // =========================================================================
    const headerPositions = [];
    for (let i = 0; i < rows.length; i++) {
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
      if (hasCatName) {
        const nonValCount = row.filter(Boolean).length;
        if (nonValCount >= 2) {
          headerPositions.push({ idx: i, type: 'cat' });
        }
      }
    }

    // =========================================================================
    // NẾU KHÔNG CÓ HEADER SKU: KIỂM TRA XEM CÓ PHẢI ƯU ĐÃI TOÀN SÀN THỰC SỰ KHÔNG
    // =========================================================================
    if (headerPositions.length === 0) {
      // CHỈ CHO PHÉP CÁC CHƯƠNG TRÌNH THANH TOÁN / NGÂN HÀNG / APP / VỆ SINH ĐƯỢC GÁN SKU=ALL
      const isUniversalSheet = /shopeepay|vnpay|tpbank|vib|payoo|homecredit|shinhan|mở thẻ|loyalty|app quý|vệ sinh miễn phí/i.test(title);
      
      if (isUniversalSheet) {
        console.log(`[Sync CTKM] Phát hiện sheet ưu đãi TOÀN SÀN / THANH TOÁN: "${title}". Tiến hành bóc tách toàn sàn (SKU=ALL)...`);
        
        let startDate = null;
        let endDate = null;
        let timeRangeText = '';
        for (let i = 0; i < Math.min(rows.length, 12); i++) {
          const rowText = (rows[i] || []).join(' ');
          if (/thời gian|hiệu lực|áp dụng/i.test(rowText)) {
            const cellWithDate = rows[i].find(c => /thời gian|hiệu lực|áp dụng/i.test(String(c)));
            if (cellWithDate) {
              timeRangeText = String(cellWithDate).trim();
              const parsed = parseDateRange(timeRangeText);
              startDate = parsed.startDate;
              endDate = parsed.endDate;
              if (startDate && endDate) break;
            }
          }
        }
        if (!startDate || !endDate) {
          startDate = '2026-01-01';
          endDate = '2026-12-31';
        }

        let programName = title;
        if (rows[1] && rows[1].filter(Boolean).length > 0) {
          const nameCell = rows[1].find(c => String(c || '').trim().length > 3);
          if (nameCell) programName = String(nameCell).trim();
        }

        let conditions = [];
        let couponInfo = '';
        let percentVal = null;

        rows.slice(0, 25).forEach(r => {
          const rowStr = (r || []).filter(Boolean).join(' | ');
          if (/điều kiện|lưu ý|hình thức|nội dung|áp dụng|scheme/i.test(rowStr)) {
            conditions.push(rowStr);
          }
          if (/giảm\s*(\d+)%/i.test(rowStr)) {
            const m = rowStr.match(/giảm\s*(\d+)%/i);
            if (m && !percentVal) percentVal = parseInt(m[1], 10);
          }
        });

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

        const fullConditions = conditions.join('\n\n') || 'Áp dụng cho toàn bộ sản phẩm kinh doanh tại Phong Vũ theo thể lệ chương trình.';

        allRecords.push({
          sheet_name: title,
          program_name: programName,
          time_range: timeRangeText || `Hiệu lực: ${startDate} - ${endDate}`,
          start_date: startDate,
          end_date: endDate,
          apply_channels: 'All channels',
          conditions: fullConditions,
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

        console.log(`[Sync CTKM] Đã tạo record toàn sàn (SKU=ALL) cho sheet "${title}".`);
        continue;
      }

      console.log(`[Sync CTKM] Bỏ qua sheet không có SKU và không phải toàn sàn: "${title}".`);
      continue;
    }

    // =========================================================================
    // BÓC TÁCH SHEET CÓ DỮ LIỆU SKU THEO TỪNG KHỐI HEADER
    // =========================================================================
    let countRows = 0;
    for (let hIdx = 0; hIdx < headerPositions.length; hIdx++) {
      const headerPos = headerPositions[hIdx];
      const headerIdx = headerPos.idx;
      const nextHeaderIdx = headerPositions[hIdx + 1] ? headerPositions[hIdx + 1].idx : rows.length;
      const headerRow = rows[headerIdx];

      // Tìm ngày bắt đầu và kết thúc từ các dòng phía trên header
      let startDate = null;
      let endDate = null;
      let timeRangeText = '';
      for (let i = 0; i < headerIdx; i++) {
        const rowText = (rows[i] || []).join(' ');
        if (/thời gian|hiệu lực|áp dụng/i.test(rowText)) {
          const cellWithDate = rows[i].find(c => /thời gian|hiệu lực|áp dụng/i.test(String(c)));
          if (cellWithDate) {
            timeRangeText = String(cellWithDate).trim();
            const parsed = parseDateRange(timeRangeText);
            startDate = parsed.startDate;
            endDate = parsed.endDate;
            break;
          }
        }
      }
      if (!startDate || !endDate) {
        startDate = '2026-01-01';
        endDate = '2026-12-31';
      }

      let programName = title;
      if (rows[1]) {
        const row2Cells = rows[1].filter(Boolean);
        if (row2Cells.length > 0 && !row2Cells[0].includes('Thời gian') && !row2Cells[0].includes('Kênh')) {
          programName = String(row2Cells[0]).trim();
        }
      }

      let conditions = '';
      for (let i = 0; i < headerIdx; i++) {
        const rowText = (rows[i] || []).join(' ');
        if (rowText.includes('Điều kiện') || rowText.includes('Nội dung')) {
          conditions = rows[i].filter(Boolean).join('\n');
          break;
        }
      }

      // Tìm tất cả các cột SKU trong headerRow
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

      // Xây dựng column map cho từng cột SKU
      const colMaps = [];
      skuIndexes.forEach((skuColIdx, sIdx) => {
        const nextSkuColIdx = skuIndexes[sIdx + 1];
        const colMap = { sku: skuColIdx };
        const endIdx = nextSkuColIdx || headerRow.length;

        // Xác định tên chương trình cho cột này nếu có
        let colProgramName = programName;
        for (let col = skuColIdx; col >= 0; col--) {
          const valRow2 = rows[1] ? String(rows[1][col] || '').trim() : '';
          const valRow3 = rows[2] ? String(rows[2][col] || '').trim() : '';
          const checkVal = (v) => {
            if (!v) return null;
            if (v.includes('Thời gian') || v.includes('Kênh') || v.includes('Lưu ý') || v.includes('Điều kiện')) return null;
            return v;
          };
          const t3 = checkVal(valRow3);
          const t2 = checkVal(valRow2);
          if (t3) { colProgramName = t3; break; }
          if (t2) { colProgramName = t2; break; }
        }
        colMap.programName = colProgramName;

        for (let c = skuColIdx + 1; c < endIdx; c++) {
          const cell = headerRow[c];
          const val = String(cell || '').trim().toLowerCase();
          if (!val) continue;

          if (val.includes('category') || val.includes('ngành hàng') || val.includes('nhóm hàng') || val === 'cat' || val === 'ngành') {
            colMap.category = c;
          } else if (val.includes('name') || val === 'tên' || val === 'sản phẩm' || val.includes('tên sản phẩm')) {
            colMap.name = c;
          } else if (val.includes('brand') || val.includes('hãng') || val.includes('thương hiệu')) {
            colMap.brand = c;
          } else if (val.includes('ny') || val.includes('niêm yết') || val.includes('bán lẻ') || val === 'list price') {
            colMap.list_price = c;
          } else if (val.includes('giá km') || val.includes('khuyến mãi') || val === 'km' || val === 'giá') {
            colMap.promo_price = c;
          } else if (val.includes('%') || val.includes('%km')) {
            colMap.promo_percent = c;
          } else if (val.includes('giới hạn') || val.includes('số lượng') || val.includes('limit') || val.includes('qty')) {
            colMap.limit_qty = c;
          } else if (val.includes('online') || val.includes('coupon') || val.includes('mã') || val.includes('giảm thêm')) {
            colMap.online_coupon = c;
          } else if (val.includes('không lấy quà') || val.includes('no gift') || val.includes('promotion price')) {
            colMap.no_gift_price = c;
          } else if (val.includes('sku quà') || val.includes('mã quà') || val.includes('sku tặng')) {
            colMap.gift_sku = c;
          } else if ((val.includes('quà') || val.includes('tặng')) && !val.includes('sku')) {
            colMap.gift_name = c;
          } else if (val.startsWith('kfi')) {
            colMap.kfi_value = c;
          }
        }
        colMaps.push(colMap);
      });

      // Duyệt qua các dòng dữ liệu bên dưới header
      for (let j = headerIdx + 1; j < nextHeaderIdx; j++) {
        const r = rows[j];
        if (!r || r.length === 0) continue;
        if (r.filter(Boolean).length === 0) continue;

        for (const colMap of colMaps) {
          let skuRaw = String(r[colMap.sku] || '').trim();
          if (!skuRaw || skuRaw === '' || skuRaw === '-' || skuRaw.toLowerCase() === 'sku' || skuRaw.toLowerCase() === 'tên') continue;

          // Xử lý nếu SKU là số chứa dấu phẩy
          let sku = skuRaw.replace(/[,.\s]/g, '');
          if (!/^\d+$/.test(sku) && !/^NH\d+/i.test(skuRaw)) {
            // Không phải SKU chuẩn dạng số hoặc mã ngành
            // Nếu là mã ngành NH...
            const matchSubcat = skuRaw.match(/^(NH\d+-\d+(?:-\d+)?)/i);
            if (matchSubcat) {
              sku = matchSubcat[1].toUpperCase();
            } else {
              continue;
            }
          }

          const parseMoney = (val) => {
            if (!val) return null;
            const numStr = String(val).replace(/[^0-9.-]/g, '');
            const num = parseFloat(numStr);
            return isNaN(num) ? null : num;
          };

          const parsePercent = (val) => {
            if (!val) return null;
            const numStr = String(val).replace(/[^0-9.-]/g, '');
            const num = parseFloat(numStr);
            return isNaN(num) ? null : num;
          };

          allRecords.push({
            sheet_name: title,
            program_name: colMap.programName || programName,
            time_range: timeRangeText || `Hiệu lực: ${startDate} - ${endDate}`,
            start_date: startDate,
            end_date: endDate,
            apply_channels: 'All channels',
            conditions: conditions || 'Áp dụng theo danh sách sản phẩm chỉ định.',
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

          countRows++;
        }
      }
    }

    console.log(`[Sync CTKM] Đã bóc tách được ${countRows} sản phẩm từ sheet "${title}".`);
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

module.exports = { syncPromotions };
