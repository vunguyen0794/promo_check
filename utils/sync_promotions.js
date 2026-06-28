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
  const clean = text.replace(/\s+/g, ' ').replace(/\./g, '/').trim();
  const dateRegex = /(\d{1,2})\/(\d{1,2})(?:\/(\d{4}))?/g;
  const matches = [];
  let match;
  while ((match = dateRegex.exec(clean)) !== null) {
    matches.push({
      day: parseInt(match[1], 10),
      month: parseInt(match[2], 10),
      year: match[3] ? parseInt(match[3], 10) : 2026
    });
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
 * Maps sheet headers to indexes
 */
function mapHeaders(headerRow) {
  const map = {};
  headerRow.forEach((cell, idx) => {
    const val = String(cell || '').trim().toLowerCase();
    if (val === 'sku') map.sku = idx;
    else if (val.includes('category') || val.includes('ngành hàng') || val.includes('nhóm hàng') || val === 'cat' || val === 'ngành') map.category = idx;
    else if (val.includes('name') || val === 'tên' || val === 'sản phẩm' || val.includes('tên sản phẩm')) map.name = idx;
    else if (val.includes('brand') || val.includes('hãng') || val.includes('thương hiệu')) map.brand = idx;
    else if (val.includes('ny') || val.includes('niêm yết') || val.includes('bán lẻ')) map.list_price = idx;
    else if (val.includes('giá km') || val.includes('khuyến mãi') || val === 'km') map.promo_price = idx;
    else if (val.includes('%') || val.includes('%km')) map.promo_percent = idx;
    else if (val.includes('giới hạn') || val.includes('số lượng')) map.limit_qty = idx;
    else if (val.includes('online') || val.includes('coupon') || val.includes('giảm thêm')) map.online_coupon = idx;
    else if (val.includes('không lấy quà') || val.includes('no gift') || val.includes('promotion price')) map.no_gift_price = idx;
    else if (val.includes('sku quà') || val.includes('mã quà')) map.gift_sku = idx;
    else if (val.includes('quà') && !val.includes('sku quà') && !val.includes('mã quà')) map.gift_name = idx;
    else if (val.startsWith('kfi')) map.kfi_value = idx;
  });
  return map;
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

    // Step A: Find all header rows in the sheet
    const headerPositions = [];
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i] || [];
      const hasSku = row.some(cell => String(cell || '').trim().toLowerCase() === 'sku');
      if (hasSku) {
        headerPositions.push({ idx: i, type: 'sku' });
        continue;
      }
      const hasName = row.some(cell => {
        const val = String(cell || '').trim().toLowerCase();
        return val === 'product name' || val === 'category' || val === 'ngành hàng' || val === 'cat' || val === 'ngành';
      });
      if (hasName) {
        const nonValCount = row.filter(Boolean).length;
        if (nonValCount >= 2) {
          headerPositions.push({ idx: i, type: 'cat' });
        }
      }
    }

    if (headerPositions.length === 0) {
      console.log(`[Sync CTKM] Không tìm thấy bất kỳ dòng header SKU hoặc Product Name hoặc Cat ở sheet: "${title}". Bỏ qua.`);
      continue;
    }

    // Get detail link mapping from GID
    let detailLink = gidLinkMap.get(sheetId) || `https://docs.google.com/spreadsheets/d/${PROMO_SPREADSHEET_ID}/edit#gid=${sheetId}`;

    // Loop through each header block
    let countRows = 0;
    for (let hIdx = 0; hIdx < headerPositions.length; hIdx++) {
      const headerPos = headerPositions[hIdx];
      const headerIdx = headerPos.idx;
      const nextHeaderIdx = headerPositions[hIdx + 1] ? headerPositions[hIdx + 1].idx : rows.length;

      const headerRow = rows[headerIdx];

      // Get dates and conditions corresponding to the first header, or general
      let startDate = null;
      let endDate = null;
      let timeRangeText = '';
      for (let i = 0; i < headerIdx; i++) {
        const rowText = rows[i].join(' ');
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
        const rowText = rows[i].join(' ');
        if (rowText.includes('Điều kiện')) {
          conditions = rows[i].filter(Boolean).join('\n');
          break;
        }
      }

      // Find all target columns in this header row
      const skuIndexes = [];
      headerRow.forEach((cell, idx) => {
        const val = String(cell || '').trim().toLowerCase();
        if (headerPos.type === 'sku') {
          if (val === 'sku') skuIndexes.push(idx);
        } else {
          if (val === 'product name' || val === 'category' || val === 'ngành hàng' || val === 'cat' || val === 'ngành') {
            skuIndexes.push(idx);
          }
        }
      });

      // Build colMaps for this header
      const colMaps = [];
      skuIndexes.forEach((skuColIdx, sIdx) => {
        const nextSkuColIdx = skuIndexes[sIdx + 1];
        
        // Build map
        const colMap = { sku: skuColIdx };
        const endIdx = nextSkuColIdx || headerRow.length;

        // Compute column-specific program name (searching left from skuColIdx in Row 2 and Row 3)
        let colProgramName = programName;
        for (let col = skuColIdx; col >= 0; col--) {
          const valRow2 = rows[1] ? String(rows[1][col] || '').trim() : '';
          const valRow3 = rows[2] ? String(rows[2][col] || '').trim() : '';
          
          const checkVal = (val) => {
            if (!val) return null;
            if (val.includes('Thời gian') || val.includes('Kênh') || val.includes('Lưu ý') || val.includes('Điều kiện')) return null;
            return val;
          };

          const title2 = checkVal(valRow2);
          const title3 = checkVal(valRow3);

          if (title3) {
            colProgramName = title3;
            break;
          }
          if (title2) {
            colProgramName = title2;
            break;
          }
        }
        colMap.programName = colProgramName;
        
        for (let idx = skuColIdx + 1; idx < endIdx; idx++) {
          const cell = headerRow[idx];
          const val = String(cell || '').trim().toLowerCase();
          if (!val) continue;

          if (val.includes('category') || val.includes('ngành hàng') || val.includes('nhóm hàng') || val === 'cat' || val === 'ngành') {
            colMap.category = idx;
          } else if (val.includes('name') || val === 'tên' || val === 'sản phẩm' || val.includes('tên sản phẩm')) {
            colMap.name = idx;
          } else if (val.includes('brand') || val.includes('hãng') || val.includes('thương hiệu')) {
            colMap.brand = idx;
          } else if (val.includes('ny') || val.includes('niêm yết') || val.includes('bán lẻ') || val === 'list price') {
            colMap.list_price = idx;
          } else if (val.includes('giá km') || val.includes('khuyến mãi') || val === 'km' || val === 'giá') {
            colMap.promo_price = idx;
          } else if (val.includes('%') || val.includes('%km')) {
            colMap.promo_percent = idx;
          } else if (val.includes('giới hạn') || val.includes('số lượng') || val.includes('limit') || val.includes('qty')) {
            colMap.limit_qty = idx;
          } else if (val.includes('online') || val.includes('coupon') || val.includes('mã') || val.includes('giảm thêm')) {
            colMap.online_coupon = idx;
          } else if (val.includes('không lấy quà') || val.includes('no gift') || val.includes('promotion price')) {
            colMap.no_gift_price = idx;
          } else if (val.includes('sku quà') || val.includes('mã quà')) {
            colMap.gift_sku = idx;
          } else if (val.includes('quà') && !val.includes('sku quà') && !val.includes('mã quà')) {
            colMap.gift_name = idx;
          } else if (val.startsWith('kfi')) {
            colMap.kfi_value = idx;
          }
        }
        colMaps.push(colMap);
      });

      // Parse rows from headerIdx + 1 to nextHeaderIdx - 1
      for (let j = headerIdx + 1; j < nextHeaderIdx; j++) {
        const r = rows[j];
        if (!r || r.length === 0) continue;

        const nonBlank = r.filter(Boolean).length;
        if (nonBlank === 0) continue;

        for (const colMap of colMaps) {
          let sku = String(r[colMap.sku] || '').trim();
          if (!sku || sku === '' || sku === '-' || sku === 'SKU' || sku === 'Tên') continue;

          // If SKU represents a category/subcat code
          const matchSubcat = sku.match(/^(NH\d+-\d+(?:-\d+)?)/i);
          if (matchSubcat) {
            sku = matchSubcat[1].toUpperCase();
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

          const record = {
            sheet_name: title,
            program_name: colMap.programName || programName,
            time_range: timeRangeText || `Hiệu lực: ${startDate} - ${endDate}`,
            start_date: startDate,
            end_date: endDate,
            apply_channels: 'All channels',
            conditions: conditions || 'Áp dụng theo danh sách sản phẩm chỉ định.',
            detail_link: detailLink,
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
          };

          allRecords.push(record);
          countRows++;
        }
      }
    }
    console.log(`[Sync CTKM] Đã bóc tách được ${countRows} sản phẩm từ sheet "${title}".`);
  }

  // 4. Update Database
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
