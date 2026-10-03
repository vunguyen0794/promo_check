/**
 * utils/teko_product_service.js
 * Dịch vụ đồng bộ thông tin sản phẩm, thông số kỹ thuật, bảo hành, VAT và giá vào Supabase
 * Đảm bảo 0% spam tới Teko: Ưu tiên đọc 100% từ Supabase, chỉ gọi 1 lần khi thiếu dữ liệu hoặc khi bấm 'Làm mới'.
 */

const TEKO_DISCOVERY_URL = 'https://discovery.tekoapis.com/api/v1/product';

/**
 * Lấy token Teko toàn cục từ Supabase site_settings
 */
async function getGlobalTekoToken(supabaseClient) {
  try {
    const { data, error } = await supabaseClient
      .from('site_settings')
      .select('value')
      .eq('id', 'quick_export_global_token')
      .single();

    if (error || !data?.value) return null;

    let parsed = data.value;
    if (typeof parsed === 'string') {
      try { parsed = JSON.parse(parsed); } catch (e) { /* silent */ }
    }
    return parsed?.tekoToken || (typeof parsed === 'string' ? parsed : null);
  } catch (err) {
    console.error('[TEKO_PRODUCT_SERVICE] Lỗi đọc global token:', err.message);
    return null;
  }
}

/**
 * Gọi Discovery API của Teko để lấy thông tin chi tiết sản phẩm
 * Có timeout 4000ms an toàn để không bao giờ làm treo hệ thống
 */
async function fetchTekoProductDetails(sku, terminalCode = 'phongvu', supabaseClient) {
  const token = await getGlobalTekoToken(supabaseClient);
  if (!token) {
    throw new Error('Chưa có token Teko khả dụng trong hệ thống.');
  }

  const cleanToken = token.trim().toLowerCase().startsWith('bearer ') ? token.trim() : `Bearer ${token.trim()}`;
  
  // Xác định mã terminal hợp lệ của hệ thống Phong Vũ (CPxx hoặc phongvu)
  const isCpCode = /^CP\d+$/i.test(String(terminalCode || '').trim());
  const initialTerminal = isCpCode ? String(terminalCode).trim() : 'phongvu';

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4000);

  try {
    const stealthHeaders = {
      'Authorization': cleanToken,
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'vi,en-US;q=0.9,en;q=0.8',
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Origin': 'https://erp.phongvu.vn',
      'Referer': 'https://erp.phongvu.vn/',
      'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
      'Sec-Ch-Ua-Mobile': '?0',
      'Sec-Ch-Ua-Platform': '"macOS"',
      'Sec-Fetch-Dest': 'empty',
      'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Site': 'cross-site',
    };

    let res = await fetch(`${TEKO_DISCOVERY_URL}?sku=${encodeURIComponent(sku)}&terminalCode=${encodeURIComponent(initialTerminal)}`, {
      method: 'GET',
      headers: stealthHeaders,
      signal: controller.signal
    });

    // Nếu mã chi nhánh hiện tại trả về 404 (ví dụ chi nhánh chưa đăng ký trên Teko Discovery), tự động fallback về 'phongvu'
    if (!res.ok && initialTerminal !== 'phongvu') {
      res = await fetch(`${TEKO_DISCOVERY_URL}?sku=${encodeURIComponent(sku)}&terminalCode=phongvu`, {
        method: 'GET',
        headers: stealthHeaders,
        signal: controller.signal
      });
    }

    clearTimeout(timeoutId);

    if (!res.ok) {
      throw new Error(`Teko Discovery API trả về mã lỗi ${res.status}: ${res.statusText}`);
    }

    const json = await res.json();
    const p = json.result?.product;
    if (!p) {
      throw new Error('Không tìm thấy dữ liệu sản phẩm trong phản hồi của Teko.');
    }

    const pInfo = p.productInfo || {};
    const pDetail = p.productDetail || {};
    const prices = p.prices?.[0] || {};

    // 1. Phân loại 3 mức giá duy nhất
    const terminalPrice = Number(prices.terminalPrice || 0);
    const supplierPrice = Number(prices.supplierRetailPrice || 0);
    const latestPrice = Number(prices.latestPrice || 0);
    const sellPrice = Number(prices.sellPrice || 0);

    const listPrice = terminalPrice > 0 ? terminalPrice : (supplierPrice > 0 ? supplierPrice : (latestPrice > 0 ? latestPrice : 0));
    const promoPrice = latestPrice > 0 ? latestPrice : (sellPrice > 0 ? sellPrice : listPrice);
    const discountAmount = Math.max(0, listPrice - promoPrice);

    // 2. Thuế suất VAT
    const vatRate = pInfo.tax?.taxOut !== undefined && pInfo.tax?.taxOut !== null ? Number(pInfo.tax.taxOut) : null;

    // 3. Thời gian bảo hành
    let warranty = null;
    if (pInfo.warranty?.months) {
      warranty = `${pInfo.warranty.months} tháng chính hãng`;
      if (pInfo.warranty.description && pInfo.warranty.description.trim()) {
        warranty += ` (${pInfo.warranty.description.trim()})`;
      }
    } else {
      // Tìm trong attributeGroups nếu có
      const wGroup = (pDetail.attributeGroups || []).find(g => (g.name || '').toLowerCase().includes('bảo hành'));
      if (wGroup && wGroup.value) {
        warranty = wGroup.value.trim();
      }
    }

    // 4. Thông số kỹ thuật (Danh sách chi tiết & Tóm tắt nhanh)
    const attributes = (pDetail.attributeGroups || [])
      .filter(g => g.name && g.value && g.value.trim() !== '')
      .map(g => ({
        name: g.name.trim(),
        value: g.value.trim().replace(/<br\s*\/?>/gi, ', ')
      }));

    const images = (pDetail.images || []).map(img => img.url).filter(Boolean);

    const specifications = {
      attributes,
      images: images.slice(0, 8),
      summary: {
        cpu: attributes.find(a => a.name.toLowerCase() === 'cpu')?.value || '',
        ram: attributes.find(a => a.name.toLowerCase() === 'ram')?.value || '',
        storage: attributes.find(a => a.name.toLowerCase() === 'lưu trữ' || a.name.toLowerCase().includes('ổ cứng'))?.value || '',
        vga: attributes.find(a => a.name.toLowerCase().includes('đồ họa') || a.name.toLowerCase().includes('vga'))?.value || '',
        screen: attributes.find(a => a.name.toLowerCase() === 'màn hình')?.value || '',
        os: attributes.find(a => a.name.toLowerCase().includes('hệ điều hành'))?.value || '',
        weight: attributes.find(a => a.name.toLowerCase().includes('khối lượng') || a.name.toLowerCase().includes('trọng lượng'))?.value || '',
        color: attributes.find(a => a.name.toLowerCase().includes('màu sắc'))?.value || ''
      }
    };

    return {
      sku: pInfo.sku || sku,
      product_name: pInfo.name || pDetail.name || '',
      brand: pInfo.brand?.name || '',
      list_price: listPrice,
      promo_price: promoPrice,
      discount_amount: discountAmount,
      vat_rate: vatRate,
      warranty: warranty,
      specifications: specifications,
      images: images
    };

  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      throw new Error('Kết nối tới Teko Discovery bị quá thời gian (timeout 4s).');
    }
    throw err;
  }
}

/**
 * Lấy thông tin sản phẩm:
 * - Bước 1: Ưu tiên trả về 100% từ Supabase nếu đã có dữ liệu.
 * - Bước 2: Chỉ gọi Teko khi chưa có thông số hoặc khi forceRefresh = true, sau đó LƯU NGAY VÀO SUPABASE.
 */
async function getOrSyncProductData(sku, terminalCode, supabaseClient, forceRefresh = false) {
  if (!sku) return null;
  const cleanSku = String(sku).trim();

  // 1. Đọc từ Supabase trước
  const { data: currentProduct, error: readError } = await supabaseClient
    .from('skus')
    .select('*')
    .eq('sku', cleanSku)
    .single();

  if (readError && readError.code !== 'PGRST116') {
    console.error(`[TEKO_PRODUCT_SERVICE] Lỗi đọc Supabase SKU ${cleanSku}:`, readError.message);
  }

  // Nếu đã có đầy đủ thông số kỹ thuật, bảo hành, vat và không phải force refresh -> Trả về luôn từ Supabase (0 request Teko)
  const isComplete = currentProduct &&
    currentProduct.specifications &&
    currentProduct.vat_rate !== null &&
    currentProduct.warranty;

  if (isComplete && !forceRefresh) {
    return currentProduct;
  }

  // 2. Cần đồng bộ (Lần đầu tiên hoặc nhân viên bấm làm mới)
  try {
    console.log(`[TEKO_PRODUCT_SERVICE] Đang đồng bộ thông số cho SKU ${cleanSku} từ Teko...`);
    const details = await fetchTekoProductDetails(cleanSku, terminalCode || 'CP01', supabaseClient);

    const updatePayload = {
      spec_updated_at: new Date().toISOString()
    };

    // Xác định chuẩn 3 mức giá duy nhất: Giá gốc, Giá khuyến mãi, Số tiền ưu đãi
    const finalListPrice = details.list_price > 0 ? details.list_price : (Number(currentProduct?.list_price) || 0);
    const finalPromoPrice = details.promo_price > 0 ? details.promo_price : (Number(currentProduct?.promo_price) || finalListPrice);
    const finalDiscountAmt = Math.max(0, finalListPrice - finalPromoPrice);

    if (finalListPrice > 0) updatePayload.list_price = finalListPrice;
    if (finalPromoPrice > 0) updatePayload.promo_price = finalPromoPrice;
    updatePayload.discount_amount = finalDiscountAmt;
    if (details.vat_rate !== null) updatePayload.vat_rate = details.vat_rate;
    if (details.warranty) updatePayload.warranty = details.warranty;
    if (details.specifications) updatePayload.specifications = details.specifications;

    // Lưu vào Supabase
    if (currentProduct) {
      await supabaseClient
        .from('skus')
        .update(updatePayload)
        .eq('sku', cleanSku);
    } else {
      // Trường hợp SKU chưa có trong bảng skus
      await supabaseClient
        .from('skus')
        .insert({
          sku: cleanSku,
          product_name: details.product_name,
          brand: details.brand,
          ...updatePayload
        });
    }

    // Kết hợp dữ liệu và trả về chuẩn xác
    return {
      ...(currentProduct || {}),
      ...details,
      ...updatePayload,
      list_price: finalListPrice,
      promo_price: finalPromoPrice,
      discount_amount: finalDiscountAmt
    };

  } catch (syncErr) {
    console.warn(`[TEKO_PRODUCT_SERVICE] Không thể đồng bộ SKU ${cleanSku} từ Teko:`, syncErr.message);
    if (forceRefresh) {
      throw syncErr;
    }
    // Fallback êm dịu khi lazy sync: Vẫn trả về dữ liệu Supabase hiện tại để không làm đơ trang
    return currentProduct;
  }
}

module.exports = {
  getGlobalTekoToken,
  fetchTekoProductDetails,
  getOrSyncProductData
};
