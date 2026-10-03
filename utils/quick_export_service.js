/**
 * utils/quick_export_service.js
 * Dịch vụ tích hợp API WMS Phong Vũ / Teko cho tính năng "Xuất kho nhanh"
 * Sử dụng native fetch (Zero-dependency, tốc độ cao)
 */

const TEKO_STAFF_BFF_URL = 'https://staff-bff.tekoapis.com';

/**
 * Chuẩn hoá token (tự động thêm 'Bearer ' nếu thiếu)
 */
function normalizeToken(token) {
  if (!token) return '';
  const clean = token.trim();
  return clean.toLowerCase().startsWith('bearer ') ? clean : `Bearer ${clean}`;
}

/**
 * Helper gửi HTTP request tới Teko Staff BFF bằng native fetch
 */
async function callTekoBff(endpoint, options = {}) {
  const {
    method = 'GET',
    params = {},
    data = null,
    token = '',
    siteId = null,
  } = options;

  const authHeader = normalizeToken(token);
  if (!authHeader) {
    throw new Error('Chưa cấu hình hoặc thiếu Token ERP (Teko Staff Token). Vui lòng cập nhật cài đặt.');
  }

  const headers = {
    'Authorization': authHeader,
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'vi,en-US;q=0.9,en;q=0.8',
    'Content-Type': 'application/json',
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

  if (siteId) {
    headers['x-site-id'] = String(siteId);
  }

  let url = `${TEKO_STAFF_BFF_URL}${endpoint.startsWith('/') ? endpoint : '/' + endpoint}`;
  if (params && Object.keys(params).length > 0) {
    const urlObj = new URL(url);
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) {
        urlObj.searchParams.append(k, String(v));
      }
    }
    url = urlObj.toString();
  }

  const fetchOpts = {
    method,
    headers,
  };

  if (data && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
    fetchOpts.body = JSON.stringify(data);
  }

  try {
    const response = await fetch(url, fetchOpts);
    const contentType = response.headers.get('content-type') || '';
    let resData;
    if (contentType.includes('application/json')) {
      resData = await response.json();
    } else {
      resData = await response.text();
    }

    if (!response.ok) {
      let errMsg = `HTTP ${response.status}`;
      if (resData && typeof resData === 'object') {
        const candidate = resData.message || resData.msg || resData.error;
        if (typeof candidate === 'string') {
          errMsg = candidate;
        } else if (candidate && typeof candidate === 'object') {
          errMsg = candidate.message || candidate.msg || candidate.error || JSON.stringify(candidate);
        } else {
          errMsg = JSON.stringify(resData);
        }
      } else if (typeof resData === 'string' && resData.length < 300) {
        errMsg = resData;
      }
      const customErr = new Error(`Lỗi Teko WMS (${response.status}): ${errMsg}`);
      customErr.status = response.status;
      customErr.responseData = resData;
      throw customErr;
    }

    // Unwrap { code, data, message } nếu Teko trả dạng wrapper chuẩn
    if (resData && typeof resData === 'object' && 'data' in resData) {
      const c = resData.code;
      if (c === 'SUCCESS' || c === 'OK' || c === 200 || c === 0 || c === '0' || !c) {
        return resData.data !== undefined ? resData.data : resData;
      }
    }
    return resData;
  } catch (error) {
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      throw new Error(`Không thể kết nối tới Teko WMS API: ${error.message}`);
    }
    throw error;
  }
}

/**
 * 0. Lấy danh sách kho / sites của user
 * GET /api/v1/sites/user
 */
async function getUserSites(token) {
  try {
    const res = await callTekoBff('/api/v1/sites/user', {
      method: 'GET',
      token,
    });
    const list = res?.sites || (Array.isArray(res) ? res : []);
    return list.map(s => ({
      id: Number(s.id),
      name: s.name || `Kho ${s.id}`,
    }));
  } catch (err) {
    return [];
  }
}

/**
 * 1. Tra cứu thông tin BIN theo tên
 * GET /api/v1/bin-by-code?binName={binName}&siteId={siteId}
 */
async function getBinByBinName(binName, token, siteId) {
  if (!binName || !binName.trim()) {
    throw new Error('Tên BIN không được để trống.');
  }
  const cleanName = binName.trim();
  let resolvedSiteId = siteId;

  // Nếu siteId chưa phải là số (e.g. chuỗi 'CP62', 'HCM.BD' hoặc undefined), tự resolve từ user sites
  if (!resolvedSiteId || isNaN(Number(resolvedSiteId))) {
    const sites = await getUserSites(token);
    if (sites.length > 0) {
      if (siteId && typeof siteId === 'string') {
        const code = siteId.toUpperCase().trim();
        const matched = sites.find(s => s.name.toUpperCase().includes(code));
        if (matched) resolvedSiteId = matched.id;
      }
      if (!resolvedSiteId) {
        // Thử tìm xem BIN có ở site nào trong danh sách
        for (const s of sites) {
          try {
            const testData = await callTekoBff('/api/v1/bin-by-code', {
              method: 'GET',
              params: { binName: cleanName, siteId: s.id },
              token,
              siteId: s.id,
            });
            if (testData && (testData.binId || testData.id)) {
              return {
                binId: testData.binId || testData.id,
                binName: testData.binName || cleanName,
                isActive: testData.isActive !== false,
                siteId: s.id,
                siteName: s.name,
              };
            }
          } catch (e) {
            // thử site tiếp theo
          }
        }
        // Fallback site đầu tiên
        resolvedSiteId = sites[0].id;
      }
    }
  }

  const params = { binName: cleanName };
  if (resolvedSiteId) {
    params.siteId = Number(resolvedSiteId);
  }

  const raw = await callTekoBff('/api/v1/bin-by-code', {
    method: 'GET',
    params,
    token,
    siteId: resolvedSiteId,
  });

  const data = (raw && typeof raw === 'object' && raw.data) ? raw.data : raw;

  if (!data || (!data.binId && !data.id)) {
    throw new Error(`Không tìm thấy BIN "${cleanName}" trên hệ thống ERP.`);
  }

  return {
    binId: data.binId || data.id,
    binName: data.binName || cleanName,
    isActive: data.isActive !== false,
    siteId: data.siteId || resolvedSiteId,
  };
}

/**
 * 2b. Lấy chi tiết phiếu xuất kho đã hoàn tất (bao gồm danh sách serial đã xuất thực tế)
 * GET /api/v1/warehouse-export/{documentId}
 */
async function getExportRequestDetail(documentId, token, siteId) {
  if (!documentId) return null;
  const cleanDoc = String(documentId).trim();
  const candidates = [cleanDoc];
  if (!cleanDoc.startsWith('FFR-')) {
    candidates.push(`FFR-${cleanDoc}`);
  }
  for (const c of candidates) {
    try {
      const data = await callTekoBff(`/api/v1/warehouse-export/${c}`, {
        method: 'GET',
        token,
        siteId,
      });
      if (data && (data.requestId || data.items)) return data;
    } catch (err) {}
  }
  return null;
}

/**
 * Tra cứu chi tiết đơn hàng Marketplace để lấy Sale bán, địa chỉ giao chi tiết, terminalCode
 * GET /api/v1/marketplace/orders/{orderCode}
 */
async function getMarketplaceOrderDetail(orderCode, token, siteId) {
  if (!orderCode) return null;
  try {
    const cleanCode = String(orderCode).split(/[-_]/)[0].trim();
    if (!cleanCode) return null;
    const data = await callTekoBff(`/api/v1/marketplace/orders/${cleanCode}`, {
      method: 'GET',
      token,
      siteId,
    });
    return data;
  } catch (err) {
    return null;
  }
}

/**
 * 2. Tải màn hình xử lý yêu cầu xuất kho
 * GET /api/v1/warehouse-export/load-screen-processing-export-request?documentId={documentId}&binId={binId}
 */
async function loadExportRequest(documentId, binId, token, siteId) {
  if (!documentId || !documentId.trim()) {
    throw new Error('Mã đơn / Mã yêu cầu xuất kho không được để trống.');
  }

  const cleanDoc = documentId.trim();
  const baseOrderCode = cleanDoc.split(/[-_]/)[0].trim();
  let params = { documentId: cleanDoc };
  if (binId) {
    params.binId = binId;
  }

  // Tra cứu đồng thời chi tiết đơn Marketplace để lấy chính xác Sale bán và Địa chỉ giao
  let marketplaceOrder = null;
  if (/^\d+$/.test(baseOrderCode) || baseOrderCode.length >= 8) {
    marketplaceOrder = await getMarketplaceOrderDetail(baseOrderCode, token, siteId);
  }

  let res = null;
  try {
    res = await callTekoBff('/api/v1/warehouse-export/load-screen-processing-export-request', {
      method: 'GET',
      params,
      token,
      siteId,
    });
  } catch (wmsErr) {
    // Nếu WMS báo không tìm thấy nhưng có mã shipment trong marketplace order, thử lại với mã shipment
    if (marketplaceOrder && Array.isArray(marketplaceOrder.shipments) && marketplaceOrder.shipments.length > 0) {
      const shipmentId = marketplaceOrder.shipments[0]?.id || `${cleanDoc}-01`;
      if (shipmentId && shipmentId !== cleanDoc) {
        try {
          res = await callTekoBff('/api/v1/warehouse-export/load-screen-processing-export-request', {
            method: 'GET',
            params: { documentId: shipmentId, ...(binId ? { binId } : {}) },
            token,
            siteId,
          });
        } catch (e) {}
      }
    }

    // Nếu WMS vẫn không có (ví dụ đơn bán hàng cũ/đã giao), fallback dựng order từ dữ liệu Marketplace
    if (!res && marketplaceOrder) {
      const mItems = (marketplaceOrder.items || marketplaceOrder.shipments?.[0]?.routerItems || []).map(it => ({
        sku: String(it.sku),
        skuName: it.displayName || it.name || `SKU ${it.sku}`,
        requestQuantity: Number(it.quantity || 1),
        scannedQuantity: Number(it.quantity || 1),
        tracking: Array.isArray(it.serial) && it.serial.length > 0 ? 'SERIAL' : 'NONE',
        serials: it.serial || [],
        lots: [],
        binQuantity: 0,
        uom: it.uom || 'Cái',
      }));

      return {
        requestId: marketplaceOrder.code,
        documentId: cleanDoc,
        status: marketplaceOrder.displayStatusName || marketplaceOrder.status || 'COMPLETED',
        isExported: true,
        exportedDate: marketplaceOrder.updatedAt || null,
        exportedBy: marketplaceOrder.creator?.name || 'Hệ thống',
        siteId: marketplaceOrder.terminalCode || siteId,
        siteName: marketplaceOrder.terminalName || '',
        branchCode: marketplaceOrder.terminalCode || 'CP02',
        saleName: marketplaceOrder.consultant?.name || marketplaceOrder.creator?.name || 'Nhân viên bán hàng',
        deliveryAddress: marketplaceOrder.shippingInfo?.fullAddress || marketplaceOrder.customer?.fullAddress || 'Tại quầy',
        receiverName: marketplaceOrder.shippingInfo?.name || marketplaceOrder.customer?.name || '',
        paymentStatus: marketplaceOrder.paymentStatus === 'FULLY_PAID' ? 'Đã thanh toán' : (marketplaceOrder.paymentStatus || 'Đã thanh toán'),
        paymentStatusCode: marketplaceOrder.paymentStatus || 'FULLY_PAID',
        paymentMethod: marketplaceOrder.payment?.displayName || marketplaceOrder.payments?.[0]?.paymentMethod || 'Tiền mặt',
        remainPayment: Number(marketplaceOrder.remainPayment ?? 0),
        grandTotal: Number(marketplaceOrder.grandTotal ?? 0),
        orderNote: marketplaceOrder.note || marketplaceOrder.customerNote || '',
        createdDate: marketplaceOrder.createdAt || '',
        expectedDate: marketplaceOrder.shippingInfo?.expectedDate || '',
        requestNote: marketplaceOrder.note || '',
        defaultProcessingBinId: 0,
        defaultProcessingBinName: '',
        scannedProcessingBinId: 0,
        items: mItems,
      };
    }

    if (!res) throw wmsErr;
  }

  if (!res || !res.requestId) {
    throw new Error(`Không tìm thấy yêu cầu xuất kho cho mã đơn "${cleanDoc}".`);
  }

  // Nếu đơn hàng đã hoàn tất (EXPORTED, PACKED), tra cứu thêm chi tiết phiếu xuất để lấy các serial đã xuất/soạn thực tế
  let detailData = null;
  if (res.status === 'EXPORTED' || res.status === 'PACKED' || res.status === 'COMPLETED') {
    detailData = await getExportRequestDetail(res.requestId || cleanDoc, token, siteId || res.siteId);
  }

  // Chuẩn hoá danh sách items
  const items = (res.items || []).map(item => {
    const skuStr = String(item.sku);
    let serials = Array.isArray(item.serials) ? item.serials : [];

    if (serials.length === 0 && detailData && Array.isArray(detailData.items)) {
      const matchedDetail = detailData.items.find(d => String(d.sku) === skuStr);
      if (matchedDetail && Array.isArray(matchedDetail.serials) && matchedDetail.serials.length > 0) {
        serials = matchedDetail.serials;
      }
    }

    const reqQty = Number(item.requestQuantity || item.quantity || 1);
    const isOrderExported = res.status === 'EXPORTED' || res.status === 'PACKED';
    const scannedQty = (isOrderExported && serials.length > 0)
      ? serials.length
      : Number(item.scannedQuantity || 0);

    return {
      sku: skuStr,
      skuName: item.skuName || item.productName || item.name || `SKU ${item.sku}`,
      requestQuantity: reqQty,
      scannedQuantity: scannedQty,
      tracking: item.tracking || ((serials.length > 0) ? 'SERIAL' : 'NONE'),
      serials,
      lots: Array.isArray(item.lots) ? item.lots : [],
      binQuantity: item.binQuantity || 0,
      uom: item.uom || 'Cái',
    };
  });

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

  // 1. Trích xuất mã chi nhánh bán (CPxx)
  let branchCode = marketplaceOrder?.terminalCode || '';
  if (!branchCode) {
    const cpMatch = (marketplaceOrder?.terminalName || '').match(/(CP\d+)/i);
    if (cpMatch) {
      branchCode = cpMatch[1].toUpperCase();
    }
  }

  // Trích xuất mã chi nhánh xuất (Kho xuất)
  let exportBranch = (res.siteName || detailData?.siteName || '').match(/(CP\d+)/i)?.[1]?.toUpperCase() || '';
  if (!exportBranch && (res.siteId || detailData?.siteId)) {
    exportBranch = SITE_ID_TO_BRANCH[Number(res.siteId || detailData?.siteId)] || '';
  }

  // Nếu branchCode bán chưa có thì fallback về exportBranch
  if (!branchCode) {
    branchCode = exportBranch || '';
  }

  // 2. Trích xuất thông tin Sale bán chính xác
  let saleName = marketplaceOrder?.consultant?.name || marketplaceOrder?.creator?.name || '';
  if (!saleName) {
    saleName = res.saleName || res.sellerName || detailData?.saleName || detailData?.sellerName || '';
  }
  if (!saleName) {
    if (res.exportType === 'ST') {
      saleName = detailData?.updatedBy || detailData?.exportedBy || 'Điều chuyển nội bộ (ST)';
    } else {
      saleName = detailData?.createdByName || detailData?.createdBy || detailData?.updatedBy || detailData?.exportedBy || 'Nhân viên bán hàng';
    }
  }

  // 3. Trích xuất địa chỉ giao chi tiết
  let deliveryAddress = marketplaceOrder?.shippingInfo?.fullAddress || marketplaceOrder?.customer?.fullAddress || marketplaceOrder?.shippingInfo?.address || '';
  if (!deliveryAddress) {
    deliveryAddress = res.deliveryAddress || res.shippingAddress || detailData?.deliveryAddress || detailData?.shippingAddress || '';
  }
  if (!deliveryAddress) {
    if (res.receiverName) {
      deliveryAddress = res.receiverName;
    } else if (detailData?.receiverName) {
      deliveryAddress = detailData?.receiverName;
    } else {
      deliveryAddress = 'Nhận tại quầy / Kho xuất';
    }
  }

  // 4. Trích xuất người nhận
  let receiverPhone = marketplaceOrder?.shippingInfo?.phone || marketplaceOrder?.customer?.phone || '';
  let receiverName = marketplaceOrder?.shippingInfo?.name || marketplaceOrder?.customer?.name || res.receiverName || detailData?.receiverName || '';

  // 5. Trích xuất thông tin thanh toán & ghi chú đơn (COD = Chưa thanh toán, hiển thị đúng số tiền còn lại)
  let paymentMethod = marketplaceOrder?.payment?.displayName
    || marketplaceOrder?.payments?.[0]?.paymentMethod
    || marketplaceOrder?.payment?.methodCode
    || 'Tiền mặt';

  const isCod = (marketplaceOrder?.payment?.methodCode === 'COD') 
    || (/COD/i.test(paymentMethod))
    || (/nhận hàng/i.test(paymentMethod));

  let rawRemain = marketplaceOrder?.remainPayment;
  let grandTotal = Number(marketplaceOrder?.grandTotal ?? 0);
  let remainPayment = (rawRemain !== undefined && rawRemain !== null) ? Number(rawRemain) : (isCod ? grandTotal : 0);

  let rawPaymentStatus = marketplaceOrder?.paymentStatus || '';
  let paymentStatusText = 'Chưa thanh toán';
  let paymentStatusCode = 'UNPAID';

  if (isCod) {
    if (remainPayment > 0) {
      paymentStatusText = 'Chưa thanh toán';
      paymentStatusCode = 'UNPAID_COD';
    } else {
      paymentStatusText = 'Đã thanh toán';
      paymentStatusCode = 'FULLY_PAID';
    }
  } else {
    if (remainPayment === 0 || rawPaymentStatus === 'FULLY_PAID') {
      paymentStatusText = 'Đã thanh toán';
      paymentStatusCode = 'FULLY_PAID';
      remainPayment = 0;
    } else if (rawPaymentStatus === 'PARTIALLY_PAID' || (remainPayment > 0 && remainPayment < grandTotal)) {
      paymentStatusText = 'Thanh toán 1 phần';
      paymentStatusCode = 'PARTIALLY_PAID';
    } else {
      paymentStatusText = 'Chưa thanh toán';
      paymentStatusCode = 'UNPAID';
    }
  }

  let orderNote = marketplaceOrder?.note || marketplaceOrder?.customerNote || res.requestNote || '';

  return {
    requestId: res.requestId,
    documentId: res.documentId || cleanDoc,
    status: res.status,
    isExported: res.status === 'EXPORTED' || res.status === 'COMPLETED',
    isPacked: res.status === 'PACKED',
    packedDate: detailData?.packedDate || null,
    packedBy: detailData?.packedBy || null,
    exportedDate: detailData?.exportedDate || null,
    exportedBy: detailData?.exportedBy || null,
    siteId: res.siteId || detailData?.siteId,
    siteName: marketplaceOrder?.terminalName || res.siteName || detailData?.siteName || '',
    branchCode: branchCode || '',
    exportBranch: exportBranch || branchCode || '',
    saleName: saleName,
    deliveryAddress: deliveryAddress,
    receiverName: receiverName,
    receiverPhone: receiverPhone,
    paymentStatus: paymentStatusText,
    paymentStatusCode: paymentStatusCode,
    paymentMethod: paymentMethod,
    remainPayment: remainPayment,
    grandTotal: grandTotal,
    orderNote: orderNote,
    createdDate: res.createdDate || marketplaceOrder?.createdAt || '',
    expectedDate: res.expectedDate || marketplaceOrder?.shippingInfo?.expectedDate || '',
    requestNote: orderNote,
    defaultProcessingBinId: res.defaultProcessingBinId,
    defaultProcessingBinName: res.defaultProcessingBinName,
    scannedProcessingBinId: res.scannedProcessingBinId,
    items,
  };
}

/**
 * 3. Tra cứu vị trí BIN hiện tại của Serial
 * GET /api/v1/serial-tracking?serial={serial}
 */
async function getSerialTracking(serial, token, siteId) {
  if (!serial || !serial.trim()) {
    throw new Error('Số Serial không được để trống.');
  }
  const cleanSerial = serial.trim();
  const params = { serial: cleanSerial };
  if (siteId && !isNaN(Number(siteId))) {
    params.siteId = Number(siteId);
  }

  try {
    const res = await callTekoBff('/api/v1/serial-tracking', {
      method: 'GET',
      params,
      token,
      siteId,
    });

    if (res && (res.serial || res.sku)) {
      let resolvedBinId = res.binId || null;
      const targetSiteId = res.siteId || siteId;

      // Nếu Teko trả về binName nhưng chưa có binId, tự động truy vấn binId qua getBinByBinName
      if (!resolvedBinId && res.binName && targetSiteId) {
        try {
          const binInfo = await getBinByBinName(res.binName, token, targetSiteId);
          if (binInfo && binInfo.binId) {
            resolvedBinId = binInfo.binId;
          }
        } catch (bErr) {
          // ignore lookup failure
        }
      }

      return {
        serial: res.serial || cleanSerial,
        sku: String(res.sku || ''),
        productName: res.productName || res.skuName || '',
        binId: resolvedBinId,
        binName: res.binName || '',
        siteId: targetSiteId,
        siteShortName: res.siteShortName || '',
        serialType: res.serialType || '',
      };
    }
  } catch (err) {
    // Nếu API Teko lỗi 404 hoặc không tìm thấy, có thể tiếp tục
  }

  return {
    serial: cleanSerial,
    sku: '',
    binId: null,
    binName: '',
  };
}

/**
 * 4. Luân chuyển sản phẩm / Serial giữa 2 BIN (Luân chuyển hàng trong kho)
 * POST /api/v1/movement/confirm
 * https://erp.phongvu.vn/warehousing/internal-stock-movement
 */
async function moveBin({ fromBinId, toBinId, sku, serials, serial, lots, quantity = 1, siteId, documentId }, token, siteIdOpt) {
  if (!fromBinId || !toBinId) {
    throw new Error('Thiếu thông tin BIN nguồn hoặc BIN đích để luân chuyển.');
  }
  if (!sku) {
    throw new Error('Thiếu mã SKU để thực hiện luân chuyển.');
  }

  const effectiveSiteId = siteId || siteIdOpt;
  const serialList = Array.isArray(serials) ? serials : (serial ? [String(serial).trim()] : []);
  const lotList = Array.isArray(lots) ? lots : [];
  const qty = serialList.length > 0 ? serialList.length : (Number(quantity) || 1);

  const payload = {
    fromBinId: Number(fromBinId),
    toBinId: Number(toBinId),
    items: [
      {
        sku: String(sku).trim(),
        quantity: qty,
        ...(serialList.length > 0 ? { serials: serialList } : {}),
        ...(lotList.length > 0 ? { lots: lotList } : {}),
      }
    ],
    ...(documentId ? { documentId: String(documentId).trim() } : {})
  };

  const res = await callTekoBff('/api/v1/movement/confirm', {
    method: 'POST',
    data: payload,
    token,
    siteId: effectiveSiteId,
  });

  return {
    success: true,
    data: res,
  };
}

/**
 * 5. Xác nhận soạn hàng / Hoàn tất xuất kho (Confirm Packing)
 * POST /api/v1/warehouse-export/confirm-packing
 */
async function confirmPacking({ requestId, binId, items, isAutoHandover = false, receiverName = '', siteId }, token, siteIdOpt) {
  if (!requestId) {
    throw new Error('Thiếu mã yêu cầu xuất kho (requestId).');
  }
  if (!binId) {
    throw new Error('Thiếu mã BIN soạn hàng (binId).');
  }

  const effectiveSiteId = siteId || siteIdOpt;
  const formattedItems = (items || []).map(it => ({
    sku: String(it.sku),
    serials: Array.isArray(it.serials) ? it.serials : [],
    lots: Array.isArray(it.lots) ? it.lots : [],
  }));

  const payload = {
    requestId: String(requestId).trim(),
    binId: Number(binId),
    items: formattedItems,
    isAutoHandover: Boolean(isAutoHandover),
    receiverName: isAutoHandover ? (receiverName || undefined) : undefined,
  };

  const res = await callTekoBff('/api/v1/warehouse-export/confirm-packing', {
    method: 'POST',
    data: payload,
    token,
    siteId: effectiveSiteId,
  });

  return {
    success: true,
    data: res,
    message: isAutoHandover ? 'Xác nhận soạn hàng và bàn giao thành công!' : 'Xác nhận soạn hàng xuất kho thành công!',
  };
}

/**
 * 6. Tra cứu tồn kho vật lý theo BIN của sản phẩm
 * GET /api/v1/stock-quantity?siteId={siteId}&skus={sku}
 */
async function getStockQuantityByBin(sku, siteId, token) {
  if (!sku) throw new Error('Thiếu mã SKU cần tra cứu tồn kho.');
  if (!siteId) throw new Error('Thiếu mã chi nhánh/siteId.');

  const res = await callTekoBff('/api/v1/stock-quantity', {
    method: 'GET',
    params: { siteId: Number(siteId), skus: String(sku).trim() },
    token,
    siteId: Number(siteId),
  });

  const stocks = Array.isArray(res?.stocks) ? res.stocks : [];
  return {
    sku: String(sku).trim(),
    siteId: Number(siteId),
    stocks: stocks.map(s => ({
      binId: s.binId,
      binName: s.binName || `BIN #${s.binId}`,
      quantity: Number(s.quantity || 0),
      zoneName: s.zoneName || 'Khu vực kho',
      productStatusTypeName: s.productStatusTypeName || 'Hàng bán mới tại kho',
      productStatusType: s.productStatusType,
      skuName: s.skuName || '',
      uom: s.uom || 'Cái',
    })),
  };
}

module.exports = {
  normalizeToken,
  callTekoBff,
  getUserSites,
  getBinByBinName,
  loadExportRequest,
  getExportRequestDetail,
  getSerialTracking,
  moveBin,
  confirmPacking,
  getStockQuantityByBin,
};
