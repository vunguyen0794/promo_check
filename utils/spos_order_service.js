/**
 * utils/spos_order_service.js
 * Dịch vụ tích hợp kết nối SPOS / Teko Carts API cho tính năng "Tạo Đơn Hàng Nhanh"
 */

const TEKO_CARTS_URL = 'https://carts.tekoapis.com';
const TEKO_STAFF_BFF_URL = 'https://staff-bff.tekoapis.com';

const { createClient } = require('@supabase/supabase-js');
let supabase = null;
if (process.env.SUPABASE_URL && (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY)) {
  supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY);
}

/**
 * Chuẩn hoá token
 */
function normalizeToken(token) {
  if (!token) return '';
  const clean = token.trim();
  return clean.toLowerCase().startsWith('bearer ') ? clean : `Bearer ${clean}`;
}

/**
 * Danh mục cấu hình Terminal & Showroom chuẩn Teko SPOS
 * id: Mã terminalId nội bộ trên hệ thống Teko Carts/SPOS (Ví dụ: CP74 -> 100246, CP00 -> 1, CP01 -> 26)
 * siteId: Mã kho / địa điểm xuất hàng WMS tương ứng (appId trong Teko Terminals)
 */
const TEKO_TERMINAL_CONFIG = {
  'CP00': { id: 1, siteId: 27, name: 'CP00 - NTMK' },
  'CP01': { id: 26, siteId: 7, name: 'CP01 - 264A-264B-264C Nguyễn Thị Minh Khai,Phường 6' },
  'CP02': { id: 14, siteId: 8, name: 'CP02 - Số 408 Đại Lộ Bình Dương, Phường Phú Lợi' },
  'CP04': { id: 16, siteId: 0, name: 'CP04 - 17A Đường Cộng Hòa, Phường 4' },
  'CP05': { id: 17, siteId: 46, name: 'CP05 - 1081C Hậu Giang, Phường 11' },
  'CP06': { id: 18, siteId: 0, name: 'CP06 - 1A Lê Văn Việt , Phường Hiệp Phú' },
  'CP07': { id: 19, siteId: 9, name: 'CP07 - Số 9-11 Nguyễn Thị Thập, Phường Tân Phú' },
  'CP08': { id: 20, siteId: 54, name: 'CP08 - Số 2A, Đường Nguyễn Oanh, Phường 7' },
  'CP09': { id: 9, siteId: 0, name: 'CP09 - Tầng 1, Số 1 Thái Hà, Phường Trung Liệt' },
  'CP10': { id: 21, siteId: 55, name: 'CP10 - 29 Nguyễn Lương Bằng, Phường Hòa Khánh Bắc' },
  'CP14': { id: 22, siteId: 57, name: 'CP14 - Lô 11 G2 Đường Nguyễn Thái Học, Phường 7' },
  'CP15': { id: 10, siteId: 16, name: 'CP15 - Tầng 1 Số 218 Lê Duẩn, Phường Trường Thi' },
  'CP18': { id: 25, siteId: 63, name: 'CP18 - 37-39 Lý Thường Kiệt, Phường 2' },
  'CP20': { id: 15, siteId: 65, name: 'CP20 - 37 Bùi Văn Hòa, Khu Phố 4, Phường Long Bình' },
  'CP25': { id: 30, siteId: 82, name: 'CP25 - Số 159 Quốc Lộ 9, Phường 5' },
  'CP28': { id: 33, siteId: 72, name: 'CP28 - 232 Ngô Gia Tự, Phường Thanh Sơn' },
  'CP32': { id: 35, siteId: 74, name: 'CP32 - 12 Lê Thánh Tông, Phường Thắng Lợi' },
  'CP34': { id: 38, siteId: 77, name: 'CP34 - 225 Ấp Bắc, Khu Phố 3, Phường 10' },
  'CP37': { id: 43, siteId: 81, name: 'CP37 - 40-42 Thái Nguyên, P. Phương Sài, Tp. Nha Trang' },
  'CP40': { id: 125, siteId: 85, name: 'CP40 - Showroom Hoàng Hoa Thám' },
  'CP42': { id: 283, siteId: 599, name: 'CP42 - Đường 30/4, P.Rạch Dừa Tỉnh Bà Rịa - Vũng Tàu' },
  'CP46': { id: 355, siteId: 628, name: 'CP46 - 164 Lê Văn Việt, Tăng Nhơn Phú B, TP.Thủ Đức' },
  'CP48': { id: 410, siteId: 692, name: 'CP48 - 62 Trần Đại Nghĩa, Phường Đồng Tâm' },
  'CP50': { id: 376, siteId: 642, name: 'CP50 - Địa Điểm Kinh Doanh 49' },
  'CP58': { id: 478, siteId: 763, name: 'CP58 - ĐỊA ĐIỂM KINH DOANH 52' },
  'CP62': { id: 493, siteId: 779, name: 'CP62 - ĐỊA ĐIỂM KINH DOANH 39' },
  'CP64': { id: 1292, siteId: 1600, name: 'CP64 - ĐỊA ĐIỂM KINH DOANH 54' },
  'CP65': { id: 3028, siteId: 3270, name: 'CP65 - ĐỊA ĐIỂM KINH DOANH 56' },
  'CP67': { id: 10020, siteId: 3480, name: 'CP67 - ĐỊA ĐIỂM KINH DOANH 57' },
  'CP68': { id: 10014, siteId: 3495, name: 'CP68 - CHI NHÁNH 37' },
  'CP69': { id: 100213, siteId: 29499, name: 'CP69 - ĐỊA ĐIỂM KINH DOANH 58' },
  'CP74': { id: 100246, siteId: 53019, name: 'CP74 - 162-164 Khánh Hội, Phường Khánh Hội, Quận 4' },
  'CP75': { id: 100247, siteId: 54290, name: 'CP75 - Showroom Phong Vũ Phan Đăng Lưu 2' },
  'CP90': { id: 3208, siteId: 3416, name: 'CP90 - CHI NHÁNH 30' },
};

const terminalCache = new Map();

/**
 * Tra cứu thông tin terminalId và siteId chính xác của showroom
 */
async function resolveTerminalInfo(branchCode, token = '') {
  if (!branchCode) return { id: 1, siteId: 27, code: 'CP00' };
  const cleanCode = String(branchCode).trim().toUpperCase();

  if (terminalCache.has(cleanCode)) {
    return terminalCache.get(cleanCode);
  }

  if (TEKO_TERMINAL_CONFIG[cleanCode]) {
    const conf = { ...TEKO_TERMINAL_CONFIG[cleanCode], code: cleanCode };
    terminalCache.set(cleanCode, conf);
    return conf;
  }

  // Nếu showroom mới chưa có trong static list, tự động query Staff BFF API
  if (token) {
    try {
      const res = await callTeko(`https://staff-bff.tekoapis.com/api/v1/terminals?code=${encodeURIComponent(cleanCode)}`, {
        method: 'GET',
        token
      });
      const term = res.data?.result?.terminals?.[0];
      if (term && term.id) {
        const info = {
          id: Number(term.id),
          siteId: Number(term.appId || 0),
          name: term.name || cleanCode,
          code: cleanCode
        };
        terminalCache.set(cleanCode, info);
        return info;
      }
    } catch (e) {
      console.warn(`[SPOS-ORDER] Không thể truy vấn terminalId cho ${cleanCode}:`, e.message);
    }
  }

  return { id: 1, siteId: 27, code: cleanCode };
}

/**
 * Sinh mã đơn hàng chuẩn Teko / SPOS Phong Vũ (dùng cho hiển thị / tra cứu cục bộ)
 * Quy tắc: 14 chữ số thuần túy (không có tiền tố PV)
 * Định dạng: YYMMDD (6 số ngày) + '3' (mã phân hệ bán lẻ) + 6 chữ số ngẫu nhiên + '0'
 * Ví dụ: 26100737190790 (tương ứng #26100737190790 trên app SPOS)
 */
function generateOrderCode() {
  const d = new Date();
  const yy = String(d.getFullYear()).slice(-2);
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const rand6 = Math.floor(100000 + Math.random() * 900000);
  return `${yy}${mm}${dd}3${rand6}0`;
}

/**
 * Helper gọi API Teko
 */
async function callTeko(url, options = {}) {
  const {
    method = 'POST',
    data = null,
    token = '',
    headers: customHeaders = {}
  } = options;

  const authHeader = normalizeToken(token);
  const headers = {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Origin': 'https://erp.phongvu.vn',
    'Referer': 'https://erp.phongvu.vn/',
    ...customHeaders
  };

  if (authHeader) {
    headers['Authorization'] = authHeader;
  }

  const fetchOpts = {
    method,
    headers
  };

  if (data && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
    fetchOpts.body = JSON.stringify(data);
  }

  const response = await fetch(url, fetchOpts);
  const contentType = response.headers.get('content-type') || '';
  let resData;
  if (contentType.includes('application/json')) {
    resData = await response.json();
  } else {
    resData = await response.text();
  }

  return { ok: response.ok, status: response.status, data: resData, headers: response.headers };
}

/**
 * Tạo đơn hàng chờ thanh toán lên hệ thống SPOS Teko
 * @param {Object} payload - Dữ liệu đơn hàng từ Web
 */
async function createPendingOrder(payload) {
  const {
    customer,
    delivery,
    items,
    voucherCode,
    note,
    paymentMethod = 'COD',
    branchCode = 'CP01',
    token = '',
    userId = ''
  } = payload;

  const validMethods = ['COD', 'BANK_TRANSFER', 'CARD', 'CASH'];
  const selectedPaymentMethod = validMethods.includes(paymentMethod) ? paymentMethod : 'COD';
  const paymentMethodLabel = selectedPaymentMethod === 'COD'
    ? 'Thanh toán khi nhận hàng (COD)'
    : (selectedPaymentMethod === 'BANK_TRANSFER'
      ? 'Chuyển khoản'
      : (selectedPaymentMethod === 'CARD' ? 'Quẹt thẻ' : 'Tiền mặt'));

  const terminalInfo = await resolveTerminalInfo(branchCode, token);
  const terminalId = terminalInfo.id || 1;
  const isTestOrMock = payload.allowOfflineMock || payload.isTestOrMock || process.env.NODE_ENV === 'test';

  // 1. Kiểm tra Token bắt buộc
  if (!isTestOrMock && (!token || token.length < 30)) {
    return {
      ok: false,
      error: 'Chưa có Token đăng nhập SPOS/ERP. Vui lòng mở trang erp.phongvu.vn trên trình duyệt để Extension tự động đồng bộ phiên làm việc.',
      tokenStatus: 'MISSING'
    };
  }

  // 2. Chuẩn bị danh sách sản phẩm
  let totalOriginal = 0;
  let totalPromoDiscount = 0;
  let totalManualDiscount = 0;
  let totalPayable = 0;

  const orderItems = (items || []).map((it) => {
    const qty = Number(it.quantity) || 1;
    const listP = Number(it.listPrice) || 0;
    const promoP = Number(it.promoPrice) > 0 ? Number(it.promoPrice) : listP;
    const itemDisc = Number(it.discount) || 0;
    const finalPrice = Math.max(0, promoP - itemDisc);
    const lineTotal = finalPrice * qty;

    totalOriginal += listP * qty;
    totalPromoDiscount += Math.max(0, listP - promoP) * qty;
    totalManualDiscount += itemDisc * qty;
    totalPayable += lineTotal;

    return {
      sku: it.sku,
      productName: it.name || it.product_name || `Sản phẩm ${it.sku}`,
      quantity: qty,
      listPrice: listP,
      promoPrice: promoP,
      discount: itemDisc,
      finalPrice: finalPrice,
      lineTotal: lineTotal,
      warranty: it.warranty || '',
      vatRate: it.vat_rate !== undefined ? it.vat_rate : null
    };
  });

  if (!orderItems.length) {
    return {
      ok: false,
      error: 'Giỏ hàng đang trống. Vui lòng chọn ít nhất 1 sản phẩm trước khi tạo đơn.',
      tokenStatus: 'VALID'
    };
  }

  if (isTestOrMock && (!token || token.length < 30)) {
    const mockOrderCode = generateOrderCode();
    const orderData = {
      orderCode: mockOrderCode,
      displayOrderCode: `#${mockOrderCode}`,
      status: 'PROCESSING',
      statusText: 'Đang xử lý trên app SPOS',
      customer: {
        name: (customer?.name || '').trim() || 'Khách lẻ',
        phone: (customer?.phone || '').trim()
      },
      delivery: {
        type: 'DELIVERY_TYPE_PICKUP',
        storeCode: branchCode,
        address: 'Showroom Phong Vũ'
      },
      items: orderItems,
      pricing: {
        totalOriginal,
        totalPromoDiscount,
        totalManualDiscount,
        totalPayable
      },
      paymentMethod: selectedPaymentMethod,
      paymentMethodLabel,
      voucherCode: voucherCode || '',
      appliedPromo: payload.appliedPromo || null,
      note: (note || '').trim(),
      rawNote: note || '',
      branchCode,
      userId,
      tokenStatus: 'MOCK',
      tekoSynced: true,
      createdAt: new Date().toISOString()
    };

    return {
      ok: true,
      orderCode: mockOrderCode,
      displayOrderCode: `#${mockOrderCode}`,
      paymentMethod: selectedPaymentMethod,
      paymentMethodLabel,
      orderData,
      tekoSynced: true,
      tokenStatus: 'MOCK',
      totalPayable,
      message: 'Tạo đơn test mock thành công'
    };
  }

  try {
    // 3. Khởi tạo giỏ hàng trên Teko Carts API
    // POST https://carts.tekoapis.com/api/v2/carts?terminal=CP01&terminalId=1
    const createCartUrl = `${TEKO_CARTS_URL}/api/v2/carts?terminal=${encodeURIComponent(branchCode)}&terminalId=${terminalId}`;
    const cartRes = await callTeko(createCartUrl, {
      method: 'POST',
      data: {},
      token
    });

    if (cartRes.status === 401) {
      return {
        ok: false,
        error: 'Phiên đăng nhập SPOS/ERP đã hết hạn (401 Unauthorized). Vui lòng mở lại trang ERP Phong Vũ để gia hạn Token mới.',
        tokenStatus: 'EXPIRED'
      };
    }

    if (!cartRes.ok || !cartRes.data?.data) {
      const errMsg = cartRes.data?.message || cartRes.data?.error?.message || `Lỗi máy chủ Teko (Mã ${cartRes.status})`;
      return {
        ok: false,
        error: `Không thể tạo giỏ hàng trên SPOS: ${errMsg}`,
        tokenStatus: 'ERROR'
      };
    }

    let currentCartToken = cartRes.data.data.cartToken || cartRes.data.data.cart?.id;
    let currentCartId = '';
    try {
      const p = JSON.parse(Buffer.from(currentCartToken.split('.')[1], 'base64').toString());
      if (p.cid) currentCartId = p.cid;
    } catch (e) {}

    function updateTokenFromRes(r) {
      if (!r) return;
      const newToken = r.headers?.get ? r.headers.get('x-cart-token') : (r.headers?.['x-cart-token'] || r.data?.data?.cartToken);
      if (newToken) {
        currentCartToken = newToken;
        try {
          const p = JSON.parse(Buffer.from(newToken.split('.')[1], 'base64').toString());
          if (p.cid) currentCartId = p.cid;
        } catch (e) {}
      }
    }

    // 3.9. Tự động kiểm tra và gắn promotionId cho các sản phẩm có ưu đãi showroom/chi nhánh
    for (const it of orderItems) {
      if (!it.promotionId) {
        try {
          const { fetchTekoProductDetails } = require('./teko_product_service');
          const pDetails = await fetchTekoProductDetails(it.sku, branchCode, supabase);
          if (pDetails && pDetails.promotions && pDetails.promotions.length > 0) {
            const discountPromo = pDetails.promotions.find(p => p.benefit?.discount?.flat > 0 || p.benefit?.discount?.percent > 0);
            if (discountPromo) {
              it.promotionId = discountPromo.id;
            } else if (pDetails.promotions[0]?.id) {
              it.promotionId = pDetails.promotions[0].id;
            }
          }
        } catch (e) {
          // Fallback an toàn nếu không lấy được chi tiết KM
        }
      }
    }

    // 4. Thêm sản phẩm vào giỏ hàng (kèm promotionId để kích hoạt giá giảm khuyến mãi ngay lập tức)
    // POST https://carts.tekoapis.com/api/v2/carts/items?terminal=CP01&terminalId=1
    const addItemsUrl = `${TEKO_CARTS_URL}/api/v2/carts/items?terminal=${encodeURIComponent(branchCode)}&terminalId=${terminalId}`;
    const addItemsRes = await callTeko(addItemsUrl, {
      method: 'POST',
      token,
      headers: {
        'x-cart-token': currentCartToken
      },
      data: {
        groups: [
          {
            products: orderItems.map(it => {
              const p = {
                sku: String(it.sku),
                quantity: Number(it.quantity) || 1
              };
              if (it.promotionId) {
                p.promotionId = Number(it.promotionId);
              }
              return p;
            })
          }
        ]
      }
    });
    updateTokenFromRes(addItemsRes);

    if (!addItemsRes.ok || !addItemsRes.data?.data) {
      const errMsg = addItemsRes.data?.message || `Lỗi thêm sản phẩm (Mã ${addItemsRes.status})`;
      return {
        ok: false,
        error: `Không thể đưa sản phẩm vào giỏ SPOS: ${errMsg}`,
        tokenStatus: 'ERROR'
      };
    }

    // 4.1. Áp dụng mã giảm giá / Voucher lên giỏ hàng Teko Carts (để kích hoạt ưu đãi & tự động đính kèm quà tặng vào đơn)
    const cleanVoucher = String(voucherCode || payload.appliedPromo?.code || '').trim().toUpperCase();
    if (cleanVoucher) {
      try {
        const couponUrl = `${TEKO_CARTS_URL}/api/v1/cart/apply-coupon?terminal=${encodeURIComponent(branchCode)}&terminalId=${terminalId}&channel=pv_showroom`;
        const couponRes = await callTeko(couponUrl, {
          method: 'POST',
          token,
          headers: {
            'x-cart-token': currentCartToken
          },
          data: {
            coupon: cleanVoucher
          }
        });
        updateTokenFromRes(couponRes);
        if (couponRes.ok) {
          console.log(`[SPOS-ORDER] Đã áp thành công mã coupon ${cleanVoucher} lên giỏ hàng Teko!`);
        } else {
          console.warn(`[SPOS-ORDER] Áp mã coupon ${cleanVoucher} thất bại:`, couponRes.status, couponRes.data?.error || couponRes.data?.message);
        }
      } catch (cErr) {
        console.warn(`[SPOS-ORDER] Lỗi gọi API apply-coupon:`, cErr.message);
      }
    }

    // 5. Lấy danh sách địa chỉ nhận hàng & chọn địa chỉ showroom
    const optUrl = `${TEKO_CARTS_URL}/api/v2/carts/delivery-options?terminal=${encodeURIComponent(branchCode)}&terminalId=${terminalId}`;
    const optRes = await callTeko(optUrl, {
      method: 'POST',
      token,
      headers: {
        'x-cart-token': currentCartToken
      },
      data: {}
    });
    updateTokenFromRes(optRes);

    let selectedAddress = null;
    if (optRes.ok && optRes.data?.data?.availableDeliveryAddresses) {
      const addresses = optRes.data.data.availableDeliveryAddresses;
      // Tìm showroom khớp branchCode
      selectedAddress = addresses.find(a =>
        a.deliveryType === 'DELIVERY_TYPE_PICKUP' &&
        (a.deliveryAddress?.addressId?.toUpperCase() === `PHONGVU:${branchCode.toUpperCase()}` ||
         a.deliveryAddress?.addressId?.toUpperCase().includes(branchCode.toUpperCase()))
      ) || addresses.find(a => a.deliveryType === 'DELIVERY_TYPE_PICKUP') || addresses[0];
    }

    // 6. Cập nhật thông tin giao nhận hàng
    const customerName = (customer?.name || '').trim() || 'Khách lẻ';
    const customerPhone = (customer?.phone || '').trim() || '0706556027';
    const customerEmail = (customer?.email || '').trim() || 'vu.nt1@phongvu-mna.vn';

    const cleanAddress = selectedAddress?.deliveryAddress ? { ...selectedAddress.deliveryAddress } : {};
    const wardId = cleanAddress.wardId ? String(cleanAddress.wardId) : '12910815';
    const districtId = cleanAddress.districtId ? String(cleanAddress.districtId) : (wardId.length >= 6 ? wardId.slice(0, 6) : '129108');
    const provinceId = String(cleanAddress.provinceId || '129');
    const siteId = cleanAddress.siteId || terminalInfo.siteId || 53019;
    const addressId = cleanAddress.addressId || `phongvu:${branchCode}`;
    const address = cleanAddress.address || delivery?.address || 'Showroom Phong Vũ';
    const fullAddress = cleanAddress.fullAddress || delivery?.address || 'Showroom Phong Vũ';

    const isShowroomPickup = !delivery?.type || delivery.type === 'SHOWROOM' || delivery.type === 'DELIVERY_TYPE_PICKUP' || delivery.useShowroomAddress;

    let checkoutShippingInfo = null;

    if (isShowroomPickup) {
      // 6.1. Nhận tại điểm / Showroom: Dùng API v2 carts/delivery-info
      // Teko tự động áp dụng gói "Giao tại showroom" (serviceId: 89 - Miễn phí)
      const dInfoUrl = `${TEKO_CARTS_URL}/api/v2/carts/delivery-info?terminal=${encodeURIComponent(branchCode)}&terminalId=${terminalId}`;
      const dInfoRes = await callTeko(dInfoUrl, {
        method: 'PUT',
        token,
        headers: {
          'x-cart-token': currentCartToken
        },
        data: {
          addressId: addressId,
          deliveryType: 'DELIVERY_TYPE_PICKUP',
          siteId: siteId,
          districtId: districtId,
          provinceId: provinceId,
          wardId: wardId,
          fullAddress: fullAddress,
          name: customerName,
          phone: customerPhone,
          email: customerEmail
        }
      });
      updateTokenFromRes(dInfoRes);

      if (!dInfoRes.ok) {
        const errMsg = dInfoRes.data?.message || dInfoRes.data?.error || `Lỗi thiết lập nhận tại showroom (Mã ${dInfoRes.status})`;
        return {
          ok: false,
          error: `Không thể chọn nhận tại showroom: ${errMsg}`,
          tokenStatus: 'ERROR'
        };
      }

      checkoutShippingInfo = {
        deliveryType: 'DELIVERY_TYPE_PICKUP',
        name: customerName,
        telephone: customerPhone,
        email: customerEmail,
        addressId: addressId,
        storeCode: branchCode,
        siteId: siteId,
        address: address,
        fullAddress: fullAddress,
        provinceId: provinceId,
        provinceCode: provinceId,
        districtId: districtId,
        districtCode: districtId,
        wardId: wardId,
        wardCode: wardId
      };
    } else {
      // 6.2. Giao hàng tận nơi: Gọi API shipping-address v1
      const shipBody = {
        addressId: `home:${customerPhone}`,
        address: delivery?.address || 'Địa chỉ giao hàng',
        fullAddress: delivery?.fullAddress || delivery?.address || 'Địa chỉ giao hàng',
        provinceId: String(delivery?.provinceId || provinceId),
        provinceCode: String(delivery?.provinceId || provinceId),
        provinceName: delivery?.provinceName || cleanAddress.provinceName || 'Thành phố Hồ Chí Minh',
        districtId: String(delivery?.districtId || districtId),
        districtCode: String(delivery?.districtId || districtId),
        districtName: delivery?.districtName || cleanAddress.districtName || '',
        wardId: String(delivery?.wardId || wardId),
        wardCode: String(delivery?.wardId || wardId),
        wardName: delivery?.wardName || cleanAddress.wardName || '',
        name: customerName,
        telephone: customerPhone,
        email: customerEmail,
        addressNote: (note || '').trim(),
        storeCode: branchCode
      };

      const shipUrl = `${TEKO_CARTS_URL}/api/v1/cart/shipping-address?terminal=${encodeURIComponent(branchCode)}&terminalId=${terminalId}&channel=pv_showroom&cartId=${encodeURIComponent(currentCartId)}`;
      const shipRes = await callTeko(shipUrl, {
        method: 'POST',
        token,
        headers: {
          'x-cart-token': currentCartToken
        },
        data: shipBody
      });
      updateTokenFromRes(shipRes);

      if (!shipRes.ok) {
        const errMsg = shipRes.data?.error || shipRes.data?.message || `Lỗi cập nhật người nhận (Mã ${shipRes.status})`;
        return {
          ok: false,
          error: `Lỗi cập nhật người nhận SPOS: ${errMsg}`,
          tokenStatus: 'ERROR'
        };
      }

      checkoutShippingInfo = {
        deliveryType: 'DELIVERY_TYPE_AT_HOME',
        name: customerName,
        telephone: customerPhone,
        email: customerEmail,
        address: shipBody.address,
        fullAddress: shipBody.fullAddress,
        provinceId: shipBody.provinceId,
        provinceCode: shipBody.provinceCode,
        districtId: shipBody.districtId,
        districtCode: shipBody.districtCode,
        wardId: shipBody.wardId,
        wardCode: shipBody.wardCode,
        addressNote: shipBody.addressNote
      };
    }

    // 7. Gán phương thức thanh toán đã chọn
    // Đối với COD (Thanh toán khi nhận hàng): Luôn apply payment method 'COD' lên giỏ hàng Teko
    // để Teko OMS và SPOS Mobile ghi nhận chính xác phương thức COD (thay vì tự động fallback về Tiền mặt CASH).
    if (selectedPaymentMethod === 'COD') {
      try {
        const payUrl = `${TEKO_CARTS_URL}/api/v1/cart/apply-payment-method?terminal=${encodeURIComponent(branchCode)}&terminalId=${terminalId}&channel=pv_showroom&cartId=${encodeURIComponent(currentCartId)}`;
        const pmRes = await callTeko(payUrl, {
          method: 'PUT',
          token,
          headers: {
            'x-cart-token': currentCartToken
          },
          data: {
            paymentMethodCode: 'COD'
          }
        });
        updateTokenFromRes(pmRes);
      } catch (e) {
        console.warn('[SPOS-ORDER] Không thể apply-payment-method COD:', e.message);
      }
    }

    // 8. Thực hiện Lưu đơn hàng (Record Order) trên Teko Carts API V2
    // Endpoint: POST /api/v2/carts/record
    // Cơ chế V2 Record Order chuẩn Teko SPOS:
    // 1. Ghi nhận trực tiếp note vào order.note trên Teko OMS (hiển thị ngay trong chi tiết & ghi chú đơn trên app SPOS Mobile)
    // 2. Không làm rỗng allowedPaymentMethods, giữ nguyên trạng thái chờ thanh toán
    // 3. Thời gian giữ đơn predictCancelAt kéo dài 24h, không bị hủy tức thì
    const orderNoteText = (note || '').trim();
    let finalOrderCode = '';
    let finalGrandTotal = totalPayable;

    try {
      const recordUrl = `${TEKO_CARTS_URL}/api/v2/carts/record?terminal=${encodeURIComponent(branchCode)}&terminalId=${terminalId}`;
      const recordRes = await callTeko(recordUrl, {
        method: 'POST',
        token,
        headers: {
          'x-cart-token': currentCartToken
        },
        data: {
          terminalCode: branchCode,
          storeCode: branchCode,
          order: {
            note: orderNoteText,
            terminalCode: branchCode,
            storeCode: branchCode,
            deliveryInfo: {
              name: customerName,
              phone: customerPhone,
              email: customerEmail
            },
            customerInfo: {
              name: customerName,
              phone: customerPhone,
              email: customerEmail
            },
            channelInfo: {
              channelId: 1,
              channelType: 'showroom',
              channelCode: 'pv_showroom',
              terminalCode: branchCode,
              storeCode: branchCode
            }
          },
          payments: []
        }
      });

      if (recordRes.ok && (recordRes.data?.data?.code || recordRes.data?.data?.orderId)) {
        finalOrderCode = String(recordRes.data.data.code || recordRes.data.data.orderId);
        finalGrandTotal = Number(recordRes.data.data.grandTotal) || totalPayable;
      } else {
        console.warn('[SPOS-ORDER] V2 /record không thành công, thử fallback sang V1 checkout:', recordRes.status, recordRes.data);
      }
    } catch (recErr) {
      console.warn('[SPOS-ORDER] Ngoại lệ khi gọi V2 /record:', recErr.message);
    }

    // Fallback nếu V2 /record không trả về mã đơn
    if (!finalOrderCode) {
      const checkoutUrl = `${TEKO_CARTS_URL}/api/v1/cart/checkout?terminal=${encodeURIComponent(branchCode)}&terminalId=${terminalId}&channel=pv_showroom&cartId=${encodeURIComponent(currentCartId)}`;
      const checkoutRes = await callTeko(checkoutUrl, {
        method: 'POST',
        token,
        headers: {
          'x-cart-token': currentCartToken
        },
        data: {
          channelId: 1,
          channelType: 'showroom',
          channelCode: 'pv_showroom',
          terminalCode: branchCode,
          storeCode: branchCode,
          note: orderNoteText,
          customer: {
            name: customerName,
            phone: customerPhone,
            email: customerEmail
          },
          shippingInfo: checkoutShippingInfo
        }
      });

      if (checkoutRes.ok && checkoutRes.data?.result) {
        finalOrderCode = String(checkoutRes.data.result.code || checkoutRes.data.result.orderId || checkoutRes.data.result.orderIdString || '');
        finalGrandTotal = Number(checkoutRes.data.result.grandTotal) || totalPayable;
      } else {
        const errMsg = checkoutRes.data?.error || checkoutRes.data?.message || `Lỗi máy chủ Teko (Mã ${checkoutRes.status})`;
        return {
          ok: false,
          error: `Không thể tạo đơn hàng trên Teko SPOS: ${errMsg}`,
          tokenStatus: 'ERROR'
        };
      }
    }

    if (!finalOrderCode) {
      return {
        ok: false,
        error: 'Teko không trả về mã đơn hàng hợp lệ sau khi lưu đơn.',
        tokenStatus: 'ERROR'
      };
    }

    // Tự động ghi chú vào Teko OMS comments thread nếu người dùng có nhập ghi chú
    if (orderNoteText) {
      try {
        const commentUrl = `https://staff-bff.tekoapis.com/api/v1/orders/${encodeURIComponent(finalOrderCode)}/comments?sellerId=1&channel=pv_showroom`;
        await callTeko(commentUrl, {
          method: 'POST',
          token,
          data: { content: orderNoteText }
        });
      } catch (cErr) {
        console.warn('[SPOS-ORDER] Không thể ghi chú vào Teko OMS comments:', cErr.message);
      }
    }

    const orderData = {
      orderCode: finalOrderCode,
      displayOrderCode: `#${finalOrderCode}`,
      cartToken: currentCartToken,
      paymentMethod: selectedPaymentMethod,
      paymentMethodLabel,
      status: 'PROCESSING',
      statusText: 'Đã lưu trên app SPOS (Chờ thu tiền)',
      customer: {
        name: customerName,
        phone: customerPhone,
        email: customerEmail
      },
      delivery: {
        type: isShowroomPickup ? 'DELIVERY_TYPE_PICKUP' : 'DELIVERY_TYPE_AT_HOME',
        storeCode: branchCode,
        address: checkoutShippingInfo?.fullAddress || fullAddress,
        deliveryMethodName: isShowroomPickup ? 'Giao tại showroom (Miễn phí)' : 'Giao hàng tận nơi'
      },
      items: orderItems,
      pricing: {
        totalOriginal,
        totalPromoDiscount,
        totalManualDiscount,
        totalPayable: finalGrandTotal
      },
      voucherCode: voucherCode || '',
      appliedPromo: payload.appliedPromo || null,
      note: orderNoteText,
      rawNote: note || '',
      branchCode,
      userId,
      tokenStatus: 'VALID',
      tekoSynced: true,
      createdAt: new Date().toISOString()
    };

    const finalPayable = finalGrandTotal;

    const successMessage = `Tạo đơn hàng thành công trên hệ thống SPOS Teko! Mã đơn: #${finalOrderCode}. Hình thức: ${paymentMethodLabel}.`;

    return {
      ok: true,
      orderCode: finalOrderCode,
      displayOrderCode: `#${finalOrderCode}`,
      cartToken: currentCartToken,
      paymentMethod: selectedPaymentMethod,
      paymentMethodLabel,
      orderData,
      tekoSynced: true,
      tokenStatus: 'VALID',
      totalPayable: finalPayable,
      message: successMessage
    };
  } catch (err) {
    console.error('[SPOS-ORDER] Lỗi thực thi:', err);
    return {
      ok: false,
      error: `Lỗi kết nối máy chủ SPOS Teko: ${err.message}`,
      tokenStatus: 'ERROR'
    };
  }
}

/**
 * Hủy đơn hàng trên hệ thống Teko SPOS / Staff BFF
 * @param {string} orderId - Mã đơn hàng Teko 14 số
 * @param {string} reason - Lý do hủy
 * @param {string} token - Token xác thực nhân viên
 */
async function cancelPendingOrder(orderId, reason = 'Huỷ đơn từ hệ thống Web', token = '') {
  if (!orderId) return { ok: false, error: 'Thiếu mã đơn hàng cần huỷ' };
  try {
    const cleanId = String(orderId).replace(/^#/, '').trim();

    let effectiveToken = token;
    if (!effectiveToken && supabase) {
      try {
        const { data } = await supabase.from('site_settings').select('value').like('id', 'quick_export_%').order('updated_at', { ascending: false }).limit(5);
        if (data && data.length > 0) {
          for (const item of data) {
            try {
              const parsed = JSON.parse(item.value);
              if (parsed.tekoToken) {
                const parts = parsed.tekoToken.split('.');
                if (parts.length === 3) {
                  const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
                  if (payload.exp && payload.exp * 1000 > Date.now()) {
                    effectiveToken = parsed.tekoToken;
                    break;
                  }
                }
              }
            } catch (e) {}
          }
        }
      } catch (dbErr) {}
    }

    const cancelUrl = `https://staff-bff.tekoapis.com/api/v2/staff-mobile/orders/${encodeURIComponent(cleanId)}/cancel?sellerId=1&channel=pv_showroom`;
    const res = await callTeko(cancelUrl, {
      method: 'PUT',
      token: effectiveToken,
      data: { reason }
    });
    if (res.ok) {
      return { ok: true, message: `Huỷ đơn hàng #${cleanId} thành công` };
    }
    return { ok: false, error: res.data?.message || `Lỗi huỷ đơn (Mã ${res.status})` };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = {
  createPendingOrder,
  cancelPendingOrder,
  generateOrderCode,
  TEKO_TERMINAL_CONFIG
};
