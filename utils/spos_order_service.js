/**
 * utils/spos_order_service.js
 * Dịch vụ tích hợp kết nối SPOS / Teko Carts API cho tính năng "Tạo Đơn Hàng Nhanh"
 */

const TEKO_CARTS_URL = 'https://carts.tekoapis.com';
const TEKO_STAFF_BFF_URL = 'https://staff-bff.tekoapis.com';

/**
 * Chuẩn hoá token
 */
function normalizeToken(token) {
  if (!token) return '';
  const clean = token.trim();
  return clean.toLowerCase().startsWith('bearer ') ? clean : `Bearer ${clean}`;
}

/**
 * Lấy số thứ tự terminalId của máy POS quầy tại chi nhánh (chuẩn Teko SPOS: luôn là 1)
 */
function extractTerminalId(branchCode) {
  // Trên Teko Carts API, mỗi showroom được định danh bởi terminal=CPxx, còn terminalId luôn là 1 (máy POS 1 tại showroom)
  // Nếu truyền terminalId theo số của mã showroom (ví dụ CP74 -> 74) Teko sẽ báo 404109 "Một số sản phẩm trong yêu cầu của bạn không tồn tại"
  return 1;
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

  const terminalId = extractTerminalId(branchCode);
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

    // 4. Thêm sản phẩm vào giỏ hàng
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
            products: orderItems.map(it => ({
              sku: String(it.sku),
              quantity: Number(it.quantity) || 1
            }))
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
    const siteId = cleanAddress.siteId || (branchCode.toUpperCase() === 'CP74' ? 53019 : 53019);
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

    // 7. Gán phương thức thanh toán đã chọn (COD / BANK_TRANSFER / CARD / CASH)
    let tekoMethodCode = 'COD';
    if (selectedPaymentMethod === 'BANK_TRANSFER') {
      tekoMethodCode = 'BANK_TRANSFER';
    } else if (selectedPaymentMethod === 'CARD') {
      tekoMethodCode = 'VNPAY_SPOS_CARD';
    } else if (selectedPaymentMethod === 'CASH') {
      tekoMethodCode = 'CASH';
    } else {
      tekoMethodCode = 'COD';
    }

    try {
      const payUrl = `${TEKO_CARTS_URL}/api/v1/cart/apply-payment-method?terminal=${encodeURIComponent(branchCode)}&terminalId=${terminalId}&channel=pv_showroom&cartId=${encodeURIComponent(currentCartId)}`;
      const pmRes = await callTeko(payUrl, {
        method: 'PUT',
        token,
        headers: {
          'x-cart-token': currentCartToken
        },
        data: {
          paymentMethodCode: tekoMethodCode
        }
      });
      updateTokenFromRes(pmRes);
    } catch (e) {
      console.warn('[SPOS-ORDER] Không thể apply-payment-method:', e.message);
    }

    // 8. Thực hiện Checkout Đơn hàng chính thức trên Teko OMS
    // Endpoint: POST /api/v1/cart/checkout
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
        customer: {
          name: customerName,
          phone: customerPhone,
          email: customerEmail
        },
        shippingInfo: checkoutShippingInfo
      }
    });

    if (!checkoutRes.ok || !checkoutRes.data?.result) {
      console.error('[SPOS-ORDER] Teko Checkout thất bại:', checkoutRes.status, checkoutRes.data);
      const errMsg = checkoutRes.data?.error || checkoutRes.data?.message || `Lỗi máy chủ Teko (Mã ${checkoutRes.status})`;
      return {
        ok: false,
        error: `Không thể tạo đơn hàng trên Teko SPOS: ${errMsg}`,
        tokenStatus: 'ERROR'
      };
    }

    const orderRes = checkoutRes.data.result;
    const finalOrderCode = String(orderRes.code || orderRes.orderId || orderRes.orderIdString || '');
    if (!finalOrderCode) {
      return {
        ok: false,
        error: 'Teko không trả về mã đơn hàng hợp lệ sau khi checkout.',
        tokenStatus: 'ERROR'
      };
    }

    // Tự động ghi chú Phương thức thanh toán vào Teko OMS để hiển thị rõ trong Ghi chú trên SPOS Mobile & Web ERP
    try {
      const commentUrl = `https://staff-bff.tekoapis.com/api/v1/orders/${encodeURIComponent(finalOrderCode)}/comments?sellerId=1&channel=pv_showroom`;
      const commentText = `[PTTT: ${paymentMethodLabel}]${note ? ' - ' + note.trim() : ''}`;
      await callTeko(commentUrl, {
        method: 'POST',
        token,
        data: { content: commentText }
      });
    } catch (cErr) {
      console.warn('[SPOS-ORDER] Không thể tự động ghi chú PTTT vào Teko OMS:', cErr.message);
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
        totalPayable: Number(orderRes.grandTotal) || totalPayable
      },
      voucherCode: voucherCode || '',
      note: note || '',
      branchCode,
      userId,
      tokenStatus: 'VALID',
      tekoSynced: true,
      createdAt: new Date().toISOString()
    };

    const finalPayable = Number(orderRes.grandTotal) || totalPayable;

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
                effectiveToken = parsed.tekoToken;
                break;
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
  generateOrderCode
};
