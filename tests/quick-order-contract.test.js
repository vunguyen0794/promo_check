const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const ejs = require('ejs');

test('Quick Order view and service contract tests', async (t) => {
  await t.test('quick-order.ejs compiles properly with partials', () => {
    const filePath = path.join(__dirname, '..', 'views', 'quick-order.ejs');
    assert.ok(fs.existsSync(filePath), 'quick-order.ejs exists');

    const content = fs.readFileSync(filePath, 'utf8');
    assert.match(content, /Tạo Đơn Hàng Nhanh/i);
    assert.match(content, /skuSearchInput/);
    assert.match(content, /custName/);
    assert.match(content, /custPhone/);
    assert.match(content, /btnSubmitOrder/);
    assert.match(content, /orderSuccessModal/);
    assert.match(content, /payOptCash/);
    assert.match(content, /payOptCard/);
    assert.match(content, /payOptBank/);
    assert.match(content, /modalPaymentMethod/);

    // Test EJS compilation
    const html = ejs.render(content, {
      title: 'Tạo Đơn Hàng Nhanh - SPOS Web',
      currentPage: 'quick-order',
      user: { id: 'u1', full_name: 'Test Staff', email: 'test@phongvu.vn', role: 'staff', branch_code: 'CP01' },
      branchCode: 'CP01',
      branchInfo: {
        name: 'PHONG VŨ (Chi nhánh 264 NTMK)',
        address: '264A-264B-264C Nguyễn Thị Minh Khai, Phường Võ Thị Sáu, Quận 3, Thành phố Hồ Chí Minh'
      },
      branches: {},
      globalTickerText: '',
      unreadCount: 0,
      locals: { user: { role: 'staff', branch_code: 'CP01' }, isBranchEventActive: false, onlineUserCount: 1 },
      filename: filePath
    });

    assert.ok(html.length > 5000, 'HTML output is non-trivial');
    assert.match(html, /Tạo Đơn Hàng Nhanh/i);
    assert.match(html, /CP01/);
    assert.match(html, /Tiền mặt/);
    assert.match(html, /Quẹt thẻ/);
    assert.match(html, /Chuyển khoản/);
  });

  await t.test('spos_order_service module exports required API functions and generates valid order codes with payment methods', async () => {
    const sos = require('../utils/spos_order_service');
    assert.equal(typeof sos.createPendingOrder, 'function');
    assert.equal(typeof sos.generateOrderCode, 'function');

    const code = sos.generateOrderCode();
    assert.match(code, /^\d{14}$/, 'Order code should match exactly 14 digits (YYMMDD3XXXXXX0)');

    // Test createPendingOrder calculation logic with CASH
    const res = await sos.createPendingOrder({
      customer: { name: 'Nguyễn Văn Test', phone: '0901234567' },
      delivery: { type: 'SHOWROOM' },
      items: [
        { sku: 'TEST01', name: 'Màn hình Gaming', quantity: 2, listPrice: 5000000, promoPrice: 4500000, discount: 100000 }
      ],
      paymentMethod: 'CASH',
      branchCode: 'CP01',
      allowOfflineMock: true
    });

    assert.equal(res.ok, true);
    assert.match(res.orderCode, /^\d{14}$/);
    assert.equal(res.paymentMethod, 'CASH');
    assert.equal(res.paymentMethodLabel, 'Tiền mặt');
    // (4500000 - 100000) * 2 = 8800000
    assert.equal(res.totalPayable, 8800000);
    assert.equal(res.orderData.pricing.totalOriginal, 10000000);

    // Test with CARD and BANK_TRANSFER
    const resCard = await sos.createPendingOrder({
      customer: { name: 'Khách quẹt thẻ', phone: '0988888888' },
      items: [{ sku: 'TEST02', name: 'Bàn phím cơ', quantity: 1, listPrice: 1500000 }],
      paymentMethod: 'CARD',
      allowOfflineMock: true
    });
    assert.equal(resCard.ok, true);
    assert.equal(resCard.paymentMethod, 'CARD');
    assert.equal(resCard.paymentMethodLabel, 'Quẹt thẻ');

    const resBank = await sos.createPendingOrder({
      customer: { name: 'Khách chuyển khoản', phone: '0977777777' },
      items: [{ sku: 'TEST03', name: 'Chuột gaming', quantity: 1, listPrice: 800000 }],
      paymentMethod: 'BANK_TRANSFER',
      allowOfflineMock: true
    });
    assert.equal(resBank.ok, true);
    assert.equal(resBank.paymentMethod, 'BANK_TRANSFER');
    assert.equal(resBank.paymentMethodLabel, 'Chuyển khoản');
  });
});
