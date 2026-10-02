const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const ejs = require('ejs');

test('Quick Export view and service contract tests', async (t) => {
  await t.test('quick-export.ejs compiles properly with partials', () => {
    const filePath = path.join(__dirname, '..', 'views', 'quick-export.ejs');
    assert.ok(fs.existsSync(filePath), 'quick-export.ejs exists');

    const content = fs.readFileSync(filePath, 'utf8');
    assert.match(content, /Xuất Kho Nhanh/i);
    assert.match(content, /txtDocumentId/);
    assert.match(content, /txtSerialScan/);
    assert.match(content, /handleSearchOrder/);
    assert.match(content, /handleScanSerialSubmit/);
    assert.match(content, /handleConfirmExport/);
    assert.match(content, /configModal/);

    // Test EJS compilation
    const html = ejs.render(content, {
      title: '⚡ Xuất kho nhanh',
      currentPage: 'quick-export',
      user: { id: 'u1', full_name: 'Test Staff', email: 'test@phongvu.vn', role: 'staff', branch_code: 'CP01' },
      globalTickerText: '',
      unreadCount: 0,
      locals: { user: { role: 'staff', branch_code: 'CP01' }, isBranchEventActive: false, onlineUserCount: 1 },
      filename: filePath
    });

    assert.ok(html.length > 5000, 'HTML output is non-trivial');
    assert.match(html, /Xuất Kho Nhanh/i);
  });

  await t.test('quick_export_service module exports required API functions', () => {
    const qe = require('../utils/quick_export_service');
    assert.equal(typeof qe.getUserSites, 'function');
    assert.equal(typeof qe.getBinByBinName, 'function');
    assert.equal(typeof qe.loadExportRequest, 'function');
    assert.equal(typeof qe.getSerialTracking, 'function');
    assert.equal(typeof qe.moveBin, 'function');
    assert.equal(typeof qe.confirmPacking, 'function');
    assert.equal(typeof qe.normalizeToken, 'function');

    // Test token normalization
    assert.equal(qe.normalizeToken('ey123'), 'Bearer ey123');
    assert.equal(qe.normalizeToken('Bearer ey456'), 'Bearer ey456');
    assert.equal(qe.normalizeToken(''), '');
  });
});
