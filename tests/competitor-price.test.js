const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const ejs = require('ejs');
const { cleanSearchKeyword, scoreCandidate } = require('../services/competitorPriceService');

test('competitorPriceService - cleanSearchKeyword tests', () => {
  // Test MacBook Air
  const rawMac = 'Máy tính Apple MacBook Air 15.3 inch (M2/8CPU/10GPU/8GB/256GB) - Bạc (Z18P00045) - Đã sử dụng';
  const cleanedMac = cleanSearchKeyword(rawMac, 'Apple');
  assert.ok(cleanedMac.includes('MacBook Air'), 'Should contain MacBook Air');
  assert.ok(!cleanedMac.includes('Đã sử dụng'), 'Should not contain Đã sử dụng');
  assert.ok(!cleanedMac.includes('Z18P00045'), 'Should not contain internal part code');

  // Test ASUS Vivobook
  const rawAsus = 'Laptop ASUS Vivobook 15 OLED A1505VA-L1114W (i5-13500H/16GB/512GB/15.6 FHD OLED/Win 11)';
  const cleanedAsus = cleanSearchKeyword(rawAsus, 'Asus');
  assert.ok(cleanedAsus.includes('ASUS') || cleanedAsus.includes('Asus'), 'Should contain ASUS');
  assert.ok(cleanedAsus.includes('A1505VA'), 'Should contain A1505VA');
  assert.ok(!cleanedAsus.includes('i5-13500H'), 'Should strip complex specs');

  // Test iPhone
  const rawPhone = 'Điện thoại iPhone 16 128GB - Đen';
  const cleanedPhone = cleanSearchKeyword(rawPhone, 'Apple');
  assert.ok(cleanedPhone.includes('iPhone 16 128GB'), 'Should contain iPhone 16 128GB');
  assert.ok(!cleanedPhone.includes('Điện thoại'), 'Should strip prefix');
});

test('competitorPriceService - scoreCandidate accessories filter', () => {
  // Candidate is an accessory, target is a laptop
  const accessoryCandidate = { name: 'Miếng dán màn hình MacBook Air 15 inch', price: 350000 };
  const score = scoreCandidate(accessoryCandidate, 'MacBook Air 15 M2', 26000000);
  assert.equal(score, -1, 'Should reject accessory candidate for laptop');

  // Candidate is the actual laptop
  const laptopCandidate = { name: 'MacBook Air 15 inch M2 2023 8GB 256GB', price: 24990000, inStock: true };
  const laptopScore = scoreCandidate(laptopCandidate, 'MacBook Air 15 M2', 26000000);
  assert.ok(laptopScore > 50, 'Should score high for actual laptop');
});

test('views/promotion.ejs - contains competitor comparison section contracts', () => {
  const tpl = fs.readFileSync('views/promotion.ejs', 'utf8');
  assert.ok(tpl.includes('id="competitorCompareSection"'), 'Should contain competitorCompareSection');
  assert.ok(tpl.includes('id="competitorGrid"'), 'Should contain competitorGrid');
  assert.ok(tpl.includes('id="btnRefreshCompetitors"'), 'Should contain btnRefreshCompetitors');
  assert.ok(tpl.includes('api/competitor-prices'), 'Should call /api/competitor-prices');

  // Compile check
  assert.doesNotThrow(() => {
    ejs.compile(tpl, { filename: 'views/promotion.ejs' });
  }, 'promotion.ejs should compile with EJS without errors');
});
