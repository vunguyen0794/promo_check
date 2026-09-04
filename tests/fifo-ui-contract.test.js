const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const ejs = require('ejs');

const fifoTemplate = fs.readFileSync('views/fifo-checking.ejs', 'utf8');

test('FIFO template compiles and preserves operating controls', () => {
  assert.doesNotThrow(() => ejs.compile(fifoTemplate, { filename: 'views/fifo-checking.ejs' }));

  for (const id of [
    'masterInput', 'btnScan', 'btnSearchSku', 'btnReset', 'filterGift',
    'filterCheckedOut', 'toggleWrap', 'filterSubcategory', 'filterBrand',
    'filterLocation', 'filterBinZone', 'resultsContainer', 'paginationContainer',
    'rankInfoCard', 'historyModal', 'scanModal'
  ]) {
    assert.match(fifoTemplate, new RegExp(`id=["']${id}["']`));
  }

  assert.match(fifoTemplate, /\/api\/fifo\/filters/);
  assert.match(fifoTemplate, /\/api\/fifo\/serials/);
  assert.match(fifoTemplate, /\/api\/fifo\/log/);
  assert.match(fifoTemplate, /\/api\/fifo\/history/);
  assert.match(fifoTemplate, /class="container fifo-workspace"/);
  assert.match(fifoTemplate, /class="dash-card fifo-commandbar"/);
  assert.match(fifoTemplate, /class="fifo-work-surface"/);
});
