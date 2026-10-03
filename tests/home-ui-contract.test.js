const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const ejs = require('ejs');

const indexTemplate = fs.readFileSync('views/index.ejs', 'utf8');
const promoTemplate = fs.readFileSync('views/partials/_featured-promos.ejs', 'utf8');

test('home templates compile and preserve interactive contracts', () => {
  assert.doesNotThrow(() => ejs.compile(indexTemplate, { filename: 'views/index.ejs' }));
  assert.doesNotThrow(() => ejs.compile(promoTemplate, { filename: 'views/partials/_featured-promos.ejs' }));

  for (const id of [
    'searchForm', 'skuSearch', 'promoGroupSelect', 'promoSearchInput',
    'promoSortSelect', 'promoExpiringOnly', 'promo-list-content',
    'promo-list-viewport', 'loading-spinner', 'promoPrevBtn', 'promoNextBtn'
  ]) {
    assert.match(indexTemplate, new RegExp(`id=["']${id}["']`));
  }

  assert.match(indexTemplate, /\/api\/featured-promos/);
  assert.match(promoTemplate, /class="promo-item/);
  assert.match(promoTemplate, /data-expiry-level=/);
  assert.match(promoTemplate, /currentRole !== 'manager'/);
});
