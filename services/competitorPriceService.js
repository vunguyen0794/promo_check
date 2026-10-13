const axios = require('axios');

/**
 * Service to scrape / fetch competitor pricing for CellphoneS (CPS), Thế Giới Di Động (TGDD), and FPT Shop (FPT)
 */

const DEFAULT_TIMEOUT = 5000;
const USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

/**
 * Clean verbose product names from Phong Vũ / Teko into concise search keywords
 */
function cleanSearchKeyword(productName, brand = '') {
  if (!productName) return '';
  let str = productName.trim();

  // 1. Remove condition notes (e.g. - Đã sử dụng, - Hàng cũ, etc.)
  str = str.replace(/-\s*(Đã sử dụng|Hàng cũ|Like new|New|Trưng bày|Chính hãng|VN\/A)[^()]*/gi, ' ');

  // 2. Remove color suffixes (e.g. - Đen, - Bạc, etc.)
  str = str.replace(/-\s*(Đen|Trắng|Bạc|Xám|Hồng|Vàng|Xanh|Titan|Gold|Silver|Space Gray|Midnight|Starlight|Black|White|Grey|Blue)[^()]*/gi, ' ');

  // 3. Remove internal part numbers in parentheses at the end: (Z18P00045), (683L9AA), (W2220A)
  str = str.replace(/\([A-Z0-9\-_]{5,}\)/gi, ' ');

  // 4. Extract capacity / storage if present
  const storageMatch = str.match(/\b(128GB|256GB|512GB|1TB|2TB|64GB|32GB|16GB)\b/i);
  const storage = storageMatch ? storageMatch[1].toUpperCase() : '';

  // 5. Remove verbose technical specs in parentheses (e.g. (i5-13500H/16GB/512GB/15.6 FHD OLED/Win 11))
  str = str.replace(/\([^)]*(\/|Intel|Core|SSD|HDD|FHD|OLED|GPU|CPU|Win 11|DOS)[^)]*\)/gi, ' ');

  // 6. Remove generic department prefixes
  str = str.replace(/^(Máy tính xách tay\/\s*Laptop|Máy tính để bàn\/\s*PC|Máy tính xách tay|Máy tính để bàn|Máy tính|Điện thoại di động|Điện thoại|Laptop|Màn hình máy tính|Màn hình|Tai nghe|Bàn phím|Chuột|Loa vi tính|Loa|Tủ lạnh|Máy giặt|Máy chiếu)\s*/i, ' ');
  str = str.replace(/\((Xám|Đen|Trắng|Bạc|Hồng|Vàng|Xanh|Titan|Gold|Silver|Black|White|Grey|Blue)\)/gi, ' ');

  // 7. Simplify complex manufacturer codes (e.g. A1505VA-L1114W -> A1505VA)
  str = str.replace(/([A-Z0-9]{4,8})-[A-Z0-9]{4,}/g, '$1');

  // 8. Clean punctuation & extra whitespace
  str = str.replace(/[,;]/g, ' ').replace(/\s+/g, ' ').trim();

  // 9. Ensure brand is included if known
  if (brand && brand.toLowerCase() !== 'phong vũ' && !str.toLowerCase().includes(brand.toLowerCase())) {
    str = `${brand} ${str}`;
  }

  // 10. Re-append storage if it got removed and is not present
  if (storage && !str.toUpperCase().includes(storage)) {
    str = `${str} ${storage}`;
  }

  return str.trim();
}

/**
 * Score candidate match vs search keyword and our price
 */
function scoreCandidate(candidate, targetKeyword, targetPrice) {
  const cName = (candidate.name || '').toLowerCase();
  const tKw = (targetKeyword || '').toLowerCase();
  const cPrice = Number(candidate.price || 0);
  const tPrice = Number(targetPrice || 0);

  // Negative check for accessories unless target itself is an accessory
  const isAccessoryWord = /dán|ốp lưng|bao da|cường lực|túi chống sốc|skin|cáp sạc/.test(cName);
  const targetIsAccessory = /dán|ốp|bao da|cường lực|túi|cáp/.test(tKw);
  if (isAccessoryWord && !targetIsAccessory) return -1;

  // Price boundary check for high-value items
  if (tPrice > 3000000) {
    if (cPrice > 0 && cPrice < tPrice * 0.4) return -1; // Way too cheap, likely an accessory
    if (cPrice > tPrice * 2.5) return -1; // Way too expensive
  }

  // Token match score
  const tokens = tKw.split(/\s+/).filter(t => t.length > 1);
  if (tokens.length === 0) return 0;

  let matched = 0;
  for (const token of tokens) {
    if (cName.includes(token)) matched++;
  }
  let score = (matched / tokens.length) * 100;

  // Price proximity bonus
  if (tPrice > 0 && cPrice > 0) {
    const diffRatio = Math.abs(cPrice - tPrice) / tPrice;
    if (diffRatio < 0.25) score += 20 * (1 - diffRatio);
  }

  // Stock availability bonus
  if (candidate.inStock !== false && cPrice > 0) score += 10;

  return score;
}

function pickBest(candidates, targetKeyword, targetPrice) {
  if (!Array.isArray(candidates) || candidates.length === 0) return null;
  let best = null;
  let maxScore = 0; // must have score > 0 to match

  for (const c of candidates) {
    const score = scoreCandidate(c, targetKeyword, targetPrice);
    if (score > maxScore) {
      maxScore = score;
      best = { ...c, matchScore: Math.round(score) };
    }
  }
  return best;
}

/**
 * 1. CellphoneS (CPS) Scraper
 */
async function searchCPS(keyword, targetPrice) {
  const query = `query advanced_search {
    advanced_search(user_query: { terms: ${JSON.stringify(keyword)}, province: 30 }, page: 1) {
      products {
        name
        price
        special_price
        url_path
        thumbnail
        category_objects { name }
      }
    }
  }`;

  try {
    const res = await axios.post('https://api.cellphones.com.vn/graphql-search/v2/graphql/query', { query }, {
      headers: {
        'user-agent': USER_AGENT,
        'x-client-type': 'web',
        'content-type': 'application/json',
        'origin': 'https://cellphones.com.vn',
        'referer': 'https://cellphones.com.vn/'
      },
      timeout: DEFAULT_TIMEOUT
    });

    const items = (res.data.data?.advanced_search?.products || []).map(p => {
      const price = p.special_price || p.price || 0;
      const originalPrice = p.price || 0;
      return {
        retailer: 'CPS',
        retailerName: 'CellphoneS',
        name: p.name,
        price,
        originalPrice,
        link: p.url_path ? `https://cellphones.com.vn/${p.url_path}` : 'https://cellphones.com.vn',
        inStock: price > 0,
        categories: (p.category_objects || []).map(c => c.name)
      };
    });

    return pickBest(items, keyword, targetPrice);
  } catch (err) {
    console.warn('[Competitor] CPS scrape warning:', err.message);
    return null;
  }
}

/**
 * 2. Thế Giới Di Động (TGDD) Scraper
 */
async function searchTGDD(keyword, targetPrice) {
  try {
    const res = await axios.post('https://api.thegioididong.com/gw/bus-tgdd-tmdt/api/Search/GetProductSearchV2', {
      pageIndex: 0,
      pageSize: 10,
      provinceId: 1027,
      sellerId: -1,
      keyWord: keyword,
      filters: [
        { filterId: -1, filterTypeId: 7, sortName: '', attrbuteCode: '', url: '' },
        { filterId: 1, filterTypeId: 6, sortName: 'RELATED_PRODUCTS', url: '' }
      ]
    }, {
      headers: {
        'user-agent': USER_AGENT,
        'siteid': '1',
        'os': 'WebTGDD',
        'platform': '1',
        'content-type': 'application/json',
        'referer': 'https://www.thegioididong.com/'
      },
      timeout: DEFAULT_TIMEOUT
    });

    const items = (res.data.data?.products || []).map(p => {
      const pr = p.productPrices?.[0];
      const price = pr?.price || 0;
      const originalPrice = pr?.sysPrice || 0;
      const url = p.url || '';
      const fullUrl = url.startsWith('http') ? url : `https://www.thegioididong.com${url.startsWith('/') ? '' : '/'}${url}`;

      return {
        retailer: 'TGDD',
        retailerName: 'Thế Giới Di Động',
        name: p.name,
        price,
        originalPrice,
        link: url ? fullUrl : 'https://www.thegioididong.com',
        inStock: pr?.isCanBuy !== false && price > 0
      };
    });

    return pickBest(items, keyword, targetPrice);
  } catch (err) {
    console.warn('[Competitor] TGDD scrape warning:', err.message);
    return null;
  }
}

/**
 * 3. FPT Shop (FPT) Scraper
 */
async function searchFPT(keyword, targetPrice) {
  try {
    const res = await axios.get(`https://fptshop.com.vn/tim-kiem?s=${encodeURIComponent(keyword)}`, {
      headers: {
        'user-agent': USER_AGENT,
        'referer': 'https://fptshop.com.vn/'
      },
      timeout: 6000
    });

    const html = res.data;
    const items = [];
    const cardRegex = /<a[^>]*href="(\/(?:dien-thoai|may-tinh-xach-tay|laptop|may-tinh-bang|dong-ho|am-thanh|phu-kien)[^"]*)"[^>]*>([\s\S]*?)<\/a>/gi;
    let match;

    while ((match = cardRegex.exec(html)) !== null) {
      const link = `https://fptshop.com.vn${match[1]}`;
      const cardEndIdx = html.indexOf('</div>', match.index + match[0].length + 1500);
      const cardChunk = html.substring(match.index, cardEndIdx > -1 ? cardEndIdx : match.index + 2000);
      const prices = [...cardChunk.matchAll(/([0-9]{1,3}(?:\.[0-9]{3})+)(?:\s*(?:₫|đ))/g)].map(m => parseInt(m[1].replace(/\./g, '')));
      const titleMatch = match[0].match(/aria-label="([^"]+)"/i) || match[0].match(/title="([^"]+)"/i) || cardChunk.match(/<h3[^>]*>([^<]+)<\/h3>/i);
      const title = titleMatch ? titleMatch[1].trim() : '';

      if (title && prices.length > 0) {
        const promoPrice = prices.length >= 2 ? Math.min(...prices.slice(0, 2)) : prices[0];
        const origPrice = Math.max(...prices);
        if (!items.some(i => i.link === link)) {
          items.push({
            retailer: 'FPT',
            retailerName: 'FPT Shop',
            name: title,
            price: promoPrice,
            originalPrice: origPrice,
            link,
            inStock: promoPrice > 0
          });
        }
      }
    }

    return pickBest(items, keyword, targetPrice);
  } catch (err) {
    console.warn('[Competitor] FPT scrape warning:', err.message);
    return null;
  }
}

/**
 * Fetch all 3 competitors simultaneously, format and sort by price Low -> High
 */
async function fetchAllCompetitors({ sku, productName, brand, targetPrice }) {
  const keyword = cleanSearchKeyword(productName, brand);
  const ourPrice = Number(targetPrice || 0);

  const [cpsRes, tgddRes, fptRes] = await Promise.allSettled([
    searchCPS(keyword, ourPrice),
    searchTGDD(keyword, ourPrice),
    searchFPT(keyword, ourPrice)
  ]);

  const defaultItem = (code, name) => ({
    retailer: code,
    retailerName: name,
    name: 'Không tìm thấy dữ liệu',
    price: 0,
    originalPrice: 0,
    link: code === 'CPS' ? 'https://cellphones.com.vn' : code === 'TGDD' ? 'https://www.thegioididong.com' : 'https://fptshop.com.vn',
    inStock: false,
    diff: 0,
    found: false
  });

  const cps = (cpsRes.status === 'fulfilled' && cpsRes.value) ? { ...cpsRes.value, found: true } : defaultItem('CPS', 'CellphoneS');
  const tgdd = (tgddRes.status === 'fulfilled' && tgddRes.value) ? { ...tgddRes.value, found: true } : defaultItem('TGDD', 'Thế Giới Di Động');
  const fpt = (fptRes.status === 'fulfilled' && fptRes.value) ? { ...fptRes.value, found: true } : defaultItem('FPT', 'FPT Shop');

  // Calculate difference vs ourPrice
  [cps, tgdd, fpt].forEach(item => {
    if (item.found && item.price > 0 && ourPrice > 0) {
      item.diff = item.price - ourPrice;
    } else {
      item.diff = 0;
    }
  });

  const list = [cps, tgdd, fpt];

  // Sắp xếp 3 đối thủ theo giá từ Thấp đến Cao (các bên có giá > 0 lên trước, sau đó tới bên 0đ/không tìm thấy)
  const sorted = [...list].sort((a, b) => {
    if (a.price > 0 && b.price > 0) return a.price - b.price;
    if (a.price > 0) return -1;
    if (b.price > 0) return 1;
    return 0;
  });

  // Gắn cờ Lowest Price cho bên có giá > 0 thấp nhất
  const validPriced = sorted.filter(x => x.price > 0);
  if (validPriced.length > 0) {
    validPriced[0].isLowest = true;
  }

  return {
    sku,
    productName,
    keyword,
    ourPrice,
    competitors: {
      CPS: cps,
      TGDD: tgdd,
      FPT: fpt
    },
    sorted, // Mảng 3 đối thủ xếp từ Thấp -> Cao
    updatedAt: new Date().toISOString()
  };
}

module.exports = {
  cleanSearchKeyword,
  scoreCandidate,
  pickBest,
  searchCPS,
  searchTGDD,
  searchFPT,
  fetchAllCompetitors
};
