const axios = require('axios');

/**
 * Service to scrape / fetch competitor pricing for CellphoneS (CPS), Thế Giới Di Động (TGDD), and FPT Shop (FPT)
 */

const DEFAULT_TIMEOUT = 5000;
const USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

const SERIES_CONFLICTS = [
  // Asus laptops
  ['rog strix', 'rog zephyrus', 'rog flow', 'rog', 'tuf', 'zenbook', 'vivobook', 'expertbook', 'proart'],
  // Lenovo laptops
  ['thinkpad', 'ideapad', 'legion', 'loq', 'yoga', 'thinkbook'],
  // Dell laptops
  ['alienware', 'xps', 'inspiron', 'vostro', 'latitude', 'precision', 'g15', 'g16'],
  // HP laptops
  ['omen', 'victus', 'spectre', 'envy', 'pavilion', 'probook', 'elitebook'],
  // Acer laptops
  ['predator', 'nitro', 'aspire', 'swift', 'spin'],
  // Apple devices
  ['macbook air', 'macbook pro', 'macbook neo', 'macbook', 'ipad', 'iphone', 'imac', 'mac mini', 'mac studio', 'watch'],
  // Samsung
  ['galaxy s', 'galaxy z', 'galaxy a', 'galaxy m', 'galaxy tab']
];

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
  // Also remove any Vietnamese color or descriptive words after hyphen (words without digits)
  str = str.replace(/-\s*[A-Za-zÀ-ỹ\s]{2,}(?=\s*(\(|$|\[|-))/g, ' ');

  // 3. Extract capacity / storage if present before removing parens
  const storageMatch = str.match(/\b(128GB|256GB|512GB|1TB|2TB|64GB|32GB|16GB)\b/i);
  const storage = storageMatch ? storageMatch[1].toUpperCase() : '';

  // 4. Extract Apple / Intel / AMD chips if present in parentheses
  const chipMatch = str.match(/\((?:[^)]*\b)?(M[1-5](?:\s*Pro|\s*Max)?|Core Ultra\s*\d|Ryzen\s*[3579]\s*[A-Z0-9]+|i[3579]-[A-Z0-9]+)\b[^)]*\)/i);
  const chip = chipMatch ? chipMatch[1].trim() : '';

  // 5. Remove fractional inches (15.3 inch -> 15 inch)
  str = str.replace(/(\d+)\.\d+\s*inch/gi, '$1 inch');

  // 6. Remove ALL content in parentheses or brackets (specs, CPU, colors, internal part numbers)
  str = str.replace(/\([^)]*\)/g, ' ');
  str = str.replace(/\[[^\]]*\]/g, ' ');

  // 7. Remove generic department prefixes
  str = str.replace(/^(Máy tính xách tay\/\s*Laptop|Máy tính để bàn\/\s*PC|Máy tính xách tay|Máy tính để bàn|Máy tính|Điện thoại di động|Điện thoại|Laptop|Màn hình máy tính|Màn hình|Tai nghe|Bàn phím|Chuột|Loa vi tính|Loa|Tủ lạnh|Máy giặt|Máy chiếu)\s*/i, ' ');

  // 8. Clean punctuation & extra whitespace
  str = str.replace(/[,;]/g, ' ').replace(/\s+/g, ' ').trim();

  // 9. Brand logic
  const bLower = (brand || '').toLowerCase().trim();
  const isApple = bLower === 'apple' || str.toLowerCase().includes('macbook') || str.toLowerCase().includes('iphone') || str.toLowerCase().includes('ipad');

  if (isApple) {
    // For Apple, avoid adding "Apple" if already starts with MacBook / iPad / iPhone
    str = str.replace(/^Apple\s+/i, '');
  } else if (brand && bLower !== 'phong vũ' && !str.toLowerCase().includes(bLower)) {
    str = `${brand} ${str}`;
  }

  // 10. Re-append chip only for Apple or when no specific model codes exist
  const existingCodes = extractModelCodes(str);
  if (chip && (isApple || existingCodes.length === 0) && !str.toLowerCase().includes(chip.toLowerCase())) {
    str = `${str} ${chip}`;
  }

  // 11. Re-append storage if extracted and not already in string
  if (storage && !str.toUpperCase().includes(storage)) {
    str = `${str} ${storage}`;
  }

  return str.replace(/\s+/g, ' ').trim();
}

/**
 * Extract alphanumeric model codes (e.g. g614ph, ts118w, ux3405ca, 13iwc11, 83ue000uvn)
 */
function extractModelCodes(text) {
  const matches = (text || '').match(/\b[A-Za-z0-9]*[0-9]+[A-Za-z0-9]*\b/g) || [];
  return matches
    .map(m => m.toLowerCase().replace(/[^a-z0-9]/g, ''))
    .filter(m => m.length >= 4 && /[a-z]/.test(m) && /[0-9]/.test(m));
}

/**
 * Score candidate match vs search keyword and our price
 */
function scoreCandidate(candidate, targetKeyword, targetPrice, originalName = '') {
  const cName = (candidate.name || '').toLowerCase();
  const tKw = (targetKeyword || '').toLowerCase();
  const oName = (originalName || targetKeyword || '').toLowerCase();
  const cPrice = Number(candidate.price || 0);
  const tPrice = Number(targetPrice || 0);

  // 1. Accessory rejection unless target itself is an accessory
  const isAccessoryWord = /dán|ốp lưng|bao da|cường lực|túi chống sốc|skin|cáp sạc|củ sạc|dây đeo/.test(cName);
  const targetIsAccessory = /dán|ốp|bao da|cường lực|túi|cáp|củ sạc|dây đeo/.test(tKw);
  if (isAccessoryWord && !targetIsAccessory) return -1;

  // 2. Price boundary check
  if (tPrice > 3000000) {
    if (cPrice > 0 && cPrice < tPrice * 0.45) return -1; // Way too cheap, likely accessory
    if (cPrice > tPrice * 2.2) return -1; // Way too expensive
  }

  // 3. Series Conflict Rejection (e.g. target is ROG, candidate is ZenBook or Vivobook)
  for (const group of SERIES_CONFLICTS) {
    let targetSeries = null;
    for (const item of group) {
      if (oName.includes(item) || tKw.includes(item)) {
        targetSeries = item;
        break;
      }
    }
    if (targetSeries) {
      for (const item of group) {
        if (item !== targetSeries && cName.includes(item)) {
          // Exceptions where one is substring of another (e.g. "rog" vs "rog strix")
          if (targetSeries.includes(item) || item.includes(targetSeries)) continue;
          return -1; // Series conflict -> reject!
        }
      }
    }
  }

  // 3b. Phone & Tablet Variant Conflict Rejection (iPhone Pro Max vs Pro vs Plus, Galaxy Ultra vs Plus vs FE)
  if (oName.includes("iphone") || cName.includes("iphone") || tKw.includes("iphone")) {
    const tHasMax = /\bmax\b/.test(oName) || /\bmax\b/.test(tKw);
    const cHasMax = /\bmax\b/.test(cName);
    if (tHasMax !== cHasMax) return -1;

    const tHasPro = /\bpro\b/.test(oName) || /\bpro\b/.test(tKw);
    const cHasPro = /\bpro\b/.test(cName);
    if (tHasPro !== cHasPro) return -1;

    const tHasPlus = /\bplus\b/.test(oName) || /\bplus\b/.test(tKw);
    const cHasPlus = /\bplus\b/.test(cName);
    if (tHasPlus !== cHasPlus) return -1;

    const tHasMini = /\bmini\b/.test(oName) || /\bmini\b/.test(tKw);
    const cHasMini = /\bmini\b/.test(cName);
    if (tHasMini !== cHasMini) return -1;
  }

  if (/galaxy\s*[sz]/i.test(oName) || /galaxy\s*[sz]/i.test(cName) || /galaxy\s*[sz]/i.test(tKw)) {
    const tHasUltra = /\bultra\b/.test(oName) || /\bultra\b/.test(tKw);
    const cHasUltra = /\bultra\b/.test(cName);
    if (tHasUltra !== cHasUltra) return -1;

    const tHasPlus = /\b(plus|\+)\b/.test(oName) || /\b(plus|\+)\b/.test(tKw);
    const cHasPlus = /\b(plus|\+)\b/.test(cName);
    if (tHasPlus !== cHasPlus) return -1;

    const tHasFE = /\bfe\b/.test(oName) || /\bfe\b/.test(tKw);
    const cHasFE = /\bfe\b/.test(cName);
    if (tHasFE !== cHasFE) return -1;
  }

  if (oName.includes("ipad") || cName.includes("ipad") || tKw.includes("ipad")) {
    const tHasPro = /\bpro\b/.test(oName) || /\bpro\b/.test(tKw);
    const cHasPro = /\bpro\b/.test(cName);
    if (tHasPro !== cHasPro) return -1;

    const tHasAir = /\bair\b/.test(oName) || /\bair\b/.test(tKw);
    const cHasAir = /\bair\b/.test(cName);
    if (tHasAir !== cHasAir) return -1;

    const tHasMini = /\bmini\b/.test(oName) || /\bmini\b/.test(tKw);
    const cHasMini = /\bmini\b/.test(cName);
    if (tHasMini !== cHasMini) return -1;
  }

  // 3c. Laptop screen size conflict (e.g. 13 vs 14 vs 15 vs 16 vs 17 inch)
  const targetSize = (oName + " " + tKw).match(/\b(13|14|15|16|17)(?:\s*inch|\b|[A-Z])/i);
  const candSize = cName.match(/\b(13|14|15|16|17)(?:\s*inch|\b|[A-Z])/i);
  if (targetSize && candSize && targetSize[1] !== candSize[1] && (oName.includes("laptop") || oName.includes("ideapad") || oName.includes("macbook") || oName.includes("zenbook") || oName.includes("vivobook"))) {
    return -1;
  }

  // 4. Model Codes check
  const targetCodes = extractModelCodes(oName + ' ' + tKw);
  const candidateCodes = extractModelCodes(cName);

  let modelCodeScore = 0;
  if (targetCodes.length > 0) {
    let hasCodeMatch = false;
    for (const tc of targetCodes) {
      for (const cc of candidateCodes) {
        if (tc === cc || tc.includes(cc) || cc.includes(tc)) {
          hasCodeMatch = true;
          modelCodeScore += 50;
          break;
        }
      }
    }
    // If target has specific alphanumeric model codes (e.g. g614ph, ts118w),
    // and candidate has distinct alphanumeric codes but 0 matches -> reject!
    if (!hasCodeMatch && candidateCodes.length > 0) {
      return -1;
    }
  }

  // 5. Token match score
  const tokens = tKw.split(/\s+/).filter(t => t.length > 1 && !/^(laptop|máy|tính|chính|hãng)$/i.test(t));
  if (tokens.length === 0) return 0;

  let matched = 0;
  for (const token of tokens) {
    if (cName.includes(token)) matched++;
  }
  const tokenRatio = matched / tokens.length;
  if (tokenRatio < 0.4 && modelCodeScore === 0) return -1;

  let score = tokenRatio * 50 + modelCodeScore;

  // Storage size match bonus / penalty
  const targetStorageMatch = (oName + " " + tKw).match(/\b(64GB|128GB|256GB|512GB|1TB|2TB)\b/i);
  const candStorageMatch = cName.match(/\b(64GB|128GB|256GB|512GB|1TB|2TB)\b/i);
  if (targetStorageMatch && candStorageMatch) {
    if (targetStorageMatch[1].toUpperCase() === candStorageMatch[1].toUpperCase()) {
      score += 25;
    } else {
      score -= 40;
    }
  }

  // Price proximity bonus
  if (tPrice > 0 && cPrice > 0) {
    const diffRatio = Math.abs(cPrice - tPrice) / tPrice;
    if (diffRatio < 0.25) score += 20 * (1 - diffRatio);
  }

  // Stock availability bonus
  if (candidate.inStock !== false && cPrice > 0) score += 10;

  return score;
}

function pickBest(candidates, targetKeyword, targetPrice, originalName = '') {
  if (!Array.isArray(candidates) || candidates.length === 0) return null;
  let best = null;
  let maxScore = 55; // Must have at least 55 points to qualify

  for (const c of candidates) {
    const score = scoreCandidate(c, targetKeyword, targetPrice, originalName);
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
async function searchCPS(keyword, targetPrice, originalName = '') {
  const fetchGraphql = async (kw) => {
    const query = `query advanced_search {
      advanced_search(user_query: { terms: ${JSON.stringify(kw)}, province: 30 }, page: 1) {
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

    return (res.data.data?.advanced_search?.products || []).map(p => {
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
  };

  try {
    // 1st attempt: exact cleaned keyword
    const items = await fetchGraphql(keyword);
    let match = pickBest(items, keyword, targetPrice, originalName);
    if (match) return match;

    // Fallback: If keyword has hyphenated suffix like G614PH-TS118W or - 83UE000UVN
    const broaderKeyword = keyword.replace(/-[A-Za-z0-9]+/g, '').replace(/\s+/g, ' ').trim();
    if (broaderKeyword && broaderKeyword !== keyword) {
      const broaderItems = await fetchGraphql(broaderKeyword);
      match = pickBest(broaderItems, broaderKeyword, targetPrice, originalName);
      if (match) return match;
    }

    return null;
  } catch (err) {
    console.warn('[Competitor] CPS scrape warning:', err.message);
    return null;
  }
}

/**
 * 2. Thế Giới Di Động (TGDD) Scraper
 */
async function searchTGDD(keyword, targetPrice, originalName = '') {
  const fetchTGDD = async (kw) => {
    const res = await axios.post('https://api.thegioididong.com/gw/bus-tgdd-tmdt/api/Search/GetProductSearchV2', {
      pageIndex: 0,
      pageSize: 10,
      provinceId: 1027,
      sellerId: -1,
      keyWord: kw,
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

    return (res.data.data?.products || []).map(p => {
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
  };

  try {
    const items = await fetchTGDD(keyword);
    let match = pickBest(items, keyword, targetPrice, originalName);
    if (match) return match;

    const broaderKeyword = keyword.replace(/-[A-Za-z0-9]+/g, '').replace(/\s+/g, ' ').trim();
    if (broaderKeyword && broaderKeyword !== keyword) {
      const broaderItems = await fetchTGDD(broaderKeyword);
      match = pickBest(broaderItems, broaderKeyword, targetPrice, originalName);
      if (match) return match;
    }

    return null;
  } catch (err) {
    console.warn('[Competitor] TGDD scrape warning:', err.message);
    return null;
  }
}

/**
 * 3. FPT Shop (FPT) Scraper
 */
/**
 * Kiểm tra trạng thái còn hàng của FPT Shop:
 * - Code 11 ("Mua ngay"): Còn hàng
 * - Code 10 ("Tạm hết hàng"), Code 2 ("Ngừng kinh doanh"), nút "Đăng ký tư vấn", qtyAvailable = 0: Hết hàng
 */
function checkFptStock(html, slug) {
  if (!html || !slug) return false;
  const cleanSlug = slug.replace(/^\//, '').replace(/^https?:\/\/fptshop\.com\.vn\//, '').split('?')[0];

  // 1. Phân tích trạng thái từ Next.js JSON stream
  let pos = 0;
  while ((pos = html.indexOf(cleanSlug, pos)) !== -1) {
    const chunk = html.slice(pos, pos + 1000);
    if (chunk.includes('statusOnWeb')) {
      if (
        chunk.includes('"code":10') ||
        chunk.includes('"code": 10') ||
        chunk.includes('Tạm hết hàng') ||
        chunk.includes('Đăng ký tư vấn') ||
        chunk.includes('Ngừng kinh doanh') ||
        chunk.includes('"code":2') ||
        chunk.includes('"code": 2')
      ) {
        return false;
      }
      if (chunk.includes('"code":11') || chunk.includes('"code": 11') || chunk.includes('Mua ngay')) {
        return true;
      }
    }
    if (chunk.includes('"displayPriceText":"Tạm hết hàng"') || chunk.includes('displayPriceTextReplace":"Đăng ký tư vấn"')) {
      return false;
    }
    const qtyMatch = chunk.match(/"qtyAvailable":([0-9]+)/);
    if (qtyMatch && parseInt(qtyMatch[1], 10) === 0) {
      return false;
    }
    pos += cleanSlug.length;
  }

  // 2. Phân tích fallback từ HTML card
  let cardPos = 0;
  while ((cardPos = html.indexOf(cleanSlug, cardPos)) !== -1) {
    const cardChunk = html.slice(Math.max(0, cardPos - 300), cardPos + 1000);
    if (cardChunk.includes('Đăng ký tư vấn') || cardChunk.includes('Tạm hết hàng') || cardChunk.includes('Ngừng kinh doanh')) {
      return false;
    }
    if (cardChunk.includes('Mua ngay') || cardChunk.includes('Thêm vào giỏ')) {
      return true;
    }
    cardPos += cleanSlug.length;
  }

  return true;
}

async function searchFPT(keyword, targetPrice, originalName = '') {
  const fetchFPT = async (kw) => {
    try {
      const res = await axios.get(`https://fptshop.com.vn/tim-kiem?s=${encodeURIComponent(kw)}`, {
        headers: {
          'user-agent': USER_AGENT,
          'referer': 'https://fptshop.com.vn/'
        },
        timeout: 6000
      });

      const html = res.data;
      const items = [];

      // 1. Phân tích trực tiếp từ Next.js JSON payload (hỗ trợ cả các sản phẩm ghi "Đăng ký tư vấn")
      const jsonRegex = /\\\"displayName\\\":\\\"([^\\\"]+)\\\"[^{}]*?\\\"slug\\\":\\\"([^\\\"]+)\\\"[^{}]*?\\\"price\\\":([0-9]+)/g;
      let m;
      while ((m = jsonRegex.exec(html)) !== null) {
        const title = m[1];
        const slug = m[2];
        const price = parseInt(m[3], 10);
        const link = "https://fptshop.com.vn/" + slug.replace(/^\//, "");
        if (!items.some(i => i.link === link)) {
          items.push({
            retailer: "FPT",
            retailerName: "FPT Shop",
            name: title,
            price,
            originalPrice: price,
            link,
            inStock: checkFptStock(html, slug) && price > 0
          });
        }
      }

      // 2. Map thêm slug và price từ cấu trúc JSON
      const slugPriceRegex = /\\\"slug\\\":\\\"([^\\\"]+)\\\",\\\"price\\\":([0-9]+)/g;
      while ((m = slugPriceRegex.exec(html)) !== null) {
        const slug = m[1];
        const price = parseInt(m[2], 10);
        const link = "https://fptshop.com.vn/" + slug.replace(/^\//, "");
        const existing = items.find(i => i.link === link);
        if (existing) {
          if (!existing.price) existing.price = price;
        } else {
          const titleMatch = html.match(new RegExp("href=\\\"/" + slug + "\\\"[^>]*>([^<]+)</a>", "i"));
          const title = titleMatch ? titleMatch[1].trim() : slug;
          items.push({
            retailer: "FPT",
            retailerName: "FPT Shop",
            name: title,
            price,
            originalPrice: price,
            link,
            inStock: checkFptStock(html, slug) && price > 0
          });
        }
      }

      // 3. Fallback phân tích thẻ HTML thông thường
      const cardRegex = /<a[^>]*href="(\/(?:dien-thoai|may-tinh-xach-tay|laptop|may-tinh-bang|dong-ho|am-thanh|phu-kien)[^"]*)"[^>]*>([\s\S]*?)<\/a>/gi;
      while ((m = cardRegex.exec(html)) !== null) {
        const link = `https://fptshop.com.vn${m[1]}`;
        const cardEndIdx = html.indexOf("</div>", m.index + m[0].length + 1500);
        const cardChunk = html.substring(m.index, cardEndIdx > -1 ? cardEndIdx : m.index + 2000);
        const prices = [...cardChunk.matchAll(/([0-9]{1,3}(?:\.[0-9]{3})+)(?:\s*(?:₫|đ))/g)].map(x => parseInt(x[1].replace(/\./g, "")));
        const titleMatch = m[0].match(/aria-label="([^"]+)"/i) || m[0].match(/title="([^"]+)"/i) || cardChunk.match(/<h3[^>]*>([^<]+)<\/h3>/i);
        const title = titleMatch ? titleMatch[1].trim() : "";
        if (title && prices.length > 0 && !items.some(i => i.link === link)) {
          const promoPrice = prices.length >= 2 ? Math.min(...prices.slice(0, 2)) : prices[0];
          items.push({
            retailer: "FPT",
            retailerName: "FPT Shop",
            name: title,
            price: promoPrice,
            originalPrice: Math.max(...prices),
            link,
            inStock: checkFptStock(html, m[1]) && promoPrice > 0
          });
        }
      }

      return items;
    } catch (err) {
      console.warn("[FPT Warning]:", err.message);
      return [];
    }
  };

  try {
    // 1st attempt: Tìm theo keyword đầy đủ đã chuẩn hoá
    const items = await fetchFPT(keyword);
    let match = pickBest(items, keyword, targetPrice, originalName);
    if (match) return match;

    // 2nd attempt: Tìm theo broader keyword (bỏ hậu tố sau dấu gạch)
    const broaderKeyword = keyword.replace(/-[A-Za-z0-9]+/g, "").replace(/\s+/g, " ").trim();
    if (broaderKeyword && broaderKeyword !== keyword) {
      const broaderItems = await fetchFPT(broaderKeyword);
      match = pickBest(broaderItems, broaderKeyword, targetPrice, originalName);
      if (match) return match;
    }

    // 3rd attempt: Tìm trực tiếp theo mã model phần cứng (ví dụ: B53KBPA, 14-fe1010QU)
    const codes = extractModelCodes(originalName || keyword);
    for (const code of codes) {
      if (code.length >= 5) {
        const codeItems = await fetchFPT(code);
        match = pickBest(codeItems, keyword, targetPrice, originalName);
        if (match) return match;
      }
    }

    return null;
  } catch (err) {
    console.warn("[Competitor] FPT scrape warning:", err.message);
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
    searchCPS(keyword, ourPrice, productName),
    searchTGDD(keyword, ourPrice, productName),
    searchFPT(keyword, ourPrice, productName)
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

  // Sắp xếp 3 đối thủ theo giá từ Thấp đến Cao
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
    sorted,
    updatedAt: new Date().toISOString()
  };
}

module.exports = {
  cleanSearchKeyword,
  extractModelCodes,
  scoreCandidate,
  pickBest,
  searchCPS,
  searchTGDD,
  searchFPT,
  fetchAllCompetitors
};
