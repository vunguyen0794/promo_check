const fs = require('fs');

const NEW_CSI_LOGIC = `// ==========================================
// GOOGLE SHEETS CSI FALLBACK
// ==========================================
const CSI_SHEET_ID = '1ArSb_yXETKWKdXfODGSFzBh24RISwrpg5C0asWVxhwg';
const CSI_RANGE = 'A2:AB';
let csiSheetCache = null;
let csiSheetCacheTime = 0;

async function fetchCSISheetData() {
  if (csiSheetCache && Date.now() - csiSheetCacheTime < 3600000) return csiSheetCache;
  const sheets = await getGlobalSheetsClient();
  const meta = await sheets.spreadsheets.get({ spreadsheetId: CSI_SHEET_ID });
  let dataRows = [];
  
  for(let s of meta.data.sheets) {
      const sheetName = s.properties.title;
      try {
          const res = await sheets.spreadsheets.values.get({ spreadsheetId: CSI_SHEET_ID, range: \`'\${sheetName}'!\${CSI_RANGE}\` });
          if (res.data.values) {
              dataRows = dataRows.concat(res.data.values);
          }
      } catch (e) {
          console.error("Error reading sheet:", sheetName, e);
      }
  }
  csiSheetCache = dataRows;
  csiSheetCacheTime = Date.now();
  return csiSheetCache;
}

async function getCsiStats(options) {
  const data = await fetchCSISheetData();
  let validSurveys = 0;
  let rawScore = 0;
  let feedbackCount = 0;
  
  data.forEach((row) => {
    if (!row[1]) return;
    const dateStr = row[1];
    
    if (options.period) {
        if (options.period === 'today') {
           const d = new Date().toISOString().split('T')[0];
           if (dateStr !== d) return;
        } else if (/^\\d{4}-\\d{2}$/.test(options.period)) {
           if (!dateStr.startsWith(options.period)) return;
        }
    }
    
    const branch = row[4];
    if (options.branch && branch) {
      if (branch.toLowerCase() !== options.branch.toLowerCase()) return;
    }
    
    const fb = row[19];
    if (fb && fb.trim() !== '') {
        feedbackCount++;
    }

    const qCount = [13, 14, 15, 16, 17, 18].filter(idx => row[idx]).length;
    if (qCount === 6) {
        validSurveys++;
        let score = 3;
        if(row[13]==='5 đ') score += 5 * 0.15;
        if(row[14]==='5 đ') score += 5 * 0.90;
        if(row[15]==='5 đ') score += 5 * 0.45;
        if(row[16]==='5 đ') score += 5 * 0.90;
        if(row[17]==='5 đ') score += 5 * 0.45;
        if(row[18]==='5 đ') score += 5 * 0.15;
        rawScore += score;
    }
  });
  
  const csi_percent = validSurveys > 0 ? (rawScore / (validSurveys * 21)) * 100 : 0;
  return { csi_percent: csi_percent.toFixed(1), feedback_count: feedbackCount };
}

async function getFeedbackList(options) {
  const data = await fetchCSISheetData();
  const list = [];
  data.forEach((row) => {
    if (!row[1]) return;
    const dateStr = row[1];
    
    if (options.period) {
        if (options.period === 'today') {
           const d = new Date().toISOString().split('T')[0];
           if (dateStr !== d) return;
        } else if (/^\\d{4}-\\d{2}$/.test(options.period)) {
           if (!dateStr.startsWith(options.period)) return;
        }
    }
    
    const branch = row[4];
    if (options.branch && branch) {
      if (branch.toLowerCase() !== options.branch.toLowerCase()) return;
    }
    
    const fb = row[19];
    if (fb && fb.trim() !== '') {
        list.push({
            date: dateStr,
            customer: row[8] || 'Khách',
            phone: row[9] || '',
            note: fb
        });
    }
  });
  return list;
}
`;

let code = fs.readFileSync('server.js', 'utf8');

const sIdx = code.indexOf('async function getCsiStats(options) {');
const eMarker = '// ======================= SALES DASHBOARD';
const eIdx = code.indexOf(eMarker);

if (sIdx !== -1 && eIdx !== -1) {
    code = code.substring(0, sIdx) + NEW_CSI_LOGIC + '\\n' + code.substring(eIdx);
    fs.writeFileSync('server.js', code);
    console.log("CSI logic fully replaced!");
} else {
    console.log("FAILED bounding", sIdx, eIdx);
}
