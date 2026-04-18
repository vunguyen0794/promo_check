// Simulate getCsiStats scoring on real CSI data from Google Sheets
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const { google } = require('googleapis');
const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

(async () => {
  const { data: tok } = await sb.from('app_google_tokens').select('*').eq('id', 'global').single();
  const oauth2 = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
  oauth2.setCredentials({ access_token: tok.access_token, refresh_token: tok.refresh_token, expiry_date: tok.expiry_date });
  const sheets = google.sheets({version:'v4', auth: oauth2});
  
  const r = await sheets.spreadsheets.values.get({spreadsheetId:'1ArSb_yXETKWKdXfODGSFzBh24RISwrpg5C0asWVxhwg', range:'csi!A2:AB'});
  const data = r.data.values || [];
  
  console.log('Total rows in sheet:', data.length);

  // Filter for April 2026
  const period = '2026-04';
  const [py, pm] = period.split('-');
  const tSub = pm + '/' + py; // "04/2026"

  let totalBonusScore = 0;
  let standardScore = 0;
  let feedbackCount = 0;
  let validSurveys = 0;
  let totalRows = 0;

  data.forEach((row) => {
    if (!row[1]) return;
    const dateStr = (row[1] || '').trim();
    if (!dateStr.includes(tSub)) return;
    
    totalRows++;
    
    const fb = (row[19] || '').trim();
    if (fb !== '') feedbackCount++;
    
    const callRecord = (row[12] || '').trim();
    const checkCol = (row[24] || '').trim();
    if (!callRecord.startsWith('1.Đồng ý KS') || checkCol !== '6') return;
    
    validSurveys++;
    standardScore += 3;
    
    const q13 = (row[13] || '').trim();
    const q14 = (row[14] || '').trim();
    const q15 = (row[15] || '').trim();
    const q16 = (row[16] || '').trim();
    const q17 = (row[17] || '').trim();
    const q18 = (row[18] || '').trim();
    
    function scoreQ(val, pos, neg) {
      if (val.startsWith(pos)) return 3;
      if (val.startsWith(neg)) return -3;
      return 1;
    }
    
    const s_greeting    = scoreQ(q13, 'Có', 'Không') * 0.05;
    const s_advice      = (q14.includes('Tốt') ? 3 : q14.startsWith('Tệ') ? -3 : 1) * 0.30;
    const s_choice      = scoreQ(q15, 'Có', 'Không') * 0.15;
    const s_satisfaction = scoreQ(q16, 'Có', 'Không') * 0.30;
    const s_referral    = (q17.startsWith('Sẵn sàng') ? 3 : q17.startsWith('Không') ? -3 : 1) * 0.15;
    const s_zalo        = scoreQ(q18, 'Có', 'Không') * 0.05;
    
    totalBonusScore += s_greeting + s_advice + s_choice + s_satisfaction + s_referral + s_zalo;
  });
  
  const csi_percent = standardScore > 0 ? (totalBonusScore / standardScore) * 100 : 0;
  
  console.log('\n=== CSI Tháng 4/2026 ===');
  console.log('Rows matching April 2026:', totalRows);
  console.log('Valid surveys (Đồng ý KS + Check=6):', validSurveys);
  console.log('Feedback count:', feedbackCount);
  console.log('Standard score (base):', standardScore);
  console.log('Total bonus score:', totalBonusScore.toFixed(4));
  console.log('CSI %:', csi_percent.toFixed(1) + '%');
  console.log('Expected: ~92.0%, 25 góp ý');
})();
