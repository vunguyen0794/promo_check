// Test CSI Sheet access using the SAME OAuth method as server.js
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const { google } = require('googleapis');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

function getOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/google/drive/callback'
  );
}

async function getGlobalSheetsClient() {
  const { data: tok, error } = await supabase
    .from('app_google_tokens')
    .select('*')
    .eq('id', 'global')
    .single();

  if (error || !tok || !tok.refresh_token) {
    throw new Error('Google Sheets/Drive chung chưa được kết nối. Token: ' + JSON.stringify({error, tok}));
  }

  console.log('Token found, expiry_date:', tok.expiry_date, 'has refresh_token:', !!tok.refresh_token);

  const oauth2 = getOAuthClient();
  oauth2.setCredentials({
    access_token: tok.access_token || undefined,
    refresh_token: tok.refresh_token || undefined,
    expiry_date: tok.expiry_date || undefined,
    scope: tok.scope || undefined,
    token_type: tok.token_type || undefined,
  });

  return google.sheets({ version: 'v4', auth: oauth2 });
}

const CSI_SHEET_ID = '1ArSb_yXETKWKdXfODGSFzBh24RISwrpg5C0asWVxhwg';
const HR_SHEET_ID = '1pUCXps6-p7_aJe9oMGpGLFM5oMuDiyiC5BXAZoOWxP0';

(async () => {
  console.log('=== TEST 1: CSI Sheet ===');
  try {
    const sheets = await getGlobalSheetsClient();
    const meta = await sheets.spreadsheets.get({ spreadsheetId: CSI_SHEET_ID });
    console.log('CSI Sheet CONNECTED! Tabs:', meta.data.sheets.map(s => s.properties.title));
    
    // Read first tab sample
    const firstTab = meta.data.sheets[0].properties.title;
    const res = await sheets.spreadsheets.values.get({ 
      spreadsheetId: CSI_SHEET_ID, 
      range: `'${firstTab}'!A1:T5` 
    });
    if (res.data.values) {
      console.log('Headers:', res.data.values[0]);
      console.log('Row 1:', res.data.values[1]);
      console.log('Date col(1):', res.data.values[1]?.[1]);
      console.log('Branch col(4):', res.data.values[1]?.[4]);
      console.log('Feedback col(19):', res.data.values[1]?.[19]);
    }
  } catch(e) {
    console.error('CSI Sheet FAILED:', e.message);
  }

  console.log('\n=== TEST 2: HR Sheet ===');
  try {
    const sheets = await getGlobalSheetsClient();
    const res = await sheets.spreadsheets.values.get({ 
      spreadsheetId: HR_SHEET_ID, 
      range: 'A1:Z3' 
    });
    console.log('HR Sheet CONNECTED! Sample:', JSON.stringify(res.data.values?.[0]?.slice(0, 10)));
  } catch(e) {
    console.error('HR Sheet FAILED:', e.message);
  }

  console.log('\n=== TEST 3: Supabase user data ===');
  try {
    const { data } = await supabase.from('users').select('id,email,full_name,role,branch_code').limit(3);
    console.log('Users table columns:', data ? Object.keys(data[0]) : 'NO DATA');
    console.log('Sample user:', data?.[0]);
  } catch(e) {
    console.error('Users FAILED:', e.message);
  }

  console.log('\n=== TEST 4: Supabase salesman_performance ===');
  try {
    const { data } = await supabase.from('salesman_performance')
      .select('full_name,email,hrm_id,revenue,orders,report_month')
      .limit(2);
    console.log('salesman_performance columns:', data ? Object.keys(data[0]) : 'NO DATA');
    console.log('Sample:', data?.[0]);
  } catch(e) {
    console.error('salesman_performance FAILED:', e.message);
  }
})();
