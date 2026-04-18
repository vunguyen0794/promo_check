require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

// To get getAllBranchTargets, we can require server.js but it's an express app.
// I'll just write the exact same logic.
const { google } = require('googleapis');
const HR_SPREADSHEET_ID = '1pUCXps6-p7_aJe9oMGpGLFM5oMuDiyiC5BXAZoOWxP0';

const keyFile = require('path').resolve(__dirname, '../bigquery-key.json');
let sheetsClient = null;
async function getSheetsClient() {
  const auth = new google.auth.GoogleAuth({
    keyFile,
    scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
  });
  return google.sheets({ version: 'v4', auth });
}

async function debugKiet() {
  const { data: salesInfo } = await supabase.from('salesman_performance').select('*').eq('full_name', 'DANH HÀO KIỆT');
  console.log("DANH HAO KIET Data:", salesInfo);
  if (!salesInfo || salesInfo.length === 0) return;

  const branch = salesInfo[0].branch_code;
  console.log(`Branch is ${branch}`);
  
  // Terminal target
  const { data: tgt } = await supabase.from('pv_terminal_monthly_targets').select('*').eq('terminal_code', branch);
  console.log("Terminal Target:", tgt);

  // HR Target
  const sheets = await getSheetsClient();
  const range = 'Sheet3!A:AA';
  const response = await sheets.spreadsheets.values.get({ spreadsheetId: HR_SPREADSHEET_ID, range });
  const rows = response.data.values;
  
  const branchRow = rows.find(r => r[0] === branch);
  console.log(`HR Sheet Headcount row for ${branch}:`, branchRow);
}

debugKiet().catch(console.error);
