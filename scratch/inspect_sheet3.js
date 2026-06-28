const { google } = require('googleapis');
const path = require('path');
const keyFile = path.resolve(__dirname, '../bigquery-key.json');
const HR_SPREADSHEET_ID = '1pUCXps6-p7_aJe9oMGpGLFM5oMuDiyiC5BXAZoOWxP0';

async function main() {
  const auth = new google.auth.GoogleAuth({
    keyFile,
    scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
  });
  const sheets = google.sheets({ version: 'v4', auth });
  
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: HR_SPREADSHEET_ID,
    range: 'Sheet3!A1:AA10'
  });
  
  const rows = response.data.values;
  if (!rows || rows.length === 0) {
    console.log("No data found in Sheet3");
    return;
  }
  
  console.log("Header row (row 0):", rows[0]);
  for (let i = 1; i < rows.length; i++) {
    console.log(`Row ${i}:`, rows[i]);
  }
}

main().catch(console.error);
