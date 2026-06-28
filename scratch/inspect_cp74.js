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
    range: 'Sheet3!A:AA'
  });
  
  const rows = response.data.values;
  const cp74Row = rows.find(r => r[0] === 'CP74');
  console.log("CP74 Row:", cp74Row);
}

main().catch(console.error);
