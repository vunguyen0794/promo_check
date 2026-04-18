require('dotenv').config();

const { google } = require('googleapis');
const path = require('path');
const keyFile = path.resolve(__dirname, '../bigquery-key.json');

async function getGlobalSheetsClient() {
  const auth = new google.auth.GoogleAuth({
    keyFile,
    scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
  });
  return google.sheets({ version: 'v4', auth });
}

const CSI_SHEET_ID = '1ArSb_yXETKWKdXfODGSFzBh24RISwrpg5C0asWVxhwg';
const CSI_RANGE = 'A2:AB';

async function testCSI() {
  const sheets = await getGlobalSheetsClient();
  const meta = await sheets.spreadsheets.get({ spreadsheetId: CSI_SHEET_ID });
  let dataRows = [];
  
  for(let s of meta.data.sheets) {
      const sheetName = s.properties.title;
      try {
          const res = await sheets.spreadsheets.values.get({ spreadsheetId: CSI_SHEET_ID, range: `'${sheetName}'!${CSI_RANGE}` });
          if (res.data.values) {
              dataRows = dataRows.concat(res.data.values);
          }
      } catch (e) {
          console.error("Error reading sheet:", sheetName, e);
      }
  }
  
  console.log("Total rows fetched from Sheets:", dataRows.length);
  
  if (dataRows.length > 0) {
      console.log("Sample row[0]:", dataRows[0]);
      console.log("Sample branch index(4):", dataRows[0][4]); // Mã SR?
      console.log("Sample date index(1):", dataRows[0][1]); // Ngày KS?
  }
}

testCSI().catch(console.error);
