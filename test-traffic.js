require('dotenv').config();
const { google } = require('googleapis');

async function testTraffic() {
  const sheetId = process.env.GOOGLE_TRAFFIC_SHEET_ID;

  // Fix newline parsing when dotEnv doesn't unescape them well
  let jsonStr = process.env.BIGQUERY_KEY_JSON;
  if (jsonStr) jsonStr = jsonStr.replace(/\\n/g, '\n');

  const auth = new google.auth.GoogleAuth({
    credentials: JSON.parse(jsonStr),
    scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
  });
  const sheets = google.sheets({ version: 'v4', auth });
  const res = await sheets.spreadsheets.values.get({ spreadsheetId: sheetId, range: 'cctv!A:F' });
  const rows = res.data.values;

  console.log(`[Traffic] Total rows from sheet: ${(rows || []).length}`);
  const h = (rows[0] || []).map(val => (val || '').toString().toLowerCase().trim());
  console.log("Headers:", h);

  if (rows && rows.length > 1) {
    console.log("Sample row 1:", rows[1]);
    console.log("Sample row 2:", rows[2]);
  }
}
testTraffic();
