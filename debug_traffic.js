/**
 * debug_traffic.js - Script kiểm tra kết nối Google Sheets và dữ liệu traffic
 * Chạy: node debug_traffic.js
 */
require('dotenv').config();
const { google } = require('googleapis');

async function main() {
    const sheetId = process.env.GOOGLE_TRAFFIC_SHEET_ID;
    console.log('Sheet ID:', sheetId);
    
    if (!sheetId) {
        console.error('ERROR: GOOGLE_TRAFFIC_SHEET_ID not set in .env');
        return;
    }

    try {
        const keyJson = JSON.parse(process.env.BIGQUERY_KEY_JSON);
        const auth = new google.auth.GoogleAuth({
            credentials: keyJson,
            scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
        });
        const sheets = google.sheets({ version: 'v4', auth });
        
        // 1. List all sheet tabs first
        console.log('\n--- Listing all sheet tabs ---');
        const meta = await sheets.spreadsheets.get({ spreadsheetId: sheetId });
        const tabs = meta.data.sheets.map(s => s.properties.title);
        console.log('Available tabs:', tabs);

        // 2. Try to read from the 'cctv' tab
        if (tabs.includes('cctv')) {
            console.log('\n--- Reading from cctv tab (first 6 rows) ---');
            const res = await sheets.spreadsheets.values.get({
                spreadsheetId: sheetId,
                range: 'cctv!A:F',
            });
            const rows = res.data.values || [];
            console.log(`Total rows: ${rows.length}`);
            if (rows.length > 0) {
                console.log('Header row (raw):', JSON.stringify(rows[0]));
                console.log('Normalized header:', rows[0].map(v => (v||'').toLowerCase().trim()));
                
                // Check column indices
                const h = rows[0].map(v => (v||'').toLowerCase().trim());
                const dI = h.indexOf('date');
                const bI = h.indexOf('branch_id');
                const vI = h.indexOf('visit_count');
                console.log(`\nColumn indices => date:${dI}, branch_id:${bI}, visit_count:${vI}`);
                
                // Show first 5 data rows
                console.log('\nFirst 5 data rows:');
                rows.slice(1, 6).forEach((r, i) => {
                    console.log(`Row ${i+1}:`, JSON.stringify(r));
                    if (dI >= 0 && bI >= 0 && vI >= 0) {
                        console.log(`  => date="${r[dI]}", branch_id="${r[bI]}", visit_count="${r[vI]}"`);
                    }
                });

                // Count total records by branch
                if (dI >= 0 && bI >= 0 && vI >= 0) {
                    const branchMap = {};
                    rows.slice(1).forEach(r => {
                        const b = r[bI];
                        if (b) branchMap[b] = (branchMap[b] || 0) + 1;
                    });
                    console.log('\nRecord count by branch_id:', branchMap);
                }
            }
        } else {
            console.error('\nERROR: Tab "cctv" NOT FOUND in the spreadsheet!');
            console.log('Please check the sheet tab name. Available tabs:', tabs);
        }

    } catch (err) {
        console.error('ERROR connecting to Google Sheets:', err.message);
        console.error(err.stack);
    }
}

main();
