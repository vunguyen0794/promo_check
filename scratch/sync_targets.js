require('dotenv').config();
const { google } = require('googleapis');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const keyFile = path.resolve(__dirname, '../bigquery-key.json');
const HR_SPREADSHEET_ID = '1pUCXps6-p7_aJe9oMGpGLFM5oMuDiyiC5BXAZoOWxP0';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

async function getSheetsClient() {
  const auth = new google.auth.GoogleAuth({
    keyFile,
    scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
  });
  return google.sheets({ version: 'v4', auth });
}

function parseTargetValue(rawVal) {
  if (!rawVal) return 0;
  // Convert "36,98" to "36.98"
  const normalized = rawVal.replace(/\./g, '').replace(',', '.').trim();
  const val = parseFloat(normalized);
  if (isNaN(val)) return 0;
  // Google Sheets values are in Billions (e.g. 36.98), Supabase is in Millions (e.g. 36980)
  // So multiply by 1000
  return Math.round(val * 1000);
}

async function syncTargets() {
  console.log("Starting Target Sync from Google Sheets to Supabase...");
  const sheets = await getSheetsClient();
  const range = 'Sheet3!A:AA';
  
  const response = await sheets.spreadsheets.values.get({ spreadsheetId: HR_SPREADSHEET_ID, range });
  const rows = response.data.values;
  if (!rows || rows.length <= 1) {
    console.log("No data found in Google Sheet3");
    return;
  }

  const payload = [];

  // Row 0 is Header
  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    const branchCode = (row[0] || '').trim().toUpperCase();
    if (!branchCode || branchCode === 'TOTAL' || branchCode === 'GRAND TOTAL') continue;

    const branchName = (row[1] || '').trim();

    // 2025 Targets (Columns T1-T12 starting at index 3)
    const targets2025 = {
      terminal_code: branchCode,
      terminal_name: branchName || `Chi Nhánh ${branchCode}`,
      year: 2025,
      m01: parseTargetValue(row[3]),
      m02: parseTargetValue(row[4]),
      m03: parseTargetValue(row[5]),
      m04: parseTargetValue(row[6]),
      m05: parseTargetValue(row[7]),
      m06: parseTargetValue(row[8]),
      m07: parseTargetValue(row[9]),
      m08: parseTargetValue(row[10]),
      m09: parseTargetValue(row[11]),
      m10: parseTargetValue(row[12]),
      m11: parseTargetValue(row[13]),
      m12: parseTargetValue(row[14])
    };

    // 2026 Targets (Columns T1-T12 starting at index 15)
    const targets2026 = {
      terminal_code: branchCode,
      terminal_name: branchName || `Chi Nhánh ${branchCode}`,
      year: 2026,
      m01: parseTargetValue(row[15]),
      m02: parseTargetValue(row[16]),
      m03: parseTargetValue(row[17]),
      m04: parseTargetValue(row[18]),
      m05: parseTargetValue(row[19]),
      m06: parseTargetValue(row[20]),
      m07: parseTargetValue(row[21]),
      m08: parseTargetValue(row[22]),
      m09: parseTargetValue(row[23]),
      m10: parseTargetValue(row[24]),
      m11: parseTargetValue(row[25]),
      m12: parseTargetValue(row[26])
    };

    payload.push(targets2025);
    payload.push(targets2026);
  }

  console.log(`Prepared ${payload.length} rows to sync to Supabase.`);

  // We attempt to upsert to pv_terminal_monthly_targets.
  // First, check if there is an index constraint we should use.
  // If we don't specify onConflict, it might try to match by primary key or it will fail if unique constraint violated.
  // We'll try upserting with onConflict on ['terminal_code', 'year'].
  const { data, error } = await supabase
    .from('pv_terminal_monthly_targets')
    .upsert(payload, { onConflict: 'terminal_code,year' });

  if (error) {
    console.error("Upsert failed, error detail:", error);
    
    // If it failed because of onConflict constraint, let's try mapping manually or deleting & inserting.
    console.log("Attempting manual sync row-by-row (fallback)...");
    let successCount = 0;
    for (const item of payload) {
      // Try to find if row already exists
      const { data: existing } = await supabase
        .from('pv_terminal_monthly_targets')
        .select('id')
        .eq('terminal_code', item.terminal_code)
        .eq('year', item.year)
        .maybeSingle();

      if (existing) {
        // Update
        const { error: updateErr } = await supabase
          .from('pv_terminal_monthly_targets')
          .update(item)
          .eq('id', existing.id);
        if (!updateErr) successCount++;
        else console.error(`Failed to update ${item.terminal_code} (${item.year}):`, updateErr.message);
      } else {
        // Insert
        const { error: insertErr } = await supabase
          .from('pv_terminal_monthly_targets')
          .insert(item);
        if (!insertErr) successCount++;
        else console.error(`Failed to insert ${item.terminal_code} (${item.year}):`, insertErr.message);
      }
    }
    console.log(`Sync completed fallback. Successfully processed ${successCount}/${payload.length} records.`);
  } else {
    console.log("Upsert successful! Synced all rows to pv_terminal_monthly_targets.");
  }
}

syncTargets().catch(console.error);
