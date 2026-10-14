const { BigQuery } = require('@google-cloud/bigquery');
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// Initialize BigQuery
const bigquery = new BigQuery({
    keyFilename: './bigquery-key.json'
});

// Initialize Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const LOCK_FILE_PATH = path.join(__dirname, '.inventory_sync.lock');

function acquireLock() {
    if (fs.existsSync(LOCK_FILE_PATH)) {
        try {
            const lockData = JSON.parse(fs.readFileSync(LOCK_FILE_PATH, 'utf-8'));
            const lockAgeMinutes = (Date.now() - lockData.timestamp) / 60000;
            if (lockAgeMinutes < 15) {
                console.warn(`[LOCK] Một tiến trình sync khác đang chạy (PID: ${lockData.pid}, chạy lúc: ${new Date(lockData.timestamp).toLocaleString()}). Bỏ qua lần chạy này để tránh double data.`);
                return false;
            } else {
                console.warn(`[LOCK] Lock cũ đã hết hạn (${lockAgeMinutes.toFixed(1)} phút trước). Tự động ghi đè lock.`);
            }
        } catch {
            // Lock file corrupt, proceed
        }
    }
    fs.writeFileSync(LOCK_FILE_PATH, JSON.stringify({ pid: process.pid, timestamp: Date.now() }), 'utf-8');
    return true;
}

function releaseLock() {
    try {
        if (fs.existsSync(LOCK_FILE_PATH)) {
            fs.unlinkSync(LOCK_FILE_PATH);
        }
    } catch (e) {
        console.warn('[LOCK] Không thể xóa lock file:', e.message);
    }
}

async function syncInventory() {
    // 🛡️ CHỐNG TRÙNG LẶP DỮ LIỆU: Nếu đang chạy trên môi trường Vercel (Cloud), bỏ qua hoàn toàn.
    // Việc đồng bộ tồn kho inventory_serials được quản trị độc quyền bởi Task Scheduler 'PromotionApp_Inventory_Sync' trên máy local lúc 07:30 AM.
    if (process.env.VERCEL) {
        console.log('[SYNC INVENTORY] Đang chạy trên Vercel: Bỏ qua bước sync inventory để tránh đụng độ và double data với Local Task Scheduler.');
        return;
    }

    console.log(`[${new Date().toLocaleString()}] Starting Sync Inventory: BQ -> Supabase...`);

    if (!acquireLock()) {
        return;
    }

    const BIGQUERY_TABLE = '`nimble-volt-459313-b8.Inventory.inv_seri_1`';
    
    try {
        // 1. Fetch data from BigQuery
        const query = `
            SELECT 
                Serial AS Serial,
                CAST(SKU AS STRING) AS SKU,
                SKU_name AS \`SKU name\`,
                Branch_ID AS \`Branch ID\`,
                Branch_name AS \`Branch name\`,
                Brand AS Brand,
                Category_ID AS \`Category ID\`,
                Category_name AS \`Category name\`,
                SubCategory_ID AS \`SubCategory ID\`,
                SubCategory_name AS \`SubCategory name\`,
                Subcat_ID_lowest_level AS \`Subcat ID lowest level\`,
                Subcat_name_lowest_level AS \`Subcat name lowest level\`,
                Location AS Location,
                BIN_type AS \`BIN type\`,
                BIN_zone AS \`BIN zone\`,
                FORMAT_DATE('%Y-%m-%d', Date_import_company) AS \`Date import company \`,
                Aging_company AS \`Aging company\`,
                Bad_stock_company AS \`Bad stock company\`,
                FORMAT_DATE('%Y-%m-%d', Date_import_site) AS \`Date import site\`,
                Aging_site AS \`Aging site\`,
                Stock_day_site AS \`Stock day site\`,
                Bad_stock_site AS \`Bad stock site\`,
                Stock_day_company AS \`Stock day company\`,
                Inventory AS Inventory,
                Inventory_amount AS \`Inventory amount\`
            FROM ${BIGQUERY_TABLE}
        `;

        console.log("Fetching data from BigQuery...");
        const [rawRows] = await bigquery.query({
            query,
            location: 'asia-southeast1'
        });

        console.log(`Successfully fetched ${rawRows.length} rows from BigQuery.`);

        if (rawRows.length === 0) {
            console.warn("No data found in BigQuery. Skipping sync.");
            return;
        }

        // Deduplicate in memory
        const seenSerials = new Set();
        const rows = [];
        let duplicateCount = 0;
        const nowIso = new Date().toISOString();

        for (const row of rawRows) {
            const serial = (row.Serial || '').trim();
            if (!serial) continue;
            if (seenSerials.has(serial)) {
                duplicateCount++;
                continue;
            }
            seenSerials.add(serial);
            rows.push({
                ...row,
                Serial: serial,
                last_sync_at: nowIso
            });
        }

        if (duplicateCount > 0) {
            console.warn(`[DEDUP] Đã loại bỏ ${duplicateCount} serial trùng lặp từ BigQuery.`);
        }

        // 2. Clear existing data in Supabase (Truncate / Overwrite)
        console.log("Clearing existing data in Supabase table 'inventory_serials'...");
        const { error: truncError } = await supabase.rpc('truncate_table', { table_name: 'inventory_serials' });

        if (truncError) {
            console.warn(`[WARN] RPC truncate_table gặp lỗi (${truncError.message}). Fallback sang DELETE...`);
            const { error: deleteError } = await supabase
                .from('inventory_serials')
                .delete()
                .neq('Serial', '_non_existent_'); 

            if (deleteError) {
                throw new Error(`Failed to clear Supabase table: ${deleteError.message}`);
            }
        } else {
            console.log("✅ Đã truncate table 'inventory_serials' sạch sẽ qua RPC truncate_table.");
        }

        // 3. Batch insert into Supabase
        const BATCH_SIZE = 1000;
        console.log(`Inserting data in batches of ${BATCH_SIZE}...`);

        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE);

            const { error: insertError } = await supabase
                .from('inventory_serials')
                .insert(batch);

            if (insertError) {
                console.error(`Error in batch ${Math.floor(i / BATCH_SIZE)}:`, insertError.message);
                throw insertError;
            }

            if (i % 10000 === 0 && i !== 0) {
                console.log(`Status: Processed ${i} / ${rows.length} rows...`);
            }
        }

        // 4. Verify post-sync count
        const { count: finalCount, error: countErr } = await supabase
            .from('inventory_serials')
            .select('*', { count: 'exact', head: true });

        if (!countErr && finalCount !== null) {
            if (finalCount === rows.length) {
                console.log(`✅ [XÁC MINH HOÀN TẤT] Supabase có đúng ${finalCount.toLocaleString()} dòng (khớp 100% với dữ liệu nguồn, ZERO duplicate)!`);
            } else {
                console.warn(`⚠️ [CẢNH BÁO LỆCH DÒNG] Supabase hiện có ${finalCount.toLocaleString()} dòng, trong khi nguồn là ${rows.length.toLocaleString()} dòng!`);
            }
        }

        console.log(`[${new Date().toLocaleString()}] Sync Completed Successfully! Total: ${rows.length} rows.`);

    } catch (error) {
        console.error(`[${new Date().toLocaleString()}] Sync Failed:`, error.message);
        if (error.message.includes('Quota exceeded')) {
            console.error("CRITICAL: BigQuery Quota is currently exceeded. Cannot perform rescue sync.");
        }
    } finally {
        releaseLock();
    }
}

// If run directly
if (require.main === module) {
    syncInventory();
}

module.exports = { syncInventory };
