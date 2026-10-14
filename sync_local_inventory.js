const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Initialize Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const CSV_FILE_PATH = "D:/_Báo cáo/Looker Studio/CSV_Output/Data.csv";
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

async function syncLocalInventory() {
    console.log(`[${new Date().toLocaleString()}] Starting Local Sync Inventory: CSV -> Supabase...`);

    if (!acquireLock()) {
        return;
    }

    try {
        if (!fs.existsSync(CSV_FILE_PATH)) {
            console.error(`CRITICAL: CSV file not found at ${CSV_FILE_PATH}`);
            return;
        }

        const rows = [];
        const seenSerials = new Set();
        let duplicateInCsvCount = 0;
        const nowIso = new Date().toISOString();
        
        console.log("Reading data from CSV...");
        
        await new Promise((resolve, reject) => {
            fs.createReadStream(CSV_FILE_PATH)
                .pipe(csv())
                .on('data', (data) => {
                    const serial = (data.Serial || '').trim();
                    if (!serial) return; // Bỏ qua serial rỗng

                    // Deduplication: Bảo đảm không bị lặp Serial trong file CSV
                    if (seenSerials.has(serial)) {
                        duplicateInCsvCount++;
                        return;
                    }
                    seenSerials.add(serial);

                    // Map the CSV headers to Supabase column names
                    const mappedRow = {
                        "Serial": serial,
                        "SKU": data.SKU,
                        "SKU name": data.SKU_name,
                        "Branch ID": data.Branch_ID,
                        "Branch name": data.Branch_name,
                        "Brand": data.Brand,
                        "Category ID": data.Category_ID,
                        "Category name": data.Category_name,
                        "SubCategory ID": data.SubCategory_ID,
                        "SubCategory name": data.SubCategory_name,
                        "Subcat ID lowest level": data.Subcat_ID_lowest_level,
                        "Subcat name lowest level": data.Subcat_name_lowest_level,
                        "Location": data.Location,
                        "BIN type": data.BIN_type,
                        "BIN zone": data.BIN_zone,
                        "Date import company ": data.Date_import_company, // trailing space required
                        "Aging company": data.Aging_company !== '' ? Number(data.Aging_company) : null,
                        "Bad stock company": data.Bad_stock_company,
                        "Date import site": data.Date_import_site,
                        "Aging site": data.Aging_site !== '' ? Number(data.Aging_site) : null,
                        "Stock day site": data.Stock_day_site !== '' ? Number(data.Stock_day_site) : null,
                        "Bad stock site": data.Bad_stock_site,
                        "Stock day company": data.Stock_day_company !== '' ? Number(data.Stock_day_company) : null,
                        "Inventory": data.Inventory !== '' ? Number(data.Inventory) : null,
                        "Inventory amount": data.Inventory_amount !== '' ? Number(data.Inventory_amount) : null,
                        "last_sync_at": nowIso
                    };
                    rows.push(mappedRow);
                })
                .on('end', () => {
                    resolve();
                })
                .on('error', (error) => {
                    reject(error);
                });
        });

        console.log(`Successfully read ${rows.length} unique rows from CSV${duplicateInCsvCount > 0 ? ` (Bỏ qua ${duplicateInCsvCount} serial trùng lặp trong CSV)` : ''}.`);

        if (rows.length === 0) {
            console.warn("No data found in CSV. Skipping sync.");
            return;
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
    } finally {
        releaseLock();
    }
}

// If run directly
if (require.main === module) {
    syncLocalInventory();
}

module.exports = { syncLocalInventory };
