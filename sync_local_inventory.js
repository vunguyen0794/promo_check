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

async function syncLocalInventory() {
    console.log(`[${new Date().toLocaleString()}] Starting Local Sync Inventory: CSV -> Supabase...`);

    if (!fs.existsSync(CSV_FILE_PATH)) {
        console.error(`CRITICAL: CSV file not found at ${CSV_FILE_PATH}`);
        return;
    }

    const rows = [];
    
    console.log("Reading data from CSV...");
    
    // Promise to read CSV
    await new Promise((resolve, reject) => {
        fs.createReadStream(CSV_FILE_PATH)
            .pipe(csv())
            .on('data', (data) => {
                // Map the CSV headers to Supabase column names
                const mappedRow = {
                    "Serial": data.Serial,
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
                    "last_sync_at": new Date().toISOString()
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

    console.log(`Successfully read ${rows.length} rows from CSV.`);

    if (rows.length === 0) {
        console.warn("No data found in CSV. Skipping sync.");
        return;
    }

    try {
        // 2. Clear existing data in Supabase (Overwrite)
        console.log("Clearing existing data in Supabase table 'inventory_serials'...");
        const { error: deleteError } = await supabase
            .from('inventory_serials')
            .delete()
            .neq('Serial', '_non_existent_'); 

        if (deleteError) {
            throw new Error(`Failed to clear Supabase table: ${deleteError.message}`);
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
                console.error(`Error in batch ${i / BATCH_SIZE}:`, insertError.message);
                throw insertError;
            }

            if (i % 5000 === 0 && i !== 0) {
                console.log(`Status: Processed ${i} / ${rows.length} rows...`);
            }
        }

        console.log(`[${new Date().toLocaleString()}] Sync Completed Successfully! Total: ${rows.length} rows.`);

    } catch (error) {
        console.error(`[${new Date().toLocaleString()}] Sync Failed:`, error.message);
    }
}

// If run directly
if (require.main === module) {
    syncLocalInventory();
}

module.exports = { syncLocalInventory };
