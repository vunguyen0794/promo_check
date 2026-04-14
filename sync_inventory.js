const { BigQuery } = require('@google-cloud/bigquery');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Initialize BigQuery
const bigquery = new BigQuery({
    keyFilename: './bigquery-key.json'
});

// Initialize Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

async function syncInventory() {
    console.log(`[${new Date().toLocaleString()}] Starting Sync Inventory: BQ -> Supabase...`);

    const BIGQUERY_TABLE = '`nimble-volt-459313-b8.Inventory.inv_seri_1`';
    
    try {
        // 1. Fetch data from BigQuery
        // Ch?n các c?t và alias v? tên m?i trong Supabase d? insert d? dàng
        const query = `
            SELECT 
                Serial AS Serial,
                CAST(SKU AS STRING) AS SKU,
                SKU_name AS \`SKU name\`,
                Brand AS Brand,
                Location AS Location,
                BIN_zone AS \`BIN zone\`,
                Branch_ID AS \`Branch ID\`,
                SubCategory_name AS \`SubCategory name\`,
                FORMAT_DATE('%Y-%m-%d', Date_import_company) AS \`Date import company \`,
                Aging_company AS \`Aging company\`
            FROM ${BIGQUERY_TABLE}
        `;

        console.log("Fetching data from BigQuery...");
        const [rows] = await bigquery.query({
            query,
            location: 'asia-southeast1'
        });

        console.log(`Successfully fetched ${rows.length} rows from BigQuery.`);

        if (rows.length === 0) {
            console.warn("No data found in BigQuery. Skipping sync.");
            return;
        }

        // 2. Clear existing data in Supabase (Overwrite)
        console.log("Clearing existing data in Supabase table 'inventory_serials'...");
        const { error: deleteError } = await supabase
            .from('inventory_serials')
            .delete()
            .neq('Serial', '_non_existent_'); // S?a thành "Serial" vi?t hoa

        if (deleteError) {
            throw new Error(`Failed to clear Supabase table: ${deleteError.message}`);
        }

        // 3. Batch insert into Supabase
        const BATCH_SIZE = 1000;
        console.log(`Inserting data in batches of ${BATCH_SIZE}...`);

        for (let i = 0; i < rows.length; i += BATCH_SIZE) {
            const batch = rows.slice(i, i + BATCH_SIZE).map(row => ({
                ...row,
                last_sync_at: new Date().toISOString()
            }));

            const { error: insertError } = await supabase
                .from('inventory_serials')
                .insert(batch);

            if (insertError) {
                console.error(`Error in batch ${i / BATCH_SIZE}:`, insertError.message);
                // Continue with next batch instead of stopping entirely? 
                // Let's stop if it's a critical error.
                throw insertError;
            }

            if (i % 10000 === 0) {
                console.log(`Status: Processed ${i} / ${rows.length} rows...`);
            }
        }

        console.log(`[${new Date().toLocaleString()}] Sync Completed Successfully! Total: ${rows.length} rows.`);

    } catch (error) {
        console.error(`[${new Date().toLocaleString()}] Sync Failed:`, error.message);
        if (error.message.includes('Quota exceeded')) {
            console.error("CRITICAL: BigQuery Quota is currently exceeded. Cannot perform rescue sync.");
        }
    }
}

// If run directly
if (require.main === module) {
    syncInventory();
}

module.exports = { syncInventory };
