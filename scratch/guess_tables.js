require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

async function findTables() {
    // We can query the pg_class or similar if we have RPC, but usually we don't.
    // Let's try guessing common names:
    const candidates = ['raw_sales_orders', 'raw_sales', 'sales_orders', 'orders', 'sale_orders'];
    for(let t of candidates) {
        const { data, error } = await supabase.from(t).select('*').limit(1);
        if(!error) {
            console.log("FOUND:", t);
        } else {
            console.log("Not found:", t, error.message);
        }
    }
}
findTables();
