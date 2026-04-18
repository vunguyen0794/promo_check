const fs = require('fs');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

async function listTables() {
    const { data, error } = await supabase.from('pv_terminal_sales_daily_final').select('*').limit(1);
    console.log("pv_terminal_sales_daily_final:", data ? "EXISTS" : error);
    
    // Test if erp_sales_data or similar exists
    const { data: d2, error: e2 } = await supabase.from('sales_data').select('*').limit(1);
    console.log("sales_data:", d2 ? "EXISTS" : e2);
}
listTables();
