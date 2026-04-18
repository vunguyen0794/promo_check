require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

async function checkDateFocus() {
    const targetMonthStr = '2026-04';
    console.log("Checking Date logic...");
    const { data: latestKp, error } = await supabase
      .from('daily_kpi_summaries')
      .select('report_date')
      .gte('report_date', `${targetMonthStr}-01`)
      .lte('report_date', `${targetMonthStr}-31`)
      .order('report_date', { ascending: false })
      .limit(1)
      .maybeSingle();

    console.log("Supabase Response:", latestKp);
    console.log("Supabase Error:", error);
    
    // Also try simple logic without date range, just like what we used previously maybe
    const { data: latestKp2, error: err2 } = await supabase
      .from('daily_kpi_summaries')
      .select('report_date')
      .ilike('report_date', `${targetMonthStr}-%`)
      .order('report_date', { ascending: false })
      .limit(1)
      .maybeSingle();
      
    console.log("Alternative LIKE query Response:", latestKp2);
    console.log("Alternative error:", err2);
}

checkDateFocus().catch(console.error);
