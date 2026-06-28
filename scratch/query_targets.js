require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

async function main() {
  const { data, error } = await supabase.from('pv_terminal_monthly_targets').select('*');
  if (error) {
    console.error("Error fetching pv_terminal_monthly_targets:", error.message);
  } else {
    console.log("Found rows:", data.length);
    if (data.length > 0) {
      console.log("Sample row:", JSON.stringify(data[0], null, 2));
      console.log("All terminal codes in DB:", data.map(r => `${r.terminal_code} (${r.year})`));
    }
  }
}

main().catch(console.error);
