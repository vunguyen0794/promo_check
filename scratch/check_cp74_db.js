require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

async function main() {
  const { data, error } = await supabase.from('pv_terminal_monthly_targets').select('*').eq('terminal_code', 'CP74');
  if (error) {
    console.error(error);
  } else {
    console.log("CP74 DB rows:", JSON.stringify(data, null, 2));
  }
}

main().catch(console.error);
