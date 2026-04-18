require('dotenv').config();
const { BigQuery } = require('@google-cloud/bigquery');
const bq = new BigQuery({projectId: 'nimble-volt-459313-b8', keyFilename: './bigquery-key.json'});

async function run() {
  const [job1] = await bq.createQueryJob({
    query: 'SELECT * FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\` WHERE Report_date >= "2026-04-01" AND Report_date <= "2026-04-30"', 
    dryRun: true
  });
  console.log('OPTIMIZED:', job1.metadata.statistics.totalBytesProcessed);

  const [job2] = await bq.createQueryJob({
    query: 'SELECT * FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\` WHERE FORMAT_DATE("%Y-%m", Report_date) = "2026-04"', 
    dryRun: true
  });
  console.log('OLD:', job2.metadata.statistics.totalBytesProcessed);
}
run();
