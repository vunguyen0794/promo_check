require('dotenv').config();
const { BigQuery } = require('@google-cloud/bigquery');
const bigquery = new BigQuery({
  projectId: 'nimble-volt-459313-b8',
  keyFilename: './bigquery-key.json',
});

async function run() {
  const query = `
    CREATE OR REPLACE TABLE \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
    PARTITION BY DATE(Report_date)
    CLUSTER BY Branch_code, Email
    AS SELECT * FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
  `;
  try {
    console.log("Partitioning table...");
    const [job] = await bigquery.createQueryJob({ query });
    console.log(`Job ${job.id} started. Waiting for completion...`);
    const [result] = await job.promise();
    console.log("Partitioning successful!");
  } catch(e) {
    console.error("Error:", e.message);
  }
}
run();
