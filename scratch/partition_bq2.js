require('dotenv').config();
const { BigQuery } = require('@google-cloud/bigquery');
const bigquery = new BigQuery({
  projectId: 'nimble-volt-459313-b8',
  keyFilename: './bigquery-key.json',
});

async function run() {
  const query = `
    CREATE OR REPLACE TABLE \`nimble-volt-459313-b8.sales.raw_sales_orders_all_part\`
    PARTITION BY Report_date_val
    CLUSTER BY Branch_code, Email
    AS SELECT *, CAST(Report_date AS DATE) as Report_date_val FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
  `;
  try {
    console.log("Partitioning table...");
    const [job] = await bigquery.createQueryJob({ query });
    const [result] = await job.promise();
    console.log("Partitioning successful! Now replacing old table...");
    // Drop old table
    await bigquery.query("DROP TABLE \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`");
    // Rename new table to old
    await bigquery.query("ALTER TABLE \`nimble-volt-459313-b8.sales.raw_sales_orders_all_part\` RENAME TO raw_sales_orders_all");
    console.log("Rename successful!");
  } catch(e) {
    console.error("Error:", e.message);
  }
}
run();
