require('dotenv').config();
const { BigQuery } = require('@google-cloud/bigquery');
const bq = new BigQuery({projectId: 'nimble-volt-459313-b8', keyFilename: './bigquery-key.json'});

async function run() {
  const query = `
    SELECT 
        Order_code, Customer_full_name, Billing_tax_code, Report_date, Branch_code, Email, Revenue_with_VAT
    FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
    WHERE FORMAT_DATE('%Y-%m', Report_date) = '2026-04'
  `;
  const [job1] = await bq.createQueryJob({ query, dryRun: true });
  console.log('NO SKU (List Query):', job1.metadata.statistics.totalBytesProcessed);

  const queryDetail = `
    SELECT SKU, SKU_name, Quantity
    FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
    WHERE Billing_tax_code = '0316032128'
  `;
  const [job2] = await bq.createQueryJob({ query: queryDetail, dryRun: true });
  console.log('ONLY SKU (Detail Query):', job2.metadata.statistics.totalBytesProcessed);
}
run();
