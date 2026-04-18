require('dotenv').config();
const { BigQuery } = require('@google-cloud/bigquery');
const bigquery = new BigQuery({
  projectId: 'nimble-volt-459313-b8',
  keyFilename: './bigquery-key.json',
});

async function runDry() {
  const queryBad = `
    SELECT * 
    FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
    WHERE FORMAT_DATE('%Y-%m', Report_date) = '2026-03'
  `;
  const queryGood = `
    SELECT * 
    FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\`
    WHERE Report_date >= '2026-03-01' AND Report_date < '2026-04-01'
  `;

  try {
    const [jobBad] = await bigquery.createQueryJob({ query: queryBad, dryRun: true });
    console.log('BAD QUERY Bytes Processed:', jobBad.metadata.statistics.totalBytesProcessed);

    const [jobGood] = await bigquery.createQueryJob({ query: queryGood, dryRun: true });
    console.log('GOOD QUERY Bytes Processed:', jobGood.metadata.statistics.totalBytesProcessed);
  } catch(e) {
    console.error(e);
  }
}
runDry();
