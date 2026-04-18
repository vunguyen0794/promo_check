require('dotenv').config();
const { BigQuery } = require('@google-cloud/bigquery');
const bigquery = new BigQuery({ keyFilename: './bigquery-key.json', projectId: 'nimble-volt-459313-b8' });

(async () => {
    try {
        const [r] = await bigquery.query({ query: 'SELECT COUNT(*) as c FROM `nimble-volt-459313-b8.sales.raw_sales_orders_all` WHERE Report_date = CURRENT_DATE()' });
        console.log('BQ works:', r);
    } catch(e) {
        console.log('BQ error:', e.message);
    }
})();
