const fs = require('fs');

const envContent = fs.readFileSync('.env', 'utf-8');
const bqKey = fs.readFileSync('bigquery-key.json', 'utf-8').trim();
const bqObj = JSON.parse(bqKey);

// replace BIGQUERY_KEY_JSON line
const newEnv = envContent.replace(
    /^BIGQUERY_KEY_JSON=.*$/m,
    'BIGQUERY_KEY_JSON=' + JSON.stringify(bqObj)
);

fs.writeFileSync('.env', newEnv);
console.log('Successfully updated .env BIGQUERY_KEY_JSON');
