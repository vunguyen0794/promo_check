const { BigQuery } = require('@google-cloud/bigquery');
const bigquery = new BigQuery({ keyFilename: './bigquery-key.json' });

async function checkJobs() {
    try {
        console.log('Fetching recent BigQuery jobs for this Service Account...');
        const [jobs] = await bigquery.getJobs({ maxResults: 10, allUsers: false });
        
        if (jobs.length === 0) {
            console.log('No recent jobs found for this service account.');
            return;
        }

        jobs.forEach(job => {
            const config = job.metadata.configuration || {};
            const stats = job.metadata.statistics || {};
            const query = config.query ? config.query.query : 'Not a query job';
            const creationTime = new Date(parseInt(stats.creationTime)).toLocaleString();
            
            console.log('--- Job ---');
            console.log(`ID: ${job.id}`);
            console.log(`Time: ${creationTime}`);
            console.log(`State: ${job.metadata.status?.state || 'Unknown'}`);
            console.log(`Bytes Billed: ${stats.query ? stats.query.totalBytesBilled : 'N/A'}`);
            console.log(`Query: ${query.substring(0, 200)}...`);
            if (job.metadata.status?.errorResult) {
                console.log(`Error: ${job.metadata.status.errorResult.message}`);
            }
        });
    } catch (err) {
        console.error('Error fetching jobs:', err.message);
    }
}

checkJobs();
