const fs = require('fs');
const content = fs.readFileSync('server.js', 'utf8');

function checkRoute(routeString) {
    const startIdx = content.indexOf(`app.get('${routeString}'`);
    if (startIdx === -1) {
        console.log(`Route ${routeString} not found`);
        return;
    }
    
    // Find the end of the route (rough estimation by looking for next app.get or app.post)
    let endIdx = content.indexOf(`app.get`, startIdx + 10);
    if (endIdx === -1) endIdx = content.length;
    
    const routeBody = content.substring(startIdx, endIdx);
    
    const hasBQ = routeBody.toLowerCase().includes('bigquery') || routeBody.toLowerCase().includes('nimble-volt');
    const hasSupabase = routeBody.toLowerCase().includes('supabase');
    
    console.log(`[${routeString}]`);
    console.log(`  Uses BigQuery: ${hasBQ}`);
    console.log(`  Uses Supabase: ${hasSupabase}`);
}

checkRoute('/executive-dashboard');
checkRoute('/customer-care');
