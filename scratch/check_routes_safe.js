const fs = require('fs');
const code = fs.readFileSync('server.js', 'utf8');

const routesToFind = ['/executive-dashboard', '/customer-care', '/sales-dashboard'];

for (const route of routesToFind) {
    const routeIndex = code.indexOf(`app.get('${route}'`);
    if (routeIndex !== -1) {
        const nextRouteIndex = code.indexOf('app.get(', routeIndex + 10);
        const limit = nextRouteIndex !== -1 ? nextRouteIndex : code.length;
        const segment = code.substring(routeIndex, limit);
        
        console.log(`Route: ${route}`);
        console.log(`- Uses BigQuery? : ${segment.includes('bigquery')}`);
        console.log(`- Uses Supabase? : ${segment.includes('supabase')}`);
    } else {
        console.log(`Route: ${route} NOT FOUND`);
    }
}
