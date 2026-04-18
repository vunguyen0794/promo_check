const fs = require('fs');
const csv = require('csv-parser');
const zlib = require('zlib');

async function getLocalSalesRows(periodValue, targetEmail = null, targetBranch = null) {
    const year = new Date().getFullYear();
    let csvPath = `D:/_Báo cáo/Báo cáo doanh thu/2025/sales_${year}_merged.csv`;
    let isGz = false;
    
    if (!fs.existsSync(csvPath)) {
        if (fs.existsSync(csvPath + '.gz')) {
            csvPath += '.gz';
            isGz = true;
        } else {
            console.warn("Local sales file not found:", csvPath);
            return [];
        }
    }

    // Determine target dates
    const now = new Date();
    let targetDates = new Set();
    
    if (periodValue === 'today') {
        targetDates.add(now.toISOString().split('T')[0]);
    } else if (periodValue === 'week') {
        const d = new Date(now);
        const day = d.getDay() || 7; // 1-7
        d.setDate(d.getDate() - day + 1); // Monday
        for(let i=0; i<7; i++) {
            targetDates.add(d.toISOString().split('T')[0]);
            d.setDate(d.getDate() + 1);
        }
    } else {
        // If it's a specific month, parse the whole month (though usually handled by Supabase)
        // just return empty here if we don't handle it
        return [];
    }

    const salesmanMap = new Map();

    return new Promise((resolve, reject) => {
        const stream = isGz ? fs.createReadStream(csvPath).pipe(zlib.createGunzip()) : fs.createReadStream(csvPath);
        stream.pipe(csv())
            .on('data', (row) => {
                const reportDateRaw = row['Report date'] || row['Report_date'] || row['Column1'];
                if (!reportDateRaw) return;
                
                const date = new Date(reportDateRaw);
                if (isNaN(date.getTime())) return;
                const dateStr = date.toISOString().split('T')[0];
                
                if (!targetDates.has(dateStr)) return;

                const branchCode = row['Branch_code'] || row['Branch code'];
                if (targetBranch && branchCode !== targetBranch) return;

                const email = (row['Email'] || row['Sales_Email']) ? (row['Email'] || row['Sales_Email']).toLowerCase().trim() : null;
                if (!email) return;
                if (targetEmail && email !== targetEmail) return;

                const revenue = parseFloat(row['Revenue'] || row['Revenue_with_VAT'] || 0);
                const orderCode = row['Order_code'] || row['Order code'];
                const orderType = row['Order_type'] || row['Order type'];
                const salesman = row['Salesman'] || row['Sales_Name'] || 'Unknown';
                const hrmId = row['HRM_ID'] || row['HRM ID'] || '';
                const subcatId = (row['Subcat_ID_lowest_level'] || row['Subcat ID lowest level'] || '').trim();
                const isIphone = subcatId === 'NH05-02-01-01';
                const kfi = parseFloat(row['Sale_point_per_item'] || row['Sale point per item'] || row['KFI'] || 0);

                if (!salesmanMap.has(email)) {
                    salesmanMap.set(email, { 
                        email, 
                        hrm_id: hrmId, 
                        full_name: salesman, 
                        branch_code: branchCode, 
                        revenue: 0, 
                        iphone_revenue: 0, 
                        orders: new Set(), 
                        kfi: 0 
                    });
                }
                const sm = salesmanMap.get(email);
                sm.revenue += revenue;
                sm.kfi += kfi;
                if (isIphone) sm.iphone_revenue += revenue;
                if (orderType === 'don_xuat_ban' || orderType === 'Export') sm.orders.add(orderCode);
            })
            .on('end', () => {
                const results = Array.from(salesmanMap.values()).map(sm => ({
                    ...sm,
                    orders: sm.orders.size
                }));
                resolve(results);
            })
            .on('error', reject);
    });
}

module.exports = { getLocalSalesRows };
