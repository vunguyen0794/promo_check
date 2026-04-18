const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const csv = require('csv-parser');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Initialize Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const SALES_FILES = [
    { year: 2024, path: "D:/_Báo cáo/Báo cáo doanh thu/2025/sales_2024_merged.csv" },
    { year: 2025, path: "D:/_Báo cáo/Báo cáo doanh thu/2025/sales_2025_merged.csv" },
    { year: 2026, path: "D:/_Báo cáo/Báo cáo doanh thu/2025/sales_2026_merged.csv" }
];

// Check for .gz versions if .csv doesn't exist
SALES_FILES.forEach(f => {
    if (!fs.existsSync(f.path) && fs.existsSync(f.path + ".gz")) {
        f.path = f.path + ".gz";
        f.isGz = true;
    }
});

async function syncSalesData() {
    console.log(`[${new Date().toLocaleString()}] Starting Full Sales Sync (2024-2026)...`);

    const customerMap = new Map();
    const customerMonthlyMap = new Map(); // New: Monthly aggregation
    const dailyKpiMap = new Map();
    const salesmanMap = new Map();

    for (const fileObj of SALES_FILES) {
        if (!fs.existsSync(fileObj.path)) {
            console.warn(`File not found: ${fileObj.path}. Skipping...`);
            continue;
        }

        console.log(`Processing ${fileObj.year} data from ${fileObj.path}...`);

        const stream = fileObj.isGz
            ? fs.createReadStream(fileObj.path).pipe(zlib.createGunzip())
            : fs.createReadStream(fileObj.path);

        await new Promise((resolve, reject) => {
            stream.pipe(csv())
                .on('data', (row) => {
                    try {
                        // Handle potential header differences (Column1)
                        const reportDateRaw = row['Report date'] || row['Report_date'] || row['Column1']; // Fallback for 2024 header
                        if (!reportDateRaw || reportDateRaw === 'Report date') return;

                        const date = new Date(reportDateRaw);
                        if (isNaN(date.getTime())) return;

                        const dateStr = date.toISOString().split('T')[0];
                        const monthStr = dateStr.substring(0, 7); // YYYY-MM
                        const branchCode = row['Branch_code'] || row['Branch code'];
                        const revenue = parseFloat(row['Revenue'] || row['Revenue_with_VAT'] || 0);
                        const orderCode = row['Order_code'] || row['Order code'];
                        const orderType = row['Order_type'] || row['Order type'];
                        const email = (row['Email'] || row['Sales_Email']) ? (row['Email'] || row['Sales_Email']).toLowerCase().trim() : null;
                        const salesman = row['Salesman'] || row['Sales_Name'] || 'Unknown';
                        const hrmId = row['HRM_ID'] || row['HRM ID'] || '';
                        const subcatId = (row['Subcat_ID_lowest_level'] || row['Subcat ID lowest level'] || '').trim();
                        const isIphone = subcatId === 'NH05-02-01-01';
                        // KFI: CSV uses Sale_point_per_item (underscore) - fallback to space version for older files
                        const kfi = parseFloat(row['Sale_point_per_item'] || row['Sale point per item'] || row['KFI'] || 0);

                        const taxCode = (row['Billing_tax_code'] || row['Billing tax code'] || row['Tax_Code'] || '').trim();
                        const customerName = row['Customer_full_name'] || row['Customer full name'] || row['Customer_Name'] || 'Khách lẻ';
                        const phone = row['SDT'] || row['Phone'] || '';

                        // Normalize tax code (remove leading zeros if inconsistent, but match BQ logic)
                        const normalizedTax = taxCode || customerName;

                        // 1. Aggregate Daily KPI (Executive Dashboard)
                        const kpiKey = `${dateStr}_${branchCode}`;
                        if (!dailyKpiMap.has(kpiKey)) {
                            dailyKpiMap.set(kpiKey, { report_date: dateStr, branch_code: branchCode, revenue: 0, order_count: new Set() });
                        }
                        const kpi = dailyKpiMap.get(kpiKey);
                        kpi.revenue += revenue;
                        if (orderType === 'don_xuat_ban' || orderType === 'Export') kpi.order_count.add(orderCode);

                        // 2. Aggregate Salesman Performance (Profile)
                        if (email) {
                            const smKey = `${email}_${monthStr}`;
                            if (!salesmanMap.has(smKey)) {
                                salesmanMap.set(smKey, { email, month: monthStr, hrm_id: hrmId, full_name: salesman, branch_code: branchCode, revenue: 0, iphone_revenue: 0, orders: new Set(), kfi: 0 });
                            }
                            const sm = salesmanMap.get(smKey);
                            sm.revenue += revenue;
                            sm.kfi += kfi;
                            if (isIphone) sm.iphone_revenue += revenue;
                            if (orderType === 'don_xuat_ban' || orderType === 'Export') sm.orders.add(orderCode);
                        }

                        // 3. Aggregate Customer Summary (All-time - CSKH Info)
                        if (normalizedTax) {
                            if (!customerMap.has(normalizedTax)) {
                                customerMap.set(normalizedTax, { tax_code: normalizedTax, customer_name: customerName, phone, total_revenue: 0, order_count: new Set(), last_purchase_date: dateStr });
                            }
                            const cust = customerMap.get(normalizedTax);
                            cust.total_revenue += revenue;
                            if (orderType === 'don_xuat_ban' || orderType === 'Export') cust.order_count.add(orderCode);
                            if (dateStr > cust.last_purchase_date) cust.last_purchase_date = dateStr;

                            // 4. Aggregate Customer Monthly (Filtered CSKH Worklist)
                            const custMonthKey = `${normalizedTax}_${monthStr}`;
                            if (!customerMonthlyMap.has(custMonthKey)) {
                                customerMonthlyMap.set(custMonthKey, { tax_code: normalizedTax, month: monthStr, customer_name: customerName, revenue: 0, order_count: new Set() });
                            }
                            const cm = customerMonthlyMap.get(custMonthKey);
                            cm.revenue += revenue;
                            if (orderType === 'don_xuat_ban' || orderType === 'Export') cm.order_count.add(orderCode);
                        }

                    } catch (e) {
                        // Skip malformed rows
                    }
                })
                .on('end', () => resolve())
                .on('error', (err) => reject(err));
        });
    }

    console.log(`Aggregation complete. Customers: ${customerMap.size}, Monthly Cust: ${customerMonthlyMap.size}, KPIs: ${dailyKpiMap.size}, Salesmen: ${salesmanMap.size}`);

    // Convert sets to counts for DB
    const dailyKpiData = Array.from(dailyKpiMap.values()).map(k => ({ ...k, order_count: k.order_count.size }));
    const salesmanData = Array.from(salesmanMap.values()).map(s => ({ ...s, orders: s.orders.size }));
    const customerData = Array.from(customerMap.values()).map(c => ({ ...c, order_count: c.order_count.size }));
    const customerMonthlyData = Array.from(customerMonthlyMap.values()).map(cm => ({ ...cm, order_count: cm.order_count.size }));

    // Upsert to Supabase in batches
    console.log("Upserting Daily KPIs...");
    await upsertInBatches('daily_kpi_summaries', dailyKpiData, ['report_date', 'branch_code']);

    console.log("Upserting Salesman Performance...");
    await upsertInBatches('salesman_performance', salesmanData, ['email', 'month']);

    console.log("Upserting Customer Summaries...");
    await upsertInBatches('customer_summaries', customerData, ['tax_code']);

    console.log("Upserting Customer Monthly Summaries...");
    await upsertInBatches('customer_monthly_summaries', customerMonthlyData, ['tax_code', 'month']);

    console.log(`[${new Date().toLocaleString()}] Sync Finished!`);
}


async function upsertInBatches(table, data, onConflictColumns) {
    const BATCH_SIZE = 500;
    for (let i = 0; i < data.length; i += BATCH_SIZE) {
        const batch = data.slice(i, i + BATCH_SIZE);
        const { error } = await supabase
            .from(table)
            .upsert(batch, { onConflict: onConflictColumns.join(',') });

        if (error) {
            console.error(`Error upserting ${table} batch at index ${i}:`, error.message);
        }
        if (i % 5000 === 0 && i !== 0) console.log(`Processed ${i} rows for ${table}...`);
    }
}

if (require.main === module) {
    syncSalesData().catch(console.error);
}

module.exports = { syncSalesData };
