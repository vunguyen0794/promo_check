// GET /api/executive/sales-data - Dynamic logic with Traffic, 4-Delta, and Trend Generation
app.get('/api/executive/sales-data', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    if (user.role !== 'manager' && user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });

    const { period = 'month', category = 'ALL', region = 'ALL', branch = 'ALL', date = null, tableCategory = 'ALL' } = req.query;
    const ranges = getDashboardDateRange(period, date);

    const minS = ranges.ly.s, currE = ranges.curr.e;
    let globalWhere = `WHERE (CAST(Report_date AS DATE) BETWEEN '${minS}' AND '${currE}')`;
    if (category !== 'ALL') globalWhere += ` AND Category_Code = '${category}'`;
    
    let tableWhere = `WHERE (CAST(Report_date AS DATE) BETWEEN '${minS}' AND '${currE}')`;
    if (tableCategory === 'CUSTOM_1') {
        tableWhere += ` AND Category_Code IN ('NH01', 'NH02', 'NH03', 'NH05')`;
    } else if (tableCategory !== 'ALL') {
        tableWhere += ` AND Category_Code = '${tableCategory}'`;
    }
    
    // Explicit Branch or Region Filter appled to both
    let filterBranches = EXECUTIVE_BRANCH_LIST.map(b => b.id);
    if (branch !== 'ALL') {
       globalWhere += ` AND Branch_Code = '${branch}'`;
       tableWhere += ` AND Branch_Code = '${branch}'`;
       filterBranches = [branch];
    } else if (region !== 'ALL') {
       const regB = EXECUTIVE_BRANCH_LIST.filter(b => b.region === region).map(b => b.id);
       globalWhere += ` AND Branch_Code IN (${regB.map(id => `'${id}'`).join(',')})`;
       tableWhere += ` AND Branch_Code IN (${regB.map(id => `'${id}'`).join(',')})`;
       filterBranches = regB;
    } else {
       globalWhere += ` AND Branch_Code IN (${filterBranches.map(id => `'${id}'`).join(',')})`;
       tableWhere += ` AND Branch_Code IN (${filterBranches.map(id => `'${id}'`).join(',')})`;
    }

    const bqQueryGlobal = `SELECT Branch_Code as branch, CAST(Report_date AS DATE) as date, SUM(Revenue) as revenue, COUNT(DISTINCT CASE WHEN Order_type = 'don_xuat_ban' THEN Order_code END) - COUNT(DISTINCT CASE WHEN Order_type = 'don_nhap_hoan_ban' THEN Order_code END) as orders FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\` ${globalWhere} GROUP BY branch, date ORDER BY date ASC`;
    const bqQueryTable = `SELECT Branch_Code as branch, CAST(Report_date AS DATE) as date, SUM(Revenue) as revenue, COUNT(DISTINCT CASE WHEN Order_type = 'don_xuat_ban' THEN Order_code END) - COUNT(DISTINCT CASE WHEN Order_type = 'don_nhap_hoan_ban' THEN Order_code END) as orders FROM \`nimble-volt-459313-b8.sales.raw_sales_orders_all\` ${tableWhere} GROUP BY branch, date ORDER BY date ASC`;

    const [globalRes, tableRes, traffic] = await Promise.all([
      bq.query({ query: bqQueryGlobal }),
      tableCategory === category ? Promise.resolve(null) : bq.query({ query: bqQueryTable }),
      fetchTrafficStats(ranges)
    ]);
    
    const globalRows = globalRes[0];
    const tableRows = tableRes ? tableRes[0] : globalRows;

    // Fetch master targets mapping globally 
    const monthCol = `m${String(new Date(ranges.curr.rawS).getMonth() + 1).padStart(2, '0')}`;
    const { data: tgtRows } = await supabase.from('pv_terminal_monthly_targets').select(`terminal_code, ${monthCol}`);
    const targets = {};
    (tgtRows || []).forEach(r => targets[r.terminal_code] = Number(r[monthCol] || 0));

    // Create parsing helper for creating branch structures
    const processRows = (rowsData) => {
        const struct = filterBranches.map(code => {
            const inf = EXECUTIVE_BRANCH_LIST.find(b => b.id === code) || {};
            const trMap = traffic && traffic[code] ? traffic[code] : { curr:0, prev:0, lw:0, lm:0, lq:0, ly:0 };
            const m = { r:0, o:0, t: trMap.curr };
            return {
                id: code, name: inf.name, region: inf.region, target: targets[code],
                data: { 
                   curr:{...m}, prev:{...m, t:trMap.prev}, 
                   lw:{...m, t:trMap.lw}, lm:{...m, t:trMap.lm}, 
                   lq:{...m, t:trMap.lq}, ly:{...m, t:trMap.ly} 
                },
                _ts: {} // For trends
            };
        });

        rowsData.forEach(r => {
            const b = struct.find(x => x.id === r.branch);
            if (!b) return;
            const ds = r.date.value;
            const rev = r.revenue || 0, ord = r.orders || 0;
            
            if (!b._ts[ds]) b._ts[ds] = { r:0, o:0 };
            b._ts[ds].r += rev; b._ts[ds].o += ord;
            
            if (ds >= ranges.curr.s && ds <= ranges.curr.e) { b.data.curr.r += rev; b.data.curr.o += ord; }
            if (ds >= ranges.prev.s && ds <= ranges.prev.e) { b.data.prev.r += rev; b.data.prev.o += ord; }
            if (ds >= ranges.lw.s && ds <= ranges.lw.e) { b.data.lw.r += rev; b.data.lw.o += ord; }
            if (ds >= ranges.lm.s && ds <= ranges.lm.e) { b.data.lm.r += rev; b.data.lm.o += ord; }
            if (ds >= ranges.lq.s && ds <= ranges.lq.e) { b.data.lq.r += rev; b.data.lq.o += ord; }
            if (ds >= ranges.ly.s && ds <= ranges.ly.e) { b.data.ly.r += rev; b.data.ly.o += ord; }
        });
        return struct;
    };

    const globalBranches = processRows(globalRows);
    const tableBranches = tableCategory === category ? globalBranches : processRows(tableRows);

    // Rollup from Global Branches to Global Level KPIs
    const roll = (periodKey) => globalBranches.reduce((acc, b) => {
      acc.r += b.data[periodKey].r; acc.o += b.data[periodKey].o; acc.t += b.data[periodKey].t;
      return acc;
    }, { r:0, o:0, t:0, a:0 });

    const currentMap = roll('curr');
    currentMap.a = currentMap.o > 0 ? currentMap.r / currentMap.o : 0;
    
    // Sums 4-periods
    const sums = ['prev', 'lw', 'lm', 'lq', 'ly'].reduce((acc, k) => {
      const obj = roll(k);
      obj.a = obj.o > 0 ? obj.r / obj.o : 0;
      acc[k] = obj;
      return acc;
    }, {});

    // Target total
    const current = {
      revenue: currentMap.r, orders: currentMap.o, traffic: currentMap.t, aov: currentMap.a,
      target: globalBranches.reduce((a, b) => a + (b.target || 0), 0)
    };

    // Trend Generator from Global Branches
    const trendData = { labels: [], revenue: [], orders: [], traffic: [], aov: [] };
    const currSObj = new Date(ranges.curr.rawS);
    const nowLocalForTrend = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Ho_Chi_Minh" }));
    nowLocalForTrend.setHours(23, 59, 59, 999);

    while (currSObj <= new Date(ranges.curr.rawE) && currSObj <= nowLocalForTrend) {
      const ds = formatVNDate(currSObj);
      trendData.labels.push(ds.substring(5)); // MM-DD
      let dR = 0, dO = 0, dT = 0;
      globalBranches.forEach(b => {
          if (b._ts[ds]) { dR += b._ts[ds].r; dO += b._ts[ds].o; }
          const trafficSource = traffic && traffic[b.id] && traffic[b.id]._ts ? traffic[b.id]._ts[ds] : 0;
          dT += trafficSource || 0;
      });
      trendData.revenue.push(dR); trendData.orders.push(dO);
      trendData.traffic.push(dT); trendData.aov.push(dO > 0 ? dR / dO : 0);
      currSObj.setDate(currSObj.getDate() + 1);
    }
    
    const nowLocal = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Ho_Chi_Minh" }));
    const elapsed = ranges.curr.rawE > ranges.curr.rawS ? Math.min(100, Math.max(0, ((nowLocal - ranges.curr.rawS) / (ranges.curr.rawE - ranges.curr.rawS)) * 100)) : 0;
    const daysLeft = Math.max(0, Math.ceil((ranges.curr.rawE - nowLocal) / 86400000));

    let actualDataEndDate = ranges.curr.e;
    if (globalRows && globalRows.length > 0) {
        const allDates = globalRows.map(r => r.date ? r.date.value : null).filter(Boolean).sort();
        if (allDates.length > 0) actualDataEndDate = allDates[allDates.length - 1];
    }

    res.json({ 
      startDate: ranges.curr.s, endDate: ranges.curr.e, dataUpdatedAt: actualDataEndDate,
      daysLeft, elapsedPercent: elapsed.toFixed(0), 
      current, 
      sums, 
      branches: tableBranches,
      globalBranches,
      trends: trendData 
    });
  } catch (e) {
    console.error('EXECUTIVE API CRITICAL ERROR:', e);
    res.status(500).json({ error: e.message || 'Internal Server Error' });
  }
});
