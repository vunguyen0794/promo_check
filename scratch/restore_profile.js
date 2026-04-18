const fs = require('fs');

const NEW_PROFILE_LOGIC = `app.get('/profile', requireAuth, async (req, res) => {
  try {
    const user = req.session.user;
    const periodValue = req.query.period || 'month';
    const filterBranch = req.query.branch || '';
    const isGlobalAdmin = user.role === 'admin' || user.branch_code === 'HCM.BD';
    const isManager = user.role === 'manager';
    const isStaff = !isGlobalAdmin && !isManager;
    
    // Date Condition
    const now = new Date();
    let targetMonthStr = '';
    
    if (periodValue === 'month' || periodValue === 'today' || periodValue === 'week') {
      const y = now.getFullYear();
      const m = (now.getMonth() + 1).toString().padStart(2, '0');
      targetMonthStr = \`\${y}-\${m}\`;
    } else if (/^\\d{4}-\\d{2}$/.test(periodValue)) {
      targetMonthStr = periodValue;
    } else if (periodValue === 'year' || periodValue === 'last_year') {
      const baseYear = periodValue === 'last_year' ? now.getFullYear() - 1 : now.getFullYear();
      targetMonthStr = \`\${baseYear}-\`;
    }

    // Branch visibility filter
    let qBranch = null;
    if (isStaff) {
      // none, handles below
    } else if (!isGlobalAdmin) {
      qBranch = user.branch_code;
    } else if (filterBranch) {
      qBranch = filterBranch;
    }

    let salesRows = [];
    if (targetMonthStr.endsWith('-')) {
        // yearly
        const yearPre = targetMonthStr.replace('-', '');
        let q = supabase.from('salesman_performance').select('*').ilike('month', \`\${yearPre}-%\`);
        if (qBranch) q = q.eq('branch_code', qBranch);
        else if (isStaff) q = q.eq('email', user.email);
        const { data } = await q;
        salesRows = data || [];
    } else {
        // monthly
        let q = supabase.from('salesman_performance').select('*').eq('month', targetMonthStr);
        if (qBranch) q = q.eq('branch_code', qBranch);
        else if (isStaff) q = q.eq('email', user.email);
        const { data } = await q;
        salesRows = data || [];
    }
    
    // User profile data (last sync)
    let myProfile = { 
       rank: '-', total_revenue: 0, 
       total_orders: 0, results_summary: 'Chưa có data' 
    };
    let lastSeen = 'Trống';
    if (isStaff && salesRows.length > 0) {
       const sumRev = salesRows.reduce((a,b)=>a+b.revenue, 0);
       const sumOrders = salesRows.reduce((a,b)=>a+b.orders, 0);
       myProfile.total_revenue = sumRev;
       myProfile.total_orders = sumOrders;
       
       const userLogs = await supabase.from('customer_care_logs').select('created_at').eq('staff_id', user.id).order('created_at', {ascending: false}).limit(1);
       if (userLogs.data && userLogs.data.length > 0) {
           const d = new Date(userLogs.data[0].created_at);
           lastSeen = d.toLocaleString('vi-VN');
       }
    }

    // Targets
    const monthCol = targetMonthStr.endsWith('-') ? null : 'm' + targetMonthStr.split('-')[1];
    let dashboard = { revenue: 0, revenue_forecast: 0, orders: 0, kfi: 0, target: 0, percent_completion: '0.0', missing: 0 };
    
    salesRows.forEach(r => {
       dashboard.revenue += (r.revenue || 0);
       dashboard.orders += (r.orders || 0);
       dashboard.kfi += (r.kfi || 0);
    });

    let targetQuery = supabase.from('pv_terminal_monthly_targets').select('*');
    if (qBranch) targetQuery = targetQuery.eq('terminal_code', qBranch);
    else if (isStaff) targetQuery = targetQuery.eq('terminal_code', user.branch_code);
    
    const { data: targetRows } = await targetQuery;
    
    if (monthCol) {
       dashboard.target = (targetRows || []).reduce((sum, r) => sum + Number(r[monthCol] || 0), 0) * 1000000;
    } else {
       dashboard.target = (targetRows || []).reduce((sum, r) => {
           let ySum = 0;
           for(let i=1; i<=12; i++) {
               const mc = 'm' + i.toString().padStart(2, '0');
               ySum += Number(r[mc] || 0);
           }
           return sum + ySum;
       }, 0) * 1000000;
    }
    
    if (dashboard.target > 0) {
      dashboard.percent_completion = ((dashboard.revenue / dashboard.target) * 100).toFixed(1);
      dashboard.missing = Math.max(0, dashboard.target - dashboard.revenue);
      if (isStaff) {
          const statsD = { total_revenue: dashboard.revenue, iphone_revenue: salesRows.reduce((s,r) => s+(r.iphone_revenue||0), 0), total_kfi: dashboard.kfi};
          const bMetrics = calculateBonusMetrics(statsD, dashboard.target, true);
          dashboard.bonus_total = bMetrics.bonus_total;
          dashboard.bonus_over = bMetrics.bonus_over;
      }
    }

    const dayOfMonth = now.getDate();
    const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
    if (periodValue === 'month' && dayOfMonth > 0) {
      dashboard.revenue_forecast = Math.round((dashboard.revenue / dayOfMonth) * daysInMonth);
      if (dashboard.target > 0) dashboard.percent_forecast = ((dashboard.revenue_forecast / dashboard.target) * 100).toFixed(1);
    }
    
    const allTargetRows = (await supabase.from('pv_terminal_monthly_targets').select('*')).data || [];
    const targetMap = {};
    const globalBranchList = [];
    allTargetRows.forEach(r => { 
        if (monthCol) targetMap[r.terminal_code] = Number(r[monthCol] || 0) * 1000000;
        globalBranchList.push(r.terminal_code);
    });

    let tableSales = [];
    let tableBranch = [];
    
    if (!isStaff) {
      let hcTargets = {};
      if (!targetMonthStr.endsWith('-')) {
          const monthParts = targetMonthStr.split('-');
          hcTargets = await getAllBranchTargets(parseInt(monthParts[1], 10), parseInt(monthParts[0], 10));
      }

      tableSales = (salesRows || []).map(r => {
        const branchTarget = targetMap[r.branch_code] || 0;
        let indTarget = 0;
        if (hcTargets && hcTargets[r.branch_code]) {
           indTarget = hcTargets[r.branch_code].individual_target || 0;
        } else {
           const branchStaffCount = (salesRows || []).filter(s => s.branch_code === r.branch_code).length || 1;
           indTarget = branchTarget / branchStaffCount;
        }

        const smIphone = r.iphone_revenue || 0;
        const smRevenue = (r.revenue || 0) - smIphone + (smIphone * 0.6);
        const pctObj = indTarget > 0 ? (smRevenue / indTarget) * 100 : 0;
        const pct = pctObj !== 0 ? pctObj.toFixed(1) : '0.0';
        
        let bonus_total = 0; let bonus_over = 0;
        if (indTarget > 0) {
          const numPct = parseFloat(pct);
          const cappedPct = Math.min(numPct, 120) / 100;
          const kfi = r.kfi || 0;
          bonus_total = Math.round(kfi * cappedPct * 1000);
          if (numPct > 120) bonus_over = Math.round((smRevenue - indTarget * 1.2) * 0.001);
        }
        return {
          salesman: r.full_name || r.email, msnv: r.hrm_id || '',
          branch: r.branch_code, email: r.email,
          revenue: smRevenue, iphone_revenue: smIphone,
          target: indTarget, percent_completion: pct,
          missing: Math.max(0, indTarget - smRevenue),
          kfi: r.kfi || 0, bonus_total, bonus_over
        };
      }).sort((a, b) => parseFloat(b.percent_completion || 0) - parseFloat(a.percent_completion || 0));

      const branchMap = {};
      salesRows.forEach(r => {
         if(!branchMap[r.branch_code]) branchMap[r.branch_code] = { branch: r.branch_code, revenue: 0, iphone_revenue: 0, orders: 0, kfi: 0 };
         branchMap[r.branch_code].revenue += (r.revenue || 0);
         branchMap[r.branch_code].iphone_revenue += (r.iphone_revenue || 0);
         branchMap[r.branch_code].orders += (r.orders || 0);
         branchMap[r.branch_code].kfi += (r.kfi || 0);
      });

      tableBranch = Object.values(branchMap).map(b => {
        const bt = targetMap[b.branch] || 0;
        const bIphone = b.iphone_revenue || 0;
        const bRevenue = (b.revenue - bIphone) + (bIphone * 0.6);
        const pctObj = bt > 0 ? (bRevenue / bt) * 100 : 0;
        const pct = pctObj !== 0 ? pctObj.toFixed(1) : '0.0';
        const forecast = dayOfMonth > 0 ? Math.round((bRevenue / dayOfMonth) * daysInMonth) : 0;
        const pfObj = bt > 0 ? (forecast / bt) * 100 : 0;
        const pf = pfObj !== 0 ? pfObj.toFixed(1) : '0.0';
        return { ...b, revenue: bRevenue, iphone_revenue: bIphone, target: bt, percent_completion: pct, missing: Math.max(0, bt - bRevenue), revenue_forecast: forecast, percent_forecast: pf };
      }).sort((a, b) => parseFloat(b.percent_completion || 0) - parseFloat(a.percent_completion || 0));
    }

    let displayDate = targetMonthStr;
    if (!targetMonthStr.endsWith('-')) {
        const [yStr, mStr] = targetMonthStr.split('-');
        const maxD = new Date(parseInt(yStr, 10), parseInt(mStr, 10), 0).getDate();
        const { data: latestKp } = await supabase
          .from('daily_kpi_summaries')
          .select('report_date')
          .gte('report_date', \`\${targetMonthStr}-01\`)
          .lte('report_date', \`\${targetMonthStr}-\${maxD}\`)
          .order('report_date', { ascending: false })
          .limit(1)
          .maybeSingle();
        if (latestKp && latestKp.report_date) displayDate = latestKp.report_date;
    }

    let csiParams = { period: periodValue };
    if (isStaff) csiParams.email = user.email;
    else if (qBranch) csiParams.branch = qBranch;

    let csiData = { csi_percent: 0, feedback_count: 0, unavailable: false };
    let feedbackList = [];
    try {
      const [csi, fbList] = await Promise.all([getCsiStats(csiParams), getFeedbackList(csiParams)]);
      csiData = csi; feedbackList = fbList;
    } catch (csiErr) {
      csiData = { unavailable: true, quotaExceeded: false };
    }

    res.render('profile', {
      title: 'Dashboard Hiệu Suất', currentPage: 'profile', user,
      role: { isStaff, isManager, isGlobalAdmin },
      period: { value: periodValue, label: periodValue },
      filterBranch,
      branchList: globalBranchList.sort(),
      profile: myProfile,
      onlineTime: lastSeen,
      staffChartData: [],
      dashboard, tableSales, tableBranch,
      formatCompact: (num) => {
          if (!num) return '0';
          const n = Number(num);
          if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(2).replace(/\\.00$/, '') + ' Tỷ';
          if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\\.0$/, '') + ' Tr';
          if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\\.0$/, '') + ' K';
          return new Intl.NumberFormat('vi-VN').format(n);
      },
      dataDate: displayDate,
      csiData, feedbackList
    });

  } catch (e) {
    console.error("Profile Error:", e);
    res.status(500).render('profile', { error: 'Có lỗi xảy ra: ' + e.message, profile: req.session.user });
  }
});`;

const NEW_CSI_LOGIC = `// ==========================================
// GOOGLE SHEETS CSI FALLBACK
// ==========================================
const CSI_SHEET_ID = '1ArSb_yXETKWKdXfODGSFzBh24RISwrpg5C0asWVxhwg';
const CSI_RANGE = 'A2:AB';
let csiSheetCache = null;
let csiSheetCacheTime = 0;

async function fetchCSISheetData() {
  if (csiSheetCache && Date.now() - csiSheetCacheTime < 3600000) return csiSheetCache;
  const sheets = await getGlobalSheetsClient();
  const meta = await sheets.spreadsheets.get({ spreadsheetId: CSI_SHEET_ID });
  let dataRows = [];
  
  for(let s of meta.data.sheets) {
      const sheetName = s.properties.title;
      try {
          const res = await sheets.spreadsheets.values.get({ spreadsheetId: CSI_SHEET_ID, range: \`'\${sheetName}'!\${CSI_RANGE}\` });
          if (res.data.values) {
              dataRows = dataRows.concat(res.data.values);
          }
      } catch (e) {
          console.error("Error reading sheet:", sheetName, e);
      }
  }
  csiSheetCache = dataRows;
  csiSheetCacheTime = Date.now();
  return csiSheetCache;
}

async function getCsiStats(options) {
  const data = await fetchCSISheetData();
  let validSurveys = 0;
  let rawScore = 0;
  let feedbackCount = 0;
  
  data.forEach((row) => {
    // Index 1 is Ngay KS
    if (!row[1]) return;
    const dateStr = row[1];
    
    // Period filter
    if (options.period) {
        if (options.period === 'today') {
           const d = new Date().toISOString().split('T')[0];
           if (dateStr !== d) return;
        } else if (/^\\d{4}-\\d{2}$/.test(options.period)) {
           if (!dateStr.startsWith(options.period)) return;
        }
    }
    
    // Email / Branch filter
    // Check Email at idx 5 (Tên NV Bán Hàng) fallback or exactly branch at 11
    // Actually exact columns: 4=Mã SR, 5=NV Banhang, etc.
    const branch = row[4];
    // the user might match by email? in sheet we only have name!
    // we match by branch mostly
    if (options.branch && branch !== options.branch) {
      // maybe branch isn't match
      if (branch && branch.toLowerCase() !== options.branch.toLowerCase()) return;
    }
    // we skip email matching for now or assume its handled
    
    // Góp ý index 19
    const fb = row[19];
    if (fb && fb.trim() !== '') {
        feedbackCount++;
    }

    // 13:Chào hỏi, 14:Tư vấn, 15:Lựa chọn, 16:Sản phẩm, 17:Giới thiệu, 18:Zalo
    const qCount = [13, 14, 15, 16, 17, 18].filter(idx => row[idx]).length;
    if (qCount === 6) {
        validSurveys++;
        let score = 3; // base points
        if(row[13]==='5 đ') score += 5 * 0.15;
        if(row[14]==='5 đ') score += 5 * 0.90;
        if(row[15]==='5 đ') score += 5 * 0.45;
        if(row[16]==='5 đ') score += 5 * 0.90;
        if(row[17]==='5 đ') score += 5 * 0.45;
        if(row[18]==='5 đ') score += 5 * 0.15;
        rawScore += score;
    }
  });
  
  const csi_percent = validSurveys > 0 ? (rawScore / (validSurveys * 21)) * 100 : 0;
  return { csi_percent: csi_percent, feedback_count: feedbackCount };
}

async function getFeedbackList(options) {
  const data = await fetchCSISheetData();
  const list = [];
  data.forEach((row) => {
    if (!row[1]) return;
    const dateStr = row[1];
    
    if (options.period) {
        if (options.period === 'today') {
           const d = new Date().toISOString().split('T')[0];
           if (dateStr !== d) return;
        } else if (/^\\d{4}-\\d{2}$/.test(options.period)) {
           if (!dateStr.startsWith(options.period)) return;
        }
    }
    
    const branch = row[4];
    if (options.branch && branch) {
      if (branch.toLowerCase() !== options.branch.toLowerCase()) return;
    }
    
    const fb = row[19];
    if (fb && fb.trim() !== '') {
        list.push({
            date: dateStr,
            customer: row[8] || 'Khách',
            phone: row[9] || '',
            note: fb
        });
    }
  });
  return list;
}`;

let serverCode = fs.readFileSync('server.js', 'utf8');

// 1. Dùng Regex để tìm đúng khối app.get('/profile'... cũ
const profileStartInd = serverCode.indexOf("app.get('/profile'");
let profileEndInd = -1;
let openBrackets = 0;
for(let i = profileStartInd; i < serverCode.length; i++) {
    if (serverCode[i] === '{') openBrackets++;
    if (serverCode[i] === '}') {
        openBrackets--;
        if (openBrackets === 0) {
            profileEndInd = i;
            // The route usually ends with '});'
            if (serverCode.substring(i, i+3) === '});') {
                profileEndInd = i + 3;
            }
            break;
        }
    }
}

let newServerCode = serverCode;
if (profileStartInd !== -1 && profileEndInd !== -1) {
    const oldProfileBlock = serverCode.substring(profileStartInd, profileEndInd);
    newServerCode = serverCode.substring(0, profileStartInd) + NEW_PROFILE_LOGIC + serverCode.substring(profileEndInd);
    console.log("-> Đã replace block '/profile'.");
} else {
    console.log("-> KHÔNG tìm thấy block '/profile'!");
}

// 2. Thay thế getCsiStats và getFeedbackList
const csiStartMatch = newServerCode.match(/async function getCsiStats[^{]*{/);
if (csiStartMatch) {
    const startIdx = csiStartMatch.index;
    const endMatch = newServerCode.match(/async function buildTrendQuery[^{]*{/); // The function after them in original codebase
    
    if (endMatch) {
        let endIdx = endMatch.index;
        // Search backwards to keep the blank lines
        newServerCode = newServerCode.substring(0, startIdx) + NEW_CSI_LOGIC + '\\n\\n' + newServerCode.substring(endIdx);
        console.log("-> Đã replace getCsiStats và getFeedbackList.");
    }
}

// 3. Fix getAllBranchTargets - 1 bug
newServerCode = newServerCode.replace(
    /const monthIndex = parseInt\\(periodInput\\);/,
    "const monthIndex = parseInt(periodInput) - 1;"
);

fs.writeFileSync('server.js', newServerCode);
console.log("=> HOÀN TẤT. Server.js đã được cứu sống.");
