/**
 * Phong Vũ ERP Auto Sync - content.js
 * Chạy trên https://erp.phongvu.vn/*
 * Tự động tìm kiếm Token ERP (TekoID / IndexedDB / Storage / API Interception)
 * và đồng bộ về hệ thống Xuất kho nhanh.
 */
(function() {
  const DEFAULT_ORIGINS = ['http://localhost:3300', 'http://127.0.0.1:3300', 'http://222.255.184.49'];
  let _lastSyncedToken = '';
  let _isSyncing = false;

  // -------------------------------------------------------------
  // 1. INJECT SCRIPT VÀO MAIN WORLD ĐỂ TRUY CẬP window.TekoID VÀ INTERCEPT FETCH/XHR
  // -------------------------------------------------------------
  function injectMainWorldScript() {
    try {
      const scriptCode = `(function() {
        let sentToken = '';

        function dispatchFoundToken(tok, source) {
          if (!tok || typeof tok !== 'string') return;
          const clean = tok.replace(/^Bearer\\s+/i, '').trim();
          if (clean.length < 30 || !clean.startsWith('eyJ')) return;
          if (clean === sentToken) return;
          sentToken = clean;
          window.dispatchEvent(new CustomEvent('__PV_TOKEN_DISPATCH__', {
            detail: { token: clean, source: source || 'main-world' }
          }));
        }

        // A. Thử trích xuất từ window.TekoID
        function tryTekoID() {
          try {
            if (window.TekoID) {
              if (window.TekoID.user && typeof window.TekoID.user.getAccessToken === 'function') {
                const t = window.TekoID.user.getAccessToken();
                if (t) dispatchFoundToken(t, 'window.TekoID.user');
              } else if (typeof window.TekoID.getAccessToken === 'function') {
                const t = window.TekoID.getAccessToken();
                if (t) dispatchFoundToken(t, 'window.TekoID');
              }
            }
          } catch(e) {}
        }

        // B. Monkey-patch window.fetch để bắt mọi token gọi API trên ERP
        try {
          const origFetch = window.fetch;
          window.fetch = function(...args) {
            try {
              const opts = args[1];
              if (opts && opts.headers) {
                let auth = '';
                if (opts.headers instanceof Headers) {
                  auth = opts.headers.get('authorization') || opts.headers.get('x-teko-token') || '';
                } else if (typeof opts.headers === 'object') {
                  auth = opts.headers['Authorization'] || opts.headers['authorization'] || opts.headers['x-teko-token'] || '';
                }
                if (auth && auth.includes('eyJ')) {
                  dispatchFoundToken(auth, 'fetch-interceptor');
                }
              }
            } catch(e) {}
            return origFetch.apply(this, args);
          };
        } catch(e) {}

        // C. Monkey-patch XMLHttpRequest
        try {
          const origSetHeader = XMLHttpRequest.prototype.setRequestHeader;
          XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
            try {
              if (header && (header.toLowerCase() === 'authorization' || header.toLowerCase() === 'x-teko-token')) {
                if (value && value.includes('eyJ')) {
                  dispatchFoundToken(value, 'xhr-interceptor');
                }
              }
            } catch(e) {}
            return origSetHeader.apply(this, arguments);
          };
        } catch(e) {}

        // Chạy kiểm tra định kỳ
        tryTekoID();
        setInterval(tryTekoID, 2000);
      })();`;

      const scriptEl = document.createElement('script');
      scriptEl.textContent = scriptCode;
      (document.head || document.documentElement).appendChild(scriptEl);
      scriptEl.remove();
    } catch (e) {}
  }

  // -------------------------------------------------------------
  // 2. TÌM TOKEN TRONG LOCALSTORAGE & SESSIONSTORAGE
  // -------------------------------------------------------------
  function scanStorage(storage) {
    if (!storage) return '';
    try {
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        const val = storage.getItem(key) || '';

        // Raw JWT
        if (val.startsWith('eyJ') && val.length > 40) return val;

        // JSON parse
        try {
          const parsed = JSON.parse(val);
          if (parsed && typeof parsed === 'object') {
            const t = parsed.access_token || parsed.accessToken || parsed.id_token || parsed.token;
            if (t && typeof t === 'string' && t.startsWith('eyJ') && t.length > 30) return t;

            if (parsed.currentUser) {
              const ct = parsed.currentUser.access_token || parsed.currentUser.accessToken || parsed.currentUser.token;
              if (ct && typeof ct === 'string' && ct.startsWith('eyJ') && ct.length > 30) return ct;
            }
          }
        } catch (err) {}
      }
    } catch (e) {}
    return '';
  }

  // -------------------------------------------------------------
  // 3. TÌM TOKEN TRONG INDEXEDDB (TẤT CẢ DATABASE)
  // -------------------------------------------------------------
  async function scanAllIndexedDBs() {
    try {
      const dbs = (indexedDB.databases ? await indexedDB.databases() : []) || [];
      const names = dbs.map(d => d.name).filter(Boolean);
      if (!names.includes('ERPAdminLocalDB')) names.push('ERPAdminLocalDB');

      for (const dbName of names) {
        const tok = await new Promise(resolve => {
          try {
            const req = indexedDB.open(dbName);
            req.onerror = () => resolve('');
            req.onsuccess = (e) => {
              try {
                const db = e.target.result;
                const storeNames = Array.from(db.objectStoreNames || []);
                if (!storeNames.length) { db.close(); return resolve(''); }

                const tx = db.transaction(storeNames, 'readonly');
                let found = '';
                let remaining = storeNames.length;

                storeNames.forEach(sName => {
                  const store = tx.objectStore(sName);
                  const getReq = store.getAll();
                  getReq.onsuccess = (ev) => {
                    const items = ev.target.result || [];
                    for (const it of items) {
                      if (found) break;
                      if (typeof it === 'string' && it.startsWith('eyJ')) { found = it; break; }
                      if (it && typeof it === 'object') {
                        const t = it.accessToken || it.access_token || it.token || it.id_token;
                        if (t && typeof t === 'string' && t.startsWith('eyJ')) { found = t; break; }
                      }
                    }
                    remaining--;
                    if (remaining === 0 || found) { db.close(); resolve(found); }
                  };
                  getReq.onerror = () => {
                    remaining--;
                    if (remaining === 0) { db.close(); resolve(found); }
                  };
                });
              } catch (err) { resolve(''); }
            };
          } catch (err) { resolve(''); }
        });
        if (tok) return tok;
      }
    } catch (e) {}
    return '';
  }

  // -------------------------------------------------------------
  // 4. LẤY DANH SÁCH TARGET ORIGIN VÀ USER_ID TỪ CHROME.STORAGE
  // -------------------------------------------------------------
  async function getTargetOriginsAndUser() {
    return new Promise(resolve => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['app_origin', 'app_user_id', 'app_user_email', 'app_branch_code'], data => {
          const list = [...DEFAULT_ORIGINS];
          if (data && data.app_origin && !list.includes(data.app_origin)) {
            list.unshift(data.app_origin);
          }
          resolve({
            origins: list,
            userId: data ? (data.app_user_id || '') : '',
            userEmail: data ? (data.app_user_email || '') : '',
            branchCode: data ? (data.app_branch_code || '') : ''
          });
        });
      } else {
        resolve({ origins: DEFAULT_ORIGINS, userId: '', userEmail: '', branchCode: '' });
      }
    });
  }

  // -------------------------------------------------------------
  // 5. HIỂN THỊ TOAST THÔNG BÁO TRÊN ERP
  // -------------------------------------------------------------
  function showSyncToast(origin) {
    if (document.getElementById('pv-erp-sync-toast')) return;
    const toast = document.createElement('div');
    toast.id = 'pv-erp-sync-toast';
    toast.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 99999999;
      background: #ffffff;
      border: 2px solid #16a34a;
      border-radius: 12px;
      padding: 14px 18px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.25);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 360px;
      display: flex;
      align-items: center;
      gap: 12px;
      animation: pvSlideIn 0.3s ease;
    `;
    toast.innerHTML = `
      <div style="font-size: 24px;">⚡</div>
      <div style="flex: 1;">
        <div style="font-weight: 800; font-size: 13px; color: #15803d; margin-bottom: 2px;">
          Phong Vũ Auto Sync
        </div>
        <div style="font-size: 12px; color: #334155; line-height: 1.4;">
          Đã đồng bộ kết nối ERP sang Xuất Kho Nhanh thành công!
        </div>
      </div>
      <button id="pv-toast-close" style="border:none;background:none;font-size:16px;cursor:pointer;color:#94a3b8;padding:0;">&times;</button>
    `;
    document.body.appendChild(toast);
    document.getElementById('pv-toast-close').onclick = () => toast.remove();
    setTimeout(() => { if (toast.parentNode) toast.remove(); }, 6000);
  }

  // -------------------------------------------------------------
  // 6. GỬI TOKEN VỀ HỆ THỐNG XUẤT KHO NHANH
  // -------------------------------------------------------------
  async function sendTokenToApp(rawToken) {
    if (!rawToken || _isSyncing) return;
    const cleanToken = rawToken.replace(/^Bearer\s+/i, '').trim();
    if (cleanToken.length < 30 || !cleanToken.startsWith('eyJ')) return;
    if (cleanToken === _lastSyncedToken) return;

    _isSyncing = true;
    _lastSyncedToken = cleanToken;

    const target = await getTargetOriginsAndUser();

    for (const origin of target.origins) {
      try {
        // Gửi POST
        fetch(origin + '/api/quick-export/sync-token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: cleanToken,
            userId: target.userId || '',
            userEmail: target.userEmail || '',
            branchCode: target.branchCode || ''
          }),
          mode: 'cors'
        })
        .then(res => res.json())
        .then(data => {
          if (data && data.success) {
            console.log('[Phong Vũ Auto Sync] Đã gửi token tới ' + origin + ' thành công!');
            showSyncToast(origin);
          }
        })
        .catch(() => {
          // Fallback qua Image beacon GET nếu POST bị CORS
          new Image().src = origin + '/api/quick-export/sync-token?token=' + encodeURIComponent(cleanToken)
            + '&userId=' + encodeURIComponent(target.userId || '')
            + '&branchCode=' + encodeURIComponent(target.branchCode || '');
        });
      } catch (err) {}
    }

    setTimeout(() => { _isSyncing = false; }, 3000);
  }

  // -------------------------------------------------------------
  // 7. VÒNG LẶP QUÉT TÌM TOKEN
  // -------------------------------------------------------------
  async function searchAndSync() {
    if (_lastSyncedToken) return;

    // 1. Quét sessionStorage & localStorage
    let tok = scanStorage(sessionStorage) || scanStorage(localStorage);

    // 2. Quét IndexedDB
    if (!tok) {
      tok = await scanAllIndexedDBs();
    }

    if (tok) {
      sendTokenToApp(tok);
    }
  }

  // -------------------------------------------------------------
  // 8. KHỞI CHẠY
  // -------------------------------------------------------------
  // Lắng nghe sự kiện từ script Main-World
  window.addEventListener('__PV_TOKEN_DISPATCH__', function(e) {
    if (e.detail && e.detail.token) {
      sendTokenToApp(e.detail.token);
    }
  });

  // Inject script ngay
  injectMainWorldScript();

  // Quét storage và IndexedDB
  searchAndSync();
  setTimeout(searchAndSync, 1000);
  setTimeout(searchAndSync, 2500);
  setTimeout(searchAndSync, 5000);
  setInterval(searchAndSync, 15000);
})();
