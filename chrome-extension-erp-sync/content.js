/**
 * Phong Vu ERP Auto Sync
 * Tu dong lay token tu IndexedDB (ERPAdminLocalDB), window.TekoID, hoac localStorage
 * va dong bo sang he thong Xuat kho nhanh
 */
(function() {
  const DEFAULT_ORIGINS = ['http://localhost:3300'];

  async function getTargetOriginsAndUser() {
    return new Promise((resolve) => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['app_origin', 'app_user_id', 'app_branch_code'], (data) => {
          const list = [...DEFAULT_ORIGINS];
          if (data && data.app_origin && !list.includes(data.app_origin)) {
            list.unshift(data.app_origin);
          }
          resolve({
            origins: list,
            userId: data ? (data.app_user_id || '') : '',
            branchCode: data ? (data.app_branch_code || '') : ''
          });
        });
      } else {
        resolve({ origins: DEFAULT_ORIGINS, userId: '', branchCode: '' });
      }
    });
  }

  // Lay token tu IndexedDB (ERPAdminLocalDB -> currentUser -> accessToken)
  function getIndexedDBToken() {
    return new Promise((resolve) => {
      try {
        const req = indexedDB.open('ERPAdminLocalDB');
        req.onerror = function() { resolve(''); };
        req.onsuccess = function(e) {
          try {
            var db = e.target.result;
            if (!db || !db.objectStoreNames || !db.objectStoreNames.contains('currentUser')) {
              if (db) db.close();
              return resolve('');
            }
            var tx = db.transaction('currentUser', 'readonly');
            var store = tx.objectStore('currentUser');
            var getReq = store.getAll();
            getReq.onsuccess = function(ev) {
              db.close();
              var results = ev.target.result || [];
              for (var i = 0; i < results.length; i++) {
                var user = results[i];
                var t = user && (user.accessToken || user.access_token || user.token || user.id_token);
                if (t && t.length > 30) return resolve(t);
              }
              resolve('');
            };
            getReq.onerror = function() { db.close(); resolve(''); };
          } catch (err) {
            resolve('');
          }
        };
      } catch (err) {
        resolve('');
      }
    });
  }

  async function trySync() {
    var token = '';

    // 1. Tu IndexedDB
    token = await getIndexedDBToken();

    // 2. Tu window.TekoID
    if (!token && window.TekoID && window.TekoID.user && typeof window.TekoID.user.getAccessToken === 'function') {
      try { token = window.TekoID.user.getAccessToken(); } catch (e) {}
    }

    // 3. Tu localStorage
    if (!token) {
      for (var i = 0; i < localStorage.length; i++) {
        var key = localStorage.key(i);
        var val = localStorage.getItem(key) || '';

        // Raw JWT string
        if (val.startsWith('eyJ') && val.length > 40) {
          token = val;
          break;
        }
        try {
          var parsed = JSON.parse(val);
          if (parsed) {
            var t = parsed.access_token || parsed.accessToken || parsed.id_token;
            if (t && t.length > 30) { token = t; break; }
            // Nested currentUser
            if (parsed.currentUser) {
              t = parsed.currentUser.access_token || parsed.currentUser.accessToken || parsed.currentUser.token;
              if (t && t.length > 30) { token = t; break; }
            }
          }
        } catch (e) {}
      }
    }

    // 4. Gui ve he thong Xuat kho nhanh
    if (token && token.length > 30) {
      var cleanToken = token.trim().replace(/^Bearer\s+/i, '');
      var target = await getTargetOriginsAndUser();

      target.origins.forEach(function(origin) {
        fetch(origin + '/api/quick-export/sync-token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: cleanToken,
            userId: target.userId || '',
            branchCode: target.branchCode || ''
          })
        })
        .then(function(res) { return res.json(); })
        .then(function(data) {
          if (data.success) {
            console.log('[Phong Vu ERP Auto Sync] Da dong bo ERP toi [' + origin + '] thanh cong!');
          }
        })
        .catch(function() {});
      });
    }
  }

  // Chay sau khi trang tai xong va dinh ky kiem tra
  setTimeout(trySync, 1500);
  setInterval(trySync, 60000);
})();
