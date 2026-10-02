/**
 * Phong Vũ ERP Auto Sync
 * Tự động lấy token từ IndexedDB (ERPAdminLocalDB), window.TekoID, hoặc localStorage
 * và đồng bộ sang hệ thống Xuất kho nhanh (http://localhost:3300)
 */
(function() {
  function getIndexedDBToken() {
    return new Promise((resolve) => {
      try {
        const req = indexedDB.open("ERPAdminLocalDB");
        req.onsuccess = (e) => {
          try {
            const db = e.target.result;
            if (!db.objectStoreNames.contains("currentUser")) {
              return resolve('');
            }
            const tx = db.transaction("currentUser", "readonly");
            const store = tx.objectStore("currentUser");
            const getReq = store.getAll();
            getReq.onsuccess = (ev) => {
              const res = ev.target.result;
              const token = res?.[0]?.accessToken || res?.[0]?.access_token;
              resolve(token || '');
            };
            getReq.onerror = () => resolve('');
          } catch (err) {
            resolve('');
          }
        };
        req.onerror = () => resolve('');
      } catch (err) {
        resolve('');
      }
    });
  }

  async function trySync() {
    let token = '';

    // 1. Thử lấy từ IndexedDB (ERPAdminLocalDB -> currentUser -> accessToken)
    token = await getIndexedDBToken();

    // 2. Thử lấy từ window.TekoID
    if (!token && window.TekoID && window.TekoID.user && typeof window.TekoID.user.getAccessToken === 'function') {
      try { token = window.TekoID.user.getAccessToken(); } catch (e) {}
    }

    // 3. Thử duyệt qua localStorage
    if (!token) {
      for (let i = 0; i < localStorage.length; i++) {
        const val = localStorage.getItem(localStorage.key(i)) || '';
        try {
          const parsed = JSON.parse(val);
          if (parsed && (parsed.access_token || parsed.accessToken)) {
            token = parsed.access_token || parsed.accessToken;
            break;
          }
        } catch (e) {}
      }
    }

    // 4. Gửi về hệ thống Xuất kho nhanh
    if (token && token.length > 30) {
      fetch('http://localhost:3300/api/quick-export/sync-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token.trim() })
      })
      .then(res => res.json())
      .then(data => {
        if (data.success) {
          console.log('[Phong Vũ ERP Auto Sync] ✅ Đã tự động đồng bộ kết nối ERP thành công!');
        }
      })
      .catch(() => {});
    }
  }

  // Chạy sau khi trang tải xong và định kỳ kiểm tra
  setTimeout(trySync, 1500);
  setInterval(trySync, 60000);
})();
