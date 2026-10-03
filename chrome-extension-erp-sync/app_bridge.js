/**
 * chrome-extension-erp-sync/app_bridge.js
 * Chạy trên các tab của hệ thống Xuất kho nhanh
 * Tự động ghi nhớ địa chỉ website và thông tin tài khoản người dùng vào chrome.storage
 */
(function() {
  function readAndStore() {
    try {
      const origin = window.location.origin;
      const el = document.documentElement;
      const body = document.body;

      const userId = (el && el.dataset.pvUserId) || (body && body.dataset.pvUserId) || '';
      const email = (el && el.dataset.pvUserEmail) || (body && body.dataset.pvUserEmail) || '';
      const branchCode = (el && el.dataset.pvBranchCode) || (body && body.dataset.pvBranchCode) || '';

      if (el) el.dataset.pvExtensionInstalled = 'true';
      if (body) body.dataset.pvExtensionInstalled = 'true';
      window.__PV_EXTENSION_INSTALLED__ = true;
      window.dispatchEvent(new CustomEvent('pv-extension-detected'));

      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({
          'app_origin': origin,
          'app_user_id': userId,
          'app_user_email': email,
          'app_branch_code': branchCode,
          'app_updated_at': Date.now()
        });
      }
    } catch (e) {}
  }

  // Chạy ngay khi nạp script
  readAndStore();

  // Chạy lại khi DOM sẵn sàng
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', readAndStore);
  }

  // Lắng nghe sự kiện từ trang EJS
  window.addEventListener('pv-user-info', function(e) {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local && e.detail) {
        chrome.storage.local.set({
          'app_origin': e.detail.origin || window.location.origin,
          'app_user_id': e.detail.userId || '',
          'app_user_email': e.detail.email || '',
          'app_branch_code': e.detail.branchCode || '',
          'app_updated_at': Date.now()
        });
      }
    } catch (err) {}
  });
})();
