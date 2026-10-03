/**
 * chrome-extension-erp-sync/app_bridge.js
 * Chạy trên các tab của ứng dụng Xuất kho nhanh (localhost hoặc Vercel)
 * Tự động ghi nhớ địa chỉ website và thông tin tài khoản người dùng
 */
(function() {
  try {
    const origin = window.location.origin;
    const userId = window.pvUserId || '';
    const branchCode = window.pvBranchCode || '';

    document.documentElement.dataset.pvExtensionInstalled = 'true';
    window.__PV_EXTENSION_INSTALLED__ = true;
    window.dispatchEvent(new CustomEvent('pv-extension-detected'));

    if (chrome && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({
        'app_origin': origin,
        'app_user_id': userId,
        'app_branch_code': branchCode,
        'app_updated_at': Date.now()
      });
    }
  } catch (e) {}
})();
