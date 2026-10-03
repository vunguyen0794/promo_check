#!/bin/bash
# ========================================================
# Script tự động Deploy code từ máy lên VPS (222.255.184.49)
# ========================================================
set -e

VPS_HOST="222.255.184.49"
VPS_USER="root"
REMOTE_DIR="/var/www/promo_check"

echo "🚀 Bắt đầu đồng bộ code lên VPS ($VPS_HOST)..."

# 1. Đóng gói lại extension zip để luôn mới nhất
if [ -d "chrome-extension-erp-sync" ]; then
  (cd chrome-extension-erp-sync && zip -r -q ../public/phongvu-erp-sync.zip .)
  echo "📦 Đã cập nhật public/phongvu-erp-sync.zip"
fi

# 2. Đồng bộ file code lên VPS (loại trừ node_modules, git, file tạm)
rsync -avz \
  --exclude 'node_modules' \
  --exclude '.git' \
  --exclude '.DS_Store' \
  --exclude '._*' \
  --exclude '.agent' \
  --exclude '.agents' \
  --exclude '.vercel' \
  --exclude 'scratch' \
  --exclude '*.log' \
  ./ "$VPS_USER@$VPS_HOST:$REMOTE_DIR/"

# 3. Reload PM2 trên VPS không làm gián đoạn người dùng
echo "🔄 Reload ứng dụng PM2 trên VPS..."
ssh "$VPS_USER@$VPS_HOST" "cd $REMOTE_DIR && pm2 reload promo_check"

echo "✅ Deploy thành công 100%! Truy cập: http://$VPS_HOST"
