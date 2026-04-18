@echo off
echo [%date% %time%] Starting Supabase Inventory Sync...
cd /d d:\promotion-app\promotion-app
node sync_local_inventory.js
echo [%date% %time%] Sync process completed.
