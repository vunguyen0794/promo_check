@echo off
set LOG_FILE=D:\_Báo cáo\Báo cáo doanh thu\2025\Log_update_Bigquery\sales_sync_supabase.log
echo [%date% %time%] --- BAT DAU DONG BO SALES SANG SUPABASE --- >> "%LOG_FILE%"

cd /d d:\promotion-app\promotion-app
node sync_sales_locally.js >> "%LOG_FILE%" 2>&1

echo [%date% %time%] --- HOAN TAT DONG BO --- >> "%LOG_FILE%"
echo. >> "%LOG_FILE%"

