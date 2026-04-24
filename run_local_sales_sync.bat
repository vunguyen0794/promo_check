@echo off
cd /d "%~dp0"
echo ======================================================
echo   PROMO CHECK - HE THONG DONG BO SALES (2024-2026)
echo ======================================================
echo.
echo Thu muc lam viec: %CD%
echo Dang doc du lieu tu CSV va tong hop len Supabase...
echo Vui long cho trong giay lat (co the mat vai phut cho 1.5M dong).
echo.

node sync_sales_locally.js

echo.
echo ======================================================
echo   DONG BO HOAN TAT!
echo ======================================================
pause
