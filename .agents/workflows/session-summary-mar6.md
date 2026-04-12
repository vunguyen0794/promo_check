---
description: Sync BQ & PC Builder Config Changes (Mar 6, 2026)
---
# Session Summary: Mar 6, 2026

## Queue System Enhancements
- **Ticket Persistence:** Allowed users to resume queue tickets using `localStorage` and a new `/api/queue/lookup` endpoint by phone number.
- **Admin Calling:** Unified technician selection modal logic across different blocks in `queue-admin.ejs`.
- **Badge Fix:** Fixed 'Tôi không rõ' service type badge to show 'Kiểm tra'.

## Performance Optimizations (Vercel)
- **Caching:** Implemented memory caching (`globalTickerText`, `isBranchEventActive`) in `server.js` with TTL.
- **Middleware Bypass:** Skipped intensive middleware for `/api/` and `/public/` paths.
- **Throttling:** Throttled `last_seen` updates to run max once per 5 minutes.
- **Smart Polling:** Modified `queue-my-status.ejs` and `queue-tv.ejs` to pause API polling when the tab is inactive (`document.hidden`), and increased interval to 12s.

## BigQuery Sync Automation
- Extracted BQ Sync logic into reusable `runBqSkuSync()` function in `server.js`.
- Configured Vercel Cron (`vercel.json`) to hit `/api/cron/sync-bq-skus` daily at 8:00 AM VN time (01:00 UTC).
- Maintains notification system on completion.

## PC Builder Tier Settings UI
- Replaced hardcoded tiers in `check-promos` with dynamic configs loaded from Supabase `site_settings`.
- Added `GET/POST /api/admin/build-pc-tiers` for CRUD operations.
- Built a management modal in `promo-management.ejs` accessible by HCM.BD Manager/Admin users to configure these thresholds visually.
