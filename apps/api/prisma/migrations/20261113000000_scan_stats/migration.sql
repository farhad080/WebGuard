-- Project Overview statistics, computed during the scan (GET /api/scans/:id/stats).
ALTER TABLE "scans" ADD COLUMN "stats_json" JSONB;
