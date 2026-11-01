# LogLens – Simplified Security Log Analysis

SIEM-lite: upload an Apache/Nginx log, get a dashboard of attacks (SQLi, XSS, traversal, brute force).

## Run
```bash
# backend
cd backend && pip install -r requirements.txt && python app.py      # http://localhost:5000
# frontend
cd frontend && npm install && npm run dev                            # http://localhost:5173
# tests
cd backend && pip install pytest && pytest
```
Optional GeoIP: download MaxMind GeoLite2-Country.mmdb and set `GEOIP_DB=/path/to/file.mmdb`.
Without it, a small demo prefix table is used.

## Performance note: how large files are handled
- **Upload:** Flask/Werkzeug writes the multipart body to a temp file in chunks; the file is never held in RAM.
- **Parsing:** `iter_log()` is a generator that reads one line at a time, so memory is O(1) in file size.
- **Aggregation:** only counters (per hour / type / IP) and a capped 300-event sample are kept, not parsed rows.
- **Async:** upload returns a job ID (202) immediately; a worker pool processes it and the UI polls `/api/jobs/<id>`.
  For production swap `ThreadPoolExecutor` for Celery/RQ + Redis (and run Gunicorn with multiple workers).
- **Detection:** regexes are pre-compiled once; paths are URL-decoded (twice) before matching to catch encoded payloads.

## Extending
Add rules in `backend/signatures.json` (`id`, `type`, `severity`, `pattern`, `target`: `request` | `user_agent`).
