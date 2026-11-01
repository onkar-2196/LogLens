"""GeoIP lookup. Set GEOIP_DB to a MaxMind GeoLite2-Country.mmdb path to enable."""
import os
from functools import lru_cache

try:
    import maxminddb
    _db_path = os.environ.get("GEOIP_DB", "GeoLite2-Country.mmdb")
    _reader = maxminddb.open_database(_db_path) if os.path.exists(_db_path) else None
except ImportError:
    _reader = None

# Fallback so the demo still shows a map-like breakdown without the MaxMind file.
_DEMO = {"185.220.": "Germany", "45.155.": "Netherlands", "103.76.": "India",
         "91.240.": "Russia", "198.51.": "United States", "203.0.": "Australia"}


@lru_cache(maxsize=100_000)
def lookup_country(ip: str) -> str:
    if _reader:
        try:
            rec = _reader.get(ip)
            if rec and "country" in rec:
                return rec["country"]["names"]["en"]
        except Exception:
            pass
        return "Unknown"
    for prefix, name in _DEMO.items():
        if ip.startswith(prefix):
            return name
    return "Unknown"
