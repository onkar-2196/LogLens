"""Generate a realistic sample log (normal traffic + attacks)."""
import random
from urllib.parse import quote
from datetime import datetime, timedelta

NORMAL = ["/", "/index.html", "/about", "/products?id=12", "/static/app.js", "/login", "/api/items"]
ATTACKS = [
    "/products?id=1' OR 1=1--", "/search?q=1 UNION SELECT username,password FROM users",
    "/item?id=5;SELECT SLEEP(5)", "/search?q=<script>alert(1)</script>",
    "/redirect?u=javascript:alert(document.cookie)", "/download?f=../../../../etc/passwd",
    "/..%2f..%2f..%2fetc/passwd",
]
UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X)",
      "curl/8.4.0"]
BAD_IPS = ["185.220.101.4", "45.155.205.9", "103.76.12.40", "91.240.118.7", "198.51.100.23"]


def line(ip, t, method, path, status, ua):
    path = quote(path, safe="/?=&")  # real clients percent-encode spaces and symbols
    return (f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"{method} {path} HTTP/1.1" {status} {random.randint(200, 9000)} "-" "{ua}"')


def generate(out_path, n=20000, seed=7):
    random.seed(seed)
    start = datetime(2026, 10, 29, 0, 0, 0)
    rows = []
    for _ in range(n):
        t = start + timedelta(seconds=random.randint(0, 86399))
        ip = f"10.0.{random.randint(0, 50)}.{random.randint(1, 250)}"
        rows.append((t, line(ip, t, "GET", random.choice(NORMAL), random.choice([200, 200, 200, 304, 404]), random.choice(UA))))
    for ip in BAD_IPS:
        for _ in range(random.randint(25, 80)):
            t = start + timedelta(seconds=random.randint(0, 86399))
            rows.append((t, line(ip, t, "GET", random.choice(ATTACKS), random.choice([200, 403, 500]), "sqlmap/1.7" if random.random() < .2 else random.choice(UA))))
    for ip in BAD_IPS[:2]:  # brute force bursts
        base = start + timedelta(hours=random.randint(1, 20))
        for i in range(40):
            t = base + timedelta(seconds=i * 2)
            rows.append((t, line(ip, t, "POST", "/login", 401, random.choice(UA))))
    rows.sort(key=lambda r: r[0])
    with open(out_path, "w") as f:
        f.write("\n".join(r[1] for r in rows) + "\n")


if __name__ == "__main__":
    generate("demo.log")
