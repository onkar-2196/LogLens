"""Streaming parser for Apache/Nginx Common & Combined Log Format."""
import re
from typing import Iterator

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)


def parse_line(line: str):
    m = LOG_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    d["status"] = int(d["status"])
    d["user_agent"] = d["user_agent"] or ""
    return d


def iter_log(path: str) -> Iterator[dict]:
    """Yield parsed entries one line at a time -- memory stays O(1) in file size."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:  # file object iterates lazily, buffered in small blocks
            entry = parse_line(line.rstrip("\n"))
            yield entry if entry else {"_malformed": True}
