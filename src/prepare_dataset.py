#!/usr/bin/env python3
"""
prepare_dataset.py - turn one day of the public CyberLab honeynet dataset
into a flat Cowrie-style JSON-lines honeypot log.

Source dataset (CC BY 4.0):
    Sedlar, U., Kren, M., Stefanic Juznic, L., Volk, M. (2020).
    "CyberLab honeynet dataset". Zenodo. https://doi.org/10.5281/zenodo.3687527

The raw file is a JSON array of {session_id: [events...]} objects with
~40 columns per event. This script flattens it to one event per line and
keeps only the fields the analyzer needs, in the same shape as Cowrie's own
`cowrie.json` output. The dataset already pseudonymizes every IP address
as a SHA-256 hash; here the hash is shortened to 16 hex chars for
readability.

What is dropped:
  * cowrie.direct-tcpip.data  - raw tunnelled payloads (spam bodies etc.)
  * client.kex / client.size / log.open / log.closed - SSH plumbing
  * events from sessions that did not start on the chosen day, and stray
    events logged more than a day later (8 events dated 2019-06-03)

Usage:
    python src/prepare_dataset.py data_raw/cyberlab_2019-05-18.json.gz
    python src/prepare_dataset.py RAW.json.gz -o evidence/sample_data.txt --day 2019-05-18
"""

import argparse
import gzip
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEEP = {
    "cowrie.session.connect",
    "cowrie.client.version",
    "cowrie.login.success",
    "cowrie.login.failed",
    "cowrie.command.success",
    "cowrie.command.failed",
    "cowrie.session.file_download",
    "cowrie.direct-tcpip.request",
    "cowrie.session.closed",
}
TCPIP_RE = re.compile(r"request to (?P<host>[0-9a-f]+|[\d.]+):(?P<port>\d+)")
COMMAND_RE = re.compile(r"^Command (?:not )?found: ?(?P<cmd>.*)$", re.S)


def short(ident):
    return ident[:16] if ident else None


def flatten(raw):
    """Yield (session_id, event) from the dataset's nested layout."""
    for block in raw:
        for session_id, events in block.items():
            for ev in events:
                yield session_id, ev


def convert(ev):
    geo = ev.get("geolocation_data") or {}
    out = {
        "timestamp": ev["timestamp"],
        "eventid": ev["eventid"],
        "session": ev.get("session_id"),
        "src_ip": short(ev.get("src_ip_identifier")),
        "country": geo.get("country_name") or "Unknown",
    }
    eid = ev["eventid"]
    if eid == "cowrie.session.connect":
        out["src_port"] = ev.get("src_port")
    elif eid == "cowrie.client.version":
        out["version"] = ev.get("ssh_client_version")
    elif eid.startswith("cowrie.login."):
        out["username"] = ev.get("username")
        out["password"] = ev.get("password")
    elif eid.startswith("cowrie.command."):
        m = COMMAND_RE.match(ev.get("message") or "")
        out["input"] = m.group("cmd").strip() if m else ev.get("message")
    elif eid == "cowrie.session.file_download":
        out["url"] = ev.get("url")
        out["shasum"] = ev.get("shasum")
    elif eid == "cowrie.direct-tcpip.request":
        m = TCPIP_RE.search(ev.get("message") or "")
        if m:
            out["dst_ip"] = short(m.group("host"))
            out["dst_port"] = int(m.group("port"))
    elif eid == "cowrie.session.closed":
        out["duration"] = ev.get("duration")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("raw", help="cyberlab_YYYY-MM-DD.json.gz from Zenodo")
    ap.add_argument("-o", "--output", default=str(ROOT / "evidence" / "sample_data.txt"))
    ap.add_argument("--day", help="keep sessions that started on this date (default: taken from file name)")
    args = ap.parse_args()

    raw_path = Path(args.raw)
    day = args.day or re.search(r"\d{4}-\d{2}-\d{2}", raw_path.name).group(0)
    opener = gzip.open if raw_path.suffix == ".gz" else open
    with opener(raw_path, "rt", encoding="utf-8") as fh:
        raw = json.load(fh)

    events = list(flatten(raw))
    session_start = {}
    for sid, ev in events:
        ts = ev["timestamp"]
        if sid not in session_start or ts < session_start[sid]:
            session_start[sid] = ts

    next_day = (date.fromisoformat(day) + timedelta(days=1)).isoformat()
    kept = [convert(ev) for sid, ev in events
            if ev["eventid"] in KEEP and session_start[sid].startswith(day)
            and ev["timestamp"][:10] in (day, next_day)]
    kept.sort(key=lambda e: e["timestamp"])

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for ev in kept:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")

    print(f"read    : {raw_path.as_posix()}  ({len(raw)} sessions, {len(events)} events)")
    print(f"kept    : {len(kept)} events from sessions starting {day}")
    try:
        shown = out_path.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        shown = out_path
    print(f"written : {shown}  ({out_path.stat().st_size / 1024:.0f} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
