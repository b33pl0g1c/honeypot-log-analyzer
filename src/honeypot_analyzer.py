#!/usr/bin/env python3
"""
honeypot_analyzer.py - SSH honeypot log analyzer and threat-actor profiler.

Parses a Cowrie-style JSON-lines honeypot log (one event per line) and
produces a "Threat Actor Profile" report:

  * top attacking IPs, most-tried usernames, passwords and credential pairs
  * per-attacker behaviour classification (brute force, IoT default-credential
    botnet, SSH tunnel / proxy abuse, malware dropper, scanner)
  * MITRE ATT&CK technique mapping, 0-100 risk score and severity
  * campaign clustering (shared payloads, credential lists, tunnel targets)
  * hourly timeline, defanged IOC list and defensive recommendations

Standard library only. Python 3.8+.

Usage:
    python src/honeypot_analyzer.py
    python src/honeypot_analyzer.py -i evidence/sample_data.txt -o evidence/honeypot_analysis.txt --top 10
"""

import argparse
import base64
import binascii
import hashlib
import json
import logging
import re
import sys
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.0"
ROOT = Path(__file__).resolve().parent.parent
WIDTH = 100
log = logging.getLogger("honeypot")

# --------------------------------------------------------------------------
# Threat-intel knowledge base
# --------------------------------------------------------------------------

# Default credentials hard-coded in the Mirai IoT botnet scanner (leaked 2016)
# plus other well-known vendor defaults.
IOT_DEFAULT_CREDS = {
    ("root", "xc3511"), ("root", "vizxv"), ("admin", "admin"), ("root", "admin"),
    ("root", "888888"), ("root", "xmhdipc"), ("root", "default"), ("root", "juantech"),
    ("root", "123456"), ("root", "54321"), ("support", "support"), ("root", ""),
    ("admin", "password"), ("root", "root"), ("root", "12345"), ("user", "user"),
    ("admin", ""), ("root", "pass"), ("admin", "admin1234"), ("root", "1111"),
    ("admin", "smcadmin"), ("admin", "1111"), ("root", "666666"), ("root", "password"),
    ("root", "1234"), ("root", "klv123"), ("Administrator", "admin"),
    ("service", "service"), ("supervisor", "supervisor"), ("guest", "guest"),
    ("guest", "12345"), ("admin1", "password"), ("administrator", "1234"),
    ("666666", "666666"), ("888888", "888888"), ("ubnt", "ubnt"), ("root", "klv1234"),
    ("root", "Zte521"), ("root", "hi3518"), ("root", "jvbzd"), ("root", "anko"),
    ("root", "zlxx."), ("root", "7ujMko0vizxv"), ("root", "7ujMko0admin"),
    ("root", "system"), ("root", "ikwb"), ("root", "dreambox"), ("root", "user"),
    ("root", "realtek"), ("root", "00000000"), ("admin", "1111111"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "54321"), ("admin", "123456"),
    ("admin", "7ujMko0admin"), ("admin", "pass"), ("admin", "meinsm"), ("tech", "tech"),
    ("pi", "raspberry"), ("admin", "changeme"), ("admin", "manager"), ("admin", "admin1"),
    ("default", "default"), ("operator", "operator"), ("ftp", "ftp"), ("adm", "adm"),
}

# Post-login command patterns -> MITRE ATT&CK technique.
COMMAND_TTPS = [
    (re.compile(r"\b(wget|curl|tftp|ftpget)\b"), "T1105", "Ingress Tool Transfer"),
    (re.compile(r"\b(sh|bash)\b\s+\S+\.sh|chmod\s+(\+x|7[0-7]{2})|\./\S+"),
     "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    (re.compile(r"HISTFILE|HISTSIZE|history -[cn]|unset HIST"),
     "T1070.003", "Indicator Removal: Clear Command History"),
    (re.compile(r"\buname\b|/proc/cpuinfo|\bwhoami\b|\blscpu\b|\bnproc\b"),
     "T1082", "System Information Discovery"),
    (re.compile(r"crontab|/etc/cron"), "T1053.003", "Scheduled Task/Job: Cron"),
    (re.compile(r"authorized_keys"), "T1098.004", "Account Manipulation: SSH Authorized Keys"),
    (re.compile(r"xmrig|minerd|stratum\+tcp"), "T1496", "Resource Hijacking"),
]

BRUTE = "BRUTE FORCE"
BOTNET = "IoT DEFAULT-CREDENTIAL BOTNET"
PROXY = "SSH TUNNEL / PROXY ABUSE"
DROPPER = "MALWARE DROPPER"
PERSIST = "BACKDOOR / PERSISTENCE"
SCANNER = "OPPORTUNISTIC SCANNER"
SHORT_TAG = {BRUTE: "BRUTE", BOTNET: "IOT-DEFAULT", PROXY: "PROXY", DROPPER: "DROPPER",
             PERSIST: "PERSIST", SCANNER: "SCANNER"}

BRUTE_MIN_ATTEMPTS = 100      # attempts that alone mean brute force
BRUTE_MIN_RATE = 5.0          # attempts/minute (with >= 20 attempts)
BRUTE_MIN_DISTINCT = 10       # distinct credential pairs - one reused cred is not guessing
BOTNET_MIN_RATIO = 0.5        # share of creds that are IoT defaults
BOTNET_MIN_ATTEMPTS = 5       # one lucky default login is not a botnet pattern
CAMPAIGN_MIN_IPS = 3          # IPs needed to call something a campaign
SMTP_PORTS = {25, 465, 587}

URL_RE = re.compile(r"https?://[^\s'\";|>)]+")
SSH_KEY_RE = re.compile(r"(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+)\s+([A-Za-z0-9+/]{40,}={0,2})(?:\s+([^\s'\"]+))?")


def ssh_key_fingerprint(b64):
    """OpenSSH-style SHA256 fingerprint of a public key blob."""
    try:
        blob = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

@dataclass
class Event:
    ts: datetime
    kind: str
    ip: str
    session: str
    data: dict


EVENT_KINDS = {
    "cowrie.session.connect": "connect",
    "cowrie.session.closed": "closed",
    "cowrie.client.version": "version",
    "cowrie.login.failed": "login_failed",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.command.success": "command",
    "cowrie.command.failed": "command",
    "cowrie.session.file_download": "download",
    "cowrie.direct-tcpip.request": "tunnel",
}


def parse_ts(value):
    ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def parse_log(path):
    """Read a JSON-lines Cowrie log. Bad lines are counted, never fatal."""
    events = []
    stats = Counter()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            stats["lines"] += 1
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    raise ValueError("not a JSON object")
                ts = parse_ts(rec["timestamp"])
                eventid = rec["eventid"]
                ip = rec.get("src_ip")
                if not ip:
                    raise ValueError("missing src_ip")
            except (ValueError, KeyError, TypeError) as exc:
                stats["malformed"] += 1
                log.debug("line %d malformed (%s): %.80s", lineno, exc, line.strip())
                continue
            kind = EVENT_KINDS.get(eventid)
            if kind is None:
                stats["ignored"] += 1
                continue
            stats["parsed"] += 1
            events.append(Event(ts, kind, str(ip), str(rec.get("session", "")), rec))
    events.sort(key=lambda e: e.ts)
    return events, stats


# --------------------------------------------------------------------------
# Per-attacker aggregation
# --------------------------------------------------------------------------

@dataclass
class Actor:
    ip: str
    country: str = "Unknown"
    attempts: int = 0
    successes: int = 0
    sessions: set = field(default_factory=set)
    users: Counter = field(default_factory=Counter)
    passwords: Counter = field(default_factory=Counter)
    creds: Counter = field(default_factory=Counter)
    first_success: tuple = None
    clients: Counter = field(default_factory=Counter)
    commands: list = field(default_factory=list)
    downloads: list = field(default_factory=list)
    tunnels: Counter = field(default_factory=Counter)
    first: datetime = None
    last: datetime = None
    first_auth: datetime = None
    last_auth: datetime = None
    tags: list = field(default_factory=list)
    ttps: dict = field(default_factory=dict)
    score: int = 0
    severity: str = "LOW"

    @property
    def auth_minutes(self):
        if not self.first_auth:
            return 0.0
        return (self.last_auth - self.first_auth).total_seconds() / 60

    @property
    def tunnel_ports(self):
        ports = Counter()
        for (_, port), n in self.tunnels.items():
            ports[port] += n
        return ports


def build_actors(events):
    actors = {}
    for ev in events:
        a = actors.get(ev.ip)
        if a is None:
            a = actors[ev.ip] = Actor(ev.ip)
        if ev.data.get("country"):
            a.country = ev.data["country"]
        a.first = a.first or ev.ts
        a.last = ev.ts
        a.sessions.add(ev.session)
        d = ev.data
        if ev.kind in ("login_failed", "login_success"):
            user, pw = d.get("username") or "", d.get("password")
            pw = "" if pw is None else pw
            a.attempts += 1
            a.users[user] += 1
            a.passwords[pw] += 1
            a.creds[(user, pw)] += 1
            a.first_auth = a.first_auth or ev.ts
            a.last_auth = ev.ts
            if ev.kind == "login_success":
                a.successes += 1
                if a.first_success is None:
                    a.first_success = (ev.ts, user, pw)
        elif ev.kind == "version" and d.get("version"):
            a.clients[d["version"]] += 1
        elif ev.kind == "command" and d.get("input"):
            a.commands.append((ev.ts, d["input"]))
        elif ev.kind == "download" and d.get("url"):
            a.downloads.append((ev.ts, d["url"], d.get("shasum") or ""))
        elif ev.kind == "tunnel" and d.get("dst_port") is not None:
            a.tunnels[(d.get("dst_ip", "?"), int(d["dst_port"]))] += 1
    return actors


def classify(a):
    """Rule-based behaviour tags, ATT&CK mapping and a 0-100 risk score."""
    tags, ttps = [], {}
    rate = a.attempts / max(a.auth_minutes, 1.0)
    iot_hits = sum(n for cred, n in a.creds.items() if cred in IOT_DEFAULT_CREDS)
    iot_ratio = iot_hits / a.attempts if a.attempts else 0.0
    command_text = "\n".join(c for _, c in a.commands)
    ports = a.tunnel_ports

    guessing = len(a.creds) >= BRUTE_MIN_DISTINCT
    if guessing and (a.attempts >= BRUTE_MIN_ATTEMPTS or (a.attempts >= 20 and rate >= BRUTE_MIN_RATE)):
        tags.append(BRUTE)
        ttps["T1110.001"] = "Brute Force: Password Guessing"
    if a.attempts >= BOTNET_MIN_ATTEMPTS and iot_ratio >= BOTNET_MIN_RATIO:
        tags.append(BOTNET)
        ttps["T1110.004"] = "Brute Force: Credential Stuffing (default-credential list)"
    if a.successes:
        ttps["T1078.001" if a.first_success[1:] in IOT_DEFAULT_CREDS else "T1078"] = (
            "Valid Accounts: Default Accounts" if a.first_success[1:] in IOT_DEFAULT_CREDS
            else "Valid Accounts")
    if a.tunnels:
        tags.append(PROXY)
        ttps["T1090"] = "Proxy (SSH direct-tcpip port forwarding)"
        if SMTP_PORTS & set(ports):
            ttps["T1583.006*"] = "Abuse of third-party infrastructure for spam relay (SMTP)"
    if a.downloads or re.search(r"\b(wget|curl|tftp)\b", command_text):
        tags.append(DROPPER)
    for rx, tid, name in COMMAND_TTPS:
        if rx.search(command_text):
            ttps[tid] = name
    if a.downloads:
        ttps["T1105"] = "Ingress Tool Transfer"
    if "T1098.004" in ttps or "T1053.003" in ttps:
        tags.append(PERSIST)
    if not tags:
        tags.append(SCANNER)
        ttps.setdefault("T1110.001", "Brute Force: Password Guessing")

    score = min(25, round(a.attempts / 20))
    score += 15 if BRUTE in tags else 0
    score += 10 if BOTNET in tags else 0
    score += 20 if a.successes and (a.commands or a.tunnels) else (5 if a.successes else 0)
    score += 15 if a.tunnels else 0
    score += 5 if SMTP_PORTS & set(ports) else 0
    score += 10 if a.commands else 0
    score += 40 if a.downloads else 0
    score += 5 if "T1070.003" in ttps else 0
    score += 25 if PERSIST in tags else 0
    a.score = min(100, score)
    a.severity = ("CRITICAL" if a.score >= 70 else "HIGH" if a.score >= 50
                  else "MEDIUM" if a.score >= 30 else "LOW")
    a.tags, a.ttps = tags, ttps
    return a


def find_campaigns(actors):
    """Group IPs that share a payload, a command script, an exact credential list or tunnel targets."""
    by_payload, by_creds, by_tunnel, by_script = (defaultdict(set) for _ in range(4))
    for a in actors.values():
        for _, url, sha in a.downloads:
            by_payload[sha or url].add((a.ip, url))
        if a.creds and len(a.creds) <= 25:
            client = a.clients.most_common(1)[0][0] if a.clients else "?"
            by_creds[(client, tuple(sorted(a.creds)))].add(a.ip)
        if a.tunnels:
            by_tunnel[tuple(sorted(a.tunnel_ports))].add(a.ip)
        if a.commands:
            by_script[tuple(dict.fromkeys(c for _, c in a.commands))].add(a.ip)

    campaigns = []
    for sha, pairs in by_payload.items():
        urls = sorted({u for _, u in pairs})
        campaigns.append(("Malware payload", f"sha256:{sha[:16]}... served from {len(urls)} URL(s): "
                          + ", ".join(defang(u) for u in urls), {ip for ip, _ in pairs}))
    for script, ips in by_script.items():
        if len(ips) >= 2:
            campaigns.append(("Identical post-login script",
                              f"{len(script)} commands, starts '{defang_cmd(script[0])[:40]}'", ips))
    for (client, creds), ips in by_creds.items():
        if len(ips) >= CAMPAIGN_MIN_IPS:
            shown = ", ".join(fmt_cred(c) for c in creds[:4]) + (" ..." if len(creds) > 4 else "")
            campaigns.append(("Identical credential list",
                              f"{len(creds)} cred(s) [{shown}] via {client}", ips))
    for ports, ips in by_tunnel.items():
        if len(ips) >= CAMPAIGN_MIN_IPS:
            campaigns.append(("Same tunnel target ports",
                              "dst ports " + ",".join(map(str, ports)), ips))
    campaigns.sort(key=lambda c: -sum(actors[ip].attempts + len(actors[ip].sessions) for ip in c[2]))
    return campaigns


# --------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------

def defang(text):
    """hxxp://1.2.3[.]4/x - safe to paste into reports and chat."""
    text = re.sub(r"^http", "hxxp", text)
    return re.sub(r"\.(?=[^./]*(/|$))", "[.]", text, count=1) if "://" in text else text


def fmt_cred(cred):
    user, pw = cred
    return f"{user or '<empty>'}/{pw if pw != '' else '<empty>'}"


def fmt_pw(pw):
    return pw if pw != "" else "<empty>"


def pct(n, total):
    return f"{100 * n / total:5.1f}%" if total else "  0.0%"


def bar(n, maximum, width=30):
    return "#" * max(1 if n else 0, round(width * n / maximum)) if maximum else ""


def section(lines, title):
    lines += ["", title, "-" * WIDTH]


def table(lines, headers, rows, aligns):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h))
              for i, h in enumerate(headers)]

    def fmt(cells):
        return "  " + "  ".join(str(c).rjust(w) if al == ">" else str(c).ljust(w)
                                for c, w, al in zip(cells, widths, aligns)).rstrip()
    lines.append(fmt(headers))
    lines.append("  " + "  ".join("-" * w for w in widths))
    lines.extend(fmt(r) for r in rows)


def counter_table(lines, title, counter, total, top, label, fmt=str):
    lines.append(f"  {title}")
    rows = [(i, fmt(k)[:34], f"{n:,}", pct(n, total), bar(n, counter.most_common(1)[0][1], 24))
            for i, (k, n) in enumerate(counter.most_common(top), 1)]
    table(lines, ["#", label, "Count", "Share", ""], rows, ["<", "<", ">", ">", "<"])
    lines.append("")


def looks_like_ip(value):
    """True for a dotted IPv4 or an IPv6 address, False for a hashed pseudonym."""
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+", value))


def when(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def build_report(events, stats, actors, campaigns, src, top):
    ranked = sorted(actors.values(), key=lambda a: (-a.attempts, -len(a.sessions)))
    attackers = [a for a in ranked if a.attempts]
    by_risk = sorted(actors.values(), key=lambda a: (-a.score, -a.attempts))
    total_attempts = sum(a.attempts for a in actors.values())
    users, pws, creds, clients, countries = Counter(), Counter(), Counter(), Counter(), Counter()
    for a in actors.values():
        users.update(a.users)
        pws.update(a.passwords)
        creds.update(a.creds)
        clients.update(a.clients)
        countries[a.country] += a.attempts
    successes = sum(a.successes for a in actors.values())
    n_cmds = sum(len(a.commands) for a in actors.values())
    n_tunnels = sum(sum(a.tunnels.values()) for a in actors.values())
    downloads = [(ts, url, sha, a.ip) for a in actors.values() for ts, url, sha in a.downloads]
    sessions = {e.session for e in events}
    t0, t1 = events[0].ts, events[-1].ts
    tag_counts = Counter(t for a in actors.values() for t in a.tags)

    L = []
    L.append("=" * WIDTH)
    L.append("THREAT ACTOR PROFILE  -  SSH HONEYPOT LOG ANALYSIS".center(WIDTH))
    L.append("=" * WIDTH)
    L.append(f"  Generated      : {datetime.now():%Y-%m-%d %H:%M:%S} (local)")
    L.append(f"  Source log     : {src}")
    L.append(f"  Analyzer       : honeypot_analyzer.py v{VERSION}")
    L.append("  Dataset        : CyberLab honeynet dataset, Cowrie SSH honeypot, 2019-05-18 (CC BY 4.0)")
    L.append("                   doi:10.5281/zenodo.3687527 - source IPs are pseudonymized by the dataset")
    L.append("  Classification : TLP:CLEAR")
    if not looks_like_ip(events[0].ip):
        L.append("")
        L.extend(textwrap.wrap(
            f"  NOTE ON IP ADDRESSES: source IPs appear as hashed IDs (e.g. {attackers[0].ip}), not "
            "x.x.x.x, because the dataset authors anonymized every address with SHA-256 before "
            "publishing (IP addresses are personal data under GDPR). Each ID always stands for the "
            "same real IP, so all counts and rankings are exact. Malware-server addresses inside "
            "download URLs are real and are listed as IOCs.", WIDTH, subsequent_indent="  "))

    # 1 ---------------------------------------------------------------
    section(L, "[1] EXECUTIVE SUMMARY")
    L.append(f"  Log lines read ............ {stats['lines']:,}  (parsed {stats['parsed']:,} | "
             f"ignored {stats['ignored']:,} | malformed {stats['malformed']:,})")
    L.append(f"  Observation window ........ {when(t0)} -> {when(t1)} UTC "
             f"({(t1 - t0).total_seconds() / 3600:.1f} h)")
    L.append(f"  SSH sessions .............. {len(sessions):,}")
    L.append(f"  Unique source IPs ......... {len(actors):,}  ({len(attackers)} tried to log in)")
    L.append(f"  Login attempts ............ {total_attempts:,}  "
             f"(failed {total_attempts - successes:,} | accepted by honeypot {successes:,})")
    L.append(f"  Unique usernames/passwords  {len(users):,} / {len(pws):,}")
    L.append(f"  Post-login commands ....... {n_cmds:,}")
    L.append(f"  Malware downloads ......... {len(downloads):,}  "
             f"({len({d[1] for d in downloads})} unique URLs)")
    L.append(f"  SSH tunnel requests ....... {n_tunnels:,}")
    L.extend(textwrap.wrap("  Behaviour mix (IPs) ....... " +
                           " | ".join(f"{t}: {n}" for t, n in tag_counts.most_common()),
                           WIDTH, subsequent_indent=" " * 30))
    top_ip = attackers[0]
    L.append("")
    L.append("  Key findings")
    L.append(f"   * One source ({top_ip.ip}, {top_ip.country}) produced {pct(top_ip.attempts, total_attempts).strip()} "
             f"of all login attempts ({top_ip.attempts:,} tries).")
    top_user, top_pw, top_cred = users.most_common(1)[0], pws.most_common(1)[0], creds.most_common(1)[0]
    L.append(f"   * '{top_user[0]}' was the most-tried username ({pct(top_user[1], total_attempts).strip()}); "
             f"'{fmt_pw(top_pw[0])}' the most-tried password; "
             f"top pair {fmt_cred(top_cred[0])} x{top_cred[1]:,}.")
    iot_share = sum(n for c, n in creds.items() if c in IOT_DEFAULT_CREDS)
    if tag_counts[PERSIST]:
        L.append(f"   * {tag_counts[PERSIST]} IP(s) planted SSH keys / cron jobs for persistent access "
                 f"after disabling shell history.")
    L.append(f"   * {pct(iot_share, total_attempts).strip()} of attempts used known IoT/vendor default "
             f"credentials (the lists Mirai-family bots use).")
    if n_tunnels:
        smtp = sum(n for a in actors.values() for p, n in a.tunnel_ports.items() if p in SMTP_PORTS)
        L.append(f"   * {tag_counts[PROXY]} IPs used the honeypot as an SSH proxy ({n_tunnels:,} tunnel requests, "
                 f"{pct(smtp, n_tunnels).strip()} to SMTP ports -> spam relaying).")
    if downloads:
        L.append(f"   * {tag_counts[DROPPER]} IP(s) logged in and pulled malware from "
                 f"{len({d[1] for d in downloads})} URL(s) - see IOC list.")
    if clients:
        c, n = clients.most_common(1)[0]
        L.append(f"   * Dominant client banner '{c}' ({pct(n, sum(clients.values())).strip()} of sessions "
                 f"that sent one) points to automated Go-based tooling, not humans.")

    start = L.index("  Key findings") + 1
    L[start:] = [w for b in L[start:] for w in
                 (textwrap.wrap(b, WIDTH - 2, subsequent_indent="     ") if b.startswith("   * ") else [b])]

    # 2 ---------------------------------------------------------------
    section(L, f"[2] TOP {top} ATTACKING IPs (by login attempts)")
    if not looks_like_ip(attackers[0].ip):
        L.append("  Source IPs are shown as anonymized IDs (see note at the top of the report).")
        L.append("")
    rows = []
    for i, a in enumerate(attackers[:top], 1):
        rows.append((i, a.ip, a.country[:14], f"{a.attempts:,}", pct(a.attempts, total_attempts),
                     len(a.sessions), len(a.users), a.successes,
                     a.first_auth.strftime("%H:%M"), a.last_auth.strftime("%H:%M"),
                     "+".join(SHORT_TAG[t] for t in a.tags)))
    table(L, ["#", "Source IP (pseudonym)", "Country", "Tries", "Share", "Sess", "Users", "OK",
              "First", "Last", "Behaviour"],
          rows, ["<", "<", "<", ">", ">", ">", ">", ">", "<", "<", "<"])

    # 3 ---------------------------------------------------------------
    section(L, "[3] CREDENTIAL INTELLIGENCE")
    counter_table(L, f"Most-tried USERNAMES (top {top})", users, total_attempts, top, "Username",
                  lambda u: u or "<empty>")
    counter_table(L, f"Most-tried PASSWORDS (top {top})", pws, total_attempts, top, "Password", fmt_pw)
    counter_table(L, f"Most-tried USERNAME/PASSWORD PAIRS (top {top})", creds, total_attempts, top,
                  "Credential pair", fmt_cred)
    counter_table(L, "SSH client banners", clients, sum(clients.values()), 6, "Client version")
    counter_table(L, "Login attempts by source country (dataset geolocation)", countries,
                  total_attempts, 8, "Country")

    # 4 ---------------------------------------------------------------
    section(L, "[4] THREAT ACTOR PROFILES (highest risk first)")
    notable = []
    for tag in (DROPPER, PERSIST, PROXY, BRUTE, BOTNET):
        best = next((a for a in by_risk if tag in a.tags and a not in notable), None)
        if best:
            notable.append(best)
    if attackers[0] not in notable:
        notable.append(attackers[0])
    shown = Counter(tuple(a.tags) for a in notable)
    for a in by_risk:
        if len(notable) >= 8 or a.score < 30:
            break
        if a not in notable and shown[tuple(a.tags)] < 2:
            notable.append(a)
            shown[tuple(a.tags)] += 1
    notable.sort(key=lambda a: (-a.score, -a.attempts))
    L.append("  One exemplar per behaviour class and the top talker, then the next highest-risk sources")
    L.append("  (max two per identical behaviour pattern; look-alikes are summarised in section [5]).")
    L.append("")
    for n, a in enumerate(notable, 1):
        L.extend(profile_block(n, a, total_attempts))
    others = [a for a in actors.values() if a not in notable]
    mix = ", ".join(f"{SHORT_TAG[t]} {n}" for t, n in Counter(t for o in others for t in o.tags).most_common())
    L.extend(textwrap.wrap(f"  Not profiled individually: {len(others)} sources, "
                           f"{sum(o.attempts for o in others):,} attempts (behaviour: {mix}). "
                           "Most belong to the clusters in section [5].", WIDTH, subsequent_indent="  "))

    # 5 ---------------------------------------------------------------
    section(L, "[5] CAMPAIGN / INFRASTRUCTURE CLUSTERS")
    L.append("  IPs grouped by shared artefacts. Pseudonymized IPs rule out /24 grouping,")
    L.append("  so clustering uses behaviour: same payload hash, same command script, same exact")
    L.append("  credential list, same tunnel ports.")
    L.append("")
    if not campaigns:
        L.append("  No clusters found.")
    for i, (kind, key, ips) in enumerate(campaigns[:10], 1):
        members = sorted(ips, key=lambda ip: -actors[ip].attempts)
        L.append(f"  C-{i:02d}  {kind}: {key}")
        L.append(f"        {len(ips)} IPs, {sum(actors[ip].attempts for ip in ips):,} login attempts, "
                 f"{sum(len(actors[ip].sessions) for ip in ips):,} sessions, countries: "
                 f"{', '.join(c for c, _ in Counter(actors[ip].country for ip in ips).most_common(4))}")
        L.append(f"        members: {', '.join(members[:5])}{' ...' if len(members) > 5 else ''}")

    # 6 ---------------------------------------------------------------
    section(L, "[6] TIMELINE - login attempts per hour (UTC)")
    hourly, tunnels_h = Counter(), Counter()
    for e in events:
        if e.kind in ("login_failed", "login_success"):
            hourly[e.ts.hour] += 1
        elif e.kind == "tunnel":
            tunnels_h[e.ts.hour] += 1
    peak = max(hourly.values()) if hourly else 0
    L.append("  Hour   Logins  Tunnels")
    for h in range(24):
        L.append(f"  {h:02d}:00 {hourly[h]:7,} {tunnels_h[h]:8,}  {bar(hourly[h], peak, 50)}")
    if hourly:
        ph = max(hourly, key=hourly.get)
        L.append(f"  Peak hour {ph:02d}:00 UTC with {hourly[ph]:,} attempts.")

    # 7 ---------------------------------------------------------------
    section(L, "[7] DEFENSIVE RECOMMENDATIONS")
    recs = [
        "Disable SSH password authentication (PasswordAuthentication no); use keys + MFA.",
        f"Never ship default credentials - {pct(iot_share, total_attempts).strip()} of attempts here used them. "
        "Force a password change on first boot for IoT/embedded devices.",
        f"Block or rename '{top_user[0]}' logins (PermitRootLogin no) - it was the #1 target.",
        "Rate-limit and auto-ban repeat offenders (fail2ban / sshguard; e.g. 5 failures -> 1 h ban).",
        "Disable TCP forwarding for untrusted users (AllowTcpForwarding no) to stop proxy/spam abuse.",
        "Egress-filter outbound SMTP (25/465/587) from servers that do not send mail.",
        "Feed the IOC list below into firewall / proxy / EDR blocklists and hunt for the file hashes.",
        "Alert on post-login discovery + history wiping (uname, unset HISTFILE) - strong intrusion signals.",
    ]
    for i, r in enumerate(recs, 1):
        L.extend(textwrap.wrap(r, WIDTH - 2, initial_indent=f"  {i}. ", subsequent_indent="     "))

    # 8 ---------------------------------------------------------------
    section(L, "[8] INDICATORS OF COMPROMISE (defanged)")
    L.append("  Malware download URLs and SHA-256 hashes:")
    seen = {}
    for ts, url, sha, ip in downloads:
        seen.setdefault((url, sha), []).append(ip)
    for (url, sha), ips in sorted(seen.items(), key=lambda kv: -len(kv[1])):
        L.append(f"    {defang(url):<38} sha256:{sha}  ({len(ips)} download{'s' * (len(ips) != 1)})")
    if not seen:
        L.append("    none")
    L.append("")
    keys = defaultdict(set)
    for a in actors.values():
        for _, cmd in a.commands:
            for m in SSH_KEY_RE.finditer(cmd):
                keys[(m.group(1), ssh_key_fingerprint(m.group(2)) or m.group(2)[:24] + "...",
                      m.group(3) or "-")].add(a.ip)
    L.append("  Attacker SSH public keys planted in authorized_keys (hunt for these on your hosts):")
    for (ktype, fp, comment), ips in sorted(keys.items(), key=lambda kv: -len(kv[1])):
        L.append(f"    {ktype} {fp}  comment '{comment}'  ({len(ips)} source IPs)")
    if not keys:
        L.append("    none")
    L.append("")
    L.append("  Source IP pseudonyms rated HIGH/CRITICAL (map back to real IPs with the dataset owner):")
    hot = [a for a in by_risk if a.severity in ("HIGH", "CRITICAL")]
    for i in range(0, len(hot), 4):
        L.append("    " + "   ".join(f"{a.ip} ({a.severity[0]})" for a in hot[i:i + 4]))
    if not hot:
        L.append("    none")

    section(L, "METHODOLOGY")
    L.extend([
        f"  Brute force  : >= {BRUTE_MIN_DISTINCT} distinct credential pairs AND (>= {BRUTE_MIN_ATTEMPTS} attempts,",
        f"                 or >= 20 attempts at >= {BRUTE_MIN_RATE:g}/min).",
        f"  IoT botnet   : >= {BOTNET_MIN_ATTEMPTS} attempts, >= {BOTNET_MIN_RATIO:.0%} of them known default credential pairs.",
        "  Proxy abuse  : any cowrie.direct-tcpip.request (attacker tunnels traffic through the honeypot).",
        "  Dropper      : a file download or wget/curl/tftp command after login.",
        "  Persistence  : writes ~/.ssh/authorized_keys or cron entries after login.",
        "  Risk score   : volume (<=25) + brute 15 + botnet 10 + post-auth activity 20 + tunnel 15",
        "                 + SMTP 5 + commands 10 + download 40 + anti-forensics 5",
        "                 + persistence 25, capped at 100.",
        "                 >=70 CRITICAL, >=50 HIGH, >=30 MEDIUM, else LOW.",
        "  Note         : a honeypot 'accepts' logins on purpose; 'OK' means the attacker got a fake shell.",
        "  (*) T1583.006 is the closest ATT&CK fit for spam relaying; no exact technique exists.",
    ])
    L.append("=" * WIDTH)
    return "\n".join(L) + "\n"


def profile_block(n, a, total):
    right = f" {a.severity} {a.score:>3}/100 --+"
    L = [f"  +-- TA-{n:02d}  {a.ip}  ({a.country}) ".ljust(WIDTH - len(right), "-") + right]

    def row(label, value):
        L.append(f"  |  {label:<15}: {value}")

    row("Behaviour", ", ".join(a.tags))
    row("Activity", f"{len(a.sessions):,} sessions, {a.attempts:,} login attempts "
                    f"({pct(a.attempts, total).strip()} of all), {a.first:%H:%M} -> {a.last:%H:%M} UTC")
    if a.attempts:
        rate = a.attempts / max(a.auth_minutes, 1.0)
        row("Tempo", f"{rate:,.2f} attempts/min over {a.auth_minutes:,.0f} min")
        row("Top usernames", ", ".join(f"{u or '<empty>'}({c})" for u, c in a.users.most_common(5)))
        row("Top passwords", ", ".join(f"{fmt_pw(p)}({c})" for p, c in a.passwords.most_common(5)))
        iot = sum(c for cr, c in a.creds.items() if cr in IOT_DEFAULT_CREDS)
        row("Default creds", f"{pct(iot, a.attempts).strip()} of attempts used IoT/vendor defaults")
    if a.first_success:
        ts, u, p = a.first_success
        row("Honeypot login", f"{a.successes} accepted, first {ts:%H:%M:%S} as {fmt_cred((u, p))}")
    if a.clients:
        row("Client", ", ".join(f"{c}({n})" for c, n in a.clients.most_common(2)))
    if a.tunnels:
        ports = a.tunnel_ports
        row("Tunnels", f"{sum(ports.values()):,} requests to {len(a.tunnels)} destination(s); ports " +
            ", ".join(f"{p}({c})" for p, c in ports.most_common(5)))
    if a.commands:
        uniq = list(dict.fromkeys(c for _, c in a.commands))
        row("Commands", f"{len(a.commands)} run, {len(uniq)} unique:")
        for c in uniq[:12]:
            L.append(f"  |                   $ {defang_cmd(c)[:WIDTH - 24]}")
    if a.downloads:
        for url, sha in dict.fromkeys((u, s) for _, u, s in a.downloads):
            row("Payload", f"{defang(url)}  sha256:{sha[:16]}...")
    row("MITRE ATT&CK", "")
    for tid, name in a.ttps.items():
        L.append(f"  |                   {tid:<10} {name}")
    wrapped = textwrap.wrap(assessment(a), WIDTH - 22)
    row("Assessment", wrapped[0])
    L.extend(f"  |                   {w}" for w in wrapped[1:])
    L.append("  +" + "-" * (WIDTH - 4) + "+")
    L.append("")
    return L


def defang_cmd(cmd):
    return URL_RE.sub(lambda m: defang(m.group(0)), cmd)


def assessment(a):
    parts = []
    if PERSIST in a.tags:
        steps = ["logged in"]
        if "T1082" in a.ttps:
            steps.append("fingerprinted the system")
        if "T1070.003" in a.ttps:
            steps.append("disabled shell history")
        steps.append("planted an attacker SSH key / cron job for persistent access")
        parts.append("Backdoor installation: " + ", ".join(steps))
    if DROPPER in a.tags:
        steps = ["logged in"]
        if "T1082" in a.ttps:
            steps.append("fingerprinted the system")
        if "T1070.003" in a.ttps:
            steps.append("disabled shell history")
        steps.append("fetched a payload" + (" and executed it" if "T1059.004" in a.ttps else ""))
        parts.append("Automated intrusion: " + ", ".join(steps) +
                     " - a typical Linux bot infection chain")
    elif PROXY in a.tags:
        smtp = SMTP_PORTS & set(a.tunnel_ports)
        cred = "a known default credential" if "T1078.001" in a.ttps else "an accepted credential"
        parts.append(f"Logs in with {cred} and tunnels traffic through the host" +
                     (" - outbound spam relay" if smtp else " - anonymising web proxy"))
    if BRUTE in a.tags:
        parts.append(f"high-volume credential guessing ({a.attempts:,} tries)")
    if BOTNET in a.tags:
        parts.append("credentials come from public IoT/vendor default lists")
    if SCANNER in a.tags:
        parts.append("low-effort opportunistic scanning")
    text = "; ".join(parts)
    return text[0].upper() + text[1:] + "."


# --------------------------------------------------------------------------
# Console summary + entry point
# --------------------------------------------------------------------------

def console_summary(stats, actors, report_path, top=5):
    attackers = sorted((a for a in actors.values() if a.attempts), key=lambda a: -a.attempts)
    total = sum(a.attempts for a in attackers)
    users, pws = Counter(), Counter()
    for a in attackers:
        users.update(a.users)
        pws.update(a.passwords)
    log.info("-" * 72)
    log.info("Parsed %s lines: %s events, %s ignored, %s malformed",
             f"{stats['lines']:,}", f"{stats['parsed']:,}", stats["ignored"], stats["malformed"])
    log.info("%s login attempts from %d IPs", f"{total:,}", len(attackers))
    log.info("")
    if attackers and not looks_like_ip(attackers[0].ip):
        log.info("Note: source IPs are anonymized IDs (SHA-256 by the dataset authors), not x.x.x.x")
        log.info("")
    log.info("TOP ATTACKING IPs           TOP USERNAMES          TOP PASSWORDS")
    ips = [f"{a.ip} {a.attempts:>5,}" for a in attackers[:top]]
    us = [f"{(u or '<empty>')[:14]:<14} {n:>5,}" for u, n in users.most_common(top)]
    ps = [f"{fmt_pw(p)[:14]:<14} {n:>5,}" for p, n in pws.most_common(top)]
    for i in range(top):
        log.info("%-27s %-22s %s", ips[i] if i < len(ips) else "", us[i] if i < len(us) else "",
                 ps[i] if i < len(ps) else "")
    log.info("")
    for a in sorted(actors.values(), key=lambda a: -a.score):
        if a.severity == "CRITICAL":
            log.warning("[ALERT] %s %s (%s) score %d: %s", a.severity, a.ip, a.country, a.score,
                        ", ".join(a.tags))
    sev = Counter(a.severity for a in actors.values())
    log.info("Severity: CRITICAL %d | HIGH %d | MEDIUM %d | LOW %d",
             sev["CRITICAL"], sev["HIGH"], sev["MEDIUM"], sev["LOW"])
    log.info("Threat Actor Profile written to %s", report_path)
    log.info("-" * 72)


def setup_logging(log_path, verbose):
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(console)
    if log_path:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, mode="w", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s", "%Y-%m-%d %H:%M:%S"))
        log.addHandler(fh)


def display_path(p):
    try:
        return Path(p).resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return str(p)


def main(argv=None):
    ap = argparse.ArgumentParser(description="SSH honeypot log analyzer / threat-actor profiler")
    ap.add_argument("-i", "--input", default=str(ROOT / "evidence" / "sample_data.txt"),
                    help="Cowrie JSON-lines log (default: evidence/sample_data.txt)")
    ap.add_argument("-o", "--output", default=str(ROOT / "evidence" / "honeypot_analysis.txt"),
                    help="report file (default: evidence/honeypot_analysis.txt)")
    ap.add_argument("-l", "--log", default=str(ROOT / "logs" / "output.log"),
                    help="run log (default: logs/output.log); '' to disable")
    ap.add_argument("-n", "--top", type=int, default=10, help="rows in top-N tables (default 10)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show debug messages on console")
    args = ap.parse_args(argv)

    setup_logging(args.log, args.verbose)
    log.info("Honeypot Log Analyzer v%s", VERSION)
    log.info("Input : %s", display_path(args.input))
    if not Path(args.input).is_file():
        log.error("Input file not found: %s", args.input)
        return 2

    events, stats = parse_log(args.input)
    if not events:
        log.error("No usable honeypot events found in %s", args.input)
        return 1
    actors = build_actors(events)
    for a in actors.values():
        classify(a)
    campaigns = find_campaigns(actors)
    log.debug("Classified %d actors, %d campaign clusters", len(actors), len(campaigns))

    report = build_report(events, stats, actors, campaigns, display_path(args.input), args.top)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    console_summary(stats, actors, display_path(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
