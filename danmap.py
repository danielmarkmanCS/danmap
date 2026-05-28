#!/usr/bin/env python3
"""danmap — Daniel's port scanner v2.0"""

import asyncio
import socket
import argparse
import subprocess
import re
import json
import csv
import ipaddress
import urllib.request
import urllib.parse
import os
import pathlib
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

# ── TIMING TEMPLATES ───────────────────────────────────────────────────────
# Maps -T flag to (max_concurrent_connections, timeout_per_port).
# Higher T = more aggressive = faster but louder on the network.
TIMING = {
    1: (50,   3.0),   # paranoid  — slow, hard to detect
    2: (150,  2.0),   # polite
    3: (300,  1.5),   # normal    (default)
    4: (500,  1.0),   # aggressive
    5: (1000, 0.5),   # insane    — fast, easily detected
}
TIMING_NAMES = {1: "paranoid", 2: "polite", 3: "normal", 4: "aggressive", 5: "insane"}

KNOWN_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}
COMMON_PORTS = list(KNOWN_SERVICES.keys())

# ── SERVICE PROBES ─────────────────────────────────────────────────────────
# Some services send a banner the moment you connect (SSH, FTP, SMTP).
# Others are silent until you send something (HTTP, Redis).
#
# None  = just read — server speaks first
# bytes = send this probe, then read
SERVICE_PROBES: dict[int | str, bytes | None] = {
    21:   None,                              # FTP     — server greets you
    22:   None,                              # SSH     — server greets you
    25:   b"EHLO danmap\r\n",               # SMTP
    80:   b"HEAD / HTTP/1.0\r\n\r\n",       # HTTP
    110:  None,                              # POP3    — server greets you
    143:  None,                              # IMAP    — server greets you
    443:  b"HEAD / HTTP/1.0\r\n\r\n",       # HTTPS   (no TLS — gets error banner with version)
    445:  None,                              # SMB
    3306: None,                              # MySQL   — server greets you
    5432: None,                              # Postgres
    6379: b"PING\r\n",                       # Redis
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    27017: None,                             # MongoDB
    "_default": b"HEAD / HTTP/1.0\r\n\r\n",
}

# ── VERSION EXTRACTION ─────────────────────────────────────────────────────
# Regexes to pull a (software, version) pair out of a banner string.
# Used as the query key for CVE lookup.
VERSION_PATTERNS = [
    (r"SSH-[\d.]+-OpenSSH_([\d.p]+)",   "OpenSSH"),
    (r"Server: Apache/([\d.]+)",         "Apache httpd"),
    (r"Server: nginx/([\d.]+)",          "nginx"),
    (r"Server: Microsoft-IIS/([\d.]+)",  "Microsoft IIS"),
    (r"220.*vsftpd ([\d.]+)",            "vsftpd"),
    (r"ProFTPD ([\d.]+)",                "ProFTPD"),
    (r"MySQL.*?([\d]+\.[\d]+\.[\d]+)",   "MySQL"),
    (r"OpenSSL/([\d.]+\w*)",             "OpenSSL"),
    (r"Postfix",                          "Postfix"),
]

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "UNKNOWN":  "dim",
}

# Auto-save directory — every scan is saved here so --diff can compare later
SCAN_DIR = pathlib.Path.home() / ".danmap" / "scans"

BANNER = r"""
[bold red]
 ██████╗  █████╗ ███╗   ██╗███╗   ███╗ █████╗ ██████╗
 ██╔══██╗██╔══██╗████╗  ██║████╗ ████║██╔══██╗██╔══██╗
 ██║  ██║███████║██╔██╗ ██║██╔████╔██║███████║██████╔╝
 ██║  ██║██╔══██║██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝
 ██████╔╝██║  ██║██║ ╚████║██║ ╚═╝ ██║██║  ██║██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
[/bold red][dim]  Daniel's Port Scanner — v2.0[/dim]
"""


# ── PORT SCANNER ───────────────────────────────────────────────────────────
# One connection per port — opens it, sends a probe (if needed), reads
# the banner, then closes. No second connection for banner grabbing.
# The semaphore keeps concurrent open sockets under control.
async def scan_port(
    host: str, port: int, timeout: float,
    sem: asyncio.Semaphore, progress, task_id,
) -> tuple[int, bool, str]:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            probe = SERVICE_PROBES.get(port, SERVICE_PROBES["_default"])
            if probe:
                writer.write(probe)
                await writer.drain()
            try:
                raw = await asyncio.wait_for(reader.read(1024), timeout=min(timeout, 2.0))
                banner = raw.decode(errors="ignore").strip().split("\n")[0][:70]
            except asyncio.TimeoutError:
                banner = ""
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
            progress.advance(task_id)
            return (port, True, banner)
        except Exception:
            progress.advance(task_id)
            return (port, False, "")


async def scan_host(
    host: str, ports: list[int], timeout: float,
    concurrency: int, progress, task_id,
) -> list[tuple[int, str]]:
    sem = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(*[
        scan_port(host, p, timeout, sem, progress, task_id) for p in ports
    ])
    return [(port, banner) for port, is_open, banner in results if is_open]


# ── HOST DISCOVERY ─────────────────────────────────────────────────────────
# For subnet scans we ping-sweep first so we don't waste time
# port-scanning hosts that aren't alive.
async def ping_host(host: str) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "1", host,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=2)
        return proc.returncode == 0
    except Exception:
        return False

async def discover_hosts(targets: list[str]) -> list[str]:
    sem = asyncio.Semaphore(100)
    async def check(host):
        async with sem:
            return host if await ping_host(host) else None
    results = await asyncio.gather(*[check(h) for h in targets])
    return [h for h in results if h]


# ── OS DETECTION ───────────────────────────────────────────────────────────
def ttl_os_guess(host: str) -> tuple[str, int]:
    try:
        out = subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", host],
            stderr=subprocess.DEVNULL, timeout=3,
        ).decode(errors="ignore")
        m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        if not m:
            return ("unknown", 0)
        ttl = int(m.group(1))
        if ttl <= 64:  return ("Linux / macOS", ttl)
        if ttl <= 128: return ("Windows", ttl)
        return ("Cisco / Network Device", ttl)
    except Exception:
        return ("unknown", 0)

BANNER_OS_PATTERNS = [
    (r"ubuntu",          "Linux — Ubuntu"),
    (r"debian",          "Linux — Debian"),
    (r"centos",          "Linux — CentOS"),
    (r"fedora",          "Linux — Fedora"),
    (r"red.?hat|rhel",   "Linux — Red Hat"),
    (r"freebsd",         "FreeBSD"),
    (r"openbsd",         "OpenBSD"),
    (r"microsoft|iis",   "Windows"),
    (r"darwin|mac os",   "macOS"),
    (r"synology",        "Synology NAS"),
    (r"mikrotik",        "MikroTik"),
    (r"linux",           "Linux"),
]

def detect_os(host: str, open_ports: list[tuple[int, str]]) -> str:
    ports   = [p for p, _ in open_ports]
    banners = [b for _, b in open_ports if b]
    combined = " ".join(banners).lower()

    ttl_guess, ttl_val = ttl_os_guess(host)
    ttl_note = f"TTL {ttl_val}" if ttl_val else ""

    for pattern, label in BANNER_OS_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            note = "banner" + (f", {ttl_note}" if ttl_note else "")
            return f"{label}  [dim]({note})[/dim]"

    if ttl_guess != "unknown":
        return f"{ttl_guess}  [dim]({ttl_note})[/dim]"

    port_set = set(ports)
    if 3389 in port_set or 5985 in port_set:
        return "Windows  [dim](RDP/WinRM)[/dim]"
    if 22 in port_set:
        return "Linux / Unix  [dim](port heuristic)[/dim]"
    return "[dim]unknown[/dim]"


# ── VERSION + CVE LOOKUP ───────────────────────────────────────────────────
def extract_version(banner: str) -> tuple[str, str] | None:
    for pattern, name in VERSION_PATTERNS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            version = m.group(1) if m.lastindex else ""
            return (name, version)
    return None

_cve_cache: dict[str, list[dict]] = {}

def lookup_cves(software: str, version: str) -> list[dict]:
    """
    Queries the NVD (National Vulnerability Database) API.
    Returns top 3 CVEs matching software+version, with severity.
    Results are cached so the same software is only queried once.
    """
    key = f"{software} {version}".strip()
    if key in _cve_cache:
        return _cve_cache[key]
    try:
        query = urllib.parse.quote(key)
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={query}&resultsPerPage=3"
        )
        req = urllib.request.Request(url, headers={"User-Agent": "danmap/2.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read())
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description",
            )[:100]
            severity = "UNKNOWN"
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(metric_key)
                if metrics:
                    severity = metrics[0]["cvssData"].get("baseSeverity", "UNKNOWN")
                    break
            cves.append({"id": cve["id"], "severity": severity, "desc": desc})
        _cve_cache[key] = cves
        return cves
    except Exception:
        _cve_cache[key] = []
        return []


# ── PARSING ────────────────────────────────────────────────────────────────
def parse_ports(arg: str) -> list[int]:
    if arg == "common":
        return COMMON_PORTS
    if "-" in arg and "," not in arg:
        s, e = arg.split("-", 1)
        return list(range(int(s), int(e) + 1))
    return [int(p.strip()) for p in arg.split(",")]

def parse_targets(target: str) -> list[str]:
    """
    Accepts three formats:
      192.168.1.0/24     → CIDR, expands to all host IPs
      192.168.1.1-50     → range, expands prefix.1 to prefix.50
      hostname / IP      → single target
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass
    m = re.match(r"^([\d.]+\.)(\d+)-(\d+)$", target)
    if m:
        prefix = m.group(1)
        return [f"{prefix}{i}" for i in range(int(m.group(2)), int(m.group(3)) + 1)]
    return [target]

def resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


# ── OUTPUT ─────────────────────────────────────────────────────────────────
def save_output(results: list[dict], path: str):
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if ext == "json":
        with open(path, "w") as f:
            json.dump(results, f, indent=2, default=str)
    elif ext == "csv":
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["host", "ip", "os", "port", "service", "banner", "cve_ids"])
            for r in results:
                os_plain = re.sub(r"\[.*?\]", "", r["os"]).strip()
                for p in r["ports"]:
                    cve_ids = " | ".join(c["id"] for c in p.get("cves", []))
                    w.writerow([r["host"], r["ip"], os_plain,
                                p["port"], p["service"], p["banner"], cve_ids])
    elif ext == "txt":
        with open(path, "w") as f:
            for r in results:
                os_plain = re.sub(r"\[.*?\]", "", r["os"]).strip()
                f.write(f"Host: {r['host']}  ({r['ip']})\n")
                f.write(f"OS:   {os_plain}\n")
                f.write(f"Open ports: {len(r['ports'])}\n")
                for p in r["ports"]:
                    cve_ids = ", ".join(c["id"] for c in p.get("cves", []))
                    cve_note = f"  CVEs: {cve_ids}" if cve_ids else ""
                    f.write(f"  {p['port']:<7} {p['service']:<14} {p['banner']}{cve_note}\n")
                f.write("\n")
    else:
        console.print(f"\n  [red]✗ Unknown format '[bold]{ext}[/bold]' — use .json, .csv, or .txt[/red]")
        return
    console.print(f"\n  [green]✓ Saved →[/green] [cyan]{path}[/cyan]")


# ── AUTO-SAVE & DIFF ──────────────────────────────────────────────────────
#
# Every scan is saved to ~/.danmap/scans/<host>_last.json.
# --diff loads that file, compares with the current results,
# and shows exactly what changed: new ports, closed ports, banner changes.
# After the diff, the file is overwritten with the latest scan.

def auto_save(host: str, results: list[dict]):
    SCAN_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.-]", "_", host)
    with open(SCAN_DIR / f"{safe}_last.json", "w") as f:
        json.dump({"timestamp": datetime.now().isoformat(), "results": results}, f, indent=2)

def load_last_scan(host: str) -> dict | None:
    safe = re.sub(r"[^\w.-]", "_", host)
    path = SCAN_DIR / f"{safe}_last.json"
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def show_diff(old: dict, new_results: list[dict]):
    ts = old.get("timestamp", "")[:16].replace("T", " ")
    console.print(f"\n[bold red]  ── Diff vs scan from {ts} ──[/bold red]\n")

    old_by_host = {r["host"]: r for r in old.get("results", [])}
    new_by_host = {r["host"]: r for r in new_results}
    multi = len(new_by_host) > 1

    for host in sorted(set(list(old_by_host) + list(new_by_host))):
        if multi:
            console.print(f"[bold cyan]  ▶ {host}[/bold cyan]")

        old_ports = {p["port"]: p for p in old_by_host.get(host, {}).get("ports", [])}
        new_ports = {p["port"]: p for p in new_by_host.get(host, {}).get("ports", [])}
        all_ports = sorted(set(list(old_ports) + list(new_ports)))

        changes = 0
        unchanged = 0
        for port in all_ports:
            in_old = port in old_ports
            in_new = port in new_ports

            if in_new and not in_old:
                p = new_ports[port]
                console.print(f"  [bold green][+] NEW    [/bold green]  {port:<7} {p['service']:<14} {p['banner']}")
                changes += 1
            elif in_old and not in_new:
                p = old_ports[port]
                console.print(f"  [bold red][-] CLOSED [/bold red]  {port:<7} {p['service']:<14} [dim]{p['banner']}[/dim]")
                changes += 1
            else:
                old_b = old_ports[port]["banner"]
                new_b = new_ports[port]["banner"]
                if old_b != new_b:
                    svc = new_ports[port]["service"]
                    console.print(f"  [yellow][~] CHANGED[/yellow]  {port:<7} {svc}")
                    console.print(f"             [dim]was: {old_b}[/dim]")
                    console.print(f"             [dim]now: {new_b}[/dim]")
                    changes += 1
                else:
                    unchanged += 1

        if unchanged:
            console.print(f"  [dim][=] {unchanged} port(s) unchanged[/dim]")
        if not changes and not unchanged:
            console.print(f"  [dim]Host not seen in previous scan[/dim]")


# ── AI CONFIG ──────────────────────────────────────────────────────────────
# Reads from ~/.danmap/.env. Supported keys:
#   DANMAP_AI_URL    — Cloudflare Worker URL  (preferred, no Gemini key needed)
#   DANMAP_AI_TOKEN  — token for the Worker   (set via: wrangler secret put DANMAP_TOKEN)
#   GEMINI_API_KEY   — fallback: call Gemini directly
def load_ai_config() -> dict:
    cfg: dict = {}
    for env_key in ("DANMAP_AI_URL", "DANMAP_AI_TOKEN", "GEMINI_API_KEY"):
        val = os.environ.get(env_key)
        if val:
            cfg[env_key] = val

    env_path = pathlib.Path.home() / ".danmap" / ".env"
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                for key in ("DANMAP_AI_URL", "DANMAP_AI_TOKEN", "GEMINI_API_KEY"):
                    if line.startswith(f"{key}=") and key not in cfg:
                        cfg[key] = line.split("=", 1)[1].strip().strip("\"'")
    except Exception:
        pass
    return cfg


# ── AI ANALYSIS ────────────────────────────────────────────────────────────
# Tries the Cloudflare Worker first (no Gemini key needed locally).
# Falls back to calling Gemini directly if only GEMINI_API_KEY is set.
def ai_analyze(results: list[dict], cfg: dict):
    console.print("\n[bold red]  ── AI Security Analysis ──[/bold red]\n")

    # Build compact scan summary
    lines = []
    for r in results:
        os_plain = re.sub(r"\[.*?\]", "", r["os"]).strip()
        lines.append(f"Host: {r['host']}  OS: {os_plain}")
        for p in r["ports"]:
            cve_note = ("  CVEs: " + ", ".join(c["id"] for c in p["cves"])) if p.get("cves") else ""
            lines.append(f"  port {p['port']} {p['service']}: {p['banner']}{cve_note}")
    scan_text = "\n".join(lines)

    try:
        worker_url = cfg.get("DANMAP_AI_URL")
        token      = cfg.get("DANMAP_AI_TOKEN", "")

        if worker_url:
            # ── via Cloudflare Worker (no Gemini key on this machine) ──
            endpoint = worker_url.rstrip("/") + "/security-analyze"
            payload  = json.dumps({"scan": scan_text}).encode()
            req = urllib.request.Request(
                endpoint,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "danmap/2.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            text = data.get("analysis", "").strip()

        elif cfg.get("GEMINI_API_KEY"):
            # ── direct Gemini fallback ──
            prompt = (
                "You are a cybersecurity expert. Analyze this port scan and respond in EXACTLY this format:\n\n"
                "RISK: [LOW / MEDIUM / HIGH / CRITICAL]\n\n"
                "FINDINGS:\n• [one line per notable port or issue]\n\n"
                "RECOMMENDATIONS:\n1. [specific action]\n2. [specific action]\n\n"
                "Keep it short and actionable. Scan results:\n\n" + scan_text
            )
            url = (
                "https://generativelanguage.googleapis.com/v1beta/models/"
                f"gemini-2.5-flash:generateContent?key={cfg['GEMINI_API_KEY']}"
            )
            req = urllib.request.Request(
                url,
                data=json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            text = data["candidates"][0]["content"]["parts"][0]["text"].strip()

        else:
            console.print("  [red]✗ No AI config found. Add to ~/.danmap/.env:[/red]")
            console.print("  [dim]DANMAP_AI_URL=https://fuelsync-ai.<id>.workers.dev[/dim]")
            console.print("  [dim]DANMAP_AI_TOKEN=your-token[/dim]")
            return

        # Color-code the structured output
        risk_colors = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}
        for line in text.split("\n"):
            if line.startswith("RISK:"):
                level = line.split(":", 1)[1].strip()
                col = risk_colors.get(level, "white")
                console.print(f"  [bold]Risk:[/bold]  [{col}]{level}[/{col}]")
            elif line.startswith("FINDINGS:") or line.startswith("RECOMMENDATIONS:"):
                console.print(f"\n  [bold]{line}[/bold]")
            elif line.startswith("•"):
                console.print(f"  [yellow]{line}[/yellow]")
            elif line and line[0].isdigit() and ". " in line:
                console.print(f"  [cyan]{line}[/cyan]")
            elif line:
                console.print(f"  {line}")

    except Exception as e:
        console.print(f"  [red]✗ AI analysis failed: {e}[/red]")


# ── MAIN ───────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="danmap",
        description="danmap — Daniel's port scanner v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  danmap 192.168.1.1
  danmap 192.168.1.0/24              subnet scan
  danmap 192.168.1.1-50              host range
  danmap google.com -p 1-1000 -T 4
  danmap 192.168.1.1 --cve -o out.json
  danmap 10.0.0.1 -p 22,80,443 -o results.csv
        """
    )
    parser.add_argument("target")
    parser.add_argument("-p", "--ports",   default="common",
                        help="common | 80 | 22,80,443 | 1-65535  (default: common)")
    parser.add_argument("-T", "--timing",  type=int, choices=[1,2,3,4,5], default=3,
                        help="1=paranoid  3=normal  5=insane  (default: 3)")
    parser.add_argument("-c", "--concurrency", type=int,
                        help="Override concurrent connections from -T")
    parser.add_argument("--timeout", type=float,
                        help="Override per-port timeout from -T")
    parser.add_argument("--cve",  action="store_true",
                        help="Look up CVEs for detected service versions (requires internet)")
    parser.add_argument("--diff", action="store_true",
                        help="Compare with last scan of the same target and show changes")
    parser.add_argument("--ai",   action="store_true",
                        help="Run Gemini AI security analysis on the results")
    parser.add_argument("-o", "--output",
                        help="Save results to file:  out.json, out.csv, or out.txt")
    args = parser.parse_args()

    base_concurrency, base_timeout = TIMING[args.timing]
    concurrency = args.concurrency or base_concurrency
    timeout     = args.timeout     or base_timeout

    console.print(BANNER)

    targets = parse_targets(args.target)
    ports   = parse_ports(args.ports)
    multi   = len(targets) > 1

    console.print(f"  [bold]Target     [/bold] [cyan]{args.target}[/cyan]" +
                  (f"  [dim]({len(targets)} hosts)[/dim]" if multi else ""))
    console.print(f"  [bold]Ports      [/bold] {len(ports)} ports")
    console.print(f"  [bold]Timing     [/bold] T{args.timing} — {TIMING_NAMES[args.timing]}"
                  f"  [dim]({concurrency} concurrent, {timeout}s/port)[/dim]")
    console.print(f"  [bold]CVE lookup [/bold] " +
                  ("[green]on[/green]" if args.cve else "[dim]off[/dim]  (--cve to enable)"))
    console.print(f"  [bold]Diff       [/bold] " +
                  ("[green]on[/green]" if args.diff else "[dim]off[/dim]  (--diff to enable)"))
    console.print(f"  [bold]AI analysis[/bold] " +
                  ("[green]on[/green]" if args.ai else "[dim]off[/dim]  (--ai to enable)"))
    console.print(f"  [bold]Started    [/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Load previous scan before running (so we can diff after)
    prev_scan = load_last_scan(args.target) if args.diff else None
    if args.diff and not prev_scan:
        console.print("  [yellow]⚠ No previous scan found for this target — running fresh scan[/yellow]\n")

    all_results: list[dict] = []

    async def run_all():
        live = targets
        if multi:
            console.print(f"  [dim]Pinging {len(targets)} hosts...[/dim]")
            live = await discover_hosts(targets)
            console.print(f"  [green]✓ {len(live)} live host(s)[/green]\n")
            if not live:
                return

        with Progress(
            SpinnerColumn(style="red"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=38, complete_style="red"),
            TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task(
                f"Scanning {'subnet' if multi else args.target}",
                total=len(live) * len(ports),
            )
            for host in live:
                ip = resolve(host)
                open_ports = await scan_host(host, ports, timeout, concurrency, progress, task_id)

                # CVE lookup per open port
                ports_data = []
                for port, banner in open_ports:
                    cves = []
                    if args.cve and banner:
                        ver = extract_version(banner)
                        if ver:
                            cves = lookup_cves(*ver)
                    ports_data.append({
                        "port":    port,
                        "service": KNOWN_SERVICES.get(port, "unknown"),
                        "banner":  banner,
                        "cves":    cves,
                    })

                all_results.append({
                    "host":  host,
                    "ip":    ip,
                    "os":    detect_os(ip, open_ports),
                    "ports": ports_data,
                })

    asyncio.run(run_all())

    # ── PRINT RESULTS ──────────────────────────────────────────────────────
    for r in all_results:
        ip_note = f"  →  [yellow]{r['ip']}[/yellow]" if r["ip"] != r["host"] else ""
        console.print(f"\n[bold cyan]  ▶ {r['host']}[/bold cyan]{ip_note}")
        console.print(f"  [bold]OS[/bold]  {r['os']}")
        console.print(f"  [bold green]{len(r['ports'])} open port(s)[/bold green]")

        if r["ports"]:
            table = Table(
                show_header=True, header_style="bold red",
                border_style="dim", show_lines=args.cve,
            )
            table.add_column("PORT",    style="cyan bold", width=8)
            table.add_column("SERVICE", style="yellow",    width=12)
            table.add_column("BANNER",  style="dim",       min_width=20)
            if args.cve:
                table.add_column("CVEs", width=42)

            for p in r["ports"]:
                cve_text = ""
                if args.cve:
                    if p["cves"]:
                        lines = []
                        for c in p["cves"]:
                            col = SEVERITY_COLORS.get(c["severity"], "dim")
                            lines.append(f"[{col}]{c['id']}  [{c['severity']}][/{col}]"
                                         f"\n[dim]{c['desc']}[/dim]")
                        cve_text = "\n\n".join(lines)
                    else:
                        cve_text = "[dim]none found[/dim]"

                row = [str(p["port"]), p["service"], p["banner"]]
                if args.cve:
                    row.append(cve_text)
                table.add_row(*row)

            console.print(table)
        else:
            console.print("  [dim]No open ports.[/dim]")

    # ── SUBNET SUMMARY ─────────────────────────────────────────────────────
    if len(all_results) > 1:
        console.print("\n[bold red]  ── Subnet Summary ──[/bold red]\n")
        summary = Table(show_header=True, header_style="bold red", border_style="dim")
        summary.add_column("HOST",       style="cyan",   width=16)
        summary.add_column("OPEN",       style="yellow", width=6)
        summary.add_column("SERVICES",   style="dim",    min_width=28)
        summary.add_column("OS",         style="green")

        for r in all_results:
            services = ", ".join(
                p["service"] for p in r["ports"] if p["service"] != "unknown"
            ) or "—"
            os_plain = re.sub(r"\[.*?\]", "", r["os"]).strip()
            summary.add_row(r["host"], str(len(r["ports"])), services, os_plain)

        console.print(summary)

    # Auto-save this scan (always) so future --diff can use it
    auto_save(args.target, all_results)

    # Show diff against previous scan
    if args.diff and prev_scan:
        show_diff(prev_scan, all_results)

    # Gemini AI analysis
    if args.ai:
        ai_analyze(all_results, load_ai_config())

    if args.output:
        save_output(all_results, args.output)

    console.print(f"\n  [dim]Scan complete — {datetime.now().strftime('%H:%M:%S')}[/dim]\n")


if __name__ == "__main__":
    main()
