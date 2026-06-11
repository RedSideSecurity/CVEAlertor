#!/usr/bin/env python3
"""
CVEAlertor - watch for new CVEs affecting your stack and alert via Telegram.

You tell it which products you run (Zabbix, Roundcube, ESXi, ...). On the first
run it pulls every existing CVE for each product into a per-service baseline
file. On every run after that it re-fetches, diffs against the baseline, and
sends an instant Telegram alert for each NEW CVE - then updates the baseline.

Backend: the NVD API (https://nvd.nist.gov), the official NIST CVE feed. It
gives keyword search per product plus CVSS score, severity and publish date.
A free API key (optional) just raises the rate limit.

PoC watching (optional, on by default): for the most recent CVEs of each
service it also checks the community PoC index at
https://github.com/nomi-sec/PoC-in-GitHub (served from the raw CDN, no API key,
no rate limit) and alerts when a NEW public proof-of-concept / exploit repo
appears for a CVE you already track - which is the common case, since PoCs are
usually published days/weeks after the CVE itself. PoC state is kept in its own
per-service file and diffed exactly like the CVE baseline.

Usage:
    python cvealertor.py --setup              # interactive wizard (recommended)
    python cvealertor.py --once               # one CVE check cycle (ideal for cron)
    python cvealertor.py --check-pocs         # one PoC check cycle (ideal for daily cron)
    python cvealertor.py --watch              # loop forever (CVE + PoC, intervals from config)
    sudo python cvealertor.py --install-service    # run on boot (systemd / Task Sched.)
    sudo python cvealertor.py --uninstall          # remove service + all data

Config (config.json):
    {
      "telegram": { "bot_token": "123:ABC", "chat_id": "123456789" },
      "nvd_api_key": "",
      "min_cvss": 0.0,
      "interval_seconds": 3600,
      "alert_on_first_run": false,
      "poc_monitoring": true,            # watch GitHub for public PoCs/exploits
      "poc_watch_recent": 20,            # only the N most-recent CVEs per service
      "poc_interval_seconds": 86400,     # how often to run the PoC cycle (daily)
      "services": [
        { "name": "Zabbix",     "keyword": "zabbix" },
        { "name": "Roundcube",  "keyword": "roundcube" },
        { "name": "VMware ESXi","keyword": "esxi" }
      ]
    }
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

SCRIPT_PATH = os.path.abspath(__file__)
SERVICE_NAME = "cvealertor"

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
STATE_DIR = os.path.join(HERE, "state")
LOG_PATH = os.path.join(HERE, "cvealertor.log")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TELEGRAM_URL = "https://api.telegram.org/bot{token}/sendMessage"
PAGE_SIZE = 2000  # NVD max resultsPerPage

# Community PoC index: per-CVE JSON on the raw CDN (no API key, no rate limit).
# 200 -> JSON array of GitHub repos; 404 -> no public PoC for that CVE.
POC_RAW_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"

SAMPLE_CONFIG = {
    "telegram": {"bot_token": "PUT-YOUR-BOT-TOKEN-HERE", "chat_id": "PUT-YOUR-CHAT-ID-HERE"},
    "nvd_api_key": "",
    "min_cvss": 0.0,
    "interval_seconds": 3600,
    "alert_on_first_run": False,
    "poc_monitoring": True,
    "poc_watch_recent": 20,
    "poc_interval_seconds": 86400,
    "services": [
        {"name": "Zabbix", "keyword": "zabbix"},
        {"name": "Roundcube", "keyword": "roundcube"},
        {"name": "VMware ESXi", "keyword": "esxi"},
    ],
}

# ---------------------------------------------------------------------------
# Service naming
# ---------------------------------------------------------------------------
#
# NAMING RULES (how a client must type a service name):
#   1. lowercase
#   2. PRODUCT NAME ONLY - no version numbers   (type "zabbix", NOT "zabbix 6.4")
#   3. one product per line
#   4. use the common product name as shown in the catalog below; a few
#      aliases are accepted (e.g. "vmware esxi" -> esxi, "exchange" -> microsoft exchange)
#
# The catalog maps what the client types -> a precise NVD search keyword, so we
# don't get noisy / empty results from free-text guessing. Unknown names are
# still allowed, but the wizard asks the client to confirm them.

CATALOG = {
    # monitoring / infra
    "zabbix":      {"name": "Zabbix",            "keyword": "zabbix"},
    "grafana":     {"name": "Grafana",           "keyword": "grafana"},
    "prometheus":  {"name": "Prometheus",        "keyword": "prometheus"},
    "nagios":      {"name": "Nagios",            "keyword": "nagios"},
    # mail / groupware
    "roundcube":   {"name": "Roundcube",         "keyword": "roundcube"},
    "exchange":    {"name": "Microsoft Exchange","keyword": "microsoft exchange server"},
    "postfix":     {"name": "Postfix",           "keyword": "postfix"},
    "zimbra":      {"name": "Zimbra",            "keyword": "zimbra"},
    # virtualization
    "esxi":        {"name": "VMware ESXi",        "keyword": "esxi"},
    "vcenter":     {"name": "VMware vCenter",     "keyword": "vcenter"},
    "proxmox":     {"name": "Proxmox VE",         "keyword": "proxmox"},
    # web servers / proxies
    "apache":      {"name": "Apache HTTP Server", "keyword": "apache http server"},
    "nginx":       {"name": "nginx",              "keyword": "nginx"},
    "tomcat":      {"name": "Apache Tomcat",      "keyword": "apache tomcat"},
    "haproxy":     {"name": "HAProxy",            "keyword": "haproxy"},
    # web apps / CMS
    "wordpress":   {"name": "WordPress",          "keyword": "wordpress"},
    "nextcloud":   {"name": "Nextcloud",          "keyword": "nextcloud"},
    "drupal":      {"name": "Drupal",             "keyword": "drupal"},
    "joomla":      {"name": "Joomla",             "keyword": "joomla"},
    "gitlab":      {"name": "GitLab",             "keyword": "gitlab"},
    "jenkins":     {"name": "Jenkins",            "keyword": "jenkins"},
    "confluence":  {"name": "Atlassian Confluence","keyword": "atlassian confluence"},
    "jira":        {"name": "Atlassian Jira",     "keyword": "atlassian jira"},
    # databases
    "mysql":       {"name": "MySQL",              "keyword": "mysql"},
    "mariadb":     {"name": "MariaDB",            "keyword": "mariadb"},
    "postgresql":  {"name": "PostgreSQL",         "keyword": "postgresql"},
    "mongodb":     {"name": "MongoDB",            "keyword": "mongodb"},
    "redis":       {"name": "Redis",              "keyword": "redis"},
    "elasticsearch": {"name": "Elasticsearch",    "keyword": "elasticsearch"},
    # network / security appliances
    "fortigate":   {"name": "Fortinet FortiOS",   "keyword": "fortios"},
    "pfsense":     {"name": "pfSense",            "keyword": "pfsense"},
    "openvpn":     {"name": "OpenVPN",            "keyword": "openvpn"},
    "citrix":      {"name": "Citrix NetScaler",   "keyword": "netscaler"},
    "sonicwall":   {"name": "SonicWall",          "keyword": "sonicwall"},
    "openssh":     {"name": "OpenSSH",            "keyword": "openssh"},
    "openssl":     {"name": "OpenSSL",            "keyword": "openssl"},
}

# accepted aliases -> canonical catalog key
ALIASES = {
    "vmware esxi": "esxi", "vmware vcenter": "vcenter",
    "microsoft exchange": "exchange", "ms exchange": "exchange",
    "apache": "apache", "httpd": "apache",
    "fortios": "fortigate", "fortinet": "fortigate",
    "netscaler": "citrix", "postgres": "postgresql",
    "elastic": "elasticsearch", "proxmox ve": "proxmox",
}


def normalize_service(raw):
    """Lowercase, trim, drop version-like tokens (e.g. '6.4', 'v2')."""
    s = raw.strip().lower()
    s = re.sub(r"\bv?\d+(\.\d+)*\b", "", s)        # strip version numbers
    s = re.sub(r"\s+", " ", s).strip()
    return s


def resolve_service(raw):
    """Map a typed name to a catalog entry. Returns (entry, recognized: bool)."""
    norm = normalize_service(raw)
    if norm in CATALOG:
        return dict(CATALOG[norm]), True
    if norm in ALIASES:
        return dict(CATALOG[ALIASES[norm]]), True
    # unknown -> use the typed text as both display name and keyword
    return {"name": raw.strip().title(), "keyword": norm or raw.strip().lower()}, False


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def slug(name):
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def parse_interval(value):
    """Accept '3600', '30m', '2h', '1d' -> seconds (int). Raises on bad input."""
    s = str(value).strip().lower()
    m = re.fullmatch(r"(\d+)\s*([smhd]?)", s)
    if not m:
        raise ValueError(f"invalid interval: {value!r} (use e.g. 1800, 30m, 2h, 1d)")
    n, unit = int(m.group(1)), m.group(2)
    return n * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def load_config():
    if not os.path.exists(CONFIG_PATH):
        sys.exit(f"[!] No config at {CONFIG_PATH}. Run:  python cvealertor.py --init-config")
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


def write_sample_config():
    if os.path.exists(CONFIG_PATH):
        sys.exit(f"[!] {CONFIG_PATH} already exists - not overwriting.")
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(SAMPLE_CONFIG, f, indent=2)
    print(f"[+] Wrote sample config to {CONFIG_PATH}")
    print("    Fill in telegram.bot_token / chat_id and your services, then run --once.")


# ---------------------------------------------------------------------------
# Baseline (the .txt list of known CVE IDs per service)
# ---------------------------------------------------------------------------

def baseline_path(service_name):
    return os.path.join(STATE_DIR, f"{slug(service_name)}.txt")


def load_baseline(service_name):
    path = baseline_path(service_name)
    if not os.path.exists(path):
        return None  # None == never baselined (first run)
    with open(path, encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def save_baseline(service_name, cve_ids):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(baseline_path(service_name), "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(cve_ids)) + "\n")


# ---------------------------------------------------------------------------
# PoC state (per service: {CVE-ID: {"pocs": [url, ...], "first_seen": "..."}})
# ---------------------------------------------------------------------------

def pocs_path(service_name):
    return os.path.join(STATE_DIR, f"{slug(service_name)}.pocs.json")


def load_pocs(service_name):
    """Return the per-service PoC state dict, or None if never checked (first run)."""
    path = pocs_path(service_name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}  # corrupt/unreadable -> treat as empty, but not a first run


def save_pocs(service_name, state):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(pocs_path(service_name), "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def recent_cve_ids(cve_ids, n):
    """The n most-recent CVE IDs, by (year, sequence) parsed from the ID itself.

    An approximation of publish order - good enough to bound PoC checks to the
    CVEs most likely to sprout a fresh PoC, with zero extra NVD calls.
    """
    def key(cid):
        m = re.match(r"CVE-(\d{4})-(\d+)", cid)
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    return sorted(cve_ids, key=key, reverse=True)[:n]


# ---------------------------------------------------------------------------
# NVD fetch
# ---------------------------------------------------------------------------

def http_get(url, headers, retries=4):
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=40) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            # 403/429 = rate limited, 503 = NVD busy -> back off and retry
            if e.code in (403, 429, 503) and attempt < retries - 1:
                wait = 6 * (attempt + 1)
                log(f"    NVD {e.code}, backing off {wait}s ...")
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < retries - 1:
                time.sleep(6)
                continue
            raise
    return None


def fetch_cves(keyword, api_key):
    """Return {cve_id: {cvss, severity, published, summary}} for a keyword."""
    headers = {"User-Agent": "CVEAlertor"}
    if api_key:
        headers["apiKey"] = api_key
    throttle = 1.0 if api_key else 6.5  # NVD: 50 req/30s with key, 5 without

    results = {}
    start = 0
    total = None
    while total is None or start < total:
        params = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": PAGE_SIZE,
            "startIndex": start,
        })
        data = http_get(f"{NVD_URL}?{params}", headers)
        if not data:
            break
        total = data.get("totalResults", 0)
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            results[cid] = {
                "cvss": cvss_score(cve),
                "severity": cvss_severity(cve),
                "published": (cve.get("published") or "")[:10],
                "summary": description(cve),
            }
        got = len(data.get("vulnerabilities", []))
        if got == 0:
            break
        start += got
        if start < total:
            time.sleep(throttle)
    return results


def cvss_score(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            return metrics[key][0].get("cvssData", {}).get("baseScore")
    return None


def cvss_severity(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            return metrics[key][0].get("cvssData", {}).get("baseSeverity")
    if metrics.get("cvssMetricV2"):
        return metrics["cvssMetricV2"][0].get("baseSeverity")
    return None


def description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


# ---------------------------------------------------------------------------
# PoC fetch (nomi-sec/PoC-in-GitHub, per-CVE JSON on the raw CDN)
# ---------------------------------------------------------------------------

def fetch_pocs_for_cve(cve_id):
    """Public PoC repos for one CVE.

    Returns a list of {url, full_name, stars, description, created_at} (possibly
    empty if no PoC is published), or None on a transient fetch error so the
    caller can leave the CVE unbaselined and retry next cycle.
    """
    m = re.match(r"CVE-(\d{4})-\d+", cve_id)
    if not m:
        return []
    url = POC_RAW_URL.format(year=m.group(1), cve=cve_id)
    try:
        data = http_get(url, {"User-Agent": "CVEAlertor"})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []  # no public PoC for this CVE - the normal case
        log(f"    [!] PoC fetch {cve_id}: HTTP {e.code}")
        return None
    except Exception as e:  # network/timeout/JSON - skip, retry next cycle
        log(f"    [!] PoC fetch {cve_id}: {e}")
        return None

    if not isinstance(data, list):
        return []
    out = []
    for r in data:
        link = r.get("html_url")
        if not link:
            continue
        out.append({
            "url": link,
            "full_name": r.get("full_name") or r.get("name") or link,
            "stars": r.get("stargazers_count") or 0,
            "description": r.get("description") or "",
            "created_at": (r.get("created_at") or "")[:10],
        })
    return out


# ---------------------------------------------------------------------------
# Telegram alerting
# ---------------------------------------------------------------------------

SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def html_escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _tg_post(token, fields):
    """POST to Telegram; return (ok, description). Reads the error body on 4xx."""
    payload = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(TELEGRAM_URL.format(token=token), data=payload)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace"))
            return body.get("ok", False), body.get("description", "")
    except urllib.error.HTTPError as e:
        # Telegram returns a JSON body explaining the 400/403 - read it.
        try:
            body = json.loads(e.read().decode("utf-8", "replace"))
            return False, body.get("description", f"HTTP {e.code}")
        except Exception:
            return False, f"HTTP {e.code}"
    except Exception as e:
        return False, str(e)


def send_telegram(token, chat_id, text):
    ok, desc = _tg_post(token, {
        "chat_id": chat_id, "text": text,
        "parse_mode": "HTML", "disable_web_page_preview": "true",
    })
    if ok:
        return True

    # If HTML entity parsing is the problem, retry as plain text (strip tags).
    if "parse" in desc.lower() or "entit" in desc.lower():
        log(f"    [!] Telegram HTML parse rejected ({desc}); retrying as plain text.")
        plain = re.sub(r"</?b>", "", text)
        ok, desc = _tg_post(token, {
            "chat_id": chat_id, "text": plain, "disable_web_page_preview": "true",
        })
        if ok:
            return True

    # Common gotcha: group/channel chat IDs are negative - the leading dash matters.
    if "chat not found" in desc.lower() and not str(chat_id).startswith("-"):
        log(f"    [!] Telegram send failed: {desc}")
        log("        Hint: group/channel chat IDs are NEGATIVE - keep the leading "
            f"dash (e.g. -{chat_id}).")
    else:
        log(f"    [!] Telegram send failed: {desc}")
    return False


def format_alert(service, cid, info):
    sev = (info.get("severity") or "UNKNOWN").upper()
    emoji = SEV_EMOJI.get(sev, "⚪")
    score = info.get("cvss")
    score_str = f"{score} {sev}" if score is not None else sev
    summary = html_escape((info.get("summary") or "")[:500])
    return (
        f"{emoji} <b>New CVE - {html_escape(service)}</b>\n\n"
        f"<b>{cid}</b>  (CVSS {score_str})\n"
        f"Published: {info.get('published') or 'n/a'}\n\n"
        f"{summary}\n\n"
        f"🔗 https://nvd.nist.gov/vuln/detail/{cid}"
    )


def format_poc_alert(service, cid, poc):
    repo = html_escape(poc.get("full_name") or poc.get("url"))
    desc = html_escape((poc.get("description") or "")[:300])
    body = f"{desc}\n\n" if desc else ""
    return (
        f"💥 <b>New PoC - {html_escape(service)}</b>\n\n"
        f"<b>{cid}</b>\n"
        f"⭐ {poc.get('stars', 0)}  ·  {repo}\n"
        f"Published: {poc.get('created_at') or 'n/a'}\n\n"
        f"{body}"
        f"🔗 {poc.get('url')}\n"
        f"CVE: https://nvd.nist.gov/vuln/detail/{cid}"
    )


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def check_service(svc, cfg):
    name = svc["name"]
    keyword = svc.get("keyword") or name
    min_cvss = float(cfg.get("min_cvss", 0.0))
    tg = cfg.get("telegram", {})
    token, chat_id = tg.get("bot_token"), tg.get("chat_id")

    log(f"[*] Checking '{name}' (keyword='{keyword}') ...")
    try:
        current = fetch_cves(keyword, cfg.get("nvd_api_key", ""))
    except Exception as e:
        log(f"    [!] fetch failed for {name}: {e}")
        return

    current_ids = set(current.keys())
    baseline = load_baseline(name)

    # First run: establish baseline, no alerts (unless configured).
    if baseline is None:
        save_baseline(name, current_ids)
        log(f"    baseline established: {len(current_ids)} CVEs.")
        if cfg.get("alert_on_first_run") and token and chat_id:
            send_telegram(token, chat_id,
                          f"📡 <b>CVEAlertor</b> now monitoring <b>{html_escape(name)}</b> "
                          f"({len(current_ids)} CVEs baselined).")
        return

    new_ids = current_ids - baseline
    if not new_ids:
        log(f"    no new CVEs ({len(current_ids)} known).")
        return

    # Sort newest-published first for nicer alert ordering.
    new_sorted = sorted(new_ids, key=lambda c: current[c].get("published") or "", reverse=True)
    alerted = 0
    failed = 0
    processed = set()  # only CVEs we've fully handled get added to the baseline
    for cid in new_sorted:
        info = current[cid]
        score = info.get("cvss")
        if min_cvss and score is not None and score < min_cvss:
            processed.add(cid)            # intentionally below threshold - don't re-check
            continue
        log(f"    NEW: {cid} CVSS={score} {info.get('severity')}")
        if not (token and chat_id):
            processed.add(cid)            # no Telegram configured - nothing to deliver
            continue
        if send_telegram(token, chat_id, format_alert(name, cid, info)):
            alerted += 1
            processed.add(cid)
            time.sleep(1)                 # be gentle with Telegram rate limits
        else:
            failed += 1                   # leave it OUT of baseline so it retries next cycle

    # Baseline += only what we handled; failed sends stay "new" and retry next run.
    save_baseline(name, baseline | processed)
    msg = f"    {len(new_ids)} new CVE(s), {alerted} alert(s) sent."
    if failed:
        msg += f" {failed} failed - will retry next cycle."
    log(msg)


def run_once(cfg):
    services = cfg.get("services", [])
    if not services:
        log("[!] No services configured.")
        return
    for svc in services:
        check_service(svc, cfg)
    log("[*] Cycle complete.")


def check_pocs_for_service(svc, cfg):
    """Check the recent CVEs of one service for newly-published public PoCs."""
    name = svc["name"]
    tg = cfg.get("telegram", {})
    token, chat_id = tg.get("bot_token"), tg.get("chat_id")
    watch_n = int(cfg.get("poc_watch_recent", 20))
    today = time.strftime("%Y-%m-%d")

    baseline = load_baseline(name)
    if not baseline:
        log(f"[*] PoC '{name}': no CVE baseline yet - skipping (run a CVE cycle first).")
        return

    targets = recent_cve_ids(baseline, watch_n)
    state = load_pocs(name)
    first_run = state is None
    if first_run:
        state = {}
    log(f"[*] PoC '{name}': checking {len(targets)} recent CVE(s)"
        + (" (first run - baselining silently)" if first_run else "") + " ...")

    alerted = failed = 0
    for cid in targets:
        pocs = fetch_pocs_for_cve(cid)
        if pocs is None:
            continue  # transient error - don't record, retry next cycle
        time.sleep(0.4)  # be gentle with the CDN
        if not pocs:
            continue

        entry = state.setdefault(cid, {"pocs": [], "first_seen": today})
        known = set(entry["pocs"])
        for poc in pocs:
            if poc["url"] in known:
                continue
            if first_run:
                known.add(poc["url"])           # silent baseline of existing PoCs
                continue
            log(f"    NEW PoC: {cid} -> {poc['full_name']} (⭐{poc['stars']})")
            if not (token and chat_id):
                known.add(poc["url"])           # no Telegram - just record
                continue
            if send_telegram(token, chat_id, format_poc_alert(name, cid, poc)):
                known.add(poc["url"])
                alerted += 1
                time.sleep(1)
            else:
                failed += 1                     # leave out, retry next cycle
        entry["pocs"] = sorted(known)

    save_pocs(name, state)
    if first_run:
        log(f"    PoC baseline established for {len(state)} CVE(s).")
        if cfg.get("alert_on_first_run") and token and chat_id:
            send_telegram(token, chat_id,
                          f"💥 <b>CVEAlertor</b> now watching public PoCs for "
                          f"<b>{html_escape(name)}</b>.")
    else:
        msg = f"    {alerted} new PoC alert(s) sent."
        if failed:
            msg += f" {failed} failed - will retry next cycle."
        log(msg)


def run_poc_check(cfg):
    if not cfg.get("poc_monitoring", True):
        log("[*] PoC monitoring disabled in config - skipping.")
        return
    services = cfg.get("services", [])
    if not services:
        log("[!] No services configured.")
        return
    log("[*] PoC check cycle ...")
    for svc in services:
        check_pocs_for_service(svc, cfg)
    log("[*] PoC cycle complete.")


# ---------------------------------------------------------------------------
# Persistence (install as a service so it runs on boot + auto-restarts)
# ---------------------------------------------------------------------------

WIN_TASK = "CVEAlertor"


def _is_admin():
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _systemd_unit():
    return (
        "[Unit]\n"
        "Description=CVEAlertor - new-CVE Telegram alerts\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={HERE}\n"
        f"ExecStart={sys.executable} {SCRIPT_PATH} --watch\n"
        "Restart=always\n"
        "RestartSec=30\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def install_service():
    """Install + start CVEAlertor as a boot-persistent, auto-restarting service."""
    if not os.path.exists(CONFIG_PATH):
        print("[!] No config.json - run 'python cvealertor.py --setup' first.")
        return False

    if os.name == "nt":
        if not _is_admin():
            print("[!] Installing the Windows task needs an Administrator prompt.")
            return False
        cmd = f'"{sys.executable}" "{SCRIPT_PATH}" --watch'
        subprocess.run(["schtasks", "/Create", "/TN", WIN_TASK, "/TR", cmd,
                        "/SC", "ONSTART", "/RL", "HIGHEST", "/F"], check=False)
        subprocess.run(["schtasks", "/Run", "/TN", WIN_TASK], check=False)
        print(f"[+] Installed Scheduled Task '{WIN_TASK}' (runs on boot + started now).")
        print(f"    manage:  schtasks /Query /TN {WIN_TASK}   |   stop: schtasks /End /TN {WIN_TASK}")
        return True

    if sys.platform.startswith("linux"):
        if not _is_admin():
            print("[!] Installing the systemd service needs root. Re-run with sudo.")
            return False
        unit_path = f"/etc/systemd/system/{SERVICE_NAME}.service"
        try:
            with open(unit_path, "w") as f:
                f.write(_systemd_unit())
        except OSError as e:
            print(f"[!] Could not write {unit_path}: {e}")
            return False
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        subprocess.run(["systemctl", "enable", "--now", SERVICE_NAME], check=False)
        print(f"[+] Installed and started systemd service '{SERVICE_NAME}'.")
        print(f"    status:  systemctl status {SERVICE_NAME}")
        print(f"    logs:    journalctl -u {SERVICE_NAME} -f")
        print(f"    stop:    systemctl disable --now {SERVICE_NAME}")
        return True

    print(f"[!] Auto-install isn't supported on {sys.platform}.")
    print(f"    Run it under your own supervisor:  {sys.executable} {SCRIPT_PATH} --watch")
    return False


def uninstall_service():
    if os.name == "nt":
        if not _is_admin():
            print("[!] Removing the Windows task needs an Administrator prompt.")
            return False
        subprocess.run(["schtasks", "/End", "/TN", WIN_TASK], check=False)
        subprocess.run(["schtasks", "/Delete", "/TN", WIN_TASK, "/F"], check=False)
        print(f"[+] Removed Scheduled Task '{WIN_TASK}'.")
        return True
    if sys.platform.startswith("linux"):
        if not _is_admin():
            print("[!] Removing the systemd service needs root. Re-run with sudo.")
            return False
        subprocess.run(["systemctl", "disable", "--now", SERVICE_NAME], check=False)
        unit_path = f"/etc/systemd/system/{SERVICE_NAME}.service"
        try:
            os.remove(unit_path)
        except FileNotFoundError:
            pass
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        print(f"[+] Removed systemd service '{SERVICE_NAME}'.")
        return True
    print(f"[!] Nothing to uninstall on {sys.platform}.")
    return False


def full_uninstall(assume_yes=False):
    """Remove the service AND all CVEAlertor data (config, baselines, logs)."""
    print("This will remove the CVEAlertor service and delete:")
    targets = [CONFIG_PATH, STATE_DIR, LOG_PATH]
    for t in targets:
        print(f"  - {t}" + ("" if os.path.exists(t) else "  (not present)"))
    if not assume_yes:
        if input("\nProceed? [y/N] ").strip().lower() != "y":
            print("[*] Aborted.")
            return False

    # 1) service
    uninstall_service()

    # 2) data
    import shutil
    for t in (CONFIG_PATH, LOG_PATH):
        try:
            os.remove(t)
            print(f"[+] removed {t}")
        except FileNotFoundError:
            pass
    if os.path.isdir(STATE_DIR):
        shutil.rmtree(STATE_DIR, ignore_errors=True)
        print(f"[+] removed {STATE_DIR}")

    print("[*] CVEAlertor uninstalled. (The script files themselves were kept - "
          "delete the folder to remove them.)")
    return True


def run_setup():
    """Interactive client onboarding: type products one per line, no versions."""
    print("=" * 64)
    print(" CVEAlertor setup")
    print("=" * 64)
    print("\nHow to type a service name:")
    print("  - lowercase, PRODUCT NAME ONLY (no version)")
    print("  - one product per line, blank line when finished")
    print("  - e.g.  zabbix   then   roundcube   then   esxi\n")
    print("Tip: type 'list' to see supported names.\n")

    services, seen = [], set()
    while True:
        raw = input("service> ").strip()
        if not raw:
            if services:
                break
            print("  (add at least one service)")
            continue
        if raw.lower() in ("list", "?"):
            print("  Supported: " + ", ".join(sorted(CATALOG.keys())))
            continue

        entry, known = resolve_service(raw)
        key = entry["keyword"]
        if key in seen:
            print(f"  already added: {entry['name']}")
            continue
        if not known:
            ans = input(f"  '{raw}' isn't in the catalog. Add it as keyword "
                        f"'{entry['keyword']}' anyway? [y/N] ").strip().lower()
            if ans != "y":
                continue
        seen.add(key)
        services.append({"name": entry["name"], "keyword": entry["keyword"]})
        print(f"  + {entry['name']}  (search: '{entry['keyword']}')")

    print(f"\n{len(services)} service(s) added.\n")

    # how often to check
    print("How often should CVEAlertor check for new CVEs?")
    print("  examples: 30m, 1h, 6h, 1d   (NVD updates ~every 2h, so 1h is a good default)")
    while True:
        raw = input("interval> [1h] ").strip() or "1h"
        try:
            interval = parse_interval(raw)
            break
        except ValueError as e:
            print(f"  {e}")
    print(f"  every {interval}s\n")

    # PoC monitoring (on by default)
    print("Also watch GitHub for public PoCs / exploits for your CVEs?")
    print("  Alerts you when a proof-of-concept appears for a CVE you track,")
    print("  for the most recent CVEs of each service.")
    poc_monitoring = input("enable PoC monitoring? [Y/n] ").strip().lower() != "n"
    poc_interval = 86400
    if poc_monitoring:
        print("\nHow often should it check for new PoCs?")
        print("  examples: 6h, 12h, 1d, 2d   (PoCs appear over days, so 1d is plenty)")
        while True:
            raw = input("poc interval> [1d] ").strip() or "1d"
            try:
                poc_interval = parse_interval(raw)
                break
            except ValueError as e:
                print(f"  {e}")
    print(f"  PoC monitoring: {'on (every %ds)' % poc_interval if poc_monitoring else 'off'}\n")

    print("Now your Telegram details (see README for how to get these):")
    print("  note: group / channel chat IDs are NEGATIVE - keep the leading dash")
    print("        e.g. private: 1357924680   group: -1002468013579")
    token = input("bot token> ").strip()
    chat_id = input("chat id>   ").strip()

    cfg = {
        "telegram": {"bot_token": token, "chat_id": chat_id},
        "nvd_api_key": "",
        "min_cvss": 0.0,
        "interval_seconds": interval,
        "alert_on_first_run": False,
        "poc_monitoring": poc_monitoring,
        "poc_watch_recent": 20,
        "poc_interval_seconds": poc_interval,
        "services": services,
    }
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(f"\n[+] Saved {CONFIG_PATH}\n")

    print("How should CVEAlertor run?")
    print("  [1] Install as a service - runs now + on every boot, auto-restarts  (recommended)")
    print("  [2] Watch in this terminal now")
    print("  [3] Nothing - I'll start it later")
    choice = input("choice> [1] ").strip() or "1"

    if choice == "1":
        # service runs --watch, which baselines silently on first start
        if not install_service():
            print("\n[*] Fix the above, then:  sudo python cvealertor.py --install-service")
        return
    if choice == "2":
        log("[*] Establishing baseline (first run is silent) ...")
        run_once(cfg)
        log(f"[*] Now watching every {interval}s. Ctrl+C to stop.")
        try:
            while True:
                time.sleep(interval)
                run_once(cfg)
        except KeyboardInterrupt:
            log("[*] Stopped.")
        return
    print("\n[*] When ready:")
    print("    service:  sudo python cvealertor.py --install-service")
    print("    or:       python cvealertor.py --watch")


def main():
    p = argparse.ArgumentParser(description="CVEAlertor - new-CVE watcher with Telegram alerts.")
    p.add_argument("--setup", action="store_true", help="Interactive setup wizard (recommended).")
    p.add_argument("--init-config", action="store_true", help="Write a sample config.json and exit.")
    p.add_argument("--list-services", action="store_true", help="Print supported service names.")
    p.add_argument("--once", action="store_true", help="Run a single CVE check cycle (good for cron).")
    p.add_argument("--check-pocs", action="store_true", dest="check_pocs",
                   help="Run a single PoC check cycle for recent CVEs (good for a daily cron).")
    p.add_argument("--watch", action="store_true", help="Loop forever using the interval.")
    p.add_argument("--interval", metavar="T",
                   help="Check interval for --watch, overrides config. e.g. 1800, 30m, 2h, 1d.")
    p.add_argument("--install-service", action="store_true",
                   help="Install + start as a boot service (systemd / Windows Task). Needs root/admin.")
    p.add_argument("--uninstall-service", action="store_true",
                   help="Stop and remove the installed service (keeps config/baselines).")
    p.add_argument("--uninstall", action="store_true",
                   help="Full removal: service + config + baselines + logs.")
    p.add_argument("--yes", action="store_true", help="Skip confirmation prompts.")
    args = p.parse_args()

    if args.install_service:
        sys.exit(0 if install_service() else 1)
    if args.uninstall_service:
        sys.exit(0 if uninstall_service() else 1)
    if args.uninstall:
        sys.exit(0 if full_uninstall(assume_yes=args.yes) else 1)
    if args.setup:
        run_setup()
        return
    if args.list_services:
        print("Supported service names (type them lowercase, no version):\n")
        for k in sorted(CATALOG):
            print(f"  {k:<14} -> {CATALOG[k]['name']}")
        return
    if args.init_config:
        write_sample_config()
        return

    cfg = load_config()

    if args.check_pocs:
        run_poc_check(cfg)
        return

    if args.watch:
        try:
            interval = parse_interval(args.interval) if args.interval \
                else int(cfg.get("interval_seconds", 3600))
        except (ValueError, KeyError) as e:
            sys.exit(f"[!] {e}")
        poc_on = cfg.get("poc_monitoring", True)
        poc_interval = int(cfg.get("poc_interval_seconds", 86400))
        log(f"[*] CVEAlertor watching every {interval}s"
            + (f" (PoC check every {poc_interval}s)" if poc_on else "")
            + ". Ctrl+C to stop.")
        last_poc = None  # None -> fire the PoC pass once on first start
        try:
            while True:
                run_once(cfg)
                if poc_on and (last_poc is None or time.monotonic() - last_poc >= poc_interval):
                    run_poc_check(cfg)
                    last_poc = time.monotonic()
                time.sleep(interval)
        except KeyboardInterrupt:
            log("[*] Stopped.")
    else:
        # default to a single cycle
        run_once(cfg)


if __name__ == "__main__":
    main()
