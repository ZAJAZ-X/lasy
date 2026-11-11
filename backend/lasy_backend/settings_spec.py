"""Every user-editable setting in one place: default, type, label, hint, category and validation.

The Settings page is rendered from this schema, and the backend validates against it, so the two
cannot drift apart. Defaults reproduce the commands lasy ran before (knockpy is the one deliberate change)."""
from __future__ import annotations

import re
import shlex

CODES = "200,204,301,302,307,308,401,403,405,500"
CODES_DIRSEARCH = "200-399,401,403,405,500"


def F(key, label, kind="text", default="", hint="", **kw):
    return {"key": key, "label": label, "kind": kind, "default": default, "hint": hint, **kw}


def ARGS(key, tool, hint=""):
    return F(key, "Extra arguments", "args", "",
             hint or f"Added to the end of the {tool} command. Flags lasy already controls are rejected here; use the options above.")


def LIMIT(key, tool, minutes):
    return F(key, "Time limit (minutes)", "int", str(minutes), f"lasy stops {tool} after this long and keeps what it found so far.", min=1, max=1440)


CATEGORIES = [
    # ------------------------------------------------------------------ General
    {"id": "general", "group": "General", "label": "General", "blurb": "Where results go and how lasy looks.", "fields": [
        F("results_root", "Results folder", "text", None, "Tool output for every project is saved here, on your Windows drive (for example /mnt/c/Users/you/lasy). "
          "The app’s database and working files stay on the Kali side.", computed=True),
        F("ui_style", "Interface style", "select", "glass", "Glass uses translucent panels over a soft green glow. Solid uses plain opaque panels. Green accents are the same in both.",
          options=[["glass", "Glass"], ["solid", "Solid"]]),
        F("ui_text_size", "Text size", "select", "large", "Large is about 1.5 pt bigger. The terminal and the report tables keep their own sizes.",
          options=[["large", "Large"], ["standard", "Standard"]]),
        F("ui_mascot", "Show the lasy mascot", "bool", "1", "A small sloth beside the lasy name, on the start screen, and in empty or waiting screens. Never in the terminal, tables or exports."),
        F("kali_prompt_user", "Terminal prompt: user name", "text", None, "Shown in the scan terminal so report screenshots match your real Kali prompt.", computed=True),
        F("kali_prompt_host", "Terminal prompt: host name", "text", None, "", computed=True),
    ]},
    # ------------------------------------------------------------------ EPT
    {"id": "nmap", "group": "External pentest", "label": "nmap", "blurb": "Port scanning performance and behaviour.", "fields": [
        F("nmap_max_parallel", "Parallel batches", "int", None, "How many nmap processes run at once. More is faster but can skew UDP results and saturate your link.", computed=True),
        F("nmap_batch_size", "Hosts per batch", "int", None, "Smaller batches lose less work when you pause or close your laptop.", computed=True),
        F("nmap_fullscan_chunk", "Full-scan port chunk size", "int", None, "Full scans are split into port ranges this wide so they can resume.", computed=True),
        F("nmap_timing", "Timing template (0 to 5)", "int", None, "4 is a common default for external tests. Use 3 for fragile or rate-limited targets.", computed=True),
        F("nmap_udp_retries", "UDP max retries", "int", None, "1 is fast; raise it for more reliable UDP results.", computed=True),
        F("nmap_extra_args", "Extra nmap arguments", "text", None, "Appended to every nmap scan, for example --max-rate 500.", computed=True),
        F("nmap_use_sudo", "Use sudo for nmap (0 or 1)", "text", None, "Only if capabilities do not work on your system. Needs a NOPASSWD sudoers rule; see the README.", computed=True),
    ]},
    {"id": "subdomain", "group": "External pentest", "label": "Subdomain enumeration", "blurb": "How found names are resolved and probed. Each source tool has its own page.", "fields": [
        F("sub_resolve_concurrency", "DNS lookups at once", "int", "50", "Parallel DNS lookups when resolving found names.", min=1, max=500),
        F("sub_probe_concurrency", "HTTP checks at once", "int", "40", "Parallel HTTP(S) reachability checks.", min=1, max=200),
        F("sub_probe_timeout", "HTTP check timeout (seconds)", "int", "8", "How long to wait for each subdomain to answer.", min=2, max=60),
    ]},
    {"id": "dig", "group": "External pentest", "label": "dig", "blurb": "Nameserver lookup.", "fields": [
        F("dig_server", "DNS server to ask", "text", "", "For example 1.1.1.1 or 8.8.8.8. Leave empty to use your system resolver."),
        ARGS("dig_args", "dig", "Added after the domain, for example +tcp or +tries=5. Output-shaping options are rejected because lasy reads the answer section."),
    ]},
    {"id": "knockpy", "group": "External pentest", "label": "knockpy", "blurb": "Subdomain recon and brute force. Pick the modes to use. lasy reads complete names from knockpy’s saved report, because its on-screen table cuts long ones.", "fields": [
        F("knockpy_recon", "Recon mode (--recon)", "bool", "1", "Passive sources. Adding API keys with knockpy --setup (VirusTotal, Shodan) improves this."),
        F("knockpy_bruteforce", "Brute-force mode (--bruteforce)", "bool", "1", "Tries names from a wordlist. Slower, but finds names passive sources miss."),
        F("knockpy_threads", "Threads (--threads)", "int", "", "Leave empty to use knockpy’s own setting.", min=1, max=500, blank=True),
        F("knockpy_timeout", "Request timeout, seconds (--timeout)", "int", "", "Leave empty to use knockpy’s own setting.", min=1, max=120, blank=True),
        F("knockpy_dns", "DNS server (--dns)", "text", "", "For example 1.1.1.1. Leave empty for the default."),
        F("knockpy_wordlist", "Wordlist (--wordlist)", "text", "", "Full path to a custom brute-force wordlist, for example /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt. Leave empty for knockpy’s built-in list."),
        ARGS("knockpy_args", "knockpy"),
        LIMIT("knockpy_limit", "knockpy", 15),
    ]},
    {"id": "subfinder", "group": "External pentest", "label": "subfinder", "blurb": "Passive subdomain discovery.", "fields": [
        F("subfinder_all", "Use every source (-all)", "bool", "0", "More results, noticeably slower."),
        F("subfinder_rate_limit", "Rate limit, requests per second (-rl)", "int", "", "Leave empty for no limit.", min=1, max=10000, blank=True),
        F("subfinder_max_time", "Max enumeration time, minutes (-max-time)", "int", "", "Leave empty for subfinder’s default of 10.", min=1, max=240, blank=True),
        ARGS("subfinder_args", "subfinder"),
        LIMIT("subfinder_limit", "subfinder", 10),
    ]},
    {"id": "amass", "group": "External pentest", "label": "amass", "blurb": "Passive OSINT enumeration.", "fields": [
        F("amass_passive", "Passive mode (-passive)", "bool", "1", "Turn this off if your amass version rejects the flag. lasy also retries without it automatically. Amass v5 needs its engine running."),
        F("amass_timeout", "Enumeration time, minutes (-timeout)", "int", "5", "", min=1, max=240),
        ARGS("amass_args", "amass"),
        LIMIT("amass_limit", "amass", 7),
    ]},
    # ------------------------------------------------------------------ Web
    {"id": "testssl", "group": "Web App PT", "label": "testssl.sh", "blurb": "Deep TLS audit.", "fields": [
        F("testssl_connect_timeout", "Connect timeout, seconds (--connect-timeout)", "int", "", "Avoids hangs on filtered ports. Leave empty for testssl’s default.", min=1, max=300, blank=True),
        F("testssl_openssl_timeout", "OpenSSL timeout, seconds (--openssl-timeout)", "int", "", "Leave empty for testssl’s default.", min=1, max=300, blank=True),
        F("testssl_sneaky", "Sneaky mode (--sneaky)", "bool", "0", "Leaves fewer traces in the target’s logs (user agent, referer)."),
        F("testssl_ids_friendly", "IDS friendly (--ids-friendly)", "bool", "0", "Skips checks that may make an IDS block your IP."),
        ARGS("testssl_args", "testssl.sh"),
        LIMIT("testssl_limit", "testssl.sh", 30),
    ]},
    {"id": "nuclei", "group": "Web App PT", "label": "nuclei", "blurb": "Template-based vulnerability scanner.", "fields": [
        F("nuclei_severity", "Severities to run (-severity)", "text", "", "Comma separated: info, low, medium, high, critical. Empty runs all."),
        F("nuclei_tags", "Only these tags (-tags)", "text", "", "For example cve,exposure. Empty runs every template."),
        F("nuclei_exclude_tags", "Skip these tags (-exclude-tags)", "text", "", "For example dos,fuzz."),
        F("nuclei_rate_limit", "Rate limit, requests per second (-rl)", "int", "", "Leave empty for nuclei’s default (150).", min=1, max=100000, blank=True),
        F("nuclei_concurrency", "Templates in parallel (-c)", "int", "", "Leave empty for nuclei’s default (25).", min=1, max=1000, blank=True),
        F("nuclei_timeout", "Request timeout, seconds (-timeout)", "int", "10", "", min=1, max=300),
        F("nuclei_retries", "Retries (-retries)", "int", "1", "", min=0, max=10),
        F("nuclei_auto", "Automatic scan (-as)", "bool", "0", "Picks templates from detected technologies. Faster and more focused."),
        ARGS("nuclei_args", "nuclei"),
        LIMIT("nuclei_limit", "nuclei", 60),
    ]},
    {"id": "nikto", "group": "Web App PT", "label": "nikto", "blurb": "Web server scanner.", "fields": [
        F("nikto_maxtime", "Max time per target, minutes (-maxtime)", "int", "20", "", min=1, max=600),
        F("nikto_tuning", "Scan tuning (-Tuning)", "text", "", "Test types, for example 123b. Empty runs everything. x reverses the selection."),
        F("nikto_pause", "Pause between tests, seconds (-Pause)", "text", "", "A number such as 1 or 0.5. Slows the scan to be gentler on fragile targets."),
        F("nikto_timeout", "Request timeout, seconds (-timeout)", "int", "", "Leave empty for nikto’s default (10).", min=1, max=300, blank=True),
        F("nikto_evasion", "Evasion technique (-evasion)", "text", "", "Encoding technique digits, for example 1. Empty means none."),
        ARGS("nikto_args", "nikto", "Added to the end of the nikto command. lasy already sets the target, time limit and output handling."),
    ]},
    {"id": "ffuf", "group": "Web App PT", "label": "ffuf", "blurb": "Fast content discovery. Threads, wordlist and extensions are set per project on the Web App PT page.", "fields": [
        F("ffuf_codes", "Status codes to keep (-mc)", "codes", CODES, "Comma separated, for example 200,301,403."),
        F("ffuf_autocalibrate", "Auto-calibrate (-ac)", "bool", "1", "Filters wildcard and soft-404 responses automatically. Recommended."),
        F("ffuf_timeout", "Request timeout, seconds (-timeout)", "int", "10", "", min=1, max=300),
        F("ffuf_follow", "Follow redirects (-r)", "bool", "0", ""),
        F("ffuf_rate", "Rate limit, requests per second (-rate)", "int", "", "Leave empty for no limit.", min=1, max=100000, blank=True),
        F("ffuf_delay", "Delay between requests, seconds (-p)", "text", "", "A number or a range, for example 0.1 or 0.1-2.0."),
        ARGS("ffuf_args", "ffuf"),
        LIMIT("ffuf_limit", "ffuf", 120),
    ]},
    {"id": "feroxbuster", "group": "Web App PT", "label": "feroxbuster", "blurb": "Recursive content discovery.", "fields": [
        F("ferox_depth", "Recursion depth (-d)", "int", "3", "0 means unlimited. Deeper is slower.", min=0, max=50),
        F("ferox_codes", "Status codes to keep (-s)", "codes", CODES, "Comma separated, for example 200,301,403."),
        F("ferox_rate_limit", "Rate limit per directory, requests per second (--rate-limit)", "int", "", "Leave empty for no limit.", min=1, max=100000, blank=True),
        F("ferox_timeout", "Request timeout, seconds (-T)", "int", "", "Leave empty for feroxbuster’s default (7).", min=1, max=300, blank=True),
        F("ferox_random_agent", "Random user agent (-A)", "bool", "0", ""),
        F("ferox_auto_tune", "Auto-tune the scan rate (--auto-tune)", "bool", "0", "Slows down automatically when the target starts returning errors."),
        ARGS("ferox_args", "feroxbuster"),
        LIMIT("ferox_limit", "feroxbuster", 120),
    ]},
    {"id": "dirsearch", "group": "Web App PT", "label": "dirsearch", "blurb": "Path discovery.", "fields": [
        F("dirsearch_codes", "Status codes to include (-i)", "text", CODES_DIRSEARCH, "Codes and ranges, for example 200-399,401,403."),
        F("dirsearch_recursive", "Recursive (-r)", "bool", "0", ""),
        F("dirsearch_depth", "Max recursion depth (-R)", "int", "", "Used with recursive mode. Leave empty for dirsearch’s default.", min=1, max=50, blank=True),
        F("dirsearch_follow", "Follow redirects (-F)", "bool", "0", ""),
        F("dirsearch_random_agent", "Random user agent (--random-agent)", "bool", "0", ""),
        F("dirsearch_delay", "Delay between requests, seconds (--delay)", "text", "", "A number such as 0.5."),
        F("dirsearch_max_rate", "Max requests per second (--max-rate)", "int", "", "Leave empty for no limit.", min=1, max=100000, blank=True),
        ARGS("dirsearch_args", "dirsearch"),
        LIMIT("dirsearch_limit", "dirsearch", 120),
    ]},
    {"id": "wordlists", "group": "Web App PT", "label": "Wordlists", "blurb": "Where lasy looks for wordlists.", "fields": [
        F("seclists_root", "SecLists location", "text", None, "Used to suggest wordlists for directory discovery.", computed=True),
    ]},
]

# Flags lasy sets itself, per tool. A clash would break parsing, file handling or (for clap-based tools) fail outright.
FORBIDDEN = {
    "dig_args": {"+short": "lasy reads the full answer section", "+noall": "lasy reads the full answer section", "+noanswer": "lasy reads the answer section",
                 "+nocomments": "lasy reads the section headers", "@": "use the DNS server setting"},
    "knockpy_args": {"-d": "the domain", "--domain": "the domain", "-f": "lasy runs one domain at a time", "--file": "lasy runs one domain at a time",
                     "--json": "it silences the live output", "--silent": "it hides the output lasy reads", "--setup": "it is interactive and would hang",
                     "--report": "it is interactive", "--check-update": "not needed", "--update-versions": "not needed",
                     "--recon": "Recon mode above", "--bruteforce": "Brute-force mode above", "--brute": "Brute-force mode above",
                     "--threads": "Threads above", "--timeout": "Request timeout above", "--dns": "DNS server above", "--wordlist": "Wordlist above"},
    "subfinder_args": {"-d": "the domain", "-dL": "lasy runs one domain at a time", "-o": "lasy saves the output", "-oJ": "lasy saves the output", "-json": "lasy reads the plain output",
                       "-all": "Use every source above", "-rl": "Rate limit above", "-rate-limit": "Rate limit above", "-max-time": "Max enumeration time above"},
    "amass_args": {"-d": "the domain", "-df": "lasy runs one domain at a time", "-o": "lasy saves the output", "-passive": "Passive mode above", "-timeout": "Enumeration time above"},
    "testssl_args": {"--jsonfile": "lasy reads the JSON result", "--jsonfile-pretty": "lasy reads the JSON result", "-oj": "lasy reads the JSON result", "--logfile": "lasy saves the output",
                     "--csvfile": "lasy saves the output", "--htmlfile": "lasy saves the output", "--outfile": "lasy saves the output", "--file": "lasy runs one target at a time",
                     "--warnings": "lasy runs non-interactively", "--color": "lasy keeps the terminal colours",
                     "--connect-timeout": "Connect timeout above", "--openssl-timeout": "OpenSSL timeout above", "--sneaky": "Sneaky mode above", "--ids-friendly": "IDS friendly above"},
    "nuclei_args": {"-u": "the target", "-target": "the target", "-l": "lasy runs one target at a time", "-list": "lasy runs one target at a time", "-o": "lasy saves the output",
                    "-output": "lasy saves the output", "-jle": "lasy reads the JSONL result", "-jsonl-export": "lasy reads the JSONL result", "-je": "lasy reads the JSONL result",
                    "-json-export": "lasy reads the JSONL result", "-jsonl": "it changes the terminal output", "-j": "it changes the terminal output", "-duc": "already set",
                    "-up": "it updates nuclei", "-update": "it updates nuclei", "-ut": "run it yourself in a terminal", "-update-templates": "run it yourself in a terminal",
                    "-timeout": "Request timeout above", "-retries": "Retries above", "-s": "Severities above", "-severity": "Severities above", "-tags": "Only these tags above",
                    "-etags": "Skip these tags above", "-exclude-tags": "Skip these tags above", "-rl": "Rate limit above", "-rate-limit": "Rate limit above",
                    "-c": "Templates in parallel above", "-concurrency": "Templates in parallel above", "-as": "Automatic scan above", "-automatic-scan": "Automatic scan above"},
    "nikto_args": {"-h": "the target", "-host": "the target", "-o": "lasy saves the output", "-output": "lasy saves the output", "-Format": "lasy reads the terminal output",
                   "-maxtime": "Max time above", "-Tuning": "Scan tuning above", "-Pause": "Pause above", "-timeout": "Request timeout above", "-evasion": "Evasion above",
                   "-ask": "already set", "-nointeractive": "already set", "-update": "it updates nikto", "-config": "not supported here"},
    "ffuf_args": {"-u": "the target", "-w": "the wordlist", "-o": "lasy reads the JSON result", "-of": "lasy reads the JSON result", "-mc": "Status codes above", "-timeout": "Request timeout above",
                  "-ac": "Auto-calibrate above", "-rate": "Rate limit above", "-p": "Delay above", "-r": "Follow redirects above", "-t": "Threads, set per project", "-e": "Extensions, set per project", "-k": "already set"},
    "ferox_args": {"-u": "the target", "--url": "the target", "-w": "the wordlist", "--wordlist": "the wordlist", "-o": "lasy saves the output", "--output": "lasy saves the output",
                   "-k": "already set", "--insecure": "already set", "--no-state": "already set", "-d": "Recursion depth above", "--depth": "Recursion depth above",
                   "-s": "Status codes above", "--status-codes": "Status codes above", "-t": "Threads, set per project", "--threads": "Threads, set per project",
                   "-x": "Extensions, set per project", "--extensions": "Extensions, set per project", "--rate-limit": "Rate limit above", "-T": "Request timeout above",
                   "--timeout": "Request timeout above", "-A": "Random user agent above", "--random-agent": "Random user agent above", "--auto-tune": "Auto-tune above",
                   "--json": "lasy reads the plain output", "--silent": "it hides the output lasy reads", "--stdin": "lasy runs one target at a time"},
    "dirsearch_args": {"-u": "the target", "--url": "the target", "-l": "lasy runs one target at a time", "-w": "the wordlist", "--wordlists": "the wordlist", "-t": "Threads, set per project",
                       "--threads": "Threads, set per project", "-e": "Extensions, set per project", "--extensions": "Extensions, set per project", "-i": "Status codes above",
                       "--include-status": "Status codes above", "-r": "Recursive above", "--recursive": "Recursive above", "-R": "Max recursion depth above",
                       "--max-recursion-depth": "Max recursion depth above", "-F": "Follow redirects above", "--follow-redirects": "Follow redirects above",
                       "--random-agent": "Random user agent above", "--delay": "Delay above", "--max-rate": "Max requests per second above", "-o": "lasy reads the terminal output",
                       "--output": "lasy reads the terminal output", "-O": "lasy reads the terminal output", "--format": "lasy reads the terminal output", "-q": "it hides the output lasy reads"},
}


def all_fields() -> list[dict]:
    return [f for c in CATEGORIES for f in c["fields"]]


def defaults() -> dict[str, str]:
    """Defaults for the settings this module owns (computed ones come from config)."""
    return {f["key"]: f["default"] for f in all_fields() if not f.get("computed")}


def _check_args(label: str, key: str, text: str) -> str | None:
    try:
        toks = shlex.split(text)
    except ValueError:
        return f"{label}: the extra arguments could not be read. Check the quotes."
    bad = FORBIDDEN.get(key, {})
    for t in toks:
        base = t.split("=", 1)[0] if t.startswith(("-", "+")) else t
        if t.startswith("@") and "@" in bad:
            return f"{label}: lasy handles the DNS server itself; use “DNS server to ask” instead of {t}."
        if base in bad:
            return f"{label}: lasy already controls {base} ({bad[base]}). Remove it from Extra arguments."
    return None


def validate(vals: dict[str, str]) -> list[str]:
    """Errors for the keys this module owns (existing nmap/storage keys keep their own checks)."""
    errs: list[str] = []
    by_key = {f["key"]: f for f in all_fields() if not f.get("computed")}
    for key, raw in vals.items():
        f = by_key.get(key)
        if f is None:
            continue
        v = str(raw).strip()
        kind, label = f["kind"], f["label"]
        tool = next((c["label"] for c in CATEGORIES if f in c["fields"]), "")
        name = f"{tool}: {label}"
        if kind == "int":
            if v == "":
                if not f.get("blank") and f["default"] != "":
                    errs.append(f"{name} needs a number from {f['min']} to {f['max']}.")
                continue
            if not v.isdigit() or not f["min"] <= int(v) <= f["max"]:
                errs.append(f"{name} must be a whole number from {f['min']} to {f['max']}.")
        elif kind == "bool":
            if v not in ("0", "1"):
                errs.append(f"{name} must be on or off.")
        elif kind == "select":
            if v not in [o[0] for o in f["options"]]:
                errs.append(f"{name} must be one of: {', '.join(o[1] for o in f['options'])}.")
        elif kind == "codes":
            if not re.fullmatch(r"\d{3}(,\d{3})*", v):
                errs.append(f"{name} must be comma-separated status codes such as 200,301,403.")
        elif kind == "args":
            e = _check_args(tool, key, v)
            if e:
                errs.append(e)
        elif key == "nuclei_severity" and v:
            if not all(s.strip() in ("info", "low", "medium", "high", "critical") for s in v.split(",")):
                errs.append("nuclei: Severities must be from info, low, medium, high, critical, comma separated.")
        elif key == "dirsearch_codes" and not re.fullmatch(r"\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*", v):
            errs.append("dirsearch: Status codes must look like 200-399,401,403.")
        elif key in ("nikto_pause", "dirsearch_delay") and v and not re.fullmatch(r"\d+(\.\d+)?", v):
            errs.append(f"{name} must be a number such as 0.5.")
        elif key == "ffuf_delay" and v and not re.fullmatch(r"\d+(\.\d+)?(-\d+(\.\d+)?)?", v):
            errs.append("ffuf: Delay must be a number or a range such as 0.1-2.0.")
        elif key == "knockpy_wordlist" and v and not v.startswith(("/", "~")):
            errs.append("knockpy: Wordlist must be a full path starting with /, for example /usr/share/wordlists/mine.txt.")
        elif key in ("knockpy_dns", "dig_server") and v and not re.fullmatch(r"[A-Za-z0-9.:\-]+", v):
            errs.append(f"{name} must be an IP address or host name.")
        elif key in ("nuclei_tags", "nuclei_exclude_tags") and v and not re.fullmatch(r"[A-Za-z0-9_,\-]+", v):
            errs.append(f"{name} must be comma-separated tag names.")
        elif key == "nikto_tuning" and v and not re.fullmatch(r"[0-9a-cx]+", v):
            errs.append("nikto: Scan tuning uses the digits and letters from nikto’s help, for example 123b.")
        elif key == "nikto_evasion" and v and not re.fullmatch(r"[0-9A-B]+", v):
            errs.append("nikto: Evasion uses nikto’s technique digits, for example 1.")
    return errs
