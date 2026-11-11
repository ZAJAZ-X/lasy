"""Builds the command line for each tool from the settings.

Scanners and the Settings page's command preview both use these functions, so what you see in Settings
is exactly what runs. With default settings every command matches what lasy ran before this was added
(knockpy now defaults to --recon --bruteforce)."""
from __future__ import annotations

import re
import shlex

from . import db, settings_spec as S


def cfg(overrides: dict | None = None) -> dict:
    c = dict(S.defaults())
    try:
        c.update(db.all_settings())
    except Exception:   # database not initialised yet (for example a script run on its own): use the defaults
        pass
    if overrides:
        c.update({k: str(v) for k, v in overrides.items()})
    return c


def _on(c: dict, key: str) -> bool:
    return str(c.get(key, "0")).strip() == "1"


def _num(c: dict, key: str) -> str:
    v = str(c.get(key, "")).strip()
    return v if v.isdigit() else ""


def _txt(c: dict, key: str) -> str:
    return str(c.get(key, "")).strip()


def _extra(c: dict, key: str) -> list[str]:
    try:
        return shlex.split(str(c.get(key, "") or ""))
    except ValueError:
        return []


def limit_seconds(c: dict, key: str, default_minutes: int) -> int:
    n = _num(c, key)
    return (int(n) if n else default_minutes) * 60


def _opt(flag: str, value: str) -> list[str]:
    return [flag, value] if value else []


# ------------------------------------------------------------------ source tools
def dig_argv(c: dict, domain: str) -> list[str]:
    server = _txt(c, "dig_server")
    return ["dig"] + ([f"@{server}"] if server else []) + [domain, "NS"] + _extra(c, "dig_args")


def subfinder_argv(c: dict, domain: str) -> list[str]:
    return (["subfinder", "-d", domain] + (["-all"] if _on(c, "subfinder_all") else [])
            + _opt("-rl", _num(c, "subfinder_rate_limit")) + _opt("-max-time", _num(c, "subfinder_max_time"))
            + _extra(c, "subfinder_args"))


def knockpy_argv(c: dict, domain: str) -> list[str]:
    return (["knockpy", "-d", domain] + (["--recon"] if _on(c, "knockpy_recon") else [])
            + (["--bruteforce"] if _on(c, "knockpy_bruteforce") else [])
            + _opt("--threads", _num(c, "knockpy_threads")) + _opt("--timeout", _num(c, "knockpy_timeout"))
            + _opt("--dns", _txt(c, "knockpy_dns")) + _opt("--wordlist", _txt(c, "knockpy_wordlist"))
            + _extra(c, "knockpy_args"))


def amass_argv(c: dict, domain: str) -> list[str]:
    return (["amass", "enum"] + (["-passive"] if _on(c, "amass_passive") else []) + ["-d", domain]
            + ["-timeout", _num(c, "amass_timeout") or "5"] + _extra(c, "amass_args"))


def assetfinder_argv(c: dict, domain: str) -> list[str]:
    return ["assetfinder", "--subs-only", domain]


SOURCE_ARGV = {"subfinder": subfinder_argv, "knockpy": knockpy_argv, "amass": amass_argv, "assetfinder": assetfinder_argv}
SOURCE_LIMIT = {"subfinder": ("subfinder_limit", 10), "knockpy": ("knockpy_limit", 15), "amass": ("amass_limit", 7), "assetfinder": (None, 3)}


def source_limit(c: dict, tool: str) -> int:
    key, default = SOURCE_LIMIT[tool]
    return limit_seconds(c, key, default) if key else default * 60


def strip_flag(argv: list[str], flag: str) -> list[str]:
    """Remove a flag and, if it takes a value, the value too."""
    out, i = [], 0
    while i < len(argv):
        if argv[i] == flag:
            if i + 1 < len(argv) and not argv[i + 1].startswith("-") and flag != "-passive":
                i += 1
            i += 1
            continue
        out.append(argv[i])
        i += 1
    return out


def retry_argv(c: dict, tool: str, argv: list[str], lines: list[str], code: int, domain: str, tried: list[list[str]]) -> list[str] | None:
    """When a tool rejects our flags (a different version than expected), try a gentler form instead of giving up."""
    blob = "\n".join(lines[-80:]).lower()
    if tool == "knockpy" and ("unrecognized arguments" in blob or "the following arguments are required" in blob or "invalid choice" in blob):
        for cand in (["knockpy", "-d", domain], ["knockpy", domain]):
            if cand not in tried and cand != argv:
                return cand
    if tool == "amass":
        m = re.search(r"flag provided but not defined: -(\S+)", blob)
        if m:
            new = strip_flag(argv, "-" + m.group(1))
            if new != argv and new not in tried:
                return new
    return None


# ------------------------------------------------------------------ web tools
def testssl_argv(c: dict, binary: str, js: str, target: str) -> list[str]:
    return ([binary, "--jsonfile", js, "--warnings", "batch", "--color", "2"]
            + _opt("--connect-timeout", _num(c, "testssl_connect_timeout"))
            + _opt("--openssl-timeout", _num(c, "testssl_openssl_timeout"))
            + (["--sneaky"] if _on(c, "testssl_sneaky") else []) + (["--ids-friendly"] if _on(c, "testssl_ids_friendly") else [])
            + _extra(c, "testssl_args") + [target])


def nuclei_argv(c: dict, url: str, txt: str, jl: str) -> list[str]:
    return (["nuclei", "-u", url, "-o", txt, "-jle", jl, "-duc", "-timeout", _num(c, "nuclei_timeout") or "10",
             "-retries", _num(c, "nuclei_retries") if _num(c, "nuclei_retries") != "" else "1"]
            + _opt("-severity", _txt(c, "nuclei_severity").replace(" ", "")) + _opt("-tags", _txt(c, "nuclei_tags"))
            + _opt("-etags", _txt(c, "nuclei_exclude_tags")) + _opt("-rl", _num(c, "nuclei_rate_limit"))
            + _opt("-c", _num(c, "nuclei_concurrency")) + (["-as"] if _on(c, "nuclei_auto") else []) + _extra(c, "nuclei_args"))


def nikto_argv(c: dict, url: str) -> list[str]:
    return (["nikto", "-h", url, "-nointeractive", "-ask", "no", "-maxtime", f"{_num(c, 'nikto_maxtime') or '20'}m"]
            + _opt("-Tuning", _txt(c, "nikto_tuning")) + _opt("-Pause", _txt(c, "nikto_pause"))
            + _opt("-timeout", _num(c, "nikto_timeout")) + _opt("-evasion", _txt(c, "nikto_evasion")) + _extra(c, "nikto_args"))


def nikto_limit(c: dict) -> int:
    return (int(_num(c, "nikto_maxtime") or 20) + 5) * 60


def ffuf_argv(c: dict, base: str, wl: str, js: str, threads: int, exts: list[str]) -> list[str]:
    return (["ffuf", "-u", f"{base}/FUZZ", "-w", wl] + (["-ac"] if _on(c, "ffuf_autocalibrate") else [])
            + ["-k", "-mc", _txt(c, "ffuf_codes") or S.CODES, "-t", str(threads), "-timeout", _num(c, "ffuf_timeout") or "10",
               "-of", "json", "-o", js]
            + (["-r"] if _on(c, "ffuf_follow") else []) + _opt("-rate", _num(c, "ffuf_rate")) + _opt("-p", _txt(c, "ffuf_delay"))
            + (["-e", ",".join("." + e for e in exts)] if exts else []) + _extra(c, "ffuf_args"))


def ferox_argv(c: dict, base: str, wl: str, txt: str, threads: int, exts: list[str]) -> list[str]:
    depth = _num(c, "ferox_depth")
    return (["feroxbuster", "-u", base, "-w", wl, "-k", "--no-state", "-d", depth if depth != "" else "3",
             "-s", _txt(c, "ferox_codes") or S.CODES, "-t", str(threads), "-o", txt]
            + _opt("--rate-limit", _num(c, "ferox_rate_limit")) + _opt("-T", _num(c, "ferox_timeout"))
            + (["-A"] if _on(c, "ferox_random_agent") else []) + (["--auto-tune"] if _on(c, "ferox_auto_tune") else [])
            + (["-x", ",".join(exts)] if exts else []) + _extra(c, "ferox_args"))


def dirsearch_argv(c: dict, base: str, wl: str, threads: int, exts: list[str]) -> list[str]:
    return (["dirsearch", "-u", base, "-w", wl, "-t", str(threads), "-i", _txt(c, "dirsearch_codes") or S.CODES_DIRSEARCH]
            + (["-r"] if _on(c, "dirsearch_recursive") else []) + _opt("-R", _num(c, "dirsearch_depth"))
            + (["-F"] if _on(c, "dirsearch_follow") else []) + (["--random-agent"] if _on(c, "dirsearch_random_agent") else [])
            + _opt("--delay", _txt(c, "dirsearch_delay")) + _opt("--max-rate", _num(c, "dirsearch_max_rate"))
            + (["-e", ",".join(exts)] if exts else []) + _extra(c, "dirsearch_args"))


# ------------------------------------------------------------------ preview for the Settings page
def preview(overrides: dict | None = None) -> dict[str, str]:
    c = cfg(overrides)
    j = lambda a: " ".join(a)
    return {
        "dig": j(dig_argv(c, "<domain>")),
        "knockpy": j(knockpy_argv(c, "<domain>")),
        "subfinder": j(subfinder_argv(c, "<domain>")),
        "amass": j(amass_argv(c, "<domain>")),
        "testssl": j(testssl_argv(c, "testssl", "<result.json>", "<host:port>")),
        "nuclei": j(nuclei_argv(c, "<url>", "<result.txt>", "<result.jsonl>")),
        "nikto": j(nikto_argv(c, "<url>")),
        "ffuf": j(ffuf_argv(c, "<url>", "<wordlist>", "<result.json>", 40, ["php", "txt"])),
        "feroxbuster": j(ferox_argv(c, "<url>", "<wordlist>", "<result.txt>", 40, ["php", "txt"])),
        "dirsearch": j(dirsearch_argv(c, "<url>", "<wordlist>", 30, ["php", "txt"])),
    }
