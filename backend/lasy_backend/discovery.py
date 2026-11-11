"""Content-discovery intelligence: score, explain and rank discovered endpoints.

The goal is to answer "what should I open first?" rather than dump a list.
Signals: what the path is called (secrets, VCS, backups, admin/debug surfaces),
what the server said (200/401/403/405/500), how the response compares with the
host's dominant (soft-404) response, and whether several tools agree.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

# (regex on lower-cased path, weight, why)
PATTERNS: list[tuple[str, int, str]] = [
    (r"/\.git(/|$)|/\.svn(/|$)|/\.hg(/|$)", 70, "Version-control metadata is reachable (source code and history may be downloadable)"),
    (r"/\.env(\.|$|/)|/\.aws|/\.ssh|id_rsa|\.pem$|\.key$|\.pfx$|\.p12$|\.kdbx$", 70, "Looks like a secrets or key file"),
    (r"wp-config|config\.php|configuration\.php|settings\.py|appsettings|web\.config|\.htpasswd|\.npmrc|\.git-credentials|credentials|secrets?\.", 60, "Configuration or credential file name"),
    (r"\.(sql|dump|db|sqlite3?|mdb)(\.|$)|/(dump|database|db_backup)", 62, "Database dump or database file"),
    (r"\.(bak|old|orig|save|swp|swo|tmp|~)$|\.(zip|tar|tgz|gz|7z|rar|bz2)$|backup", 58, "Backup or archive file"),
    (r"phpinfo|info\.php|/test\.php|/debug", 55, "Debug or information-disclosure page"),
    (r"/actuator|/heapdump|/jolokia|/env$|/trace$|/metrics$|/_profiler|/telescope|/__debug__|/elmah|/console$", 58, "Framework debug or management endpoint"),
    (r"server-status|server-info|/status$|/nginx_status", 50, "Server status page"),
    (r"phpmyadmin|/pma|adminer|/manager/html|jmx-console|/solr|/jenkins|/grafana|/kibana|/portainer|/hudson", 52, "Management console"),
    (r"swagger|api-docs|openapi|/graphiql|/graphql|/redoc|/api/v\d|/v\d/api", 38, "API documentation or schema endpoint"),
    (r"/(admin|administrator|wp-admin|cpanel|dashboard|backend|manage|control|panel|secure)(/|$|\.)", 28, "Administrative interface"),
    (r"/(login|signin|sign-in|auth|sso|oauth|account)(/|$|\.)|wp-login", 14, "Authentication surface"),
    (r"/(upload|uploads|files|filemanager|elfinder|attachments|media/private)(/|$)", 28, "File upload or file-management area"),
    (r"/(install|setup|installer|migrate|upgrade|update)(/|\.|$)", 36, "Installer or setup script"),
    (r"\.(log)$|/logs?(/|$)|error_log|access\.log|debug\.log", 48, "Log file or log directory"),
    (r"/(private|internal|secret|hidden|staging|stage|dev|test|testing|beta|old|new|tmp|temp)(/|$)", 24, "Non-production or private-looking path"),
    (r"xmlrpc\.php|wp-json/wp/v2/users|/wp-content/debug", 34, "WordPress attack surface"),
    (r"/cgi-bin(/|$)|\.cgi$|\.pl$", 16, "CGI script area"),
    (r"composer\.(json|lock)|package(-lock)?\.json|yarn\.lock|dockerfile|docker-compose|\.gitlab-ci|jenkinsfile|\.travis", 40, "Build or dependency manifest (reveals stack and versions)"),
    (r"readme|changelog|license|version(\.txt)?$", 12, "Version or documentation file (may disclose software versions)"),
    (r"robots\.txt|sitemap\.xml|crossdomain\.xml|security\.txt|\.well-known", 6, "Standard metadata file"),
]
_STATUS_BASE = {200: 30, 204: 12, 301: 8, 302: 8, 307: 8, 308: 8, 401: 35, 403: 28, 405: 25,
                500: 30, 502: 22, 503: 22}
_STATUS_FACTOR = {200: 1.0, 204: 0.6, 301: 0.55, 302: 0.55, 307: 0.55, 308: 0.55, 401: 0.7,
                  403: 0.6, 405: 0.7, 500: 0.6}
_STATUS_WHY = {
    200: "responds with HTTP 200 (content is reachable)",
    401: "requires authentication (a login surface worth testing for weak or default credentials)",
    403: "exists but is forbidden (check access-control bypasses and alternate paths)",
    405: "exists but rejects GET (try POST/PUT and other methods)",
    500: "returns a server error (possible stack-trace leakage or injectable parameter)",
}


def _key(e: dict) -> tuple[str, str]:
    return e["origin"], (e["path"].rstrip("/") or "/")


def _priority(score: int) -> str:
    return "high" if score >= 70 else "medium" if score >= 45 else "low" if score >= 25 else "info"


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


def analyze(endpoints: list[dict]) -> list[dict]:
    """Merge endpoints found by several tools, score them, and return best-first."""
    merged: dict[tuple, dict] = {}
    for e in endpoints:
        m = merged.setdefault(_key(e), {
            "origin": e["origin"], "path": _key(e)[1], "statuses": {}, "size": 0, "words": None,
            "lines": None, "redirect": "", "tools": set()})
        m["statuses"][e["tool"]] = e["status"]
        m["size"] = max(m["size"], e["size"])
        m["redirect"] = m["redirect"] or e["redirect"]
        m["tools"].add(e["tool"])

    # soft-404 / wildcard baseline per origin
    by_origin: dict[str, list[dict]] = defaultdict(list)
    for m in merged.values():
        by_origin[m["origin"]].append(m)
    noise: dict[str, tuple[int, int]] = {}
    sizes_by_origin: dict[str, list[int]] = {}
    for origin, items in by_origin.items():
        c = Counter((max(m["statuses"].values()), m["size"]) for m in items)
        (st, sz), n = c.most_common(1)[0]
        if n >= 8 and n / len(items) >= 0.4:
            noise[origin] = (st, sz)
        sizes_by_origin[origin] = sorted(m["size"] for m in items)

    results = []
    for m in merged.values():
        sts = list(m["statuses"].values())
        status = 200 if 200 in sts else sorted(sts, key=lambda s: -_STATUS_BASE.get(s, 0))[0]
        path = m["path"].lower()
        score = _STATUS_BASE.get(status, 0)
        reasons: list[str] = []
        if status in _STATUS_WHY:
            reasons.append(f"{m['path']} {_STATUS_WHY[status]}")
        best = max(((w, why) for rx, w, why in PATTERNS if re.search(rx, path)),
                   default=(0, ""), key=lambda x: x[0])
        if best[0]:
            score += round(best[0] * _STATUS_FACTOR.get(status, 0.3))
            reasons.append(best[1])
        if len(m["tools"]) >= 2:
            score += 10
            reasons.append("Confirmed by " + " and ".join(sorted(m["tools"])))
        loc = (m["redirect"] or "").lower()
        if status in (301, 302, 307, 308) and loc:
            if "login" in loc or "signin" in loc or "auth" in loc:
                score += 8
                reasons.append(f"Redirects to an authentication page ({m['redirect']})")
            elif loc.startswith("http") and m["origin"].split("//")[-1].split(":")[0] not in loc:
                score += 6
                reasons.append(f"Redirects to a different host ({m['redirect']})")
        sizes = sizes_by_origin[m["origin"]]
        if status == 200 and len(sizes) >= 10:
            p95 = sizes[int(len(sizes) * 0.95) - 1]
            if m["size"] > max(p95, 100_000):
                score += 15
                reasons.append(f"Unusually large response ({_human(m['size'])}) compared with other paths")
        if status == 200 and m["size"] == 0:
            score -= 12
            reasons.append("Empty 200 response (often a placeholder)")
        is_noise = noise.get(m["origin"]) == (status, m["size"])
        if is_noise and best[0] < 50:
            score = 0
            reasons = ["Matches the host's dominant (wildcard / soft-404) response, so it is probably not a real page"]
        score = max(0, min(100, score))
        results.append({
            "origin": m["origin"], "path": m["path"], "url": m["origin"] + m["path"], "status": status,
            "statuses": m["statuses"], "size": m["size"], "redirect": m["redirect"],
            "tools": sorted(m["tools"]), "score": score, "priority": _priority(score),
            "reasons": reasons, "noise": is_noise and best[0] < 50,
        })
    results.sort(key=lambda r: (-r["score"], r["path"]))
    return results


def to_findings(scored: list[dict], min_score: int = 25) -> list[dict]:
    out = []
    for r in scored:
        if r["score"] < min_score:
            continue
        sev = "high" if r["score"] >= 70 else "medium" if r["score"] >= 45 else "low"
        out.append({
            "severity": sev,
            "title": f"{r['path']} (HTTP {r['status']})",
            "target": r["url"],
            "evidence": " • ".join(r["reasons"]) + f" • size {_human(r['size'])} • found by {', '.join(r['tools'])}",
            "extra": {"score": r["score"], "tools": r["tools"], "status": r["status"], "size": r["size"]},
        })
    return out
