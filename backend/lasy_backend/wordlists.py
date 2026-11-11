"""Suggest sensibly-sized wordlists for directory/file discovery by application type."""
from __future__ import annotations

import os
from functools import lru_cache

WC = "Discovery/Web-Content/"
COMMON = [
    (WC + "quickhits.txt", "Quick", "Known sensitive files and paths: small and high-signal"),
    (WC + "common.txt", "Quick", "Short general-purpose list"),
    (WC + "raft-small-words.txt", "Quick", "Small list of very common words"),
    ("/usr/share/wordlists/dirb/common.txt", "Quick", "dirb common list"),
    (WC + "raft-medium-directories.txt", "Standard", "Common directory names"),
    (WC + "raft-medium-files.txt", "Standard", "Common file names"),
    ("/usr/share/wordlists/dirb/big.txt", "Standard", "dirb big list"),
    (WC + "directory-list-2.3-medium.txt", "Deep", "Classic DirBuster medium list"),
    ("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "Deep", "Classic DirBuster medium list"),
    (WC + "raft-large-directories.txt", "Deep", "Large directory list"),
]
PROFILES: dict[str, dict] = {
    "generic": {"label": "Generic website", "exts": ["php", "html", "txt", "bak", "zip"], "lists": COMMON},
    "wordpress": {"label": "WordPress", "exts": ["php", "txt", "bak", "zip"], "lists": [
        (WC + "CMS/wp-plugins.fuzz.txt", "Standard", "WordPress plugin paths"),
        (WC + "CMS/wordpress.fuzz.txt", "Standard", "WordPress core paths"),
        (WC + "CMS/wp-themes.fuzz.txt", "Standard", "WordPress theme paths"),
    ] + COMMON[:3] + COMMON[4:6]},
    "api": {"label": "REST / API", "exts": [], "lists": [
        (WC + "api/api-endpoints.txt", "Quick", "Common API endpoints"),
        (WC + "api/api-endpoints-res.txt", "Standard", "API endpoints (resource style)"),
        (WC + "api/objects.txt", "Quick", "Common API object names"),
        (WC + "api/actions.txt", "Quick", "Common API actions"),
        (WC + "common-api-endpoints-mazen160.txt", "Standard", "Community API endpoint list"),
        (WC + "swagger.txt", "Quick", "Swagger / OpenAPI paths"),
        (WC + "graphql.txt", "Quick", "GraphQL paths"),
    ] + COMMON[1:3]},
    "aspnet": {"label": "ASP.NET / IIS", "exts": ["aspx", "asp", "config", "bak", "zip"], "lists": [
        (WC + "IIS.fuzz.txt", "Quick", "IIS-specific paths"),
        (WC + "CMS/sharepoint.txt", "Quick", "SharePoint paths"),
    ] + COMMON[:3] + COMMON[4:6]},
    "java": {"label": "Java / Tomcat / Spring", "exts": ["jsp", "do", "action", "xml", "bak"], "lists": [
        (WC + "tomcat.txt", "Quick", "Tomcat paths"),
        (WC + "spring-boot.txt", "Quick", "Spring Boot actuator paths"),
        (WC + "Apache.fuzz.txt", "Quick", "Apache paths"),
    ] + COMMON[:3] + COMMON[4:6]},
    "php": {"label": "PHP application", "exts": ["php", "inc", "bak", "txt", "zip"], "lists": [
        (WC + "PHP.fuzz.txt", "Quick", "PHP-specific paths"),
    ] + COMMON[:3] + COMMON[4:6]},
}
APPROX = {"Quick": "minutes", "Standard": "tens of minutes", "Deep": "an hour or more"}


@lru_cache(maxsize=256)
def _count(path: str, mtime: float) -> int:
    n = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            n += chunk.count(b"\n")
    return n


def count_lines(path: str) -> int:
    try:
        return _count(path, os.path.getmtime(path))
    except OSError:
        return 0


def suggest(profile: str, seclists_root: str) -> list[dict]:
    prof = PROFILES.get(profile) or PROFILES["generic"]
    seen, out = set(), []
    for rel, tier, note in prof["lists"]:
        path = rel if rel.startswith("/") else os.path.join(seclists_root, rel)
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        out.append({"path": path, "name": os.path.basename(path), "tier": tier, "note": note,
                    "lines": count_lines(path), "eta": APPROX[tier]})
    return out


def default_for(profile: str, seclists_root: str) -> str:
    items = suggest(profile, seclists_root)
    for tier in ("Standard", "Quick", "Deep"):
        for it in items:
            if it["tier"] == tier:
                return it["path"]
    return ""


def profile_catalog() -> list[dict]:
    return [{"key": k, "label": v["label"], "exts": v["exts"]} for k, v in PROFILES.items()]
