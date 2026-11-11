#!/usr/bin/env bash
# One-time setup for lasy on WSL2 Kali.   Run:  bash scripts/install.sh
set -uo pipefail
REPO="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
SUDO="sudo"; [ "$(id -u)" -eq 0 ] && SUDO=""
say() { printf '\n\033[1m[lasy] %s\033[0m\n' "$*"; }
MISSING=()

say "1/7  Checking tools (anything already on this machine is left alone)"
# have <package>: true if it is already present, whether apt installed it or you did (git clone, release binary, go install...)
have() {
  case "$1" in
    dnsutils)     command -v dig >/dev/null 2>&1 ;;
    testssl.sh)   command -v testssl.sh >/dev/null 2>&1 || command -v testssl >/dev/null 2>&1 ;;
    wslu)         command -v wslview >/dev/null 2>&1 ;;
    libcap2-bin)  command -v setcap >/dev/null 2>&1 ;;
    python3-pip)  command -v pip3 >/dev/null 2>&1 ;;
    python3-venv) python3 -c "import venv, ensurepip" >/dev/null 2>&1 ;;
    seclists)
      for d in /usr/share/seclists /usr/share/wordlists/seclists /usr/share/SecLists \
               "$HOME/SecLists" "$HOME/seclists" /opt/SecLists /opt/seclists; do
        [ -d "$d/Discovery/Web-Content" ] && return 0
      done
      return 1 ;;
    *)            command -v "$1" >/dev/null 2>&1 || dpkg -s "$1" >/dev/null 2>&1 ;;
  esac
}
TO_INSTALL=()
for pkg in nmap dnsutils seclists nikto ffuf feroxbuster dirsearch nuclei subfinder amass \
           assetfinder testssl.sh python3-venv python3-pip pipx curl wslu libcap2-bin; do
  if have "$pkg"; then echo "  already present  $pkg"; else TO_INSTALL+=("$pkg"); fi
done
if [ ${#TO_INSTALL[@]} -gt 0 ]; then
  echo "  will install: ${TO_INSTALL[*]}"
  $SUDO apt-get update -y || echo "apt update failed; continuing"
  # One at a time so a package that is missing never aborts the rest.
  for pkg in "${TO_INSTALL[@]}"; do
    if $SUDO apt-get install -y "$pkg" >/dev/null 2>&1; then echo "  installed        $pkg"
    else echo "  MISSING          $pkg"; MISSING+=("$pkg"); fi
  done
else
  echo "  nothing to install; skipping apt entirely"
fi

say "2/7  knockpy (optional, best effort)"
if ! command -v knockpy >/dev/null 2>&1; then
  pipx install knock-subdomains >/dev/null 2>&1 && echo "  installed knockpy" || { echo "  could not install knockpy (lasy works without it)"; MISSING+=("knockpy"); }
  pipx ensurepath >/dev/null 2>&1 || true
else echo "  ok       knockpy"; fi

say "3/7  Letting nmap use raw sockets without sudo"
NMAP_BIN="$(readlink -f "$(command -v nmap)" 2>/dev/null || true)"
if [ -n "$NMAP_BIN" ] && $SUDO setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_BIN"; then
  echo "  ok: capabilities set on $NMAP_BIN"
else
  echo "  setcap failed. See README, section 'If nmap still asks for sudo'."
fi

say "4/7  Python environment"
python3 -m venv "$REPO/.venv" && "$REPO/.venv/bin/pip" install --upgrade pip >/dev/null \
  && "$REPO/.venv/bin/pip" install -r "$REPO/backend/requirements.txt" || { echo "Python setup failed"; exit 1; }

say "5/7  Web interface"
if [ -f "$REPO/frontend/dist/index.html" ]; then
  echo "  prebuilt interface found, skipping the build"
else
  $SUDO apt-get install -y nodejs npm >/dev/null 2>&1
  ( cd "$REPO/frontend" && npm install && npm run build ) || { echo "UI build failed"; exit 1; }
fi

say "6/7  Nuclei templates"
if command -v nuclei >/dev/null 2>&1; then
  if [ -d "$HOME/nuclei-templates" ] || [ -d "$HOME/.local/nuclei-templates" ]; then echo "  templates already present; not downloading again"
  else nuclei -update-templates >/dev/null 2>&1 && echo "  templates downloaded" || echo "  could not download templates now; run: nuclei -update-templates"; fi
fi

say "7/7  Installing the 'lasy' command"
mkdir -p "$HOME/.local/bin"
ln -sf "$REPO/bin/lasy" "$HOME/.local/bin/lasy"
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [ -f "$rc" ] || continue
  grep -q '.local/bin' "$rc" || printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$rc"
done
export PATH="$HOME/.local/bin:$PATH"
( cd "$REPO/backend" && "$REPO/.venv/bin/python" - <<'PY'
import os
from lasy_backend import db
db.init_db()
cur = db.get_setting("seclists_root", "")
if not os.path.isdir(os.path.join(cur, "Discovery")):   # point lasy at the SecLists you already have
    home = os.path.expanduser("~")
    for d in ("/usr/share/seclists", "/usr/share/wordlists/seclists", "/usr/share/SecLists", home + "/SecLists",
              home + "/seclists", "/opt/SecLists", "/opt/seclists"):
        if os.path.isdir(os.path.join(d, "Discovery", "Web-Content")):
            db.set_setting("seclists_root", d)
            print("  SecLists found at", d, "and used as is")
            break
PY
)

echo
if [ ${#MISSING[@]} -gt 0 ]; then
  echo "Not installed: ${MISSING[*]}"
  echo "lasy still works; those tools just stay unavailable until you install them."
fi
say "Done. Open a NEW terminal (or run: source ~/.zshrc) and then type:  lasy"
echo "Check your setup any time with:  lasy doctor"
