# lasy user guide

The details behind the [README](../README.md): how to use each part, what the settings do, and how problems are handled.

## Checking your setup with `lasy doctor`

| Check | Must be green? | If not |
| --- | --- | --- |
| nmap, dig | Yes | `sudo apt install nmap dnsutils` |
| nmap raw sockets without a password | Yes | run the `setcap` command it prints |
| Results folder writable | Yes | mount the drive (`ls /mnt/c`), or fix the path in Settings |
| testssl, nuclei, nikto, ffuf, feroxbuster, dirsearch | Per tool | `sudo apt install <name>`; a missing tool is skipped, not fatal |
| subfinder, amass, assetfinder, knockpy | Per tool | same; knockpy: `pipx install knock-subdomains` (that is the PyPI name; the command it gives you is `knockpy`) |
| SecLists | For wordlist suggestions | `sudo apt install seclists` |
| nuclei templates | For nuclei | `nuclei -update-templates` |

Commands: `lasy` (start and open), `lasy stop`, `lasy restart`, `lasy status`, `lasy logs`, `lasy doctor`.


## Using it

**Projects.** Naming a project creates its folder under your results location, with a sub-folder per tool. Files are
timestamped; nothing is overwritten. Only tool output goes there. The database, input lists and terminal replay logs stay
on the Kali side.

**Deleting a project.** On the Projects page (trash icon) or at the bottom of a project's Overview. The dialog shows what will
go: the scans and findings in lasy, and, with the switch on, the project's results folder on your PC (file count and size).
You must type the project name exactly. It refuses while a scan is running, and refuses any folder that is not clearly that
project's own (for example your home folder or the results root). If Windows has a file open, nothing is removed from lasy so
you can close it and retry. Switch the folder option off to forget the project but keep its files.

**Layout.** A sidebar on the left follows you through the app (Projects, Settings, and the current project's tasks); collapse it
with the button at its foot. Interface style (Settings → General) switches between Glass (translucent panels over a soft green
glow) and Solid (opaque panels). The green accents, the terminal and the report tables look the same in both.

### External Pentest
- **Nmap scans.** Paste IPs, ranges and domains in any mix. Choose stages and press *Run all selected stages*, or run any
  stage alone. Order: TCP top 1000, service scan, UDP top 1000, UDP service scan; TCP/UDP all-ports run in the
  background, and ports they find beyond the top 1000 are scanned automatically. UDP all-ports is off by default.
  Hosts are split into parallel batches (Settings: parallel batches, hosts per batch).
  The results table fills in as scans finish. Every IP and domain you entered has a row (dashes if nothing was found);
  ranges list only the hosts that respond. *Export current table to Excel* downloads to your Windows Downloads folder.
  *Web scans for open web ports* sends the web services found to Web App PT.
- **Subdomain enumeration.** subfinder, knockpy, amass, assetfinder and crt.sh run together. Results are merged, resolved,
  and probed over HTTP(S): 4xx is No, 3xx is Yes with the redirect target, other answers are Yes, no IP or no answer is a
  dash. Excel has the main table plus a sheet of names found by only one tool.
  **knockpy note:** knockpy's on-screen result table cuts any name longer than 26 characters, so lasy reads the complete
  list from knockpy's own saved report (`~/.knockpy/reports.db`, read-only) instead of the screen. The terminal still shows
  knockpy's table exactly as it prints it, and the full names are also saved as `knockpy_subdomains.txt`.
- **Nameserver lookup** (dig) and **Host up/down** (nmap -sn).

### Web App Pentest
1. Add targets (`host:port`, a URL, or `host port`). Plain HTTP targets are skipped by TLS tools.
2. Set up directory discovery: pick the application type and a suggested wordlist (sizes and time estimates are shown).
3. **Run everything in order:** tick the tools you want, reorder with the arrows, press *Run selected tools in order*.
   Tools run strictly one after another. A missing or blocked tool is skipped with the reason and the run continues.
   A summary appears when it ends.
4. **Or run one tool on its own** with its *Run* button.
5. *Open results* on any tool shows that tool's page: findings (with severity filters and search), for directory tools
   a ranked "look at these first" list and all endpoints, per-target outcome, saved files, run history, the live terminal,
   and a per-tool Excel download. *All findings* combines every tool; *Content discovery intelligence* merges
   ffuf, feroxbuster and dirsearch into one ranked view.

Order of the default full run: Nmap SSL scripts, testssl.sh, Nikto, Nuclei, ffuf, feroxbuster, dirsearch.

---

## Settings

Settings is organised by category (sidebar on the left): **General** (results folder, text size, mascot, terminal prompt),
**External pentest** (nmap, subdomain enumeration, dig, knockpy, subfinder, amass), **Web App PT** (testssl.sh, nuclei,
nikto, ffuf, feroxbuster, dirsearch, wordlists) and **System checks**. Every tool page shows the exact command that will run,
updating as you type. Every default reproduces the command lasy always ran, except knockpy, which now defaults to
`--recon --bruteforce`.

- **Options** are typed fields (tick boxes, numbers) for flags lasy sets itself, so there is never a clash.
- **Extra arguments** is added to the end of the command. Flags lasy already controls are refused with an explanation,
  and interactive or output-changing flags are blocked.
- **Time limit** stops a tool after that many minutes and keeps what it found so far.
- **Reset this section to defaults** restores a category (press Save to apply).
- **If a tool version rejects a flag**, lasy retries with a gentler form: knockpy falls back to a plain run, and amass drops
  a flag its version does not know. Amass v5 also needs its engine running.
- **Interface style** (Glass or Solid), **Text size** (Large or Standard) and **Show the lasy mascot** are under General. The mascot never appears in the terminal,
  tables or exports.

## Pause and resume

nmap cannot pause mid-scan. Pausing stops the nmap processes safely (like Ctrl-C) and keeps everything already finished.
nmap scans a batch of hosts as one group and writes results only when the group completes, so a pause or a closed laptop
costs the batches in flight, not the whole scan. Smaller batches lose less; full scans are also split into port ranges for
the same reason. After a restart lasy marks unfinished work as *interrupted* and you press *Resume* (or *Retry failed
batches*). Pause is only offered on scans long enough to need it.

## How lasy handles problems

| Situation | What happens |
| --- | --- |
| Tool not installed | Blocked immediately with the install command. In a full run it is skipped and the run continues. |
| Target unreachable, port closed, not TLS, timeout | Reported as **Could not scan** for that target with the reason. Never shown as "no findings". |
| One target fails among several | Other targets finish; a warning says coverage is incomplete. |
| Every target fails | The run is marked Failed with the reason. |
| Plain HTTP target for a TLS tool | Skipped with the reason. |
| You press Stop | Work finished before the Stop is kept and marked partial. |
| Wordlist missing or empty | Blocked up front with a message. |
| Results folder unreachable (drive not mounted) | Scan refuses to start and says how to fix it. |
| Windows drive path typed wrongly | First-run and Settings verify the folder is writable before saving. |
| Invalid settings (timing, extra nmap flags that clash with lasy's files) | Rejected with an explanation. |
| Range larger than a /16 | Rejected; split it up. |
| Wildcard DNS on a domain | Detected; wildcard-only names are flagged and can be hidden. |
| Everything on a host looks like a soft-404 | Noise is detected and down-ranked, with a warning. |
| Closed laptop or lasy restarted mid-scan | Scans become Interrupted and can be resumed; terminal history is kept. |
| Backend stops while the page is open | A banner says so; terminals reconnect on their own. |
| Unexpected page error | A friendly error page; your results are safe. |

## If nmap still asks for sudo

The installer sets file capabilities on nmap. If that does not work on your system, add a scoped rule instead:
```
# sudo visudo -f /etc/sudoers.d/lasy-nmap
your_user ALL=(root) NOPASSWD: /usr/bin/nmap
```
Then set *Use sudo for nmap* to 1 in Settings.

## Troubleshooting

- `lasy: command not found`: open a new terminal, or add `export PATH="$HOME/.local/bin:$PATH"` to `~/.zshrc`.
- Browser did not open: lasy prints the address; open `http://127.0.0.1:8847`. If Windows cannot reach it, run
  `wsl --shutdown` in Windows and start Kali again.
- Port in use: `LASY_PORT=9000 lasy`.
- Logs: `lasy logs`.

## Font note

The terminal uses Cascadia Mono (the Windows Terminal default), then Consolas. Both are present on Windows, so
screenshots match a real Kali WSL window.
