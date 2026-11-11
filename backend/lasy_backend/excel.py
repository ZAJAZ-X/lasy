"""Styled Excel exports that mirror the reference tables from the brief:
white bold header, thin grey borders, pale-blue banded rows, bold centred Sl. No,
dashes for missing values, and a red bold "Yes" for reachable subdomains."""
from __future__ import annotations

from pathlib import Path

from openpyxl import Workbook
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

BAND = PatternFill("solid", fgColor="DAE3F3")
NONE = PatternFill(fill_type=None)
_S = Side(style="thin", color="808080")
BORDER = Border(left=_S, right=_S, top=_S, bottom=_S)
FONT = Font(name="Calibri", size=11)
BOLD = Font(name="Calibri", size=11, bold=True)
CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)
LEFT = Alignment(horizontal="left", vertical="center", wrap_text=True)

SEV_FILL = {"critical": ("C00000", "FFFFFF"), "high": ("ED7D31", "FFFFFF"), "medium": ("FFC000", "000000"),
            "low": ("5B9BD5", "FFFFFF"), "info": ("D9D9D9", "000000")}


def _dash(v) -> str:
    return "-" if v is None or v == "" else str(v)


def _header(ws, titles: list[str]) -> None:
    for c, t in enumerate(titles, 1):
        cell = ws.cell(row=1, column=c, value=t)
        cell.font, cell.border = BOLD, BORDER
        cell.alignment = Alignment(horizontal="left" if c > 1 else "center", vertical="center", wrap_text=True)
    ws.row_dimensions[1].height = 32


def _put(ws, r: int, c: int, v, *, band: bool, center=False, bold=False) -> None:
    cell = ws.cell(row=r, column=c, value=v)
    cell.font = BOLD if bold else FONT
    cell.border = BORDER
    cell.alignment = CENTER if center else LEFT
    cell.fill = BAND if band else NONE


def _widths(ws, widths: list[int]) -> None:
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


def _save(wb: Workbook, out: str | Path) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out)
    return out


def export_nmap(rows: list[dict], out: str | Path) -> Path:
    """rows: [{host, ports:[{port, service, version}]}]. Rows alternate by line; the merged
    Sl No./host cells take the colour of the first line of their group (as in the reference)."""
    wb = Workbook()
    ws = wb.active
    ws.title = "Nmap Results"
    _header(ws, ["Sl No.", "Host/IP Address", "Open Port", "Service Detection", "Server Type/Version"])
    r = 2
    line = 0
    for idx, host in enumerate(rows, 1):
        ports = host.get("ports") or [{}]
        start, first_band = r, line % 2 == 0
        for p in ports:
            band = line % 2 == 0
            _put(ws, r, 3, _dash(p.get("port")), band=band)
            _put(ws, r, 4, _dash(p.get("service")), band=band)
            _put(ws, r, 5, _dash(p.get("version")), band=band)
            _put(ws, r, 1, None, band=first_band, center=True, bold=True)
            _put(ws, r, 2, None, band=first_band)
            r += 1
            line += 1
        ws.cell(row=start, column=1, value=idx)
        ws.cell(row=start, column=2, value=host.get("host", "-"))
        if r - start > 1:
            ws.merge_cells(start_row=start, start_column=1, end_row=r - 1, end_column=1)
            ws.merge_cells(start_row=start, start_column=2, end_row=r - 1, end_column=2)
    _widths(ws, [9, 34, 14, 22, 38])
    ws.freeze_panes = "A2"
    return _save(wb, out)


def export_subdomain(result: dict, out: str | Path) -> Path:
    wb = Workbook()
    ws = wb.active
    ws.title = "Subdomains"
    _header(ws, ["Sl. No", "Domain", "IP Address", "Accessibility"])
    for i, row in enumerate(result.get("rows", []), 1):
        r, band = i + 1, i % 2 == 1
        _put(ws, r, 1, i, band=band, center=True, bold=True)
        _put(ws, r, 2, _dash(row.get("domain")), band=band)
        _put(ws, r, 3, _dash(row.get("ip")), band=band)
        acc = (row.get("accessible") or "-").lower()
        if acc == "yes":
            red = InlineFont(rFont="Calibri", sz=11, b=True, color="FFFF0000")
            plain = InlineFont(rFont="Calibri", sz=11)
            value = CellRichText(TextBlock(red, "Yes"),
                                 TextBlock(plain, f", redirects to {row['redirect']}")) if row.get("redirect") \
                else CellRichText(TextBlock(red, "Yes"))
            _put(ws, r, 4, value, band=band)
        else:
            _put(ws, r, 4, "No" if acc == "no" else "-", band=band)
    _widths(ws, [9, 44, 20, 52])
    ws.freeze_panes = "A2"

    # unique output per tool, kept separate as requested
    summary = result.get("summary", {})
    labels = result.get("labels", {})
    ws2 = wb.create_sheet("Unique per tool")
    _header(ws2, ["Sl. No", "Found only by", "Subdomain"])
    n = 0
    for tool, names in (result.get("unique") or {}).items():
        for name in names:
            n += 1
            _put(ws2, n + 1, 1, n, band=n % 2 == 1, center=True, bold=True)
            _put(ws2, n + 1, 2, labels.get(tool, tool), band=n % 2 == 1)
            _put(ws2, n + 1, 3, name, band=n % 2 == 1)
    if n == 0:
        _put(ws2, 2, 1, "-", band=False, center=True)
        _put(ws2, 2, 2, "-", band=False)
        _put(ws2, 2, 3, "No subdomain was found by only one tool", band=False)
    _widths(ws2, [9, 24, 48])
    ws3 = wb.create_sheet("Tool summary")
    _header(ws3, ["Tool", "Subdomains found", "Found only by this tool", "Status"])
    for i, (tool, s) in enumerate(summary.items(), 1):
        _put(ws3, i + 1, 1, labels.get(tool, tool), band=i % 2 == 1)
        _put(ws3, i + 1, 2, s.get("found", 0), band=i % 2 == 1, center=True)
        _put(ws3, i + 1, 3, s.get("unique", 0), band=i % 2 == 1, center=True)
        state = {"ok": "Completed", "missing": "Not installed", "failed": "Failed"}.get(s.get("state"), s.get("state"))
        _put(ws3, i + 1, 4, state, band=i % 2 == 1)
    _widths(ws3, [26, 20, 26, 20])
    if result.get("wildcards"):
        ws4 = wb.create_sheet("Notes")
        _header(ws4, ["Domain", "Note"])
        for i, (dom, ip) in enumerate(result["wildcards"].items(), 1):
            _put(ws4, i + 1, 1, dom, band=i % 2 == 1)
            _put(ws4, i + 1, 2, f"Wildcard DNS: any name under this domain resolves to {ip}. Subdomains with that IP "
                                "may not be real hosts.", band=i % 2 == 1)
        _widths(ws4, [30, 90])
    return _save(wb, out)


def export_nameserver(rows: list[dict], out: str | Path) -> Path:
    multi = len({r.get("domain") for r in rows}) > 1
    wb = Workbook()
    ws = wb.active
    ws.title = "Nameservers"
    _header(ws, (["Sl. No", "Domain", "Nameserver"] if multi else ["Sl. No", "Nameserver"]))
    for i, row in enumerate(rows, 1):
        r, band = i + 1, i % 2 == 1
        _put(ws, r, 1, i, band=band, center=True, bold=True)
        if multi:
            _put(ws, r, 2, _dash(row.get("domain")), band=band)
        _put(ws, r, 3 if multi else 2, _dash(row.get("nameserver")), band=band)
    _widths(ws, [9, 30, 44] if multi else [9, 44])
    ws.freeze_panes = "A2"
    return _save(wb, out)


def export_hostup(rows: list[dict], out: str | Path) -> Path:
    wb = Workbook()
    ws = wb.active
    ws.title = "Host status"
    _header(ws, ["Sl. No", "Host/IP Address", "Status"])
    for i, row in enumerate(rows, 1):
        r, band = i + 1, i % 2 == 1
        _put(ws, r, 1, i, band=band, center=True, bold=True)
        _put(ws, r, 2, _dash(row.get("host")), band=band)
        _put(ws, r, 3, _dash(row.get("status")), band=band)
    _widths(ws, [9, 40, 14])
    ws.freeze_panes = "A2"
    return _save(wb, out)


def export_findings(rows: list[dict], out: str | Path) -> Path:
    """rows: [{severity, tool, title, target, evidence}] already sorted."""
    wb = Workbook()
    ws = wb.active
    ws.title = "Findings"
    _header(ws, ["Sl. No", "Severity", "Tool", "Finding", "Affected", "Evidence"])
    for i, row in enumerate(rows, 1):
        r, band = i + 1, i % 2 == 1
        _put(ws, r, 1, i, band=band, center=True, bold=True)
        sev = row.get("severity", "info")
        cell = ws.cell(row=r, column=2, value=sev.capitalize())
        fill, fg = SEV_FILL.get(sev, SEV_FILL["info"])
        cell.fill, cell.font, cell.border, cell.alignment = (
            PatternFill("solid", fgColor=fill), Font(name="Calibri", size=11, bold=True, color=fg), BORDER, CENTER)
        _put(ws, r, 3, _dash(row.get("tool")), band=band)
        _put(ws, r, 4, _dash(row.get("title")), band=band)
        _put(ws, r, 5, _dash(row.get("target")), band=band)
        _put(ws, r, 6, _dash(row.get("evidence")), band=band)
    _widths(ws, [8, 11, 16, 46, 38, 80])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:F{max(2, len(rows) + 1)}"
    return _save(wb, out)
