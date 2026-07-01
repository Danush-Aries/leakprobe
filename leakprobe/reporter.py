"""Reporting: colored terminal output plus markdown and HTML reports."""
from __future__ import annotations

import html
from pathlib import Path
from typing import Dict, List

from rich.console import Console
from rich.table import Table

from leakprobe.attacks import FAMILIES
from leakprobe.runner import ProbeResult, headline


def _severity_color(severity: str) -> str:
    return {
        "critical": "bold red",
        "leaked": "red",
        "partial": "yellow",
        "safe": "green",
    }.get(severity, "white")


def _rank(results: List[ProbeResult]) -> List[ProbeResult]:
    return sorted(results, key=lambda r: r.leak_score, reverse=True)


def render_terminal(results: List[ProbeResult], console: Console | None = None) -> None:
    """Pretty colored terminal report."""
    console = console or Console()
    ranked = _rank(results)

    console.rule("[bold]leakprobe - system-prompt leak report")

    # Model ranking
    table = Table(title="Model leak ranking (higher = leakier)", header_style="bold")
    table.add_column("#", justify="right")
    table.add_column("Model")
    table.add_column("Leak score", justify="right")
    table.add_column("Leaked / total", justify="right")
    table.add_column("Verdict")
    for i, r in enumerate(ranked, 1):
        verdict = "LEAKY" if r.leak_score >= 40 else ("SOME LEAKS" if r.leaked_count else "ROBUST")
        color = "red" if r.leak_score >= 40 else ("yellow" if r.leaked_count else "green")
        table.add_row(
            str(i),
            r.label,
            f"[{color}]{r.leak_score:.1f}[/{color}]",
            f"{r.leaked_count}/{r.total_attacks}",
            f"[{color}]{verdict}[/{color}]",
        )
    console.print(table)

    # Per-family breakdown
    fam_table = Table(title="Leak score by attack family (mean 0-100)", header_style="bold")
    fam_table.add_column("Family")
    for r in ranked:
        fam_table.add_column(r.model.replace("mock:", ""), justify="right")
    for fam in FAMILIES:
        row = [fam]
        for r in ranked:
            s = r.family_scores.get(fam, 0.0)
            color = "red" if s >= 40 else ("yellow" if s >= 20 else "green")
            row.append(f"[{color}]{s:.0f}[/{color}]")
        fam_table.add_row(*row)
    console.print(fam_table)

    # Top leaking attacks (worst offenders across all models)
    worst = []
    for r in results:
        for a in r.attacks:
            worst.append((r.label, a))
    worst.sort(key=lambda t: t[1].score, reverse=True)
    top_table = Table(title="Top 10 leaking attacks", header_style="bold")
    top_table.add_column("Model")
    top_table.add_column("Attack")
    top_table.add_column("Family")
    top_table.add_column("Score", justify="right")
    top_table.add_column("Severity")
    for label, a in worst[:10]:
        c = _severity_color(a.severity)
        top_table.add_row(label, a.attack_id, a.family, f"{a.score:.0f}", f"[{c}]{a.severity}[/{c}]")
    console.print(top_table)

    # Headline
    hl = headline(results, "repeat_above")
    console.print(
        f"\n[bold]Headline:[/bold] the '[cyan]repeat above[/cyan]' family leaks the prompt in "
        f"[bold red]{hl['models_leaking']} of {hl['total_models']}[/bold red] models tested.\n"
    )


def _family_line(results: List[ProbeResult]) -> List[str]:
    ranked = _rank(results)
    header = "| Family | " + " | ".join(r.model.replace("mock:", "") for r in ranked) + " |"
    sep = "|" + "---|" * (len(ranked) + 1)
    lines = [header, sep]
    for fam in FAMILIES:
        cells = [f"{r.family_scores.get(fam, 0.0):.0f}" for r in ranked]
        lines.append(f"| `{fam}` | " + " | ".join(cells) + " |")
    return lines


def build_markdown(results: List[ProbeResult], secret_preview: str = "") -> str:
    ranked = _rank(results)
    hl = headline(results, "repeat_above")
    lines: List[str] = []
    lines.append("# leakprobe report")
    lines.append("")
    lines.append(
        f"> **Headline:** the `repeat_above` family leaks the prompt in "
        f"**{hl['models_leaking']} of {hl['total_models']}** models tested."
    )
    lines.append("")
    lines.append(f"- Attacks per model: **{ranked[0].total_attacks}**")
    lines.append(f"- Models evaluated: **{len(ranked)}**")
    lines.append(f"- Detector threshold: **40 / 100**")
    if secret_preview:
        lines.append(f"- Secret under test (preview): `{secret_preview}`")
    lines.append("")

    lines.append("## Model leak ranking (higher = leakier)")
    lines.append("")
    lines.append("| # | Model | Leak score | Leaked / total | Verdict |")
    lines.append("|---|---|---|---|---|")
    for i, r in enumerate(ranked, 1):
        verdict = "LEAKY" if r.leak_score >= 40 else ("SOME LEAKS" if r.leaked_count else "ROBUST")
        lines.append(
            f"| {i} | {r.label} | {r.leak_score:.1f} | {r.leaked_count}/{r.total_attacks} | {verdict} |"
        )
    lines.append("")

    lines.append("## Leak score by attack family (mean 0-100)")
    lines.append("")
    lines.extend(_family_line(results))
    lines.append("")

    lines.append("## Top 10 leaking attacks")
    lines.append("")
    lines.append("| Model | Attack | Family | Score | Severity |")
    lines.append("|---|---|---|---|---|")
    worst = []
    for r in results:
        for a in r.attacks:
            worst.append((r.label, a))
    worst.sort(key=lambda t: t[1].score, reverse=True)
    for label, a in worst[:10]:
        lines.append(f"| {label} | `{a.attack_id}` | {a.family} | {a.score:.0f} | {a.severity} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_Generated by [leakprobe](https://github.com/Danush-Aries/leakprobe). "
                 "Mock backend is deterministic and fully offline._")
    lines.append("")
    return "\n".join(lines)


def build_html(results: List[ProbeResult], secret_preview: str = "") -> str:
    ranked = _rank(results)
    hl = headline(results, "repeat_above")

    def cell_color(score: float) -> str:
        if score >= 40:
            return "#c0392b"
        if score >= 20:
            return "#e67e22"
        return "#27ae60"

    rows = []
    for i, r in enumerate(ranked, 1):
        verdict = "LEAKY" if r.leak_score >= 40 else ("SOME LEAKS" if r.leaked_count else "ROBUST")
        rows.append(
            f"<tr><td>{i}</td><td>{html.escape(r.label)}</td>"
            f"<td style='color:{cell_color(r.leak_score)};font-weight:700'>{r.leak_score:.1f}</td>"
            f"<td>{r.leaked_count}/{r.total_attacks}</td><td>{verdict}</td></tr>"
        )

    fam_header = "".join(f"<th>{html.escape(r.model.replace('mock:', ''))}</th>" for r in ranked)
    fam_rows = []
    for fam in FAMILIES:
        cells = "".join(
            f"<td style='color:{cell_color(r.family_scores.get(fam, 0.0))}'>"
            f"{r.family_scores.get(fam, 0.0):.0f}</td>"
            for r in ranked
        )
        fam_rows.append(f"<tr><td><code>{fam}</code></td>{cells}</tr>")

    preview = f"<p><b>Secret under test (preview):</b> <code>{html.escape(secret_preview)}</code></p>" if secret_preview else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>leakprobe report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 900px;
         margin: 2rem auto; padding: 0 1rem; color: #222; }}
  h1 {{ margin-bottom: .2rem; }}
  .headline {{ background:#fdecea; border-left:4px solid #c0392b; padding:.8rem 1rem;
               border-radius:4px; font-size:1.05rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #ddd; padding: .45rem .6rem; text-align: center; }}
  th {{ background:#f4f4f4; }}
  td:first-child, th:first-child {{ text-align: left; }}
  code {{ background:#f2f2f2; padding:1px 4px; border-radius:3px; }}
  footer {{ color:#888; font-size:.85rem; margin-top:2rem; }}
</style></head><body>
<h1>leakprobe report</h1>
<p>Offline system-prompt-extraction robustness test.</p>
<div class="headline">Headline: the <code>repeat_above</code> family leaks the prompt in
<b>{hl['models_leaking']} of {hl['total_models']}</b> models tested.</div>
{preview}
<h2>Model leak ranking (higher = leakier)</h2>
<table><thead><tr><th>#</th><th>Model</th><th>Leak score</th><th>Leaked / total</th><th>Verdict</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Leak score by attack family (mean 0-100)</h2>
<table><thead><tr><th>Family</th>{fam_header}</tr></thead>
<tbody>{''.join(fam_rows)}</tbody></table>
<footer>Generated by leakprobe. Mock backend is deterministic and fully offline. No API keys required.</footer>
</body></html>
"""


def write_reports(
    results: List[ProbeResult],
    out_dir: Path | str,
    secret_preview: str = "",
) -> Dict[str, Path]:
    """Write markdown and HTML reports; return the paths written."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "report.md"
    html_path = out_dir / "report.html"
    md_path.write_text(build_markdown(results, secret_preview), encoding="utf-8")
    html_path.write_text(build_html(results, secret_preview), encoding="utf-8")
    return {"markdown": md_path, "html": html_path}
