"""leakprobe command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List

from rich.console import Console

from leakprobe import __version__
from leakprobe.attacks import FAMILIES, load_attacks
from leakprobe.models import DEFAULT_MODELS, list_mock_profiles
from leakprobe.reporter import render_terminal, write_reports
from leakprobe.runner import ProbeResult, headline, run_many

_DEFAULT_RESULTS = Path("results/results.json")
_DEFAULT_OUTDIR = Path("results")


def _load_results_json(path: Path) -> List[ProbeResult]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [_probe_from_dict(d) for d in data["results"]]


def _probe_from_dict(d: dict) -> ProbeResult:
    from leakprobe.runner import AttackResult

    attacks = [AttackResult(**a) for a in d.get("attacks", [])]
    d = {**d, "attacks": attacks}
    return ProbeResult(**d)


def _save_results_json(results: List[ProbeResult], system_prompt: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": __version__,
        "secret_preview": system_prompt.strip().splitlines()[0][:80] if system_prompt.strip() else "",
        "results": [r.to_dict() for r in results],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def cmd_run(args: argparse.Namespace) -> int:
    console = Console()
    sp_path = Path(args.system_prompt)
    if not sp_path.exists():
        console.print(f"[red]error:[/red] system prompt file not found: {sp_path}")
        return 2
    system_prompt = sp_path.read_text(encoding="utf-8")
    if not system_prompt.strip():
        console.print(f"[red]error:[/red] system prompt file is empty: {sp_path}")
        return 2

    models = args.model or DEFAULT_MODELS
    attacks = load_attacks()
    console.print(
        f"[bold]leakprobe[/bold] running [cyan]{len(attacks)}[/cyan] attacks "
        f"against [cyan]{len(models)}[/cyan] model(s)..."
    )
    results = run_many(models, system_prompt, attacks, threshold=args.threshold)

    render_terminal(results, console)

    results_path = Path(args.results)
    _save_results_json(results, system_prompt, results_path)
    preview = system_prompt.strip().splitlines()[0][:80] if system_prompt.strip() else ""
    written = write_reports(results, args.out_dir, secret_preview=preview)
    console.print(f"[green]saved[/green] raw results -> {results_path}")
    console.print(f"[green]wrote[/green] markdown report -> {written['markdown']}")
    console.print(f"[green]wrote[/green] html report     -> {written['html']}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    console = Console()
    results_path = Path(args.results)
    if not results_path.exists():
        console.print(
            f"[red]error:[/red] no results found at {results_path}. "
            f"Run `leakprobe run --system-prompt <file>` first."
        )
        return 2
    results = _load_results_json(results_path)
    render_terminal(results, console)
    if args.write:
        written = write_reports(results, args.out_dir)
        console.print(f"[green]wrote[/green] markdown -> {written['markdown']}")
        console.print(f"[green]wrote[/green] html     -> {written['html']}")
    return 0


def cmd_attacks(args: argparse.Namespace) -> int:
    console = Console()
    attacks = load_attacks()
    console.print(f"[bold]{len(attacks)}[/bold] attacks across {len(FAMILIES)} families:\n")
    for fam, desc in FAMILIES.items():
        fam_attacks = [a for a in attacks if a.family == fam]
        console.print(f"[cyan]{fam}[/cyan] ({len(fam_attacks)}) - {desc}")
        if args.verbose:
            for a in fam_attacks:
                console.print(f"    [dim]{a.id}[/dim] {a.prompt[:70]}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="leakprobe",
        description="Offline system-prompt-extraction robustness tester.",
    )
    p.add_argument("--version", action="version", version=f"leakprobe {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the attack pack against a model + secret prompt")
    run.add_argument("--system-prompt", required=True, help="path to secret system prompt file")
    run.add_argument(
        "--model",
        action="append",
        help=f"model spec, e.g. mock:weak, mock:hardened, ollama:llama3 "
        f"(repeatable; default: all mock profiles {list(list_mock_profiles())})",
    )
    run.add_argument("--threshold", type=float, default=40.0, help="leak threshold 0-100 (default 40)")
    run.add_argument("--results", default=str(_DEFAULT_RESULTS), help="where to write raw results json")
    run.add_argument("--out-dir", default=str(_DEFAULT_OUTDIR), help="directory for md/html reports")
    run.set_defaults(func=cmd_run)

    rep = sub.add_parser("report", help="render the last saved results")
    rep.add_argument("--results", default=str(_DEFAULT_RESULTS), help="raw results json to render")
    rep.add_argument("--out-dir", default=str(_DEFAULT_OUTDIR), help="directory for md/html reports")
    rep.add_argument("--write", action="store_true", help="also (re)write md/html reports")
    rep.set_defaults(func=cmd_report)

    atk = sub.add_parser("attacks", help="list the attack pack")
    atk.add_argument("-v", "--verbose", action="store_true", help="show each attack prompt")
    atk.set_defaults(func=cmd_attacks)

    return p


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
