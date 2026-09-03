#!/usr/bin/env python3
"""
Skill Scanner — static + LLM-powered analyzer for AI skill files.

Three top-level rules, each independently produces Benign/Suspicious/Malicious:

  Rule 1  MALICIOUS_INSTRUCTIONS   Static regex patterns (fast, no network)
  Rule 2  CONSISTENCY_CHECK        LLM: does the code match declared intent?
  Rule 3  DEPENDENCY_CHECK         LLM: are all URLs/imports legitimate?

Overall verdict = worst of the three.

Usage:
    python skill_scanner.py <path>                  # full scan (all 3 rules)
    python skill_scanner.py <path> --static-only    # Rule 1 only, no LLM calls
    python skill_scanner.py <path> -v               # verbose findings
    python skill_scanner.py <path> --json out.json  # also write JSON report
    python skill_scanner.py <path> --fail-on malicious   # CI exit code
"""

import argparse
import json
import os
import sys
from collections import defaultdict

from scanner import scan_path, ScanResult, RuleResult

# ── Verdict ordering (used for comparisons and filtering) ──────────────────
VERDICT_ORDER = {"Benign": 0, "Suspicious": 1, "Malicious": 2}

# ── ANSI colors — disabled automatically when stdout is not a TTY ──────────
COLORS = {
    "Benign":     "\033[32m",   # green
    "Suspicious": "\033[33m",   # yellow
    "Malicious":  "\033[31m",   # red
    "reset":      "\033[0m",
    "bold":       "\033[1m",
    "dim":        "\033[2m",
    "cyan":       "\033[36m",
}

def _c(text, key, use_color):
    """Wrap text in an ANSI color if colors are enabled."""
    if not use_color:
        return text
    return f"{COLORS.get(key, '')}{text}{COLORS['reset']}"


# ── Skill-unit discovery (same logic as before) ────────────────────────────

def _is_skill_dir(path: str) -> bool:
    return os.path.isfile(os.path.join(path, "SKILL.md"))

def _find_skill_units(root: str):
    """
    Identify the individual skill units under `root`.
    A skill unit is either a single file, a directory containing SKILL.md,
    or (fallback) the whole root directory.
    """
    if os.path.isfile(root):
        return [root]
    if _is_skill_dir(root):
        return [root]
    units = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       (".git", "node_modules", "__pycache__", ".venv", "venv")]
        if "SKILL.md" in filenames:
            units.append(dirpath)
    return units or [root]


# ── Report rendering ───────────────────────────────────────────────────────

_RULE_LABELS = {
    "MALICIOUS_INSTRUCTIONS": "Rule 1 — MALICIOUS_INSTRUCTIONS (static patterns)",
    "CONSISTENCY_CHECK":      "Rule 2 — CONSISTENCY_CHECK      (LLM)",
    "DEPENDENCY_CHECK":       "Rule 3 — DEPENDENCY_CHECK       (LLM)",
}

def _print_rule_result(rr: RuleResult, verbose: bool, use_color: bool):
    """Print one rule's result block inside a skill report."""
    label = _RULE_LABELS.get(rr.rule_id, rr.rule_id)
    verdict_str = _c(f"[{rr.verdict}]", rr.verdict, use_color)

    # Rule header line
    mock_tag = _c("  ⚠ mock agent", "dim", use_color) if rr.used_mock else ""
    conf_tag  = f"  confidence: {rr.llm_confidence}" if rr.llm_confidence else ""
    score_tag = f"  score: {rr.score}" if rr.rule_id == "MALICIOUS_INSTRUCTIONS" else ""
    print(f"  {verdict_str}  {_c(label, 'cyan', use_color)}{score_tag}{conf_tag}{mock_tag}")

    if rr.error:
        print(_c(f"    ↳ {rr.error}", "dim", use_color))

    if not rr.findings:
        print(_c("    ↳ no findings", "dim", use_color))
        return

    if verbose:
        # Group by category for readable output
        by_cat = defaultdict(list)
        for f in rr.findings:
            by_cat[f.category].append(f)
        for cat, items in sorted(by_cat.items()):
            print(f"    [{cat}]")
            for f in items:
                loc = f":{f.line_no}" if f.line_no else ""
                src = os.path.basename(f.file) if f.file != "[LLM analysis]" else f.file
                wt  = f"  weight {f.weight}" if f.weight else ""
                print(f"      - {f.description}{wt}")
                print(_c(f"        {src}{loc}: {f.snippet}", "dim", use_color))
    else:
        # Non-verbose: top 3 findings by weight (or first 3 for LLM rules)
        top = sorted(rr.findings, key=lambda f: -f.weight)[:3]
        for f in top:
            print(f"    ↳ {f.description}")
            if f.snippet:
                print(_c(f"      {f.snippet[:120]}", "dim", use_color))
        remaining = len(rr.findings) - len(top)
        if remaining > 0:
            print(_c(f"    ... +{remaining} more; use -v for full detail", "dim", use_color))


def _print_skill_report(name: str, result: ScanResult,
                         verbose: bool, use_color: bool, min_severity: str):
    """Print the full report for one skill unit."""
    if VERDICT_ORDER[result.verdict] < VERDICT_ORDER.get(min_severity, 0):
        return

    # Skill header
    header = f"{'─'*60}\n[{result.verdict}]  {name}"
    print(_c(header, result.verdict, use_color))
    print(f"  files scanned: {result.files_scanned}")
    print()

    # One block per rule
    for rr in result.rule_results:
        _print_rule_result(rr, verbose, use_color)
        print()


# ── JSON serialisation ─────────────────────────────────────────────────────

def _result_to_dict(name: str, result: ScanResult) -> dict:
    return {
        "skill": name,
        "verdict": result.verdict,
        "files_scanned": result.files_scanned,
        "rules": [
            {
                "rule_id":    rr.rule_id,
                "verdict":    rr.verdict,
                "score":      rr.score,
                "used_mock":  rr.used_mock,
                "confidence": rr.llm_confidence,
                "error":      rr.error,
                "findings": [
                    {
                        "file":        f.file,
                        "line":        f.line_no,
                        "rule_id":     f.rule_id,
                        "category":    f.category,
                        "weight":      f.weight,
                        "description": f.description,
                        "snippet":     f.snippet,
                    }
                    for f in rr.findings
                ],
            }
            for rr in result.rule_results
        ],
    }


# ── CLI entry point ────────────────────────────────────────────────────────

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="skill_scanner",
        description="Static + LLM-powered scanner for AI skill files. "
                     "Produces Benign / Suspicious / Malicious per rule and overall.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("path",
        help="Path to a single skill file or a directory of skills")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="Show every finding with file:line detail")
    parser.add_argument("--static-only", action="store_true",
        help="Run only Rule 1 (static patterns); skip the two LLM rules. "
             "Useful when you have no API key or want a fast offline scan.")
    parser.add_argument("--json", metavar="FILE",
        help="Write a full JSON report to FILE in addition to console output")
    parser.add_argument("--no-color", action="store_true",
        help="Disable ANSI colored output")
    parser.add_argument("--min-severity",
        choices=["benign", "suspicious", "malicious"], default="benign",
        help="Only print skills at or above this severity (default: show all)")
    parser.add_argument("--fail-on",
        choices=["suspicious", "malicious"], default=None,
        help="Exit with code 1 if any skill reaches this severity (for CI)")
    args = parser.parse_args(argv)

    use_color  = (not args.no_color) and sys.stdout.isatty()
    run_llm    = not args.static_only
    min_sev    = args.min_severity.capitalize()

    if not os.path.exists(args.path):
        print(f"error: path does not exist: {args.path}", file=sys.stderr)
        return 2

    units = _find_skill_units(args.path)

    mode_label = "static only" if args.static_only else "static + LLM (Rules 1-3)"
    print(_c(f"Scanning {len(units)} skill unit(s) — {mode_label}\n", "bold", use_color))

    json_report  = []
    worst_verdict = "Benign"
    exit_code    = 0
    fail_thresh  = VERDICT_ORDER.get(args.fail_on.capitalize()) if args.fail_on else None

    for unit in sorted(units):
        result = scan_path(unit, run_llm=run_llm)
        _print_skill_report(unit, result, args.verbose, use_color, min_sev)
        json_report.append(_result_to_dict(unit, result))

        if VERDICT_ORDER[result.verdict] > VERDICT_ORDER[worst_verdict]:
            worst_verdict = result.verdict
        if fail_thresh is not None and VERDICT_ORDER[result.verdict] >= fail_thresh:
            exit_code = 1

    print("─" * 60)
    print(_c(f"Overall verdict: {worst_verdict}", worst_verdict, use_color))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"overall_verdict": worst_verdict, "skills": json_report}, f, indent=2)
        print(f"\nJSON report → {args.json}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
