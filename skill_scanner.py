#!/usr/bin/env python3
"""
Skill Scanner — analyzes AI skill files for malicious behavior.

For each skill, reports: verdict (Benign / Suspicious / Malicious) and
a plain-English explanation. Nothing else shown by default.

Usage:
    python skill_scanner.py <path>
    python skill_scanner.py <path> -v              # add per-finding detail
    python skill_scanner.py <path> --static-only   # skip LLM checks (faster)
    python skill_scanner.py <path> --json out.json
    python skill_scanner.py <path> --fail-on malicious
"""

import argparse
import json
import os
import sys

from scanner import scan_path, ScanResult, RuleResult

VERDICT_ORDER = {"Benign": 0, "Suspicious": 1, "Malicious": 2}

COLORS = {
    "Benign":     "\033[32m",
    "Suspicious": "\033[33m",
    "Malicious":  "\033[31m",
    "reset":      "\033[0m",
    "bold":       "\033[1m",
    "dim":        "\033[2m",
}

def _c(text, key, use_color):
    if not use_color:
        return text
    return f"{COLORS.get(key, '')}{text}{COLORS['reset']}"


# ── Skill-unit discovery ───────────────────────────────────────────────────

def _find_skill_units(root: str):
    """
    Identify skill units to scan.

    A "skill unit" is any of:
      - A single file passed directly (any extension, any name)
      - A directory containing SKILL.md or any other .md file at the top level
      - A directory anywhere in the tree that contains a .md file

    """
    if os.path.isfile(root):
        return [root] if root.lower().endswith(".md") else []

    units = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in (".git", "node_modules", "__pycache__", ".venv", "venv")
        ]

        for filename in filenames:
            if filename.lower().endswith(".md"):
                units.append(os.path.join(dirpath, filename))

    return units

# ── Reasoning synthesiser ─────────────────────────────────────────────────

def _build_reasoning(result: ScanResult, verbose: bool) -> list[str]:
    """
    Collapse all rule findings into a flat list of human-readable reason
    strings.  The internal rule names never appear in output.
    """
    lines = []

    for rr in result.rule_results:
        if rr.verdict == "Benign" and not verbose:
            continue   # suppress clean rules in default mode

        if rr.rule_id == "MALICIOUS_INSTRUCTIONS":
            # Group static findings by category, emit one line per category
            from collections import defaultdict
            by_cat = defaultdict(list)
            for f in rr.findings:
                by_cat[f.category].append(f)

            cat_labels = {
                "remote_execution":   "Executes remote or dynamic code",
                "obfuscation":        "Uses code obfuscation",
                "exfiltration":       "Attempts data exfiltration",
                "networking":         "Makes outbound network requests",
                "credential_theft":   "Accesses credentials or secrets",
                "filesystem":         "Modifies sensitive filesystem locations",
                "prompt_injection":   "Contains prompt injection instructions",
                "suspicious_behavior":"Shows suspicious behavioral patterns",
            }
            for cat, findings in sorted(by_cat.items()):
                label = cat_labels.get(cat, cat)
                if verbose:
                    for f in findings:
                        loc = f":{f.line_no}" if f.line_no else ""
                        src = os.path.basename(f.file)
                        lines.append(f"• {label} — {f.description} ({src}{loc})")
                else:
                    # Non-verbose: one line per category with count
                    n = len(findings)
                    lines.append(f"• {label} ({n} indicator{'s' if n > 1 else ''})")

        else:
            # LLM rules: emit the LLM's own reason text.
            # Each rule produces one summary Finding (CONSISTENCY_CHECK /
            # DEPENDENCY_CHECK) plus optional detail Findings.  We deduplicate
            # the summary text so the same reason isn't printed twice when both
            # rules fire the same backend result.
            seen_rule_ids: set = set()
            for f in rr.findings:
                if f.rule_id in ("CONSISTENCY_CHECK", "DEPENDENCY_CHECK") and f.snippet:
                    # One summary line per rule_id — prevents the same rule
                    # from printing twice if findings are duplicated.
                    if f.rule_id not in seen_rule_ids:
                        seen_rule_ids.add(f.rule_id)
                        lines.append(f"• {f.snippet.rstrip('.')}")
                elif f.rule_id in ("CONSISTENCY_DISCREPANCY", "DEPENDENCY_SUSPICIOUS_ITEM", "INJECTION_ITEM") and verbose:
                    lines.append(f"  ↳ {f.snippet}")

    return lines


# ── Report printer ─────────────────────────────────────────────────────────

def _print_skill_report(name: str, result: ScanResult,
                         verbose: bool, use_color: bool, min_severity: str):
    if VERDICT_ORDER[result.verdict] < VERDICT_ORDER.get(min_severity, 0):
        return

    # ── Header: skill name + verdict badge ────────────────────────────────
    short_name = os.path.basename(name.rstrip("/")) or name
    verdict_badge = _c(f" {result.verdict.upper()} ", result.verdict, use_color)
    print(f"\n{_c('─'*60, 'dim', use_color)}")
    print(f"{_c(short_name, 'bold', use_color)}  [{verdict_badge}]")

    # ── LLM backend note (only when not mock) ─────────────────────────────
    backends = {rr.llm_backend for rr in result.rule_results
                if rr.llm_backend and rr.llm_backend != "mock" and not rr.used_mock}
    if backends:
        print(_c(f"  analyzed via {', '.join(sorted(backends))}", "dim", use_color))

    # ── Reasoning lines ───────────────────────────────────────────────────
    reasons = _build_reasoning(result, verbose)
    if reasons:
        for r in reasons:
            print(f"  {r}")
    else:
        print(_c("  No issues detected.", "dim", use_color))

    # ── Mock warning ──────────────────────────────────────────────────────
    mock_rules = [rr for rr in result.rule_results if rr.used_mock]
    if mock_rules:
        print(_c("  ⚠  LLM checks ran in mock mode — configure Ollama or OpenAI for full analysis.", "dim", use_color))


# ── JSON serialisation ─────────────────────────────────────────────────────

def _result_to_dict(name: str, result: ScanResult) -> dict:
    return {
        "skill":   name,
        "verdict": result.verdict,
        "files_scanned": result.files_scanned,
        "rules": [
            {
                "rule_id":    rr.rule_id,
                "verdict":    rr.verdict,
                "score":      rr.score,
                "llm_backend": rr.llm_backend,
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


# ── Entry point ────────────────────────────────────────────────────────────

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="skill_scanner",
        description="Scan AI skill files for malicious behavior.",
    )
    parser.add_argument("path",
        help="Skill file or directory to scan")
    parser.add_argument("-v", "--verbose", action="store_true",
        help="Show per-finding detail alongside the reasoning")
    parser.add_argument("--static-only", action="store_true",
        help="Skip LLM checks (faster, offline-safe)")
    parser.add_argument("--json", metavar="FILE",
        help="Write full JSON report to FILE")
    parser.add_argument("--no-color", action="store_true",
        help="Disable colored output")
    parser.add_argument("--min-severity",
        choices=["benign", "suspicious", "malicious"], default="benign",
        help="Only show results at or above this severity")
    parser.add_argument("--fail-on",
        choices=["suspicious", "malicious"], default=None,
        help="Exit with code 1 if any skill reaches this severity (CI use)")
    args = parser.parse_args(argv)

    use_color = (not args.no_color) and sys.stdout.isatty()
    run_llm   = not args.static_only
    min_sev   = args.min_severity.capitalize()

    if not os.path.exists(args.path):
        print(f"error: path does not exist: {args.path}", file=sys.stderr)
        return 2

    units = _find_skill_units(args.path)
    json_report   = []
    worst_verdict = "Benign"
    exit_code     = 0
    fail_thresh   = VERDICT_ORDER.get(args.fail_on.capitalize()) if args.fail_on else None

    for unit in sorted(units):
        result = scan_path(unit, run_llm=run_llm)
        _print_skill_report(unit, result, args.verbose, use_color, min_sev)
        json_report.append(_result_to_dict(unit, result))

        if VERDICT_ORDER[result.verdict] > VERDICT_ORDER[worst_verdict]:
            worst_verdict = result.verdict
        if fail_thresh is not None and VERDICT_ORDER[result.verdict] >= fail_thresh:
            exit_code = 1

    # ── Summary footer ─────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(_c(f"Overall: {worst_verdict}", worst_verdict, use_color))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"overall_verdict": worst_verdict, "skills": json_report}, f, indent=2)
        print(f"JSON report → {args.json}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
