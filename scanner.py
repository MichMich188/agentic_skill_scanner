"""
scanner.py — Orchestration engine for the three top-level scanner rules.

The scanner has exactly three rules, run in order for every skill unit:

  ┌─────────────────────────────────────────────────────────────────────┐
  │  Rule 1 — MALICIOUS_INSTRUCTIONS                                    │
  │  Static regex patterns across 8 categories (all of rules.py).      │
  │  Fast. No network call. Runs on every file in the skill.            │
  │                                                                     │
  │  Rule 2 — CONSISTENCY_CHECK                                         │
  │  LLM compares SKILL.md declared intent vs. what the code does.     │
  │  Catches trojan skills that look benign from the description.       │
  │                                                                     │
  │  Rule 3 — DEPENDENCY_CHECK                                          │
  │  LLM audits every URL, import, and download target in the skill.   │
  │  Catches supply-chain attacks via malicious dependencies.           │
  └─────────────────────────────────────────────────────────────────────┘

Each rule independently produces: Benign / Suspicious / Malicious.
The skill's overall verdict is the worst of the three.

Public entry point:
    scan_path(path, run_llm=True) -> ScanResult
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

from rules import (
    STATIC_RULES,
    CRITICAL_WEIGHT,
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    scan_file_for_patterns,
    PatternFinding,
)
from llm_rules import LLMRuleResult, run_consistency_check, run_dependency_check


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Extensions we read as text and pass through rules.
SCANNABLE_EXTENSIONS = {".md", ".py", ".js", ".ts", ".sh", ".bash", ".ps1",
                         ".json", ".yaml", ".yml", ".txt"}

# Extensions we consider "instructions / declarations" (SKILL.md-like).
# These feed Rule 2's `instructions` argument.
INSTRUCTION_EXTENSIONS = {".md", ".txt"}

# Files bigger than this are almost certainly not hand-written skill source.
MAX_FILE_BYTES = 2_000_000


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    A single matched finding from ANY rule.  The three top-level rules all
    produce findings in this shape so the reporter never needs to know which
    rule type produced a given finding.
    """
    file: str           # which file triggered this finding
    line_no: int         # 1-indexed line number (0 for LLM-level findings)
    rule_id: str          # e.g. "RCE_OS_SYSTEM", "CONSISTENCY_CHECK"
    category: str          # e.g. "remote_execution", "llm_consistency"
    weight: int             # contribution to Rule 1 score; 0 for LLM rules
    description: str         # human-readable explanation
    snippet: str              # relevant text excerpt (code line or LLM reason)


@dataclass
class RuleResult:
    """
    The outcome of ONE of the three top-level rules for a given skill.
    Contains the rule's own verdict and all the findings it produced.
    """
    rule_id: str                          # "MALICIOUS_INSTRUCTIONS" | "CONSISTENCY_CHECK" | "DEPENDENCY_CHECK"
    verdict: str          = "Benign"       # "Benign" | "Suspicious" | "Malicious"
    score: int            = 0              # numeric risk score (Rule 1 only; 0 for LLM rules)
    findings: List[Finding] = field(default_factory=list)
    used_mock: bool       = False          # True if LLM rule fell back to mock agent
    llm_confidence: str   = ""            # "low" | "medium" | "high" (LLM rules only)
    error: Optional[str]  = None          # error message if something went wrong


@dataclass
class ScanResult:
    """
    The full result for one skill unit (a single file or a skill directory).

    rule_results holds one RuleResult per top-level rule (up to 3 entries).
    verdict is the worst verdict across all three rules.
    """
    root: str
    verdict: str                    = "Benign"
    files_scanned: int              = 0
    rule_results: List[RuleResult]  = field(default_factory=list)

    @property
    def all_findings(self) -> List[Finding]:
        """Flat list of every finding across all three rules."""
        out = []
        for rr in self.rule_results:
            out.extend(rr.findings)
        return out


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def _is_scannable(path: str) -> bool:
    _, ext = os.path.splitext(path)
    return ext.lower() in SCANNABLE_EXTENSIONS


def _read_text(path: str) -> str:
    """
    Safely read a file as text.  Returns "" on any failure so callers never
    have to handle OSError / UnicodeDecodeError themselves.
    """
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return ""
    except OSError:
        return ""
    for encoding in ("utf-8", "latin-1"):
        try:
            with open(path, "r", encoding=encoding, errors="ignore") as f:
                return f.read()
        except (OSError, UnicodeDecodeError):
            continue
    return ""


def _collect_files(path: str) -> List[str]:
    """
    Return all scannable files under `path`.
    If `path` is a file, return [path].
    If `path` is a directory, walk it recursively skipping noise dirs.
    """
    files = []
    if os.path.isfile(path):
        files.append(path)
    else:
        for dirpath, dirnames, filenames in os.walk(path):
            dirnames[:] = [d for d in dirnames if d not in
                           (".git", "node_modules", "__pycache__", ".venv", "venv")]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if _is_scannable(full):
                    files.append(full)
    return files


def _split_content(files: List[str]):
    """
    Given a list of file paths, return two strings:
      instructions — concatenated text of .md / .txt files (SKILL.md etc.)
      code         — concatenated text of all other script files
    Also returns all_content (instructions + code) for Rule 3.
    """
    instructions_parts = []
    code_parts = []
    for path in files:
        text = _read_text(path)
        if not text:
            continue
        _, ext = os.path.splitext(path)
        header = f"\n\n=== {path} ===\n"
        if ext.lower() in INSTRUCTION_EXTENSIONS:
            instructions_parts.append(header + text)
        else:
            code_parts.append(header + text)
    instructions = "\n".join(instructions_parts)
    code = "\n".join(code_parts)
    all_content = instructions + "\n\n" + code
    return instructions, code, all_content


# ---------------------------------------------------------------------------
# Rule 1 — MALICIOUS_INSTRUCTIONS
# ---------------------------------------------------------------------------

def _verdict_from_score(score: int, has_critical: bool) -> str:
    """
    Convert a numeric risk score into a verdict label.

    A single critical hit (weight >= CRITICAL_WEIGHT) is enough to force
    Malicious, even if the total score would only be Suspicious.  This
    prevents dilution: one genuinely critical pattern should not be washed
    out by a sea of zero-weight clean lines.
    """
    if has_critical or score >= MALICIOUS_THRESHOLD:
        return "Malicious"
    if score >= SUSPICIOUS_THRESHOLD:
        return "Suspicious"
    return "Benign"


def run_malicious_instructions(files: List[str]) -> RuleResult:
    """
    Rule 1: Run all static regex patterns (from rules.py) across every file
    and aggregate into a single MALICIOUS_INSTRUCTIONS verdict.

    Steps:
      1. For each file, call scan_file_for_patterns() which handles the
         markdown fence awareness logic.
      2. Translate raw PatternFindings into the unified Finding type.
      3. Sum weights, check for any critical hit, derive verdict.
    """
    result = RuleResult(rule_id="MALICIOUS_INSTRUCTIONS")
    all_pattern_findings: List[PatternFinding] = []

    for path in files:
        text = _read_text(path)
        if not text:
            continue
        pf_list = scan_file_for_patterns(path, text)
        all_pattern_findings.extend(pf_list)

    # Translate PatternFindings -> Findings
    for pf in all_pattern_findings:
        result.findings.append(Finding(
            file=pf.file,
            line_no=pf.line_no,
            rule_id=pf.rule_id,
            category=pf.category,
            weight=pf.weight,
            description=pf.description,
            snippet=pf.snippet,
        ))

    result.score = sum(f.weight for f in result.findings)
    has_critical = any(f.weight >= CRITICAL_WEIGHT for f in result.findings)
    result.verdict = _verdict_from_score(result.score, has_critical)
    return result


# ---------------------------------------------------------------------------
# Rule 2 — CONSISTENCY_CHECK (LLM)
# ---------------------------------------------------------------------------

def run_consistency_rule(instructions: str, code: str) -> RuleResult:
    """
    Rule 2: Ask the LLM whether the implementation matches the declared intent.

    If instructions or code are both empty, skip gracefully (returns Benign).
    The LLM result is converted into one Finding so it appears in all reports.
    """
    result = RuleResult(rule_id="CONSISTENCY_CHECK")

    if not instructions.strip() and not code.strip():
        # Nothing to compare — treat as Benign (no content = no mismatch)
        result.verdict = "Benign"
        return result

    llm_result: LLMRuleResult = run_consistency_check(instructions, code)

    result.verdict = llm_result.verdict
    result.used_mock = llm_result.used_mock
    result.llm_confidence = llm_result.confidence
    result.error = llm_result.error

    # Represent the LLM's judgment as a single Finding so the reporter can
    # display it uniformly alongside Rule 1's pattern findings.
    result.findings.append(Finding(
        file="[LLM analysis]",
        line_no=0,
        rule_id="CONSISTENCY_CHECK",
        category="llm_consistency",
        weight=0,              # LLM rules don't contribute to Rule 1's numeric score
        description="LLM consistency analysis: declared intent vs. implementation",
        snippet=llm_result.reason[:300],
    ))

    # If the LLM flagged specific discrepancies, add one Finding per item
    # so they each appear as a separate line in verbose output.
    for disc in llm_result.details.get("discrepancies", []):
        result.findings.append(Finding(
            file="[LLM analysis]",
            line_no=0,
            rule_id="CONSISTENCY_DISCREPANCY",
            category="llm_consistency",
            weight=0,
            description="Discrepancy identified by LLM",
            snippet=str(disc)[:300],
        ))

    return result


# ---------------------------------------------------------------------------
# Rule 3 — DEPENDENCY_CHECK (LLM)
# ---------------------------------------------------------------------------

def run_dependency_rule(all_content: str) -> RuleResult:
    """
    Rule 3: Ask the LLM to evaluate every URL, import, and download target.

    all_content should be the full concatenated text of SKILL.md + all scripts,
    so the LLM has context for whether a dependency makes sense for this skill.
    """
    result = RuleResult(rule_id="DEPENDENCY_CHECK")

    if not all_content.strip():
        result.verdict = "Benign"
        return result

    llm_result: LLMRuleResult = run_dependency_check(all_content)

    result.verdict = llm_result.verdict
    result.used_mock = llm_result.used_mock
    result.llm_confidence = llm_result.confidence
    result.error = llm_result.error

    # Summary finding
    result.findings.append(Finding(
        file="[LLM analysis]",
        line_no=0,
        rule_id="DEPENDENCY_CHECK",
        category="llm_dependency",
        weight=0,
        description="LLM dependency audit: URLs, imports, and download targets",
        snippet=llm_result.reason[:300],
    ))

    # One Finding per suspicious item identified by the LLM
    for item in llm_result.details.get("suspicious_items", []):
        result.findings.append(Finding(
            file="[LLM analysis]",
            line_no=0,
            rule_id="DEPENDENCY_SUSPICIOUS_ITEM",
            category="llm_dependency",
            weight=0,
            description=f"Suspicious dependency: {item.get('item', '?')}",
            snippet=item.get("reason", "")[:300],
        ))

    return result


# ---------------------------------------------------------------------------
# Verdict combiner
# ---------------------------------------------------------------------------

_VERDICT_RANK = {"Benign": 0, "Suspicious": 1, "Malicious": 2}

def _worst_verdict(*verdicts: str) -> str:
    """Return the most severe verdict from a set of per-rule verdicts."""
    return max(verdicts, key=lambda v: _VERDICT_RANK.get(v, 0))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan_path(path: str, run_llm: bool = True) -> ScanResult:
    """
    Scan a single file or skill directory and return a ScanResult.

    Args:
        path    — file or directory to scan
        run_llm — if False, skip Rules 2 and 3 (useful for fast offline mode
                  or to avoid API costs when you just want static analysis)

    Flow:
        1. Collect all scannable files under `path`
        2. Run Rule 1 (static) on all files
        3. Split content into instructions vs. code
        4. Run Rule 2 (LLM consistency) on instructions + code
        5. Run Rule 3 (LLM dependency) on all content
        6. Overall verdict = worst of the three rule verdicts
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"No such file or directory: {path}")

    files = _collect_files(path)
    result = ScanResult(root=path, files_scanned=len(files))

    # ── Rule 1: static patterns ────────────────────────────────────────────
    r1 = run_malicious_instructions(files)
    result.rule_results.append(r1)

    if run_llm:
        # Split file content so LLM rules get the right context
        instructions, code, all_content = _split_content(files)

        # ── Rule 2: LLM consistency check ─────────────────────────────────
        r2 = run_consistency_rule(instructions, code)
        result.rule_results.append(r2)

        # ── Rule 3: LLM dependency check ──────────────────────────────────
        r3 = run_dependency_rule(all_content)
        result.rule_results.append(r3)

        result.verdict = _worst_verdict(r1.verdict, r2.verdict, r3.verdict)
    else:
        # Static-only mode: only Rule 1 contributes
        result.verdict = r1.verdict

    return result
