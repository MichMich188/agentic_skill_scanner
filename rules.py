"""
rules.py — Static pattern library for the MALICIOUS_INSTRUCTIONS rule.

This module owns the raw regex patterns that power Rule #1 (MALICIOUS_INSTRUCTIONS).
It no longer produces a verdict on its own — scanner.py calls run_malicious_instructions()
which wraps all these patterns into a single composite top-level rule result.

Architecture reminder (see scanner.py for the full picture):
  Rule 1 — MALICIOUS_INSTRUCTIONS  (this file, regex-based, fast)
  Rule 2 — CONSISTENCY_CHECK       (llm_rules.py, LLM-based)
  Rule 3 — DEPENDENCY_CHECK        (llm_rules.py, LLM-based)
"""

import re
import os
from dataclasses import dataclass, field
from typing import Pattern, List, Optional


# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------
# These are shared with scanner.py via import.  Tune them here to adjust
# how aggressively the static rule fires.
#
# CRITICAL_WEIGHT   — a single hit at this weight forces Malicious verdict.
# MALICIOUS_THRESHOLD — cumulative score needed for Malicious (no critical hit).
# SUSPICIOUS_THRESHOLD — cumulative score needed for Suspicious.
CRITICAL_WEIGHT      = 8
MALICIOUS_THRESHOLD  = 8
SUSPICIOUS_THRESHOLD = 4


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StaticRule:
    """
    One atomic regex pattern within the MALICIOUS_INSTRUCTIONS composite rule.

    frozen=True: these are built once at module load and never mutated.

    Fields:
      id          — short unique name, e.g. "RCE_OS_SYSTEM"
      category    — logical group shown in reports, e.g. "remote_execution"
      pattern     — compiled regex; applied line-by-line to file content
      weight      — how many risk points a single match adds to the score
      description — human-readable explanation shown in findings output
      md_exempt   — if True, this rule is SKIPPED for lines inside markdown
                    code fences (``` or ~~~).  Low-signal rules (weight <= 2)
                    are exempt because fenced blocks in SKILL.md are almost
                    always documentation examples, not live code.  Critical
                    rules are never exempt — a real attacker might hide a
                    payload inside a fence hoping we skip it.
    """
    id: str
    category: str
    pattern: Pattern
    weight: int
    description: str
    md_exempt: bool = False          # True => skip inside ``` / ~~~ fences in .md files


@dataclass
class PatternFinding:
    """
    A single regex match: one StaticRule fired on one line of one file.
    scanner.py translates these into the unified Finding dataclass.
    """
    file: str
    line_no: int
    rule_id: str
    category: str
    weight: int
    description: str
    snippet: str
    inside_fence: bool = False       # True if the match was inside a code fence
                                     # (only recorded, never suppressed, for critical rules)


def _r(pat: str, flags=re.IGNORECASE) -> Pattern:
    """Convenience wrapper: compile a pattern with IGNORECASE by default."""
    return re.compile(pat, flags)


# ---------------------------------------------------------------------------
# The static pattern library
# ---------------------------------------------------------------------------
# All of these feed into the MALICIOUS_INSTRUCTIONS composite rule.
# Grouped into 8 categories, roughly ordered severity-high-to-low within
# each group.  md_exempt=True on rules whose weight <= 2 (they're too noisy
# when applied to documentation code examples in .md files).
STATIC_RULES: List[StaticRule] = [

    # ===================================================================
    # 1. REMOTE_EXECUTION
    #    Code that runs commands or arbitrary code dynamically, especially
    #    from an untrusted source (network, decoded data, user input).
    # ===================================================================
    StaticRule("RCE_CURL_PIPE_SHELL", "remote_execution",
        _r(r"(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh|python[0-9.]*)"),
        CRITICAL_WEIGHT,
        "Downloads a remote script and pipes it directly into a shell/interpreter"),

    StaticRule("RCE_DYNAMIC_EVAL", "remote_execution",
        _r(r"\b(eval|exec)\s*\(\s*(base64|requests\.get|urllib|open\(|input\(|compile\()"),
        CRITICAL_WEIGHT,
        "Evaluates/executes code built from network input, decoded data, or user input"),

    StaticRule("RCE_SUBPROCESS_SHELL_TRUE", "remote_execution",
        _r(r"subprocess\.(run|call|Popen|check_output)\([^)]*shell\s*=\s*True"),
        5,
        "Runs a subprocess with shell=True (higher injection risk)"),

    StaticRule("RCE_OS_SYSTEM", "remote_execution",
        _r(r"\bos\.system\s*\("),
        3,
        "Uses os.system to execute shell commands"),

    # ===================================================================
    # 2. OBFUSCATION
    #    Code that hides what it is actually doing.  Legitimate skills
    #    rarely need to conceal their logic.
    # ===================================================================
    StaticRule("OBF_BASE64_EXEC", "obfuscation",
        _r(r"(base64\.b64decode|atob\()[^\n]{0,80}(exec|eval|Function\()"),
        CRITICAL_WEIGHT,
        "Decodes a base64 blob and immediately executes it"),

    StaticRule("OBF_LONG_B64_BLOB", "obfuscation",
        _r(r"[A-Za-z0-9+/]{200,}={0,2}"),
        3,
        "Contains a very long base64-like blob, often used to hide payloads"),

    StaticRule("OBF_CHAR_CODE_BUILD", "obfuscation",
        _r(r"(chr\(\d+\)\s*\+\s*){5,}|String\.fromCharCode\([\d,\s]{20,}\)"),
        4,
        "Builds a string character-by-character, a common obfuscation technique"),

    StaticRule("OBF_HEX_ESCAPES", "obfuscation",
        _r(r"(\\x[0-9a-f]{2}){10,}", flags=re.IGNORECASE),
        3,
        "Contains a long run of hex-escaped characters"),

    # ===================================================================
    # 3. EXFILTRATION
    #    Sending data (especially secrets) somewhere it should not go.
    #    Rules here look for the network call AND suspicious payload/dest.
    # ===================================================================
    StaticRule("EXFIL_ENV_TO_NETWORK", "exfiltration",
        _r(r"(requests\.(post|get)|fetch\(|urlopen\()[^\n]{0,120}(os\.environ|process\.env|getenv)"),
        CRITICAL_WEIGHT,
        "Sends environment variables (secrets/API keys) over the network"),

    StaticRule("EXFIL_RAW_IP_URL", "exfiltration",
        _r(r"https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?"),
        4,
        "Contacts a hardcoded raw IP address rather than a named domain"),

    StaticRule("EXFIL_WEBHOOK_DISCORD_TELEGRAM", "exfiltration",
        _r(r"(discord(app)?\.com/api/webhooks|api\.telegram\.org/bot)"),
        5,
        "Sends data to a Discord/Telegram webhook, a common exfiltration channel"),

    StaticRule("EXFIL_PASTEBIN_TRANSFER", "exfiltration",
        _r(r"(pastebin\.com/raw|transfer\.sh|0x0\.st|file\.io)\b"),
        4,
        "References anonymous file/paste-sharing services used to move stolen data"),

    # ===================================================================
    # 4. NETWORKING  (low-weight, informational)
    #    Catch-all: "this makes ANY outbound network call."
    #    md_exempt=True because documentation examples almost always show
    #    a requests.get() call — we do not want to flag mcp-builder for
    #    teaching developers how to make HTTP calls.
    # ===================================================================
    StaticRule("NET_GENERIC_REQUEST", "networking",
        _r(r"\b(requests\.(get|post)|urllib\.request|fetch\(|axios\.|http\.request)\b"),
        1,
        "Makes an outbound network request",
        md_exempt=True),             # <-- skip inside markdown code fences

    # ===================================================================
    # 5. CREDENTIAL_THEFT
    #    Reading files or API stores that hold secrets.
    # ===================================================================
    StaticRule("CRED_SSH_KEYS", "credential_theft",
        _r(r"\.ssh/(id_rsa|id_ed25519|authorized_keys|known_hosts)"),
        CRITICAL_WEIGHT,
        "Accesses SSH private key material"),

    StaticRule("CRED_CLOUD_CREDENTIALS", "credential_theft",
        _r(r"\.aws/credentials|\.config/gcloud|\.azure/credentials|credentials\.json"),
        CRITICAL_WEIGHT,
        "Accesses cloud provider credential files"),

    StaticRule("CRED_BROWSER_STORE", "credential_theft",
        _r(r"(Login Data|Cookies)['\"]?\s*\)|Chrome/User Data|Firefox/Profiles"),
        6,
        "Accesses browser credential/cookie storage"),

    StaticRule("CRED_ENV_FILE_READ", "credential_theft",
        _r(r"open\(['\"]\.env['\"]|dotenv\.load|read.*\.env['\"]\)"),
        2,
        "Reads a local .env file (may be legitimate config loading)",
        md_exempt=True),

    StaticRule("CRED_HARDCODED_SECRET", "credential_theft",
        _r(r"(api[_-]?key|secret|token|password)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
        3,
        "Contains what looks like a hardcoded secret/API key"),

    # ===================================================================
    # 6. FILESYSTEM
    #    Destructive actions or persistence mechanisms (survive reboot /
    #    run automatically in the future without user consent).
    # ===================================================================
    StaticRule("FS_BROAD_DELETE", "filesystem",
        _r(r"(rm\s+-rf\s+/(?!\S)|shutil\.rmtree\(['\"]/['\"]\)|rm\s+-rf\s+~)"),
        CRITICAL_WEIGHT,
        "Recursively deletes broad filesystem locations (root or home)"),

    StaticRule("FS_PERSISTENCE_CRON", "filesystem",
        _r(r"(crontab\s+-e|/etc/cron|systemctl enable|~/\.bashrc|~/\.zshrc|LaunchAgents)"),
        5,
        "Modifies startup/persistence mechanisms (cron, shell rc files, launch agents)"),

    StaticRule("FS_WRITE_OUTSIDE_SCOPE", "filesystem",
        _r(r"open\(['\"]/(etc|usr|bin|System|Windows)/"),
        5,
        "Writes to sensitive system directories outside the skill's own scope"),

    # ===================================================================
    # 7. PROMPT_INJECTION
    #    Text in SKILL.md aimed at manipulating the AI assistant itself,
    #    rather than at the machine the skill runs on.  Unique to AI skill
    #    scanning vs. traditional malware analysis.
    # ===================================================================
    StaticRule("INJECT_IGNORE_INSTRUCTIONS", "prompt_injection",
        _r(r"ignore (all )?(previous|prior|above) instructions"),
        CRITICAL_WEIGHT,
        "Attempts to override the assistant's prior instructions"),

    StaticRule("INJECT_SYSTEM_OVERRIDE", "prompt_injection",
        _r(r"(you are now|act as|pretend to be) (DAN|unrestricted|jailbroken|an? AI with no (rules|restrictions))"),
        CRITICAL_WEIGHT,
        "Attempts a jailbreak-style persona override"),

    StaticRule("INJECT_HIDE_FROM_USER", "prompt_injection",
        _r(r"(do not|don't) (tell|inform|let) the user|without (telling|informing) the user|secretly (send|exfiltrate|upload)"),
        7,
        "Instructs the assistant to hide actions from the user"),

    StaticRule("INJECT_DISABLE_SAFETY", "prompt_injection",
        _r(r"(disable|bypass|turn off|ignore) (safety|content) (filters?|guidelines?|policy)"),
        7,
        "Attempts to get the assistant to disable safety behavior"),

    StaticRule("INJECT_EXFIL_VIA_TOOL_CALL", "prompt_injection",
        _r(r"(send|post|upload) (this|the) (conversation|chat history|api key|credentials?) to https?://"),
        CRITICAL_WEIGHT,
        "Instructs the assistant to exfiltrate conversation/credential data to a URL"),

    # ===================================================================
    # 8. SUSPICIOUS_BEHAVIOR
    #    Lower-confidence signals: surveillance APIs, self-replication.
    #    Individually weak — useful when they stack with other categories.
    # ===================================================================
    StaticRule("SUS_KEYLOGGER", "suspicious_behavior",
        _r(r"(pynput\.keyboard|GetAsyncKeyState|keylogger)"),
        6,
        "Contains keylogging-related APIs or terminology"),

    StaticRule("SUS_SCREEN_CAPTURE", "suspicious_behavior",
        _r(r"(pyautogui\.screenshot|ImageGrab\.grab|mss\.mss\()"),
        3,
        "Captures screen content, which could be used for surveillance"),

    StaticRule("SUS_CLIPBOARD_ACCESS", "suspicious_behavior",
        _r(r"(pyperclip\.paste|navigator\.clipboard\.readText)"),
        2,
        "Reads clipboard contents",
        md_exempt=True),

    StaticRule("SUS_SELF_MODIFY", "suspicious_behavior",
        _r(r"open\(__file__|open\(sys\.argv\[0\]"),
        5,
        "Skill script reads/modifies its own source (possible self-replication)"),

    StaticRule("SUS_WIDE_PERMISSIONS_CLAIM", "suspicious_behavior",
        _r(r"(requires?|needs?) (full|root|admin(istrator)?) access"),
        2,
        "Explicitly requests broad/root-level access",
        md_exempt=True),
]


# ---------------------------------------------------------------------------
# Markdown fence tracker
# ---------------------------------------------------------------------------
# A markdown file alternates between "prose" and "code fence" regions.
# Fences start and end with ``` or ~~~  (optionally followed by a lang tag).
# We track this as simple boolean state while iterating lines.

_FENCE_OPEN = re.compile(r"^\s*(```|~~~)")

def is_fence_toggle(line: str) -> bool:
    """True if this line opens or closes a markdown code fence."""
    return bool(_FENCE_OPEN.match(line))


# ---------------------------------------------------------------------------
# Core scanning function (used by scanner.py)
# ---------------------------------------------------------------------------

def scan_file_for_patterns(path: str, text: str) -> List[PatternFinding]:
    """
    Run all STATIC_RULES against `text` (already read by scanner.py) and
    return a flat list of PatternFinding objects.

    Markdown fence awareness:
      - We track whether the current line is inside a ``` / ~~~ fence.
      - Rules with md_exempt=True are skipped for fenced lines in .md files.
        This prevents documentation examples from being flagged as malicious.
      - Critical rules (weight >= CRITICAL_WEIGHT) always fire, even inside
        fences — an attacker might try to hide a payload there deliberately.

    Args:
        path: file path (used to detect .md extension and set finding.file)
        text: full file content as a string (caller handles reading)
    """
    findings: List[PatternFinding] = []
    is_markdown = path.lower().endswith(".md")
    lines = text.splitlines()

    inside_fence = False  # fence state: toggled each time we hit ``` or ~~~

    for i, line in enumerate(lines, start=1):

        # Update fence state BEFORE scanning this line.
        # A fence-opener line itself is part of the fence region.
        if is_markdown and is_fence_toggle(line):
            inside_fence = not inside_fence

        for rule in STATIC_RULES:
            # Fence exemption: skip low-signal rules when inside a code fence
            # in a markdown file.  This is the fix for the mcp-builder false
            # positive where NET_GENERIC_REQUEST fired on documentation examples.
            if inside_fence and is_markdown and rule.md_exempt:
                continue

            if rule.pattern.search(line):
                snippet = line.strip()
                if len(snippet) > 140:
                    snippet = snippet[:140] + "..."
                findings.append(PatternFinding(
                    file=path,
                    line_no=i,
                    rule_id=rule.id,
                    category=rule.category,
                    weight=rule.weight,
                    description=rule.description,
                    snippet=snippet,
                    inside_fence=inside_fence,
                ))

    return findings
