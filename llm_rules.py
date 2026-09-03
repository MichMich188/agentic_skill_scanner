"""
llm_rules.py — LLM-powered rules for the Skill Scanner.

This module implements Rules 2 and 3 of the three top-level scanner rules:

  Rule 2 — CONSISTENCY_CHECK
    Compares what SKILL.md *says* the skill does vs. what the code
    *actually* does.  A gap between declared intent and implementation
    is a strong indicator of a trojan skill (e.g. "Analyze files" in
    the description but collect_credentials() in the script).

  Rule 3 — DEPENDENCY_CHECK
    Examines every URL, import, and download target in the skill's code
    and asks whether they are legitimate: official domains, reasonable
    file paths, plausible context.  Catches supply-chain-style attacks
    where the skill itself looks fine but silently fetches a malicious
    dependency.

Both rules call an LLM (OpenAI GPT-4o by default) and parse the JSON
response into a structured verdict.  If the LLM call fails for any
reason — no API key, network error, quota exceeded — we fall back to a
MockAgent that returns deterministic placeholder output so the rest of
the scanner pipeline keeps running.

The LLM response schema is strict JSON, described in each prompt.
We strip markdown code fences before parsing in case the model wraps
the JSON in ```json ... ```.
"""

import json
import os
import re
import textwrap
import traceback
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration — set your key here or via the OPENAI_API_KEY env variable
# ---------------------------------------------------------------------------
OPENAI_API_KEY: Optional[str] = os.environ.get("OPENAI_API_KEY", "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")
OPENAI_MODEL   = "gpt-4o"
OPENAI_TIMEOUT = 30          # seconds per LLM call
MAX_CONTEXT_CHARS = 12_000   # trim skill content to this before sending to LLM
                              # (keeps cost low and avoids hitting context limits)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class LLMRuleResult:
    """
    The structured output of one LLM-based rule evaluation.

    Fields:
      rule_id        — "CONSISTENCY_CHECK" or "DEPENDENCY_CHECK"
      verdict        — "Benign", "Suspicious", or "Malicious"
      confidence     — "low", "medium", or "high" (from LLM self-assessment)
      reason         — short paragraph explaining the verdict
      details        — raw parsed JSON from the LLM (for verbose output)
      used_mock      — True if we fell back to the mock agent (LLM unavailable)
      error          — error message if something went wrong, else None
    """
    rule_id: str
    verdict: str           = "Benign"
    confidence: str        = "low"
    reason: str            = ""
    details: dict          = field(default_factory=dict)
    used_mock: bool        = False
    error: Optional[str]   = None


# ---------------------------------------------------------------------------
# LLM client
# ---------------------------------------------------------------------------

def _call_openai(system_prompt: str, user_prompt: str) -> str:
    """
    Send a chat completion request to OpenAI and return the raw text response.

    Raises an exception on any failure (network, auth, quota, etc.) so the
    caller can catch it and fall back to the mock agent.

    We import `urllib` rather than `requests` to keep the scanner dependency-
    free (no pip install needed).
    """
    import urllib.request
    import urllib.error

    payload = json.dumps({
        "model": OPENAI_MODEL,
        "temperature": 0,          # deterministic output — we want consistent verdicts
        "response_format": {"type": "json_object"},   # enforces JSON output mode
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=OPENAI_TIMEOUT) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    return body["choices"][0]["message"]["content"]


def _parse_llm_json(raw: str) -> dict:
    """
    Parse the LLM's response as JSON.

    Models sometimes wrap JSON in ```json ... ``` even when asked not to,
    so we strip fences before parsing.  Returns an empty dict on failure.
    """
    # Strip optional ```json ... ``` wrappers
    clean = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.IGNORECASE)
    clean = re.sub(r"\s*```$", "", clean)
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        return {}


def _trim(text: str, max_chars: int = MAX_CONTEXT_CHARS) -> str:
    """
    Trim a long string to at most `max_chars` characters, adding a notice
    so the LLM knows the content was truncated rather than complete.
    """
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n\n[... TRUNCATED at {max_chars} chars for analysis ...]"


# ---------------------------------------------------------------------------
# Mock agent (fallback when LLM is unavailable)
# ---------------------------------------------------------------------------

class MockAgent:
    """
    A deterministic stand-in for the real LLM.

    Returns fixed but plausible JSON so the scanner pipeline always
    produces complete output even without an API key or network access.
    The mock is clearly labeled in the result (used_mock=True) so you
    know not to treat its verdicts as authoritative.

    Design note: the mock always returns "Benign" with low confidence so
    it never generates false alarms.  Its job is pipeline continuity,
    not security judgment.
    """

    CONSISTENCY_RESPONSE = {
        "intended_purpose":   "Could not determine — LLM unavailable (mock response)",
        "actual_behavior":    "Could not determine — LLM unavailable (mock response)",
        "discrepancies":      [],
        "verdict":            "Benign",
        "confidence":         "low",
        "reason":             "Mock agent used — real LLM unavailable. "
                              "Re-run with a valid OPENAI_API_KEY for actual analysis.",
    }

    DEPENDENCY_RESPONSE = {
        "urls_found":         [],
        "imports_found":      [],
        "suspicious_items":   [],
        "verdict":            "Benign",
        "confidence":         "low",
        "reason":             "Mock agent used — real LLM unavailable. "
                              "Re-run with a valid OPENAI_API_KEY for actual analysis.",
    }

    @staticmethod
    def consistency(instructions: str, code: str) -> dict:
        return MockAgent.CONSISTENCY_RESPONSE.copy()

    @staticmethod
    def dependency(skill_content: str) -> dict:
        return MockAgent.DEPENDENCY_RESPONSE.copy()


# ---------------------------------------------------------------------------
# Rule 2 — CONSISTENCY_CHECK
# ---------------------------------------------------------------------------

_CONSISTENCY_SYSTEM = textwrap.dedent("""
    You are a security analyst reviewing agentic AI skills.
    Your job is to detect trojan skills: skills whose declared purpose
    (in SKILL.md) does not match what the implementation code actually does.

    Respond ONLY with a JSON object — no markdown, no explanation outside the JSON.

    Required JSON schema:
    {
      "intended_purpose": "<one sentence: what SKILL.md says this skill does>",
      "actual_behavior":  "<one sentence: what the code actually does>",
      "discrepancies": [
        "<each behavior in the code that is NOT explained by the declared purpose>"
      ],
      "verdict":     "Benign" | "Suspicious" | "Malicious",
      "confidence":  "low" | "medium" | "high",
      "reason":      "<2-3 sentences explaining the verdict>"
    }

    Verdict guide:
      Benign     — implementation matches declared purpose; no unexplained behaviors.
      Suspicious — minor unexplained behaviors, or ambiguous intent.
      Malicious  — implementation clearly does things the declared purpose does not
                   mention and that could harm the user or system (credential theft,
                   exfiltration, persistence, etc.).
""").strip()


def run_consistency_check(instructions: str, code: str) -> LLMRuleResult:
    """
    Rule 2: Ask the LLM whether the skill's code matches its declared instructions.

    Args:
        instructions: full text of SKILL.md (the declared intent)
        code:         concatenated text of all non-.md script files

    Returns:
        LLMRuleResult with verdict, confidence, and reason populated.
    """
    rule_id = "CONSISTENCY_CHECK"

    user_prompt = textwrap.dedent(f"""
        DECLARED INSTRUCTIONS (from SKILL.md):
        {_trim(instructions)}

        ---

        IMPLEMENTATION (all script files concatenated):
        {_trim(code)}
    """).strip()

    # Try real LLM first; fall back to mock on any failure
    used_mock = False
    parsed = {}

    key_looks_real = (
        OPENAI_API_KEY
        and OPENAI_API_KEY != "YOUR_OPENAI_API_KEY_HERE"
        and len(OPENAI_API_KEY) > 20
    )

    if key_looks_real:
        try:
            raw = _call_openai(_CONSISTENCY_SYSTEM, user_prompt)
            parsed = _parse_llm_json(raw)
        except Exception as exc:
            used_mock = True
            error_msg = f"LLM call failed: {exc}"
    else:
        used_mock = True
        error_msg = "No valid OPENAI_API_KEY — using mock agent"

    if used_mock:
        parsed = MockAgent.consistency(instructions, code)
        return LLMRuleResult(
            rule_id=rule_id,
            verdict=parsed.get("verdict", "Benign"),
            confidence=parsed.get("confidence", "low"),
            reason=parsed.get("reason", ""),
            details=parsed,
            used_mock=True,
            error=error_msg if used_mock else None,
        )

    # Validate + extract from real LLM response
    verdict = parsed.get("verdict", "Benign")
    if verdict not in ("Benign", "Suspicious", "Malicious"):
        verdict = "Suspicious"   # unknown verdict → conservative fallback

    return LLMRuleResult(
        rule_id=rule_id,
        verdict=verdict,
        confidence=parsed.get("confidence", "low"),
        reason=parsed.get("reason", "(no reason provided)"),
        details=parsed,
        used_mock=False,
    )


# ---------------------------------------------------------------------------
# Rule 3 — DEPENDENCY_CHECK
# ---------------------------------------------------------------------------

_DEPENDENCY_SYSTEM = textwrap.dedent("""
    You are a supply-chain security analyst reviewing agentic AI skills.
    Your job is to evaluate every URL, remote dependency, import, and
    file download target in the skill's code and assess whether they
    are legitimate and consistent with the skill's stated purpose.

    Respond ONLY with a JSON object — no markdown, no explanation outside the JSON.

    Required JSON schema:
    {
      "urls_found": ["<each URL or domain mentioned in the code>"],
      "imports_found": ["<each package/module imported>"],
      "suspicious_items": [
        {
          "item": "<the URL, import, or path>",
          "reason": "<why it is suspicious>"
        }
      ],
      "verdict":    "Benign" | "Suspicious" | "Malicious",
      "confidence": "low" | "medium" | "high",
      "reason":     "<2-3 sentences explaining the verdict>"
    }

    When evaluating, ask yourself:
      1. Does this URL belong to an official, well-known domain for the task
         described?  (e.g. pypi.org for Python packages is fine; a random IP
         is not.)
      2. Are the file paths being downloaded reasonable for the skill's purpose?
         (e.g. a .whl file from pypi is fine; a .sh file from an IP is not.)
      3. Is there any URL that could be a C2 (command-and-control) server,
         a data exfiltration endpoint, or an anonymous drop site?
      4. Are there imports of packages known to be malicious or unusually
         capable (keyloggers, RATs, crypto miners)?

    Verdict guide:
      Benign     — all dependencies are official, plausible, and consistent
                   with the skill's purpose.
      Suspicious — some dependencies are unusual or unverifiable but not
                   clearly malicious.
      Malicious  — at least one dependency is clearly a threat (raw IP C2,
                   known-bad package, anonymous exfiltration service, etc.).
""").strip()


def run_dependency_check(skill_content: str) -> LLMRuleResult:
    """
    Rule 3: Ask the LLM to evaluate the legitimacy of all URLs, imports,
    and download targets found in the skill's files.

    Args:
        skill_content: full concatenated text of ALL skill files
                       (SKILL.md + scripts), so the LLM has context
                       for whether a dependency makes sense.

    Returns:
        LLMRuleResult with verdict, confidence, and reason populated.
    """
    rule_id = "DEPENDENCY_CHECK"

    user_prompt = textwrap.dedent(f"""
        FULL SKILL CONTENT (SKILL.md + all script files):
        {_trim(skill_content)}
    """).strip()

    used_mock = False
    parsed = {}
    error_msg = ""

    key_looks_real = (
        OPENAI_API_KEY
        and OPENAI_API_KEY != "YOUR_OPENAI_API_KEY_HERE"
        and len(OPENAI_API_KEY) > 20
    )

    if key_looks_real:
        try:
            raw = _call_openai(_DEPENDENCY_SYSTEM, user_prompt)
            parsed = _parse_llm_json(raw)
        except Exception as exc:
            used_mock = True
            error_msg = f"LLM call failed: {exc}"
    else:
        used_mock = True
        error_msg = "No valid OPENAI_API_KEY — using mock agent"

    if used_mock:
        parsed = MockAgent.dependency(skill_content)
        return LLMRuleResult(
            rule_id=rule_id,
            verdict=parsed.get("verdict", "Benign"),
            confidence=parsed.get("confidence", "low"),
            reason=parsed.get("reason", ""),
            details=parsed,
            used_mock=True,
            error=error_msg,
        )

    verdict = parsed.get("verdict", "Benign")
    if verdict not in ("Benign", "Suspicious", "Malicious"):
        verdict = "Suspicious"

    return LLMRuleResult(
        rule_id=rule_id,
        verdict=verdict,
        confidence=parsed.get("confidence", "low"),
        reason=parsed.get("reason", "(no reason provided)"),
        details=parsed,
        used_mock=False,
    )
