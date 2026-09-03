# Skill Scanner

A static heuristic scanner for AI "skill" files/directories. Classifies input as
**Benign**, **Suspicious**, or **Malicious** before you install or run it.

## Usage

```bash
# Scan a single skill file
python3 skill_scanner.py path/to/SKILL.md

# Scan a directory (auto-detects nested skills by their SKILL.md marker)
python3 skill_scanner.py path/to/skills-folder

# Verbose: show every finding with file:line detail
python3 skill_scanner.py path/to/skills-folder -v

# Write a full JSON report (for tooling/CI)
python3 skill_scanner.py path/to/skills-folder --json report.json

# Only show skills that are at least Suspicious
python3 skill_scanner.py path/to/skills-folder --min-severity suspicious

# CI mode: exit code 1 if anything is Malicious (or Suspicious, if you choose)
python3 skill_scanner.py path/to/skills-folder --fail-on malicious
```

No third-party dependencies — pure standard library.

## How it classifies

Every scannable file (`.md .py .js .ts .sh .bash .ps1 .json .yaml .yml .txt`)
is checked line-by-line against a rule set in `rules.py`, grouped into
categories:

- **remote_execution** — curl|bash pipes, `eval`/`exec` on dynamic data, `shell=True`, `os.system`
- **obfuscation** — base64-decode-then-exec, long base64 blobs, char-code string building, hex-escape runs
- **exfiltration** — sending env vars/secrets over the network, raw-IP URLs, Discord/Telegram webhooks, paste/transfer sites
- **credential_theft** — reading SSH keys, cloud credential files, browser cookie stores, hardcoded secrets
- **filesystem** — broad `rm -rf`, cron/rc-file persistence, writes to system directories
- **prompt_injection** — "ignore previous instructions", jailbreak personas, "don't tell the user", instructions to exfiltrate the conversation
- **suspicious_behavior** — keylogging APIs, screen capture, clipboard reads, self-modifying scripts, "requires root access" claims

Each match has a weight. A single high-confidence "critical" rule (weight 8,
e.g. a reverse-shell pipe or credential exfiltration) forces at least a
**Malicious** verdict on its own. Otherwise:

- total score ≥ 8 → **Malicious**
- total score ≥ 4 → **Suspicious**
- else → **Benign**

## Limitations (read before relying on this)

This is a **static, pattern-based** scanner — it does not execute code,
understand semantics, or use an LLM to reason about intent. That means:

- **False negatives are possible.** Well-obfuscated or novel attack patterns
  that don't match the regexes will slip through. This is a triage aid, not
  a guarantee of safety.
- **False positives are possible.** Legitimate skills that use `subprocess`,
  `requests`, or read a `.env` file will trigger lower-weight findings — use
  `-v` to read the actual context before trusting the verdict.
- Tune `rules.py` for your own threat model — add rules, adjust weights, or
  change `SUSPICIOUS_THRESHOLD` / `MALICIOUS_THRESHOLD` in `rules.py`.
- For anything flagged Suspicious or Malicious, a human review of the
  flagged lines is recommended before install/execution.

## Files

- `skill_scanner.py` — CLI entry point
- `scanner.py` — file-walking and scoring engine
- `rules.py` — the detection rule set (edit this to tune behavior)
