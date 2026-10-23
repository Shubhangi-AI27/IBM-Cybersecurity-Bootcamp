#  NotebookGuard Lite

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/Streamlit-1.32%2B-FF4B4B?style=flat-square&logo=streamlit" alt="Streamlit"/>
  <img src="https://img.shields.io/badge/Pandas-2.0%2B-150458?style=flat-square&logo=pandas" alt="Pandas"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/Offline-100%25-brightgreen?style=flat-square" alt="Fully Offline"/>
  <img src="https://img.shields.io/badge/Network_Calls-Zero-critical?style=flat-square" alt="Zero Network Calls"/>
</p>

> **Offline Jupyter Notebook Leak Scanner — no data ever leaves your machine.**

---

##  Project Description & Overview

**NotebookGuard Lite** is a lightweight, fully offline security scanning tool for Jupyter Notebooks (`.ipynb` files). It detects secrets, personally identifiable information (PII), dangerous code patterns, and unsafe ML practices that should never appear in shared or version-controlled notebooks.

Data scientists and ML engineers routinely embed sensitive credentials, hardcoded paths, and risky code patterns directly in notebooks during development. NotebookGuard Lite provides an instant, in-browser triage layer — acting as a last line of defence before notebooks are committed or shared.

**Key design principles:**
-  **Privacy-first** — all scanning runs entirely in the local Python process; no telemetry, no network calls, no cloud APIs.
-  **Zero-config** — two dependencies (`streamlit`, `pandas`) and a single command.
-  **Risk-scored** — every finding carries a 0–100 score with a plain-English explanation, not just a flag.
-  **Actionable** — each finding includes a concrete remediation hint so you know exactly what to do next.

---

##  Key Features

| Feature | Details |
|---|---|
| **Secret Detection** | OpenAI, AWS, HuggingFace, GitHub, Google API keys; PEM private-key blocks; database connection strings; hardcoded passwords; Slack & Discord webhooks; Bearer tokens |
| **PII Detection** | Email addresses, phone numbers, Luhn-validated credit-card numbers, sensitive DataFrame column names (`email`, `phone`, `ssn`, `aadhaar`, `dob`) |
| **Local Path Leaks** | Exposes of local usernames via `C:\Users\<name>\`, `/home/<name>/`, `/Users/<name>/` |
| **ML Safety Checks** | `torch.load` without `weights_only=True`, `pickle.load/loads`, `trust_remote_code=True`, `np.load(allow_pickle=True)` |
| **Risky Shell/Exec** | `curl`/`wget` piped to shell, `os.environ` dumps, `exec`/`eval` with base64 decode |
| **Smart Scoring** | Contextual 0–100 risk score with modifiers (output cell, known token format, placeholder detection, multi-cell spread) |
| **Sensitive Value Masking** | Matched secrets are masked in displayed snippets — API keys, emails, and phone numbers are partially redacted |
| **Batch Scanning** | Upload and scan multiple notebooks simultaneously |
| **Live Filtering** | Filter results by minimum risk score and finding type without re-scanning |
| **CSV Export** | Download all findings as a structured CSV for offline review or audit trails |
| **Built-in Demo** | One-click demo notebook with intentional, non-functional findings for quick evaluation |

---

##  System Architecture & Data Flow

```
┌────────────────────────────────────────────────────────────────┐
│                        USER'S BROWSER                          │
│                                                                │
│   ┌─────────────┐     Upload .ipynb      ┌──────────────────┐ │
│   │  Sidebar UI │ ──────────────────────▶ │  Streamlit App   │ │
│   │  (Filters)  │ ◀────────────────────── │    (app.py)      │ │
│   └─────────────┘     Filtered Results    └────────┬─────────┘ │
└────────────────────────────────────────────────────┼───────────┘
                                                     │ (local process only)
                         ┌───────────────────────────▼──────────────────────┐
                         │                  SCANNING PIPELINE                │
                         │                                                   │
                         │  1. parse_notebook()  ──▶  Extract code cells    │
                         │         │                  + output cells         │
                         │         ▼                                         │
                         │  2. scan_notebook()   ──▶  Apply RULES regexes   │
                         │         │                  + optional validators  │
                         │         ▼                                         │
                         │  3. _compute_score()  ──▶  Base score            │
                         │         │                  + modifiers            │
                         │         │                  + placeholder penalty  │
                         │         ▼                                         │
                         │  4. scan_all()        ──▶  Multi-cell bonus      │
                         │         │                  Sort by score          │
                         │         ▼                                         │
                         │  5. group_findings()  ──▶  Collapse duplicates   │
                         │         │                                         │
                         │         ▼                                         │
                         │  6. overall_score()   ──▶  Repo-level score      │
                         └───────────────────────────────────────────────────┘
                                                     │
                                         ┌───────────▼──────────┐
                                         │   Results rendered   │
                                         │   in Streamlit UI    │
                                         │   (metrics, chart,   │
                                         │   table, expanders,  │
                                         │   CSV export)        │
                                         └──────────────────────┘
```

**Data Flow Summary:**
1. The user uploads one or more `.ipynb` files (or clicks "Use demo notebook").
2. `parse_notebook()` deserializes the JSON and extracts all **code cells** and their **outputs**.
3. `scan_notebook()` applies each rule's compiled regex to both cell source and output text.
4. Optional validators (Luhn checksum, `weights_only` check, table-context check) filter false positives.
5. `_compute_score()` calculates a contextual risk score using configurable weights in `SCORE_CONFIG`.
6. `scan_all()` applies the multi-cell bonus for secrets seen across multiple cells.
7. `group_findings()` collapses repeated matches in the same cell/location into a single row.
8. The Streamlit UI renders metrics, a bar chart, a findings table, per-finding expanders, and a CSV download button.

>  **No data ever leaves the local process.** The Streamlit server runs on `localhost` and makes zero outbound network calls.

---

##  Prerequisites & System Requirements

| Requirement | Minimum Version | Notes |
|---|---|---|
| **Python** | 3.9 | 3.10+ recommended |
| **Streamlit** | 1.32 | UI framework |
| **Pandas** | 2.0 | Results table handling |
| **Operating System** | Windows / macOS / Linux | Any OS that runs Python |
| **Browser** | Any modern browser | Chrome, Firefox, Edge, Safari |
| **RAM** | 256 MB | Scanning large notebooks may use more |
| **Disk** | < 5 MB | Tool only; excludes Python environment |
| **Network** | Not required | 100% offline operation |

---

##  Installation & Setup Guide

### 1 — Clone or download the project

```bash
git clone https://github.com/your-username/notebookguard-lite.git
cd notebookguard-lite
```

Or simply download `app.py` and `requirements.txt` into a folder.

### 2 — (Recommended) Create a virtual environment

```bash
# macOS / Linux
python -m venv .venv
source .venv/bin/activate

# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3 — Install dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install "streamlit>=1.32" "pandas>=2.0"
```

### 4 — Run the application

```bash
streamlit run app.py
```

Streamlit will automatically open `http://localhost:8501` in your default browser.

---

## ⚡ Usage & Quick Start Examples

### Scanning your own notebook

1. Launch the app with `streamlit run app.py`.
2. In the **sidebar**, click **"Upload .ipynb notebook(s)"** and select one or more files.
3. The scan runs automatically. Review results in the main panel.

### Using the built-in demo

Click **▶ Use demo notebook** in the sidebar to load a pre-built notebook containing 17 cells with intentional (non-functional) findings across all detection categories.

### Filtering results

Use the sidebar controls after scanning:
- **Minimum risk score** (slider, 0–100) — hide low-severity findings.
- **Finding types** (multi-select) — focus on specific categories (e.g., only `secret` and `pii`).

### Exporting findings

Scroll to the **Export** section at the bottom of the page and click **⬇ Download findings as CSV**.

CSV columns:

| Column | Description |
|---|---|
| `file` | Notebook filename |
| `cell` | Cell number (1-indexed) |
| `where` | `code` or `output` |
| `type` | Finding rule name |
| `score` | Risk score 0–100 |
| `count` | Number of matches in this group |
| `example_snippet` | Masked code snippet |
| `why` | Score breakdown |
| `fix` | Remediation hint |

---

##  Results, Benchmarks & Visualizations

### Risk Scoring System

Each finding is assigned a risk score from **0 to 100** using a configurable weight table:

| Modifier | Effect | Reason |
|---|---|---|
| Category base — `secret` | **+80** | API keys grant direct account access |
| Category base — `risky` | **+65** | Shell/exec patterns enable code execution |
| Category base — `ml` | **+55** | Unsafe ML patterns can execute arbitrary code |
| Category base — `path` | **+30** | Leaks local username and directory structure |
| Category base — `pii` | **+25** | Personal data; lower than credential exposure |
| Value is in an **output** cell | **+20** | Already printed/visible — higher exposure |
| Matches a known high-specificity token format | **+10** | Strong indicator of a real (not test) secret |
| Same secret seen in **more than one cell** | **+8** *(secrets only)* | Spread increases breach impact |
| Value looks like a **placeholder** | **−60** | e.g. `your_api_key`, `changeme`, `<YOUR_KEY>` |

> The **overall notebook score** = highest individual finding score + log-scale volume bonus (capped at +15), clamped to 100.

### Risk Score Reference

| Score Range | Severity | Typical Finding |
|---|---|---|
| 80–100 | 🔴 **Critical** | Real API key in output cell |
| 60–79 | 🟠 **High** | Hardcoded password or risky exec pattern |
| 40–59 | 🟡 **Medium** | Unsafe ML load, PII in output |
| 20–39 | 🔵 **Low** | Local path leak, PII in code |
| 0–19 | ⚪ **Info** | Placeholder-like value, low-confidence match |

### Detection Categories

| Icon | Category | Examples |
|---|---|---|
| 🔴 | `secret` | OpenAI key, AWS key, GitHub token, DB password |
| 🟠 | `pii` | Email, phone, credit card, sensitive column names |
| 🟡 | `path` | `/home/alice/projects/`, `C:\Users\john\` |
| 🔵 | `ml` | `torch.load`, `pickle.load`, `trust_remote_code=True` |
| ⛔ | `risky` | `curl | bash`, `os.environ` dump, `eval(base64...)` |

---

##  Known Issues & Roadmap

### Known Limitations

- **Regex-based detection** — may miss obfuscated or dynamically-constructed secrets; may produce false positives on test data.
- **No code execution** — the scanner reads notebook text statically; it cannot evaluate runtime values.
- **Zero network calls** — cannot cross-reference revoked or rotated credentials.
- **Not a policy replacement** — intended for awareness and triage only; not a substitute for dedicated secrets-management tools such as `gitleaks` or `truffleHog`.
- **Code cells only** — markdown cells and raw cells are not currently scanned.

### Roadmap

- [ ] **Markdown cell scanning** — detect secrets leaked in narrative/documentation cells.
- [ ] **`.py` and `.ipynb` git-diff mode** — scan only newly added lines before a commit.
- [ ] **Pre-commit hook integration** — block commits containing high-score findings.
- [ ] **SARIF / JSON export** — structured output for CI/CD pipeline integration.
- [ ] **Custom rule configuration** — load additional regex rules from a YAML file.
- [ ] **Severity threshold enforcement** — exit with non-zero code when score exceeds a threshold (CI use case).
- [ ] **Entropy-based detection** — supplement regex with Shannon entropy scoring for high-entropy strings.
- [ ] **Multi-language support** — scan R Markdown (`.Rmd`) and Quarto (`.qmd`) documents.

---

##  Contributing Guidelines

Contributions are welcome! Please follow these steps:

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**, keeping the single-file design in mind. All logic lives in `app.py`.

3. **Add or update rules** in the `RULES` list (Section 2 of `app.py`). Each rule requires:
   - `name` — short display label
   - `pattern` — compiled `re` regex
   - `category` — one of `secret`, `pii`, `path`, `ml`, `risky`
   - `fix` — one-line remediation hint
   - `score_why` — plain-English reason for the score
   - `mask_style` — `"key"`, `"email"`, `"phone"`, or `"full"`

4. **Test your changes** against the built-in demo notebook and at least one real-world notebook.

5. **Open a pull request** with a clear description of what was changed and why.

**Code style:** follow the existing inline-comment style; keep functions focused and < 40 lines; place all tunable numbers in `SCORE_CONFIG`.

---

##  License & Acknowledgments

### License

This project is released under the **MIT License** — use freely, at your own risk.

```
MIT License

Copyright (c) 2024 NotebookGuard Lite Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

### Acknowledgments

- **[Streamlit](https://streamlit.io/)** — for making it trivial to build interactive data apps in pure Python.
- **[Pandas](https://pandas.pydata.org/)** — for results table handling.
- **[gitleaks](https://github.com/gitleaks/gitleaks)** and **[truffleHog](https://github.com/trufflesecurity/trufflehog)** — for inspiring the detection category design.
- The broader **Jupyter / IPython** community for the open `.ipynb` format specification.

---

<p align="center">
  Developed for the data science community &nbsp;|&nbsp; <strong>NotebookGuard Lite</strong> &nbsp;|&nbsp; MIT License
</p>
