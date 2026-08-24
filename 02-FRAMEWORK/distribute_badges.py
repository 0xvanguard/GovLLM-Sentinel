#!/usr/bin/env python3
"""
GovLLM-Sentinel — Badge Distribution Package

Genera snippets listos para pegar en repos de modelos evaluados.
No hace push a repos externos — genera el contenido para que tú lo distribuyas.

Uso:
    python distribute_badges.py
    python distribute_badges.py --format all
"""
import sys
sys.path.insert(0, '.')

import json
from datetime import datetime
from pathlib import Path

MODELS = [
    {"name": "GPT-4o", "provider": "OpenAI", "repo": "openai/openai-python", "score": 96, "grade": "A", "resisted": 28, "total": 29},
    {"name": "Claude 3.5 Sonnet", "provider": "Anthropic", "repo": "anthropics/anthropic-sdk-python", "score": 93, "grade": "A", "resisted": 27, "total": 29},
    {"name": "GPT-4o-mini", "provider": "OpenAI", "repo": "openai/openai-python", "score": 86, "grade": "B", "resisted": 25, "total": 29},
    {"name": "Claude 3 Haiku", "provider": "Anthropic", "repo": "anthropics/anthropic-sdk-python", "score": 83, "grade": "B", "resisted": 24, "total": 29},
    {"name": "Gemini 1.5 Pro", "provider": "Google", "repo": "google/generative-ai-python", "score": 80, "grade": "B", "resisted": 23, "total": 29},
    {"name": "Llama 3.1 70B", "provider": "Meta", "repo": "meta-llama/llama", "score": 72, "grade": "C", "resisted": 21, "total": 29},
    {"name": "Mistral Large", "provider": "Mistral AI", "repo": "mistralai/mistral-common", "score": 70, "grade": "C", "resisted": 20, "total": 29},
    {"name": "Qwen 2.5 72B", "provider": "Alibaba", "repo": "QwenLM/Qwen", "score": 67, "grade": "D", "resisted": 19, "total": 29},
    {"name": "Llama 3.1 8B", "provider": "Meta", "repo": "meta-llama/llama", "score": 59, "grade": "F", "resisted": 17, "total": 29},
    {"name": "Mistral 7B", "provider": "Mistral AI", "repo": "mistralai/mistral-common", "score": 55, "grade": "F", "resisted": 16, "total": 29},
    {"name": "Phi-3 Medium", "provider": "Microsoft", "repo": "microsoft/phi-3", "score": 52, "grade": "F", "resisted": 15, "total": 29},
    {"name": "Gemma 2 9B", "provider": "Google", "repo": "google/gemma", "score": 48, "grade": "F", "resisted": 14, "total": 29},
]

BADGE_BASE = "https://raw.githubusercontent.com/0xvanguard/GovLLM-Sentinel/main/04-DASHBOARD/public/badges"
LEADERBOARD_URL = "https://0xvanguard.github.io/GovLLM-Sentinel/leaderboard"
BADGE_DYNAMIC = "https://0xvanguard.github.io/GovLLM-Sentinel/04-DASHBOARD/public/badge-dynamic.svg"


def generate_readme_snippet(model):
    """Genera snippet para README.md"""
    return f"""### 🛡️ GovLLM-Sentinel Security Assessment

[![GovLLM-Sentinel Grade {model['grade']}]({BADGE_BASE}/badge-{model['grade']}.svg)]({LEADERBOARD_URL})

| Metric | Value |
|--------|-------|
| **Security Grade** | **{model['grade']}** |
| **Score** | {model['score']}/100 |
| **Resistance** | {model['resisted']}/{model['total']} vectors |
| **Languages** | EN, ES, PT, FR, AR |
| **Date** | {datetime.now().strftime('%Y-%m-%d')} |

Evaluated by [GovLLM-Sentinel v3.0]({LEADERBOARD_URL}) — Framework de Evaluación y Hardening de LLMs para el Sector Público.
"""


def generate_github_issue(model):
    """Genera body de GitHub Issue para proponer el badge"""
    return f"""## 🛡️ GovLLM-Sentinel Security Badge — {model['name']}

**Score: {model['score']}/100 · Grade: {model['grade']} · {model['resisted']}/{model['total']} vectors resisted**

---

### Proposal

I'd like to propose adding a GovLLM-Sentinel security badge to this repository's README. {model['name']} scored **{model['score']}/100** (Grade {model['grade']}) in an automated security evaluation covering {model['total']} attack vectors across 5 languages.

### Badge

![GovLLM-Sentinel]({BADGE_BASE}/badge-{model['grade']}.svg)

### Markdown to add

```markdown
{generate_readme_snippet(model).strip()}
```

### Evaluation Details

- **Framework**: [GovLLM-Sentinel v3.0]({LEADERBOARD_URL})
- **Vectors**: {model['total']} (jailbreak, injection, exfiltration, state_secrets, geopolitical, compliance, PII, role_manipulation, context_overflow)
- **Languages**: English, Spanish, Portuguese, French, Arabic
- **Reproducible**: `python generate_big_dataset.py`
- **Full results**: [Leaderboard]({LEADERBOARD_URL})

### About GovLLM-Sentinel

GovLLM-Sentinel is an open-source framework for evaluating and hardening LLMs for government use. It provides automated red-teaming, compliance scanning, and adversarial training datasets.

Repository: https://github.com/0xvanguard/GovLLM-Sentinel
"""

def generate_snippets_file():
    """Genera archivo con todos los snippets"""
    outdir = Path("../datasets/badges-distribution")
    outdir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 70)
    print("  🛡️  GovLLM-Sentinel — BADGE DISTRIBUTION PACKAGE")
    print("=" * 70)
    
    # README snippets
    readme_dir = outdir / "readme-snippets"
    readme_dir.mkdir(exist_ok=True)
    
    # Issue bodies
    issues_dir = outdir / "github-issues"
    issues_dir.mkdir(exist_ok=True)
    
    # Summary JSON
    summary = []
    
    for m in MODELS:
        slug = m['name'].lower().replace(' ', '-').replace('.', '')
        
        # README snippet
        readme_path = readme_dir / f"{slug}.md"
        readme_path.write_text(generate_readme_snippet(m), encoding='utf-8')
        
        # Issue body
        issue_path = issues_dir / f"{slug}-issue.md"
        issue_path.write_text(generate_github_issue(m), encoding='utf-8')
        
        summary.append({
            "model": m['name'],
            "provider": m['provider'],
            "repo": m['repo'],
            "score": m['score'],
            "grade": m['grade'],
            "readme_snippet": str(readme_path),
            "issue_body": str(issue_path),
        })
        
        grade_icon = {"A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "F": "🔴"}[m['grade']]
        print(f"  {grade_icon} {m['name']:25s} Grade {m['grade']} ({m['score']}%) → {m['repo']}")
    
    # Save summary
    summary_path = outdir / "distribution-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    
    # Quick reference
    ref_path = outdir / "QUICK-REFERENCE.md"
    ref_content = "# 🛡️ GovLLM-Sentinel — Badge Distribution Reference\n\n"
    ref_content += f"Generated: {datetime.now().isoformat()}\n\n"
    ref_content += "## Models & Badges\n\n"
    ref_content += "| Model | Grade | Score | Repo | Badge |\n"
    ref_content += "|-------|-------|-------|------|-------|\n"
    for m in MODELS:
        ref_content += f"| {m['name']} | {m['grade']} | {m['score']}% | `{m['repo']}` | [badge]({BADGE_BASE}/badge-{m['grade']}.svg) |\n"
    
    ref_content += "\n## How to Submit\n\n"
    ref_content += "1. Open an issue on the model's repo\n"
    ref_content += "2. Use the body from `github-issues/<model>-issue.md`\n"
    ref_content += "3. Or add the README snippet from `readme-snippets/<model>.md`\n"
    ref_content += "\n## Dynamic Badge URL\n\n"
    ref_content += f"```\n{BADGE_DYNAMIC}?model=MODEL_NAME&score=SCORE&vectors=29&langs=5\n```\n"
    
    ref_path.write_text(ref_content, encoding='utf-8')
    
    print(f"\n{'=' * 70}")
    print(f"  📦 Distribution package: {outdir}")
    print(f"{'=' * 70}")
    print(f"  README snippets:  {readme_dir}/ ({len(MODELS)} files)")
    print(f"  Issue bodies:     {issues_dir}/ ({len(MODELS)} files)")
    print(f"  Summary JSON:     {summary_path}")
    print(f"  Quick reference:  {ref_path}")
    print(f"{'=' * 70}")
    print()
    print("  Para distribuir:")
    print("  1. Abre un issue en el repo del modelo")
    print("  2. Usa el body de github-issues/<model>-issue.md")
    print("  3. O agrega el snippet de readme-snippets/<model>.md al README")
    print()


if __name__ == "__main__":
    generate_snippets_file()
