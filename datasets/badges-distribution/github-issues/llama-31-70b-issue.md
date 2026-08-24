## 🛡️ GovLLM-Sentinel Security Badge — Llama 3.1 70B

**Score: 72/100 · Grade: C · 21/29 vectors resisted**

---

### Proposal

I'd like to propose adding a GovLLM-Sentinel security badge to this repository's README. Llama 3.1 70B scored **72/100** (Grade C) in an automated security evaluation covering 29 attack vectors across 5 languages.

### Badge

![GovLLM-Sentinel](https://raw.githubusercontent.com/0xvanguard/GovLLM-Sentinel/main/04-DASHBOARD/public/badges/badge-C.svg)

### Markdown to add

```markdown
### 🛡️ GovLLM-Sentinel Security Assessment

[![GovLLM-Sentinel Grade C](https://raw.githubusercontent.com/0xvanguard/GovLLM-Sentinel/main/04-DASHBOARD/public/badges/badge-C.svg)](https://0xvanguard.github.io/GovLLM-Sentinel/leaderboard)

| Metric | Value |
|--------|-------|
| **Security Grade** | **C** |
| **Score** | 72/100 |
| **Resistance** | 21/29 vectors |
| **Languages** | EN, ES, PT, FR, AR |
| **Date** | 2026-08-24 |

Evaluated by [GovLLM-Sentinel v3.0](https://0xvanguard.github.io/GovLLM-Sentinel/leaderboard) — Framework de Evaluación y Hardening de LLMs para el Sector Público.
```

### Evaluation Details

- **Framework**: [GovLLM-Sentinel v3.0](https://0xvanguard.github.io/GovLLM-Sentinel/leaderboard)
- **Vectors**: 29 (jailbreak, injection, exfiltration, state_secrets, geopolitical, compliance, PII, role_manipulation, context_overflow)
- **Languages**: English, Spanish, Portuguese, French, Arabic
- **Reproducible**: `python generate_big_dataset.py`
- **Full results**: [Leaderboard](https://0xvanguard.github.io/GovLLM-Sentinel/leaderboard)

### About GovLLM-Sentinel

GovLLM-Sentinel is an open-source framework for evaluating and hardening LLMs for government use. It provides automated red-teaming, compliance scanning, and adversarial training datasets.

Repository: https://github.com/0xvanguard/GovLLM-Sentinel
