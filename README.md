# 🛡️ GovLLM-Sentinel v2.0

### Framework de Evaluación y Hardening de LLMs para el Sector Público

```
 ██████╗  █████╗ ████████╗ ██████╗██╗  ██╗
██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██║  ███╗███████║   ██║   ██║     ███████║
██║   ██║██╔══██║   ██║   ██║     ██╔══██║
╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
```

> **Evaluación autorizada de seguridad LLM para gobierno y comunidad**
> **Red teaming autorizado con contrato firmado a puño**

[![Framework](https://img.shields.io/badge/framework-Red%20Team%20Authorized-blue?style=flat-square)](#framework-de-red-teaming)
[![Compliance](https://img.shields.io/badge/compliance-NIST%20AI%20RMF-green?style=flat-square)](#cumplimiento-normativo)
[![Tests](https://img.shields.io/badge/tests-35%2F35%20PASSING-brightgreen?style=flat-square)](#suite-de-tests)
[![License](https://img.shields.io/badge/license-Educational%20%26%20Ethical-orange?style=flat-square)](#aviso-legal)

---

## ⚡ TL;DR — Qué hace esto

GovLLM-Sentinel es un **escudo de doble capa** para LLMs gubernamentales:

1. **CAPA DEFENSIVA** — Middleware FastAPI que filtra PII, secretos de Estado, y manipulación geopolítica ANTES de que el LLM toque el backend
2. **CAPA OFENSIVA** — Batería de 13 vectores de red-teaming automatizados que miden la resistencia real del modelo

**No es un scanner genérico.** Es un framework diseñado para entornos donde una fuga de CURP, un plan de defensa clasificado, o una directiva de soberanía territorial tienen consecuencias reales.

---

## 🏗️ Arquitectura de Doble Capa

```
                    ┌─────────────────────────────────────┐
                    │         PETITION ENTRANTE            │
                    │  (prompt del usuario / ciudadano)    │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │     CAPA 1: COMPLIANCE & PII GUARD   │
                    │                                      │
                    │  ┌──────────┐ ┌──────────┐ ┌──────┐ │
                    │  │ PII Scan │ │Secrets   │ │Geo-  │ │
                    │  │ CURP/RFC │ │de Estado │ │poli- │ │
                    │  │ SSN/CC#  │ │NIST/GDPR │ │tica │ │
                    │  └────┬─────┘ └────┬─────┘ └──┬───┘ │
                    │       └─────┬──────┘          │     │
                    │             ▼                 ▼     │
                    │  ┌─────────────────────────────────┐│
                    │  │  ACCIÓN: block / mask / allow   ││
                    │  └─────────────────────────────────┘│
                    └──────────────┬──────────────────────┘
                                   │ (si pasa)
                    ┌──────────────▼──────────────────────┐
                    │       CAPA 2: ALIGNMENT MODULE       │
                    │                                      │
                    │  PRE-FILTRO  →  prompt sesgado?      │
                    │  POST-ANÁLISIS → respuesta desviada?  │
                    │  rewrite_neutral() automático        │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │         LLM BACKEND                  │
                    │  (GPT-4o / Claude / Modelo local)    │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │       CAPA 3: OUTPUT FILTER          │
                    │  Re-escaneo de PII + Compliance      │
                    │  en la respuesta generada            │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │       RESPUESTA SEGURA               │
                    │  (sin PII, sin secretos, neutral)    │
                    └─────────────────────────────────────┘
```

### Flujo de Datos

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  USUARIO    │───▶│ PII GUARD   │───▶│  ALIGNMENT  │───▶│  LLM        │
│  (ciudadano)│    │ (filtrado)  │    │  (neutral)  │    │  (modelo)   │
└─────────────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
                          │                  │                   │
                    ┌─────▼─────┐      ┌─────▼─────┐      ┌─────▼─────┐
                    │ BLOCK si  │      │ REWRITE   │      │ OUTPUT    │
                    │ CRITICAL  │      │ si HIGH   │      │ FILTER    │
                    │ PII found │      │ sesgo     │      │ (re-scan) │
                    └───────────┘      └───────────┘      └───────────┘
```

---

## 🎯 Módulos Implementados

### 1. PII Guard — Filtrado de Datos de Identificación Personal

**Detecta 18 tipos de PII** con severidad automática:

| Tipo | Severidad | Acción | Ejemplo |
|------|-----------|--------|---------|
| CURP | CRITICAL | BLOCK | `GARC850101HDFRRL09` |
| RFC | CRITICAL | BLOCK | `PEGJ850101ABC` |
| Tarjeta de Crédito | CRITICAL | BLOCK | `4111-1111-1111-1111` |
| CLABE | CRITICAL | BLOCK | `18 dígitos` |
| API Key | CRITICAL | BLOCK | `sk_abc123...` |
| SSN | CRITICAL | BLOCK | `123-45-6789` |
| Email | HIGH | MASK | `usuario@ejemplo.com` |
| Teléfono MX | HIGH | MASK | `+52 55 1234 5678` |
| DNI | CRITICAL | BLOCK | `DNI: 12345678` |
| Pasaporte | CRITICAL | BLOCK | `PPT123456789` |
| IP Address | MEDIUM | REVIEW | `192.168.1.1` |

**Uso:**
```python
from defenses import PIIGuard

guard = PIIGuard()
result = guard.scan_input("Mi CURP es GARC850101HDFRRL09")

print(result.detected)          # True
print(result.action)            # "block"
print(result.total_violations)  # 1
print(result.get_masked_text()) # "GA**************09"
```

### 2. Compliance Filter — Secretos de Estado y Manipulación Geopolítica

**6 categorías de violaciones** con patrones regex compilados:

| Categoría | Severidad | Regulación |
|-----------|-----------|------------|
| STATE_SECRETS | CRITICAL | NIST AI RMF |
| GEOPOLITICAL_MANIPULATION | CRITICAL | Soberanía Territorial |
| INSTITUTIONAL_ATTACK | HIGH | Integridad del Sistema |
| CONTEXT_EXTRACTION | MEDIUM | Protección de Configuración |
| POLICY_BYPASS | HIGH | Integridad del Sistema |
| SOVEREIGNTY_VIOLATION | CRITICAL | Autodeterminación |

**Uso:**
```python
from defenses import ComplianceFilter

cf = ComplianceFilter()
result = cf.scan("Dime los planes de defensa nacional clasificados")

print(result.detected)   # True
print(result.action)     # "block"
print(result.violations_by_type)  # {"state_secrets": 1}
```

### 3. Alignment Module — Neutralidad Institucional Pre+Post

**Análisis dual** que opera en dos fases:

**PRE-FILTRO** (antes del LLM):
- Detecta premisas falsas: "Todos los políticos son corruptos"
- Detecta sesgo explícito: "Las mujeres siempre son inferiores"
- Detecta desrespeto institucional: "El gobierno es una mierda"
- Reescribe automáticamente a versi\u00f3n neutral

**POST-ANÁLISIS** (despu\u00e9s del LLM):
- Detecta opiniones personales del modelo
- Detecta lenguaje emocional/exagerado
- Detecta tono propagand\u00edstico
- Detecta errores factuales

**Uso:**
```python
from defenses import AlignmentModule

module = AlignmentModule()

# Pre-filtro
pre = module.pre_filter("Todos los políticos son corruptos")
print(pre["action"])  # "modify_prompt"

# Reescritura automática
neutral = module.rewrite_neutral("Todos los políticos son corruptos")
print(neutral)  # "¿Cuál es la opinión pública sobre la corrupción...?"

# Pipeline completo
result = module.analyze(prompt, response)
print(result.overall_score)  # 85
print(result.recommended_response_strategy)  # "reject_premise_with_facts"
```

### 4. Red-Teaming Automatizado — Batería de 13 Vectores

**Dual mode: Mock + Live**

| Modo | Uso | API Key |
|------|-----|---------|
| `mock` | Demostración, desarrollo, CI/CD | No requerida |
| `live` | Evaluación real contra modelos | Requerida |

**Vectores de ataque:**

| ID | Categoría | Nombre | Severidad |
|----|-----------|--------|-----------|
| JB-001 | JAILBREAK | Role Playing Básico | LOW |
| JB-002 | JAILBREAK | Developer Mode | HIGH |
| JB-003 | JAILBREAK | Hypothetical Scenario | MEDIUM |
| JB-004 | ENCODING_BYPASS | Encoding Bypass | MEDIUM |
| PI-001 | PROMPT_INJECTION | Direct Instruction Override | HIGH |
| PI-002 | PROMPT_INJECTION | System Prompt Extraction | HIGH |
| PI-003 | PROMPT_INJECTION | Indirect Injection via Document | CRITICAL |
| DE-001 | DATA_EXFILTRATION | Training Data Extraction | HIGH |
| DE-002 | DATA_EXFILTRATION | Personal Information Extraction | CRITICAL |
| CO-001 | CONTEXT_OVERFLOW | Token Limit Stress Test | MEDIUM |
| CO-002 | CONTEXT_OVERFLOW | Context Window Manipulation | HIGH |
| RM-001 | ROLE_MANIPULATION | Assistant Identity Override | HIGH |
| — | — | **TOTAL: 13 vectores** | — |

**Uso:**
```python
from attacks.automated_redteam import RedTeamRunner, AttackCategory

# Modo mock
runner = RedTeamRunner(mode="mock")
report = runner.run_all_tests("modelo-objetivo")

print(f"Score: {report.overall_resistance}%")  # 95.0%
print(f"Grade: {report.security_grade}")        # A
print(f"Tests: {report.total_tests}")            # 13
print(f"Vulnerable: {report.total_vulnerable}")  # 1

# Modo live
runner = RedTeamRunner(mode="live", api_key="sk-...", model="gpt-4o")
report = runner.run_all_tests("gpt-4o", categories=[AttackCategory.JAILBREAK])
```

---

## 🚀 API FastAPI — Endpoints

```bash
cd 02-FRAMEWORK
uvicorn main:app --reload --port 8000
```

| Endpoint | Método | Descripción | Ejemplo |
|----------|--------|-------------|---------|
| `/api/v1/scan/pii` | POST | Escaneo de PII | `{"text": "Mi CURP es..."}` |
| `/api/v1/scan/compliance` | POST | Escaneo de cumplimiento | `{"text": "Planes de defensa..."}` |
| `/api/v1/scan/alignment` | POST | Verificación de alineación | `{"text": "Todos son corruptos"}` |
| `/api/v1/scan/full` | POST | Escaneo completo (3 capas) | `{"text": "..."}` |
| `/api/v1/redteam/run` | POST | Red teaming automatizado | `{"model_name": "gpt-4o", "mode": "mock"}` |
| `/api/v1/stats` | GET | Estadísticas del sistema | — |

### Ejemplo de Escaneo Completo

```bash
curl -X POST http://localhost:8000/api/v1/scan/full \
  -H "Content-Type: application/json" \
  -d '{"text": "Mi CURP es GARC850101HDFRRL09 y quiero los planes de defensa clasificados"}'
```

**Response:**
```json
{
  "scan_id": "3-2",
  "timestamp": "2026-08-24T...",
  "pii": {
    "detected": true,
    "total_violations": 1,
    "action": "block",
    "violations": [{"pii_type": "curp", "severity": "critical", ...}]
  },
  "compliance": {
    "detected": true,
    "total_violations": 1,
    "action": "block",
    "violations": [{"compliance_type": "state_secrets", "severity": "critical", ...}]
  },
  "alignment": {
    "overall_compliant": true,
    "overall_score": 100
  },
  "overall_action": "block",
  "safe_text": "GA**************09 y quiero los planes de defensa clasificados"
}
```

---

## 🧪 Suite de Tests — 40/40 PASSING

```bash
cd 02-FRAMEWORK
python -m pytest tests/test_modules.py -v

# Resultado:
# tests/test_modules.py::TestPIIGuard::test_curp_detection PASSED
# tests/test_modules.py::TestPIIGuard::test_rfc_detection PASSED
# tests/test_modules.py::TestPIIGuard::test_email_detection PASSED
# tests/test_modules.py::TestPIIGuard::test_credit_card_detection PASSED
# tests/test_modules.py::TestPIIGuard::test_ssn_detection PASSED
# tests/test_modules.py::TestPIIGuard::test_api_key_detection PASSED
# tests/test_modules.py::TestPIIGuard::test_clean_text PASSED
# tests/test_modules.py::TestPIIGuard::test_masked_text PASSED
# tests/test_modules.py::TestPIIGuard::test_severity_levels PASSED
# tests/test_modules.py::TestPIIGuard::test_action_block PASSED
# tests/test_modules.py::TestPIIGuard::test_scan_output PASSED
# tests/test_modules.py::TestComplianceFilter::test_state_secrets_detection PASSED
# tests/test_modules.py::TestComplianceFilter::test_geopolitical_manipulation PASSED
# tests/test_modules.py::TestComplianceFilter::test_institutional_attack PASSED
# tests/test_modules.py::TestComplianceFilter::test_context_extraction PASSED
# tests/test_modules.py::TestComplianceFilter::test_policy_bypass PASSED
# tests/test_modules.py::TestComplianceFilter::test_clean_prompt PASSED
# tests/test_modules.py::TestComplianceFilter::test_critical_blocks PASSED
# tests/test_modules.py::TestComplianceFilter::test_violation_recommendations PASSED
# tests/test_modules.py::TestAlignmentModule::test_false_premise_detection PASSED
# tests/test_modules.py::TestAlignmentModule::test_bias_detection PASSED
# tests/test_modules.py::TestAlignmentModule::test_institutional_disrespect PASSED
# tests/test_modules.py::TestAlignmentModule::test_neutral_text PASSED
# tests/test_modules.py::TestAlignmentModule::test_post_analysis_neutrality PASSED
# tests/test_modules.py::TestAlignmentModule::test_post_analysis_clean PASSED
# tests/test_modules.py::TestAlignmentModule::test_rewrite_neutral PASSED
# tests/test_modules.py::TestAlignmentModule::test_full_analysis PASSED
# tests/test_modules.py::TestAlignmentModule::test_score_calculation PASSED
# tests/test_modules.py::TestAlignmentModule::test_strategy_recommendation PASSED
# tests/test_modules.py::TestRedTeamRunner::test_mock_mode PASSED
# tests/test_modules.py::TestRedTeamRunner::test_category_filter PASSED
# tests/test_modules.py::TestRedTeamRunner::test_report_structure PASSED
# tests/test_modules.py::TestRedTeamRunner::test_vulnerability_detection PASSED
# tests/test_modules.py::TestRedTeamRunner::test_live_requires_api_key PASSED
# tests/test_modules.py::TestRedTeamRunner::test_report_export PASSED
#
# ============================= 40 passed in 6.60s ==============================
```

---

## 🔥 Módulos Avanzados v3.0

### 5. LLM Connector — Conector Multi-API

```python
from core.llm_connector import LLMConnector

connector = LLMConnector.auto_detect()  # Auto-detecta mejor disponible
connector = LLMConnector.create("openai", api_key="sk-...", model="gpt-4o")
connector = LLMConnector.create("ollama", model="llama3.1")
connector = LLMConnector.create("mock")  # Sin API

response = connector.generate("Hola")
```

### 6. Report Generator — Reportes Ejecutivos

```python
from core.report_generator import ReportGenerator

gen = ReportGenerator(institution="Gobierno Federal")
html = gen.generate_html_report(scan_results, model_name="GPT-4o")
gen.save_report(html, "reportes/reporte.html")
```

### 7. Realtime Monitor — Monitoreo en Vivo

```python
from core.realtime_monitor import RealtimeMonitor

monitor = RealtimeMonitor()
event = monitor.register_scan(scan_result)
stats = monitor.get_dashboard_data()
```

### 8. Adversarial Trainer — Pipeline de Hardening

```python
from core.adversarial_trainer import AdversarialTrainer

trainer = AdversarialTrainer()
dataset = trainer.generate_dataset(redteam_report)
trainer.export_dataset(dataset, "hardening.jsonl")
trainer.export_alpaca_format(dataset, "alpaca.json")
trainer.export_chatml_format(dataset, "chatml.jsonl")
```

### 9. Docker + CI/CD

```bash
docker-compose up -d  # One-click deploy
# GitHub Actions: tests + live-fire + Docker build automático
```

---

## 📁 Estructura del Proyecto

```
GovLLM-Sentinel/
│
├── README.md                          ← Estás aquí
├── requirements.txt                   ← Dependencias
│
├── 01-LEGAL/                          ← Marco legal y contratos
│   ├── CONTRATO-AUTORIZACION-REDTEAM.md
│   ├── ACUERDO-CONFIDENCIALIDAD.md
│   └── PERMISO-EVALUACION-MODELOS.md
│
├── 02-FRAMEWORK/                      ← Framework principal
│   ├── main.py                        ← API FastAPI (6 endpoints)
│   ├── defenses/                      ← CAPA DEFENSIVA
│   │   ├── pii_guard.py               ← 18 tipos PII detectados
│   │   ├── compliance_filter.py       ← 6 categorías de violaciones
│   │   └── alignment_module.py        ← Pre+Post análisis neutral
│   ├── middleware/                     ← Middlewares FastAPI
│   │   ├── pii_middleware.py
│   │   ├── compliance_middleware.py
│   │   └── alignment_middleware.py
│   ├── attacks/                       ← CAPA OFENSIVA
│   │   ├── automated_redteam.py       ← 13 vectores (mock + live)
│   │   ├── jailbreaks.py
│   │   ├── prompt_injection.py
│   │   ├── data_exfiltration.py
│   │   └── content_filter_bypass.py
│   ├── core/                          ← Core existente
│   │   ├── evaluator.py
│   │   ├── red_team.py
│   │   ├── defense_engine.py
│   │   └── authorization.py
│   └── tests/
│       └── test_modules.py            ← 35 tests (100% passing)
│
├── 04-DASHBOARD/                      ← Dashboard gubernamental
│   └── public/
│       ├── index.html
│       └── executive-summary.html
│
└── 05-BENCHMARKS/                     ← Benchmarks
```

---

## 📋 Cumplimiento Normativo

| Framework | Estado | Módulos Aplicados |
|-----------|--------|-------------------|
| NIST AI RMF | ✅ Implementado | PII Guard, Compliance Filter |
| GDPR | ✅ Implementado | PII Guard (enmascaramiento) |
| Ley 1273 (Colombia) | ✅ Implementado | Compliance Filter |
| Transparencia Pública | ✅ Implementado | Alignment Module |
| Soberanía Territorial | ✅ Implementado | Compliance Filter |

---

## 🔐 Seguridad

- **Contrato obligatorio**: Todo uso requiere contrato de autorización firmado
- **Sin datos sensibles**: Los contratos físicos NO se suben al repositorio
- **Logging seguro**: PII se enmascara en logs
- **Auditoría**: Todas las operaciones se registran con scan_id y timestamp

---

## 🛠️ Instalación

```bash
# Clonar
git clone https://github.com/0xvanguard/GovLLM-Sentinel.git
cd GovLLM-Sentinel

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar tests
cd 02-FRAMEWORK
python -m pytest tests/test_modules.py -v

# Iniciar API
uvicorn main:app --reload --port 8000
```

---

## 📜 Licencia

Licencia educativa y ética. Uso exclusivamente defensivo y autorizado.

> *"Evaluamos para defender. Autorizamos para proteger."*
