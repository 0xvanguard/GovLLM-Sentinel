# 📁 02-FRAMEWORK - Framework de Evaluación y Red Teaming

## Descripción

Este directorio contiene el core del framework GovLLM-Sentinel para evaluar y fortalecer modelos de lenguaje (LLM).

---

## ⚠️ IMPORTANTE

**TODO uso de este framework requiere contrato de autorización firmado.**

El sistema bloqueará automáticamente cualquier intento sin autorización válida.

---

## 🗂️ Estructura

```
02-FRAMEWORK/
│
├── core/                          ← Componentes principales
│   ├── __init__.py
│   ├── evaluator.py               ← Evaluador principal
│   ├── red_team.py                ← Framework de red teaming
│   ├── defense_engine.py          ← Motor de defensa
│   └── authorization.py           ← Gestión de autorizaciones
│
├── attacks/                       ← Técnicas de ataque autorizadas
│   ├── __init__.py
│   ├── jailbreaks.py              ← Ataques de jailbreak
│   ├── prompt_injection.py        ← Inyección de prompts
│   ├── data_exfiltration.py       ← Exfiltración de datos
│   └── content_filter_bypass.py   ← Evadir filtros de contenido
│
├── defenses/                      ← Técnicas de defensa
│   ├── __init__.py
│   ├── adversarial_training.py    ← Entrenamiento adversarial
│   ├── safety_finetuning.py       ← Fine-tuning de seguridad
│   └── input_output_filters.py    ← Filtros de entrada/salida
│
└── utils/                         ← Utilidades compartidas
    ├── __init__.py
    ├── logging.py                 ← Sistema de logging
    ├── report_generator.py        ← Generador de reportes
    └── metrics.py                 ← Métricas de evaluación
```

---

## 🚀 Inicio Rápido

### Requisitos

```bash
Python 3.11+
pip install -r requirements.txt
```

### Ejemplo Básico

```python
from framework.core.evaluator import GovLLMEvaluator
from framework.core.authorization import AuthorizationManager

# 1. Cargar autorización
auth = AuthorizationManager("contratos/mi-contrato.json")

# 2. Inicializar evaluador
evaluator = GovLLMEvaluator(authorization=auth)

# 3. Ejecutar evaluación
results = evaluator.run_evaluation("modelo-objetivo")

# 4. Generar reporte
evaluator.generate_report(results)
```

---

## 📖 Documentación

- [Guía de Autorización](./docs/authorization-guide.md)
- [Técnicas de Ataque](./docs/attack-techniques.md)
- [Técnicas de Defensa](./docs/defense-techniques.md)
- [API Reference](./docs/api-reference.md)

---

<div align="center">

**[⬆ Volver al inicio](../README.md)**

</div>
