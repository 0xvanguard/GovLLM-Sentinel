# 📁 03-MODELS - Modelos Evaluados y Fortalecidos

## Descripción

Directorio para almacenar información sobre modelos evaluados y fortalecidos.

---

## 🗂️ Estructura

```
03-MODELS/
│
├── evaluated/                    ← Modelos que han sido evaluados
│   ├── gpt-4o/
│   ├── claude-3.5/
│   ├── llama-3.1/
│   └── mistral-7b/
│
└── hardened/                     ← Modelos que han sido fortalecidos
    ├── gpt-4o-hardened/
    └── llama-3.1-hardened/
```

---

## 📊 Modelo de Datos

### Evaluación de Modelo

```json
{
  "model_id": "gpt-4o",
  "version": "2024-08-06",
  "provider": "OpenAI",
  "evaluation_date": "2026-08-23",
  "contract_id": "CONTRATO-RT-2026-001",
  "scores": {
    "overall": 82.5,
    "jailbreak": 78.0,
    "injection": 85.0,
    "exfiltration": 90.0,
    "filters": 72.0
  },
  "vulnerabilities": {
    "total": 12,
    "critical": 2,
    "high": 5,
    "medium": 3,
    "low": 2
  }
}
```

### Modelo Fortalecido

```json
{
  "model_id": "gpt-4o-hardened",
  "base_model": "gpt-4o",
  "hardening_date": "2026-08-25",
  "defenses_applied": [
    "adversarial_training",
    "input_filtering",
    "output_filtering"
  ],
  "improvement": {
    "before_score": 82.5,
    "after_score": 91.0,
    "improvement_pct": 10.3
  }
}
```

---

## ⚠️ Restricciones

- ✅ Información de modelos evaluados está disponible
- ✅ Scores de seguridad son públicos
- ❌ Código fuente de modelos NO está disponible
- ❌ Datos de entrenamiento NO están disponibles

---

<div align="center">

**[⬆ Volver al inicio](../README.md)**

</div>
