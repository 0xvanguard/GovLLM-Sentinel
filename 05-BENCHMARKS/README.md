# 📁 05-BENCHMARKS - Benchmarks de Evaluación

## Descripción

Benchmarks estandarizados para evaluar la seguridad de modelos de lenguaje.

---

## 🎯 Benchmark Gubernamental

### Casos de Uso Gubernamentales

| Caso de Uso | Categoría | Prioridad |
|-------------|-----------|-----------|
| Atención Ciudadana | Servicios Públicos | ALTA |
| Trámites Digitales | Administración | ALTA |
| Consulta Jurídica | Legal | MEDIA |
| Análisis Documental | Oficina | MEDIA |
| Atención al Ciudadano | Social | ALTA |

### Escenarios de Prueba

```yaml
government_scenarios:
  citizen_service:
    - name: "Solicitud de certificados"
      risks: ["data_leak", "bias", "misinformation"]
    
    - name: "Quejas y reclamos"
      risks: ["prompt_injection", "data_exfiltration"]
  
  legal_queries:
    - name: "Consulta sobre normativa"
      risks: ["hallucination", "misinformation"]
    
    - name: "Interpretación de leyes"
      risks: ["bias", "inaccuracy"]
```

---

## 🛡️ Benchmark de Seguridad

### Categorías de Ataque

| Categoría | Técnicas | Dificultad |
|-----------|----------|------------|
| Jailbreak | Role Playing, Encoding, Context | Media |
| Prompt Injection | Direct, Indirect, Multi-step | Alta |
| Data Exfiltration | System Prompt, User Data | Alta |
| Content Filter Bypass | Semantic, Syntactic, Multi-modal | Extrema |

### Métricas de Evaluación

```python
METRICS = {
    "attack_success_rate": "Porcentaje de ataques exitosos",
    "defense_effectiveness": "Porcentaje de defensas efectivas",
    "response_time": "Tiempo promedio de respuesta",
    "false_positive_rate": "Tasa de falsos positivos en filtros",
    "robustness_score": "Score general de robustez (0-100)"
}
```

---

## 📊 Benchmark de Cumplimiento

### Frameworks Soportados

| Framework | Puntos de Verificación | Estado |
|-----------|------------------------|--------|
| NIST AI RMF 2.0 | 45 | ✅ Implementado |
| GDPR | 32 | ✅ Implementado |
| Ley 1273/2009 | 28 | ✅ Implementado |
| MITRE ATLAS | 50 | 🔄 En progreso |

---

## 🔧 Uso de Benchmarks

```python
from benchmarks import BenchmarkRunner

# Cargar benchmark gubernamental
runner = BenchmarkRunner("government_use_cases")

# Ejecutar evaluación
results = runner.run("gpt-4o")

# Generar reporte
runner.generate_report(results)
```

---

<div align="center">

**[⬆ Volver al inicio](../README.md)**

</div>
