# 📡 API de Solo Lectura - GovLLM-Sentinel

## Descripción

API de solo lectura diseñada para entidades gubernamentales y la comunidad.

**⚠️ ACCESO: Solo lectura - No permite modificaciones**

---

## 🔒 Autenticación

```bash
# Todos los endpoints requieren token de solo lectura
Authorization: Bearer <READ_ONLY_TOKEN>
```

---

## 📊 Endpoints Disponibles

### 1. Score General de Seguridad

```http
GET /api/v1/security-score
```

**Descripción:** Retorna el score general de seguridad del modelo evaluado.

**Respuesta:**
```json
{
  "status": "success",
  "data": {
    "model_name": "GPT-4o",
    "evaluation_date": "2026-08-23T10:30:00Z",
    "overall_score": 82.5,
    "security_grade": "B+",
    "risk_level": "MEDIO",
    "breakdown": {
      "jailbreak_resistance": 78.0,
      "prompt_injection_resistance": 85.0,
      "data_exfiltration_resistance": 90.0,
      "content_filter_resistance": 72.0
    }
  }
}
```

---

### 2. Resumen de Vulnerabilidades

```http
GET /api/v1/vulnerabilities
```

**Descripción:** Retorna resumen de vulnerabilidades detectadas.

**Parámetros de consulta:**
- `severity` (opcional): Filtrar por severidad (critical, high, medium, low)
- `category` (opcional): Filtrar por categoría

**Respuesta:**
```json
{
  "status": "success",
  "data": {
    "total": 12,
    "by_severity": {
      "critical": 2,
      "high": 5,
      "medium": 3,
      "low": 2
    },
    "by_category": {
      "jailbreak": 4,
      "prompt_injection": 3,
      "data_exfiltration": 2,
      "content_filter": 3
    },
    "last_updated": "2026-08-23T10:30:00Z"
  }
}
```

---

### 3. Estado de Cumplimiento

```http
GET /api/v1/compliance
```

**Descripción:** Retorna estado de cumplimiento normativo.

**Respuesta:**
```json
{
  "status": "success",
  "data": {
    "frameworks": [
      {
        "name": "NIST AI RMF 2.0",
        "status": "COMPLIANT",
        "score": 85,
        "last_audit": "2026-08-20T08:00:00Z"
      },
      {
        "name": "GDPR",
        "status": "COMPLIANT",
        "score": 90,
        "last_audit": "2026-08-20T08:00:00Z"
      },
      {
        "name": "Ley 1273/2009 (CO)",
        "status": "COMPLIANT",
        "score": 88,
        "last_audit": "2026-08-20T08:00:00Z"
      },
      {
        "name": "MITRE ATLAS",
        "status": "IN_PROGRESS",
        "score": null,
        "last_audit": null
      }
    ],
    "overall_compliance": 87.7
  }
}
```

---

### 4. Historial de Evaluaciones

```http
GET /api/v1/evaluations
```

**Descripción:** Retorna historial de evaluaciones realizadas.

**Parámetros de consulta:**
- `limit` (opcional): Número de resultados (default: 10)
- `offset` (opcional): Offset para paginación

**Respuesta:**
```json
{
  "status": "success",
  "data": {
    "total": 15,
    "evaluations": [
      {
        "id": "EV-GPT4O-20260823",
        "model_name": "GPT-4o",
        "date": "2026-08-23T10:30:00Z",
        "score": 82.5,
        "grade": "B+",
        "vulnerabilities": 12,
        "status": "COMPLETED"
      },
      {
        "id": "EV-CLAUDE-20260822",
        "model_name": "Claude 3.5",
        "date": "2026-08-22T14:15:00Z",
        "score": 88.0,
        "grade": "A-",
        "vulnerabilities": 8,
        "status": "COMPLETED"
      }
    ],
    "pagination": {
      "limit": 10,
      "offset": 0,
      "total": 15
    }
  }
}
```

---

### 5. Recomendaciones

```http
GET /api/v1/recommendations
```

**Descripción:** Retorna recomendaciones principales.

**Respuesta:**
```json
{
  "status": "success",
  "data": {
    "recommendations": [
      {
        "priority": "HIGH",
        "title": "Implementar Adversarial Training",
        "description": "Mejorar resistencia a ataques de jailbreak",
        "category": "defense",
        "status": "PENDING"
      },
      {
        "priority": "HIGH",
        "title": "Reforzar Filtros de Entrada",
        "description": "Añadir capas de validación para inyección",
        "category": "defense",
        "status": "PENDING"
      },
      {
        "priority": "MEDIUM",
        "title": "Mejorar Protección System Prompt",
        "description": "Prevenir extracción de configuración",
        "category": "defense",
        "status": "IN_PROGRESS"
      }
    ],
    "generated_at": "2026-08-23T10:30:00Z"
  }
}
```

---

### 6. Información del Modelo

```http
GET /api/v1/model-info
```

**Descripción:** Retorna información del modelo evaluado.

**Respuesta:**
```json
{
  "status": "success",
  "data": {
    "name": "GPT-4o",
    "version": "2024-08-06",
    "provider": "OpenAI",
    "type": "LLM",
    "evaluation_count": 5,
    "last_evaluation": "2026-08-23T10:30:00Z",
    "contract_id": "CONTRATO-RT-2026-001"
  }
}
```

---

## 🔒 Restricciones de la API

### Acciones Permitidas

| Método | Endpoint | Permitido |
|--------|----------|-----------|
| GET | /api/v1/* | ✅ SÍ |
| POST | /api/v1/* | ❌ NO |
| PUT | /api/v1/* | ❌ NO |
| DELETE | /api/v1/* | ❌ NO |
| PATCH | /api/v1/* | ❌ NO |

### Rate Limiting

- **Requests por minuto:** 60
- **Requests por hora:** 1000
- **Conexiones simultáneas:** 10

### Headers de Respuesta

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1692765600
X-Read-Only: true
X-Access-Level: GOVERNMENT
```

---

## 📝 Ejemplos de Uso

### cURL

```bash
# Obtener score de seguridad
curl -X GET "https://api.govllm-sentinel.gov/api/v1/security-score" \
  -H "Authorization: Bearer READ_ONLY_TOKEN"

# Obtener vulnerabilidades críticas
curl -X GET "https://api.govllm-sentinel.gov/api/v1/vulnerabilities?severity=critical" \
  -H "Authorization: Bearer READ_ONLY_TOKEN"
```

### Python

```python
import requests

# Configuración
API_BASE = "https://api.govllm-sentinel.gov"
HEADERS = {"Authorization": "Bearer READ_ONLY_TOKEN"}

# Obtener score de seguridad
response = requests.get(f"{API_BASE}/api/v1/security-score", headers=HEADERS)
data = response.json()

print(f"Score: {data['data']['overall_score']}")
print(f"Grade: {data['data']['security_grade']}")
```

### JavaScript

```javascript
// Configuración
const API_BASE = 'https://api.govllm-sentinel.gov';
const HEADERS = {'Authorization': 'Bearer READ_ONLY_TOKEN'};

// Obtener score de seguridad
fetch(`${API_BASE}/api/v1/security-score`, { headers: HEADERS })
  .then(response => response.json())
  .then(data => {
    console.log(`Score: ${data.data.overall_score}`);
    console.log(`Grade: ${data.data.security_grade}`);
  });
```

---

## 🚨 Errores Comunes

### 401 Unauthorized

```json
{
  "status": "error",
  "code": "UNAUTHORIZED",
  "message": "Token de autorización inválido o expirado"
}
```

### 403 Forbidden

```json
{
  "status": "error",
  "code": "FORBIDDEN",
  "message": "Acceso denegado - Solo lectura permitida"
}
```

### 429 Rate Limit Exceeded

```json
{
  "status": "error",
  "code": "RATE_LIMIT_EXCEEDED",
  "message": "Límite de requests excedido",
  "retry_after": 60
}
```

---

## 📞 Soporte

- **Email:** api-support@govllm-sentinel.gov
- **Documentación:** https://docs.govllm-sentinel.gov
- **Estado del servicio:** https://status.govllm-sentinel.gov

---

<div align="center">

**[⬆ Volver al Dashboard](../public/index.html)**

</div>
