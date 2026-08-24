# 🔒 Auditoría de Seguridad — Backend FastAPI
## GovLLM-Sentinel v2.0

---

**Fecha:** 24 de Agosto, 2026  
**Auditor:** Buffy (Codebuff/Freebuff)  
**Alcance:** 02-FRAMEWORK/* (Backend Completo)  
**Clasificación:** CONFIDENCIAL — Solo para entidades autorizadas

---

## 📋 Resumen Ejecutivo

| Métrica | Valor |
|---------|-------|
| **Vulnerabilidades Totales** | 12 |
| **Críticas** | 2 |
| **Altas** | 4 |
| **Medias** | 4 |
| **Bajas** | 2 |
| **Puntuación de Seguridad** | 45/100 (CRÍTICO) |

### ⚠️ Hallazgos Críticos

1. **CORS permisivo** — `allow_origins=["*"]` permite cualquier origen
2. **Sin autenticación** — Todos los endpoints son públicos
3. **API keys en logs** — Posible exposición de credenciales
4. **Rate limiting ausente** — Sin límite de requests

---

## 🚨 Vulnerabilidades CRÍTICAS (2)

### VULN-B001: CORS Permiso Total
**Archivo:** `main.py` Línea 107-112  
**Severidad:** CRÍTICA  
**CVSS:** 9.1

**Descripción:**
La configuración CORS permite cualquier origen, método y header:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # ⚠️ PELIGROSO
    allow_credentials=True,    # ⚠️ Combinado con * es peor
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Impacto:**
- Ataques CSRF desde cualquier sitio
- Robo de datos sensibles
- Ejecución de acciones no autorizadas

**Remediación:**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://govllm-sentinel.gov",
        "https://dashboard.govllm-sentinel.gov",
        "http://localhost:3000",  # Solo desarrollo
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)
```

---

### VULN-B002: Sin Autenticación/Authorization
**Archivo:** `main.py` (todos los endpoints)  
**Severidad:** CRÍTICA  
**CVSS:** 9.0

**Descripción:**
Ningún endpoint requiere autenticación. Cualquier usuario puede:
- Escanear textos ilimitadamente
- Ejecutar red teaming
- Acceder a estadísticas del sistema

**Impacto:**
- Abuso del servicio
- Consumo de recursos excesivo
- Acceso no autorizado a funcionalidades sensibles

**Remediación:**
```python
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if not validate_token(token):
        raise HTTPException(status_code=401, detail="Token inválido")
    return token

@app.post("/api/v1/scan/pii")
async def scan_pii(request: ScanRequest, token: str = Depends(verify_token)):
    # ...
```

---

## 🔴 Vulnerabilidades ALTAS (4)

### VULN-B003: Rate Limiting Ausente
**Archivo:** `main.py`  
**Severidad:** ALTA  
**CVSS:** 7.5

**Descripción:**
No hay límite de requests por usuario o IP. Un atacante puede:
- Sobrecargar el servidor (DoS)
- Agotar cuotas de APIs externas
- Generar costos elevados

**Remediación:**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/api/v1/scan/full")
@limiter.limit("30/minute")
async def scan_full(request: Request, ...):
    # ...
```

---

### VULN-B004: Información de Versión Expuesta
**Archivo:** `main.py` Línea 104, 340, 360  
**Severidad:** ALTA  
**CVSS:** 6.5

**Descripción:**
La versión del framework es visible en múltiples endpoints:
```python
app = FastAPI(version="1.0.0", ...)

return {"version": "1.0.0", ...}  # Health check
return {"version": "1.0.0", ...}  # Root endpoint
```

**Impacto:**
- Facilita fingerprinting
- Ayuda a encontrar vulnerabilidades conocidas

**Remediación:**
```python
import os

APP_VERSION = os.getenv("APP_VERSION", "1.0.0")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "GovLLM-Sentinel",
        # No exponer versión en producción
    }
```

---

### VULN-B005: API Key en Request Body
**Archivo:** `main.py` Línea 88-92  
**Severidad:** ALTA  
**CVSS:** 7.0

**Descripción:**
La API key se recibe en el body de la request:
```python
class RedTeamRequest(BaseModel):
    api_key: Optional[str] = Field(None, description="API key")
```

**Impacto:**
- Puede quedar en logs del servidor
- Visible en historial de navegación
- Expuesta en proxies intermediarios

**Remediación:**
```python
@app.post("/api/v1/redteam/run")
async def run_redteam(
    request: RedTeamRequest,
    api_key: str = Header(..., alias="X-API-Key")
):
    # Usar header en vez de body
```

---

### VULN-B006: Logs sin Sanitización
**Archivo:** `main.py` (implícito)  
**Severidad:** ALTA  
**CVSS:** 6.8

**Descripción:**
Los logs pueden contener:
- API keys en requests
- PII en textos escaneados
- Tokens de autenticación

**Impacto:**
- Exposición de datos sensibles
- Violación de GDPR/LDPD
- Riesgo de auditoría

**Remediación:**
```python
from loguru import logger

def sanitize_log_data(data: dict) -> dict:
    sensitive_keys = ["api_key", "password", "token", "secret"]
    sanitized = data.copy()
    for key in sanitized:
        if any(s in key.lower() for s in sensitive_keys):
            sanitized[key] = "***REDACTED***"
    return sanitized

logger.info("Request received", extra={"data": sanitize_log_data(request.dict())})
```

---

## 🟡 Vulnerabilidades MEDIAS (4)

### VULN-B007: Sin Security Headers
**Archivo:** `main.py`  
**Severidad:** MEDIA  
**CVSS:** 5.5

**Remediación:**
```python
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response
```

---

### VULN-B008: Sin Request ID/Tracing
**Archivo:** `main.py`  
**Severidad:** MEDIA  
**CVSS:** 4.5

**Remediación:**
```python
import uuid

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response
```

---

### VULN-B009: Error Messages Detallados
**Archivo:** `main.py`  
**Severidad:** MEDIA  
**CVSS:** 5.0

**Descripción:**
Los errores pueden exponer información interna:
```python
raise HTTPException(status_code=400, detail=f"Categoría inválida: {e}")
```

**Remediación:**
```python
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Error interno del servidor"}
    )
```

---

### VULN-B010: Sin Input Size Limit
**Archivo:** `main.py`  
**Severidad:** MEDIA  
**CVSS:** 5.0

**Descripción:**
El campo `text` no tiene límite de tamaño definido:
```python
class ScanRequest(BaseModel):
    text: str = Field(..., description="Texto a escanear")
```

**Remediación:**
```python
class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)
```

---

## 🟢 Vulnerabilidades BAJAS (2)

### VULN-B011: Docs URL Público
**Archivo:** `main.py` Línea 104  
**Severidad:** BAJA  
**CVSS:** 3.5

```python
app = FastAPI(docs_url="/docs", redoc_url="/redoc")
```

**Remediación:**
```python
import os

app = FastAPI(
    docs_url="/docs" if os.getenv("ENV") != "production" else None,
    redoc_url="/redoc" if os.getenv("ENV") != "production" else None,
)
```

---

### VULN-B012: Host Binding Abierto
**Archivo:** `main.py` Línea 392  
**Severidad:** BAJA  
**CVSS:** 3.0

```python
uvicorn.run("main:app", host="0.0.0.0", port=8000)
```

**Remediación:**
```python
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("ENV") == "development",
    )
```

---

## 📊 Distribución por Categoría

| Categoría | Crítica | Alta | Media | Baja | Total |
|-----------|---------|------|-------|------|-------|
| Auth/AuthZ | 1 | 1 | 0 | 0 | 2 |
| Configuration | 1 | 2 | 2 | 2 | 7 |
| Input Validation | 0 | 0 | 1 | 0 | 1 |
| Logging | 0 | 1 | 0 | 0 | 1 |
| Information Disclosure | 0 | 0 | 1 | 0 | 1 |
| **Total** | **2** | **4** | **4** | **2** | **12** |

---

## ✅ Controles Existentes (Positivos)

| Control | Estado | Notas |
|---------|--------|-------|
| Pydantic Validation | ✅ | Modelos tipados |
| Error Handling | ⚠️ | Parcial (HTTPException) |
| CORS Configured | ⚠️ | Presente pero permisivo |
| Health Check | ✅ | Implementado |
| Structured Logging | ✅ | Loguru disponible |
| Type Hints | ✅ | Bien implementado |

---

## 🛡️ Recomendaciones Prioritarias

### Inmediatas (Esta semana)
1. **FIX VULN-B001** — Restringir CORS a orígenes específicos
2. **FIX VULN-B002** — Implementar autenticación básica
3. **FIX VULN-B003** — Agregar rate limiting

### Corto Plazo (1-2 semanas)
4. **FIX VULN-B004** — Ocultar versión en producción
5. **FIX VULN-B005** — Mover API key a header
6. **FIX VULN-B006** — Sanitizar logs

### Mediano Plazo (1 mes)
7. **FIX VULN-B007** — Agregar security headers
8. **FIX VULN-B010** — Validar tamaño de input
9. Implementar auditoría de dependencias

---

## 🔧 Plan de Remediación

| Prioridad | Vulnerabilidad | Esfuerzo | Impacto | Estado |
|-----------|----------------|----------|---------|--------|
| P0 | VULN-B001 (CORS) | Bajo | Alto | ⏳ PENDIENTE |
| P0 | VULN-B002 (No Auth) | Alto | Alto | ⏳ PENDIENTE |
| P1 | VULN-B003 (No Rate Limit) | Medio | Alto | ⏳ PENDIENTE |
| P1 | VULN-B004 (Version Exposed) | Bajo | Medio | ⏳ PENDIENTE |
| P1 | VULN-B005 (API Key in Body) | Bajo | Alto | ⏳ PENDIENTE |
| P1 | VULN-B006 (Logs sin sanitizar) | Medio | Alto | ⏳ PENDIENTE |
| P2 | VULN-B007 (No Security Headers) | Bajo | Medio | ⏳ PENDIENTE |
| P2 | VULN-B008 (No Request ID) | Bajo | Bajo | ⏳ PENDIENTE |
| P2 | VULN-B009 (Error Messages) | Bajo | Medio | ⏳ PENDIENTE |
| P2 | VULN-B010 (No Input Limit) | Bajo | Medio | ⏳ PENDIENTE |
| P3 | VULN-B011 (Docs Público) | Bajo | Bajo | ⏳ PENDIENTE |
| P3 | VULN-B012 (Host Abierto) | Bajo | Bajo | ⏳ PENDIENTE |

---

## 📝 Notas del Auditor

1. **Urgencia:** El backend tiene vulnerabilidades críticas que deben corregirse ANTES de producción.

2. **Dependencias:** Se recomienda ejecutar `pip-audit` o `safety check` para revisar vulnerabilidades en dependencias.

3. **Pruebas:** Ejecutar `pytest tests/` para verificar que los cambios no rompen funcionalidad.

4. **Próximos Pasos:**
   - Implementar autenticación JWT
   - Configurar WAF
   - Agregar monitoreo de seguridad
   - Revisar dependencias

---

**Firma del Auditor:** Buffy (Codebuff/Freebuff)  
**Fecha:** 2026-08-24  
**Próxima Revisión:** 2026-09-07 (2 semanas)

---

<div align="center">

**[⬆ Volver al Framework](main.py)** | **[📄 Ver Auditoría Frontend](../04-DASHBOARD/SECURITY-AUDIT-2026-08-24.md)**

</div>
