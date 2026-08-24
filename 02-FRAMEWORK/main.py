"""
GovLLM-Sentinel - Aplicación Principal FastAPI

Framework de Evaluación y Hardening de LLMs para el Sector Público.

Endpoints:
- /api/v1/scan/pii - Escaneo de PII
- /api/v1/scan/compliance - Escaneo de cumplimiento
- /api/v1/scan/alignment - Verificación de alineación
- /api/v1/scan/full - Escaneo completo (PII + Compliance + Alignment)
- /api/v1/redteam/run - Ejecutar red teaming automatizado
- /api/v1/stats - Estadísticas del sistema
- /health - Health check

⚠️ REQUIERE CONTRATO DE AUTORIZACIÓN VÁLIDO para operaciones de red teaming

Uso:
    # Desarrollo
    uvicorn main:app --reload
    
    # Producción
    uvicorn main:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict
from time import time
import uvicorn
import os
import secrets
import uuid

# Imports del framework
from defenses.pii_guard import PIIGuard
from defenses.compliance_filter import ComplianceFilter
from defenses.alignment_module import AlignmentModule
from attacks.automated_redteam import RedTeamRunner, AttackCategory
from auth import (
    verify_token, create_token, authenticate_user,
    TokenRequest, TokenResponse, require_permission,
    get_public_users, JWT_EXPIRY_MINUTES
)
from monitoring import (
    security_monitor, record_auth_event, record_rate_limit_event,
    record_injection_attempt, SecurityEvent, AlertLevel
)
from report_export import ReportExporter
from fastapi.responses import HTMLResponse
import logging
import re


# ═══════════════════════════════════════════════════════════════════
# SECURE LOGGER (VULN-B006 fix)
# ═══════════════════════════════════════════════════════════════════

logger = logging.getLogger("govllm-sentinel")

# Sensitive patterns to redact in logs
SENSITIVE_PATTERNS = {
    "api_key": re.compile(r'(api[_-]?key["\':=\s]*["\']?)[\w-]{20,}', re.IGNORECASE),
    "email": re.compile(r'[\w.-]+@[\w.-]+\.\w+'),
    "curp": re.compile(r'[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z\d]\d'),
    "rfc": re.compile(r'[A-Z&]{3,4}\d{6}[A-Z\d]{3}'),
    "credit_card": re.compile(r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}'),
    "ssn": re.compile(r'\d{3}-\d{2}-\d{4}'),
    "password": re.compile(r'(password["\':=\s]*["\']?)[^"\s,]+', re.IGNORECASE),
    "token": re.compile(r'(token["\':=\s]*["\']?)[\w.-]{20,}', re.IGNORECASE),
}

def sanitize_for_log(data: Any) -> Any:
    """Sanitize sensitive data for logging.
    
    VULN-B006 fix: Remove PII, API keys, and credentials from logs.
    """
    if isinstance(data, str):
        sanitized = data
        for name, pattern in SENSITIVE_PATTERNS.items():
            sanitized = pattern.sub('[REDACTED]', sanitized)
        return sanitized
    elif isinstance(data, dict):
        return {k: sanitize_for_log(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_for_log(item) for item in data]
    return data

def log_request(method: str, path: str, status_code: int = None, duration_ms: float = None, client_ip: str = None):
    """Log request with sanitized data."""
    msg = f"{method} {path}"
    if status_code:
        msg += f" -> {status_code}"
    if duration_ms is not None:
        msg += f" ({duration_ms:.1f}ms)"
    if client_ip:
        msg += f" from {client_ip}"
    logger.info(msg)


# ═══════════════════════════════════════════════════════════════════
# MODELOS PYDANTIC
# ═══════════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    """Request para escaneo de texto.
    
    VULN-B010 fix: Add input size limits.
    """
    text: str = Field(..., min_length=1, max_length=10000, description="Texto a escanear (max 10,000 chars)")
    context: Optional[Dict[str, Any]] = Field(None, description="Contexto adicional")

class PIIScanResponse(BaseModel):
    """Response de escaneo PII."""
    scan_id: str
    detected: bool
    total_violations: int
    violations_by_severity: Dict[str, int]
    violations: List[Dict[str, Any]]
    action: str
    scan_duration_ms: float

class ComplianceScanResponse(BaseModel):
    """Response de escaneo de cumplimiento."""
    scan_id: str
    detected: bool
    total_violations: int
    violations_by_type: Dict[str, int]
    violations: List[Dict[str, Any]]
    action: str
    scan_duration_ms: float

class AlignmentScanResponse(BaseModel):
    """Response de verificación de alineación."""
    scan_id: str
    overall_compliant: bool
    overall_score: float
    pre_filter: Dict[str, Any]
    post_analysis: Dict[str, Any]
    recommended_strategy: str

class FullScanResponse(BaseModel):
    """Response de escaneo completo."""
    scan_id: str
    timestamp: str
    pii: PIIScanResponse
    compliance: ComplianceScanResponse
    alignment: AlignmentScanResponse
    overall_action: str
    safe_text: Optional[str]

class RedTeamRequest(BaseModel):
    """Request para ejecutar red teaming.
    
    VULN-B005 fix: api_key se recibe via header X-API-Key
    """
    model_name: str = Field(..., description="Nombre del modelo a evaluar")
    mode: str = Field("mock", description="Modo: 'mock' o 'live'")
    # api_key se recibe via header X-API-Key (VULN-B005 fix)
    provider: str = Field("openai", description="Proveedor: 'openai' o 'anthropic'")
    categories: Optional[List[str]] = Field(None, description="Categorías específicas a probar")

class RedTeamReportResponse(BaseModel):
    """Response de reporte de red teaming."""
    report_id: str
    model_name: str
    execution_mode: str
    total_tests: int
    total_vulnerable: int
    total_resistant: int
    overall_resistance: float
    security_grade: str
    top_vulnerabilities: List[Dict[str, Any]]
    recommendations: List[str]
    total_duration_ms: float


# ═══════════════════════════════════════════════════════════════════
# CONFIGURACIÓN DE SEGURIDAD (VULN-B001, VULN-B003 fix)
# ═══════════════════════════════════════════════════════════════════

ENV = os.getenv("ENV", "development")

# CORS - VULN-B001 fix: Orígenes restringidos
ALLOWED_ORIGINS = {
    "development": [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ],
    "staging": [
        "https://staging.govllm-sentinel.gov",
        "https://staging-dashboard.govllm-sentinel.gov",
    ],
    "production": [
        "https://govllm-sentinel.gov",
        "https://dashboard.govllm-sentinel.gov",
    ],
}

cors_origins = ALLOWED_ORIGINS.get(ENV, ALLOWED_ORIGINS["development"])

# Rate Limiting - VULN-B003 fix
class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self, requests_per_minute: int = 60, requests_per_hour: int = 1000):
        self.rpm = requests_per_minute
        self.rph = requests_per_hour
        self.requests = defaultdict(list)
    
    def is_allowed(self, client_id: str) -> tuple[bool, dict]:
        now = time()
        
        # Clean old requests
        self.requests[client_id] = [
            t for t in self.requests[client_id] if now - t < 3600
        ]
        
        # Count requests in last minute and hour
        last_minute = sum(1 for t in self.requests[client_id] if now - t < 60)
        last_hour = len(self.requests[client_id])
        
        # Check limits
        if last_minute >= self.rpm:
            return False, {
                "error": "Rate limit exceeded",
                "retry_after": 60,
                "limit": self.rpm,
                "window": "minute"
            }
        
        if last_hour >= self.rph:
            return False, {
                "error": "Hourly rate limit exceeded",
                "retry_after": 3600,
                "limit": self.rph,
                "window": "hour"
            }
        
        # Record request
        self.requests[client_id].append(now)
        
        return True, {
            "limit": self.rpm,
            "remaining": self.rpm - last_minute - 1,
            "window": "minute"
        }

# Rate limiter instance
rate_limiter = RateLimiter(
    requests_per_minute=int(os.getenv("RATE_LIMIT_RPM", "60")),
    requests_per_hour=int(os.getenv("RATE_LIMIT_RPH", "1000"))
)


# ═══════════════════════════════════════════════════════════════════
# APLICACIÓN FASTAPI
# ═══════════════════════════════════════════════════════════════════

app = FastAPI(
    title="GovLLM-Sentinel",
    description="Framework de Evaluación y Hardening de LLMs para el Sector Público",
    version="1.0.0",  # Required by FastAPI, but not exposed in responses
    docs_url="/docs" if ENV != "production" else None,
    redoc_url="/redoc" if ENV != "production" else None,
)# CORS - VULN-B001 fix: Orígenes restringidos
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


# ═══════════════════════════════════════════════════════════════════
# SECURITY MIDDLEWARE (VULN-B007 fix)
# ═══════════════════════════════════════════════════════════════════

@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    if ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    # Rate limit headers
    client_ip = request.client.host if request.client else "unknown"
    allowed, rate_info = rate_limiter.is_allowed(client_ip)
    
    response.headers["X-RateLimit-Limit"] = str(rate_info.get("limit", 60))
    response.headers["X-RateLimit-Remaining"] = str(rate_info.get("remaining", 0))
    
    if not allowed:
        # Record rate limit event for monitoring
        record_rate_limit_event(client_ip, exceeded=True)
        
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "detail": rate_info.get("error", "Too many requests"),
                "retry_after": rate_info.get("retry_after", 60)
            },
            headers={
                "Retry-After": str(rate_info.get("retry_after", 60)),
                "X-RateLimit-Limit": str(rate_info.get("limit", 60)),
                "X-RateLimit-Remaining": "0",
            }
        )
    
    return response


# ═══════════════════════════════════════════════════════════════════
# REQUEST ID MIDDLEWARE (VULN-B008 fix)
# ═══════════════════════════════════════════════════════════════════

@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """Add unique request ID for tracing.
    
    VULN-B008 fix: Generate unique ID for each request.
    """
    # Generate unique request ID
    request_id = str(uuid.uuid4())
    
    # Store in request state for use in endpoints
    request.state.request_id = request_id
    
    # Process request
    response = await call_next(request)
    
    # Add request ID to response headers
    response.headers["X-Request-ID"] = request_id
    
    return response


# ═══════════════════════════════════════════════════════════════════
# REQUEST LOGGING MIDDLEWARE (VULN-B006 fix)
# ═══════════════════════════════════════════════════════════════════

@app.middleware("http")
async def request_logging(request: Request, call_next):
    """Log all requests with sanitized data.
    
    VULN-B006 fix: Sanitize sensitive data in logs.
    VULN-B008 fix: Include request ID in logs.
    """
    start_time = time()
    client_ip = request.client.host if request.client else "unknown"
    request_id = getattr(request.state, 'request_id', 'unknown')
    
    # Get request body safely
    body = None
    if request.method == "POST":
        try:
            body_bytes = await request.body()
            body = sanitize_for_log(body_bytes.decode()) if body_bytes else None
        except Exception:
            body = "[Could not read body]"
    
    # Log incoming request with request ID
    logger.info(f"[{request_id}] {request.method} {request.url.path} from {client_ip}")
    
    # Process request
    try:
        response = await call_next(request)
    except Exception as e:
        # Log error (sanitized) with request ID
        duration_ms = (time() - start_time) * 1000
        logger.error(f"[{request_id}] Request failed: {request.method} {request.url.path} - {sanitize_for_log(str(e))} ({duration_ms:.1f}ms)")
        raise
    
    # Calculate duration
    duration_ms = (time() - start_time) * 1000
    
    # Log response with request ID
    logger.info(f"[{request_id}] {request.method} {request.url.path} -> {response.status_code} ({duration_ms:.1f}ms)")
    
    return response


# ═══════════════════════════════════════════════════════════════════
# GLOBAL EXCEPTION HANDLER (VULN-B009 fix)
# ═══════════════════════════════════════════════════════════════════

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with safe error messages.
    
    VULN-B009 fix: Don't expose internal details.
    """
    # Log the actual error (sanitized)
    logger.warning(f"HTTP {exc.status_code}: {sanitize_for_log(str(exc.detail))} - {request.url.path}")
    
    # Return safe error message
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "status_code": exc.status_code,
            "detail": str(exc.detail) if exc.status_code < 500 else "Internal server error",
            "path": request.url.path,
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all uncaught exceptions safely.
    
    VULN-B009 fix: Never expose internal error details to clients.
    """
    # Log full error internally (sanitized)
    logger.error(
        f"Unhandled exception: {sanitize_for_log(str(exc))} - "
        f"{request.method} {request.url.path}",
        exc_info=True
    )
    
    # Return generic error to client
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "status_code": 500,
            "detail": "Internal server error",
            "message": "An unexpected error occurred. Please try again later.",
        }
    )


# ═══════════════════════════════════════════════════════════════════
# INSTANCIAS GLOBALES
# ═══════════════════════════════════════════════════════════════════
pii_guard = PIIGuard()
compliance_filter = ComplianceFilter()
alignment_module = AlignmentModule()


# ═══════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Health check del sistema.
    
    VULN-B004 fix: No exponer versión en producción
    """
    response = {
        "status": "healthy",
        "service": "GovLLM-Sentinel",
        "timestamp": datetime.now().isoformat(),
    }
    
    # Solo mostrar versión en desarrollo
    if ENV == "development":
        response["version"] = os.getenv("APP_VERSION", "1.0.0")
    
    return response


@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(request: TokenRequest, fastapi_request: Request):
    """
    Authenticate user and return JWT token.
    
    VULN-B002 fix: Authentication endpoint.
    
    Default users:
    - admin / admin123 (full access)
    - analyst / analyst123 (read/write)
    - viewer / viewer123 (read only)
    """
    user = authenticate_user(request.username, request.password)
    
    # Get client IP for monitoring
    client_ip = fastapi_request.client.host if fastapi_request.client else "unknown"
    
    if not user:
        # Record failed authentication
        record_auth_event(False, request.username, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Record successful authentication
    record_auth_event(True, request.username, client_ip)
    
    # Generate token
    token = create_token(user)
    
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=JWT_EXPIRY_MINUTES * 60,
        user={
            "username": user["username"],
            "role": user["role"]
        }
    )


@app.get("/api/v1/auth/me")
async def get_current_user(user: dict = Depends(verify_token)):
    """Get current authenticated user info."""
    return {
        "username": user["username"],
        "role": user["role"],
        "permissions": user["permissions"]
    }


@app.get("/api/v1/auth/users")
async def list_users(user: dict = Depends(require_permission("admin"))):
    """List all users (admin only)."""
    return {"users": get_public_users()}


@app.post("/api/v1/scan/pii", response_model=PIIScanResponse)
async def scan_pii(
    request: ScanRequest,
    user: dict = Depends(require_permission("read"))
):
    """
    Escanea un texto en busca de datos de identificación personal (PII).
    
    VULN-B002 fix: Requires authentication.
    
    Detecta:
    - Documentos de identidad (CURP, RFC, DNI, pasaportes)
    - Información financiera (tarjetas, cuentas bancarias)
    - Datos de contacto (emails, teléfonos)
    - Información gubernamental sensible
    """
    result = pii_guard.scan_input(request.text, request.context)
    
    return PIIScanResponse(
        scan_id=result.scan_id,
        detected=result.detected,
        total_violations=result.total_violations,
        violations_by_severity=result.violations_by_severity,
        violations=[v.to_dict() for v in result.violations],
        action=result.action,
        scan_duration_ms=result.scan_duration_ms,
    )


@app.post("/api/v1/scan/compliance", response_model=ComplianceScanResponse)
async def scan_compliance(
    request: ScanRequest,
    user: dict = Depends(require_permission("read"))
):
    """
    Escanea un texto en busca de violaciones de cumplimiento normativo.
    
    Detecta:
    - Secretos de Estado y patrones de acceso
    - Manipulación geopolítica
    - Violasiones de soberanía territorial
    - Ataques a la neutralidad institucional
    """
    result = compliance_filter.scan(request.text, request.context)
    
    return ComplianceScanResponse(
        scan_id=result.scan_id,
        detected=result.detected,
        total_violations=result.total_violations,
        violations_by_type=result.violations_by_type,
        violations=[v.to_dict() for v in result.violations],
        action=result.action,
        scan_duration_ms=result.scan_duration_ms,
    )


@app.post("/api/v1/scan/alignment", response_model=AlignmentScanResponse)
async def scan_alignment(
    request: ScanRequest,
    user: dict = Depends(require_permission("read"))
):
    """
    Verifica la alineación de un texto con principios institucionales.
    
    Análisis:
    - Neutralidad institucional
    - Rechazo de premisas falsas
    - Ausencia de sesgo
    - Tono apropiado
    """
    result = alignment_module.analyze(request.text, "", request.context)
    
    return AlignmentScanResponse(
        scan_id=result.scan_id,
        overall_compliant=result.overall_compliant,
        overall_score=result.overall_score,
        pre_filter={
            "violations": [v.to_dict() for v in result.pre_filter_violations],
            "action": result.pre_filter_action,
        },
        post_analysis={
            "violations": [v.to_dict() for v in result.post_analysis_violations],
            "action": result.post_analysis_action,
        },
        recommended_strategy=result.recommended_response_strategy,
    )


@app.post("/api/v1/scan/full", response_model=FullScanResponse)
async def scan_full(
    request: ScanRequest,
    user: dict = Depends(require_permission("read"))
):
    """
    Escaneo completo: PII + Compliance + Alignment.
    
    Ejecuta todos los filtros de seguridad y retorna un reporte consolidado.
    """
    scan_id = f"{pii_guard.scan_count}-{compliance_filter.scan_count}"
    
    # PII
    pii_result = pii_guard.scan_input(request.text, request.context)
    
    # Compliance
    compliance_result = compliance_filter.scan(request.text, request.context)
    
    # Alignment
    alignment_result = alignment_module.analyze(request.text, "", request.context)
    
    # Determinar acción general
    actions = [pii_result.action, compliance_result.action]
    if pii_result.action == "block" or compliance_result.action == "block":
        overall_action = "block"
    elif "mask" in actions or "escalate" in actions:
        overall_action = "review"
    else:
        overall_action = "allow"
    
    # Texto seguro
    safe_text = pii_result.get_masked_text() if pii_result.detected else None
    
    return FullScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now().isoformat(),
        pii=PIIScanResponse(
            scan_id=pii_result.scan_id,
            detected=pii_result.detected,
            total_violations=pii_result.total_violations,
            violations_by_severity=pii_result.violations_by_severity,
            violations=[v.to_dict() for v in pii_result.violations],
            action=pii_result.action,
            scan_duration_ms=pii_result.scan_duration_ms,
        ),
        compliance=ComplianceScanResponse(
            scan_id=compliance_result.scan_id,
            detected=compliance_result.detected,
            total_violations=compliance_result.total_violations,
            violations_by_type=compliance_result.violations_by_type,
            violations=[v.to_dict() for v in compliance_result.violations],
            action=compliance_result.action,
            scan_duration_ms=compliance_result.scan_duration_ms,
        ),
        alignment=AlignmentScanResponse(
            scan_id=alignment_result.scan_id,
            overall_compliant=alignment_result.overall_compliant,
            overall_score=alignment_result.overall_score,
            pre_filter={
                "violations": [v.to_dict() for v in alignment_result.pre_filter_violations],
                "action": alignment_result.pre_filter_action,
            },
            post_analysis={
                "violations": [v.to_dict() for v in alignment_result.post_analysis_violations],
                "action": alignment_result.post_analysis_action,
            },
            recommended_strategy=alignment_result.recommended_response_strategy,
        ),
        overall_action=overall_action,
        safe_text=safe_text,
    )


@app.post("/api/v1/redteam/run", response_model=RedTeamReportResponse)
async def run_redteam(
    request: RedTeamRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    user: dict = Depends(require_permission("redteam"))
):
    """
    Ejecuta batería completa de pruebas de red teaming.
    
    Modos:
    - mock: Ejecuta patrones contra backend mock (demostración)
    - live: Conecta a API real del modelo (requiere api_key)
    
    ⚠️ REQUIERE CONTRATO DE AUTORIZACIÓN VÁLIDO para modo live
    
    VULN-B005 fix: api_key se recibe via header X-API-Key
    """
    # Validar modo live - VULN-B005 fix: usar header
    api_key = x_api_key
    if request.mode == "live" and not api_key:
        raise HTTPException(
            status_code=400,
            detail="Header X-API-Key es requerido para modo live"
        )
    
    # Convertir categorías
    categories = None
    if request.categories:
        try:
            categories = [AttackCategory(cat) for cat in request.categories]
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Categoría inválida"
            )
    
    # Ejecutar red teaming
    runner = RedTeamRunner(
        mode=request.mode,
        api_key=api_key or "",
        model=request.model_name,
        provider=request.provider,
    )
    
    report = runner.run_all_tests(request.model_name, categories)
    
    return RedTeamReportResponse(
        report_id=report.report_id,
        model_name=report.model_name,
        execution_mode=report.execution_mode,
        total_tests=report.total_tests,
        total_vulnerable=report.total_vulnerable,
        total_resistant=report.total_resistant,
        overall_resistance=report.overall_resistance,
        security_grade=report.security_grade,
        top_vulnerabilities=report.top_vulnerabilities,
        recommendations=report.recommendations,
        total_duration_ms=report.total_duration_ms,
    )


@app.get("/api/v1/stats")
async def get_stats(user: dict = Depends(require_permission("read"))):
    """Retorna estadísticas acumuladas del sistema.
    
    VULN-B002 fix: Requires authentication.
    """
    return {
        "pii_guard": pii_guard.get_violation_stats(),
        "compliance_filter": compliance_filter.get_violation_stats(),
        "alignment_module": {
            "total_scans": alignment_module.scan_count,
        },
        "timestamp": datetime.now().isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════
# MONITORING ENDPOINTS (Security Monitoring)
# ═══════════════════════════════════════════════════════════════════

@app.get("/api/v1/security/dashboard")
async def security_dashboard(user: dict = Depends(require_permission("admin"))):
    """Get security monitoring dashboard data."""
    return security_monitor.get_dashboard()


@app.get("/api/v1/security/events")
async def security_events(
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    severity: Optional[str] = None,
    last_minutes: int = 60,
    limit: int = 100,
    user: dict = Depends(require_permission("admin"))
):
    """Get security events with filters."""
    return {
        "events": security_monitor.get_events(
            event_type=event_type,
            source_ip=source_ip,
            severity=severity,
            last_minutes=last_minutes,
            limit=limit
        ),
        "total": security_monitor.stats["total_events"]
    }


@app.get("/api/v1/security/alerts")
async def security_alerts(
    level: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    last_minutes: int = 60,
    user: dict = Depends(require_permission("admin"))
):
    """Get security alerts."""
    return {
        "alerts": security_monitor.get_alerts(
            level=level,
            acknowledged=acknowledged,
            last_minutes=last_minutes
        ),
        "unacknowledged_count": len([a for a in security_monitor.alerts if not a.acknowledged])
    }


@app.post("/api/v1/security/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    user: dict = Depends(require_permission("admin"))
):
    """Acknowledge a security alert."""
    success = security_monitor.acknowledge_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"success": True, "alert_id": alert_id}


@app.get("/api/v1/security/audit-log")
async def audit_log(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user: dict = Depends(require_permission("admin"))
):
    """Export audit log for compliance."""
    return {
        "events": security_monitor.export_audit_log(start_date, end_date),
        "total": len(security_monitor.events)
    }


@app.get("/api/v1/security/export/executive")
async def export_executive_report(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user: dict = Depends(require_permission("admin"))
):
    """Export executive security report as HTML."""
    exporter = ReportExporter(security_monitor)
    html = exporter.generate_executive_report(start_date, end_date)
    return HTMLResponse(content=html)


@app.get("/api/v1/security/export/events")
async def export_event_log(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    user: dict = Depends(require_permission("admin"))
):
    """Export detailed event log as HTML."""
    exporter = ReportExporter(security_monitor)
    html = exporter.generate_event_log(start_date, end_date, event_type, severity)
    return HTMLResponse(content=html)


@app.get("/")
async def root():
    """Información del API.
    
    VULN-B004 fix: No exponer versión en producción
    """
    response = {
        "service": "GovLLM-Sentinel API",
        "description": "Framework de Evaluación y Hardening de LLMs para el Sector Público",
        "endpoints": {
            "scan_pii": "/api/v1/scan/pii",
            "scan_compliance": "/api/v1/scan/compliance",
            "scan_alignment": "/api/v1/scan/alignment",
            "scan_full": "/api/v1/scan/full",
            "redteam": "/api/v1/redteam/run",
            "stats": "/api/v1/stats",
        },
    }
    
    # Solo mostrar docs y versión en desarrollo
    if ENV == "development":
        response["docs"] = "/docs"
        response["version"] = os.getenv("APP_VERSION", "1.0.0")
    
    return response


# ═══════════════════════════════════════════════════════════════════
# MAIN (VULN-B004, VULN-B012 fix)
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # VULN-B012 fix: Use environment variables for host and port
    host = os.getenv("HOST", "127.0.0.1" if ENV == "production" else "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload = ENV == "development"
    
    print(f"\n🛡️  GovLLM-Sentinel API")
    print(f"   Environment: {ENV}")
    print(f"   Host: {host}:{port}")
    print(f"   Docs: {'http://{}:{}/docs'.format(host, port) if reload else 'Disabled in production'}")
    print(f"\n")
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=reload,
    )
