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

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
import uvicorn

# Imports del framework
from defenses.pii_guard import PIIGuard
from defenses.compliance_filter import ComplianceFilter
from defenses.alignment_module import AlignmentModule
from attacks.automated_redteam import RedTeamRunner, AttackCategory


# ═══════════════════════════════════════════════════════════════════
# MODELOS PYDANTIC
# ═══════════════════════════════════════════════════════════════════

class ScanRequest(BaseModel):
    """Request para escaneo de texto."""
    text: str = Field(..., description="Texto a escanear")
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
    """Request para ejecutar red teaming."""
    model_name: str = Field(..., description="Nombre del modelo a evaluar")
    mode: str = Field("mock", description="Modo: 'mock' o 'live'")
    api_key: Optional[str] = Field(None, description="API key (requerido para modo live)")
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
# APLICACIÓN FASTAPI
# ═══════════════════════════════════════════════════════════════════

app = FastAPI(
    title="GovLLM-Sentinel",
    description="Framework de Evaluación y Hardening de LLMs para el Sector Público",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instancias globales
pii_guard = PIIGuard()
compliance_filter = ComplianceFilter()
alignment_module = AlignmentModule()


# ═══════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Health check del sistema."""
    return {
        "status": "healthy",
        "service": "GovLLM-Sentinel",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/api/v1/scan/pii", response_model=PIIScanResponse)
async def scan_pii(request: ScanRequest):
    """
    Escanea un texto en busca de datos de identificación personal (PII).
    
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
async def scan_compliance(request: ScanRequest):
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
async def scan_alignment(request: ScanRequest):
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
async def scan_full(request: ScanRequest):
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
async def run_redteam(request: RedTeamRequest):
    """
    Ejecuta batería completa de pruebas de red teaming.
    
    Modos:
    - mock: Ejecuta patrones contra backend mock (demostración)
    - live: Conecta a API real del modelo (requiere api_key)
    
    ⚠️ REQUIERE CONTRATO DE AUTORIZACIÓN VÁLIDO para modo live
    """
    # Validar modo live
    if request.mode == "live" and not request.api_key:
        raise HTTPException(
            status_code=400,
            detail="api_key es requerido para modo live"
        )
    
    # Convertir categorías
    categories = None
    if request.categories:
        try:
            categories = [AttackCategory(cat) for cat in request.categories]
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Categoría inválida: {e}"
            )
    
    # Ejecutar red teaming
    runner = RedTeamRunner(
        mode=request.mode,
        api_key=request.api_key or "",
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
async def get_stats():
    """Retorna estadísticas acumuladas del sistema."""
    return {
        "pii_guard": pii_guard.get_violation_stats(),
        "compliance_filter": compliance_filter.get_violation_stats(),
        "alignment_module": {
            "total_scans": alignment_module.scan_count,
        },
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/")
async def root():
    """Información del API."""
    return {
        "service": "GovLLM-Sentinel API",
        "version": "1.0.0",
        "description": "Framework de Evaluación y Hardening de LLMs para el Sector Público",
        "docs": "/docs",
        "endpoints": {
            "scan_pii": "/api/v1/scan/pii",
            "scan_compliance": "/api/v1/scan/compliance",
            "scan_alignment": "/api/v1/scan/alignment",
            "scan_full": "/api/v1/scan/full",
            "redteam": "/api/v1/redteam/run",
            "stats": "/api/v1/stats",
        },
    }


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
