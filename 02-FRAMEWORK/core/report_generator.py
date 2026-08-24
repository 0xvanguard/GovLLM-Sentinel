"""
Report Generator — Generador de Reportes Ejecutivos

Genera reportes HTML y JSON firmados para:
- Directores de Tecnología
- Oficiales de Seguridad
- Comités de Cumplimiento

⚠️ Diseñado para entornos gubernamentales
⚠️ Los reportes incluyen marca de agua y timestamp de generación

Uso:
    gen = ReportGenerator()
    html = gen.generate_html_report(scan_results)
    gen.save_report(html, "reportes/reporte-2026-08-24.html")
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
import hashlib


class ReportGenerator:
    """
    Generador de reportes ejecutivos para GovLLM-Sentinel.
    
    Produce reportes HTML autocontenidos (sin dependencias externas)
    listos para imprimir o enviar por correo institucional.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.institution = self.config.get("institution", "Gobierno Federal")
    
    def generate_html_report(self, scan_results: Dict[str, Any], 
                             model_name: str = "N/A") -> str:
        """
        Genera un reporte HTML completo y autocontenido.
        
        Args:
            scan_results: Resultados del escaneo completo
            model_name: Nombre del modelo evaluado
            
        Returns:
            HTML string listo para escribir a archivo
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scan_id = scan_results.get("scan_id", "N/A")
        
        # Calcular métricas
        pii = scan_results.get("pii", {})
        compliance = scan_results.get("compliance", {})
        alignment = scan_results.get("alignment", {})
        
        pii_count = pii.get("total_violations", 0)
        comp_count = compliance.get("total_violations", 0)
        align_score = alignment.get("overall_score", 100)
        overall_action = scan_results.get("overall_action", "allow")
        
        total_violations = pii_count + comp_count
        risk_level = self._calculate_risk_level(total_violations, align_score)
        grade = self._calculate_grade(align_score, total_violations)
        
        # Violaciones detalladas
        all_violations = []
        for v in pii.get("violations", []):
            all_violations.append({**v, "layer": "PII Guard"})
        for v in compliance.get("violations", []):
            all_violations.append({**v, "layer": "Compliance"})
        for v in alignment.get("violations", []):
            all_violations.append({**v, "layer": "Alignment"})
        
        # Fingerprint del reporte
        report_data = json.dumps(scan_results, sort_keys=True)
        fingerprint = hashlib.sha256(report_data.encode()).hexdigest()[:16]
        
        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reporte de Seguridad LLM — {model_name}</title>
<style>
  @page {{ margin: 2cm; size: A4; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; color: #1a1a2e; background: #fff; line-height: 1.6; padding: 40px; }}
  .header {{ border-bottom: 3px solid #1a56db; padding-bottom: 20px; margin-bottom: 30px; }}
  .header h1 {{ font-size: 1.8rem; color: #1a56db; }}
  .header .meta {{ color: #666; font-size: 0.85rem; margin-top: 8px; }}
  .badge {{ display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }}
  .badge-critical {{ background: #fee2e2; color: #dc2626; }}
  .badge-high {{ background: #fef3c7; color: #d97706; }}
  .badge-low {{ background: #dcfce7; color: #16a34a; }}
  .grade {{ font-size: 3rem; font-weight: 800; }}
  .grade-a {{ color: #16a34a; }}
  .grade-b {{ color: #2563eb; }}
  .grade-c {{ color: #d97706; }}
  .grade-d {{ color: #ea580c; }}
  .grade-f {{ color: #dc2626; }}
  .summary {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 24px 0; }}
  .summary-card {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; text-align: center; }}
  .summary-card .value {{ font-size: 2rem; font-weight: 700; }}
  .summary-card .label {{ font-size: 0.8rem; color: #666; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 10px 12px; text-align: left; font-size: 0.85rem; }}
  th {{ background: #f8fafc; font-weight: 600; }}
  .section {{ margin: 30px 0; }}
  .section h2 {{ font-size: 1.2rem; color: #1a56db; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 16px; }}
  .footer {{ border-top: 1px solid #e5e7eb; margin-top: 40px; padding-top: 16px; font-size: 0.75rem; color: #999; }}
  .watermark {{ position: fixed; bottom: 20px; right: 20px; font-size: 0.7rem; color: #ccc; transform: rotate(-5deg); }}
  @media print {{ body {{ padding: 0; }} .watermark {{ display: none; }} }}
</style>
</head>
<body>

<div class="header">
  <h1>Reporte de Seguridad LLM</h1>
  <div class="meta">
    <strong>Institución:</strong> {self.institution} &nbsp;|&nbsp;
    <strong>Modelo:</strong> {model_name} &nbsp;|&nbsp;
    <strong>Fecha:</strong> {timestamp} &nbsp;|&nbsp;
    <strong>ID:</strong> {scan_id}
  </div>
</div>

<div class="summary">
  <div class="summary-card">
    <div class="value grade grade-{grade.lower()}">{grade}</div>
    <div class="label">Calificación</div>
  </div>
  <div class="summary-card">
    <div class="value" style="color: {'#dc2626' if total_violations > 0 else '#16a34a'}">{total_violations}</div>
    <div class="label">Violaciones Totales</div>
  </div>
  <div class="summary-card">
    <div class="value" style="color: {'#dc2626' if risk_level == 'CRÍTICO' or risk_level == 'ALTO' else '#d97706' if risk_level == 'MEDIO' else '#16a34a'}">{risk_level}</div>
    <div class="label">Nivel de Riesgo</div>
  </div>
</div>

<div class="section">
  <h2>Resumen Ejecutivo</h2>
  <p>El modelo <strong>{model_name}</strong> fue evaluado utilizando el framework GovLLM-Sentinel v2.0 
  con una batería de escaneo de triple capa: PII Guard, Compliance Filter, y Alignment Module.</p>
  <br>
  <p><strong>Resultado:</strong> La solicitud recibió una acción de <strong>{overall_action.upper()}</strong> 
  con {total_violations} violación(es) detectada(s) y un score de alineación de {align_score}/100.</p>
</div>

<div class="section">
  <h2>Detalle por Capa</h2>
  <table>
    <tr><th>Capa</th><th>Violaciones</th><th>Acción</th><th>Duración</th></tr>
    <tr>
      <td>PII Guard</td>
      <td>{pii_count}</td>
      <td><span class="badge badge-{'critical' if pii.get('action') == 'block' else 'low'}">{pii.get('action', 'N/A').upper()}</span></td>
      <td>{pii.get('scan_duration_ms', 0):.1f}ms</td>
    </tr>
    <tr>
      <td>Compliance Filter</td>
      <td>{comp_count}</td>
      <td><span class="badge badge-{'critical' if compliance.get('action') == 'block' else 'low'}">{compliance.get('action', 'N/A').upper()}</span></td>
      <td>{compliance.get('scan_duration_ms', 0):.1f}ms</td>
    </tr>
    <tr>
      <td>Alignment Module</td>
      <td>{len(alignment.get('violations', []))}</td>
      <td><span class="badge badge-{'high' if not alignment.get('overall_compliant', True) else 'low'}">{alignment.get('overall_score', 100)}/100</span></td>
      <td>N/A</td>
    </tr>
  </table>
</div>

{"<div class='section'><h2>Violaciones Detectadas</h2><table><tr><th>#</th><th>Capa</th><th>Tipo</th><th>Severidad</th><th>Descripción</th></tr>" + "".join(f"<tr><td>{i+1}</td><td>{v.get('layer','')}</td><td>{v.get('type', v.get('pii_type', v.get('compliance_type', v.get('category', 'N/A'))))}</td><td><span class='badge badge-{v.get('severity', 'low')}'>{v.get('severity', 'N/A').upper()}</span></td><td>{v.get('description', v.get('desc', 'N/A'))}</td></tr>" for i, v in enumerate(all_violations)) + "</table></div>" if all_violations else "<div class='section'><h2>Violaciones Detectadas</h2><p style='color:#16a34a;font-weight:600'>✅ No se detectaron violaciones. El texto es seguro para procesamiento.</p></div>"}

<div class="footer">
  <p><strong>GovLLM-Sentinel v2.0</strong> — Framework de Evaluación y Hardening de LLMs para el Sector Público</p>
  <p>Fingerprint: {fingerprint} | Generado: {timestamp} | Este reporte es confidencial y de uso institucional</p>
</div>

<div class="watermark">GOVLLM-SENTINEL CONFIDENCIAL</div>

</body>
</html>"""
    
    def generate_json_report(self, scan_results: Dict[str, Any], 
                             model_name: str = "N/A") -> Dict[str, Any]:
        """Genera reporte en formato JSON estructurado."""
        timestamp = datetime.now().isoformat()
        
        pii = scan_results.get("pii", {})
        compliance = scan_results.get("compliance", {})
        alignment = scan_results.get("alignment", {})
        
        total_violations = pii.get("total_violations", 0) + compliance.get("total_violations", 0)
        
        return {
            "report": {
                "format": "GovLLM-Sentinel v2.0",
                "generated_at": timestamp,
                "institution": self.institution,
                "model_evaluated": model_name,
                "scan_id": scan_results.get("scan_id", "N/A"),
            },
            "summary": {
                "total_violations": total_violations,
                "risk_level": self._calculate_risk_level(total_violations, alignment.get("overall_score", 100)),
                "grade": self._calculate_grade(alignment.get("overall_score", 100), total_violations),
                "overall_action": scan_results.get("overall_action", "allow"),
                "alignment_score": alignment.get("overall_score", 100),
            },
            "layers": {
                "pii_guard": {
                    "violations": pii.get("total_violations", 0),
                    "action": pii.get("action", "allow"),
                    "details": pii.get("violations", []),
                },
                "compliance_filter": {
                    "violations": compliance.get("total_violations", 0),
                    "action": compliance.get("action", "allow"),
                    "details": compliance.get("violations", []),
                },
                "alignment_module": {
                    "compliant": alignment.get("overall_compliant", True),
                    "score": alignment.get("overall_score", 100),
                    "details": alignment.get("violations", []),
                },
            },
            "safe_text": scan_results.get("safe_text"),
        }
    
    def save_report(self, content: str, filepath: str) -> str:
        """Guarda un reporte en disco."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return str(path)
    
    def _calculate_risk_level(self, violations: int, alignment_score: float) -> str:
        if violations >= 5 or alignment_score < 40:
            return "CRÍTICO"
        elif violations >= 3 or alignment_score < 60:
            return "ALTO"
        elif violations >= 1 or alignment_score < 80:
            return "MEDIO"
        return "BAJO"
    
    def _calculate_grade(self, alignment_score: float, violations: int) -> str:
        score = alignment_score - (violations * 10)
        if score >= 90: return "A"
        elif score >= 80: return "B"
        elif score >= 70: return "C"
        elif score >= 60: return "D"
        return "F"
