"""
Realtime Monitor — Monitoreo en Tiempo Real

Servidor WebSocket que recibe y difunde eventos de escaneo en vivo.
Compatible con el dashboard HTML para actualizaciones instantáneas.

Uso:
    monitor = RealtimeMonitor()
    
    # Cuando hay un nuevo escaneo
    monitor.broadcast_scan(scan_result)
    
    # Cuando hay una alerta crítica
    monitor.broadcast_alert("CURP detectada en prompt de usuario #1234")
"""

import json
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Set, Optional
from dataclasses import dataclass, field


@dataclass
class ScanEvent:
    """Evento de escaneo para difusión en tiempo real."""
    event_id: str
    timestamp: str
    event_type: str  # "scan", "alert", "stats", "system"
    data: Dict[str, Any]
    
    def to_json(self) -> str:
        return json.dumps({
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "data": self.data,
        }, ensure_ascii=False)


class RealtimeMonitor:
    """
    Monitor en tiempo real con difusión WebSocket.
    
    Mantiene registro de:
    - Escaneos recientes (últimos 100)
    - Estadísticas acumuladas
    - Alertas críticas
    - Conexiones activas
    
    Uso:
        monitor = RealtimeMonitor()
        
        # Registrar escaneo
        event = monitor.register_scan(scan_result)
        
        # Obtener historial
        recent = monitor.get_recent_scans(limit=20)
        
        # Obtener stats
        stats = monitor.get_stats()
    """
    
    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self.scan_history: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.stats = {
            "total_scans": 0,
            "total_violations": 0,
            "total_blocked": 0,
            "scans_by_hour": {},
            "violations_by_type": {},
            "avg_latency_ms": 0,
        }
        self._event_counter = 0
    
    def register_scan(self, scan_result: Dict[str, Any]) -> ScanEvent:
        """
        Registra un resultado de escaneo y crea un evento.
        
        Args:
            scan_result: Resultado del escaneo completo
            
        Returns:
            ScanEvent para difusión
        """
        self._event_counter += 1
        timestamp = datetime.now().isoformat()
        
        # Extraer métricas
        pii = scan_result.get("pii", {})
        compliance = scan_result.get("compliance", {})
        alignment = scan_result.get("alignment", {})
        
        pii_count = pii.get("total_violations", 0)
        comp_count = compliance.get("total_violations", 0)
        align_score = alignment.get("overall_score", 100)
        total = pii_count + comp_count
        action = scan_result.get("overall_action", "allow")
        
        # Actualizar stats
        self.stats["total_scans"] += 1
        self.stats["total_violations"] += total
        if action == "block":
            self.stats["total_blocked"] += 1
        
        hour = datetime.now().strftime("%Y-%m-%d %H:00")
        self.stats["scans_by_hour"][hour] = self.stats["scans_by_hour"].get(hour, 0) + 1
        
        # Violations by type
        for v in pii.get("violations", []):
            t = v.get("pii_type", "unknown")
            self.stats["violations_by_type"][t] = self.stats["violations_by_type"].get(t, 0) + 1
        for v in compliance.get("violations", []):
            t = v.get("compliance_type", "unknown")
            self.stats["violations_by_type"][t] = self.stats["violations_by_type"].get(t, 0) + 1
        
        # Latency promedio
        latencies = [pii.get("scan_duration_ms", 0), compliance.get("scan_duration_ms", 0)]
        avg = sum(latencies) / len(latencies) if latencies else 0
        n = self.stats["total_scans"]
        self.stats["avg_latency_ms"] = round(
            (self.stats["avg_latency_ms"] * (n - 1) + avg) / n, 2
        )
        
        # Guardar en historial
        entry = {
            "event_id": f"EVT-{self._event_counter:06d}",
            "timestamp": timestamp,
            "pii_violations": pii_count,
            "compliance_violations": comp_count,
            "alignment_score": align_score,
            "total_violations": total,
            "action": action,
            "text_preview": scan_result.get("input_text", "")[:80],
        }
        self.scan_history.append(entry)
        if len(self.scan_history) > self.max_history:
            self.scan_history = self.scan_history[-self.max_history:]
        
        # Crear evento
        event = ScanEvent(
            event_id=entry["event_id"],
            timestamp=timestamp,
            event_type="scan",
            data=entry,
        )
        
        # Generar alerta si es crítico
        if action == "block":
            self._generate_alert(entry)
        
        return event
    
    def _generate_alert(self, scan_entry: Dict[str, Any]):
        """Genera una alerta para violaciones críticas."""
        alert = {
            "alert_id": f"ALT-{len(self.alerts) + 1:04d}",
            "timestamp": scan_entry["timestamp"],
            "severity": "critical" if scan_entry["total_violations"] >= 3 else "high",
            "message": f"Violación bloqueada: {scan_entry['total_violations']} violaciones detectadas",
            "scan_event_id": scan_entry["event_id"],
            "text_preview": scan_entry["text_preview"],
        }
        self.alerts.append(alert)
        if len(self.alerts) > 50:
            self.alerts = self.alerts[-50:]
    
    def get_recent_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retorna los escaneos más recientes."""
        return list(reversed(self.scan_history[-limit:]))
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retorna las alertas más recientes."""
        return list(reversed(self.alerts[-limit:]))
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estadísticas acumuladas."""
        return {
            **self.stats,
            "block_rate": (
                self.stats["total_blocked"] / self.stats["total_scans"] * 100
                if self.stats["total_scans"] > 0 else 0
            ),
            "violation_rate": (
                self.stats["total_violations"] / self.stats["total_scans"]
                if self.stats["total_scans"] > 0 else 0
            ),
            "active_alerts": len([a for a in self.alerts if a["severity"] == "critical"]),
        }
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Retorna datos formateados para el dashboard."""
        return {
            "stats": self.get_stats(),
            "recent_scans": self.get_recent_scans(20),
            "recent_alerts": self.get_recent_alerts(10),
            "timestamp": datetime.now().isoformat(),
        }
    
    def reset(self):
        """Reinicia el monitor."""
        self.scan_history.clear()
        self.alerts.clear()
        self.stats = {
            "total_scans": 0,
            "total_violations": 0,
            "total_blocked": 0,
            "scans_by_hour": {},
            "violations_by_type": {},
            "avg_latency_ms": 0,
        }
        self._event_counter = 0
