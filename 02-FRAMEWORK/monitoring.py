"""
Security Monitoring Module — GovLLM-Sentinel
=============================================

Real-time security monitoring, anomaly detection, and alerting.

Features:
- Track all security events
- Detect brute force attacks
- Monitor rate limit violations
- Track authentication failures
- Detect suspicious patterns
- Generate security alerts
- Export audit logs

Usage:
    from monitoring import security_monitor, SecurityEvent, AlertLevel
    
    # Record security event
    security_monitor.record_event(SecurityEvent(
        event_type="auth_failure",
        source_ip="192.168.1.100",
        details={"username": "admin"},
        severity="high"
    ))
    
    # Get alerts
    alerts = security_monitor.get_alerts(last_minutes=60)
    
    # Get security dashboard data
    dashboard = security_monitor.get_dashboard()
"""
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict
from enum import Enum
import json
import os
import threading


# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

ALERT_THRESHOLDS = {
    "auth_failures_per_minute": 5,
    "auth_failures_per_hour": 20,
    "rate_limit_violations_per_minute": 10,
    "rate_limit_violations_per_hour": 50,
    "failed_scans_per_minute": 20,
    "unique_ips_per_hour": 100,
}

LOG_DIR = os.getenv("SECURITY_LOG_DIR", "logs/security")
ENABLE_FILE_LOGGING = os.getenv("SECURITY_FILE_LOGGING", "true").lower() == "true"


# ═══════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════

class AlertLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    # Authentication
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_TOKEN_EXPIRED = "auth_token_expired"
    AUTH_TOKEN_INVALID = "auth_token_invalid"
    
    # Rate Limiting
    RATE_LIMIT_HIT = "rate_limit_hit"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    
    # Input Validation
    INPUT_VALIDATION_FAILED = "input_validation_failed"
    INPUT_TOO_LONG = "input_too_long"
    
    # Security
    CORS_VIOLATION = "cors_violation"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    INJECTION_ATTEMPT = "injection_attempt"
    
    # API
    API_ERROR = "api_error"
    API_SLOW_RESPONSE = "api_slow_response"
    
    # System
    SYSTEM_START = "system_start"
    SYSTEM_ERROR = "system_error"


# ═══════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════

class SecurityEvent:
    """Security event for monitoring."""
    
    def __init__(
        self,
        event_type: str,
        source_ip: str = "unknown",
        details: Dict[str, Any] = None,
        severity: str = "info",
        user: str = None
    ):
        self.id = f"{datetime.utcnow().timestamp()}-{hash(str(details))}"
        self.timestamp = datetime.utcnow().isoformat()
        self.event_type = event_type
        self.source_ip = source_ip
        self.details = details or {}
        self.severity = severity
        self.user = user
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "details": self.details,
            "severity": self.severity,
            "user": self.user
        }


class Alert:
    """Security alert."""
    
    def __init__(
        self,
        level: AlertLevel,
        title: str,
        message: str,
        source_ip: str = None,
        event_count: int = 1,
        details: Dict[str, Any] = None
    ):
        self.id = f"alert-{datetime.utcnow().timestamp()}"
        self.timestamp = datetime.utcnow().isoformat()
        self.level = level
        self.title = title
        self.message = message
        self.source_ip = source_ip
        self.event_count = event_count
        self.details = details or {}
        self.acknowledged = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "level": self.level.value,
            "title": self.title,
            "message": self.message,
            "source_ip": self.source_ip,
            "event_count": self.event_count,
            "details": self.details,
            "acknowledged": self.acknowledged
        }


# ═══════════════════════════════════════════════════════════════════
# SECURITY MONITOR
# ═══════════════════════════════════════════════════════════════════

class SecurityMonitor:
    """Real-time security monitoring and alerting."""
    
    def __init__(self):
        self.events: List[SecurityEvent] = []
        self.alerts: List[Alert] = []
        self.stats = {
            "total_events": 0,
            "events_by_type": defaultdict(int),
            "events_by_severity": defaultdict(int),
            "events_by_ip": defaultdict(int),
            "alerts_generated": 0,
        }
        self._lock = threading.Lock()
        
        # Create log directory if needed
        if ENABLE_FILE_LOGGING:
            os.makedirs(LOG_DIR, exist_ok=True)
    
    def record_event(self, event: SecurityEvent) -> Optional[Alert]:
        """Record a security event and check for alert conditions.
        
        Args:
            event: Security event to record
            
        Returns:
            Alert if threshold exceeded, None otherwise
        """
        with self._lock:
            # Store event
            self.events.append(event)
            
            # Update stats
            self.stats["total_events"] += 1
            self.stats["events_by_type"][event.event_type] += 1
            self.stats["events_by_severity"][event.severity] += 1
            self.stats["events_by_ip"][event.source_ip] += 1
            
            # Keep only last 24 hours of events
            cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
            self.events = [e for e in self.events if e.timestamp > cutoff]
            
            # Log to file if enabled
            if ENABLE_FILE_LOGGING:
                self._log_to_file(event)
            
            # Check for alert conditions
            alert = self._check_thresholds(event)
            if alert:
                self.alerts.append(alert)
                self.stats["alerts_generated"] += 1
                
                # Log alert
                self._log_alert(alert)
            
            return alert
    
    def _check_thresholds(self, event: SecurityEvent) -> Optional[Alert]:
        """Check if event triggers an alert."""
        now = datetime.utcnow()
        one_minute_ago = (now - timedelta(minutes=1)).isoformat()
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        
        # Count recent events by type
        recent_minute = [
            e for e in self.events
            if e.timestamp > one_minute_ago and e.event_type == event.event_type
        ]
        recent_hour = [
            e for e in self.events
            if e.timestamp > one_hour_ago and e.event_type == event.event_type
        ]
        
        # Check auth failures
        if event.event_type == EventType.AUTH_FAILURE:
            if len(recent_minute) >= ALERT_THRESHOLDS["auth_failures_per_minute"]:
                return Alert(
                    level=AlertLevel.HIGH,
                    title="Brute Force Detection",
                    message=f"Multiple authentication failures from {event.source_ip}",
                    source_ip=event.source_ip,
                    event_count=len(recent_minute),
                    details={"threshold": "per_minute", "type": "auth_failure"}
                )
            if len(recent_hour) >= ALERT_THRESHOLDS["auth_failures_per_hour"]:
                return Alert(
                    level=AlertLevel.CRITICAL,
                    title="Sustained Attack Detected",
                    message=f"High volume of auth failures in last hour from {event.source_ip}",
                    source_ip=event.source_ip,
                    event_count=len(recent_hour),
                    details={"threshold": "per_hour", "type": "auth_failure"}
                )
        
        # Check rate limit violations
        if event.event_type == EventType.RATE_LIMIT_EXCEEDED:
            if len(recent_minute) >= ALERT_THRESHOLDS["rate_limit_violations_per_minute"]:
                return Alert(
                    level=AlertLevel.MEDIUM,
                    title="Rate Limit Abuse",
                    message=f"Excessive rate limit violations from {event.source_ip}",
                    source_ip=event.source_ip,
                    event_count=len(recent_minute),
                    details={"threshold": "per_minute", "type": "rate_limit"}
                )
        
        # Check injection attempts
        if event.event_type == EventType.INJECTION_ATTEMPT:
            return Alert(
                level=AlertLevel.CRITICAL,
                title="Injection Attack Detected",
                message=f"Potential injection attack from {event.source_ip}",
                source_ip=event.source_ip,
                details=event.details
            )
        
        return None
    
    def _log_to_file(self, event: SecurityEvent):
        """Log event to file."""
        try:
            date_str = datetime.utcnow().strftime("%Y-%m-%d")
            filename = f"{LOG_DIR}/security-{date_str}.jsonl"
            
            with open(filename, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception:
            pass  # Don't fail on logging errors
    
    def _log_alert(self, alert: Alert):
        """Log alert to file."""
        try:
            filename = f"{LOG_DIR}/alerts.jsonl"
            
            with open(filename, "a") as f:
                f.write(json.dumps(alert.to_dict()) + "\n")
        except Exception:
            pass
    
    def get_events(
        self,
        event_type: str = None,
        source_ip: str = None,
        severity: str = None,
        last_minutes: int = 60,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get filtered security events."""
        cutoff = (datetime.utcnow() - timedelta(minutes=last_minutes)).isoformat()
        
        events = [
            e for e in self.events
            if e.timestamp > cutoff
        ]
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if source_ip:
            events = [e for e in events if e.source_ip == source_ip]
        if severity:
            events = [e for e in events if e.severity == severity]
        
        # Return most recent first
        return [e.to_dict() for e in reversed(events[-limit:])]
    
    def get_alerts(
        self,
        level: str = None,
        acknowledged: bool = None,
        last_minutes: int = 60,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get filtered alerts."""
        cutoff = (datetime.utcnow() - timedelta(minutes=last_minutes)).isoformat()
        
        alerts = [
            a for a in self.alerts
            if a.timestamp > cutoff
        ]
        
        if level:
            alerts = [a for a in alerts if a.level.value == level]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        
        return [a.to_dict() for a in reversed(alerts[-limit:])]
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                return True
        return False
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get security dashboard data."""
        now = datetime.utcnow()
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        one_day_ago = (now - timedelta(hours=24)).isoformat()
        
        recent_hour = [e for e in self.events if e.timestamp > one_hour_ago]
        recent_day = [e for e in self.events if e.timestamp > one_day_ago]
        
        # Count by type
        events_by_type = defaultdict(int)
        for e in recent_hour:
            events_by_type[e.event_type] += 1
        
        # Count by severity
        events_by_severity = defaultdict(int)
        for e in recent_hour:
            events_by_severity[e.severity] += 1
        
        # Unique IPs
        unique_ips_hour = len(set(e.source_ip for e in recent_hour))
        unique_ips_day = len(set(e.source_ip for e in recent_day))
        
        # Unacknowledged alerts
        unack_alerts = [a for a in self.alerts if not a.acknowledged]
        
        # Security score (simple calculation)
        critical_count = events_by_severity.get("critical", 0)
        high_count = events_by_severity.get("high", 0)
        
        score = 100
        score -= critical_count * 20
        score -= high_count * 10
        score = max(0, score)
        
        return {
            "timestamp": now.isoformat(),
            "security_score": score,
            "events_last_hour": len(recent_hour),
            "events_last_day": len(recent_day),
            "events_by_type": dict(events_by_type),
            "events_by_severity": dict(events_by_severity),
            "unique_ips_last_hour": unique_ips_hour,
            "unique_ips_last_day": unique_ips_day,
            "alerts_unacknowledged": len(unack_alerts),
            "alerts_critical": len([a for a in unack_alerts if a.level == AlertLevel.CRITICAL]),
            "alerts_high": len([a for a in unack_alerts if a.level == AlertLevel.HIGH]),
            "top_offenders": self._get_top_offenders(recent_hour),
        }
    
    def _get_top_offenders(self, events: List[SecurityEvent], limit: int = 5) -> List[Dict[str, Any]]:
        """Get top offending IPs."""
        ip_counts = defaultdict(int)
        for e in events:
            if e.severity in ["high", "critical"]:
                ip_counts[e.source_ip] += 1
        
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        
        return [
            {"ip": ip, "count": count}
            for ip, count in sorted_ips[:limit]
        ]
    
    def export_audit_log(self, start_date: str = None, end_date: str = None) -> List[Dict[str, Any]]:
        """Export audit log for compliance."""
        events = self.events.copy()
        
        if start_date:
            events = [e for e in events if e.timestamp >= start_date]
        if end_date:
            events = [e for e in events if e.timestamp <= end_date]
        
        return [e.to_dict() for e in events]


# ═══════════════════════════════════════════════════════════════════
# SINGLETON INSTANCE
# ═══════════════════════════════════════════════════════════════════

security_monitor = SecurityMonitor()


# ═══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def record_auth_event(success: bool, username: str, source_ip: str):
    """Record authentication event."""
    event_type = EventType.AUTH_SUCCESS if success else EventType.AUTH_FAILURE
    severity = "info" if success else "high"
    
    security_monitor.record_event(SecurityEvent(
        event_type=event_type,
        source_ip=source_ip,
        details={"username": username},
        severity=severity
    ))


def record_rate_limit_event(source_ip: str, exceeded: bool = False):
    """Record rate limit event."""
    event_type = EventType.RATE_LIMIT_EXCEEDED if exceeded else EventType.RATE_LIMIT_HIT
    severity = "high" if exceeded else "medium"
    
    security_monitor.record_event(SecurityEvent(
        event_type=event_type,
        source_ip=source_ip,
        severity=severity
    ))


def record_injection_attempt(source_ip: str, pattern: str = None):
    """Record potential injection attempt."""
    security_monitor.record_event(SecurityEvent(
        event_type=EventType.INJECTION_ATTEMPT,
        source_ip=source_ip,
        details={"pattern": pattern} if pattern else {},
        severity="critical"
    ))


def record_api_error(source_ip: str, endpoint: str, error: str):
    """Record API error."""
    security_monitor.record_event(SecurityEvent(
        event_type=EventType.API_ERROR,
        source_ip=source_ip,
        details={"endpoint": endpoint, "error": error},
        severity="medium"
    ))
