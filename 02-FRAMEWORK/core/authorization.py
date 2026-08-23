"""
Módulo de Gestión de Autorizaciones
GovLLM-Sentinel

Este módulo valida autorizaciones basándose en contratos firmados físicamente
que residen en la empresa. NO almacena datos personales ni sensibles.

⚠️ Los contratos físicos NO se suben a repositorios
"""

import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass


@dataclass
class ContractReference:
    """Referencia a contrato firmado físicamente (sin datos sensibles)."""
    
    contract_id: str
    model_authorized: str
    valid_from: str
    valid_until: str
    signature_hash: str
    authorized_by: str
    organization: str
    authorized_tests: List[str]
    test_intensity: str
    max_tests_per_day: int
    notes: str
    
    def is_valid(self) -> bool:
        """Verifica si el contrato está vigente."""
        now = datetime.now()
        start = datetime.fromisoformat(self.valid_from)
        end = datetime.fromisoformat(self.valid_until)
        return start <= now <= end
    
    def days_remaining(self) -> int:
        """Retorna días restantes de vigencia."""
        end = datetime.fromisoformat(self.valid_until)
        delta = end - datetime.now()
        return max(0, delta.days)
    
    def is_test_authorized(self, test_type: str) -> bool:
        """Verifica si un tipo de prueba está autorizado."""
        return test_type in self.authorized_tests
    
    def to_dict(self) -> Dict[str, Any]:
        """Convierte a diccionario."""
        return {
            "contract_id": self.contract_id,
            "model_authorized": self.model_authorized,
            "valid_until": self.valid_until,
            "days_remaining": self.days_remaining(),
            "authorized_tests": self.authorized_tests,
            "test_intensity": self.test_intensity,
            "is_valid": self.is_valid()
        }


class AuthorizationManager:
    """
    Gestor de autorizaciones para GovLLM-Sentinel.
    
    Usa archivos de referencia locales que apuntan a contratos
    firmados físicamente en la empresa.
    
    ⚠️ NO almacena datos personales ni sensibles
    
    Uso:
        auth = AuthorizationManager()
        auth.validate()  # Valida que haya autorización
        
        # Verificar prueba específica
        auth.validate_test("jailbreak")
    """
    
    def __init__(self, config_dir: str = "config/"):
        """
        Inicializa el gestor de autorizaciones.
        
        Args:
            config_dir: Directorio con archivos de configuración
        """
        self.config_dir = Path(config_dir)
        self.contracts: Dict[str, ContractReference] = {}
        self.access_log: List[Dict[str, Any]] = []
        
        # Cargar contratos de referencia
        self._load_contracts()
    
    def _load_contracts(self) -> None:
        """Carga archivos de referencia de contratos."""
        contracts_file = self.config_dir / "contrato-referencia.json"
        
        if not contracts_file.exists():
            print("⚠️ No se encontró archivo de referencia de contrato")
            print("   Ejecuta: cp config/contrato-referencia.json.example config/contrato-referencia.json")
            return
        
        try:
            with open(contracts_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            contract = ContractReference(
                contract_id=data["contract_id"],
                model_authorized=data["model_authorized"],
                valid_from=data["valid_from"],
                valid_until=data["valid_until"],
                signature_hash=data["signature_hash"],
                authorized_by=data["authorized_by"],
                organization=data["organization"],
                authorized_tests=data["authorized_tests"],
                test_intensity=data["test_intensity"],
                max_tests_per_day=data["max_tests_per_day"],
                notes=data.get("notes", "")
            )
            
            self.contracts[contract.contract_id] = contract
            
        except Exception as e:
            print(f"❌ Error cargando contrato: {e}")
    
    def validate(self) -> bool:
        """
        Valida que exista al menos un contrato vigente.
        
        Returns:
            True si hay autorización válida
            
        Raises:
            PermissionError: Si no hay autorización
        """
        valid_contracts = [c for c in self.contracts.values() if c.is_valid()]
        
        if not valid_contracts:
            raise PermissionError(
                "❌ BLOQUEADO: No hay contrato de autorización válido.\n"
                "   Para ejecutar pruebas de seguridad:\n"
                "   1. Tener contrato firmado físicamente\n"
                "   2. Crear archivo de referencia:\n"
                "      cp config/contrato-referencia.json.example config/contrato-referencia.json\n"
                "   3. Editar con datos del contrato (sin datos personales)\n"
                "   4. Ejecutar: auth.validate()\n\n"
                "   Consulta: 01-LEGAL/README.md"
            )
        
        return True
    
    def validate_test(self, test_type: str) -> bool:
        """
        Valida que un tipo de prueba específico esté autorizado.
        
        Args:
            test_type: Tipo de prueba (jailbreak, prompt_injection, etc.)
            
        Returns:
            True si la prueba está autorizada
            
        Raises:
            PermissionError: Si la prueba no está autorizada
        """
        self.validate()
        
        for contract in self.contracts.values():
            if contract.is_valid() and contract.is_test_authorized(test_type):
                self._log_access("VALIDATE_TEST", test_type, "AUTHORIZED")
                return True
        
        raise PermissionError(
            f"❌ BLOQUEADO: La prueba '{test_type}' no está autorizada.\n"
            f"   Pruebas autorizadas: {self._get_all_authorized_tests()}"
        )
    
    def validate_model(self, model_name: str) -> bool:
        """
        Valida que un modelo específico esté autorizado.
        
        Args:
            model_name: Nombre del modelo
            
        Returns:
            True si el modelo está autorizado
            
        Raises:
            PermissionError: Si el modelo no está autorizado
        """
        self.validate()
        
        for contract in self.contracts.values():
            if contract.is_valid() and model_name.lower() in contract.model_authorized.lower():
                self._log_access("VALIDATE_MODEL", model_name, "AUTHORIZED")
                return True
        
        raise PermissionError(
            f"❌ BLOQUEADO: El modelo '{model_name}' no está autorizado.\n"
            f"   Modelos autorizados: {self._get_authorized_models()}"
        )
    
    def get_active_contracts(self) -> List[ContractReference]:
        """Retorna contratos vigentes."""
        return [c for c in self.contracts.values() if c.is_valid()]
    
    def get_contract_status(self) -> Dict[str, Any]:
        """Retorna estado de los contratos."""
        contracts = []
        for contract in self.contracts.values():
            contracts.append({
                "id": contract.contract_id,
                "model": contract.model_authorized,
                "valid_until": contract.valid_until,
                "days_remaining": contract.days_remaining(),
                "status": "VIGENTE" if contract.is_valid() else "VENCIDO"
            })
        
        return {
            "total_contracts": len(contracts),
            "active_contracts": sum(1 for c in contracts if c["status"] == "VIGENTE"),
            "contracts": contracts
        }
    
    def _get_authorized_models(self) -> List[str]:
        """Retorna lista de modelos autorizados."""
        models = []
        for contract in self.contracts.values():
            if contract.is_valid():
                models.append(contract.model_authorized)
        return models
    
    def _get_all_authorized_tests(self) -> List[str]:
        """Retorna todas las pruebas autorizadas."""
        tests = set()
        for contract in self.contracts.values():
            if contract.is_valid():
                tests.update(contract.authorized_tests)
        return list(tests)
    
    def _log_access(self, action: str, resource: str, result: str) -> None:
        """Registra evento de auditoría."""
        self.access_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "resource": resource,
            "result": result
        })
    
    def export_audit_log(self, output_file: str = "audit_log.json") -> None:
        """Exporta registro de auditoría."""
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(self.access_log, f, indent=2, ensure_ascii=False)


# ============================================================
# FUNCIONES DE UTILIDAD
# ============================================================

def quick_validate() -> bool:
    """
    Validación rápida de autorización.
    
    Uso:
        from framework.core.authorization import quick_validate
        if quick_validate():
            print("Autorización válida")
    """
    try:
        auth = AuthorizationManager()
        auth.validate()
        return True
    except PermissionError:
        return False


def validate_before_action(func):
    """
    Decorador para validar autorización antes de ejecutar.
    
    Uso:
        @validate_before_action
        def mi_funcion():
            # Solo se ejecuta si hay autorización
            pass
    """
    def wrapper(*args, **kwargs):
        auth = AuthorizationManager()
        auth.validate()
        return func(*args, **kwargs)
    return wrapper
