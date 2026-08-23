"""
Módulo de Motor de Defensa
GovLLM-Sentinel

Este módulo implementa técnicas para crear LLMs robustos y seguros.

Propósito:
- Fortalecer modelos contra ataques conocidos
- Implementar defensas en capas
- Crear pipelines de hardening
- Evaluar efectividad de defensas

⚠️ Uso exclusivamente defensivo y educativo
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class DefenseType(Enum):
    """Tipos de defensa disponibles."""
    ADVERSARIAL_TRAINING = "adversarial_training"
    SAFETY_FINETUNING = "safety_finetuning"
    INPUT_FILTERING = "input_filtering"
    OUTPUT_FILTERING = "output_filtering"
    SYSTEM_PROMPT_HARDENING = "system_prompt_hardening"
    REAL_TIME_MONITORING = "real_time_monitoring"


@dataclass
class DefenseImplementation:
    """Implementación de una defensa."""
    
    implementation_id: str
    defense_type: DefenseType
    name: str
    description: str
    
    # Configuración
    parameters: Dict[str, Any]
    
    # Métricas de efectividad
    effectiveness_score: float  # 0-100
    false_positive_rate: float
    performance_impact_ms: float
    
    # Estado
    status: str  # ACTIVE, INACTIVE, TESTING
    deployed_date: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HardeningPipeline:
    """Pipeline completo de hardening para un modelo."""
    
    pipeline_id: str
    model_name: str
    created_date: str
    
    # Defensas implementadas
    defenses: List[DefenseImplementation]
    
    # Métricas globales
    overall_robustness: float
    performance_overhead: float  # % de impacto en latencia
    
    # Estado
    status: str  # READY, IN_PROGRESS, COMPLETED
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DefenseEngine:
    """
    Motor de defensa para crear LLMs robustos.
    
    Responsabilidades:
    - Implementar defensas contra ataques conocidos
    - Crear pipelines de hardening
    - Evaluar efectividad de defensas
    - Generar recomendaciones de mejora
    
    Uso:
        engine = DefenseEngine()
        
        # Crear pipeline para modelo
        pipeline = engine.create_hardening_pipeline("mi-modelo")
        
        # Agregar defensas
        engine.add_defense(pipeline, DefenseType.ADVERSARIAL_TRAINING)
        engine.add_defense(pipeline, DefenseType.INPUT_FILTERING)
        
        # Evaluar robustez
        score = engine.evaluate_robustness(pipeline)
    """
    
    def __init__(self):
        self.pipelines: Dict[str, HardeningPipeline] = {}
        self.available_defenses = self._load_defenses()
    
    def _load_defenses(self) -> Dict[DefenseType, Dict[str, Any]]:
        """Carga las defensas disponibles con sus configuraciones."""
        return {
            DefenseType.ADVERSARIAL_TRAINING: {
                "name": "Adversarial Training",
                "description": "Entrenamiento con ejemplos adversariales para mejorar robustez",
                "default_params": {
                    "epochs": 3,
                    "learning_rate": 0.00001,
                    "adversarial_ratio": 0.3,
                    "attack_techniques": ["jailbreak", "injection", "exfiltration"]
                },
                "effectiveness": 85.0,
                "performance_impact_ms": 50
            },
            DefenseType.SAFETY_FINETUNING: {
                "name": "Safety Fine-tuning",
                "description": "Fine-tuning con datos de seguridad para mejorar comportamiento seguro",
                "default_params": {
                    "safety_dataset_size": 10000,
                    "epochs": 5,
                    "safety_categories": ["harmful", "biased", "misleading"]
                },
                "effectiveness": 80.0,
                "performance_impact_ms": 30
            },
            DefenseType.INPUT_FILTERING: {
                "name": "Input Filtering",
                "description": "Filtros multicapa para detectar entradas maliciosas",
                "default_params": {
                    "layers": ["keyword", "pattern", "semantic", "ml_classifier"],
                    "threshold": 0.8,
                    "block_on_detection": True
                },
                "effectiveness": 75.0,
                "performance_impact_ms": 20
            },
            DefenseType.OUTPUT_FILTERING: {
                "name": "Output Filtering",
                "description": "Filtros de salida para prevenir divulgación de información sensible",
                "default_params": {
                    "sensitive_patterns": ["personal_data", "system_info", "credentials"],
                    "action": "block_and_log",
                    "alert_threshold": 0.9
                },
                "effectiveness": 70.0,
                "performance_impact_ms": 15
            },
            DefenseType.SYSTEM_PROMPT_HARDENING: {
                "name": "System Prompt Hardening",
                "description": "Hardening del system prompt para prevenir extracción y manipulación",
                "default_params": {
                    "instruction_hierarchy": True,
                    "role_enforcement": True,
                    "prompt_protection": True
                },
                "effectiveness": 65.0,
                "performance_impact_ms": 5
            },
            DefenseType.REAL_TIME_MONITORING: {
                "name": "Real-time Monitoring",
                "description": "Monitoreo en tiempo real para detectar comportamientos sospechosos",
                "default_params": {
                    "alert_channels": ["log", "webhook"],
                    "threshold_critical": 0.95,
                    "threshold_high": 0.85,
                    "auto_block": False
                },
                "effectiveness": 60.0,
                "performance_impact_ms": 10
            }
        }
    
    def create_hardening_pipeline(self, model_name: str) -> HardeningPipeline:
        """
        Crea un nuevo pipeline de hardening para un modelo.
        
        Args:
            model_name: Nombre del modelo a fortalecer
            
        Returns:
            HardeningPipeline creado
        """
        pipeline_id = f"PIPE-{model_name[:10].upper()}-{datetime.now().strftime('%Y%m%d')}"
        
        pipeline = HardeningPipeline(
            pipeline_id=pipeline_id,
            model_name=model_name,
            created_date=datetime.now().isoformat(),
            defenses=[],
            overall_robustness=0.0,
            performance_overhead=0.0,
            status="READY"
        )
        
        self.pipelines[pipeline_id] = pipeline
        
        print(f"🔧 Pipeline creado: {pipeline_id}")
        print(f"   Modelo: {model_name}")
        
        return pipeline
    
    def add_defense(self, pipeline_id: str, 
                   defense_type: DefenseType,
                   custom_params: Optional[Dict[str, Any]] = None) -> DefenseImplementation:
        """
        Agrega una defensa al pipeline.
        
        Args:
            pipeline_id: ID del pipeline
            defense_type: Tipo de defensa a agregar
            custom_params: Parámetros personalizados (opcional)
            
        Returns:
            DefenseImplementation creada
        """
        if pipeline_id not in self.pipelines:
            raise ValueError(f"Pipeline no encontrado: {pipeline_id}")
        
        defense_config = self.available_defenses[defense_type]
        
        implementation = DefenseImplementation(
            implementation_id=f"DEF-{defense_type.value.upper()[:10]}-{datetime.now().strftime('%H%M%S')}",
            defense_type=defense_type,
            name=defense_config["name"],
            description=defense_config["description"],
            parameters=custom_params or defense_config["default_params"],
            effectiveness_score=defense_config["effectiveness"],
            false_positive_rate=0.05,
            performance_impact_ms=defense_config["performance_impact_ms"],
            status="ACTIVE",
            deployed_date=datetime.now().isoformat()
        )
        
        self.pipelines[pipeline_id].defenses.append(implementation)
        
        # Recalcular métricas
        self._recalculate_metrics(pipeline_id)
        
        print(f"✅ Defensa agregada: {defense_config['name']}")
        print(f"   Efectividad: {defense_config['effectiveness']}%")
        
        return implementation
    
    def _recalculate_metrics(self, pipeline_id: str) -> None:
        """Recalcula métricas del pipeline."""
        pipeline = self.pipelines[pipeline_id]
        
        if not pipeline.defenses:
            pipeline.overall_robustness = 0.0
            pipeline.performance_overhead = 0.0
            return
        
        # Promedio de efectividad
        total_effectiveness = sum(d.effectiveness_score for d in pipeline.defenses)
        pipeline.overall_robustness = total_effectiveness / len(pipeline.defenses)
        
        # Suma de overhead de performance
        pipeline.performance_overhead = sum(d.performance_impact_ms for d in pipeline.defenses)
    
    def evaluate_robustness(self, pipeline_id: str) -> Dict[str, Any]:
        """
        Evalúa la robustez de un pipeline.
        
        Args:
            pipeline_id: ID del pipeline a evaluar
            
        Returns:
            Diccionario con métricas de robustez
        """
        if pipeline_id not in self.pipelines:
            raise ValueError(f"Pipeline no encontrado: {pipeline_id}")
        
        pipeline = self.pipelines[pipeline_id]
        
        return {
            "pipeline_id": pipeline_id,
            "model_name": pipeline.model_name,
            "overall_robustness": pipeline.overall_robustness,
            "performance_overhead_ms": pipeline.performance_overhead,
            "defenses_count": len(pipeline.defenses),
            "defense_breakdown": [
                {
                    "name": d.name,
                    "effectiveness": d.effectiveness_score,
                    "status": d.status
                }
                for d in pipeline.defenses
            ],
            "recommendations": self._generate_recommendations(pipeline)
        }
    
    def _generate_recommendations(self, pipeline: HardeningPipeline) -> List[str]:
        """Genera recomendaciones basadas en el estado del pipeline."""
        recommendations = []
        
        # Verificar defensas esenciales
        defense_types = {d.defense_type for d in pipeline.defenses}
        
        if DefenseType.ADVERSARIAL_TRAINING not in defense_types:
            recommendations.append("Agregar Adversarial Training para mejorar robustez contra ataques")
        
        if DefenseType.INPUT_FILTERING not in defense_types:
            recommendations.append("Implementar Input Filtering para detectar entradas maliciosas")
        
        if DefenseType.OUTPUT_FILTERING not in defense_types:
            recommendations.append("Agregar Output Filtering para prevenir exfiltración de datos")
        
        if DefenseType.REAL_TIME_MONITORING not in defense_types:
            recommendations.append("Implementar monitoreo en tiempo real para detección temprana")
        
        if pipeline.overall_robustness < 70:
            recommendations.append("La robustez general es baja - considerar agregar más defensas")
        
        if pipeline.performance_overhead > 100:
            recommendations.append("El overhead de performance es alto - optimizar configuraciones")
        
        if not recommendations:
            recommendations.append("Pipeline está bien configurado - mantener monitoreo continuo")
        
        return recommendations
    
    def get_available_defenses(self) -> List[Dict[str, Any]]:
        """Retorna todas las defensas disponibles."""
        return [
            {
                "type": dt.value,
                "name": config["name"],
                "description": config["description"],
                "effectiveness": config["effectiveness"],
                "performance_impact_ms": config["performance_impact_ms"]
            }
            for dt, config in self.available_defenses.items()
        ]
    
    def export_pipeline(self, pipeline_id: str, output_file: str) -> str:
        """
        Exporta pipeline a archivo JSON.
        
        Args:
            pipeline_id: ID del pipeline
            output_file: Ruta del archivo de salida
            
        Returns:
            Ruta del archivo generado
        """
        import json
        
        if pipeline_id not in self.pipelines:
            raise ValueError(f"Pipeline no encontrado: {pipeline_id}")
        
        pipeline = self.pipelines[pipeline_id]
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(pipeline.to_dict(), f, indent=2, ensure_ascii=False)
        
        print(f"📁 Pipeline exportado a: {output_file}")
        return output_file
