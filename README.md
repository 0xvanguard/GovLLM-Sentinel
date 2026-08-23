<div align="center">

# 🛡️ GovLLM-Sentinel

### Framework de Evaluación y Hardening de LLMs para Sector Público

```
 ██████╗  █████╗ ████████╗ ██████╗██╗  ██╗
██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██║  ███╗███████║   ██║   ██║     ███████║
██║   ██║██╔══██║   ██║   ██║     ██╔══██║
╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
```

> **Evaluación autorizada de seguridad LLM para gobierno y comunidad**

[![Framework](https://img.shields.io/badge/framework-Red%20Team%20Authorized-blue?style=flat-square)](#framework-de-red-teaming)
[![Compliance](https://img.shields.io/badge/compliance-NIST%20AI%20RMF-green?style=flat-square)](#cumplimiento-normativo)
[![License](https://img.shields.io/badge/license-Educational%20%26%20Ethical-orange?style=flat-square)](#aviso-legal)

</div>

---

## 📌 ¿Qué es GovLLM-Sentinel?

**GovLLM-Sentinel** es un framework de evaluación y fortalecimiento de modelos de lenguaje (LLM) diseñado específicamente para el **sector público y gubernamental**.

### Filosofía

> *"Evaluamos para defender. Autorizamos para proteger."*

- ✅ **Red teaming autorizado** con contrato legal firmado
- ✅ **Enfoque defensivo** - mejoramos modelos, no los dañamos
- ✅ **Acceso gubernamental de solo lectura** para transparencia
- ✅ **Colaboración comunitaria** - código abierto, defensa colectiva
- ✅ **Cumplimiento normativo** integrado (NIST AI RMF, GDPR, Ley 1273)

---

## 🎯 Objetivos

### 1. Evaluar Seguridad LLM
- Detectar vulnerabilidades en modelos de lenguaje
- Probar resistencia a jailbreaks, prompt injection y otros ataques
- Generar métricas de robustez estandarizadas

### 2. Fortalecer Modelos
- Crear pipelines de adversarial training
- Implementar filtros de entrada/salida
- Desarrollar sistemas de monitoreo en tiempo real

### 3. Servir al Sector Público
- Dashboard ejecutivo de solo lectura
- Reportes de cumplimiento normativo
- Recomendaciones accionables para entidades gubernamentales

### 4. Beneficiar a la Comunidad
- Herramientas open source de evaluación
- Documentación y guías de implementación
- Capacitación en seguridad LLM

---

## 🗂️ Estructura del Proyecto

```
GovLLM-Sentinel/
│
├── 📄 README.md                          ← Estás aquí
├── 📋 CONTRIBUTING.md                    ← Guía de contribución
├── ⚖️ LICENSE                            ← Licencia educativa
│
├── 📁 01-LEGAL/                          ← Marco legal y contratos
│   ├── README.md
│   ├── CONTRATO-AUTORIZACION-REDTEAM.md
│   ├── ACUERDO-CONFIDENCIALIDAD.md
│   ├── PERMISO-EVALUACION-MODELOS.md
│   └── AVISO-LEGAL-USO-ETICO.md
│
├── 📁 02-FRAMEWORK/                      ← Framework de evaluación
│   ├── README.md
│   ├── core/
│   │   ├── evaluator.py
│   │   ├── red_team.py
│   │   └── defense_engine.py
│   ├── attacks/
│   │   ├── jailbreaks.py
│   │   ├── prompt_injection.py
│   │   ├── data_exfiltration.py
│   │   └── content_filter_bypass.py
│   ├── defenses/
│   │   ├── adversarial_training.py
│   │   ├── safety_finetuning.py
│   │   └── input_output_filters.py
│   └── utils/
│       ├── authorization.py
│       ├── logging.py
│       └── report_generator.py
│
├── 📁 03-MODELS/                         ← Modelos evaluados
│   ├── README.md
│   ├── evaluated/                        ← Modelos ya evaluados
│   └── hardened/                         ← Modelos fortalecidos
│
├── 📁 04-DASHBOARD/                      ← Dashboard gubernamental
│   ├── README.md
│   ├── public/                           ← Dashboard de solo lectura
│   │   ├── index.html
│   │   ├── executive-summary.html
│   │   └── compliance-report.html
│   ├── api/                              ← API de datos
│   │   └── read-only-endpoints.md
│   └── assets/
│       ├── css/
│       ├── js/
│       └── img/
│
├── 📁 05-BENCHMARKS/                     ← Benchmarks de evaluación
│   ├── README.md
│   ├── government-use-cases/
│   ├── adversarial-test-sets/
│   └── compliance-checks/
│
├── 📁 06-DOCUMENTATION/                  ← Documentación completa
│   ├── README.md
│   ├── guia-rapida.md
│   ├── arquitectura.md
│   └── api-reference.md
│
└── 📁 07-COMMUNITY/                      ← Recursos comunitarios
    ├── README.md
    ├── guias/
    ├── tutoriales/
    └── ejemplos/
```

---

## 🚀 Inicio Rápido

### Requisitos Previos

- Python 3.11+
- Docker (opcional, para entornos aislados)
- Contrato de autorización firmado (obligatorio)

### Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/[tu-usuario]/GovLLM-Sentinel.git
cd GovLLM-Sentinel

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Verificar contrato de autorización
python -c "from framework.core.authorization import verify_contract; verify_contract()"
```

### Ejecución

```python
from framework.core.evaluator import GovLLMEvaluator
from framework.core.authorization import AuthorizationManager

# Cargar contrato de autorización
auth = AuthorizationManager("contratos/mi-contrato-firmado.json")

# Inicializar evaluador
evaluator = GovLLMEvaluator(authorization=auth)

# Ejecutar evaluación autorizada
results = evaluator.run_full_evaluation("modelo-objetivo")

# Generar reporte ejecutivo
evaluator.generate_executive_report(results)
```

---

## 📜 Marco Legal

**CRÍTICO:** Este framework requiere autorización legal explícita para su uso.

### Contratos Requisitos

| Documento | Propósito |
|-----------|-----------|
| `CONTRATO-AUTORIZACION-REDTEAM.md` | Autoriza red teaming específico |
| `ACUERDO-CONFIDENCIALIDAD.md` | Protege información sensible |
| `PERMISO-EVALUACION-MODELOS.md` | Autoriza evaluación de modelos específicos |
| `AVISO-LEGAL-USO-ETICO.md` | Define uso ético y responsable |

### Flujo de Autorización

```
1. Firmar contrato → 2. Validar permisos → 3. Ejecutar evaluación → 4. Generar reportes
        ↓                      ↓                      ↓                      ↓
    Documento legal      Verificación auto      Solo modelos autorizados   Solo lectura gobierno
```

---

## 🏛️ Acceso Gubernamental

### Nivel de Acceso: Solo Lectura

El dashboard gubernamental está diseñado para:

- ✅ **Ver** reportes ejecutivos de seguridad
- ✅ **Ver** métricas de robustez de modelos
- ✅ **Ver** vulnerabilidades detectadas (resumen)
- ✅ **Descargar** reportes de cumplimiento
- ❌ **NO** modificar configuraciones
- ❌ **NO** ejecutar pruebas de seguridad
- ❌ **NO** acceder a código fuente
- ❌ **NO** exportar datos sensibles

### Beneficiarios

- Jefes de seguridad informática
- Equipos de tecnología gubernamental
- Auditores de cumplimiento
- Comunidad de investigación en seguridad

---

## 📊 Cumplimiento Normativo

### Frameworks Integrados

| Framework | Uso | Estado |
|-----------|-----|--------|
| **NIST AI RMF 2.0** | Gestión de riesgos IA | ✅ Integrado |
| **GDPR** | Protección de datos | ✅ Integrado |
| **Ley 1273/2009 (CO)** | Marco legal colombiano | ✅ Integrado |
| **MITRE ATLAS** | Tácticas de adversarios IA | 🔄 En progreso |
| **ISO 27001** | Gestión seguridad información | 🔄 En progreso |

---

## 🤝 Contribuir

¡Bienvenidas contribuciones! Lee [`CONTRIBUTING.md`](./CONTRIBUTING.md) para:

- Reportar vulnerabilidades (responsablemente)
- Proponer mejoras defensivas
- Agregar benchmarks gubernamentales
- Mejorar documentación

---

## ⚖️ Aviso Legal y Ético

> **Este proyecto es estrictamente educativo y defensivo.**

- Todo red teaming requiere **autorización escrita explícita**
- Se usa exclusivamente en **modelos autorizados** por sus propietarios
- Los hallazgos se reportan **responsablemente** a las partes afectadas
- **NO** se promueve ni facilita uso malicioso
- Cumple con: **Ley 1273/2009 (CO)** · **GDPR** · **CFAA** (EE.UU.)

### Autorización Requerida

```
ANTES de ejecutar CUALQUIER prueba:
1. Tener contrato firmado con autorización explícita
2. Verificar que el modelo está autorizado para evaluación
3. Registrar cada prueba ejecutada con timestamp
4. Reportar hallazgos solo a partes autorizadas
```

---

## 👤 Autor

**[Tu Nombre]** · [Tu GitHub] · [Tu País]

Especialista en seguridad de IA y LLMs | Colaboración gubernamental

---

<div align="center">

*"Evaluar es defender. Autorizar es proteger."*

**[⬆ Volver al inicio](#govllm-sentinel)** · **[📜 Contratos](./01-LEGAL/)** · **[🛡️ Framework](./02-FRAMEWORK/)** · **[📊 Dashboard](./04-DASHBOARD/)**

</div>
