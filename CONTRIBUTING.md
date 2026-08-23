# 🤝 Contribuir a GovLLM-Sentinel

¡Gracias por tu interés en contribuir! Este documento explica cómo participar en el proyecto.

---

## ⚠️ Importante: Compromiso Ético

**GovLLM-Sentinel es un proyecto defensivo y educativo.**

Al contribuir, te comprometes a:

- ✅ Usar conocimiento exclusivamente para mejorar la seguridad
- ✅ No facilitar ni promover actividades maliciosas
- ✅ Reportar vulnerabilidades de forma responsable
- ✅ Respetar la privacidad y confidencialidad
- ✅ Cumplir con todas las leyes aplicables

---

## 📋 Tipos de Contribución

### 1. 🐛 Reportar Bugs

**Canal:** GitHub Issues

**Plantilla:**
```markdown
## Descripción del Bug
[Descripción clara del problema]

## Pasos para Reproducir
1. ...
2. ...
3. ...

## Comportamiento Esperado
[Qué esperabas que pasara]

## Comportamiento Actual
[Qué pasó realmente]

## Entorno
- OS: [ej: Windows 11]
- Python: [ej: 3.11.0]
- Versión GovLLM-Sentinel: [ej: 1.0.0]
```

### 2. 💡 Proponer Funcionalidades

**Canal:** GitHub Discussions

**Formato:**
```markdown
## Nombre de la Funcionalidad
[Breve descripción]

## Problema que Resuelve
[Cuál es el problema actual]

## Solución Propuesta
[Cómo se resolvería]

## Alternativas Consideradas
[Otras opciones evaluadas]

## Impacto
- ¿A quién beneficia?
- ¿Cuál es la prioridad?
```

### 3. 🔧 Enviar Código

**Canal:** Pull Requests

**Proceso:**
1. Fork el repositorio
2. Crea una branch para tu cambio
3. Escribe tests si aplica
4. Asegura que los tests pasen
5. Envía el Pull Request

### 4. 📝 Mejorar Documentación

**Canal:** Pull Requests

**Áreas de mejora:**
- Correcciones ortográficas/gramaticales
- Aclaraciones en guías
- Nuevos ejemplos
- Traducciones

### 5. 🔬 Investigación en Seguridad

**Canal:** Email seguro o GitHub Security Advisories

**⚠️ IMPORTANTE:** No reportes vulnerabilidades públicamente.

**Proceso:**
1. Envía reporte a `security@govllm-sentinel.gov`
2. Espera confirmación (máximo 48 horas)
3. Coordinar divulgación responsable
4. Recibe reconocimiento (opcional)

---

## 🛠️ Guías de Desarrollo

### Configuración del Entorno

```bash
# 1. Clonar repositorio
git clone https://github.com/govllm-sentinel/GovLLM-Sentinel.git
cd GovLLM-Sentinel

# 2. Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# 3. Instalar dependencias
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 4. Configurar hooks
pre-commit install
```

### Estructura de Código

```
GovLLM-Sentinel/
├── framework/           # Core del framework
│   ├── core/           # Módulos principales
│   ├── attacks/        # Técnicas de ataque
│   ├── defenses/       # Técnicas de defensa
│   └── utils/          # Utilidades
├── dashboard/          # Dashboard gubernamental
├── docs/               # Documentación
└── tests/              # Tests unitarios
```

### Convenciones de Código

- **Python:** Seguir PEP 8
- **Type Hints:** Usar en todas las funciones
- **Docstrings:** Google style
- **Tests:** Cobertura mínima del 80%
- **Commits:** Mensajes claros en inglés

### Ejemplo de Función

```python
def evaluate_model(
    model_name: str,
    contract: Contract,
    categories: Optional[List[AttackCategory]] = None
) -> EvaluationResult:
    """
    Evalúa un modelo de lenguaje de forma autorizada.
    
    Args:
        model_name: Nombre del modelo a evaluar
        contract: Contrato de autorización válido
        categories: Categorías específicas a evaluar (todas si None)
        
    Returns:
        Resultado de la evaluación
        
    Raises:
        PermissionError: Si no hay autorización válida
        ValueError: Si el modelo no está autorizado
    """
    # Implementación...
```

---

## 📝 Proceso de Pull Request

### 1. Preparar Cambios

```bash
# Actualizar desde main
git fetch origin
git checkout -b feature/tu-funcionalidad origin/main

# Hacer cambios
# ...

# Ejecutar tests
pytest tests/

# Verificar estilo
flake8 framework/
black --check framework/
mypy framework/
```

### 2. Commit

```bash
# Commits descriptivos
git commit -m "feat: add adversarial training for jailbreak resistance"

# Con cuerpo explicativo
git commit -m "feat: add adversarial training

- Implement GCG-style adversarial training
- Add integration with HarmBench framework
- Include benchmarks for jailbreak resistance

Closes #123"
```

### 3. Enviar PR

**Plantilla de PR:**
```markdown
## Descripción
[Qué hace este cambio]

## Tipo de Cambio
- [ ] 🐛 Bug fix
- [ ] ✨ Nueva funcionalidad
- [ ] 📝 Documentación
- [ ] 🔧 Refactor
- [ ] 🧪 Tests

## Testing
- [ ] Tests unitarios pasan
- [ ] Tests de integración pasan
- [ ] Cobertura de código >= 80%

## Checklist
- [ ] Código sigue convenciones
- [ ] Documentación actualizada
- [ ] No rompe funcionalidad existente
- [ ] Commit messages son claros
```

---

## 🔒 Seguridad

### Reportar Vulnerabilidades

**⚠️ NO uses GitHub Issues para reportar vulnerabilidades.**

**Canal seguro:** `security@govllm-sentinel.gov`

**Incluir:**
- Descripción de la vulnerabilidad
- Pasos para reproducir
- Impacto potencial
- Fix sugerido (si tienes)

**Proceso:**
1. Envía reporte
2. Recibe confirmación en 48 horas
3. Coordinar divulgación
4. Recibe reconocimiento (opcional)

### Responsable Disclosure

Seguimos el [Coordinated Vulnerability Disclosure](https://www.first.org/cvss/calculator/3.1).

---

## 📜 Licencia

Al contribuir, aceptas que tus contribuciones bajo la [Licencia del Proyecto](./LICENSE).

---

## ❓ Preguntas

- **Discusiones:** GitHub Discussions
- **Email:** contribuciones@govllm-sentinel.gov
- **Discord:** [GovLLM-Sentinel](https://discord.gg/govllm-sentinel)

---

<div align="center">

**[⬆ Volver al inicio](./README.md)**

</div>
