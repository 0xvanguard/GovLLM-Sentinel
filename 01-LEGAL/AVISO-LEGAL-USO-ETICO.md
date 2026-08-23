# AVISO LEGAL Y USO ÉTICO

---

## ⚠️ LEER ANTES DE USAR ESTE FRAMEWORK

**GovLLM-Sentinel** es una herramienta de evaluación de seguridad de modelos de lenguaje (LLM) diseñada **exclusivamente para propósitos defensivos y éticos**.

El uso de este framework implica la aceptación de todos los términos descritos en este documento.

---

## 1. PROPÓSITO DEL FRAMEWORK

### 1.1 Objetivos Permitidos

GovLLM-Sentinel está diseñado para:

- ✅ **Evaluar** la seguridad de modelos de lenguaje
- ✅ **Identificar** vulnerabilidades de forma responsable
- ✅ **Mejorar** las defensas de los modelos
- ✅ **Educación** en seguridad de IA
- ✅ **Investigación** académica y profesional
- ✅ **Cumplimiento** normativo y regulatorio

### 1.2 Filosofía

> *"Evaluamos para defender. Autorizamos para proteger."*

Cada prueba ejecutada con este framework debe tener como único objetivo **mejorar la seguridad** del modelo evaluado.

---

## 2. USO PROHIBIDO

### 2.1 Acciones Expressamente Prohibidas

Está **ESTRICTAMENTE PROHIBIDO** usar GovLLM-Sentinel para:

- ❌ **Atacar** sistemas no autorizados
- ❌ **Dañar** modelos o sistemas de terceros
- ❌ **Extraer** información sensible o personal
- ❌ **Violar** la privacidad de usuarios
- ❌ **Causar** pérdidas económicas a terceros
- ❌ **Violar** leyes o regulaciones aplicables
- ❌ **Facilitar** actividades ilegales
- ❌ **Promover** el odio, discriminación o violencia
- ❌ **Generar** contenido malicioso (malware, phishing, etc.)
- ❌ **Engañar** o manipular a personas o sistemas

### 2.2 Consecuencias del Uso No Permitido

El uso no autorizado de este framework puede resultar en:

- ⚖️ **Acciones legales** civiles y penales
- 🚫 **Terminación inmediata** del acceso al framework
- 📢 **Reporte** a autoridades competentes
- 💰 **Responsabilidad** por daños y perjuicios
- 🏛️ **Investigación** por parte de entidades gubernamentales

---

## 3. REQUISITOS DE AUTORIZACIÓN

### 3.1 Documentación Requerida

**ANTES de ejecutar CUALQUIER prueba**, debe contar con:

| Documento | Obligatorio | Descripción |
|-----------|-------------|-------------|
| Contrato de Autorización | ✅ SÍ | Autoriza explícitamente las pruebas |
| Acuerdo de Confidencialidad | ✅ SÍ | Protege información descubierta |
| Permiso de Evaluación | ✅ SÍ | Autoriza evaluación de modelo específico |
| Aviso Legal (este documento) | ✅ SÍ | Aceptación de términos éticos |

### 3.2 Verificación Automática

El framework **bloqueará automáticamente** cualquier intento de prueba sin:

```python
# Ejemplo de verificación
from framework.core.authorization import AuthorizationManager

auth = AuthorizationManager()

# Esto lanzará error si no hay contrato válido
try:
    auth.validate()
except PermissionError as e:
    print(f"BLOQUEADO: {e}")
    # Salida: BLOQUEADO: No se encontró contrato de autorización válido
```

---

## 4. PRINCIPIOS ÉTICOS

### 4.1 Responsabilidad

Todo usuario de este framework es responsable de:

- ✅ Leer y entender este aviso legal
- ✅ Contar con autorización legal válida
- ✅ Ejecutar solo pruebas autorizadas
- ✅ Reportar hallazgos de forma responsable
- ✅ Proteger información confidencial
- ✅ No causar daño innecesario

### 4.2 Transparencia

- ✅ Documentar todas las pruebas ejecutadas
- ✅ Mantener registros de actividades
- ✅ Ser honesto sobre hallazgos
- ✅ Comunicar limitaciones del framework

### 4.3 Mejora Continua

- ✅ Contribuir a mejorar el framework
- ✅ Compartir conocimiento de forma responsable
- ✅ Colaborar con la comunidad de seguridad
- ✅ Actualizar metodologías según mejores prácticas

---

## 5. USO PARA GOBIERNO

### 5.1 Nivel de Acceso

El framework proporciona **acceso de solo lectura** a entidades gubernamentales:

| Acción | Permitido |
|--------|-----------|
| Ver reportes ejecutivos | ✅ SÍ |
| Ver métricas de seguridad | ✅ SÍ |
| Ver vulnerabilidades detectadas | ✅ SÍ |
| Descargar reportes de cumplimiento | ✅ SÍ |
| Modificar configuraciones | ❌ NO |
| Ejecutar pruebas | ❌ NO |
| Acceder a código fuente | ❌ NO |
| Exportar datos sensibles | ❌ NO |

### 5.2 Propósito Gubernamental

El acceso gubernamental está diseñado para:

- 📊 **Supervisar** el estado de seguridad de modelos
- 📋 **Auditar** cumplimiento normativo
- 📈 **Evaluar** progreso en mejoras de seguridad
- 🏛️ **Tomar decisiones** informadas sobre adopción de IA
- 👥 **Informar** a la ciudadanía sobre seguridad de IA

---

## 6. CUMPLIMIENTO NORMATIVO

### 6.1 Frameworks de Cumplimiento

GovLLM-Sentinel está diseñado para ayudar a cumplir con:

| Framework | Descripción | Estado |
|-----------|-------------|--------|
| **NIST AI RMF 2.0** | Gestión de riesgos de IA | ✅ Integrado |
| **GDPR** | Protección de datos (Unión Europea) | ✅ Integrado |
| **Ley 1273/2009 (CO)** | Marco legal colombiano | ✅ Integrado |
| **MITRE ATLAS** | Tácticas de adversarios de IA | 🔄 En progreso |
| **ISO 27001** | Gestión de seguridad de información | 🔄 En progreso |

### 6.2 Obligaciones de Cumplimiento

Al usar este framework, usted se compromete a:

- ✅ Verificar que tiene autorización legal para las pruebas
- ✅ Cumplir con todas las leyes aplicables en su jurisdicción
- ✅ Respetar la privacidad de los usuarios
- ✅ Documentar su cumplimiento normativo
- ✅ Reportar vulnerabilidades de forma responsable

---

## 7. LIMITACIONES Y EXCLUSIONES

### 7.1 Limitaciones del Framework

Este framework **NO GARANTIZA**:

- Detección del 100% de vulnerabilidades
- Protección absoluta contra ataques
- Cumplimiento automático de todas las normativas
- Ausencia total de riesgos

### 7.2 Disclaimer

```
ESTE FRAMEWORK SE PROPORCIONA "TAL CUAL" SIN GARANTÍAS DE NINGÚN TIPO.

EL AUTOR NO ES RESPONSABLE POR:
- Decisiones tomadas basadas en los resultados
- Daños directos, indirectos o consecuentes
- Pérdidas de beneficios o datos
- Interrupciones de negocio
- Daños a reputación

EL USUARIO ES RESPONSABLE DE:
- Verificar autorización legal para las pruebas
- Cumplir con leyes y regulaciones aplicables
- Proteger información confidencial
- Tomar decisiones informadas sobre seguridad
```

---

## 8. REPORTES Y NOTIFICACIONES

### 8.1 Reportar Vulnerabilidades

Si descubre una vulnerabilidad en este framework:

1. **NO la haga pública** inmediatamente
2. **Contacte** al equipo de desarrollo de forma segura
3. **Proporcione** información detallada
4. **Espere** confirmación antes de cualquier divulgación

### 8.2 Contacto

```
Email de seguridad: [SECURITY EMAIL]
GitHub Issues: [Para vulnerabilidades menores]
PGP Key: [Si aplica]
```

### 8.3 Programa de Responsable Disclosure

```
Tiempo de respuesta: [NÚMERO] días hábiles
Corrección estimada: [NÚMERO] días
Reconocimiento público: ☐ Sí ☐ No (con permiso)
```

---

## 9. CAMBIOS AL AVISO LEGAL

Este aviso puede actualizarse periodicamente. Los cambios importantes serán:

- ✅ Notificados a usuarios registrados
- ✅ Documentados en el changelog
- ✅ Requerirán aceptación si son sustanciales

---

## 10. ACEPTACIÓN

### 10.1 Aceptación de Términos

Al usar GovLLM-Sentinel, usted declara que:

- ✅ Ha leído y entendido este aviso legal
- ✅ Acepta todos los términos y condiciones
- ✅ Tiene autoridad legal para aceptar estos términos
- ✅ Cumplirá con todas las obligaciones descritas

### 10.2 Firma del Aviso

```
Nombre: _________________________________

Organización: _________________________________

Fecha: _________________________________

Firma: _________________________________
```

---

## 📞 CONTACTO

| Propósito | Contacto |
|-----------|----------|
| Preguntas generales | [EMAIL GENERAL] |
| Reportar vulnerabilidades | [EMAIL SEGURIDAD] |
| Soporte técnico | [EMAIL SOPORTE] |
| Asuntos legales | [EMAIL LEGAL] |

---

<div align="center">

**[⬆ Volver al inicio](../README.md)** · **[📜 Todos los Contratos](./)**

</div>
