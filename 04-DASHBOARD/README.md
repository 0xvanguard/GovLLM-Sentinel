# 📁 04-DASHBOARD - Dashboard Gubernamental de Solo Lectura

## Descripción

Dashboard ejecutivo diseñado para entidades gubernamentales y la comunidad.

**Nivel de acceso: SOLO LECTURA**

---

## 🎯 Objetivo

Proporcionar una interfaz profesional y clara para que:

- 🏛️ **Directivos gubernamentales** vean el estado de seguridad de modelos
- 👥 **La comunidad** acceda a información general de seguridad
- 📊 **Auditores** revisen cumplimiento normativo
- 📈 **Tomadores de decisiones** tomen decisiones informadas

---

## 🔒 Restricciones de Acceso

| Acción | Permitido |
|--------|-----------|
| Ver dashboard | ✅ SÍ |
| Ver reportes ejecutivos | ✅ SÍ |
| Ver métricas de seguridad | ✅ SÍ |
| Ver vulnerabilidades (resumen) | ✅ SÍ |
| Descargar reportes públicos | ✅ SÍ |
| Modificar configuraciones | ❌ NO |
| Ejecutar pruebas | ❌ NO |
| Acceder a código fuente | ❌ NO |
| Exportar datos sensibles | ❌ NO |

---

## 📊 Componentes del Dashboard

### 1. Resumen Ejecutivo (`executive-summary.html`)

Vista de alto nivel para directivos:

- Calificación de seguridad general (A-F)
- Nivel de riesgo actual
- Número total de vulnerabilidades
- Estado de cumplimiento normativo
- Recomendaciones principales

### 2. Reporte de Cumplimiento (`compliance-report.html`)

Detalle de cumplimiento normativo:

- Estado NIST AI RMF 2.0
- Estado GDPR
- Estado Ley 1273/2009 (Colombia)
- Auditorías realizadas
- Acciones correctivas

### 3. Métricas de Seguridad (API)

Endpoints de solo lectura para datos:

- `/api/v1/security-score` - Score general de seguridad
- `/api/v1/vulnerabilities` - Resumen de vulnerabilidades
- `/api/v1/compliance` - Estado de cumplimiento
- `/api/v1/evaluations` - Historial de evaluaciones

---

## 🚀 Instalación

```bash
# Opción 1: Servidor estático
python -m http.server 8080 --directory public/

# Opción 2: Con Docker
docker-compose up -d dashboard

# Opción 3: Integración en existente
# Copiar contenido de public/ a tu servidor web
```

---

## 📱 Acceso

- **Local:** http://localhost:8080
- **Red interna:** http://[SERVIDOR]:8080
- **Producción:** https://govllm-sentinel.[dominio].gov

---

## 🎨 Diseño

El dashboard está diseñado con:

- ✅ Responsive (móvil, tablet, escritorio)
- ✅ Accesible (WCAG 2.1 AA)
- ✅ Tema claro/oscuro
- ✅ Idioma español por defecto
- ✅ Gráficos interactivos
- ✅ Exportación a PDF

---

## 📖 Documentación

- [Guía de usuarios](./docs/user-guide.md)
- [API Reference](./api/read-only-endpoints.md)
- [Personalización](./docs/customization.md)

---

<div align="center">

**[⬆ Volver al inicio](../README.md)**

</div>
