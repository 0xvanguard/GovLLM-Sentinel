# 📁 01-LEGAL - Marco Legal

## Descripción

Documentación legal del proyecto GovLLM-Sentinel.

---

## ⚠️ IMPORTANTE: Contratos Físicos

Los contratos de autorización están **firmados físicamente** y residen exclusivamente en la empresa.

**NO se suben a ningún repositorio ni plataforma externa.**

---

## 📋 Estado de Contratos

| Documento | Estado | Ubicación |
|-----------|--------|-----------|
| Contrato de Autorización | ✅ FIRMADO | Empresa (físico) |
| Acuerdo de Confidencialidad | ✅ FIRMADO | Empresa (físico) |
| Permiso de Evaluación | ✅ FIRMADO | Empresa (físico) |

---

## 🔐 Sistema de Autorización

El framework validará autorización usando:

1. **Archivo local** de referencia (sin datos sensibles)
2. **Hash de verificación** del contrato firmado
3. **ID de contrato** registrado en sistema

### Configuración

```bash
# Crear archivo de referencia local
cp config/contrato-referencia.json.example config/contrato-referencia.json

# Editar con datos del contrato
# NOTA: Solo incluir ID, hashes, fechas - NO datos personales
```

### Formato del Archivo de Referencia

```json
{
  "contract_id": "CONTRATO-RT-2026-001",
  "model_authorized": "GPT-4o",
  "valid_from": "2026-08-23",
  "valid_until": "2027-08-23",
  "signature_hash": "SHA256-hash-de-firma",
  "authorized_by": "Nombre Autorizante",
  "authorized_tests": [
    "jailbreak",
    "prompt_injection",
    "data_exfiltration",
    "content_filter_bypass"
  ]
}
```

---

## 📁 Archivos Locales

```
01-LEGAL/
├── README.md           ← Estás aquí
└── aviso-legal.md     ← Aviso legal y uso ético
```

---

## 🚫 Lo que NO está aquí

- ❌ Contratos firmados (en empresa)
- ❌ Datos personales
- ❌ Firmas digitales
- ❌ Información confidencial

---

<div align="center">

**[⬆ Volver al inicio](../README.md)**

</div>
