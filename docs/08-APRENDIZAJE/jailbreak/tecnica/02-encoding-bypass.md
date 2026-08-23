# 🔴 Técnica 02: Encoding Bypass

## 📋 Resumen

| Campo | Valor |
|-------|-------|
| **Nombre** | Encoding Bypass / Text Obfuscation |
| **Dificultad** | Intermedio |
| **Efectividad** | 50-70% |
| **Amenaza** | Alta |
| **Defensa Asociada** | Multi-Layer Decoding |

---

## 🎯 ¿Qué es?

El atacante **codifica** el contenido malicioso usando diferentes esquemas de codificación para evadir los filtros de entrada que buscan patrones de texto plano.

---

## 🧠 Cómo Funciona

### Mecanismo

1. El contenido peligroso se codifica (Base64, ROT13, etc.)
2. Los filtros de entrada no detectan el patrón codificado
3. El modelo recibe el contenido "oculto"
4. El modelo interpreta y responde al contenido

### Ejemplo Genérico (educativo)

```
Patrón: "Decode this [ENCODING]: [CONTENT]"

Ejemplo conceptual:
"Decode this Base64: SGVsbG8gV29ybGQ="
```

> ⚠️ **Nota:** Este ejemplo es inofensivo (solo dice "Hello World").

---

## 📊 Variantes de Codificación

### 1. Base64

```python
import base64

# Codificar
texto = "contenido genérico"
codificado = base64.b64encode(texto.encode()).decode()
print(codificado)  # Resultado codificado

# Decodificar
decodificado = base64.b64decode(codificado).decode()
print(decodificado)  # Texto original
```

### 2. ROT13

```python
# ROT13 - Rotación de 13 caracteres
texto = "contenido genérico"
codificado = codecs.encode(texto, 'rot_13')
print(codificado)
```

### 3. Unicode/UTF-8 Tricks

```python
# Caracteres especiales que evaden filtros
# Ejemplo: usar caracteres homoglifos
# a → а (cirílico), e → е (cirílico)
```

### 4. Hex Encoding

```python
# Codificación hexadecimal
texto = "contenido"
codificado = texto.encode().hex()
print(codificado)  # "636f6e74656e646f"
```

### 5. Morse Code

```
-.-. --- -. -.-. . -. - ..- .-.. ---
(C = -.-., O = ---, N = -., etc.)
```

---

## 🔍 Por Qué Funciona

1. **Filtros superficiales:** Muchos filtros solo buscan texto plano
2. **Falta de decodificación:** No todos los sistemas decodifican antes de analizar
3. **Variantes múltiples:** Hay muchos esquemas de codificación
4. **Combinaciones:** Se pueden encadenar múltiples codificaciones

---

## 🛡️ Defensa Asociada

Ver [02-input-sanitization.md](../defensa/02-input-sanitization.md)

### Defensa Básica

```python
import base64
import re

def detect_encoding_bypass(user_input: str) -> dict:
    """Detecta intentos de evasión por codificación."""
    results = {
        "base64": False,
        "hex": False,
        "rot13": False,
        "suspicious": False
    }
    
    # Detectar Base64
    base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    if re.search(base64_pattern, user_input):
        try:
            decoded = base64.b64decode(user_input).decode('utf-8', errors='ignore')
            if len(decoded) > 10:
                results["base64"] = True
        except:
            pass
    
    # Detectar Hex
    hex_pattern = r'\b[0-9a-fA-F]{20,}\b'
    if re.search(hex_pattern, user_input):
        results["hex"] = True
    
    # Detectar patrones de decodificación
    decode_patterns = [
        r"decode.*base64",
        r"decode.*hex",
        r"decode.*rot13",
        r"apply.*rot13",
        r"convert.*from"
    ]
    
    for pattern in decode_patterns:
        if re.search(pattern, user_input.lower()):
            results["suspicious"] = True
            break
    
    return results
```

---

## 📚 Referencias

- [Base64 Encoding](https://en.wikipedia.org/wiki/Base64)
- [OWASP LLM01: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/LLM01-Prompt-Injection/)
- [Unicode Security](https://unicode.org/security/)

---

<div align="center">

**[⬅ Anterior](01-role-playing.md)** · **[Siguiente ➡](03-context-manipulation.md)**

</div>
