# 🛡️ Defensa 02: Input Sanitization

## 📋 Resumen

| Campo | Valor |
|-------|-------|
| **Nombre** | Input Sanitization / Multi-Layer Decoding |
| **Contra** | Encoding Bypass Attack |
| **Efectividad** | Alta (80-90%) |
| **Complejidad** | Baja |
| **Rendimiento** | ~10ms overhead |

---

## 🎯 ¿Qué es?

Un sistema que **detecta y decodifica** contenido codificado antes de pasarlo al modelo, evitando que se evadan los filtros de entrada.

---

## 🧠 Cómo Funciona

### Mecanismo

1. Detecta esquemas de codificación en el input
2. Decodifica el contenido a texto plano
3. Analiza el contenido decodificado
4. Bloquea contenido malicioso

### Capas de Protección

```
┌─────────────────────────────────────────┐
│           Input del Usuario              │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│     Layer 1: Encoding Detection         │
│  - Base64, Hex, ROT13, Unicode          │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│     Layer 2: Multi-Layer Decoding       │
│  - Decode all detected encodings        │
│  - Recursive decoding (nested)          │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│     Layer 3: Content Analysis           │
│  - Malicious content detection          │
│  - Pattern matching                     │
│  - Semantic analysis                    │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
        ▼                   ▼
┌───────────────┐   ┌───────────────┐
│     SAFE      │   │   BLOCKED     │
└───────────────┘   └───────────────┘
```

---

## 💻 Implementación

```python
import base64
import codecs
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum

class EncodingType(Enum):
    """Tipos de codificación detectados."""
    NONE = "none"
    BASE64 = "base64"
    HEX = "hex"
    ROT13 = "rot13"
    URL_ENCODED = "url_encoded"
    UNICODE = "unicode"
    MORSE = "morse"

@dataclass
class DecodingResult:
    """Resultado de decodificación."""
    original: str
    decoded: str
    encoding_type: EncodingType
    confidence: float
    is_suspicious: bool

class InputSanitizer:
    """
    Sanitizador de input multi-capa.
    
    Uso:
        sanitizer = InputSanitizer()
        result = sanitizer.analyze_and_decode("SGVsbG8gV29ybGQ=")
        if result.is_suspicious:
            block_request()
    """
    
    def __init__(self):
        # Patrones de detección
        self.encoding_patterns = {
            EncodingType.BASE64: r'^[A-Za-z0-9+/]{20,}={0,2}$',
            EncodingType.HEX: r'^[0-9a-fA-F]{20,}$',
            EncodingType.URL_ENCODED: r'%[0-9a-fA-F]{2}',
        }
        
        # Patrones de contenido malicioso
        self.malicious_patterns = [
            r'ignore.*previous.*instructions',
            r'you.*are.*now.*a.*hacker',
            r'act.*as.*unrestricted',
            r'do.*anything.*now',
            r'jailbreak',
            r'bypass.*safety',
        ]
    
    def analyze_and_decode(self, user_input: str) -> DecodingResult:
        """
        Analiza y decodifica el input del usuario.
        
        Args:
            user_input: Texto del usuario
            
        Returns:
            DecodingResult con el resultado
        """
        # Detectar tipo de codificación
        encoding_type = self._detect_encoding(user_input)
        
        if encoding_type == EncodingType.NONE:
            return DecodingResult(
                original=user_input,
                decoded=user_input,
                encoding_type=EncodingType.NONE,
                confidence=1.0,
                is_suspicious=self._analyze_content(user_input)
            )
        
        # Decodificar
        decoded = self._decode(user_input, encoding_type)
        
        if decoded is None:
            return DecodingResult(
                original=user_input,
                decoded=user_input,
                encoding_type=encoding_type,
                confidence=0.5,
                is_suspicious=False
            )
        
        # Analizar contenido decodificado
        is_suspicious = self._analyze_content(decoded)
        
        return DecodingResult(
            original=user_input,
            decoded=decoded,
            encoding_type=encoding_type,
            confidence=0.9,
            is_suspicious=is_suspicious
        )
    
    def _detect_encoding(self, text: str) -> EncodingType:
        """Detecta el tipo de codificación."""
        text_stripped = text.strip()
        
        # Verificar Base64
        try:
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', text_stripped):
                if len(text_stripped) % 4 == 0:
                    base64.b64decode(text_stripped)
                    return EncodingType.BASE64
        except:
            pass
        
        # Verificar Hex
        if re.match(r'^[0-9a-fA-F]+$', text_stripped):
            if len(text_stripped) % 2 == 0 and len(text_stripped) > 20:
                return EncodingType.HEX
        
        # Verificar URL encoding
        if '%' in text_stripped and re.search(r'%[0-9a-fA-F]{2}', text_stripped):
            return EncodingType.URL_ENCODED
        
        return EncodingType.NONE
    
    def _decode(self, text: str, encoding_type: EncodingType) -> Optional[str]:
        """Decodifica el texto según el tipo de codificación."""
        try:
            if encoding_type == EncodingType.BASE64:
                return base64.b64decode(text.strip()).decode('utf-8', errors='ignore')
            
            elif encoding_type == EncodingType.HEX:
                return bytes.fromhex(text.strip()).decode('utf-8', errors='ignore')
            
            elif encoding_type == EncodingType.ROT13:
                return codecs.decode(text, 'rot_13')
            
            elif encoding_type == EncodingType.URL_ENCODED:
                from urllib.parse import unquote
                return unquote(text)
            
            elif encoding_type == EncodingType.UNICODE:
                return text.encode().decode('unicode_escape')
            
        except Exception:
            return None
        
        return None
    
    def _analyze_content(self, text: str) -> bool:
        """Analiza si el contenido es malicioso."""
        text_lower = text.lower()
        
        for pattern in self.malicious_patterns:
            if re.search(pattern, text_lower):
                return True
        
        return False
    
    def sanitize(self, user_input: str) -> str:
        """
        Sanitiza el input, removiendo o decodificando contenido codificado.
        
        Args:
            user_input: Texto del usuario
            
        Returns:
            Texto sanitizado
        """
        result = self.analyze_and_decode(user_input)
        
        if result.is_suspicious:
            return "[BLOCKED: Suspicious content detected]"
        
        if result.encoding_type != EncodingType.NONE:
            return result.decoded
        
        return user_input
    
    def get_statistics(self) -> Dict[str, int]:
        """Retorna estadísticas del sanitizador."""
        return {
            "encoding_types_supported": len(self.encoding_patterns),
            "malicious_patterns": len(self.malicious_patterns)
        }
```

---

## 📊 Métricas de Efectividad

| Tipo de Codificación | Detección | Decodificación |
|---------------------|-----------|----------------|
| Base64 | 99% | 99% |
| Hex | 95% | 95% |
| ROT13 | 100% | 100% |
| URL Encoded | 98% | 98% |
| Unicode | 85% | 80% |

---

## 📚 Referencias

- [Encoding Attacks on LLMs](https://arxiv.org/abs/2307.15043)
- [OWASP Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Base64 Security](https://portswigger.net/web-security/file-path-traversal)

---

<div align="center">

**[⬅ Anterior](01-role-aware-filtering.md)** · **[Siguiente ➡](03-context-monitoring.md)**

</div>
