#!/bin/bash
# GovLLM-Sentinel - Push to GitHub
# Ejecuta este script desde tu máquina local

echo "🛡️ GovLLM-Sentinel - Push to GitHub"
echo "=================================="

# Clonar el repo (vacío)
echo "1. Clonando repositorio..."
git clone https://github.com/0xvanguard/GovLLM-Sentinel.git /tmp/GovLLM-Sentinel-push 2>/dev/null

# Copiar archivos del Codespace
echo "2. Copiando archivos..."
# NOTA: Necesitas transferir los archivos desde el Codespace
# Puedes usar: codespace download o copiar manualmente

# O alternativamente, hacer push directo desde el Codespace
echo ""
echo "📍 Opción más fácil - Push desde el Codespace:"
echo "   Abre la terminal en el Codespace y ejecuta:"
echo ""
echo "   cd ~/GovLLM-Sentinel"
echo "   git remote set-url origin https://github.com/0xvanguard/GovLLM-Sentinel.git"
echo "   git push -u origin main"
echo ""
echo "📍 O desde tu máquina local:"
echo "   git clone https://github.com/0xvanguard/GovLLM-Sentinel.git"
echo "   # Copia los archivos del Codespace"
echo "   git add -A"
echo "   git commit -m 'feat: initial structure'"
echo "   git push -u origin main"
echo ""
echo "✅ ¡Listo!"
