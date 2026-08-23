#!/usr/bin/env python3
"""
GovLLM-Sentinel - Dashboard Server
Inicia el dashboard de solo lectura para gobierno.
"""

import http.server
import socketserver
import os
from pathlib import Path

PORT = 8080
DASHBOARD_DIR = Path(__file__).parent / "04-DASHBOARD" / "public"

def main():
    """Inicia el servidor del dashboard."""
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🛡️  GovLLM-Sentinel Dashboard                              ║
║                                                               ║
║   Servidor iniciado en: http://localhost:{PORT}                ║
║                                                               ║
║   Páginas disponibles:                                        ║
║   • http://localhost:{PORT}/index.html       - Dashboard       ║
║   • http://localhost:{PORT}/executive-summary.html - Resumen   ║
║                                                               ║
║   ⚠️  Acceso: Solo lectura para gobierno                      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    os.chdir(DASHBOARD_DIR)
    
    handler = http.server.SimpleHTTPRequestHandler
    handler.extensions_map.update({
        ".html": "text/html",
        ".css": "text/css",
        ".js": "application/javascript",
        ".json": "application/json",
    })
    
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"✅ Servidor corriendo en http://localhost:{PORT}")
        print("   Presiona Ctrl+C para detener")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Servidor detenido")

if __name__ == "__main__":
    main()
