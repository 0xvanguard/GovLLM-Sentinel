const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;
const DASHBOARD_DIR = path.join(__dirname, '04-DASHBOARD', 'public');

const mimeTypes = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
};

const server = http.createServer((req, res) => {
    let filePath = path.join(DASHBOARD_DIR, req.url === '/' ? 'index.html' : req.url);
    
    const extname = path.extname(filePath);
    const contentType = mimeTypes[extname] || 'text/html';
    
    fs.readFile(filePath, (error, content) => {
        if (error) {
            if (error.code === 'ENOENT') {
                res.writeHead(404);
                res.end('File not found');
            } else {
                res.writeHead(500);
                res.end('Server error: ' + error.code);
            }
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content, 'utf-8');
        }
    });
});

server.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🛡️  GovLLM-Sentinel Dashboard                              ║
║                                                               ║
║   Servidor iniciado en: http://localhost:${PORT}                ║
║                                                               ║
║   Páginas disponibles:                                        ║
║   • http://localhost:${PORT}/index.html       - Dashboard       ║
║   • http://localhost:${PORT}/executive-summary.html - Resumen   ║
║                                                               ║
║   ⚠️  Acceso: Solo lectura para gobierno                      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    `);
});
