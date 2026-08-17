const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ROOT_DIR = path.resolve(__dirname);
const REPORTS_DIR = path.join(ROOT_DIR, 'reports');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function updateReportsManifest() {
  try {
    if (!fs.existsSync(REPORTS_DIR)) return;
    const files = fs.readdirSync(REPORTS_DIR);
    const reportFiles = files.filter(f => f.endsWith('.json') && f !== 'reports.json' && f !== 'manifest.json');
    
    const manifest = [];
    for (const file of reportFiles) {
      try {
        const fullPath = path.join(REPORTS_DIR, file);
        const data = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
        const scan = data.scan || {};
        const summary = scan.summary || {};
        manifest.push({
          filename: file,
          path: `reports/${file}`,
          target: scan.target || data.target || 'Unknown',
          timestamp: scan.timestamp || data.timestamp || new Date().toISOString(),
          formattedDate: scan.formattedDate || new Date().toLocaleString(),
          total: summary.total !== undefined ? summary.total : (data.findings ? data.findings.length : 0),
          active: summary.active !== undefined ? summary.active : (data.findings ? data.findings.filter(f => !f.isFalsePositive).length : 0),
          falsePositives: summary.falsePositives !== undefined ? summary.falsePositives : (data.findings ? data.findings.filter(f => !!f.isFalsePositive).length : 0),
          critical: summary.critical || 0,
          high: summary.high || 0,
          medium: summary.medium || 0,
          low: summary.low || 0
        });
      } catch (e) {}
    }

    manifest.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    fs.writeFileSync(path.join(REPORTS_DIR, 'reports.json'), JSON.stringify(manifest, null, 2), 'utf8');
  } catch (err) {
    console.error('Error updating manifest:', err.message);
  }
}

const server = http.createServer((req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // Handle CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // API: Toggle False Positive
  if (req.method === 'POST' && pathname === '/api/toggle-fp') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const { filename, findingId, isFalsePositive } = JSON.parse(body);
        if (!filename || !findingId) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing filename or findingId' }));
          return;
        }

        const safeFilename = path.basename(filename);
        const reportPath = path.join(REPORTS_DIR, safeFilename);

        if (!fs.existsSync(reportPath)) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Report file ${safeFilename} not found` }));
          return;
        }

        const reportData = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
        const findings = reportData.findings || [];
        const targetFinding = findings.find(f => String(f.id) === String(findingId));

        if (!targetFinding) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: `Finding ${findingId} not found in report` }));
          return;
        }

        targetFinding.isFalsePositive = !!isFalsePositive;

        // Recalculate summary stats
        const activeFindings = findings.filter(f => !f.isFalsePositive);
        const fpFindings = findings.filter(f => !!f.isFalsePositive);

        if (!reportData.scan) reportData.scan = {};
        reportData.scan.summary = {
          critical: activeFindings.filter(f => f.severity === 'CRITICAL').length,
          high: activeFindings.filter(f => f.severity === 'HIGH').length,
          medium: activeFindings.filter(f => f.severity === 'MEDIUM').length,
          low: activeFindings.filter(f => f.severity === 'LOW').length,
          active: activeFindings.length,
          falsePositives: fpFindings.length,
          total: findings.length
        };

        fs.writeFileSync(reportPath, JSON.stringify(reportData, null, 2), 'utf8');
        updateReportsManifest();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, findingId, isFalsePositive: !!isFalsePositive }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // API: Save Full Report
  if (req.method === 'POST' && pathname === '/api/save-report') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const { filename, report } = JSON.parse(body);
        const safeFilename = path.basename(filename || 'report.json');
        const reportPath = path.join(REPORTS_DIR, safeFilename);

        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');
        updateReportsManifest();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, filename: safeFilename }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // API: Get Full File Content
  if (req.method === 'GET' && pathname === '/api/file-content') {
    const targetFile = parsedUrl.searchParams.get('path');
    if (!targetFile) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing path query parameter' }));
      return;
    }

    const scanTarget = parsedUrl.searchParams.get('target');

    let candidates = [
      targetFile,
      path.isAbsolute(targetFile) ? targetFile : null,
      scanTarget ? path.resolve(scanTarget, targetFile) : null,
      path.resolve(ROOT_DIR, targetFile),
      path.resolve(ROOT_DIR, '..', targetFile),
      path.resolve('/Users/manishbansal/code', targetFile)
    ].filter(Boolean);

    let resolvedPath = candidates.find(p => {
      try {
        return fs.existsSync(p) && !fs.statSync(p).isDirectory();
      } catch (e) {
        return false;
      }
    });

    if (!resolvedPath) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `File not found: ${targetFile}` }));
      return;
    }

    try {
      const stats = fs.statSync(resolvedPath);
      if (stats.isDirectory()) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Path is a directory, not a file' }));
        return;
      }

      if (stats.size > 8 * 1024 * 1024) {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'File is too large (> 8MB)' }));
        return;
      }

      const content = fs.readFileSync(resolvedPath, 'utf8');
      const lines = content.split(/\r?\n/);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        path: resolvedPath,
        filename: path.basename(resolvedPath),
        totalLines: lines.length,
        sizeBytes: stats.size,
        content: content
      }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }

  // Static File Serving
  let filePath = pathname === '/' || pathname === '/index.html'
    ? path.join(ROOT_DIR, 'index.html')
    : path.join(ROOT_DIR, pathname);

  // Security: prevent directory traversal outside ROOT_DIR
  if (!filePath.startsWith(ROOT_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    // If reports/index.html requested or fallback to root viewer
    if (pathname.startsWith('/reports/')) {
      filePath = path.join(REPORTS_DIR, pathname.replace('/reports/', ''));
    }
    if (!fs.existsSync(filePath)) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
      return;
    }
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  try {
    const data = fs.readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  } catch (err) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Internal Server Error: ' + err.message);
  }
});

server.listen(PORT, () => {
  updateReportsManifest();
  console.log('\n╔══════════════════════════════════════════════════════════════════╗');
  console.log('║   🛡️  IBM SecretScanner Report Viewer Server                     ║');
  console.log('╠══════════════════════════════════════════════════════════════════╣');
  console.log(`║  Viewer URL:  http://localhost:${PORT}                           ║`);
  console.log('║  Disk Sync:   Active (Auto-updates JSON files on disk on click) ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝\n');
});
