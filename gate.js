// AOS Gate — Drop-in audit proxy for AI workflows
// Copyright (c) 2026 Gene Salvatore / AOS (Agentic Operating System)
// Licensed under the AOS Humanitarian License v1.0.1
// https://aos-constitution.com
//
// HUMANITARIAN USE ONLY — Military and harmful applications PROHIBITED.
// Full license: LICENSE file in this repository.
//
// Drop-in API proxy for N8N → LLM workflows.
// Sits between your automation tool and the LLM provider.
// Logs every request/response, scans for PII, enforces basic rules.
//
// NOT a policy engine — just standard audit logging and content filtering
// applied to the gap between your workflow tool and the AI.
//
// Usage: Point your N8N HTTP Request nodes at http://aos-gate:3100
//        instead of https://api.anthropic.com or https://api.openai.com
// ─────────────────────────────────────────────────────────────────────────────

import express from 'express';
import { mkdirSync, appendFileSync, readFileSync, existsSync, readdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import https from 'https';

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'));
const GATE_VERSION = pkg.version || '1.0.0';

const app = express();
const GATE_PORT = process.env.GATE_PORT || 3100;
const DASHBOARD_PORT = process.env.DASHBOARD_PORT || 3101;
const LOG_DIR = process.env.LOG_DIR || './logs';
const POLICY_FILE = process.env.POLICY_FILE || './policy.json';

// Ensure log directory exists
mkdirSync(LOG_DIR, { recursive: true });

// ─── Load Policy ────────────────────────────────────────────────────────────
let policy = {
    blockedPatterns: [],
    maxTokens: null,
    allowedModels: [],
    logLevel: 'full'           // 'full' = log prompts+responses, 'meta' = metadata only
};

if (existsSync(POLICY_FILE)) {
    try {
        policy = { ...policy, ...JSON.parse(readFileSync(POLICY_FILE, 'utf-8')) };
        console.log(`📋 Policy loaded from ${POLICY_FILE}`);
    } catch (e) {
        console.warn(`⚠ Could not parse ${POLICY_FILE}, using defaults`);
    }
}

// ─── PII Scanner ────────────────────────────────────────────────────────────
// Basic regex patterns for common PII. Not exhaustive — just a first line.
const PII_PATTERNS = [
    { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
    { name: 'Credit Card', pattern: /\b(?:\d{4}[- ]?){3}\d{4}\b/g },
    { name: 'Email', pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g },
    { name: 'Phone (US)', pattern: /\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b/g },
];

function scanForPII(text) {
    const findings = [];
    for (const { name, pattern } of PII_PATTERNS) {
        const matches = text.match(pattern);
        if (matches) {
            findings.push({ type: name, count: matches.length });
        }
    }
    return findings;
}

// ─── Content Scanner ────────────────────────────────────────────────────────
function scanForBlockedContent(text) {
    const violations = [];
    for (const entry of (policy.blockedPatterns || [])) {
        const regex = new RegExp(entry.pattern, entry.flags || 'gi');
        if (regex.test(text)) {
            violations.push(entry.label || entry.pattern);
        }
    }
    return violations;
}

// ─── Audit Logger ───────────────────────────────────────────────────────────
function logEntry(entry) {
    const date = new Date().toISOString().split('T')[0];
    const logFile = join(LOG_DIR, `gate-${date}.jsonl`);
    appendFileSync(logFile, JSON.stringify(entry) + '\n');
}

// ─── Proxy Middleware ───────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ limit: '10mb' }));

// Health check
app.get('/health', (_req, res) => {
    res.json({ status: 'ok', uptime: process.uptime(), policy: !!existsSync(POLICY_FILE) });
});

// ─── Anthropic Proxy (/v1/messages) ─────────────────────────────────────────
app.post('/v1/messages', async (req, res) => {
    const startTime = Date.now();
    const requestBody = req.body;
    const apiKey = req.headers['x-api-key'] || '';

    // Extract prompt text for scanning
    const promptText = (requestBody.messages || [])
        .map(m => typeof m.content === 'string' ? m.content : JSON.stringify(m.content))
        .join('\n');

    // ── Pre-flight checks ──
    const piiFindings = scanForPII(promptText);
    const blockedContent = scanForBlockedContent(promptText);

    // Model allowlist check
    if (policy.allowedModels?.length > 0 && !policy.allowedModels.includes(requestBody.model)) {
        const entry = {
            timestamp: new Date().toISOString(),
            provider: 'anthropic',
            action: 'BLOCKED',
            reason: `Model "${requestBody.model}" not in allowlist`,
            model: requestBody.model,
        };
        logEntry(entry);
        return res.status(403).json({ error: 'Model not permitted by policy', gate: entry });
    }

    // Blocked content check
    if (blockedContent.length > 0) {
        const entry = {
            timestamp: new Date().toISOString(),
            provider: 'anthropic',
            action: 'BLOCKED',
            reason: `Content policy violation: ${blockedContent.join(', ')}`,
            model: requestBody.model,
        };
        logEntry(entry);
        return res.status(403).json({ error: 'Content blocked by policy', gate: entry });
    }

    // PII warning (log but don't block — configurable)
    if (piiFindings.length > 0) {
        logEntry({
            timestamp: new Date().toISOString(),
            provider: 'anthropic',
            action: 'PII_WARNING',
            findings: piiFindings,
            model: requestBody.model,
        });
    }

    // ── Forward to Anthropic ──
    const targetUrl = `${process.env.ANTHROPIC_API_URL || 'https://api.anthropic.com'}/v1/messages`;

    try {
        const upstream = await fetch(targetUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
                'anthropic-version': req.headers['anthropic-version'] || '2023-06-01',
            },
            body: JSON.stringify(requestBody),
        });

        const responseBody = await upstream.json();
        const duration = Date.now() - startTime;

        // Extract response text
        const responseText = (responseBody.content || [])
            .map(c => c.text || '')
            .join('\n');

        // Scan response for PII too
        const responsePII = scanForPII(responseText);

        // Log the full exchange
        const entry = {
            timestamp: new Date().toISOString(),
            provider: 'anthropic',
            action: 'PASSED',
            model: requestBody.model,
            durationMs: duration,
            inputTokens: responseBody.usage?.input_tokens,
            outputTokens: responseBody.usage?.output_tokens,
            inputPII: piiFindings.length > 0 ? piiFindings : undefined,
            outputPII: responsePII.length > 0 ? responsePII : undefined,
        };

        // Full logging mode includes prompt/response text
        if (policy.logLevel === 'full') {
            entry.prompt = promptText.substring(0, 2000); // cap at 2k chars
            entry.response = responseText.substring(0, 2000);
        }

        logEntry(entry);

        // Forward response to N8N
        res.status(upstream.status).json(responseBody);

    } catch (err) {
        const entry = {
            timestamp: new Date().toISOString(),
            provider: 'anthropic',
            action: 'ERROR',
            error: err.message,
            model: requestBody.model,
        };
        logEntry(entry);
        res.status(502).json({ error: 'Gateway error', message: err.message });
    }
});

// ─── OpenAI Proxy (/v1/chat/completions) ────────────────────────────────────
app.post('/v1/chat/completions', async (req, res) => {
    const startTime = Date.now();
    const requestBody = req.body;
    const authHeader = req.headers['authorization'] || '';

    const promptText = (requestBody.messages || [])
        .map(m => typeof m.content === 'string' ? m.content : JSON.stringify(m.content))
        .join('\n');

    const piiFindings = scanForPII(promptText);
    const blockedContent = scanForBlockedContent(promptText);

    if (policy.allowedModels?.length > 0 && !policy.allowedModels.includes(requestBody.model)) {
        const entry = {
            timestamp: new Date().toISOString(),
            provider: 'openai',
            action: 'BLOCKED',
            reason: `Model "${requestBody.model}" not in allowlist`,
            model: requestBody.model,
        };
        logEntry(entry);
        return res.status(403).json({ error: 'Model not permitted by policy', gate: entry });
    }

    if (blockedContent.length > 0) {
        const entry = {
            timestamp: new Date().toISOString(),
            provider: 'openai',
            action: 'BLOCKED',
            reason: `Content policy violation: ${blockedContent.join(', ')}`,
            model: requestBody.model,
        };
        logEntry(entry);
        return res.status(403).json({ error: 'Content blocked by policy', gate: entry });
    }

    if (piiFindings.length > 0) {
        logEntry({
            timestamp: new Date().toISOString(),
            provider: 'openai',
            action: 'PII_WARNING',
            findings: piiFindings,
            model: requestBody.model,
        });
    }

    const targetUrl = `${process.env.OPENAI_API_URL || 'https://api.openai.com'}/v1/chat/completions`;

    try {
        const upstream = await fetch(targetUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': authHeader,
            },
            body: JSON.stringify(requestBody),
        });

        const responseBody = await upstream.json();
        const duration = Date.now() - startTime;

        const responseText = (responseBody.choices || [])
            .map(c => c.message?.content || '')
            .join('\n');

        const responsePII = scanForPII(responseText);

        const entry = {
            timestamp: new Date().toISOString(),
            provider: 'openai',
            action: 'PASSED',
            model: requestBody.model,
            durationMs: duration,
            inputTokens: responseBody.usage?.prompt_tokens,
            outputTokens: responseBody.usage?.completion_tokens,
            inputPII: piiFindings.length > 0 ? piiFindings : undefined,
            outputPII: responsePII.length > 0 ? responsePII : undefined,
        };

        if (policy.logLevel === 'full') {
            entry.prompt = promptText.substring(0, 2000);
            entry.response = responseText.substring(0, 2000);
        }

        logEntry(entry);
        res.status(upstream.status).json(responseBody);

    } catch (err) {
        logEntry({
            timestamp: new Date().toISOString(),
            provider: 'openai',
            action: 'ERROR',
            error: err.message,
            model: requestBody.model,
        });
        res.status(502).json({ error: 'Gateway error', message: err.message });
    }
});

// ─── Start Gate ─────────────────────────────────────────────────────────────
app.listen(GATE_PORT, () => {
    console.log(`\n🚪 AOS Gate running on port ${GATE_PORT}`);
    console.log(`   Anthropic proxy: http://localhost:${GATE_PORT}/v1/messages`);
    console.log(`   OpenAI proxy:    http://localhost:${GATE_PORT}/v1/chat/completions`);
    console.log(`   Logs:            ${LOG_DIR}/`);
    console.log(`   Policy:          ${existsSync(POLICY_FILE) ? 'loaded' : 'none (defaults)'}\n`);
});

// ─── Audit Dashboard ────────────────────────────────────────────────────────
const dashboard = express();
import crypto from 'crypto';

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'aos-admin';
const sessionTokens = new Set();

dashboard.use(express.urlencoded({ extended: true }));
dashboard.use((req, res, next) => {
    req.cookies = req.headers.cookie?.split(';').reduce((acc, item) => {
        const data = item.trim().split('=');
        return { ...acc, [data[0]]: data[1] };
    }, {}) || {};
    next();
});

const requireAuth = (req, res, next) => {
    if (sessionTokens.has(req.cookies.aos_gate_session)) return next();
    res.redirect('/login');
};

dashboard.get('/login', (req, res) => {
    res.send(`<!DOCTYPE html>
<html><head><title>AOS Gate — Sovereign Auth</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0a; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
  .login-box { background: #151515; padding: 2.5rem; border-radius: 12px; border: 1px solid #222; width: 360px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
  .title { font-size: 1.2rem; margin-top: 0; margin-bottom: 0.25rem; text-align: center; font-weight: 700; letter-spacing: -0.02em; }
  .subtitle { font-size: 0.75rem; text-align: center; color: #666; margin-bottom: 2rem; font-family: monospace; text-transform: uppercase; letter-spacing: 0.1em; }
  input { width: 100%; padding: 0.85rem; margin-bottom: 1rem; background: #0a0a0a; border: 1px solid #333; color: #fff; border-radius: 6px; font-family: monospace; transition: border-color 0.2s; }
  input:focus { outline: none; border-color: #666; }
  button { width: 100%; padding: 0.85rem; background: #fff; color: #000; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
  button:hover { background: #e0e0e0; }
</style></head>
<body>
  <div class="login-box">
    <div style="display: flex; flex-direction: column; align-items: center; margin-bottom: 2rem;">
      <svg style="width: 48px; height: 48px; color: #fff; margin-bottom: 1rem;" viewBox="0 0 100 100" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
        <polygon points="50,20 80,40 50,100" fill="none" stroke="currentColor" stroke-width="8"/>
        <polygon points="50,40 70,55 50,80" fill="currentColor" />
        <line x1="35" y1="10" x2="35" y2="90" stroke="currentColor" stroke-width="12" />
      </svg>
      <div class="title">AOS Gate</div>
      <div class="subtitle" style="margin-bottom: 0;">Sovereign Admin</div>
    </div>
    <form method="POST" action="/login">
      <input type="password" name="password" placeholder="Passphrase" required autofocus/>
      <button type="submit">Authenticate</button>
    </form>
  </div>
</body></html>`);
});

dashboard.post('/login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) {
        const token = crypto.randomBytes(16).toString('hex');
        sessionTokens.add(token);
        res.setHeader('Set-Cookie', `aos_gate_session=${token}; HttpOnly; Path=/; Max-Age=86400`);
        res.redirect('/');
    } else {
        res.redirect('/login');
    }
});

dashboard.get('/logout', (req, res) => {
    if (req.cookies.aos_gate_session) sessionTokens.delete(req.cookies.aos_gate_session);
    res.setHeader('Set-Cookie', `aos_gate_session=; HttpOnly; Path=/; Max-Age=0`);
    res.redirect('/login');
});

// A common layout wrapper for the admin UI
const renderLayout = (title, content, currentPath) => `<!DOCTYPE html>
<html><head><title>AOS Gate — ${title}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; display: flex; min-height: 100vh; }
  .sidebar { width: 250px; background: #151515; border-right: 1px solid #222; display: flex; flex-direction: column; flex-shrink: 0; }
  .sidebar-header { padding: 1.5rem; border-bottom: 1px solid #222; }
  .sidebar-title { font-weight: 700; font-size: 1.25rem; color: #fff; letter-spacing: -0.02em; }
  .sidebar-nav { flex: 1; padding: 1.5rem 0; }
  .nav-item { display: block; padding: 0.75rem 1.5rem; color: #888; text-decoration: none; font-size: 0.9rem; transition: all 0.2s; border-left: 3px solid transparent; }
  .nav-item:hover { color: #fff; background: #222; }
  .nav-item.active { color: #fff; border-left: 3px solid #fff; background: #222; }
  .sidebar-footer { padding: 1.5rem; border-top: 1px solid #222; }
  .logout-btn { display: block; width: 100%; text-align: center; padding: 0.5rem; background: transparent; color: #888; text-decoration: none; border: 1px solid #333; border-radius: 4px; font-size: 0.8rem; transition: all 0.2s; }
  .logout-btn:hover { color: #fff; border-color: #666; }
  .main-content { flex: 1; padding: 2.5rem 3rem; overflow-y: auto; background: #0a0a0a; }
  h2 { font-size: 1.5rem; margin-bottom: 0.25rem; color: #fff; display: flex; justify-content: space-between; align-items: center; }
  .subtitle { color: #666; font-size: 0.85rem; margin-bottom: 2rem; font-family: monospace; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2.5rem; }
  .stat { background: #151515; border: 1px solid #222; border-radius: 8px; padding: 1.25rem; }
  .stat .label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; color: #666; }
  .stat .value { font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }
  .passed .value { color: #4ade80; }
  .blocked .value { color: #f87171; }
  .pii .value { color: #fbbf24; }
  .errors .value { color: #f97316; }
  .card { background: #151515; border: 1px solid #222; border-radius: 8px; margin-bottom: 2rem; overflow: hidden; }
  .card-header { padding: 1rem 1.5rem; border-bottom: 1px solid #222; font-weight: 600; font-size: 0.9rem; background: #111; color: #ddd; }
  .card-body { padding: 1.5rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { text-align: left; padding: 0.75rem 1.5rem; color: #666; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.1em; border-bottom: 1px solid #222; background: #111; }
  td { padding: 0.75rem 1.5rem; border-bottom: 1px solid #151515; }
  .mono { font-family: monospace; font-size: 0.8rem; color: #888; }
  .action-passed { color: #4ade80; }
  .action-blocked { color: #f87171; font-weight: 600; }
  .action-pii_warning { color: #fbbf24; }
  .action-error { color: #f97316; }
  /* Forms */
  .form-group { margin-bottom: 1.5rem; }
  label { display: block; font-size: 0.75rem; font-weight: 600; color: #999; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.05em; }
  textarea, input[type="text"], select { width: 100%; padding: 0.75rem; background: #0a0a0a; border: 1px solid #333; color: #e0e0e0; border-radius: 4px; font-family: monospace; font-size: 0.85rem; }
  textarea { min-height: 100px; resize: vertical; }
  button.submit-btn { padding: 0.75rem 1.5rem; background: #fff; color: #000; border: none; border-radius: 4px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
  button.submit-btn:hover { background: #ccc; }
  .pattern-row { display: grid; grid-template-columns: 1fr 2fr 80px 40px; gap: 0.75rem; margin-bottom: 0.75rem; align-items: start; }
  .btn-icon { background: #222; color: #fff; border: 1px solid #333; padding: 0.5rem; border-radius: 4px; cursor: pointer; text-align: center; }
  .btn-icon:hover { background: #333; }
  .btn-add { background: #151515; color: #fff; border: 1px dashed #333; padding: 0.5rem 1rem; cursor: pointer; font-size: 0.8rem; border-radius: 4px; display: inline-block; margin-top: 0.5rem; }
  .btn-add:hover { border-color: #666; }
</style>
<script>
  function addPatternRow() {
    const container = document.getElementById('patterns-container');
    const html = \`
      <div class="pattern-row">
        <input type="text" name="patternLabel" placeholder="Label (e.g. Internal Pricing)" required>
        <input type="text" name="patternRegex" placeholder="Regex (e.g. confidential\\\\s+pricing)" required>
        <input type="text" name="patternFlags" placeholder="Flags (gi)" value="gi">
        <button type="button" class="btn-icon" onclick="this.parentElement.remove()">✕</button>
      </div>\`;
    container.insertAdjacentHTML('beforeend', html);
  }
</script>
</head><body>
  <div class="sidebar">
    <div class="sidebar-header" style="display: flex; align-items: center; gap: 1rem;">
      <svg style="width: 32px; height: 32px; color: #fff; flex-shrink: 0;" viewBox="0 0 100 100" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
        <polygon points="50,20 80,40 50,100" fill="none" stroke="currentColor" stroke-width="8"/>
        <polygon points="50,40 70,55 50,80" fill="currentColor" />
        <line x1="35" y1="10" x2="35" y2="90" stroke="currentColor" stroke-width="12" />
      </svg>
      <div>
        <div class="sidebar-title">AOS Gate</div>
        <div style="font-size: 0.7rem; color:#666; margin-top:2px;">Sovereign Control</div>
      </div>
    </div>
    <div class="sidebar-nav">
      <a href="/" class="nav-item ${currentPath === '/' ? 'active' : ''}">Activity Log</a>
      <a href="/stats" class="nav-item ${currentPath === '/stats' ? 'active' : ''}">Usage Stats</a>
      <a href="/rules" class="nav-item ${currentPath === '/rules' ? 'active' : ''}">Policy &amp; Rules</a>
      <a href="/export" class="nav-item ${currentPath === '/export' ? 'active' : ''}">Export Logs</a>
      <a href="/docs" class="nav-item ${currentPath === '/docs' ? 'active' : ''}">Documentation</a>
    </div>
    <div class="sidebar-footer">
      <div style="font-size: 0.75rem; color: #666; margin-bottom: 0.5rem; text-align: center;">v${GATE_VERSION}</div>
      <button onclick="checkUpdate()" id="update-btn" style="width: 100%; padding:0.5rem; margin-bottom:0.5rem; background:#111; color:#888; border:1px solid #333; border-radius:4px; font-size:0.75rem; cursor:pointer; font-weight:bold;">Check for Updates</button>
      <a href="/logout" class="logout-btn">Sign Out</a>
    </div>
  </div>
  <div class="main-content">
    <h2>${title}</h2>
    ${content}
  </div>
  <script>
    function checkUpdate() {
       const btn = document.getElementById('update-btn');
       btn.innerText = 'Checking...';
       fetch('/update').then(r=>r.json()).then(d => {
           if (d.updateAvailable) {
               btn.style.background = '#064e3b';
               btn.style.color = '#a7f3d0';
               btn.style.border = '1px solid #047857';
               btn.innerText = 'v' + d.latest + ' Available! ↓';
               btn.onclick = () => alert('New version available. SSH into The Forge and run:\\n\\ncd aos-gate\\ngit pull origin main\\ndocker compose up -d --build');
           } else {
               btn.innerText = 'Up to Date ✓';
               setTimeout(() => { btn.innerText = 'Check for Updates'; }, 3000);
           }
       }).catch(e => {
           btn.innerText = 'Update Check Failed';
       });
    }
  </script>
</body></html>`;

// Helper: read entries for a given date string
function readEntriesForDate(date) {
    const logFile = join(LOG_DIR, `gate-${date}.jsonl`);
    if (!existsSync(logFile)) return [];
    return readFileSync(logFile, 'utf-8')
        .split('\n').filter(Boolean)
        .map(line => { try { return JSON.parse(line); } catch { return null; } })
        .filter(Boolean);
}

dashboard.get('/', requireAuth, (req, res) => {
    const date = req.query.date || new Date().toISOString().split('T')[0];
    const entries = readEntriesForDate(date);

    const passed = entries.filter(e => e.action === 'PASSED').length;
    const blocked = entries.filter(e => e.action === 'BLOCKED').length;
    const piiWarnings = entries.filter(e => e.action === 'PII_WARNING').length;
    const errors = entries.filter(e => e.action === 'ERROR').length;

    // Calculate prev/next dates
    const d = new Date(date + 'T12:00:00Z');
    const prev = new Date(d); prev.setDate(prev.getDate() - 1);
    const next = new Date(d); next.setDate(next.getDate() + 1);
    const prevStr = prev.toISOString().split('T')[0];
    const nextStr = next.toISOString().split('T')[0];
    const today = new Date().toISOString().split('T')[0];
    const isToday = date === today;

    const content = `
      <div class="subtitle" style="display:flex; align-items:center; gap:1rem;">
        <a href="/?date=${prevStr}" style="color:#888; text-decoration:none; font-size:1.2rem;">&larr;</a>
        <span>Log File: gate-${date}.jsonl &middot; ${entries.length} requests captured</span>
        ${!isToday ? `<a href="/?date=${nextStr}" style="color:#888; text-decoration:none; font-size:1.2rem;">&rarr;</a>` : ''}
        ${!isToday ? `<a href="/" style="color:#555; text-decoration:none; font-size:0.75rem; border:1px solid #333; padding:0.2rem 0.5rem; border-radius:4px;">Today</a>` : ''}
      </div>
      <div class="stats">
        <div class="stat passed"><div class="label">Passed</div><div class="value">${passed}</div></div>
        <div class="stat blocked"><div class="label">Blocked</div><div class="value">${blocked}</div></div>
        <div class="stat pii"><div class="label">PII Warnings</div><div class="value">${piiWarnings}</div></div>
        <div class="stat errors"><div class="label">Errors</div><div class="value">${errors}</div></div>
      </div>
      <div class="card">
        <div class="card-header">Audit Trail &mdash; ${date}</div>
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Provider</th><th>Model</th><th>Tokens (In/Out)</th><th>Duration</th><th>Notes</th></tr></thead>
          <tbody>
            ${entries.length > 0 ? entries.reverse().map(e => `<tr>
              <td class="mono">${e.timestamp?.split('T')[1]?.substring(0,8) || '\u2014'}</td>
              <td class="action-${(e.action||'').toLowerCase()}">${e.action}</td>
              <td>${e.provider || '\u2014'}</td>
              <td class="mono">${e.model || '\u2014'}</td>
              <td class="mono">${e.inputTokens || '\u2014'} / ${e.outputTokens || '\u2014'}</td>
              <td class="mono">${e.durationMs ? e.durationMs + 'ms' : '\u2014'}</td>
              <td class="mono" style="max-width:300px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${e.reason || (e.inputPII ? 'PII: ' + e.inputPII.map(p=>p.type).join(', ') : '') || (e.error || '')}">
                ${e.reason || (e.inputPII ? 'PII: ' + e.inputPII.map(p=>p.type).join(', ') : '') || (e.error || '') || ''}
              </td>
            </tr>`).join('') : `<tr><td colspan="7" style="text-align:center; padding: 2rem; color:#666;">No audit records found for ${date}.</td></tr>`}
          </tbody>
        </table>
      </div>
    `;
    res.send(renderLayout('Activity Log', content, '/'));
});

dashboard.get('/rules', requireAuth, (_req, res) => {
    let currentPolicy = { logLevel: 'full', allowedModels: [], blockedPatterns: [] };
    if (existsSync(POLICY_FILE)) {
        try { currentPolicy = JSON.parse(readFileSync(POLICY_FILE, 'utf-8')); } catch (e) {}
    }

    let messageHtml = '';
    if (_req.query.saved) {
        messageHtml = `<div style="background: #064e3b; color: #a7f3d0; padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem; font-weight: 600; border: 1px solid #047857;">✓ Policy updated securely. Changes applied to active memory immediately.</div>`;
    }

    const content = `
      <div class="subtitle">Gate configuration applied at the proxy level. Edits are deterministic.</div>
      ${messageHtml}
      <form method="POST" action="/rules">
        <div class="card">
          <div class="card-header">General Rules</div>
          <div class="card-body">
            <div class="form-group">
              <label>Log Level</label>
              <select name="logLevel">
                <option value="full" ${currentPolicy.logLevel === 'full' ? 'selected' : ''}>Full (Capture Prompt & Response Text)</option>
                <option value="meta" ${currentPolicy.logLevel !== 'full' ? 'selected' : ''}>Meta Only (Capture Usage Stats, Mask Text)</option>
              </select>
            </div>
            <div class="form-group" style="margin-bottom:0;">
              <label>Allowed Models (One per line)</label>
              <textarea name="allowedModels">${(currentPolicy.allowedModels || []).join('\\n')}</textarea>
              <div style="font-size:0.75rem; color:#666; margin-top:0.5rem;">Leave empty to allow all requested models.</div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">Content Block Rules (Regex)</div>
          <div class="card-body" style="padding-bottom:1rem;">
            <div id="patterns-container">
              ${(currentPolicy.blockedPatterns || []).map(p => `
                <div class="pattern-row">
                  <input type="text" name="patternLabel" value="${p.label || ''}" placeholder="Label" required>
                  <input type="text" name="patternRegex" value="${p.pattern || ''}" placeholder="Regex" required>
                  <input type="text" name="patternFlags" value="${p.flags || 'gi'}" placeholder="Flags">
                  <button type="button" class="btn-icon" onclick="this.parentElement.remove()">✕</button>
                </div>
              `).join('')}
            </div>
            <button type="button" class="btn-add" onclick="addPatternRow()">+ Add Block Rule</button>
          </div>
        </div>

        <button type="submit" class="submit-btn" style="width:100%; max-width:250px;">Save Rules to Disk</button>
      </form>
    `;
    res.send(renderLayout('Policy Settings', content, '/rules'));
});

dashboard.post('/rules', requireAuth, (req, res) => {
    // Process form body structure
    const updatedPolicy = {
        logLevel: req.body.logLevel || 'full',
        allowedModels: (req.body.allowedModels || '').replace(/\\r\\n/g, '\\n').split('\\n').map(s => s.trim()).filter(Boolean),
        blockedPatterns: []
    };

    const labels = req.body.patternLabel ? (Array.isArray(req.body.patternLabel) ? req.body.patternLabel : [req.body.patternLabel]) : [];
    const regexps = req.body.patternRegex ? (Array.isArray(req.body.patternRegex) ? req.body.patternRegex : [req.body.patternRegex]) : [];
    const flags = req.body.patternFlags ? (Array.isArray(req.body.patternFlags) ? req.body.patternFlags : [req.body.patternFlags]) : [];

    for (let i = 0; i < labels.length; i++) {
        if (regexps[i]) {
            updatedPolicy.blockedPatterns.push({
                label: labels[i],
                pattern: regexps[i],
                flags: flags[i] || 'gi'
            });
        }
    }

    writeFileSync(POLICY_FILE, JSON.stringify(updatedPolicy, null, 4));
    policy = updatedPolicy; // Hot reload active memory

    res.redirect('/rules?saved=1');
});

// ─── Usage Stats ────────────────────────────────────────────────────────────
dashboard.get('/stats', requireAuth, (_req, res) => {
    const files = readdirSync(LOG_DIR).filter(f => f.endsWith('.jsonl')).sort().reverse().slice(0, 14);
    const days = [];
    let maxTotal = 1;
    for (const file of files.reverse()) {
        const date = file.replace('gate-', '').replace('.jsonl', '');
        const entries = readEntriesForDate(date);
        const passed = entries.filter(e => e.action === 'PASSED').length;
        const blocked = entries.filter(e => e.action === 'BLOCKED').length;
        const pii = entries.filter(e => e.action === 'PII_WARNING').length;
        const errs = entries.filter(e => e.action === 'ERROR').length;
        const total = entries.length;
        if (total > maxTotal) maxTotal = total;
        days.push({ date, passed, blocked, pii, errors: errs, total });
    }

    const barWidth = 40;
    const chartHeight = 200;
    const chartWidth = Math.max(days.length * (barWidth + 10), 300);
    const bars = days.map((d, i) => {
        const x = i * (barWidth + 10) + 5;
        const h = (d.total / maxTotal) * (chartHeight - 30);
        const passedH = (d.passed / maxTotal) * (chartHeight - 30);
        const blockedH = (d.blocked / maxTotal) * (chartHeight - 30);
        const piiH = (d.pii / maxTotal) * (chartHeight - 30);
        let y = chartHeight - h;
        return `<rect x="${x}" y="${chartHeight - passedH}" width="${barWidth}" height="${passedH}" fill="#4ade80" rx="2"/>
                <rect x="${x}" y="${chartHeight - passedH - blockedH}" width="${barWidth}" height="${blockedH}" fill="#f87171" rx="2"/>
                <rect x="${x}" y="${chartHeight - passedH - blockedH - piiH}" width="${barWidth}" height="${piiH}" fill="#fbbf24" rx="2"/>
                <text x="${x + barWidth/2}" y="${chartHeight + 14}" text-anchor="middle" fill="#666" font-size="10">${d.date.substring(5)}</text>
                <text x="${x + barWidth/2}" y="${chartHeight - h - 4}" text-anchor="middle" fill="#888" font-size="10">${d.total}</text>`;
    }).join('');

    // Model breakdown
    const allEntries = [];
    for (const d of days) { allEntries.push(...readEntriesForDate(d.date)); }
    const modelCounts = {};
    for (const e of allEntries) { if (e.model) modelCounts[e.model] = (modelCounts[e.model] || 0) + 1; }
    const modelRows = Object.entries(modelCounts).sort((a, b) => b[1] - a[1]);
    const totalRequests = allEntries.length;

    const content = `
      <div class="subtitle">Last ${days.length} days &middot; ${totalRequests} total requests</div>
      <div class="card">
        <div class="card-header">Daily Request Volume</div>
        <div class="card-body" style="overflow-x:auto;">
          <svg width="${chartWidth}" height="${chartHeight + 20}" style="display:block;">
            <line x1="0" y1="${chartHeight}" x2="${chartWidth}" y2="${chartHeight}" stroke="#333" stroke-width="1"/>
            ${bars}
          </svg>
          <div style="display:flex; gap:1.5rem; margin-top:1rem; font-size:0.75rem;">
            <span><span style="display:inline-block;width:10px;height:10px;background:#4ade80;border-radius:2px;"></span> Passed</span>
            <span><span style="display:inline-block;width:10px;height:10px;background:#f87171;border-radius:2px;"></span> Blocked</span>
            <span><span style="display:inline-block;width:10px;height:10px;background:#fbbf24;border-radius:2px;"></span> PII Warning</span>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-header">Model Usage Breakdown</div>
        <table>
          <thead><tr><th>Model</th><th>Requests</th><th style="width:50%">Share</th></tr></thead>
          <tbody>
            ${modelRows.length > 0 ? modelRows.map(([model, count]) => {
              const pct = ((count / totalRequests) * 100).toFixed(1);
              return `<tr>
                <td class="mono">${model}</td>
                <td class="mono">${count}</td>
                <td><div style="background:#222;border-radius:4px;overflow:hidden;"><div style="width:${pct}%;background:#4ade80;height:8px;"></div></div><span style="font-size:0.7rem;color:#666;">${pct}%</span></td>
              </tr>`;
            }).join('') : '<tr><td colspan="3" style="text-align:center; padding:2rem; color:#666;">No model data yet.</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
    res.send(renderLayout('Usage Stats', content, '/stats'));
});

// ─── Export Logs ────────────────────────────────────────────────────────────
dashboard.get('/export', requireAuth, (_req, res) => {
    const files = readdirSync(LOG_DIR).filter(f => f.endsWith('.jsonl')).sort().reverse();
    const fileRows = files.map(f => {
        const date = f.replace('gate-', '').replace('.jsonl', '');
        const entries = readEntriesForDate(date);
        const size = existsSync(join(LOG_DIR, f)) ? readFileSync(join(LOG_DIR, f)).length : 0;
        const sizeStr = size > 1024 ? (size / 1024).toFixed(1) + ' KB' : size + ' B';
        return `<tr>
            <td class="mono">${date}</td>
            <td class="mono">${entries.length}</td>
            <td class="mono">${sizeStr}</td>
            <td>
              <a href="/export/download?date=${date}&format=json" style="color:#4ade80; text-decoration:none; margin-right:1rem;">JSON</a>
              <a href="/export/download?date=${date}&format=csv" style="color:#60a5fa; text-decoration:none;">CSV</a>
            </td>
        </tr>`;
    }).join('');

    const content = `
      <div class="subtitle">Download audit logs for compliance and evidence preservation.</div>
      <div class="card">
        <div class="card-header">Available Log Files</div>
        <table>
          <thead><tr><th>Date</th><th>Entries</th><th>Size</th><th>Download</th></tr></thead>
          <tbody>
            ${fileRows || '<tr><td colspan="4" style="text-align:center; padding:2rem; color:#666;">No log files found.</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
    res.send(renderLayout('Export Logs', content, '/export'));
});

dashboard.get('/export/download', requireAuth, (req, res) => {
    const { date, format } = req.query;
    if (!date) return res.status(400).send('Missing date parameter');
    const entries = readEntriesForDate(date);

    if (format === 'csv') {
        const headers = 'timestamp,action,provider,model,inputTokens,outputTokens,durationMs,reason';
        const rows = entries.map(e =>
            [e.timestamp, e.action, e.provider, e.model, e.inputTokens, e.outputTokens, e.durationMs, (e.reason || '')].map(v => '"' + String(v || '').replace(/"/g, '""') + '"').join(',')
        );
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="aos-gate-${date}.csv"`);
        res.send(headers + '\n' + rows.join('\n'));
    } else {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="aos-gate-${date}.json"`);
        res.json({ date, version: GATE_VERSION, entries });
    }
});

// API endpoint for log data
dashboard.get('/api/logs', requireAuth, (_req, res) => {
    const files = readdirSync(LOG_DIR).filter(f => f.endsWith('.jsonl')).sort().reverse();
    const logs = {};
    for (const file of files.slice(0, 7)) {
        const entries = readEntriesForDate(file.replace('gate-', '').replace('.jsonl', ''));
        logs[file.replace('gate-', '').replace('.jsonl', '')] = entries;
    }
    res.json(logs);
});

// ─── Documentation ──────────────────────────────────────────────────────────
dashboard.get('/docs', requireAuth, (_req, res) => {
    const content = `
      <div class="subtitle">Quick reference for routing, policy blocks, and workflow integrations.</div>
      <div class="card">
        <div class="card-header">Workflow Setup (N8N / Make / Zapier)</div>
        <div class="card-body">
            <h3 style="margin-bottom:0.5rem; color:#fff; font-size: 1rem;">Routing your API Calls</h3>
            <p style="color:#aaa; font-size:0.85rem; margin-bottom:1rem; line-height:1.5;">To use AOS Gate, change the base URL in your HTTP request blocks to point to the proxy instead of the provider directly. Do not change your API keys—they will process normally.</p>
            <table style="margin-bottom:1.5rem;">
                <thead><tr><th>Original Endpoint</th><th>AOS Gate Proxy Endpoint</th></tr></thead>
                <tbody>
                    <tr><td>https://api.anthropic.com/v1/messages</td><td class="mono">http://aos-gate:3100/v1/messages</td></tr>
                    <tr><td>https://api.openai.com/v1/chat/completions</td><td class="mono">http://aos-gate:3100/v1/chat/completions</td></tr>
                </tbody>
            </table>
            <p style="color:#aaa; font-size:0.85rem; margin-bottom:1rem; line-height:1.5;"><em>Note: If your automation tool is running outside of Docker directly on your system, use <code>localhost</code> instead of <code>aos-gate</code>.</em></p>
        </div>
      </div>

      <div class="card">
        <div class="card-header">Policy Editor Reference</div>
        <div class="card-body">
            <h3 style="margin-bottom:0.5rem; color:#fff; font-size: 1rem;">Model Allowlisting</h3>
            <p style="color:#aaa; font-size:0.85rem; margin-bottom:1rem; line-height:1.5;">Limits which AI models your workflows can use. Prevent users from requesting expensive models (e.g. <code>claude-3-opus-20240229</code>). Add one model string per line. Leave empty to allow any model.</p>
            
            <h3 style="margin-bottom:0.5rem; color:#fff; font-size: 1rem;">Content Regex Rules</h3>
            <p style="color:#aaa; font-size:0.85rem; margin-bottom:1rem; line-height:1.5;">AOS Gate supports standard JavaScript RegExp. The proxy scans every outbound prompt. If a match is found, the request is immediately rejected with a 403 Forbidden status, and the event is logged as <strong>BLOCKED</strong>.</p>
            <ul style="color:#aaa; font-size:0.85rem; line-height:1.6; padding-left:1.5rem; margin-bottom:1rem;">
                <li><code>(?:confidential|internal)\\s+pricing</code> &rarr; Blocks leak of pricing matrices</li>
                <li><code>sk-[a-zA-Z0-9]{48}</code> &rarr; Blocks outbound OpenAI keys from being transmitted</li>
            </ul>
        </div>
      </div>
      
      <div class="card">
        <div class="card-header">Troubleshooting & Common Pitfalls</div>
        <div class="card-body">
            <h3 style="margin-bottom:0.5rem; color:#fff; font-size: 1rem;">1. "ENOTFOUND" or Connection Refused</h3>
            <p style="color:#aaa; font-size:0.85rem; margin-bottom:1.5rem; line-height:1.5;">If your automation tool runs in Docker, it lives on its own isolated network. By changing the URL to <code>http://aos-gate:3100</code>, you're asking it to find AOS Gate on that network. <strong>Fix:</strong> You must add the <code>aos-gate_default</code> network to your N8N <code>docker-compose.yml</code> file. (See the Github README for exactly what to copy/paste).</p>
            
            <h3 style="margin-bottom:0.5rem; color:#fff; font-size: 1rem;">2. API Key / "Unauthorized" Errors</h3>
            <p style="color:#aaa; font-size:0.85rem; margin-bottom:1.5rem; line-height:1.5;">AOS Gate does NOT store or manage your API keys. It expects the upstream HTTP node to include them exactly as Anthropic or OpenAI requires (e.g. <code>x-api-key</code> or <code>Authorization: Bearer ...</code>). <strong>Fix:</strong> Leave your credentials inside N8N entirely alone. AOS Gate seamlessly forwards these headers.</p>
            
            <h3 style="margin-bottom:0.5rem; color:#fff; font-size: 1rem;">3. Dashboard UI says "Saved" but Policy Resets</h3>
            <p style="color:#aaa; font-size:0.85rem; margin-bottom:1.5rem; line-height:1.5;">This happens if your <code>docker-compose.yml</code> previously mounted <code>policy.json</code> as Read-Only. <strong>Fix:</strong> Ensure your volume mapping looks like <code>- ./policy.json:/app/policy.json</code> (without the <code>:ro</code> flag at the end).</p>
            
            <h3 style="margin-bottom:0.5rem; color:#fff; font-size: 1rem;">4. "Unsupported Model" / 403 Forbidden</h3>
            <p style="color:#aaa; font-size:0.85rem; margin-bottom:0; line-height:1.5;">If you are receiving 403s but never configured Regex rules, you likely enabled <strong>Model Allowlisting</strong> but forgot to add the exact subversion (e.g. you allowed <code>gpt-4o</code> but your script requested <code>gpt-4o-2024-05-13</code>). <strong>Fix:</strong> Check the Activity Log to see the exact model string being requested, and add it to your allowlist.</p>
        </div>
      </div>
    `;
    res.send(renderLayout('Documentation', content, '/docs'));
});

dashboard.get('/update', requireAuth, (req, res) => {
    https.get('https://raw.githubusercontent.com/genesalvatore/aos-gate.com/main/package.json', (resp) => {
        let data = '';
        resp.on('data', (c) => data += c);
        resp.on('end', () => {
            try {
                const remote = JSON.parse(data);
                if (remote.version !== GATE_VERSION) {
                    res.json({ updateAvailable: true, current: GATE_VERSION, latest: remote.version });
                } else {
                    res.json({ updateAvailable: false, current: GATE_VERSION });
                }
            } catch(e) {
                res.status(500).json({ error: 'Failed to fetch upstream' });
            }
        });
    }).on("error", () => res.status(500).json({ error: 'Network error' }));
});

dashboard.listen(DASHBOARD_PORT, () => {
    console.log(`[Dashboard] http://localhost:${DASHBOARD_PORT}`);
});
