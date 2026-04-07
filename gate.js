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
import { mkdirSync, appendFileSync, readFileSync, existsSync, readdirSync } from 'fs';
import { join } from 'path';

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
    <div class="title">AOS Gate</div>
    <div class="subtitle">Sovereign Admin</div>
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

dashboard.get('/', requireAuth, (_req, res) => {
    // Read today's log
    const date = new Date().toISOString().split('T')[0];
    const logFile = join(LOG_DIR, `gate-${date}.jsonl`);
    let entries = [];
    if (existsSync(logFile)) {
        entries = readFileSync(logFile, 'utf-8')
            .split('\n')
            .filter(Boolean)
            .map(line => { try { return JSON.parse(line); } catch { return null; } })
            .filter(Boolean);
    }

    const passed = entries.filter(e => e.action === 'PASSED').length;
    const blocked = entries.filter(e => e.action === 'BLOCKED').length;
    const piiWarnings = entries.filter(e => e.action === 'PII_WARNING').length;
    const errors = entries.filter(e => e.action === 'ERROR').length;

    res.send(`<!DOCTYPE html>
<html><head><title>AOS Gate — Audit Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 2rem; }
  h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
  .subtitle { color: #666; font-size: 0.85rem; margin-bottom: 2rem; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: #151515; border: 1px solid #222; border-radius: 8px; padding: 1.25rem; }
  .stat .label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; color: #666; }
  .stat .value { font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }
  .passed .value { color: #4ade80; }
  .blocked .value { color: #f87171; }
  .pii .value { color: #fbbf24; }
  .errors .value { color: #f97316; }
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th { text-align: left; padding: 0.5rem; color: #666; text-transform: uppercase; font-size: 0.65rem; letter-spacing: 0.1em; border-bottom: 1px solid #222; }
  td { padding: 0.5rem; border-bottom: 1px solid #151515; }
  .action-passed { color: #4ade80; }
  .action-blocked { color: #f87171; font-weight: 600; }
  .action-pii_warning { color: #fbbf24; }
  .action-error { color: #f97316; }
  .mono { font-family: monospace; font-size: 0.75rem; color: #888; }
</style></head><body>
  <h1 style="display: flex; justify-content: space-between; align-items: center;">
    <span>🚪 AOS Gate — Audit Log</span>
    <a href="/logout" style="font-size: 0.8rem; padding: 0.4rem 0.8rem; background: #222; color: #fff; text-decoration: none; border-radius: 4px; font-weight: normal; border: 1px solid #333;">Sign Out</a>
  </h1>
  <div class="subtitle">${date} · ${entries.length} events</div>
  <div class="stats">
    <div class="stat passed"><div class="label">Passed</div><div class="value">${passed}</div></div>
    <div class="stat blocked"><div class="label">Blocked</div><div class="value">${blocked}</div></div>
    <div class="stat pii"><div class="label">PII Warnings</div><div class="value">${piiWarnings}</div></div>
    <div class="stat errors"><div class="label">Errors</div><div class="value">${errors}</div></div>
  </div>
  <table>
    <thead><tr><th>Time</th><th>Action</th><th>Provider</th><th>Model</th><th>Tokens (In/Out)</th><th>Duration</th><th>Notes</th></tr></thead>
    <tbody>
      ${entries.reverse().map(e => `<tr>
        <td class="mono">${e.timestamp?.split('T')[1]?.substring(0,8) || '—'}</td>
        <td class="action-${(e.action||'').toLowerCase()}">${e.action}</td>
        <td>${e.provider || '—'}</td>
        <td class="mono">${e.model || '—'}</td>
        <td class="mono">${e.inputTokens || '—'} / ${e.outputTokens || '—'}</td>
        <td class="mono">${e.durationMs ? e.durationMs + 'ms' : '—'}</td>
        <td class="mono">${e.reason || (e.inputPII ? 'PII: ' + e.inputPII.map(p=>p.type).join(', ') : '') || (e.error || '') || ''}</td>
      </tr>`).join('')}
    </tbody>
  </table>
</body></html>`);
});

// API endpoint for log data
dashboard.get('/api/logs', requireAuth, (_req, res) => {
    const files = readdirSync(LOG_DIR).filter(f => f.endsWith('.jsonl')).sort().reverse();
    const logs = {};
    for (const file of files.slice(0, 7)) { // Last 7 days
        const entries = readFileSync(join(LOG_DIR, file), 'utf-8')
            .split('\n').filter(Boolean)
            .map(l => { try { return JSON.parse(l); } catch { return null; } })
            .filter(Boolean);
        logs[file.replace('gate-', '').replace('.jsonl', '')] = entries;
    }
    res.json(logs);
});

dashboard.listen(DASHBOARD_PORT, () => {
    console.log(`📊 Dashboard: http://localhost:${DASHBOARD_PORT}`);
});
