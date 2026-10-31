// AOS Gate v2.0: Deterministic Intent Firewall & Policy Proxy
// Copyright (c) 2026 Gene Salvatore / AOS (Agentic Operating System)
// Licensed under the AOS Humanitarian License v1.0.1
// https://aos-constitution.com
//
// HUMANITARIAN USE ONLY. Military and harmful applications PROHIBITED.
// Full license: LICENSE file in this repository.
//
// Drop-in API proxy for AI workflows (N8N, Make, LangChain, Cursor, custom daemons).
// Sits between your automation tool and upstream AI providers.
// Enforces sub-millisecond deterministic intent policies, 3-mode PII protection,
// real-time SSE streaming intercepts, and SHA-256 hash-chained immutable audit ledgers.
//
// Usage: Point your HTTP request nodes or agent base URLs at http://aos-gate:3100
//        instead of https://api.anthropic.com, https://api.openai.com,
//        or https://generativelanguage.googleapis.com
// ─────────────────────────────────────────────────────────────────────────────

import express from 'express';
import { mkdirSync, appendFileSync, readFileSync, existsSync, readdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import crypto from 'crypto';
import https from 'https';

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'));
const GATE_VERSION = pkg.version || '2.0.0';
const GENESIS_HASH = crypto.createHash('sha256').update('AOS-GATE-2.0:GENESIS').digest('hex');

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
    piiAction: 'warn',        // 'warn' = log PII_WARNING, 'redact' = mask with [REDACTED_*], 'block' = 403 Forbidden
    logLevel: 'full'          // 'full' = log prompt/response text, 'meta' = usage stats only
};

if (existsSync(POLICY_FILE)) {
    try {
        policy = { ...policy, ...JSON.parse(readFileSync(POLICY_FILE, 'utf-8')) };
        console.log(`[Policy] Loaded from ${POLICY_FILE} (piiAction: ${policy.piiAction || 'warn'})`);
    } catch (e) {
        console.warn(`[Policy] Warning: Could not parse ${POLICY_FILE}, using defaults:`, e.message);
    }
}

// ─── Dynamic Glob / Wildcard Model Matcher ──────────────────────────────────
export function isModelAllowed(requestedModel, allowedModels) {
    if (!allowedModels || allowedModels.length === 0) return true;
    if (allowedModels.includes('*')) return true;
    if (!requestedModel) return false;
    return allowedModels.some(pattern => {
        if (pattern === '*' || pattern === requestedModel) return true;
        const regexPattern = '^' + pattern
            .replace(/[.+^${}()|[\]\\]/g, '\\$&')
            .replace(/\*/g, '.*')
            .replace(/\?/g, '.') + '$';
        return new RegExp(regexPattern, 'i').test(requestedModel);
    });
}

// ─── PII Scanner & Redaction Engine ─────────────────────────────────────────
const PII_PATTERNS = [
    { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, token: '[REDACTED_SSN]' },
    { name: 'Credit Card', pattern: /\b(?:\d{4}[- ]?){3}\d{4}\b/g, token: '[REDACTED_CARD]' },
    { name: 'Email', pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g, token: '[REDACTED_EMAIL]' },
    { name: 'Phone (US)', pattern: /\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b/g, token: '[REDACTED_PHONE]' },
    { name: 'AWS Access Key', pattern: /\bAKIA[0-9A-Z]{16}\b/g, token: '[REDACTED_KEY]' },
    { name: 'API Secret Key', pattern: /\bsk-(?:ant-|proj-)?[a-zA-Z0-9_-]{20,}\b/g, token: '[REDACTED_KEY]' }
];

export function scanForPII(text) {
    if (!text || typeof text !== 'string') return [];
    const findings = [];
    for (const { name, pattern } of PII_PATTERNS) {
        pattern.lastIndex = 0;
        const matches = text.match(pattern);
        if (matches && matches.length > 0) {
            findings.push({ type: name, count: matches.length });
        }
    }
    return findings;
}

export function redactPIIText(text) {
    if (!text || typeof text !== 'string') return text;
    let redacted = text;
    for (const { pattern, token } of PII_PATTERNS) {
        pattern.lastIndex = 0;
        redacted = redacted.replace(pattern, token);
    }
    return redacted;
}

export function redactRequestBody(body) {
    if (!body || typeof body !== 'object') return body;
    const cloned = JSON.parse(JSON.stringify(body));

    if (Array.isArray(cloned.messages)) {
        for (const msg of cloned.messages) {
            if (typeof msg.content === 'string') {
                msg.content = redactPIIText(msg.content);
            } else if (Array.isArray(msg.content)) {
                for (const part of msg.content) {
                    if (part && typeof part.text === 'string') {
                        part.text = redactPIIText(part.text);
                    }
                }
            }
        }
    }

    if (typeof cloned.system === 'string') {
        cloned.system = redactPIIText(cloned.system);
    } else if (Array.isArray(cloned.system)) {
        for (const item of cloned.system) {
            if (item && typeof item.text === 'string') {
                item.text = redactPIIText(item.text);
            }
        }
    }

    if (Array.isArray(cloned.contents)) {
        for (const content of cloned.contents) {
            if (Array.isArray(content.parts)) {
                for (const part of content.parts) {
                    if (part && typeof part.text === 'string') {
                        part.text = redactPIIText(part.text);
                    }
                }
            }
        }
    }

    if (typeof cloned.prompt === 'string') {
        cloned.prompt = redactPIIText(cloned.prompt);
    }
    if (typeof cloned.input === 'string') {
        cloned.input = redactPIIText(cloned.input);
    }

    return cloned;
}

// ─── Content Scanner ────────────────────────────────────────────────────────
export function scanForBlockedContent(text) {
    if (!text || typeof text !== 'string') return [];
    const violations = [];
    for (const entry of (policy.blockedPatterns || [])) {
        try {
            const regex = new RegExp(entry.pattern, entry.flags || 'gi');
            if (regex.test(text)) {
                violations.push(entry.label || entry.pattern);
            }
        } catch (e) {
            console.warn(`[ContentFilter] Invalid regex pattern "${entry.pattern}":`, e.message);
        }
    }
    return violations;
}

// ─── Native SHA-256 Hash-Chained Audit Ledger ───────────────────────────────
const lastChainHashByDate = new Map();

export function getLastChainHash(date) {
    if (lastChainHashByDate.has(date)) {
        return lastChainHashByDate.get(date);
    }
    const logFile = join(LOG_DIR, `gate-${date}.jsonl`);
    if (existsSync(logFile)) {
        try {
            const content = readFileSync(logFile, 'utf-8');
            const lines = content.split('\n').map(l => l.trim()).filter(Boolean);
            if (lines.length > 0) {
                const last = JSON.parse(lines[lines.length - 1]);
                if (last.chain_hash) {
                    lastChainHashByDate.set(date, last.chain_hash);
                    return last.chain_hash;
                }
            }
        } catch (e) {
            console.warn(`[Audit] Could not read last chain hash from ${logFile}:`, e.message);
        }
    }
    lastChainHashByDate.set(date, GENESIS_HASH);
    return GENESIS_HASH;
}

export function logEntry(entry) {
    if (!entry.timestamp) entry.timestamp = new Date().toISOString();
    const date = entry.timestamp.split('T')[0];
    const previous_hash = getLastChainHash(date);
    const model = entry.model || '';
    const reason = entry.reason || (entry.findings ? JSON.stringify(entry.findings) : (entry.error || ''));
    const chainInput = `${previous_hash}:${entry.timestamp}:${entry.action}:${model}:${reason}`;
    const chain_hash = crypto.createHash('sha256').update(chainInput).digest('hex');

    entry.previous_hash = previous_hash;
    entry.chain_hash = chain_hash;

    lastChainHashByDate.set(date, chain_hash);

    const logFile = join(LOG_DIR, `gate-${date}.jsonl`);
    appendFileSync(logFile, JSON.stringify(entry) + '\n');
    return entry;
}

export function verifyChainIntegrity(targetDate = null) {
    const files = readdirSync(LOG_DIR)
        .filter(f => f.startsWith('gate-') && f.endsWith('.jsonl'))
        .sort();

    const results = {
        verified: true,
        filesChecked: 0,
        totalEntries: 0,
        genesisHash: GENESIS_HASH,
        fileResults: [],
        errors: []
    };

    for (const file of files) {
        const fileDate = file.replace('gate-', '').replace('.jsonl', '');
        if (targetDate && fileDate !== targetDate) continue;

        results.filesChecked++;
        const filePath = join(LOG_DIR, file);
        let lines = [];
        try {
            lines = readFileSync(filePath, 'utf-8').split('\n').map(l => l.trim()).filter(Boolean);
        } catch (err) {
            results.verified = false;
            results.errors.push({ file, type: 'FILE_READ_ERROR', message: err.message });
            continue;
        }

        let expectedPrevHash = GENESIS_HASH;
        let fileValid = true;

        for (let idx = 0; idx < lines.length; idx++) {
            results.totalEntries++;
            try {
                const entry = JSON.parse(lines[idx]);
                const model = entry.model || '';
                const reason = entry.reason || (entry.findings ? JSON.stringify(entry.findings) : (entry.error || ''));

                if (entry.previous_hash !== expectedPrevHash) {
                    fileValid = false;
                    results.verified = false;
                    results.errors.push({
                        file,
                        line: idx + 1,
                        type: 'PREVIOUS_HASH_MISMATCH',
                        expectedPrevious: expectedPrevHash,
                        actualPrevious: entry.previous_hash
                    });
                }

                const chainInput = `${entry.previous_hash}:${entry.timestamp}:${entry.action}:${model}:${reason}`;
                const calculatedHash = crypto.createHash('sha256').update(chainInput).digest('hex');

                if (entry.chain_hash !== calculatedHash) {
                    fileValid = false;
                    results.verified = false;
                    results.errors.push({
                        file,
                        line: idx + 1,
                        type: 'CHAIN_HASH_CORRUPTED',
                        calculatedHash,
                        recordedHash: entry.chain_hash
                    });
                }

                expectedPrevHash = entry.chain_hash;
            } catch (err) {
                fileValid = false;
                results.verified = false;
                results.errors.push({
                    file,
                    line: idx + 1,
                    type: 'JSON_PARSE_ERROR',
                    message: err.message
                });
            }
        }

        results.fileResults.push({
            file,
            entries: lines.length,
            valid: fileValid,
            lastHash: expectedPrevHash
        });
    }

    return results;
}

// ─── HTML Sanitizer ─────────────────────────────────────────────────────────
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ─── Proxy Middleware ───────────────────────────────────────────────────────
app.use(express.json({ limit: '20mb' }));
app.use(express.text({ limit: '20mb' }));

// Health check
app.get('/health', (_req, res) => {
    res.json({
        status: 'ok',
        version: GATE_VERSION,
        uptime: process.uptime(),
        policy: !!existsSync(POLICY_FILE),
        piiAction: policy.piiAction || 'warn',
        genesisHash: GENESIS_HASH
    });
});

// ─── Universal SSE Streaming Relay Helper ───────────────────────────────────
async function streamSSEWithIntentScanning({
    upstream,
    req,
    res,
    provider,
    model,
    promptText,
    piiFindings,
    startTime
}) {
    res.status(upstream.status);
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    if (typeof res.flushHeaders === 'function') {
        res.flushHeaders();
    }

    let accumulatedResponse = '';
    let streamAborted = false;
    let inputTokens = null;
    let outputTokens = null;

    try {
        for await (const chunk of upstream.body) {
            if (streamAborted) break;
            const chunkStr = Buffer.isBuffer(chunk) ? chunk.toString('utf-8') : Buffer.from(chunk).toString('utf-8');
            accumulatedResponse += chunkStr;

            // Inspect accumulated stream for intent/tool policy violations
            const blockedViolations = scanForBlockedContent(accumulatedResponse);
            if (blockedViolations.length > 0) {
                streamAborted = true;
                const entry = {
                    timestamp: new Date().toISOString(),
                    provider,
                    action: 'INTENT_BLOCKED',
                    reason: `Tool/Intent policy violation in stream: ${blockedViolations.join(', ')}`,
                    model,
                    durationMs: Date.now() - startTime,
                };
                logEntry(entry);

                res.write(`event: error\ndata: ${JSON.stringify({ error: 'Tool/Intent blocked by policy', violations: blockedViolations })}\n\n`);
                res.end();

                if (typeof upstream.body.cancel === 'function') {
                    try { await upstream.body.cancel(); } catch (_) {}
                }
                return;
            }

            // Clean chunk forwarded to client
            res.write(chunk);
        }

        if (!streamAborted) {
            res.end();
            const duration = Date.now() - startTime;
            const responsePII = scanForPII(accumulatedResponse);

            // Attempt to extract token usage from final SSE packets
            const usageMatches = accumulatedResponse.match(/"usage"\s*:\s*\{([^}]+)\}/);
            if (usageMatches) {
                try {
                    const parsedUsage = JSON.parse(`{${usageMatches[1]}}`);
                    inputTokens = parsedUsage.prompt_tokens || parsedUsage.input_tokens;
                    outputTokens = parsedUsage.completion_tokens || parsedUsage.output_tokens;
                } catch (_) {}
            }

            const entry = {
                timestamp: new Date().toISOString(),
                provider,
                action: 'PASSED',
                model,
                durationMs: duration,
                stream: true,
                inputTokens,
                outputTokens,
                inputPII: piiFindings.length > 0 ? piiFindings : undefined,
                outputPII: responsePII.length > 0 ? responsePII : undefined,
            };

            if (policy.logLevel === 'full') {
                entry.prompt = promptText.substring(0, 2000);
                entry.response = accumulatedResponse.substring(0, 2000);
            }

            logEntry(entry);
        }
    } catch (streamErr) {
        if (!res.writableEnded) {
            res.end();
        }
        logEntry({
            timestamp: new Date().toISOString(),
            provider,
            action: 'ERROR',
            error: `Stream relay exception: ${streamErr.message}`,
            model,
            durationMs: Date.now() - startTime,
        });
    }
}

// ─── Models Listing Passthrough (/v1/models) ────────────────────────────────
app.get('/v1/models', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (authHeader && !process.env.MOCK_PROVIDERS) {
        try {
            const upstream = await fetch(`${process.env.OPENAI_API_URL || 'https://api.openai.com'}/v1/models`, {
                method: 'GET',
                headers: { 'Authorization': authHeader }
            });
            if (upstream.ok) {
                const data = await upstream.json();
                return res.status(upstream.status).json(data);
            }
        } catch (_) {}
    }

    // Default policy-backed model list
    const modelsList = (policy.allowedModels && policy.allowedModels.length > 0)
        ? policy.allowedModels.map(m => ({
            id: m,
            object: 'model',
            created: Math.floor(Date.now() / 1000),
            owned_by: 'aos-gate-policy'
        }))
        : [
            { id: 'claude-sonnet-4-20250514', object: 'model', created: Math.floor(Date.now() / 1000), owned_by: 'anthropic' },
            { id: 'claude-3-5-sonnet-20241022', object: 'model', created: Math.floor(Date.now() / 1000), owned_by: 'anthropic' },
            { id: 'gpt-4o', object: 'model', created: Math.floor(Date.now() / 1000), owned_by: 'openai' },
            { id: 'gpt-4o-mini', object: 'model', created: Math.floor(Date.now() / 1000), owned_by: 'openai' },
            { id: 'gemini-2.0-flash', object: 'model', created: Math.floor(Date.now() / 1000), owned_by: 'google' }
        ];

    res.json({ object: 'list', data: modelsList });
});

// ─── Local Deterministic Evaluator (/v1/evaluate) ───────────────────────────
app.post('/v1/evaluate', (req, res) => {
    const body = req.body || {};
    const model = body.model || '';

    // Extract prompt text
    let promptText = '';
    if (typeof body.prompt === 'string') {
        promptText = body.prompt;
    } else if (Array.isArray(body.messages)) {
        promptText = body.messages.map(m => typeof m.content === 'string' ? m.content : JSON.stringify(m.content)).join('\n');
    } else if (Array.isArray(body.contents)) {
        promptText = body.contents.flatMap(c => (c.parts || []).map(p => typeof p === 'string' ? p : (p.text || JSON.stringify(p)))).join('\n');
    }

    const responseText = body.response || body.output || '';
    const requestedPiiAction = (body.piiAction || policy.piiAction || 'warn').toLowerCase();

    const modelAllowed = isModelAllowed(model, policy.allowedModels);
    const promptPII = scanForPII(promptText);
    const promptBlocked = scanForBlockedContent(promptText);
    const redactedPrompt = redactPIIText(promptText);

    const responsePII = responseText ? scanForPII(responseText) : [];
    const responseBlocked = responseText ? scanForBlockedContent(responseText) : [];
    const redactedResponse = responseText ? redactPIIText(responseText) : undefined;

    let action = 'PASSED';
    let reason = '';

    if (!modelAllowed) {
        action = 'BLOCKED';
        reason = `Model "${model}" not in allowlist`;
    } else if (promptBlocked.length > 0) {
        action = 'BLOCKED';
        reason = `Content policy violation: ${promptBlocked.join(', ')}`;
    } else if (responseBlocked.length > 0) {
        action = 'INTENT_BLOCKED';
        reason = `Tool/Intent policy violation: ${responseBlocked.join(', ')}`;
    } else if (promptPII.length > 0 || responsePII.length > 0) {
        const totalPII = [...promptPII, ...responsePII];
        if (requestedPiiAction === 'block') {
            action = 'PII_BLOCKED';
            reason = `PII blocked by policy: ${totalPII.map(p => `${p.type} (${p.count})`).join(', ')}`;
        } else if (requestedPiiAction === 'redact') {
            action = 'PII_REDACTED';
            reason = `PII redacted: ${totalPII.map(p => `${p.type} (${p.count})`).join(', ')}`;
        } else {
            action = 'PII_WARNING';
            reason = `PII detected: ${totalPII.map(p => `${p.type} (${p.count})`).join(', ')}`;
        }
    }

    const timestamp = new Date().toISOString();
    const date = timestamp.split('T')[0];
    const previousHash = getLastChainHash(date);
    const chainInput = `${previousHash}:${timestamp}:${action}:${model}:${reason}`;
    const chainHash = crypto.createHash('sha256').update(chainInput).digest('hex');

    res.json({
        allowed: action === 'PASSED' || action === 'PII_REDACTED' || action === 'PII_WARNING',
        action,
        reason,
        model,
        modelAllowed,
        piiAction: requestedPiiAction,
        piiFindings: {
            prompt: promptPII,
            response: responsePII
        },
        blockedContent: {
            prompt: promptBlocked,
            response: responseBlocked
        },
        redactedPrompt,
        redactedResponse,
        previousHash,
        chainHash,
        timestamp,
        gateVersion: GATE_VERSION
    });
});

// ─── Anthropic Proxy (/v1/messages) ─────────────────────────────────────────
app.post('/v1/messages', async (req, res) => {
    const startTime = Date.now();
    let requestBody = req.body;
    const apiKey = req.headers['x-api-key'] || '';

    const promptText = (requestBody.messages || [])
        .map(m => typeof m.content === 'string' ? m.content : JSON.stringify(m.content))
        .join('\n');

    const piiFindings = scanForPII(promptText);
    const blockedContent = scanForBlockedContent(promptText);
    const piiAction = (policy.piiAction || 'warn').toLowerCase();

    // 1. Model allowlist check
    if (!isModelAllowed(requestBody.model, policy.allowedModels)) {
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

    // 2. Inbound prompt content check
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

    // 3. PII Engine Enforcement
    if (piiFindings.length > 0) {
        if (piiAction === 'block') {
            const entry = {
                timestamp: new Date().toISOString(),
                provider: 'anthropic',
                action: 'PII_BLOCKED',
                reason: `PII blocked: ${piiFindings.map(f => `${f.type} (${f.count})`).join(', ')}`,
                findings: piiFindings,
                model: requestBody.model,
            };
            logEntry(entry);
            return res.status(403).json({ error: 'PII blocked by policy', gate: entry });
        } else if (piiAction === 'redact') {
            requestBody = redactRequestBody(requestBody);
            logEntry({
                timestamp: new Date().toISOString(),
                provider: 'anthropic',
                action: 'PII_REDACTED',
                findings: piiFindings,
                model: requestBody.model,
            });
        } else {
            logEntry({
                timestamp: new Date().toISOString(),
                provider: 'anthropic',
                action: 'PII_WARNING',
                findings: piiFindings,
                model: requestBody.model,
            });
        }
    }

    const isStream = Boolean(requestBody.stream === true || (req.headers.accept && req.headers.accept.includes('text/event-stream')));
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

        // Upstream error response
        if (upstream.status >= 400) {
            const errText = await upstream.text();
            logEntry({
                timestamp: new Date().toISOString(),
                provider: 'anthropic',
                action: 'ERROR',
                error: `Upstream returned status ${upstream.status}`,
                model: requestBody.model,
                durationMs: Date.now() - startTime,
            });
            return res.status(upstream.status).type('application/json').send(errText);
        }

        // Real-Time SSE Streaming Proxy
        const contentType = upstream.headers.get('content-type') || '';
        if (isStream || contentType.includes('text/event-stream')) {
            return await streamSSEWithIntentScanning({
                upstream,
                req,
                res,
                provider: 'anthropic',
                model: requestBody.model,
                promptText,
                piiFindings,
                startTime
            });
        }

        // Non-streaming JSON response
        const responseBody = await upstream.json();
        const duration = Date.now() - startTime;

        const responseText = (responseBody.content || [])
            .map(c => c.text || '')
            .join('\n');

        // Downstream Tool/Intent Intercept
        const responseString = JSON.stringify(responseBody);
        const blockedResponseContent = scanForBlockedContent(responseString);

        if (blockedResponseContent.length > 0) {
            const entry = {
                timestamp: new Date().toISOString(),
                provider: 'anthropic',
                action: 'INTENT_BLOCKED',
                reason: `Tool/Intent policy violation: ${blockedResponseContent.join(', ')}`,
                model: requestBody.model,
            };
            logEntry(entry);
            return res.status(403).json({ error: 'Tool/Intent blocked by policy', gate: entry });
        }

        const responsePII = scanForPII(responseText);

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

        if (policy.logLevel === 'full') {
            entry.prompt = promptText.substring(0, 2000);
            entry.response = responseText.substring(0, 2000);
        }

        logEntry(entry);
        res.status(upstream.status).json(responseBody);

    } catch (err) {
        logEntry({
            timestamp: new Date().toISOString(),
            provider: 'anthropic',
            action: 'ERROR',
            error: err.message,
            model: requestBody.model,
            durationMs: Date.now() - startTime,
        });
        res.status(502).json({ error: 'Gateway error', message: err.message });
    }
});

// ─── OpenAI Proxy (/v1/chat/completions) ────────────────────────────────────
app.post('/v1/chat/completions', async (req, res) => {
    const startTime = Date.now();
    let requestBody = req.body;
    const authHeader = req.headers['authorization'] || '';

    const promptText = (requestBody.messages || [])
        .map(m => typeof m.content === 'string' ? m.content : JSON.stringify(m.content))
        .join('\n');

    const piiFindings = scanForPII(promptText);
    const blockedContent = scanForBlockedContent(promptText);
    const piiAction = (policy.piiAction || 'warn').toLowerCase();

    // 1. Model allowlist check
    if (!isModelAllowed(requestBody.model, policy.allowedModels)) {
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

    // 2. Inbound prompt content check
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

    // 3. PII Engine Enforcement
    if (piiFindings.length > 0) {
        if (piiAction === 'block') {
            const entry = {
                timestamp: new Date().toISOString(),
                provider: 'openai',
                action: 'PII_BLOCKED',
                reason: `PII blocked: ${piiFindings.map(f => `${f.type} (${f.count})`).join(', ')}`,
                findings: piiFindings,
                model: requestBody.model,
            };
            logEntry(entry);
            return res.status(403).json({ error: 'PII blocked by policy', gate: entry });
        } else if (piiAction === 'redact') {
            requestBody = redactRequestBody(requestBody);
            logEntry({
                timestamp: new Date().toISOString(),
                provider: 'openai',
                action: 'PII_REDACTED',
                findings: piiFindings,
                model: requestBody.model,
            });
        } else {
            logEntry({
                timestamp: new Date().toISOString(),
                provider: 'openai',
                action: 'PII_WARNING',
                findings: piiFindings,
                model: requestBody.model,
            });
        }
    }

    const isStream = Boolean(requestBody.stream === true || (req.headers.accept && req.headers.accept.includes('text/event-stream')));
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

        if (upstream.status >= 400) {
            const errText = await upstream.text();
            logEntry({
                timestamp: new Date().toISOString(),
                provider: 'openai',
                action: 'ERROR',
                error: `Upstream returned status ${upstream.status}`,
                model: requestBody.model,
                durationMs: Date.now() - startTime,
            });
            return res.status(upstream.status).type('application/json').send(errText);
        }

        const contentType = upstream.headers.get('content-type') || '';
        if (isStream || contentType.includes('text/event-stream')) {
            return await streamSSEWithIntentScanning({
                upstream,
                req,
                res,
                provider: 'openai',
                model: requestBody.model,
                promptText,
                piiFindings,
                startTime
            });
        }

        const responseBody = await upstream.json();
        const duration = Date.now() - startTime;

        const responseText = (responseBody.choices || [])
            .map(c => c.message?.content || '')
            .join('\n');

        // Downstream Tool/Intent Intercept
        const responseString = JSON.stringify(responseBody);
        const blockedResponseContent = scanForBlockedContent(responseString);

        if (blockedResponseContent.length > 0) {
            const entry = {
                timestamp: new Date().toISOString(),
                provider: 'openai',
                action: 'INTENT_BLOCKED',
                reason: `Tool/Intent policy violation: ${blockedResponseContent.join(', ')}`,
                model: requestBody.model,
            };
            logEntry(entry);
            return res.status(403).json({ error: 'Tool/Intent blocked by policy', gate: entry });
        }

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
            durationMs: Date.now() - startTime,
        });
        res.status(502).json({ error: 'Gateway error', message: err.message });
    }
});

// ─── Google Gemini API Proxy (/v1beta/models/:modelAction) ──────────────────
app.post('/v1beta/models/:modelAction', async (req, res) => {
    const startTime = Date.now();
    let requestBody = req.body || {};
    const modelAction = req.params.modelAction || '';
    const rawModel = modelAction.includes(':') ? modelAction.split(':')[0] : (requestBody.model || modelAction);

    // Extract prompt text from Gemini contents or prompt format
    let promptText = '';
    if (Array.isArray(requestBody.contents)) {
        promptText = requestBody.contents.flatMap(c =>
            (Array.isArray(c.parts) ? c.parts : []).map(p => typeof p === 'string' ? p : (p.text || JSON.stringify(p)))
        ).join('\n');
    } else if (typeof requestBody.prompt === 'string') {
        promptText = requestBody.prompt;
    } else if (Array.isArray(requestBody.messages)) {
        promptText = requestBody.messages.map(m => typeof m.content === 'string' ? m.content : JSON.stringify(m.content)).join('\n');
    }

    const piiFindings = scanForPII(promptText);
    const blockedContent = scanForBlockedContent(promptText);
    const piiAction = (policy.piiAction || 'warn').toLowerCase();

    // 1. Model allowlist check
    if (!isModelAllowed(rawModel, policy.allowedModels)) {
        const entry = {
            timestamp: new Date().toISOString(),
            provider: 'gemini',
            action: 'BLOCKED',
            reason: `Model "${rawModel}" not in allowlist`,
            model: rawModel,
        };
        logEntry(entry);
        return res.status(403).json({ error: 'Model not permitted by policy', gate: entry });
    }

    // 2. Inbound prompt content check
    if (blockedContent.length > 0) {
        const entry = {
            timestamp: new Date().toISOString(),
            provider: 'gemini',
            action: 'BLOCKED',
            reason: `Content policy violation: ${blockedContent.join(', ')}`,
            model: rawModel,
        };
        logEntry(entry);
        return res.status(403).json({ error: 'Content blocked by policy', gate: entry });
    }

    // 3. PII Engine Enforcement
    if (piiFindings.length > 0) {
        if (piiAction === 'block') {
            const entry = {
                timestamp: new Date().toISOString(),
                provider: 'gemini',
                action: 'PII_BLOCKED',
                reason: `PII blocked: ${piiFindings.map(f => `${f.type} (${f.count})`).join(', ')}`,
                findings: piiFindings,
                model: rawModel,
            };
            logEntry(entry);
            return res.status(403).json({ error: 'PII blocked by policy', gate: entry });
        } else if (piiAction === 'redact') {
            requestBody = redactRequestBody(requestBody);
            logEntry({
                timestamp: new Date().toISOString(),
                provider: 'gemini',
                action: 'PII_REDACTED',
                findings: piiFindings,
                model: rawModel,
            });
        } else {
            logEntry({
                timestamp: new Date().toISOString(),
                provider: 'gemini',
                action: 'PII_WARNING',
                findings: piiFindings,
                model: rawModel,
            });
        }
    }

    const isStream = Boolean(modelAction.includes('streamGenerateContent') || req.query.alt === 'sse' || requestBody.stream === true);
    const queryString = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const targetUrl = `${process.env.GEMINI_API_URL || 'https://generativelanguage.googleapis.com'}/v1beta/models/${modelAction}${queryString}`;

    const upstreamHeaders = { 'Content-Type': 'application/json' };
    if (req.headers['x-goog-api-key']) upstreamHeaders['x-goog-api-key'] = req.headers['x-goog-api-key'];
    if (req.headers['authorization']) upstreamHeaders['authorization'] = req.headers['authorization'];

    try {
        const upstream = await fetch(targetUrl, {
            method: 'POST',
            headers: upstreamHeaders,
            body: JSON.stringify(requestBody),
        });

        if (upstream.status >= 400) {
            const errText = await upstream.text();
            logEntry({
                timestamp: new Date().toISOString(),
                provider: 'gemini',
                action: 'ERROR',
                error: `Upstream returned status ${upstream.status}`,
                model: rawModel,
                durationMs: Date.now() - startTime,
            });
            return res.status(upstream.status).type('application/json').send(errText);
        }

        const contentType = upstream.headers.get('content-type') || '';
        if (isStream || contentType.includes('text/event-stream')) {
            return await streamSSEWithIntentScanning({
                upstream,
                req,
                res,
                provider: 'gemini',
                model: rawModel,
                promptText,
                piiFindings,
                startTime
            });
        }

        const responseBody = await upstream.json();
        const duration = Date.now() - startTime;

        let responseText = '';
        if (Array.isArray(responseBody.candidates)) {
            responseText = responseBody.candidates.flatMap(c =>
                (c.content?.parts || []).map(p => typeof p === 'string' ? p : (p.text || ''))
            ).join('\n');
        }

        // Downstream Tool/Intent Intercept
        const responseString = JSON.stringify(responseBody);
        const blockedResponseContent = scanForBlockedContent(responseString);

        if (blockedResponseContent.length > 0) {
            const entry = {
                timestamp: new Date().toISOString(),
                provider: 'gemini',
                action: 'INTENT_BLOCKED',
                reason: `Tool/Intent policy violation: ${blockedResponseContent.join(', ')}`,
                model: rawModel,
            };
            logEntry(entry);
            return res.status(403).json({ error: 'Tool/Intent blocked by policy', gate: entry });
        }

        const responsePII = scanForPII(responseText);

        const entry = {
            timestamp: new Date().toISOString(),
            provider: 'gemini',
            action: 'PASSED',
            model: rawModel,
            durationMs: duration,
            inputTokens: responseBody.usageMetadata?.promptTokenCount,
            outputTokens: responseBody.usageMetadata?.candidatesTokenCount,
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
            provider: 'gemini',
            action: 'ERROR',
            error: err.message,
            model: rawModel,
            durationMs: Date.now() - startTime,
        });
        res.status(502).json({ error: 'Gateway error', message: err.message });
    }
});

// ─── Start Gate Proxy Server ────────────────────────────────────────────────
app.listen(GATE_PORT, () => {
    console.log(`\n🚪 AOS Gate v${GATE_VERSION} running on port ${GATE_PORT}`);
    console.log(`   Anthropic proxy:  http://localhost:${GATE_PORT}/v1/messages`);
    console.log(`   OpenAI proxy:     http://localhost:${GATE_PORT}/v1/chat/completions`);
    console.log(`   Gemini proxy:     http://localhost:${GATE_PORT}/v1beta/models/:modelAction`);
    console.log(`   Model listing:    http://localhost:${GATE_PORT}/v1/models`);
    console.log(`   Local Evaluator:  http://localhost:${GATE_PORT}/v1/evaluate`);
    console.log(`   Logs Directory:   ${LOG_DIR}/`);
    console.log(`   Genesis Ledger:   ${GENESIS_HASH.substring(0, 16)}...\n`);
});

// ─── Audit Dashboard Server ─────────────────────────────────────────────────
const dashboard = express();

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'aos-admin';
const getSessionHash = () => crypto.createHash('sha256').update(ADMIN_PASSWORD + '-aos-salt').digest('hex');

dashboard.use(express.urlencoded({ extended: true }));
dashboard.use(express.json());
dashboard.use((req, res, next) => {
    req.cookies = req.headers.cookie?.split(';').reduce((acc, item) => {
        const data = item.trim().split('=');
        return { ...acc, [data[0]]: data[1] };
    }, {}) || {};
    next();
});

const requireAuth = (req, res, next) => {
    if (req.cookies.aos_gate_session === getSessionHash()) return next();
    res.redirect('/login');
};

dashboard.get('/login', (_req, res) => {
    res.send(`<!DOCTYPE html>
<html><head><title>AOS Gate: Sovereign Auth</title>
<style>
  * { box-sizing: border-box; }
  :root {
    --bg-main: #f8fafc; --bg-card: #ffffff; --border-color: #e2e8f0; --text-main: #0f172a; --text-muted: #64748b; --input-bg: #f8fafc; --input-border: #cbd5e1; --accent: #3b82f6; --accent-hover: #2563eb;
  }
  [data-theme='dark'] {
    --bg-main: #0a0a0a; --bg-card: #151515; --border-color: #222222; --text-main: #e0e0e0; --text-muted: #888888; --input-bg: #0a0a0a; --input-border: #333333;
  }
  body { font-family: -apple-system, system-ui, sans-serif; background: var(--bg-main); color: var(--text-main); display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
  .login-box { background: var(--bg-card); padding: 3rem; border-radius: 12px; border: 1px solid var(--border-color); width: 380px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); }
  .title { font-size: 1.4rem; margin-top: 0; margin-bottom: 0.25rem; text-align: center; font-weight: 800; letter-spacing: -0.02em; color: var(--text-main); }
  .subtitle { font-size: 0.8rem; text-align: center; color: var(--text-muted); margin-bottom: 2rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; }
  input { width: 100%; padding: 0.85rem; margin-bottom: 1.25rem; background: var(--input-bg); border: 1px solid var(--input-border); color: var(--text-main); border-radius: 6px; font-family: ui-monospace, SFMono-Regular, monospace; transition: border-color 0.2s; font-size: 0.95rem; }
  input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
  button { width: 100%; padding: 0.95rem; background: var(--accent); color: #ffffff; border: none; border-radius: 6px; font-weight: 700; font-size: 0.95rem; cursor: pointer; transition: background 0.2s; box-shadow: 0 4px 6px -1px rgba(59, 130, 246, 0.2); }
  button:hover { background: var(--accent-hover); }
</style>
<script>
  const saved = localStorage.getItem('aos-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', saved);
</script>
</head>
<body>
  <div class="login-box">
    <div style="display: flex; flex-direction: column; align-items: center; margin-bottom: 1.5rem;">
      <svg style="width: 54px; height: 54px; color: #3b82f6; margin-bottom: 1.5rem;" viewBox="0 0 100 100" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
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
        res.setHeader('Set-Cookie', `aos_gate_session=${getSessionHash()}; HttpOnly; Path=/; Max-Age=86400`);
        res.redirect('/');
    } else {
        res.redirect('/login');
    }
});

dashboard.get('/logout', (_req, res) => {
    res.setHeader('Set-Cookie', `aos_gate_session=; HttpOnly; Path=/; Max-Age=0`);
    res.redirect('/login');
});

// Admin UI layout wrapper
const renderLayout = (title, content, currentPath) => `<!DOCTYPE html>
<html><head><title>AOS Gate: ${escapeHtml(title)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --bg-main: #f8fafc;
    --bg-sidebar: #0f172a;
    --border-color: #e2e8f0;
    --border-sidebar: #1e293b;
    --text-main: #0f172a;
    --text-sidebar: #94a3b8;
    --text-sidebar-hover: #ffffff;
    --text-sidebar-title: #ffffff;
    --sidebar-active-bg: #1e293b;
    --card-bg: #ffffff;
    --card-header-bg: #f1f5f9;
    --text-muted: #64748b;
    --input-bg: #ffffff;
    --input-border: #cbd5e1;
    --accent: #3b82f6;
    --accent-hover: #2563eb;
    --table-border: #f1f5f9;
  }
  [data-theme='dark'] {
    --bg-main: #0a0a0a;
    --bg-sidebar: #151515;
    --border-color: #222222;
    --border-sidebar: #222222;
    --text-main: #e0e0e0;
    --text-sidebar: #888888;
    --text-sidebar-hover: #ffffff;
    --text-sidebar-title: #ffffff;
    --sidebar-active-bg: #222222;
    --card-bg: #151515;
    --card-header-bg: #111111;
    --text-muted: #888888;
    --input-bg: #0a0a0a;
    --input-border: #333333;
    --table-border: #1a1a1a;
  }
  body { font-family: -apple-system, system-ui, sans-serif; background: var(--bg-main); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; transition: background 0.2s; }
  .sidebar { width: 260px; background: var(--bg-sidebar); border-right: 1px solid var(--border-sidebar); display: flex; flex-direction: column; flex-shrink: 0; box-shadow: 1px 0 15px rgba(0,0,0,0.03); transition: background 0.2s; height: 100vh; overflow-y: auto; }
  .sidebar-header { padding: 1.5rem; border-bottom: 1px solid var(--border-sidebar); }
  .sidebar-title { font-weight: 800; font-size: 1.25rem; color: var(--text-sidebar-title); letter-spacing: -0.02em; }
  .sidebar-nav { flex: 1; padding: 1.5rem 0; overflow-y: auto; }
  .nav-item { display: block; padding: 0.75rem 1.5rem; color: var(--text-sidebar); text-decoration: none; font-size: 0.95rem; font-weight: 500; transition: all 0.2s; border-left: 3px solid transparent; }
  .nav-item:hover { color: var(--text-sidebar-hover); background: var(--sidebar-active-bg); }
  .nav-item.active { color: #ffffff; border-left: 3px solid var(--accent); background: var(--sidebar-active-bg); }
  .sidebar-footer { padding: 1.5rem; border-top: 1px solid var(--border-sidebar); }
  .logout-btn { display: block; width: 100%; text-align: center; padding: 0.6rem; background: transparent; color: var(--text-sidebar); text-decoration: none; border: 1px dotted var(--border-sidebar); border-radius: 6px; font-size: 0.85rem; font-weight: 600; transition: all 0.2s; }
  .logout-btn:hover { color: var(--text-sidebar-hover); border-style: solid; border-color: var(--text-sidebar); }
  .main-content { flex: 1; padding: 2.5rem 3rem; overflow-y: auto; height: 100vh; background: var(--bg-main); }
  h2 { font-size: 1.7rem; font-weight: 800; margin-bottom: 0.5rem; color: var(--text-main); display: flex; justify-content: space-between; align-items: center; letter-spacing: -0.02em; }
  .subtitle { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 2.5rem; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.5rem; margin-bottom: 2.5rem; }
  .stat { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }
  .stat .label { font-size: 0.75rem; text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; color: var(--text-muted); }
  .stat .value { font-size: 2.2rem; font-weight: 800; margin-top: 0.5rem; color: var(--text-main); }
  .passed .value { color: #22c55e; }
  .blocked .value { color: #ef4444; }
  .pii .value { color: #f59e0b; }
  .errors .value { color: #f97316; }
  .card { background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 12px; margin-bottom: 2.5rem; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }
  .card-header { padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border-color); font-weight: 700; font-size: 1rem; background: var(--card-header-bg); color: var(--text-main); }
  .card-body { padding: 1.5rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th { text-align: left; padding: 1rem 1.25rem; color: var(--text-muted); text-transform: uppercase; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; border-bottom: 2px solid var(--border-color); background: var(--card-header-bg); }
  td { padding: 1rem 1.25rem; border-bottom: 1px solid var(--table-border); color: var(--text-main); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.85rem; color: var(--text-muted); }
  .action-passed { color: #22c55e; font-weight: 600; }
  .action-blocked { color: #ef4444; font-weight: 700; }
  .action-intent_blocked { color: #ef4444; font-weight: 800; background: rgba(239, 68, 68, 0.1); padding: 2px 4px; border-radius: 4px; border: 1px solid #ef4444; }
  .action-pii_warning { color: #f59e0b; font-weight: 600; }
  .action-pii_redacted { color: #3b82f6; font-weight: 600; background: rgba(59, 130, 246, 0.1); padding: 2px 4px; border-radius: 4px; }
  .action-pii_blocked { color: #ef4444; font-weight: 700; background: rgba(239, 68, 68, 0.15); padding: 2px 4px; border-radius: 4px; }
  .action-error { color: #f97316; font-weight: 600; }
  .chain-badge { font-family: ui-monospace, monospace; font-size: 0.75rem; background: rgba(59, 130, 246, 0.1); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.3); padding: 2px 6px; border-radius: 4px; text-decoration: none; cursor: help; }
  /* Forms */
  .form-group { margin-bottom: 1.5rem; }
  label { display: block; font-size: 0.8rem; font-weight: 700; color: var(--text-muted); margin-bottom: 0.5rem; }
  textarea, input[type="text"], select { width: 100%; padding: 0.85rem; background: var(--input-bg); border: 1px solid var(--input-border); color: var(--text-main); border-radius: 6px; font-size: 0.9rem; transition: border-color 0.2s; }
  textarea:focus, input[type="text"]:focus, select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
  textarea { min-height: 120px; resize: vertical; font-family: ui-monospace, SFMono-Regular, monospace; }
  button.submit-btn { padding: 0.85rem 2rem; background: var(--accent); color: #ffffff; border: none; border-radius: 6px; font-weight: 700; font-size: 0.95rem; cursor: pointer; transition: background 0.2s; box-shadow: 0 4px 6px -1px rgba(59, 130, 246, 0.2); }
  button.submit-btn:hover { background: var(--accent-hover); }
  .pattern-row { display: grid; grid-template-columns: 1fr 2fr 80px 40px; gap: 0.75rem; margin-bottom: 1rem; align-items: start; }
  .btn-icon { background: var(--card-bg); color: var(--text-muted); border: 1px solid var(--input-border); padding: 0.6rem; border-radius: 6px; cursor: pointer; text-align: center; transition: all 0.2s; }
  .btn-icon:hover { background: #fee2e2; color: #ef4444; border-color: #fca5a5; }
  .btn-add { background: var(--card-bg); color: var(--accent); border: 2px dashed var(--input-border); padding: 0.75rem 1.5rem; cursor: pointer; font-size: 0.9rem; font-weight: 600; border-radius: 6px; display: inline-block; margin-top: 0.5rem; transition: all 0.2s; }
  .btn-add:hover { border-color: var(--accent); }
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
  function toggleTheme() {
    const root = document.documentElement;
    const current = root.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    localStorage.setItem('aos-theme', next);
  }
  function verifyLedger() {
    const btn = document.getElementById('verify-chain-btn');
    btn.innerText = 'Verifying...';
    fetch('/api/verify-chain').then(r=>r.json()).then(d => {
      if (d.verified) {
        btn.style.background = '#064e3b';
        btn.style.color = '#a7f3d0';
        btn.style.border = '1px solid #047857';
        btn.innerText = '✓ ' + d.totalEntries + ' Entries Verified';
        alert('Cryptographic Ledger Validated.\\nFiles: ' + d.filesChecked + '\\nEntries: ' + d.totalEntries + '\\nGenesis Hash: ' + d.genesisHash);
      } else {
        btn.style.background = '#7f1d1d';
        btn.style.color = '#fecaca';
        btn.innerText = '✗ Chain Error (' + d.errors.length + ')';
        alert('Chain Verification Failed!\\n' + JSON.stringify(d.errors, null, 2));
      }
      setTimeout(() => { btn.innerText = 'Verify Chain Integrity'; btn.style.background = ''; btn.style.color = ''; btn.style.border = ''; }, 6000);
    }).catch(e => {
      btn.innerText = 'Verification Failed';
    });
  }
  const saved = localStorage.getItem('aos-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', saved);
</script>
</head><body>
  <div class="sidebar">
    <div class="sidebar-header" style="display: flex; align-items: center; gap: 1rem;">
      <svg style="width: 32px; height: 32px; color: #3b82f6; flex-shrink: 0;" viewBox="0 0 100 100" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
        <polygon points="50,20 80,40 50,100" fill="none" stroke="currentColor" stroke-width="8"/>
        <polygon points="50,40 70,55 50,80" fill="currentColor" />
        <line x1="35" y1="10" x2="35" y2="90" stroke="currentColor" stroke-width="12" />
      </svg>
      <div>
        <div class="sidebar-title">AOS Gate</div>
        <div style="font-size: 0.75rem; color:#64748b; margin-top:2px;">Intent Firewall v${GATE_VERSION}</div>
      </div>
    </div>
    <div class="sidebar-nav">
      <a href="/" class="nav-item ${currentPath === '/' ? 'active' : ''}">Activity Log</a>
      <a href="/stats" class="nav-item ${currentPath === '/stats' ? 'active' : ''}">Usage Stats</a>
      <a href="/rules" class="nav-item ${currentPath === '/rules' ? 'active' : ''}">Policy &amp; Rules</a>
      <a href="/how-it-works" class="nav-item ${currentPath === '/how-it-works' ? 'active' : ''}">How It Works</a>
      <a href="/export" class="nav-item ${currentPath === '/export' ? 'active' : ''}">Export Logs</a>
      <a href="/docs" class="nav-item ${currentPath === '/docs' ? 'active' : ''}">Documentation</a>
    </div>
    <div class="sidebar-footer">
      <button onclick="verifyLedger()" id="verify-chain-btn" style="width: 100%; padding:0.6rem; margin-bottom:0.75rem; background:rgba(59,130,246,0.1); color:var(--accent); border:1px solid rgba(59,130,246,0.3); border-radius:6px; font-size:0.8rem; cursor:pointer; font-weight:700; transition:all 0.2s;">🔗 Verify Chain Integrity</button>
      <button onclick="toggleTheme()" style="width: 100%; padding:0.6rem; margin-bottom:0.75rem; background:transparent; color:var(--text-sidebar); border:1px dashed var(--border-sidebar); border-radius:6px; font-size:0.8rem; cursor:pointer; font-weight:600; transition:all 0.2s;">Toggle Dark / Light</button>
      <div style="display: flex; gap: 0.5rem; margin-bottom: 0.75rem;">
        <a href="https://aos-constitution.com" target="_blank" class="logout-btn" style="flex:1; padding:0.5rem; font-size:0.75rem; margin-bottom:0;">Constitution</a>
        <a href="https://aos-governance.com" target="_blank" class="logout-btn" style="flex:1; padding:0.5rem; font-size:0.75rem; margin-bottom:0;">Governance</a>
      </div>
      <a href="/logout" class="logout-btn">Sign Out</a>
    </div>
  </div>
  <div class="main-content">
    <h2>${escapeHtml(title)}</h2>
    ${content}
  </div>
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

// ─── Dashboard Routes ───────────────────────────────────────────────────────
dashboard.get('/', requireAuth, (req, res) => {
    const date = req.query.date || new Date().toISOString().split('T')[0];
    const entries = readEntriesForDate(date);

    const passed = entries.filter(e => e.action === 'PASSED').length;
    const blocked = entries.filter(e => e.action === 'BLOCKED' || e.action === 'INTENT_BLOCKED' || e.action === 'PII_BLOCKED').length;
    const piiActions = entries.filter(e => e.action === 'PII_WARNING' || e.action === 'PII_REDACTED').length;
    const errors = entries.filter(e => e.action === 'ERROR').length;

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
        <span>Log File: gate-${escapeHtml(date)}.jsonl &middot; ${entries.length} requests captured</span>
        ${!isToday ? `<a href="/?date=${nextStr}" style="color:#888; text-decoration:none; font-size:1.2rem;">&rarr;</a>` : ''}
        ${!isToday ? `<a href="/" style="color:#555; text-decoration:none; font-size:0.75rem; border:1px solid #333; padding:0.2rem 0.5rem; border-radius:4px;">Today</a>` : ''}
      </div>
      <div class="stats">
        <div class="stat passed"><div class="label">Passed</div><div class="value">${passed}</div></div>
        <div class="stat blocked"><div class="label">Blocked</div><div class="value">${blocked}</div></div>
        <div class="stat pii"><div class="label">PII Intercepts</div><div class="value">${piiActions}</div></div>
        <div class="stat errors"><div class="label">Errors</div><div class="value">${errors}</div></div>
      </div>
      <div class="card">
        <div class="card-header">Cryptographic Audit Trail : ${escapeHtml(date)}</div>
        <table>
          <thead><tr><th>Time</th><th>Action</th><th>Provider</th><th>Model</th><th>Tokens</th><th>Duration</th><th>SHA-256 Ledger</th><th>Notes</th></tr></thead>
          <tbody>
            ${entries.length > 0 ? entries.reverse().map(e => `<tr>
              <td class="mono">${escapeHtml(e.timestamp?.split('T')[1]?.substring(0,8) || '')}</td>
              <td class="action-${escapeHtml((e.action||'').toLowerCase())}">${escapeHtml(e.action)}</td>
              <td>${escapeHtml(e.provider || '')}</td>
              <td class="mono">${escapeHtml(e.model || '')}</td>
              <td class="mono">${escapeHtml(e.inputTokens || '')} / ${escapeHtml(e.outputTokens || '')}</td>
              <td class="mono">${e.durationMs ? escapeHtml(e.durationMs + 'ms') : ''}</td>
              <td>
                ${e.chain_hash ? `<span class="chain-badge" title="Chain Hash: ${escapeHtml(e.chain_hash)}\\nPrevious: ${escapeHtml(e.previous_hash || '')}">🔗 ${escapeHtml(e.chain_hash.substring(0,8))}...</span>` : '<span style="color:#666;">Legacy</span>'}
              </td>
              <td class="mono" style="max-width:280px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${escapeHtml(e.reason || (e.inputPII ? 'PII: ' + e.inputPII.map(p=>p.type).join(', ') : '') || (e.error || ''))}">
                ${escapeHtml(e.reason || (e.inputPII ? 'PII: ' + e.inputPII.map(p=>p.type).join(', ') : '') || (e.error || '') || '')}
              </td>
            </tr>`).join('') : `<tr><td colspan="8" style="text-align:center; padding: 2rem; color:#666;">No audit records found for ${escapeHtml(date)}.</td></tr>`}
          </tbody>
        </table>
      </div>
    `;
    res.send(renderLayout('Activity Log', content, '/'));
});

dashboard.get('/rules', requireAuth, (_req, res) => {
    let currentPolicy = { logLevel: 'full', piiAction: 'warn', allowedModels: [], blockedPatterns: [] };
    if (existsSync(POLICY_FILE)) {
        try { currentPolicy = JSON.parse(readFileSync(POLICY_FILE, 'utf-8')); } catch (e) {}
    }

    let messageHtml = '';
    if (_req.query.saved) {
        messageHtml = `<div style="background: #064e3b; color: #a7f3d0; padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem; font-weight: 600; border: 1px solid #047857;">✓ Policy updated securely. Changes applied to active proxy memory immediately.</div>`;
    }

    const content = `
      <div class="subtitle">Gate configuration applied at the proxy level. Enforced deterministically in sub-millisecond memory.</div>
      ${messageHtml}
      <form method="POST" action="/rules">
        <div class="card">
          <div class="card-header">General Rules &amp; PII Defense</div>
          <div class="card-body">
            <div class="form-group">
              <label>Log Level</label>
              <select name="logLevel">
                <option value="full" ${currentPolicy.logLevel === 'full' ? 'selected' : ''}>Full (Capture Prompt &amp; Response Text)</option>
                <option value="meta" ${currentPolicy.logLevel !== 'full' ? 'selected' : ''}>Meta Only (Capture Usage Stats, Mask Text)</option>
              </select>
            </div>
            <div class="form-group">
              <label>PII Engine Action (SSN, Credit Card, Email, US Phone, AWS Access Key, API Secret Key)</label>
              <select name="piiAction">
                <option value="warn" ${(currentPolicy.piiAction || 'warn') === 'warn' ? 'selected' : ''}>Warn (Log PII_WARNING, forward unmodified)</option>
                <option value="redact" ${(currentPolicy.piiAction || 'warn') === 'redact' ? 'selected' : ''}>Redact (Replace PII with [REDACTED_*] synthetic tokens, forward clean)</option>
                <option value="block" ${(currentPolicy.piiAction || 'warn') === 'block' ? 'selected' : ''}>Block (Reject request immediately with 403 Forbidden PII_BLOCKED)</option>
              </select>
            </div>
            <div class="form-group" style="margin-bottom:0;">
              <label>Allowed Models (One per line: supports glob wildcards such as claude-sonnet-4-*, gpt-4o*, gemini-*, *)</label>
              <textarea name="allowedModels">${escapeHtml((currentPolicy.allowedModels || []).join('\n'))}</textarea>
              <div style="font-size:0.75rem; color:#666; margin-top:0.5rem;">Leave empty or enter * to allow all requested models.</div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-header">Content &amp; Downstream Intent Block Rules (Regex)</div>
          <div class="card-body" style="padding-bottom:1rem;">
            <div id="patterns-container">
              ${(currentPolicy.blockedPatterns || []).map(p => `
                <div class="pattern-row">
                  <input type="text" name="patternLabel" value="${escapeHtml(p.label || '')}" placeholder="Label" required>
                  <input type="text" name="patternRegex" value="${escapeHtml(p.pattern || '')}" placeholder="Regex" required>
                  <input type="text" name="patternFlags" value="${escapeHtml(p.flags || 'gi')}" placeholder="Flags">
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
    const updatedPolicy = {
        logLevel: req.body.logLevel || 'full',
        piiAction: req.body.piiAction || 'warn',
        allowedModels: (req.body.allowedModels || '').replace(/\r\n/g, '\n').split('\n').map(s => s.trim()).filter(Boolean),
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
    policy = updatedPolicy;

    res.redirect('/rules?saved=1');
});

dashboard.get('/stats', requireAuth, (_req, res) => {
    const files = readdirSync(LOG_DIR).filter(f => f.endsWith('.jsonl')).sort().reverse().slice(0, 14);
    const days = [];
    let maxTotal = 1;
    for (const file of files.reverse()) {
        const date = file.replace('gate-', '').replace('.jsonl', '');
        const entries = readEntriesForDate(date);
        const passed = entries.filter(e => e.action === 'PASSED').length;
        const blocked = entries.filter(e => e.action === 'BLOCKED' || e.action === 'INTENT_BLOCKED' || e.action === 'PII_BLOCKED').length;
        const pii = entries.filter(e => e.action === 'PII_WARNING' || e.action === 'PII_REDACTED').length;
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
        return `<rect x="${x}" y="${chartHeight - passedH}" width="${barWidth}" height="${passedH}" fill="#4ade80" rx="2"/>
                <rect x="${x}" y="${chartHeight - passedH - blockedH}" width="${barWidth}" height="${blockedH}" fill="#f87171" rx="2"/>
                <rect x="${x}" y="${chartHeight - passedH - blockedH - piiH}" width="${barWidth}" height="${piiH}" fill="#fbbf24" rx="2"/>
                <text x="${x + barWidth/2}" y="${chartHeight + 14}" text-anchor="middle" fill="#666" font-size="10">${escapeHtml(d.date.substring(5))}</text>
                <text x="${x + barWidth/2}" y="${chartHeight - h - 4}" text-anchor="middle" fill="#888" font-size="10">${d.total}</text>`;
    }).join('');

    const allEntries = [];
    for (const d of days) { allEntries.push(...readEntriesForDate(d.date)); }
    const modelCounts = {};
    for (const e of allEntries) { if (e.model) modelCounts[e.model] = (modelCounts[e.model] || 0) + 1; }
    const modelRows = Object.entries(modelCounts).sort((a, b) => b[1] - a[1]);
    const totalRequests = allEntries.length;

    const content = `
      <div class="subtitle">Last ${days.length} days &middot; ${totalRequests} total requests captured</div>
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
            <span><span style="display:inline-block;width:10px;height:10px;background:#fbbf24;border-radius:2px;"></span> PII Intercept</span>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-header">Model Usage Breakdown</div>
        <table>
          <thead><tr><th>Model</th><th>Requests</th><th style="width:50%">Share</th></tr></thead>
          <tbody>
            ${modelRows.length > 0 ? modelRows.map(([model, count]) => {
              const pct = totalRequests > 0 ? ((count / totalRequests) * 100).toFixed(1) : '0';
              return `<tr>
                <td class="mono">${escapeHtml(model)}</td>
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

dashboard.get('/export', requireAuth, (_req, res) => {
    const files = readdirSync(LOG_DIR).filter(f => f.endsWith('.jsonl')).sort().reverse();
    const fileRows = files.map(f => {
        const date = f.replace('gate-', '').replace('.jsonl', '');
        const entries = readEntriesForDate(date);
        const size = existsSync(join(LOG_DIR, f)) ? readFileSync(join(LOG_DIR, f)).length : 0;
        const sizeStr = size > 1024 ? (size / 1024).toFixed(1) + ' KB' : size + ' B';
        return `<tr>
            <td class="mono">${escapeHtml(date)}</td>
            <td class="mono">${entries.length}</td>
            <td class="mono">${sizeStr}</td>
            <td>
              <a href="/export/download?date=${escapeHtml(date)}&format=json" style="color:#4ade80; text-decoration:none; margin-right:1rem;">JSON</a>
              <a href="/export/download?date=${escapeHtml(date)}&format=csv" style="color:#60a5fa; text-decoration:none;">CSV (Chained)</a>
            </td>
        </tr>`;
    }).join('');

    const content = `
      <div class="subtitle">Download audit logs for compliance, legal discovery, and cryptographic verification.</div>
      <div class="card">
        <div class="card-header">Available Log Files (SHA-256 Chained)</div>
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
        const headers = 'timestamp,action,provider,model,inputTokens,outputTokens,durationMs,previous_hash,chain_hash,reason';
        const rows = entries.map(e =>
            [
                e.timestamp,
                e.action,
                e.provider,
                e.model,
                e.inputTokens,
                e.outputTokens,
                e.durationMs,
                e.previous_hash || '',
                e.chain_hash || '',
                (e.reason || (e.inputPII ? 'PII: ' + e.inputPII.map(p=>p.type).join(', ') : '') || (e.error || ''))
            ].map(v => '"' + String(v || '').replace(/"/g, '""') + '"').join(',')
        );
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="aos-gate-${date}.csv"`);
        res.send(headers + '\n' + rows.join('\n'));
    } else {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="aos-gate-${date}.json"`);
        res.json({ date, version: GATE_VERSION, genesisHash: GENESIS_HASH, entries });
    }
});

// Verification API
dashboard.get('/api/verify-chain', requireAuth, (req, res) => {
    const targetDate = req.query.date || null;
    const result = verifyChainIntegrity(targetDate);
    res.json(result);
});

// Log query API
dashboard.get('/api/logs', requireAuth, (_req, res) => {
    const files = readdirSync(LOG_DIR).filter(f => f.endsWith('.jsonl')).sort().reverse();
    const logs = {};
    for (const file of files.slice(0, 7)) {
        const entries = readEntriesForDate(file.replace('gate-', '').replace('.jsonl', ''));
        logs[file.replace('gate-', '').replace('.jsonl', '')] = entries;
    }
    res.json(logs);
});

// Documentation page
dashboard.get('/docs', requireAuth, (_req, res) => {
    const content = `
      <div class="subtitle">Reference for proxy routing, wildcard allowlists, SSE streaming, and PII modes.</div>
      <div class="card">
        <div class="card-header">Workflow Setup (N8N / Make / Cursor / Devin)</div>
        <div class="card-body">
            <h3 style="margin-bottom:0.5rem; color:var(--text-main); font-size: 1rem;">Routing API Calls</h3>
            <p style="color:var(--text-muted); font-size:0.85rem; margin-bottom:1rem; line-height:1.5;">To enforce policy with AOS Gate, point your HTTP request nodes or SDK base URLs at the proxy. Upstream credentials are forwarded securely.</p>
            <table style="margin-bottom:1.5rem;">
                <thead><tr><th>Upstream Provider</th><th>Original Endpoint</th><th>AOS Gate Proxy Endpoint</th></tr></thead>
                <tbody>
                    <tr><td>Anthropic</td><td>https://api.anthropic.com/v1/messages</td><td class="mono">http://aos-gate:3100/v1/messages</td></tr>
                    <tr><td>OpenAI</td><td>https://api.openai.com/v1/chat/completions</td><td class="mono">http://aos-gate:3100/v1/chat/completions</td></tr>
                    <tr><td>Google Gemini</td><td>https://generativelanguage.googleapis.com/v1beta/models/...</td><td class="mono">http://aos-gate:3100/v1beta/models/:modelAction</td></tr>
                    <tr><td>Model List</td><td>https://api.openai.com/v1/models</td><td class="mono">http://aos-gate:3100/v1/models</td></tr>
                    <tr><td>Deterministic Evaluator</td><td>Local Testing (No upstream call)</td><td class="mono">http://aos-gate:3100/v1/evaluate</td></tr>
                </tbody>
            </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header">PII Engine (3 Enforcement Modes)</div>
        <div class="card-body">
            <p style="color:var(--text-muted); font-size:0.85rem; margin-bottom:1rem; line-height:1.5;">AOS Gate inspects outbound prompts and inbound responses for 6 categories: SSN, Credit Cards, Emails, US Phone Numbers, AWS Access Keys, and API Secret Keys.</p>
            <ul style="color:var(--text-muted); font-size:0.85rem; line-height:1.6; padding-left:1.5rem; margin-bottom:1rem;">
                <li><strong>warn</strong>: Logs <code>PII_WARNING</code> with exact match counts and forwards unmodified.</li>
                <li><strong>redact</strong>: Deterministically substitutes matches with synthetic tokens (<code>[REDACTED_SSN]</code>, <code>[REDACTED_CARD]</code>, <code>[REDACTED_EMAIL]</code>, <code>[REDACTED_PHONE]</code>, <code>[REDACTED_KEY]</code>) before forwarding upstream.</li>
                <li><strong>block</strong>: Instantly returns <code>403 Forbidden</code> with action <code>PII_BLOCKED</code>, halting packet transit before external network egress.</li>
            </ul>
        </div>
      </div>
    `;
    res.send(renderLayout('Documentation', content, '/docs'));
});

dashboard.get('/how-it-works', requireAuth, (_req, res) => {
    const content = `
      <div class="subtitle">Deterministic containment and immutable forensic verification.</div>

      <div class="card">
        <div class="card-header" style="color: var(--accent); font-weight: 800;">1. The Physical Bottleneck (Pre-Flight &amp; Downstream Intercept)</div>
        <div class="card-body">
          <p style="color:var(--text-muted); font-size:0.95rem; line-height:1.6; margin-bottom:1.5rem;">
            AOS Gate is a local network bottleneck running inside your private VPC or container environment. Outbound requests are evaluated before they leave the host. If prompt tokens violate model allowlists or regex policies, or contain forbidden PII in block mode, the packet is terminated with a 403 Forbidden. Furthermore, response streams are inspected in real time: if hallucinated tool calls (such as S3 deletions or SQL injections) emerge in SSE chunks, the stream is severed instantly.
          </p>
        </div>
      </div>

      <div class="card">
        <div class="card-header" style="color: var(--accent); font-weight: 800;">2. Native SHA-256 Hash-Chained Audit Ledger</div>
        <div class="card-body">
          <p style="color:var(--text-muted); font-size:0.95rem; line-height:1.6; margin-bottom:0;">
            Every audit event records the preceding record hash, timestamp, provider, action, model, and decision reason into a cryptographic chain. The genesis entry anchors to <code>AOS-GATE-2.0:GENESIS</code>. If any record in <code>gate-YYYY-MM-DD.jsonl</code> is modified, deleted, or reordered, <code>GET /api/verify-chain</code> immediately flags the tamper boundary.
          </p>
        </div>
      </div>
    `;
    res.send(renderLayout('How It Works', content, '/how-it-works'));
});

dashboard.listen(DASHBOARD_PORT, () => {
    console.log(`[Dashboard] http://localhost:${DASHBOARD_PORT}`);
});
