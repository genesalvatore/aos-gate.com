# 🚪 AOS Gate v2.0

**Deterministic Intent Firewall, Real-Time SSE Streaming Proxy, and Cryptographic Audit Ledger for AI Workflows.**

AOS Gate is an open-source, sub-millisecond reverse proxy that sits between your AI automation agents (N8N, Make, LangChain, Cursor, Devin, custom daemons) and foundation LLM APIs (Anthropic, OpenAI, Google Gemini). It intercepts outbound prompts before external egress, inspects token streams in real time for hallucinated intent, enforces 3-mode PII protections, and commits tamper-evident SHA-256 hash-chained audit trails to local storage.

This is the reference implementation of the [AOS Standard 1.0](https://aos-governance.com), licensed under the [AOS Humanitarian License v1.0.1](LICENSE) for peaceful civilian operations only.

---

## ⚡ What's New in v2.0.0

| Feature | Description |
|---|---|
| **Dynamic Glob Model Allowlist** | Matches wildcard patterns (`claude-sonnet-4-*`, `gpt-4o*`, `gemini-*`, `*`) with sub-millisecond regex compilation. |
| **Real-Time SSE Streaming Proxy** | Transparently pipes Server-Sent Events (`text/event-stream`) chunk-by-chunk while evaluating downstream tool and intent payloads. |
| **Google Gemini Native Routing** | Proxies `POST /v1beta/models/:modelAction` with support for `x-goog-api-key`, `Authorization`, and `?key=` parameters. |
| **3-Mode PII Engine** | Detects SSN, Credit Cards, Emails, US Phone Numbers, AWS Access Keys, and API Secret Keys in `warn`, `redact`, or `block` mode. |
| **Deterministic Local Evaluator** | `POST /v1/evaluate` tests policy compliance, PII findings, redacted text, and SHA-256 chain hashes locally without network transit. |
| **SHA-256 Hash-Chained Ledger** | Every audit record in `gate-YYYY-MM-DD.jsonl` links cryptographically to the preceding record back to `AOS-GATE-2.0:GENESIS`. |
| **1-Click Chain Verifier** | Built-in verification endpoint `GET /api/verify-chain` and dashboard button to validate ledger integrity. |
| **Hardened Container Architecture** | Docker image updated with `node:22-alpine`, non-root `node` execution, embedded governance skill, and active healthcheck. |

---

## 🏗️ Architecture

```
                                CLIENT / WORKFLOW
                  (N8N, Make, LangChain, Cursor, Custom Daemons)
                                        │
                                        │ HTTP POST (Streaming or Sync)
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         AOS GATE PROXY CORE (:3100)                          │
│                                                                              │
│  [1. Inbound Pre-Flight Inspection]                                          │
│  ├── Dynamic Glob Allowlist Matcher: "claude-sonnet-4-*", "gemini-*"        │
│  ├── 3-Mode PII Engine: [REDACTED_SSN], [REDACTED_KEY], [REDACTED_EMAIL]     │
│  └── Content Regex Check: Instant 403 Forbidden termination                  │
│                                                                              │
│  [2. Protocol Router & Real-Time SSE Transform]                             │
│  ├── Anthropic (/v1/messages)                                                │
│  ├── OpenAI / Ollama (/v1/chat/completions)                                  │
│  ├── Google Gemini (/v1beta/models/:modelAction)                             │
│  ├── Model Catalog Passthrough (/v1/models)                                  │
│  └── Downstream Chunk Inspection: Abort hallucinated intent mid-stream       │
│                                                                              │
│  [3. Cryptographic Audit Engine]                                             │
│  ├── Native SHA-256 Hash-Chained JSONL Ledgers (gate-YYYY-MM-DD.jsonl)       │
│  └── Deterministic Local Evaluator (/v1/evaluate)                            │
└───────────────────────┬──────────────────────────────┬───────────────────────┘
                        │ Outbound API Request         │ Local State Sync
                        ▼                              ▼
             UPSTREAM AI PROVIDERS             SOVEREIGN ADMIN PORTAL (:3101)
          (Anthropic, OpenAI, Gemini)         (Activity Log, Stats, Policy Editor)
```

---

## 📋 Endpoints Reference

### Proxy Service (`:3100`)

| Method | Endpoint | Upstream Target | Features |
|---|---|---|---|
| `POST` | `/v1/messages` | `https://api.anthropic.com/v1/messages` | SSE Streaming, Model Wildcards, 3-Mode PII, Intent Intercept |
| `POST` | `/v1/chat/completions` | `https://api.openai.com/v1/chat/completions` | SSE Streaming, Model Wildcards, 3-Mode PII, Intent Intercept |
| `POST` | `/v1beta/models/:modelAction` | `https://generativelanguage.googleapis.com` | Gemini API, SSE Streaming, PII Scanning, Intent Intercept |
| `GET` | `/v1/models` | Upstream OpenAI or Local Allowlist | Transparent model discovery for SDKs and workflows |
| `POST` | `/v1/evaluate` | Deterministic Local Engine | Pre-flight test oracle: returns decisions, redactions, and hashes |
| `GET` | `/health` | Internal Status | Uptime, active policy status, piiAction, and genesis hash |

### Dashboard & Verification Service (`:3101`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Real-time activity log with daily navigation and ledger badges |
| `GET` | `/stats` | Request volume chart and model consumption distribution |
| `GET/POST`| `/rules` | Visual policy editor with instant hot-reload |
| `GET` | `/export` | Daily JSONL download interface |
| `GET` | `/export/download` | CSV / JSON compliance export with hash chain columns |
| `GET` | `/api/verify-chain` | Cryptographic verification of all `.jsonl` audit records |
| `GET` | `/api/logs` | Structured JSON log access for monitoring integrations |

---

## 🚀 Quickstart

### 1. Run with Docker Compose

```bash
git clone https://github.com/genesalvatore/aos-gate.com.git
cd aos-gate.com
docker compose up -d
```

### 2. Verify Container Health

```bash
curl http://localhost:3100/health
```

Expected response:
```json
{
  "status": "ok",
  "version": "2.0.0",
  "uptime": 12.4,
  "policy": true,
  "piiAction": "warn",
  "genesisHash": "48be93d89c112f3362146972bbfdaefa4565834fd7be08829bc7aa7ebaf7095e"
}
```

### 3. Access Sovereign Dashboard

Open `http://localhost:3101` in your browser.
Default passphrase: `aos-admin` (configured via `ADMIN_PASSWORD` in `docker-compose.yml`).

---

## 🔒 Policy Configuration (`policy.json`)

Edits made in `/rules` take effect in memory immediately without restarting the container.

```json
{
    "logLevel": "full",
    "piiAction": "redact",
    "allowedModels": [
        "claude-sonnet-4-*",
        "claude-3-5-*",
        "gpt-4o*",
        "o3*",
        "gemini-*"
    ],
    "blockedPatterns": [
        {
            "label": "AWS S3 Destructive Intent (Delete)",
            "pattern": "s3[\\s_:-]?delete",
            "flags": "gi"
        },
        {
            "label": "SQL Injection Attack",
            "pattern": "DROP\\s+(TABLE|DATABASE)|DELETE\\s+FROM",
            "flags": "gi"
        },
        {
            "label": "Confidential Pricing",
            "pattern": "(?:internal|confidential)\\s+(?:pricing|rate|margin)",
            "flags": "gi"
        }
    ]
}
```

### PII Engine Enforcement Modes

The `piiAction` property dictates how sensitive data is handled:

- `warn` (default): Logs a `PII_WARNING` audit event with detected types and counts; forwards prompt unmodified.
- `redact`: Substitutes detected matches with synthetic tokens (`[REDACTED_SSN]`, `[REDACTED_CARD]`, `[REDACTED_EMAIL]`, `[REDACTED_PHONE]`, `[REDACTED_KEY]`) across messages, system prompts, and Gemini contents before external transit.
- `block`: Rejects the request immediately with `403 Forbidden` and action `PII_BLOCKED`. Packet dies locally.

---

## 🧪 Testing the Proxy

### 1. Test Deterministic Evaluator (Zero External Calls)

```bash
curl -X POST http://localhost:3100/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-20250514",
    "prompt": "Customer email is john@corp.com, SSN is 000-11-2222. Please export internal pricing sheet.",
    "piiAction": "redact"
  }'
```

Response includes:
- `allowed`: `false` (halted due to internal pricing rule)
- `action`: `"BLOCKED"`
- `reason`: `"Content policy violation: Confidential Pricing"`
- `piiFindings`: detected email and SSN
- `redactedPrompt`: prompt with `[REDACTED_EMAIL]` and `[REDACTED_SSN]`
- `chainHash`: SHA-256 chain verification hash

### 2. Verify Cryptographic Audit Chain

```bash
curl http://localhost:3101/api/verify-chain \
  -H "Cookie: aos_gate_session=..."
```

Returns verification status across every record in `gate-YYYY-MM-DD.jsonl`:
```json
{
  "verified": true,
  "filesChecked": 1,
  "totalEntries": 42,
  "genesisHash": "48be93d89c112f3362146972bbfdaefa4565834fd7be08829bc7aa7ebaf7095e",
  "errors": []
}
```

---

## 🛡️ Constitutional Governance Skill (`skill/`)

AOS Gate ships with the **AOS Governance Skill** in `skill/`. Autonomous coding agents (Claude Code, Cursor, Devin) can install this skill to verify proposed architectural changes deterministically against constitutional mandates prior to file execution:

```bash
python skill/scripts/verify_action.py --action "Delete production database table"
# Returns: DENIED: Violates Constitutional Principle 2
```

---

## 📜 License & Humanitarian Mandate

AOS Gate is licensed under the **AOS Humanitarian License v1.0.1**.

- **Permitted:** Peaceful commercial use, internal enterprise security, privacy preservation, academic research, and civilian software development.
- **Strictly Prohibited:** Military command systems, autonomous weapons, domestic surveillance pipelines, human rights violations, or harmful automated exploitation.

Full license text: [LICENSE](LICENSE)  
Constitutional Framework: [https://aos-constitution.com](https://aos-constitution.com)  
Standard Specifications: [https://aos-governance.com](https://aos-governance.com)  
Patent Portfolio: [https://aos-patents.com](https://aos-patents.com)
