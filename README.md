# 🚪 AOS Gate

**The open-source governance toolkit for AI workflows.**

AOS Gate is a transparent audit proxy that sits between your AI automation tools (N8N, Make, Zapier, custom scripts) and the AI provider. It logs every exchange, detects sensitive data, enforces policy rules, and gives you a full enterprise dashboard — all in a single Docker container.

**Think of it like a security camera + policy engine for your AI calls.** It records everything, blocks what you tell it to block, and gives you the forensic trail to prove what happened.

This is the reference implementation of the [AOS Standard 1.0](https://aos-governance.com) — a governance architecture for the Intelligence Age.

Licensed under the [AOS Humanitarian License v1.0.1](LICENSE) — peaceful civilian use only.

---

## What's Included

| Component | Description |
|-----------|-------------|
| **AOS Gate Proxy** (port 3100) | Transparent API proxy with audit logging, PII detection, and policy enforcement |
| **Admin Dashboard** (port 3101) | Enterprise UI with activity log, usage stats, policy editor, and log export |
| **Governance Skill** (`skill/`) | Agent-installable governance scripts for constitutional verification |

---

## 📋 What You Need Before Starting

You need **Docker** installed on your computer. That's it.

- **If you already have Docker running** (you'll know because you're running N8N or similar in containers), you're ready to go.
- **If you don't have Docker yet**, install Docker Desktop from https://www.docker.com/products/docker-desktop/

To check if Docker is installed, open a terminal and type:
```
docker --version
```
If you see a version number, you're good.

---

## 🚀 Setup — Step by Step

### Step 1: Download AOS Gate

Open a terminal (Command Prompt on Windows, Terminal on Mac/Linux) and run:

```bash
git clone https://github.com/genesalvatore/aos-gate.com.git
cd aos-gate.com
```

**Don't have git?** You can also download the ZIP file from GitHub and unzip it.

### Step 2: Start AOS Gate

In the same terminal, run:

```bash
docker compose up -d
```

That's it. AOS Gate is now running.

You should see something like:
```
✔ Container aos-gate  Started
```

### Step 3: Verify It's Running

Open your web browser and go to:

```
http://localhost:3101
```

You will be presented with the **Sovereign Admin** login screen.
> **Default Passphrase:** `aos-admin`

*(You can change this by setting the `ADMIN_PASSWORD` variable in your environment or `docker-compose.yml`.)*

Once logged in, you should see the **AOS Gate Dashboard** — showing your audit log, usage stats, policy editor, and log export tools.

### Step 4: Update Your N8N Nodes

This is the only change you need to make to your existing setup.

In your N8N workflow, find any **HTTP Request** node that calls an AI provider. Change the URL:

| What you have now | Change it to |
|---|---|
| `https://api.anthropic.com/v1/messages` | `http://aos-gate:3100/v1/messages` |
| `https://api.openai.com/v1/chat/completions` | `http://aos-gate:3100/v1/chat/completions` |

**Important:** If N8N is running in Docker too, use `aos-gate` as the hostname. If N8N is running directly on your computer (not in Docker), use `localhost` instead:

| N8N in Docker | N8N on your computer directly |
|---|---|
| `http://aos-gate:3100/v1/messages` | `http://localhost:3100/v1/messages` |

**Your API keys stay exactly where they are** — in the N8N node's headers. AOS Gate just passes them through.

### Step 5: Test It

Run one of your N8N workflows that calls an AI model. Then check the dashboard at `http://localhost:3101`. You should see the call logged with:

- ✅ **PASSED** — the call went through
- ⏱ Duration in milliseconds
- 📊 Token count (input/output)
- ⚠️ Any PII warnings (emails, phone numbers, etc. detected in your prompts)

---

## 📊 Dashboard

The admin dashboard at `:3101` provides four pages:

| Page | Description |
|------|-------------|
| **Activity Log** | Real-time audit trail with date navigation (← → arrows) |
| **Usage Stats** | 14-day request volume chart + model usage breakdown |
| **Policy & Rules** | GUI editor for log levels, model allowlists, and regex block rules |
| **Export Logs** | One-click JSON/CSV download per day for compliance and evidence |

---

## ⚙️ Customizing the Rules

You can configure policy directly from the **Policy & Rules** page in the dashboard, or edit `policy.json` manually.

### Restrict Which AI Models Can Be Used

```json
{
    "allowedModels": [
        "claude-sonnet-4-20250514",
        "gpt-4o-mini"
    ]
}
```

If someone tries to use a model not on this list, AOS Gate will **block the request** and log it as `BLOCKED`.

### Block Sensitive Topics

Add patterns to `blockedPatterns` to prevent certain content from being sent to the AI:

```json
{
    "blockedPatterns": [
        {
            "label": "Internal pricing",
            "pattern": "confidential\\s+pricing",
            "flags": "gi"
        }
    ]
}
```

### Change Logging Detail

Set `logLevel` to control how much is logged:

- `"full"` — Logs the first 2,000 characters of every prompt and response (default)
- `"meta"` — Logs only metadata (model, tokens, duration) — no prompt text

---

## 🛡️ Governance Skill (Agent-Installable)

The `skill/` directory contains the **AOS Governance Skill** — deterministic verification scripts that an AI agent can use to check its own actions against the AOS Constitution before execution.

### How It Works

1. **Intercept** — Agent proposes an action
2. **Verify** — `verify_action.py` checks against the Constitution
3. **Gate** — Action proceeds only if all checks pass. If not, it is blocked and logged.

### Key Scripts

| Script | Purpose |
|--------|---------|
| `skill/scripts/verify_action.py` | Deterministic constitutional verification |
| `skill/scripts/log_evidence.py` | Immutable evidence logging to cryptographic ledger |
| `skill/SKILL.md` | Agent instructions and workflow |

### Installation in Any Agent

```bash
cp -r skill/ ./your-agent/skills/aos-governance
export AOS_CONSTITUTION_PATH=./skills/aos-governance/references
```

The skill is platform-agnostic — works with Claude, ChatGPT, Gemini, open-source models, or custom implementations.

---

## 🏢 Enterprise Application: WSM-DPG (Website Manager DPG)

The AOS Gate framework can extend deeply into build pipelines as the **WSM-DPG**, the definitive solution for web agency client handoffs.

By deploying the WSM-DPG as a GitHub Action intercepting a Vercel/Netlify pipeline, you can safely hand over complete repository access to a client using autonomous agents (Cursor, Devin, Claude). The WSM-DPG acts as a cryptographic **Senior Architect** that never sleeps:
- **Enforces Design Systems:** Automatically rejects pull requests that inject messy inline styling or unauthorized colors outside of standard variable tokens.
- **Structural Integrity:** Fails builds that attempt to mutate core layouts, routing grids, or bloat the `package.json`.
- **The SaaS-to-Governance Pivot:** Flips the traditional agency model from "fixing what the client breaks for $150/hr" to selling a flat-fee "Architectural Insurance" pipeline.
- **The Upsell Trigger:** Whenever the Gate blocks a garbage-code PR generated by a client's agent, it creates an immediate, highly qualified lead for your agency to execute the custom architecture securely.

---

## 🏗️ Architecture

```
                    Your Computer / Server
┌──────────────────────────────────────────────────┐
│                                                  │
│   CRM Webhook ──→ N8N ──→ AOS Gate ──→ Claude    │
│                            │    │        API     │
│                            │    │                │
│                         Logs  Dashboard          │
│                       (JSONL) (port 3101)        │
│                                                  │
└──────────────────────────────────────────────────┘
```

AOS Gate is a **transparent proxy**. It doesn't change your prompts or responses. It just records them and checks them against your rules before forwarding.

---

## 📁 Where Are the Logs?

Logs are stored as daily files inside the Docker volume. To access them:

```bash
# See today's log
docker exec aos-gate cat /data/logs/gate-$(date +%Y-%m-%d).jsonl

# Or copy all logs to your computer
docker cp aos-gate:/data/logs ./my-logs
```

You can also download logs directly from the **Export Logs** page in the dashboard as JSON or CSV.

---

## 🔧 Common Issues

### "Cannot connect to aos-gate from N8N"

Your N8N and AOS Gate need to be on the same Docker network. Add this to your N8N's `docker-compose.yml`:

```yaml
services:
  n8n:
    # ... your existing n8n config ...
    networks:
      - default
      - aos-gate_default

networks:
  aos-gate_default:
    external: true
```

Then restart N8N: `docker compose restart`

### "I changed policy.json but nothing happened"

Edit policy from the dashboard instead — changes apply immediately. If editing manually, restart the gate: `docker compose restart`

### "I want to stop AOS Gate"

```bash
cd aos-gate.com
docker compose down
```

Your N8N workflows will stop working until you either restart AOS Gate or change the URLs back to the original provider URLs.

### "I want to update AOS Gate"

```bash
cd aos-gate.com
git pull
docker compose up -d --build
```

---

## 🌐 AOS Ecosystem

| Site | Purpose |
|------|---------|
| [aos-governance.com](https://aos-governance.com) | The AOS Standard — technical specifications and policy responses |
| [aos-constitution.com](https://aos-constitution.com) | Constitutional governance framework and Humanitarian License |
| [aos-patents.com](https://aos-patents.com) | Full patent portfolio registry (101 USPTO filings) |
| [aos-evidence.com](https://aos-evidence.com) | Evidence preservation and validation |

---

## 📜 License

This software is licensed under the **AOS Humanitarian License v1.0.1**.

**You may** use this software freely for peaceful civilian purposes — personal projects, business operations, research, education.

**You may not** use this software for weapons, military applications, surveillance, exploitation, or any purpose that causes measurable harm to human welfare.

**Patent Notice:** This software implements standard proxy and audit patterns. Advanced AOS-patented methods (Deterministic Policy Gate, AOS Attest, Constitutional Governance Framework) are documented in the [AOS Standard](https://aos-governance.com) and available under separate licensing terms.

Full license text: [LICENSE](LICENSE)
Full license details: https://aos-constitution.com

---

## 👤 Attribution

Built by [Gene Salvatore](https://aos-governance.com) / AOS (Agentic Operating System)

- Standard: https://aos-governance.com
- Constitution: https://aos-constitution.com
- Patents: https://aos-patents.com
- Contact: gene@aos-governance.com
