# 🚪 AOS Gate

**A simple logging proxy that sits between your AI automation tool and the AI provider.**

Every time your automation (N8N, Make, Zapier, custom scripts) calls an AI model, AOS Gate logs the exchange — what you sent, what came back, how long it took, and whether any sensitive data was in the request. It also gives you a dashboard to see everything at a glance.

**Think of it like a security camera for your AI calls.** It doesn't change what the AI does — it just makes sure you have a record of everything.

Licensed under the [AOS Humanitarian License v1.0.1](LICENSE) — peaceful civilian use only.

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
git clone https://github.com/genesalvatore/aos-gate.git
cd aos-gate
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

You should see the **AOS Gate Dashboard** — a dark screen showing "0 events". This is your audit log. It's empty because nothing has gone through the gate yet.

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

## ⚙️ Customizing the Rules (Optional)

AOS Gate comes with a `policy.json` file. You can edit this to add your own rules.

### Restrict Which AI Models Can Be Used

Open `policy.json` and edit the `allowedModels` list:

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

After editing `policy.json`, restart AOS Gate:

```bash
docker compose restart
```

---

## 📊 Reading the Dashboard

Open `http://localhost:3101` in your browser.

| Color | Meaning |
|---|---|
| 🟢 Green (PASSED) | Call went through normally |
| 🔴 Red (BLOCKED) | Call was blocked by a policy rule |
| 🟡 Yellow (PII_WARNING) | Sensitive data detected (SSN, credit card, email, phone) |
| 🟠 Orange (ERROR) | Something went wrong connecting to the AI provider |

---

## 📁 Where Are the Logs?

Logs are stored as daily files inside the Docker volume. To access them:

```bash
# See today's log
docker exec aos-gate cat /data/logs/gate-$(date +%Y-%m-%d).jsonl

# Or copy all logs to your computer
docker cp aos-gate:/data/logs ./my-logs
```

Each line in the log file is a JSON object. You can open them in any text editor or import them into a spreadsheet.

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

Restart the gate: `docker compose restart`

### "I want to stop AOS Gate"

```bash
cd aos-gate
docker compose down
```

Your N8N workflows will stop working until you either restart AOS Gate or change the URLs back to the original provider URLs.

### "I want to update AOS Gate"

```bash
cd aos-gate
git pull
docker compose up -d --build
```

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

## 📜 License

This software is licensed under the **AOS Humanitarian License v1.0.1**.

**You may** use this software freely for peaceful civilian purposes — personal projects, business operations, research, education.

**You may not** use this software for weapons, military applications, surveillance, exploitation, or any purpose that causes measurable harm to human welfare.

**Patent Notice:** This software is a standard API proxy. It does not implement any AOS-patented methods (Deterministic Policy Gate, AOS Attest, Constitutional Governance Framework, etc.). Use of this software does not grant rights under any AOS patents.

Full license text: [LICENSE](LICENSE)
Full license details: https://aos-constitution.com

---

## 👤 Attribution

Built by [Gene Salvatore](https://aos-governance.com) / AOS (Agentic Operating System)

- Website: https://aos-governance.com
- Constitution: https://aos-constitution.com
- Patents: https://aos-patents.com
