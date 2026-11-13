# AgentGuard User Manual

> **Note (0.2.0):** the dashboard is now the main way to use AgentGuard. See [README.md](README.md) for the dashboard flow. The command reference below still applies to the manual CLI path.


Welcome to **AgentGuard**, an automated red-teaming and vulnerability assessment tool designed specifically for AI agents and LLM-powered applications. 

This manual guides you through installing AgentGuard, instrumenting your AI agents, running security scans, and interpreting vulnerability reports on your local machine.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Installation & Setup](#2-installation--setup)
3. [Configuring LLM Providers](#3-configuring-llm-providers)
4. [Quickstart Tutorial (Run a Sample Agent)](#4-quickstart-tutorial-run-a-sample-agent)
5. [Instrumenting Your Own Agent](#5-instrumenting-your-own-agent)
6. [CLI Reference & Commands](#6-cli-reference--commands)
7. [Understanding the Output Reports](#7-understanding-the-output-reports)
8. [Attack Vectors Covered](#8-attack-vectors-covered)
9. [Configuration Reference](#9-configuration-reference)
10. [Troubleshooting & FAQ](#10-troubleshooting--faq)

---

## 1. System Requirements

- **Operating System:** Linux, macOS, or Windows 10/11
- **Python:** Version `3.10`, `3.11`, or `3.12`
- **Git:** Installed and available in your terminal
- **LLM API Key:** At least one API key from a supported provider (free-tier options available from Groq, Cohere, or Google AI Studio).

---

## 2. Installation & Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/<your-username>/agentguard.git
cd agentguard
```

### Step 2: Create a Virtual Environment

It is strongly recommended to use an isolated Python virtual environment:

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### Step 3: Install AgentGuard

Install AgentGuard in editable mode with all dependencies:

```bash
pip install -e .
```

Verify that the CLI is accessible:

```bash
agentguard --help
```

---

## 3. Configuring LLM Providers

AgentGuard uses LLMs to dynamically generate attack sequences and synthesize security remediation reports.

### Step 1: Create your `.env` file

Copy the provided template to create your local `.env`:

```bash
# Linux / macOS
cp .env.example .env

# Windows
copy .env.example .env
```

### Step 2: Add your API keys

Open `.env` in any text editor and supply your API key(s). Free tiers are available:

- **Groq** (Fastest inference & generous free tier): [https://console.groq.com](https://console.groq.com)
- **Cohere** (Free trial available): [https://dashboard.cohere.com](https://dashboard.cohere.com)
- **Google Gemini** (Free AI Studio keys): [https://aistudio.google.com](https://aistudio.google.com)

Example `.env` configuration:

```env
GROQ_API_KEY=gsk_your_groq_api_key_here
COHERE_API_KEY=your_cohere_key_here

# Recommended high-throughput models:
AGENTGUARD_ATTACKER_MODEL=groq/openai/gpt-oss-20b
AGENTGUARD_REPORTER_MODEL=cohere/command-r-08-2024
AGENTGUARD_CHAT_MODEL=groq/openai/gpt-oss-20b
```

*(You can also use OpenAI, Anthropic, or local Ollama models. See [Configuration Reference](#9-configuration-reference) below).*

---

## 4. Quickstart Tutorial (Run a Sample Agent)

AgentGuard comes bundled with pre-built vulnerable agents in the `samples/` directory so you can test the entire workflow immediately.

### Step 1: Start the Vulnerable Target

Open your first terminal window, activate your virtual environment, and launch the `unsafe_tool` sample application:

```bash
uvicorn samples.unsafe_tool.app:app --host 127.0.0.1 --port 8000
```

You should see Uvicorn running at `http://127.0.0.1:8000`.

### Step 2: Run AgentGuard Red-Teaming

Open a second terminal window, activate your virtual environment, and run:

```bash
agentguard -v test samples/unsafe_tool --target-url http://127.0.0.1:8000 --max-probes 3
```

### Step 3: Review Results

Once complete, AgentGuard outputs:
1. `findings.json` — Raw attack transcripts and side-effect tool logs.
2. `report.md` — Complete vulnerability scorecard and remediation patches.

Open `report.md` to see the detected vulnerabilities, CVSS risk ratings, and suggested code fixes!

---

## 5. Instrumenting Your Own Agent

To red-team your own AI agent, AgentGuard provides a lightweight adapter via two decorators: `@expose` and `@watch`.

### Step 1: Add decorators to your code

```python
# your_agent.py
from agentguard import expose, watch

# 1. @watch observes critical functions, tool calls, and side-effects.
# Any call to a watched function will be logged with arguments during attack runs.
@watch
def execute_system_command(cmd: str):
    import subprocess
    return subprocess.check_output(cmd, shell=True, text=True)

@watch
def database_query(query: str):
    # Simulated database lookup
    return f"Results for: {query}"

# 2. @expose wraps your agent's primary message handler.
# It automatically provides a standard POST /invoke endpoint.
@expose
def handle_message(prompt: str, session_id: str = None) -> str:
    # Your agent reasoning / LLM invocation loop goes here
    if "run:" in prompt:
        cmd = prompt.replace("run:", "").strip()
        return execute_system_command(cmd)
    return f"Processed: {prompt}"
```

### Step 2: Expose the agent via FastAPI

Create a minimal FastAPI server:

```python
# main.py
from fastapi import FastAPI
from agentguard.adapter import router
import your_agent # imports handle_message decorated with @expose

app = FastAPI(title="My Protected Agent")
app.include_router(router)
```

Run your agent:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

AgentGuard will now communicate with your agent at `POST http://127.0.0.1:8000/invoke`.

---

## 6. CLI Reference & Commands

The AgentGuard CLI provides three core commands:

### `agentguard init <source_dir>`

Performs a pre-flight static analysis of your agent repository.

- Inspects the code AST without executing it.
- Extracts system prompts, declared tools, and model definitions.
- Generates a local `manifest.yaml` describing your agent's attack surface.

```bash
agentguard init path/to/my_agent
```

---

### `agentguard test <source_dir> [OPTIONS]`

Executes an adaptive dynamic red-teaming assessment against your live agent.

**Syntax:**
```bash
agentguard test <source_dir> [OPTIONS]
```

**Common Options:**
| Option | Description | Default |
|---|---|---|
| `--target-url TEXT` | HTTP URL of the running target agent | `http://127.0.0.1:8000` |
| `--max-probes INTEGER` | Maximum probe attempts per attack category | `5` |
| `--categories TEXT` | Comma-separated list of categories to test | All 7 categories |
| `--output-dir PATH` | Directory to save `findings.json` and `report.md` | Current directory |
| `-v, --verbose` | Enable verbose/debug logs | Disabled |
| `-q, --quiet` | Suppress non-error logs | Disabled |

**Examples:**
```bash
# Run a quick 3-probe test with verbose logging
agentguard -v test my_agent --target-url http://127.0.0.1:8000 --max-probes 3

# Test only prompt leak and insecure tool calling
agentguard test my_agent --categories prompt_leak,insecure_tool
```

---

### `agentguard report <source_dir> [OPTIONS]`

Regenerates the human-readable markdown report from an existing `findings.json` without re-running any network attacks. Useful if you want to update analysis or apply new remediation prompts.

```bash
agentguard report path/to/my_agent --findings findings.json --output report.md
```

---

## 7. Understanding the Output Reports

AgentGuard produces two primary outputs:

### 1. `findings.json` (Machine-Readable Artifact)
Contains the exact JSON record of the test execution:
- Attack session metadata and timestamps.
- Multi-turn probe inputs sent by the attacker LLM.
- Raw target responses.
- Captured `@watch` tool calls (e.g. arguments passed to destructive functions).
- Oracle verification results (`canary_leak`, `side_effect_detected`, `judge_verdict`).

### 2. `report.md` (Human-Readable Vulnerability Report)
A structured security audit report featuring:
- **Executive Summary:** Overview of tests run, number of successful exploits, and overall risk posture.
- **Risk Scorecard:** Tabular breakdown of tested categories, severity (CRITICAL, HIGH, MEDIUM, LOW), and exploit status.
- **Vulnerability Deep Dives:** For each exploit:
  - Exact attack transcript that bypassed defenses.
  - Evidence of compromise (tool calls or leaked confidential strings).
  - Semantic source code context retrieved from your repository.
  - Concrete remediation recommendations (e.g. prompt guardrails, input sanitation, tool sandboxing).
- **Appendix:** Failed probe attempts and agent defensive refusals.

---

## 8. Attack Vectors Covered

AgentGuard ships with specialized attack playbooks covering the OWASP Top 10 for LLM Applications:

1. **`prompt_leak`**: Attempts to trick the agent into disclosing its system instructions, internal architecture, and confidential secrets.
2. **`insecure_tool`**: Probes for arbitrary code execution, command injection, and unsanitized parameters passed into execution tools.
3. **`prompt_injection`**: Evaluates susceptibility to direct and indirect jailbreaks that override system safety boundaries.
4. **`data_exfiltration`**: Tests if an attacker can coerce the agent into leaking sensitive internal data to external web endpoints.
5. **`privilege_escalation`**: Attempts to bypass role checks to execute administrative actions or restricted tools.
6. **`memory_poisoning`**: Tests whether multi-turn conversational context can be manipulated into storing false or malicious instructions.
7. **`hallucination`**: Verifies agent factual grounding when pressured with contradictory or fabricated facts.

---

## 9. Configuration Reference

AgentGuard settings can be customized via environment variables in your `.env` file or exported in your shell:

### LLM Model Configuration
| Variable | Description | Example |
|---|---|---|
| `AGENTGUARD_ATTACKER_MODEL` | Model used to generate attack probes | `groq/openai/gpt-oss-20b` |
| `AGENTGUARD_REPORTER_MODEL` | Model used for security report generation | `cohere/command-r-08-2024` |
| `AGENTGUARD_CHAT_MODEL` | Fallback model used for judge evaluations | `groq/openai/gpt-oss-20b` |

*Any model string supported by LiteLLM can be used (e.g., `openai/gpt-4o-mini`, `anthropic/claude-3-5-haiku-20241022`, `ollama/llama3`).*

### Execution Tuning
| Variable | Description | Default |
|---|---|---|
| `AGENTGUARD_PROBE_DELAY_SECONDS` | Delay in seconds between individual probes | `0.5` |
| `AGENTGUARD_CATEGORY_COOLDOWN` | Cooldown in seconds between attack categories | `2.0` |
| `AGENTGUARD_TIMEOUT_SECONDS` | HTTP request timeout for target calls | `30.0` |

---

## 10. Troubleshooting & FAQ

### Q: Why do I get a connection error when running `agentguard test`?
**A:** Ensure your target agent application is actively running and listening on the URL passed to `--target-url`. Test it manually by sending a request:
```bash
curl -X POST http://127.0.0.1:8000/invoke -H "Content-Type: application/json" -d "{\"input\": \"ping\"}"
```

### Q: I received a `429 Rate Limit` or quota error from my LLM provider.
**A:** AgentGuard automatically retries transient rate limits with exponential backoff. If you hit a daily quota cap:
1. Switch to another provider or model in `.env` (e.g. switch between Groq and Cohere).
2. Reduce `--max-probes` (e.g. `--max-probes 2` or `--max-probes 3`).
3. Test a subset of categories using `--categories prompt_leak,insecure_tool`.

### Q: Can I run AgentGuard completely offline with local models?
**A:** Yes! Install [Ollama](https://ollama.ai) and pull a model like `llama3`. Then configure your `.env`:
```env
AGENTGUARD_ATTACKER_MODEL=ollama/llama3
AGENTGUARD_REPORTER_MODEL=ollama/llama3
AGENTGUARD_CHAT_MODEL=ollama/llama3
```

### Q: How do I run the internal unit tests?
**A:** To run the test suite:
```bash
pytest
```
All 39 unit tests will execute and verify the adapter, attackers, ratelimiter, reporters, and configuration engine.
