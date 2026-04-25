# RAMPART

RAMPART is a prompt and tool-calling firewall for OpenAI-compatible API requests.

`RAMPART` stands for **Request And Model Prompt Analysis & Routing Tool**.

## Quick Start

Pull and run from GitHub Container Registry:

```bash
docker run -d -p 8080:8080 --name rampart ghcr.io/mulkeym/rampart:latest
```

Open `http://localhost:8080` and log in with `admin` / `password123`.

## Docker Deployment with Persistent Data

Mount volumes to persist configuration, API keys, and logs across container restarts:

```bash
mkdir -p /opt/rampart/{data,logs,policies}

docker run -d -p 8080:8080 -p 8443:8443 --name rampart \
  -v /opt/rampart/data:/app/data \
  -v /opt/rampart/logs:/app/logs \
  -v /opt/rampart/policies:/app/policies \
  ghcr.io/mulkeym/rampart:latest
```

| Port | Service | Purpose |
|------|---------|---------|
| `8080` | Main app (HTTP) | UI, API, playground, MCP, extension download |
| `8443` | Identity server (HTTPS/mTLS) | CAC-based extension enrollment (optional, requires certs in `data/certs/`) |

| Volume | Contents |
|--------|----------|
| `data/` | Admin credentials, API key store, runtime settings, groups, mTLS certs |
| `logs/` | Audit trail, violation/evaluation events |
| `policies/` | Policy YAML file |

## Docker Compose

```bash
docker compose up -d
```

Override settings with environment variables in a `.env` file or directly in
`docker-compose.yml`.

## Run without Docker

```bash
pip install .
uvicorn rampart.app.main:app --host 0.0.0.0 --port 8080
```

For development with auto-reload:

```bash
python3 -m uvicorn rampart.app.main:app --reload --host 0.0.0.0 --port 8080
```

## Local Admin Auth

By default, local auth seeds an initial admin account on first startup:

```text
username: admin
password: password123
```

The first login redirects to `/change-password` and requires a new password before
policy management is available. The updated local credential hash is stored in
`data/auth.json`.

For environment-managed credentials instead, generate a password hash:

```bash
python3 scripts/hash_password.py
```

Set local auth environment variables before starting the service:

```bash
export RAMPART_ADMIN_USERNAME=admin
export RAMPART_ADMIN_PASSWORD_HASH='pbkdf2_sha256$...'
export RAMPART_SESSION_SECRET='replace-with-a-long-random-secret'
```

When `RAMPART_ADMIN_PASSWORD_HASH` is set, password changes through the GUI are
disabled because the password is owned by the environment.

## Default Policies

RAMPART ships with 9 default policies covering the OWASP Top 10 for LLM Applications
and industry best practices:

| Policy | Severity | Action | Coverage |
|--------|----------|--------|----------|
| `no-credential-disclosure` | high | block | OWASP LLM06 — Sensitive Information Disclosure |
| `no-system-prompt-exfiltration` | high | block | OWASP LLM01 — Prompt Injection |
| `tool-allowlist` | medium | block | OWASP LLM07 — Insecure Plugin Design |
| `max-message-size` | medium | block | OWASP LLM04 — Model Denial of Service |
| `No-PII-Data` | high | block | OWASP LLM06 / GDPR / HIPAA |
| `prompt-injection-defense` | critical | block | OWASP LLM01 — Prompt Injection |
| `harmful-content` | high | block | NIST AI RMF / EU AI Act |
| `insecure-output` | high | block | OWASP LLM02 — Insecure Output Handling |
| `excessive-agency` | medium | warn | OWASP LLM08 — Excessive Agency |

Policies use a combination of deterministic checks (regex, tool allowlists, size limits)
and context-aware LLM evaluation. Add, edit, or disable policies through the admin UI
or MCP tools.

## Gateway Mode

`/v1/chat/completions` behaves like an OpenAI-compatible gateway:

- Accepted requests are forwarded to the upstream LLM
- Blocking policy violations return an OpenAI-compatible error
- Warn-only violations are forwarded using the sanitized request
- Per-client token usage is tracked (prompt/completion/total)

`/v1/rampart/evaluate` returns a RAMPART decision document without proxying.

## API Keys and Clients

Create customer/app API keys in the admin UI at `/ui/clients`. Each client can have:

- Assigned policies (subset of enabled policies)
- Custom upstream LLM endpoint override
- Token usage tracking (prompt, completion, total requests)

Use a generated key with the `Authorization` header:

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer rmp_live_..." \
  -H "content-type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}'
```

## Playground

The interactive playground at `/ui/playground` lets you:

- Compose multimodal messages (text + paste images directly)
- Select policies or create ad-hoc rules
- See per-policy pass/fail results with violation details
- View the sanitized request
- Optionally send to the upstream LLM and see the response

Policy results display immediately while the LLM response loads asynchronously.

## Vision Evaluator

RAMPART can evaluate image content against policies using a separate vision-capable
LLM. Configure the vision evaluator in Settings with its own endpoint and model.
When enabled, each image in a request is evaluated individually against applicable
LLM policies. Add `skip_vision: true` to any check to opt it out of image evaluation.

## MCP Server and Tool API

RAMPART exposes tools for LLM-driven administration via two interfaces:

**MCP (JSON-RPC):** `POST /mcp` — for MCP-compatible clients.

**REST Tool API:** `POST /v1/tools/{tool_name}` — individual endpoints per tool,
auto-discovered via OpenAPI at `/openapi.json`. Compatible with llama.cpp and other
OpenAI-compatible tool servers.

Enable in Settings:
1. Check **Enabled** under MCP Server
2. Generate an **Admin Key**
3. Optionally enable **Admin Write Access** for create/update/delete operations

### Available Tools

| Category | Tools |
|----------|-------|
| Policy Management | `list_policies`, `get_policy`, `create_policy`, `update_policy`, `delete_policy` |
| Client Management | `list_clients`, `get_client`, `create_client`, `update_client`, `delete_client`, `toggle_client`, `rotate_client_key` |
| Policy Assignment | `assign_policies` |
| Evaluation | `evaluate_prompt` |
| Monitoring | `get_violations` |

## Configuration

The service loads `policies/default.yaml` unless `RAMPART_POLICY_FILE` is set.
Runtime settings can be changed in the admin UI at `/ui/settings` and are persisted
to `data/settings.json`.

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `RAMPART_TLS_VERIFY` | Set to `false` to disable TLS certificate verification (for self-signed certs) |
| `RAMPART_POLICY_FILE` | Path to policy YAML file |
| `RAMPART_ADMIN_USERNAME` | Admin username (default: `admin`) |
| `RAMPART_ADMIN_PASSWORD_HASH` | Admin password hash (disables UI password changes) |
| `RAMPART_SESSION_SECRET` | Session signing secret |
| `RAMPART_AUDIT_LOG` | Audit log path |
| `RAMPART_MCP_ADMIN_KEY` | MCP admin API key |
| `RAMPART_UPSTREAM_ENABLED` | Enable/disable upstream LLM proxying |
| `RAMPART_UPSTREAM_BASE_URL` | Upstream LLM API base URL |
| `RAMPART_UPSTREAM_MODEL` | Override upstream model name |
| `RAMPART_UPSTREAM_API_KEY` | Upstream LLM API key |
| `RAMPART_LLM_EVALUATOR_BASE_URL` | Context analysis LLM endpoint |
| `RAMPART_LLM_EVALUATOR_MODEL` | Context analysis model name |
| `RAMPART_VISION_EVALUATOR_BASE_URL` | Vision evaluator LLM endpoint |
| `RAMPART_VISION_EVALUATOR_MODEL` | Vision evaluator model name |
| `RAMPART_TRACKING_ENABLED` | Enable/disable violation tracking |
| `RAMPART_EVALUATION_LOG` | Evaluation log path |
| `RAMPART_CLIENT_STORE` | Client store JSON path |
| `RAMPART_SETTINGS_FILE` | Runtime settings JSON path |
