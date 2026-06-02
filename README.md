# RAMPART

**Request And Model Prompt Analysis & Routing Tool**

A prompt and tool-calling firewall for OpenAI-compatible API requests.

## Quick Start

```bash
docker run -d -p 8080:8080 --name rampart ghcr.io/mulkeym/rampart:latest
```

Open `http://localhost:8080` and log in with `admin` / `admin`.

## Docker Deployment

```bash
mkdir -p /opt/rampart/{data,logs,policies}

docker run -d -p 8080:8080 --name rampart \
  -v /opt/rampart/data:/app/data \
  -v /opt/rampart/logs:/app/logs \
  -v /opt/rampart/policies:/app/policies \
  -e RAMPART_ADMIN_PASSWORD=changeme \
  -e RAMPART_SESSION_SECRET='replace-with-a-long-random-secret' \
  ghcr.io/mulkeym/rampart:latest
```

| Port | Service |
|------|---------|
| `8080` | Main app (UI, API, playground, MCP, extension) |
| `8443` | mTLS identity server (optional, CAC enrollment) |

| Volume | Contents |
|--------|----------|
| `data/` | Credentials, API keys, groups, settings, group mappings |
| `logs/` | Audit trail, evaluation events |
| `policies/` | Policy YAML definitions |

## Docker Compose

```yaml
services:
  rampart:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - rampart-data:/app/data
      - rampart-logs:/app/logs
      - ./policies:/app/policies
    environment:
      - RAMPART_ADMIN_PASSWORD=changeme
      - RAMPART_SESSION_SECRET=replace-with-a-long-random-secret
    restart: unless-stopped

volumes:
  rampart-data:
  rampart-logs:
```

```bash
docker compose up -d
```

## Run Without Docker

```bash
pip install .
uvicorn rampart.app.main:app --host 0.0.0.0 --port 8080
```

## Authentication

RAMPART supports three authentication methods. They can be used simultaneously.

### Local Password (Default)

Default credentials: `admin` / `admin`

Set a custom password via environment variable:

```bash
RAMPART_ADMIN_PASSWORD=yourpassword
```

Or use a pre-hashed password for security-hardened deployments:

```bash
RAMPART_ADMIN_PASSWORD_HASH='pbkdf2_sha256$...'
```

Password can also be changed in the admin UI under Settings > Admin Password (when env vars are not set).

**Priority:** `RAMPART_ADMIN_PASSWORD` > `RAMPART_ADMIN_PASSWORD_HASH` > `data/auth.json` > default `admin/admin`

### Keycloak SSO (OIDC)

Enable Keycloak OIDC login for the admin UI. When enabled, a "Login with Keycloak" button appears on the login page alongside local password auth.

Configure in the admin UI under Settings > Keycloak Admin Authentication, or via environment variables:

```bash
RAMPART_KC_ADMIN_BASE_URL=https://keycloak.example.com
RAMPART_KC_ADMIN_REALM=dha
RAMPART_KC_ADMIN_CLIENT_ID=rampart-admin
RAMPART_KC_ADMIN_CLIENT_SECRET=your-client-secret
RAMPART_KC_ADMIN_VERIFY_SSL=false  # for self-signed certs
```

**Keycloak client setup:**
- Client Type: OpenID Connect
- Client Authentication: ON (confidential)
- Authentication Flow: Standard flow (Authorization Code)
- Valid Redirect URIs: `https://<rampart-host>/auth/keycloak/callback`
- Scopes: `openid email profile`

The admin UI Settings page includes a detailed setup guide.

### CAC/mTLS Identity (Extension Enrollment)

For DoD/Gov environments with CAC/PIV smart cards. Used during browser extension enrollment, not admin UI login. Requires certificates in `data/certs/` and port 8443.

## Default Policies

RAMPART ships with policies covering the OWASP Top 10 for LLM Applications:

| Policy | Severity | Action | Coverage |
|--------|----------|--------|----------|
| `no-credential-disclosure` | high | block | OWASP LLM06 - Sensitive Information Disclosure |
| `no-system-prompt-exfiltration` | high | block | OWASP LLM01 - Prompt Injection |
| `tool-allowlist` | medium | block | OWASP LLM07 - Insecure Plugin Design |
| `max-message-size` | medium | block | OWASP LLM04 - Model Denial of Service |
| `No-PII-Data` | high | block | OWASP LLM06 / GDPR / HIPAA |
| `prompt-injection-defense` | critical | block | OWASP LLM01 - Prompt Injection |
| `harmful-content` | high | block | NIST AI RMF / EU AI Act |
| `insecure-output` | high | block | OWASP LLM02 - Insecure Output Handling |
| `excessive-agency` | medium | warn | OWASP LLM08 - Excessive Agency |

Policies use deterministic checks (regex, tool allowlists, size limits) and context-aware LLM evaluation. Manage through the admin UI or MCP tools.

## User Identity and Group-Based Policies

RAMPART can evaluate prompts differently based on who the user is, using an external identity provider (Keycloak, with future support for PingFederate and AD/LDAP).

**How it works:**
1. The `user` field in the OpenAI request (e.g. `"user": "jsmith@dha.mil"`) identifies the end user
2. RAMPART looks up the user's groups in the identity provider (cached with configurable TTL)
3. External groups are mapped to RAMPART groups via the Group Mappings admin page
4. The union of all matched groups' policies is used for evaluation

**Policy resolution precedence:**
1. User group resolution (if enabled and matches) - replaces API key baseline
2. Client's assigned group policies
3. Client's directly assigned policies
4. All enabled policies (fallback)

Configure in Settings > User Group Resolver. Manage mappings at `/ui/group-mappings`.

## Prompt Log and Syslog

All prompt evaluations are logged to an in-memory ring buffer (10,000 entries) viewable at `/ui/prompt-log`. Each entry includes:
- Full prompt content, user identity, client ID
- Resolved external groups and mapped RAMPART groups
- Per-policy pass/fail results with violation messages
- Source (api, gateway, playground), timing

### Syslog / Splunk Forwarding

Enable CEF syslog forwarding in Settings > Syslog Forwarder. Three event types:

| Event | CEF ID | Description |
|-------|--------|-------------|
| Prompt Evaluation | `prompt-eval` | Full prompt evaluation with policies (polled) |
| Admin Audit | `audit` | Login, settings changes, CRUD actions (immediate) |
| Evaluation Tracking | `eval-track` | Decision and violations per request (immediate) |

```bash
RAMPART_SYSLOG_ENABLED=true
RAMPART_SYSLOG_HOST=splunk.example.com
RAMPART_SYSLOG_PORT=514
RAMPART_SYSLOG_PROTOCOL=udp  # or tcp
```

## Gateway Mode

`/v1/chat/completions` - OpenAI-compatible gateway. Accepted requests are forwarded to the upstream LLM. Blocking violations return an OpenAI-compatible error.

`/v1/rampart/evaluate` - Returns a RAMPART decision document without proxying.

## API Keys and Clients

Create API keys in the admin UI at `/ui/clients`. Each client can be assigned to a group (inherits group policies) or have directly assigned policies. Custom upstream LLM overrides per client.

```bash
curl http://localhost:8080/v1/rampart/evaluate \
  -H "Authorization: Bearer rmp_live_..." \
  -H "Content-Type: application/json" \
  -d '{"request":{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}],"user":"jsmith@example.com"}}'
```

## Playground

The interactive playground at `/ui/playground` supports three test scenarios:

- **Prompt Evaluation** - Compose messages with images, set user identity
- **Tool Call Test** - Test tool names against allowlist/denylist policies
- **Raw JSON** - Edit a complete OpenAI request with pre-populated template

Select a client from the "Test as Client" dropdown to evaluate using that client's exact policy set.

## Browser Extension

Chrome and Firefox extension that intercepts prompts on AI chat sites, evaluates them against policies, and blocks violations.

**Supported sites:** ChatGPT, Claude, Gemini, Ask Sage

Setup: `/ui/extension` > Download Extension > Load in browser > Enroll with group key or API key.

## MCP Server

Tools for LLM-driven administration via JSON-RPC (`POST /mcp`) or REST (`POST /v1/tools/{tool_name}`).

Enable in Settings > MCP Server. Available tools: policy CRUD, client CRUD, group CRUD, group mapping CRUD, prompt evaluation, violation monitoring.

## Backup and Restore

Download a complete backup of all configs, policies, and logs from Settings > Backup & Restore. Upload a previous backup to restore. Both actions are audit logged.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| **Auth** | |
| `RAMPART_ADMIN_PASSWORD` | Admin password (plaintext, simplest) |
| `RAMPART_ADMIN_PASSWORD_HASH` | Admin password hash (pre-hashed) |
| `RAMPART_ADMIN_USERNAME` | Admin username (default: `admin`) |
| `RAMPART_SESSION_SECRET` | Session signing secret (auto-generated if not set) |
| **Keycloak Admin Auth** | |
| `RAMPART_KC_ADMIN_BASE_URL` | Keycloak server URL |
| `RAMPART_KC_ADMIN_REALM` | Keycloak realm |
| `RAMPART_KC_ADMIN_CLIENT_ID` | OIDC client ID |
| `RAMPART_KC_ADMIN_CLIENT_SECRET` | OIDC client secret |
| `RAMPART_KC_ADMIN_VERIFY_SSL` | SSL verification (default: `true`) |
| **User Group Resolver** | |
| `RAMPART_KEYCLOAK_BASE_URL` | Keycloak URL for user group lookup |
| `RAMPART_KEYCLOAK_REALM` | Keycloak realm for user groups |
| `RAMPART_KEYCLOAK_CLIENT_ID` | Service account client ID |
| `RAMPART_KEYCLOAK_CLIENT_SECRET` | Service account client secret |
| **Upstream LLM** | |
| `RAMPART_UPSTREAM_ENABLED` | Enable/disable upstream proxying |
| `RAMPART_UPSTREAM_BASE_URL` | Upstream LLM API base URL |
| `RAMPART_UPSTREAM_MODEL` | Override upstream model name |
| `RAMPART_UPSTREAM_API_KEY` | Upstream LLM API key |
| **LLM Evaluators** | |
| `RAMPART_LLM_EVALUATOR_BASE_URL` | Context analysis LLM endpoint |
| `RAMPART_LLM_EVALUATOR_MODEL` | Context analysis model name |
| `RAMPART_VISION_EVALUATOR_BASE_URL` | Vision evaluator endpoint |
| `RAMPART_VISION_EVALUATOR_MODEL` | Vision evaluator model name |
| **Syslog** | |
| `RAMPART_SYSLOG_ENABLED` | Enable syslog forwarding |
| `RAMPART_SYSLOG_HOST` | Syslog server host |
| `RAMPART_SYSLOG_PORT` | Syslog server port |
| `RAMPART_SYSLOG_PROTOCOL` | `udp` or `tcp` |
| **Other** | |
| `RAMPART_TLS_VERIFY` | Disable TLS verification (`false`) |
| `RAMPART_POLICY_FILE` | Path to policy YAML |
| `RAMPART_TRACKING_ENABLED` | Enable/disable evaluation tracking |
| `RAMPART_EVALUATION_LOG` | Evaluation log path |
| `RAMPART_AUDIT_LOG` | Audit log path |
