# RAMPART Architecture Diagrams

## 1. Network Flow Diagram

```
                                    RAMPART NETWORK ARCHITECTURE
 ============================================================================================================

  BROWSER (End User Workstation)                          RAMPART SERVER (Docker)
 +------------------------------------------+            +----------------------------------------------+
 |                                           |            |                                              |
 |  +------------------+                     |            |  :8080 (HTTP)  FastAPI + Uvicorn (4 workers)  |
 |  |  Browser Plugin  |                     |            | +------------------------------------------+ |
 |  |  (Chrome/Firefox) |                     |            | |                                          | |
 |  |                  |                     |            | |  +-----------+    +-----------+           | |
 |  |  +-----------+   |                     |            | |  | /v1/enroll|    | /v1/ext/  |           | |
 |  |  |  popup.js |---+----- enrollment ----+-- POST ---+->  | Enrollment|    |  config   |           | |
 |  |  +-----------+   |     /v1/enroll      |            | |  +-----------+    +-----------+           | |
 |  |                  |                     |            | |                                          | |
 |  |  +-----------+   |                     |            | |  +----------------------------------+    | |
 |  |  |background |   |                     |            | |  | /v1/rampart/evaluate             |    | |
 |  |  |   .js     |<--+--- site configs ----+-- GET ----+->  |   Policy Evaluation Endpoint     |    | |
 |  |  +-----------+   |   /v1/extension/    |            | |  +----------------------------------+    | |
 |  |       |          |     config          |            | |                  |                       | |
 |  |       v          |                     |            | |                  v                       | |
 |  |  +-----------+   |                     |            | |  +----------------------------------+    | |
 |  |  | bridge.js |   |                     |            | |  |        PolicyEngine              |    | |
 |  |  +-----------+   |                     |            | |  |  +----------+ +------+ +-------+ |    | |
 |  |       |          |                     |            | |  |  |Determin- | | LLM  | |Vision | |    | |
 |  |       v          |                     |            | |  |  |istic     | | Eval | | Eval  | |    | |
 |  |  +-----------+   |                     |            | |  |  +----------+ +------+ +-------+ |    | |
 |  |  |content.js |---+----- evaluate ------+-- POST ---+->  +----------------------------------+    | |
 |  |  +-----------+   |  /v1/rampart/       |            | |                                          | |
 |  |       |          |    evaluate         |            | |  +----------------------------------+    | |
 |  |       v          |                     |            | |  | /v1/chat/completions             |    | |
 |  |  +-----------+   |                     |            | |  |   OpenAI-Compatible Gateway      |----+->--+
 |  |  | Violation |   |                     |            | |  +----------------------------------+    | |  |
 |  |  | Overlay   |   |                     |            | |                                          | |  |
 |  |  +-----------+   |                     |            | |  +----------------------------------+    | |  |
 |  +------------------+                     |            | |  | /ui/*   Admin Dashboard          |    | |  |
 |                                           |            | |  |  - /ui/policies                  |    | |  |
 |  +------------------+                     |            | |  |  - /ui/clients                   |    | |  |
 |  |  Admin Browser   |--- session auth ----+-- HTTPS --+->  |  - /ui/groups                    |    | |  |
 |  +------------------+                     |            | |  |  - /ui/playground                |    | |  |
 |                                           |            | |  |  - /ui/violations                |    | |  |
 +------------------------------------------+            | |  +----------------------------------+    | |  |
                                                          | |                                          | |  |
  MCP CLIENT (Programmatic)                               | |  +----------------------------------+    | |  |
 +------------------------------------------+            | |  | /mcp   JSON-RPC 2.0              |    | |  |
 |  Claude Code / AI Agent / Script         |            | |  |   27 management tools            |    | |  |
 |                                          |-- Bearer --+->  +----------------------------------+    | |  |
 |  Tools: list/create/update/delete        |   token    |            | |                              | |  |
 |  policies, clients, groups               |            | +----------+-+------- :8080 ---------------+ |  |
 +------------------------------------------+            |            |                                  |  |
                                                          | +----------+---------- :8443 (mTLS) ------+ |  |
                                                          | | Identity Server (optional)               | |  |
  CAC-ENABLED BROWSER                                     | |  /whoami  - X.509 cert extraction        | |  |
 +------------------------------------------+            | |  /nonce   - challenge-response auth       | |  |
 |  DoD / Gov Workstation with CAC          |-- mTLS ---+->  +-------------------------------------+  | |  |
 +------------------------------------------+            | +------------------------------------------+ |  |
                                                          +----------------------------------------------+  |
                                                                                                             |
                  +------------------------------------------------------------------------------------------+
                  |
                  v
  EXTERNAL SERVICES
 +============================================================================================================+
 |                                                                                                            |
 |  +-------------------------+   +-----------------------------+   +------------------------------+           |
 |  | Upstream LLM            |   | LLM Evaluator               |   | Vision Evaluator             |           |
 |  | (OpenAI / Azure / etc.) |   | (Granite Guardian / GPT-4)  |   | (GPT-4 Vision / LLaVA)      |           |
 |  |                         |   |                             |   |                              |           |
 |  | Receives proxied        |   | Receives prompt text        |   | Receives base64 images       |           |
 |  | chat/completions after  |   | Returns: violates (bool)    |   | Returns: violates (bool)     |           |
 |  | policy approval         |   |          message (str)      |   |          message (str)       |           |
 |  |                         |   |          confidence (float)  |   |                              |           |
 |  +-------------------------+   +-----------------------------+   +------------------------------+           |
 |                                                                                                            |
 +============================================================================================================+

  DATA LAYER (Docker Volume: rampart-data)
 +============================================================================================================+
 |                                                                                                            |
 |  +----------------+  +---------------+  +--------------+  +--------------+  +--------------+               |
 |  | clients.json   |  | groups.json   |  | sites.json   |  | settings.json|  | auth.json    |               |
 |  | API keys,      |  | Enrollment    |  | Site extract  |  | Runtime      |  | Admin creds  |               |
 |  | client config  |  | keys, policy  |  | patterns for  |  | overrides    |  | (PBKDF2)     |               |
 |  | (PBKDF2 hash)  |  | assignments   |  | ChatGPT,     |  |              |  |              |               |
 |  |                |  |               |  | Sage, etc.   |  |              |  |              |               |
 |  +----------------+  +---------------+  +--------------+  +--------------+  +--------------+               |
 |                                                                                                            |
 |  +-----------------------+  +-----------------------+  +-------------------------+                         |
 |  | policies/default.yaml |  | logs/evaluations.jsonl|  | logs/audit.jsonl        |                         |
 |  | OWASP LLM Top 10      |  | Prompt eval events    |  | Admin action trail      |                         |
 |  | policy definitions     |  | (append-only)         |  | (append-only)           |                         |
 |  +-----------------------+  +-----------------------+  +-------------------------+                         |
 |                                                                                                            |
 +============================================================================================================+


  IN-MEMORY CACHES (per-worker, ephemeral)
 +============================================================================================================+
 |  Evaluation Cache (TTL: 5min, max: 1000)  |  Nonce Store (TTL: 2min)  |  Discovery Buffer (100/client)    |
 +============================================================================================================+
```

---

## 2. Logical Process Diagram: Browser Plugin Evaluation Flow

```
  USER ACTION                         BROWSER EXTENSION                              RAMPART SERVER
 ====================================================================================================

  User visits AI chat site
  (chatgpt.com, claude.ai,
   asksage.com, gemini)
        |
        v
  +----------------+
  | Page loads      |
  +----------------+
        |
        v                       +---------------------------+
                                | bridge.js injects into    |
                                | page via <script> tag     |
                                +---------------------------+
                                            |
                                            v
                                +---------------------------+
                                | content.js activates      |
                                | Fetches site configs:     |
                                |  GET /v1/extension/config |------------------------------->  Resolve client
                                |                           |<-------------------------------  Return site patterns
                                | Stores extraction rules   |                                  + discovery status
                                | per matched hostname      |
                                +---------------------------+
                                            |
                                            v
                                +---------------------------+
                                | Hooks into page:          |
                                |  - Overrides fetch()      |
                                |  - Overrides XMLHttpReq   |
                                |  - Monitors clipboard     |
                                |    paste events           |
                                |  - Monitors drag/drop     |
                                |    image events           |
                                +---------------------------+
                                            |
                                            | (waits for user action)
                                            |
  User types prompt            +---------------------------+
  and clicks "Send"            | Intercepted!              |
        |  ------------------>  | fetch() or XHR trapped    |
        |                       +---------------------------+
        |                                   |
        |                                   v
        |                       +---------------------------+
        |                       | EXTRACT PROMPT            |
        |                       |                           |
        |                       | Site-specific rules:      |
        |                       |  ChatGPT:                 |
        |                       |   messages[0].content     |
        |                       |     .parts[0]             |
        |                       |  Ask Sage:                |
        |                       |   JSON[].message          |
        |                       |  Gemini:                  |
        |                       |   FormData f.req parse    |
        |                       |  Claude:                  |
        |                       |   body.prompt             |
        |                       +---------------------------+
        |                                   |
        |                                   v
        |                       +---------------------------+
        |                       | EXTRACT IMAGES            |
        |                       |  - Pasted images (base64) |
        |                       |  - Dropped images (base64)|
        |                       |  - Inline image URLs      |
        |                       +---------------------------+
        |                                   |
        |                                   v
        |                       +---------------------------+
        |                       | BUILD EVALUATION REQUEST  |
        |                       | {                         |
        |                       |   "request": {            |
        |                       |     "model": "<detected>",|
        |                       |     "messages": [{        |
        |                       |       "role": "user",     |
        |                       |       "content": "<text>" |
        |                       |     }]                    |
        |                       |   }                       |
        |                       | }                         |
        |                       +---------------------------+
        |                                   |
        |                                   | POST /v1/rampart/evaluate
        |                                   | Authorization: Bearer <api_key>
        |                                   |
        |                                   v
        |                                                       +================================+
        |                                                       |  RAMPART EVALUATION PIPELINE   |
        |                                                       +================================+
        |                                                                      |
        |                                                                      v
        |                                                       +------------------------------+
        |                                                       | 1. RESOLVE CLIENT            |
        |                                                       |    - Match Bearer token      |
        |                                                       |      against key_hash store  |
        |                                                       |    - Check client.enabled    |
        |                                                       |    - Update last_used_at     |
        |                                                       +------------------------------+
        |                                                                      |
        |                                                                      v
        |                                                       +------------------------------+
        |                                                       | 2. RESOLVE POLICIES          |
        |                                                       |                              |
        |                                                       |  client.group_id set?        |
        |                                                       |    YES -> group.policy_ids   |
        |                                                       |    NO  -> client.policy_ids  |
        |                                                       |    NONE -> all enabled       |
        |                                                       +------------------------------+
        |                                                                      |
        |                                                                      v
        |                                                       +------------------------------+
        |                                                       | 3. DETERMINISTIC CHECKS      |
        |                                                       |    (fast, synchronous)        |
        |                                                       |                              |
        |                                                       |  For each policy.check:      |
        |                                                       |    +------------------------+|
        |                                                       |    | regex: scan all message||
        |                                                       |    |   content for patterns  ||
        |                                                       |    +------------------------+|
        |                                                       |    | max_chars: check total  ||
        |                                                       |    |   message length        ||
        |                                                       |    +------------------------+|
        |                                                       |    | tool_allowlist: verify  ||
        |                                                       |    |   requested tools       ||
        |                                                       |    +------------------------+|
        |                                                       |    | tool_denylist: block    ||
        |                                                       |    |   forbidden tools       ||
        |                                                       |    +------------------------+|
        |                                                       |    | model_allowlist: verify ||
        |                                                       |    |   requested model       ||
        |                                                       |    +------------------------+|
        |                                                       |                              |
        |                                                       |  Blocking violation found?   |
        |                                                       |    YES -> FAIL FAST          |
        |                                                       |    NO  -> continue           |
        |                                                       +------------------------------+
        |                                                              |               |
        |                                                              | (parallel)    |
        |                                                       +------v------+ +------v------+
        |                                                       | 4a. LLM     | | 4b. VISION  |
        |                                                       | EVALUATION  | | EVALUATION  |
        |                                                       |             | |             |
        |                                                       | For each    | | For each    |
        |                                                       | policy with | | image in    |
        |                                                       | type: llm   | | request:    |
        |                                                       |             | |             |
        |                                                       | +Standard:  | | Send base64 |
        |                                                       |  JSON req   | | to vision   |
        |                                                       |  -> LLM     | | LLM with    |
        |                                                       |  -> JSON    | | policy      |
        |                                                       |   response  | | instructions|
        |                                                       |             | |             |
        |                                                       | +Granite:   | | Returns:    |
        |                                                       |  text ->    | |  violates   |
        |                                                       |  logprobs   | |  message    |
        |                                                       |  -> Yes/No  | |             |
        |                                                       |  threshold  | |             |
        |                                                       +------+------+ +------+------+
        |                                                              |               |
        |                                                              v               v
        |                                                       +------------------------------+
        |                                                       | 5. AGGREGATE & DEDUPLICATE   |
        |                                                       |                              |
        |                                                       |  Merge all violations        |
        |                                                       |  Dedup by:                   |
        |                                                       |   (policy_id, path, message) |
        |                                                       |                              |
        |                                                       |  Each violation:             |
        |                                                       |   { policy_id, severity,     |
        |                                                       |     category, message,       |
        |                                                       |     source, path }           |
        |                                                       +------------------------------+
        |                                                                      |
        |                                                                      v
        |                                                       +------------------------------+
        |                                                       | 6. DECISION                  |
        |                                                       |                              |
        |                                                       |  Any action:block violation? |
        |                                                       |    YES -> decision = "fail"  |
        |                                                       |    NO  -> decision = "accept"|
        |                                                       |                              |
        |                                                       |  Warnings kept separate      |
        |                                                       +------------------------------+
        |                                                                      |
        |                                                                      v
        |                                                       +------------------------------+
        |                                                       | 7. LOG & TRACK               |
        |                                                       |                              |
        |                                                       |  Append to evaluations.jsonl:|
        |                                                       |   timestamp, client_id,      |
        |                                                       |   decision, violations,      |
        |                                                       |   applied_policies           |
        |                                                       |                              |
        |                                                       |  Update client counters:     |
        |                                                       |   total_evaluations++        |
        |                                                       |   total_violations++         |
        |                                                       +------------------------------+
        |                                                                      |
        |                                                                      v
        |                                                       +------------------------------+
        |                                                       | 8. RETURN RESPONSE           |
        |                                                       |  {                           |
        |                                                       |    "decision": "fail|accept",|
        |                                                       |    "violations": [...],      |
        |                                                       |    "warnings": [...]         |
        |                                                       |  }                           |
        |                                                       +------------------------------+
        |                                                                      |
        |                                   +----------------------------------+
        |                                   |
        |                                   v
        |                       +===========================+
        |                       |  EXTENSION DECISION POINT |
        |                       +===========================+
        |                                   |
        |                       +-----------+-----------+
        |                       |                       |
        |                       v                       v
        |            decision = "fail"       decision = "accept"
        |                       |                       |
        |                       v                       v
        |           +---------------------+  +---------------------+
        |           | BLOCK REQUEST       |  | ALLOW REQUEST       |
        |           |                     |  |                     |
        |           | - Suppress original |  | - Release original  |
        |           |   fetch/XHR         |  |   fetch/XHR         |
  User sees         | - Show violation    |  | - Request proceeds  |
  violation  <----- |   modal overlay:    |  |   to AI chat site   |
  overlay           |   +---------------+ |  |                     |
        |           |   | Policy name   | |  | Prompt delivered    |
        |           |   | Severity      | |  | to ChatGPT/Claude/ |
        |           |   | Description   | |  | Gemini/Sage        |
        |           |   | Original text | |  +---------------------+
        |           |   +---------------+ |            |
        |           |                     |            v
        v           | User must click     |  +---------------------+
  User clicks       | "Acknowledged"      |  | AI responds         |
  "Acknowledged"    | to dismiss          |  | normally            |
        |           +---------------------+  +---------------------+
        |                       |
        v                       v
  Prompt NEVER sent      Overlay dismissed
  to AI service          User may retype
```

---

## 3. Enrollment Flow (Extension Setup)

```
  USER                          EXTENSION POPUP                    RAMPART SERVER
 ============================================================================================

  Opens extension popup
        |
        v
  Enters:                  +------------------------+
  - RAMPART URL            | popup.js               |
  - Group enrollment key   |                        |
  - Email (optional)       | Validates inputs       |
        |                  +------------------------+
        |                              |
        |                              | POST /v1/enroll
        |                              | {
        |                              |   "enrollment_key": "...",
        |                              |   "user_email": "...",
        |                              |   "device_id": "<generated>"
        |                              | }
        |                              |
        |                              v
        |                                              +-----------------------------+
        |                                              | Enrollment Handler          |
        |                                              |                             |
        |                                              | 1. Rate limit check         |
        |                                              | 2. Match enrollment_key     |
        |                                              |    to group                 |
        |                                              | 3. Create client record     |
        |                                              |    - Assign to group        |
        |                                              |    - Generate API key       |
        |                                              |    - Hash key (PBKDF2)      |
        |                                              | 4. Store in clients.json    |
        |                                              | 5. Return plaintext API key |
        |                                              +-----------------------------+
        |                              |
        |                              v
        |                  +------------------------+
        |                  | Store API key in       |
        |                  | chrome.storage.sync    |
        |                  |                        |
  Extension shows          | Store RAMPART URL      |
  "Enrolled" status  <---  | Update popup UI        |
        |                  +------------------------+
        v
  Extension now active
  on supported AI sites
```

---

## Legend

```
  +--------+
  | Box    |   Component / process step
  +--------+

  +========+
  | Double |   Decision point / gateway
  +========+

  ------->     Network request (HTTP/HTTPS)
  - - - ->     Internal communication (IPC / in-process)

  Sources:
    deterministic  =  regex, tool/model allowlist, max_chars
    llm            =  LLM-based contextual evaluation
    vision         =  image content evaluation

  Severity levels:  critical > high > medium > low
  Actions:          block (stops request)  |  warn (allows with notice)
```
