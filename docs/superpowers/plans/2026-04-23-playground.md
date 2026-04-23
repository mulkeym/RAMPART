# RAMPART Playground Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an interactive Playground page to RAMPART where users can compose multimodal prompts, select/create policies, run the real policy engine, see per-policy results + sanitized request, and optionally send to the upstream LLM.

**Architecture:** New file `rampart/app/playground.py` contains all playground logic (routes, form parsing, HTML rendering). It reuses existing `PolicyEngine`, `proxy_chat_completion`, and `sanitize_request` directly. `ui.py` gets a nav link + playground CSS. `main.py` includes the playground router.

**Tech Stack:** Python/FastAPI server-rendered HTML, inline vanilla JavaScript (~80 lines for dynamic form + fetch-based evaluation), existing policy engine + LLM proxy.

**Spec:** `docs/superpowers/specs/2026-04-23-playground-design.md`

---

### Task 1: Add Playground nav link and CSS to ui.py

**Files:**
- Modify: `rampart/app/ui.py:971-988` (`_page()` nav links)
- Modify: `rampart/app/ui.py:1139` (CSS before `@keyframes`)

- [ ] **Step 1: Add "Playground" to the nav link list in `_page()`**

In `rampart/app/ui.py`, find the `_nav_class` inner function (line 971) and add a Playground case. Then add the Playground nav link to the `auth_nav` construction.

Replace the `_nav_class` function:

```python
    def _nav_class(label: str) -> str:
        t = title.lower()
        if label == "Policies" and "polic" in t:
            return "active"
        if label == "API Keys" and ("api key" in t or "client" in t):
            return "active"
        if label == "Violations" and "violation" in t:
            return "active"
        if label == "Settings" and "setting" in t:
            return "active"
        if label == "Playground" and "playground" in t:
            return "active"
        return ""
```

Replace the `auth_nav` construction (lines 983-992) to add the Playground link:

```python
    auth_nav = (
        f'<div class="nav-links">'
        f'<a class="{_nav_class("Policies")}" href="/ui/policies">Policies</a>'
        f'<a class="{_nav_class("API Keys")}" href="/ui/clients">API Keys</a>'
        f'<a class="{_nav_class("Violations")}" href="/ui/violations">Violations</a>'
        f'<a class="{_nav_class("Playground")}" href="/ui/playground">Playground</a>'
        f'<a class="{_nav_class("Settings")}" href="/ui/settings">Settings</a>'
        f'</div>'
        f'<form method="post" action="/logout"><span style="color:var(--muted);font-size:13px">{escape(actor)}</span><button type="submit">Log Out</button></form>'
        if actor
        else '<a href="/login">Log In</a>'
    )
```

- [ ] **Step 2: Add playground CSS classes to the style block**

In `rampart/app/ui.py`, find the line `.login h1 {{ color: var(--primary); }}` (line 1135). Insert the playground CSS right after it (before the `.modal-overlay` line):

```css
    .pg-layout {{ display: flex; flex-direction: column; gap: 18px; }}
    .pg-input {{ display: flex; gap: 16px; }}
    .pg-messages {{ flex: 3; display: flex; flex-direction: column; gap: 10px; }}
    .pg-policies {{ flex: 2; }}
    .pg-msg-row {{ display: flex; gap: 8px; align-items: flex-start; }}
    .pg-msg-role {{ width: 100px; flex-shrink: 0; }}
    .pg-msg-text {{ flex: 1; min-height: 60px; }}
    .pg-msg-images {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 6px; }}
    .pg-msg-images img {{ max-height: 80px; border-radius: 4px; border: 1px solid var(--border); object-fit: contain; }}
    .pg-controls {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; flex-wrap: wrap; }}
    .pg-results {{ display: flex; gap: 12px; min-height: 300px; }}
    .pg-results > div {{ flex: 1; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; overflow-y: auto; max-height: 500px; }}
    .pg-decision {{ padding: 8px 12px; border-radius: 6px; font-weight: 700; font-size: 13px; text-align: center; margin-bottom: 12px; animation: fadeIn 0.2s ease-out; }}
    .pg-decision.accepted {{ background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success); }}
    .pg-decision.blocked {{ background: var(--danger-bg); border: 1px solid var(--danger-border); color: var(--danger); }}
    .pg-policy-item {{ padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }}
    .pg-policy-header {{ display: flex; justify-content: space-between; align-items: center; cursor: pointer; }}
    .pg-policy-detail {{ display: none; padding: 8px 0 0 12px; color: var(--text-secondary); font-size: 12px; }}
    .pg-policy-detail.open {{ display: block; }}
    .pg-json {{ background: var(--bg); border-radius: 6px; padding: 12px; font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; overflow-x: auto; }}
    .pg-json .key {{ color: var(--primary); }}
    .pg-json .redacted {{ color: var(--warning); font-weight: 600; }}
    .pg-adhoc {{ border: 1px dashed var(--border); border-radius: 6px; padding: 10px; margin-top: 8px; }}
    .pg-loading {{ display: flex; align-items: center; justify-content: center; min-height: 200px; color: var(--muted); }}
```

Also add to the `@media (max-width: 760px)` block (line 1140 area), inside the media query braces:

```css
      .pg-input {{ flex-direction: column; }}
      .pg-results {{ flex-direction: column; }}
      .pg-results > div {{ max-height: none; }}
```

- [ ] **Step 3: Commit**

```bash
git add rampart/app/ui.py
git commit -m "feat(ui): add Playground nav link and pg-* CSS classes"
```

---

### Task 2: Create playground.py with GET route (form rendering)

**Files:**
- Create: `rampart/app/playground.py`

This task creates the playground module with the GET route that renders the full playground form (message builder, policy selector, controls). No evaluation logic yet.

- [ ] **Step 1: Create `rampart/app/playground.py` with the GET route**

```python
from __future__ import annotations

import json
import time
from copy import deepcopy
from html import escape
from typing import Any, Optional
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from rampart.app.config import CheckConfig, PolicyConfig, UpstreamConfig, get_config
from rampart.app.security.audit import audit_event
from rampart.app.security.auth import read_session_user, require_ui_user
from rampart.app.ui import _page, _severity_pill

router = APIRouter()


@router.get("/ui/playground", response_class=HTMLResponse)
async def playground_form(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/playground")
        return redirect
    actor = read_session_user(request)
    config = get_config()
    return HTMLResponse(_playground_page(config, actor))


def _playground_page(config, actor: Optional[str], results_html: str = "") -> str:
    policy_checkboxes = _policy_checkboxes(config.policies)
    upstream_model = escape(config.upstream.model or "")
    upstream_url = escape(config.upstream.base_url or "")
    body = f"""
      <section class="toolbar">
        <div>
          <h1>Playground</h1>
          <p>Simulate policy evaluation against prompts. Results are not logged.</p>
        </div>
      </section>
      <form id="pg-form" class="pg-layout">
        <div class="pg-input">
          <div class="pg-messages panel" style="padding:16px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
              <label style="font-size:14px;font-weight:700;color:var(--text)">Messages</label>
              <button type="button" class="button small" onclick="pgAddMessage()">Add Message</button>
            </div>
            <div id="pg-msg-list">
              <div class="pg-msg-row" data-idx="0">
                <select class="pg-msg-role" name="msg_role_0">
                  <option value="system" selected>system</option>
                  <option value="user">user</option>
                  <option value="assistant">assistant</option>
                </select>
                <div style="flex:1;display:flex;flex-direction:column;gap:6px">
                  <textarea class="pg-msg-text" name="msg_text_0" rows="2" placeholder="System message...">You are a helpful assistant.</textarea>
                  <div class="pg-msg-images" id="pg-imgs-0"></div>
                  <div><a href="#" onclick="pgAddImage(0);return false" style="font-size:12px;color:var(--primary)">+ Add Image URL</a></div>
                </div>
              </div>
              <div class="pg-msg-row" data-idx="1" style="margin-top:10px">
                <select class="pg-msg-role" name="msg_role_1">
                  <option value="system">system</option>
                  <option value="user" selected>user</option>
                  <option value="assistant">assistant</option>
                </select>
                <div style="flex:1;display:flex;flex-direction:column;gap:6px">
                  <textarea class="pg-msg-text" name="msg_text_1" rows="3" placeholder="Enter your prompt..."></textarea>
                  <div class="pg-msg-images" id="pg-imgs-1"></div>
                  <div><a href="#" onclick="pgAddImage(1);return false" style="font-size:12px;color:var(--primary)">+ Add Image URL</a></div>
                </div>
                <button type="button" class="button small danger" onclick="pgRemoveMessage(this)" title="Remove message" style="padding:5px 8px">✕</button>
              </div>
            </div>
            <input type="hidden" name="msg_count" id="pg-msg-count" value="2">
          </div>
          <div class="pg-policies panel" style="padding:16px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
              <label style="font-size:14px;font-weight:700;color:var(--text)">Policies</label>
              <a href="#" onclick="pgToggleAll(this);return false" style="font-size:12px;color:var(--primary)">Select All</a>
            </div>
            {policy_checkboxes}
            <div style="margin-top:12px">
              <div id="pg-adhoc-list"></div>
              <button type="button" class="button small" onclick="pgAddAdhoc()" style="margin-top:8px">+ Ad-hoc Rule</button>
              <input type="hidden" name="adhoc_count" id="pg-adhoc-count" value="0">
            </div>
          </div>
        </div>
        <div class="pg-controls panel" style="padding:12px 16px">
          <div style="display:flex;gap:12px;align-items:center;flex:1">
            <label style="font-size:12px;color:var(--muted);white-space:nowrap">Model</label>
            <input name="model_override" placeholder="{upstream_model}" style="max-width:200px">
            <a href="#" onclick="document.getElementById('pg-upstream').style.display=document.getElementById('pg-upstream').style.display==='none'?'flex':'none';return false" style="font-size:12px;color:var(--primary);white-space:nowrap">Override Upstream ▾</a>
          </div>
          <div style="display:flex;gap:8px">
            <button type="button" class="button" onclick="pgSubmit('evaluate')">Evaluate Only</button>
            <button type="button" class="button primary" onclick="pgSubmit('send')">Evaluate &amp; Send</button>
          </div>
        </div>
        <div id="pg-upstream" style="display:none;gap:12px;padding:0 16px" class="panel pg-controls">
          <label style="flex:1;font-size:12px">Base URL<input name="upstream_override_url" placeholder="{upstream_url}"></label>
          <label style="flex:1;font-size:12px">API Key<input name="upstream_override_key" placeholder="Bearer token" autocomplete="off"></label>
          <label style="font-size:12px;width:120px">Timeout<input name="upstream_override_timeout" placeholder="120" inputmode="decimal"></label>
        </div>
        <input type="hidden" name="action" id="pg-action" value="evaluate">
      </form>
      <div id="playground-results">{results_html}</div>
      {_playground_script()}
    """
    return _page("RAMPART Playground", body, actor)


def _policy_checkboxes(policies: list[PolicyConfig]) -> str:
    if not policies:
        return '<div class="muted">No policies configured.</div>'
    items = []
    for policy in policies:
        checked = "checked" if policy.enabled else ""
        items.append(
            f'<label class="checkbox" style="margin-bottom:6px">'
            f'<input type="checkbox" name="policy_{escape(policy.id)}" {checked}>'
            f'<span><code>{escape(policy.id)}</code> {_severity_pill(policy.severity)}'
            f'<span class="muted" style="display:block;font-size:11px">{escape(policy.description)}</span></span>'
            f'</label>'
        )
    return "\n".join(items)


def _playground_script() -> str:
    return """<script>
var msgCount=2, adhocCount=0, imgCounts={0:0,1:0};

function pgAddMessage(){
  var idx=msgCount++;
  document.getElementById('pg-msg-count').value=msgCount;
  imgCounts[idx]=0;
  var row=document.createElement('div');
  row.className='pg-msg-row';row.dataset.idx=idx;row.style.marginTop='10px';
  row.innerHTML='<select class="pg-msg-role" name="msg_role_'+idx+'"><option value="system">system</option><option value="user" selected>user</option><option value="assistant">assistant</option></select><div style="flex:1;display:flex;flex-direction:column;gap:6px"><textarea class="pg-msg-text" name="msg_text_'+idx+'" rows="3" placeholder="Enter message..."></textarea><div class="pg-msg-images" id="pg-imgs-'+idx+'"></div><div><a href="#" onclick="pgAddImage('+idx+');return false" style="font-size:12px;color:var(--primary)">+ Add Image URL</a></div></div><button type="button" class="button small danger" onclick="pgRemoveMessage(this)" title="Remove" style="padding:5px 8px">✕</button>';
  document.getElementById('pg-msg-list').appendChild(row);
}

function pgRemoveMessage(btn){
  var rows=document.querySelectorAll('.pg-msg-row');
  if(rows.length<=1)return;
  btn.closest('.pg-msg-row').remove();
}

function pgAddImage(msgIdx){
  var c=imgCounts[msgIdx]||0;
  var container=document.getElementById('pg-imgs-'+msgIdx);
  var div=document.createElement('div');
  div.style.cssText='display:flex;gap:6px;align-items:center;margin-top:4px';
  div.innerHTML='<input name="msg_img_'+msgIdx+'_'+c+'" placeholder="https://example.com/image.png" style="flex:1;font-size:12px" onblur="pgPreviewImg(this)"><img src="" style="max-height:60px;border-radius:4px;display:none"><button type="button" class="button small danger" onclick="this.parentNode.remove()" style="padding:3px 6px;font-size:11px">✕</button>';
  container.appendChild(div);
  imgCounts[msgIdx]=c+1;
}

function pgPreviewImg(input){
  var img=input.nextElementSibling;
  if(input.value.trim()){img.src=input.value.trim();img.style.display='block';}
  else{img.style.display='none';img.src='';}
}

function pgToggleAll(link){
  var boxes=document.querySelectorAll('.pg-policies input[type=checkbox]');
  var allChecked=[].every.call(boxes,function(b){return b.checked;});
  boxes.forEach(function(b){b.checked=!allChecked;});
  link.textContent=allChecked?'Select All':'Deselect All';
}

function pgAddAdhoc(){
  var idx=adhocCount++;
  document.getElementById('pg-adhoc-count').value=adhocCount;
  var div=document.createElement('div');
  div.className='pg-adhoc';
  div.innerHTML='<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px"><select name="adhoc_type_'+idx+'" onchange="pgAdhocType(this,'+idx+')" style="width:100px"><option value="regex">regex</option><option value="llm">llm</option></select><select name="adhoc_severity_'+idx+'" style="width:90px"><option value="medium" selected>medium</option><option value="low">low</option><option value="high">high</option><option value="critical">critical</option></select><select name="adhoc_action_'+idx+'" style="width:80px"><option value="block" selected>block</option><option value="warn">warn</option></select><button type="button" class="button small danger" onclick="this.closest(\\'.pg-adhoc\\').remove()" style="padding:3px 6px">✕</button></div><input name="adhoc_pattern_'+idx+'" placeholder="Regex pattern (case-insensitive)" id="adhoc-pattern-'+idx+'"><textarea name="adhoc_instruction_'+idx+'" placeholder="Plain-text policy instruction for LLM evaluation" rows="2" id="adhoc-instruction-'+idx+'" style="display:none"></textarea>';
  document.getElementById('pg-adhoc-list').appendChild(div);
}

function pgAdhocType(sel,idx){
  var p=document.getElementById('adhoc-pattern-'+idx);
  var i=document.getElementById('adhoc-instruction-'+idx);
  if(sel.value==='regex'){p.style.display='';i.style.display='none';}
  else{p.style.display='none';i.style.display='';}
}

function pgSubmit(action){
  document.getElementById('pg-action').value=action;
  var form=document.getElementById('pg-form');
  var data=new FormData(form);
  var results=document.getElementById('playground-results');
  results.innerHTML='<div class="pg-loading">Evaluating...</div>';
  fetch('/ui/playground',{method:'POST',body:new URLSearchParams(data),headers:{'Content-Type':'application/x-www-form-urlencoded'}})
    .then(function(r){return r.text();})
    .then(function(html){results.innerHTML=html;})
    .catch(function(e){results.innerHTML='<div class="notice error">'+e.message+'</div>';});
}

function pgForceSend(){
  document.getElementById('pg-action').value='force_send';
  pgSubmit('force_send');
}

function pgToggleDetail(el){
  var detail=el.nextElementSibling;
  if(detail)detail.classList.toggle('open');
}
</script>"""
```

- [ ] **Step 2: Verify the file loads without import errors**

Run: `python3 -c "from rampart.app.playground import router; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/playground.py
git commit -m "feat(playground): create playground.py with GET route and form rendering"
```

---

### Task 3: Add POST route with evaluation and results rendering

**Files:**
- Modify: `rampart/app/playground.py`

This task adds the POST handler that parses the form, builds the OpenAI request, runs the policy engine, optionally sends to upstream, and renders the results HTML.

- [ ] **Step 1: Add the POST route and all helper functions to playground.py**

Add these functions to `rampart/app/playground.py` after the existing code:

```python
@router.post("/ui/playground", response_class=HTMLResponse)
async def playground_evaluate(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/playground")
        return redirect
    actor = read_session_user(request)
    config = get_config()
    form = await _parse_form(request)
    action = form.get("action", "evaluate")

    # Build OpenAI-compatible request
    messages = _build_messages(form)
    openai_request: dict[str, Any] = {"messages": messages}
    model_override = form.get("model_override", "").strip()
    if model_override:
        openai_request["model"] = model_override

    # Resolve policies
    selected_policies = _resolve_selected_policies(config, form)

    # Run evaluation
    from rampart.app.policy.engine import PolicyEngine
    engine = PolicyEngine(config, selected_policies)
    start_time = time.time()
    response = await engine.evaluate(openai_request)
    eval_ms = int((time.time() - start_time) * 1000)

    # Determine per-policy results
    policy_results = _build_policy_results(selected_policies, response)

    # Optionally send to upstream
    llm_response_html = ""
    if action in ("send", "force_send"):
        has_blocking = any(
            r["status"] == "match" and _policy_action(r["policy_id"], selected_policies) == "block"
            for r in policy_results
        )
        if not has_blocking or action == "force_send":
            llm_response_html = await _send_upstream(config, form, openai_request, response)
        else:
            llm_response_html = _blocked_response_html()
    else:
        llm_response_html = '<div class="muted">Not sent to upstream — use "Evaluate &amp; Send" to see LLM response.</div>'

    # Render results
    results_html = _render_results(response, policy_results, openai_request, eval_ms, llm_response_html)
    return HTMLResponse(results_html)


async def _parse_form(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8")
    parsed = parse_qs(body, keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


def _build_messages(form: dict[str, str]) -> list[dict[str, Any]]:
    msg_count = int(form.get("msg_count", "0"))
    messages: list[dict[str, Any]] = []
    for i in range(msg_count):
        role = form.get(f"msg_role_{i}", "user")
        text = form.get(f"msg_text_{i}", "")
        if not role:
            continue

        # Check for images
        image_urls = []
        for j in range(20):  # max 20 images per message
            img_url = form.get(f"msg_img_{i}_{j}", "").strip()
            if img_url:
                image_urls.append(img_url)
            elif j > 0 and f"msg_img_{i}_{j}" not in form:
                break

        if image_urls:
            content: list[dict[str, Any]] = [{"type": "text", "text": text}]
            for url in image_urls:
                content.append({"type": "image_url", "image_url": {"url": url}})
            messages.append({"role": role, "content": content})
        else:
            messages.append({"role": role, "content": text})
    return messages


def _resolve_selected_policies(config, form: dict[str, str]) -> list[PolicyConfig]:
    selected: list[PolicyConfig] = []
    for policy in config.policies:
        if form.get(f"policy_{policy.id}") == "on":
            # Force enabled for evaluation regardless of policy.enabled
            p = policy.model_copy()
            p.enabled = True
            selected.append(p)

    # Ad-hoc rules
    adhoc_count = int(form.get("adhoc_count", "0"))
    for i in range(adhoc_count):
        adhoc_type = form.get(f"adhoc_type_{i}", "regex")
        severity = form.get(f"adhoc_severity_{i}", "medium")
        action = form.get(f"adhoc_action_{i}", "block")
        pattern = form.get(f"adhoc_pattern_{i}", "").strip()
        instruction = form.get(f"adhoc_instruction_{i}", "").strip()
        if adhoc_type == "regex" and pattern:
            selected.append(PolicyConfig(
                id=f"adhoc-{i+1}",
                enabled=True,
                severity=severity,
                category="adhoc",
                description=f"Ad-hoc regex: {pattern}",
                action=action,
                checks=[CheckConfig(type="regex", pattern=pattern)],
            ))
        elif adhoc_type == "llm" and instruction:
            selected.append(PolicyConfig(
                id=f"adhoc-{i+1}",
                enabled=True,
                severity=severity,
                category="adhoc",
                description=f"Ad-hoc LLM rule",
                action=action,
                checks=[CheckConfig(type="llm", instruction=instruction)],
            ))
    return selected


def _build_policy_results(policies: list[PolicyConfig], response) -> list[dict[str, Any]]:
    violation_map: dict[str, list] = {}
    for v in response.violations:
        violation_map.setdefault(v.policy_id, []).append(v)

    results = []
    for policy in policies:
        violations = violation_map.get(policy.id, [])
        results.append({
            "policy_id": policy.id,
            "severity": policy.severity,
            "action": policy.action,
            "description": policy.description,
            "status": "match" if violations else "pass",
            "violations": violations,
        })
    return results


def _policy_action(policy_id: str, policies: list[PolicyConfig]) -> str:
    for p in policies:
        if p.id == policy_id:
            return p.action
    return "block"


async def _send_upstream(config, form: dict[str, str], openai_request: dict[str, Any], response) -> str:
    from rampart.app.openai.proxy import proxy_chat_completion

    upstream = config.upstream.model_copy()
    override_url = form.get("upstream_override_url", "").strip()
    override_key = form.get("upstream_override_key", "").strip()
    override_timeout = form.get("upstream_override_timeout", "").strip()
    if override_url:
        upstream.base_url = override_url
    if override_key:
        upstream.api_key = override_key
    if override_timeout:
        try:
            upstream.timeout_seconds = float(override_timeout)
        except ValueError:
            pass

    # Use sanitized request if there were violations
    payload = response.sanitized_request if response.violations and response.sanitized_request else openai_request
    payload = deepcopy(payload)
    model_override = form.get("model_override", "").strip()
    if model_override:
        payload["model"] = model_override
    elif upstream.model:
        payload["model"] = upstream.model

    start_time = time.time()
    try:
        body, status = await proxy_chat_completion(upstream, payload)
        elapsed_ms = int((time.time() - start_time) * 1000)
    except Exception as e:
        return f'<div class="notice error">Upstream error: {escape(str(e))}</div>'

    if status >= 400:
        error_msg = body.get("error", {}).get("message", json.dumps(body)) if isinstance(body, dict) else str(body)
        return f'<div class="notice error">Upstream returned {status}: {escape(str(error_msg))}</div>'

    # Extract response content
    content = ""
    model_name = ""
    usage_html = ""
    if isinstance(body, dict):
        model_name = body.get("model", "")
        choices = body.get("choices", [])
        if choices and isinstance(choices[0], dict):
            msg = choices[0].get("message", {})
            content = msg.get("content", "") if isinstance(msg, dict) else ""
        usage = body.get("usage")
        if isinstance(usage, dict):
            prompt_tokens = usage.get("prompt_tokens", "?")
            completion_tokens = usage.get("completion_tokens", "?")
            total_tokens = usage.get("total_tokens", "?")
            usage_html = f'<div class="muted" style="font-size:11px;margin-top:8px">Tokens: {prompt_tokens} prompt + {completion_tokens} completion = {total_tokens} total</div>'

    return f"""
      <div style="white-space:pre-wrap;font-size:13px;line-height:1.6">{escape(content)}</div>
      <div class="muted" style="font-size:11px;margin-top:8px">Model: {escape(model_name)} | {elapsed_ms}ms</div>
      {usage_html}
    """


def _blocked_response_html() -> str:
    return """
      <div class="muted">Blocked by policy — not sent to upstream.</div>
      <button type="button" class="button small danger" onclick="pgForceSend()" style="margin-top:8px">Force Send Anyway</button>
    """


def _render_results(response, policy_results: list[dict], openai_request: dict, eval_ms: int, llm_response_html: str) -> str:
    decision_class = "accepted" if response.decision == "accept" else "blocked"
    decision_label = "ACCEPTED" if response.decision == "accept" else "BLOCKED"

    # Policy results panel
    policy_items = []
    for pr in policy_results:
        status_color = "var(--success)" if pr["status"] == "pass" else "var(--danger)"
        status_label = "PASS" if pr["status"] == "pass" else "MATCH"
        is_adhoc = pr["policy_id"].startswith("adhoc-")
        id_suffix = " <span class='muted'>(ad-hoc)</span>" if is_adhoc else ""

        detail_html = ""
        if pr["violations"]:
            details = []
            for v in pr["violations"]:
                details.append(f"<div><strong>Message:</strong> {escape(v.message)}</div>")
                details.append(f"<div><strong>Source:</strong> {escape(v.source)}</div>")
                if v.path:
                    details.append(f"<div><strong>Path:</strong> <code>{escape(v.path)}</code></div>")
            detail_html = f'<div class="pg-policy-detail">{"".join(details)}</div>'

        policy_items.append(f"""
          <div class="pg-policy-item">
            <div class="pg-policy-header" onclick="pgToggleDetail(this)">
              <span><code>{escape(pr["policy_id"])}</code>{id_suffix} {_severity_pill(pr["severity"])}</span>
              <span style="color:{status_color};font-size:12px;font-weight:600">{status_label}</span>
            </div>
            {detail_html}
          </div>
        """)

    # Sanitized request panel
    sanitized_html = ""
    if response.sanitized_request:
        san_json = json.dumps(response.sanitized_request, indent=2, sort_keys=False, ensure_ascii=False)
        # Highlight [REDACTED] tokens
        san_json_escaped = escape(san_json).replace("[REDACTED]", '<span class="redacted">[REDACTED]</span>')
        sanitized_html = f'<div class="pg-json">{san_json_escaped}</div>'
    else:
        sanitized_html = '<div class="muted">No modifications — original request passes clean.</div>'

    return f"""
      <div class="pg-results">
        <div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Policy Results</div>
          <div class="pg-decision {decision_class}">{decision_label}</div>
          {"".join(policy_items)}
          <div class="muted" style="font-size:11px;margin-top:12px">Evaluated in {eval_ms}ms</div>
        </div>
        <div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Sanitized Request</div>
          {sanitized_html}
        </div>
        <div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">LLM Response</div>
          {llm_response_html}
        </div>
      </div>
    """
```

- [ ] **Step 2: Verify the file loads without import errors**

Run: `python3 -c "from rampart.app.playground import router; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add rampart/app/playground.py
git commit -m "feat(playground): add POST evaluation route and results rendering"
```

---

### Task 4: Register playground router in main.py

**Files:**
- Modify: `rampart/app/main.py:13-20`

- [ ] **Step 1: Add the playground router import and registration**

In `rampart/app/main.py`, add the import after the `ui_router` import (line 13):

```python
from rampart.app.playground import router as playground_router
```

Then add the router registration after `app.include_router(ui_router)` (line 20):

```python
app.include_router(playground_router)
```

- [ ] **Step 2: Verify the app starts**

Run: `python3 -c "from rampart.app.main import app; print('Routes:', [r.path for r in app.routes if hasattr(r, 'path') and 'playground' in r.path])"`
Expected: `Routes: ['/ui/playground']` (or similar showing the playground routes)

- [ ] **Step 3: Commit**

```bash
git add rampart/app/main.py
git commit -m "feat(playground): register playground router in main app"
```

---

### Task 5: Run tests and verify no regressions

**Files:**
- Read: `tests/`

- [ ] **Step 1: Run the full test suite**

Run: `python3 -m pytest tests/ -v`

Expected: All previously-passing tests still pass (35 pass, 2 pre-existing failures in test_gateway.py). No new failures introduced.

- [ ] **Step 2: Fix any import errors or regressions**

If `_severity_pill` is not importable from `ui.py` (it's a module-level function, not prefixed with underscore convention that would block import), verify it can be imported. If needed, adjust the import.

- [ ] **Step 3: Commit (if fixes needed)**

```bash
git add -A
git commit -m "fix: resolve any playground import issues"
```

---

### Task 6: Visual QA and end-to-end test

**Files:**
- No code changes expected unless touch-ups needed

- [ ] **Step 1: Verify Playground page loads**

Open `http://localhost:8080/ui/playground` — should show:
- "Playground" highlighted in nav
- Message builder with system + user messages
- Policy selector with checkboxes
- Controls bar with model field and two buttons

- [ ] **Step 2: Test "Evaluate Only" with a credential prompt**

Enter in user message: `My API key is sk-1234567890abcdefghijk`
Check the `no-credential-disclosure` policy checkbox. Click "Evaluate Only".
Verify:
- Decision: BLOCKED
- `no-credential-disclosure` shows MATCH with violation detail
- Sanitized request shows `[REDACTED]` in amber
- LLM Response shows "Not sent to upstream"

- [ ] **Step 3: Test ad-hoc rule**

Click "Add Ad-hoc Rule", select regex, enter pattern: `hello`. Enter "hello world" in user message.
Click "Evaluate Only". Verify the ad-hoc rule shows MATCH.

- [ ] **Step 4: Test multimodal input**

Click "Add Image URL" on a message. Enter any image URL. Verify thumbnail preview appears.

- [ ] **Step 5: Test mobile responsiveness**

Resize browser to < 760px. Verify input area stacks vertically and results panels stack vertically.

- [ ] **Step 6: Commit any touch-ups**

```bash
git add -A
git commit -m "fix(playground): visual QA touch-ups"
```
