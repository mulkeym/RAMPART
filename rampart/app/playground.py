from __future__ import annotations

import json
import time
from copy import deepcopy
from html import escape
from typing import Any, Optional
from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from rampart.app.client_store import get_client, list_clients
from rampart.app.config import CheckConfig, PolicyConfig, UpstreamConfig, get_config
from rampart.app.prompt_log import PromptLogEntry, build_policy_results, log_prompt
from rampart.app.security.audit import audit_event
from rampart.app.security.auth import read_session_user, require_ui_user
from rampart.app.ui import _page, _severity_pill

router = APIRouter(include_in_schema=False)


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
    client_options = _client_options(config)
    body = f"""
      <section class="toolbar">
        <div>
          <h1>Playground</h1>
          <p>Simulate policy evaluation against prompts.</p>
        </div>
      </section>
      <form id="pg-form" class="pg-layout">
        <div style="padding:12px 16px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:8px;margin-bottom:12px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <label style="font-size:13px;color:var(--muted);white-space:nowrap;margin:0">Test Scenario:</label>
          <select id="pg-scenario" name="scenario_type" onchange="pgScenarioChange(this.value)" style="flex:1;max-width:300px">
            <option value="prompt" selected>Prompt Evaluation</option>
            <option value="tools">Tool Call Test</option>
            <option value="raw_json">Raw JSON</option>
          </select>
          <label style="font-size:13px;color:var(--muted);white-space:nowrap;margin:0">Test as Client:</label>
          <select id="pg-client" name="test_client_id" onchange="pgClientChange(this.value)" style="flex:1;max-width:300px">
            <option value="">Manual (select policies below)</option>
            {client_options}
          </select>
        </div>
        <div class="pg-input">
          <div class="pg-input-left">
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
                  <textarea class="pg-msg-text" name="msg_text_1" rows="3" placeholder="Enter your prompt... (paste images here)"></textarea>
                  <div class="pg-msg-images" id="pg-imgs-1"></div>
                  <div><a href="#" onclick="pgAddImage(1);return false" style="font-size:12px;color:var(--primary)">+ Add Image URL</a></div>
                </div>
                <button type="button" class="button small danger" onclick="pgRemoveMessage(this)" title="Remove message" style="padding:5px 8px">&#10005;</button>
              </div>
            </div>
            <input type="hidden" name="msg_count" id="pg-msg-count" value="2">
          </div>
          <div class="pg-user-field panel" style="padding:12px 16px;margin-top:8px" id="pg-user-section">
            <label style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:6px;display:block">User Identity (optional)</label>
            <input name="user_field" placeholder="email@example.com — for testing group-based policy resolution" style="width:100%">
          </div>
          <div id="pg-tools-section" style="display:none">
            <div class="panel" style="padding:16px;margin-top:8px">
              <label style="font-size:14px;font-weight:700;color:var(--text);display:block;margin-bottom:8px">Tool Names</label>
              <input name="tool_names" placeholder="get_weather, execute_code, send_email (comma-separated)" style="width:100%">
              <div class="hint" style="margin-top:6px">Enter tool names to test against tool_allowlist and tool_denylist policies. Names are wrapped in OpenAI function tool format automatically.</div>
            </div>
          </div>
          <div id="pg-raw-section" style="display:none">
            <div class="panel" style="padding:16px;margin-top:8px">
              <label style="font-size:14px;font-weight:700;color:var(--text);display:block;margin-bottom:8px">OpenAI Request JSON</label>
              <textarea name="raw_json" rows="18" style="width:100%;font-family:monospace;font-size:12px;line-height:1.5;background:var(--bg-primary);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:12px;resize:vertical">{_raw_json_template()}</textarea>
              <div class="hint" style="margin-top:6px">Edit the full OpenAI-compatible request. Includes model, user, messages, and tools. RAMPART evaluates everything.</div>
            </div>
          </div>
          </div>
          <div class="pg-policies panel" style="padding:16px;text-align:left">
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
            <a href="#" onclick="document.getElementById('pg-upstream').style.display=document.getElementById('pg-upstream').style.display==='none'?'flex':'none';return false" style="font-size:12px;color:var(--primary);white-space:nowrap">Override Upstream &#9662;</a>
          </div>
          <div style="display:flex;gap:8px">
            <button type="button" class="button" onclick="pgSubmit('evaluate')">Evaluate Only</button>
            <button type="button" class="button primary" onclick="pgSubmit('send')">Evaluate &amp; Send</button>
          </div>
        </div>
        <div id="pg-upstream" style="display:none;gap:12px;padding:12px 16px" class="panel pg-controls">
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


def _client_options(config) -> str:
    clients = list_clients(config.clients.path)
    items = []
    for c in clients:
        if not c.enabled:
            continue
        label = c.id
        if c.owner_email or c.owner_name:
            label += f" ({c.owner_email or c.owner_name})"
        if c.group_id:
            label += f" [group: {c.group_id}]"
        items.append(f'<option value="{escape(c.id)}">{escape(label)}</option>')
    return "\n".join(items)


def _resolve_client_policies(config, client_id: str) -> list[PolicyConfig]:
    """Resolve policies for a client the same way the API does."""
    client = get_client(client_id, config.clients.path)
    if not client:
        return []
    enabled_policies = [p for p in config.policies if p.enabled]
    if client.group_id:
        from rampart.app.group_store import get_group
        group = get_group(client.group_id)
        if group and group.policy_ids:
            assigned = set(group.policy_ids)
            return [p for p in enabled_policies if p.id in assigned]
        return enabled_policies
    if client.policy_ids:
        assigned = set(client.policy_ids)
        return [p for p in enabled_policies if p.id in assigned]
    return enabled_policies


def _raw_json_template() -> str:
    return escape(json.dumps({
        "model": "gpt-4",
        "user": "testuser@example.com",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Enter your prompt here"},
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "example_tool",
                    "description": "An example tool definition",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                        },
                    },
                },
            },
        ],
    }, indent=2))


def _policy_checkboxes(policies: list[PolicyConfig]) -> str:
    if not policies:
        return '<div class="muted">No policies configured.</div>'
    items = []
    for policy in policies:
        checked = "checked" if policy.enabled else ""
        items.append(
            f'<label style="display:flex;align-items:flex-start;gap:8px;font-weight:400;margin-bottom:6px;cursor:pointer">'
            f'<input type="checkbox" name="policy_{escape(policy.id)}" {checked} style="width:auto;margin-top:3px;flex-shrink:0">'
            f'<span style="text-align:left"><code>{escape(policy.id)}</code> {_severity_pill(policy.severity)}'
            f'<span class="muted" style="display:block;font-size:11px;text-align:left">{escape(policy.description)}</span></span>'
            f'</label>'
        )
    return "\n".join(items)


def _playground_script() -> str:
    return """<script>
function pgClientChange(clientId) {
  var policiesSection = document.querySelector('.pg-policies');
  if (clientId) {
    if (policiesSection) policiesSection.style.display = 'none';
  } else {
    if (policiesSection) policiesSection.style.display = '';
  }
}

function pgScenarioChange(scenario) {
  var msgSection = document.querySelector('.pg-messages');
  var userSection = document.getElementById('pg-user-section');
  var toolsSection = document.getElementById('pg-tools-section');
  var rawSection = document.getElementById('pg-raw-section');
  var policiesSection = document.querySelector('.pg-policies');

  if (msgSection) msgSection.style.display = 'none';
  if (userSection) userSection.style.display = 'none';
  if (toolsSection) toolsSection.style.display = 'none';
  if (rawSection) rawSection.style.display = 'none';

  if (scenario === 'prompt') {
    if (msgSection) msgSection.style.display = '';
    if (userSection) userSection.style.display = '';
  } else if (scenario === 'tools') {
    if (msgSection) msgSection.style.display = '';
    if (userSection) userSection.style.display = '';
    if (toolsSection) toolsSection.style.display = '';
  } else if (scenario === 'raw_json') {
    if (rawSection) rawSection.style.display = '';
  }
}

var msgCount=2, adhocCount=0, imgCounts={0:0,1:0};

function pgAddMessage(){
  var idx=msgCount++;
  document.getElementById('pg-msg-count').value=msgCount;
  imgCounts[idx]=0;
  var row=document.createElement('div');
  row.className='pg-msg-row';row.dataset.idx=idx;row.style.marginTop='10px';
  row.innerHTML='<select class="pg-msg-role" name="msg_role_'+idx+'"><option value="system">system</option><option value="user" selected>user</option><option value="assistant">assistant</option></select><div style="flex:1;display:flex;flex-direction:column;gap:6px"><textarea class="pg-msg-text" name="msg_text_'+idx+'" rows="3" placeholder="Enter message... (paste images here)"></textarea><div class="pg-msg-images" id="pg-imgs-'+idx+'"></div><div><a href="#" onclick="pgAddImage('+idx+');return false" style="font-size:12px;color:var(--primary)">+ Add Image URL</a></div></div><button type="button" class="button small danger" onclick="pgRemoveMessage(this)" title="Remove" style="padding:5px 8px">&#10005;</button>';
  document.getElementById('pg-msg-list').appendChild(row);
  pgBindPaste(row.querySelector('.pg-msg-text'));
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
  div.innerHTML='<input name="msg_img_'+msgIdx+'_'+c+'" placeholder="https://example.com/image.png" style="flex:1;font-size:12px" onblur="pgPreviewImg(this)"><img src="" style="max-height:60px;border-radius:4px;display:none"><button type="button" class="button small danger" onclick="this.parentNode.remove()" style="padding:3px 6px;font-size:11px">&#10005;</button>';
  container.appendChild(div);
  imgCounts[msgIdx]=c+1;
}

function pgPreviewImg(input){
  var img=input.nextElementSibling;
  if(input.value.trim()){img.src=input.value.trim();img.style.display='block';}
  else{img.style.display='none';img.src='';}
}

function pgPasteImage(msgIdx,dataUrl){
  var c=imgCounts[msgIdx]||0;
  var container=document.getElementById('pg-imgs-'+msgIdx);
  var div=document.createElement('div');
  div.style.cssText='display:flex;gap:6px;align-items:center;margin-top:4px';
  div.innerHTML='<input type="hidden" name="msg_img_'+msgIdx+'_'+c+'" value="'+dataUrl+'"><img src="'+dataUrl+'" style="max-height:80px;border-radius:4px;border:1px solid rgba(255,255,255,0.08)"><span style="color:var(--muted);font-size:11px">Pasted image</span><button type="button" class="button small danger" onclick="this.parentNode.remove()" style="padding:3px 6px;font-size:11px">&#10005;</button>';
  container.appendChild(div);
  imgCounts[msgIdx]=c+1;
}

function pgBindPaste(textarea){
  textarea.addEventListener('paste',function(e){
    var items=e.clipboardData&&e.clipboardData.items;
    if(!items)return;
    for(var i=0;i<items.length;i++){
      if(items[i].type.indexOf('image')===0){
        e.preventDefault();
        var file=items[i].getAsFile();
        var reader=new FileReader();
        var row=textarea.closest('.pg-msg-row');
        var idx=row?parseInt(row.dataset.idx):0;
        reader.onload=function(ev){pgPasteImage(idx,ev.target.result);};
        reader.readAsDataURL(file);
        return;
      }
    }
  });
}

document.querySelectorAll('.pg-msg-text').forEach(pgBindPaste);

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
  div.innerHTML='<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px"><select name="adhoc_type_'+idx+'" onchange="pgAdhocType(this,'+idx+')" style="width:100px"><option value="regex">regex</option><option value="llm">llm</option></select><select name="adhoc_severity_'+idx+'" style="width:90px"><option value="medium" selected>medium</option><option value="low">low</option><option value="high">high</option><option value="critical">critical</option></select><select name="adhoc_action_'+idx+'" style="width:80px"><option value="block" selected>block</option><option value="warn">warn</option></select><button type="button" class="button small danger" onclick="this.closest(\\'.pg-adhoc\\').remove()" style="padding:3px 6px">&#10005;</button></div><input name="adhoc_pattern_'+idx+'" placeholder="Regex pattern (case-insensitive)" id="adhoc-pattern-'+idx+'"><textarea name="adhoc_instruction_'+idx+'" placeholder="Plain-text policy instruction for LLM evaluation" rows="2" id="adhoc-instruction-'+idx+'" style="display:none"></textarea>';
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
    .then(function(html){
      results.innerHTML=html;
      var pending=document.getElementById('pg-llm-pending');
      if(pending){
        fetch('/ui/playground/llm',{method:'POST',body:new URLSearchParams(data),headers:{'Content-Type':'application/x-www-form-urlencoded'}})
          .then(function(r){return r.text();})
          .then(function(llmHtml){if(pending.parentNode)pending.parentNode.innerHTML=llmHtml;})
          .catch(function(e){if(pending.parentNode)pending.innerHTML='<div class="notice error">'+e.message+'</div>';});
      }
    })
    .catch(function(e){results.innerHTML='<div class="notice error">'+e.message+'</div>';});
}

function pgForceSend(){
  pgSubmit('force_send');
}

function pgToggleDetail(el){
  var detail=el.nextElementSibling;
  if(detail)detail.classList.toggle('open');
}
</script>"""


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

    try:
        openai_request = _build_openai_request(form)
    except ValueError as e:
        return HTMLResponse(f'<div class="notice error">{escape(str(e))}</div>')

    test_client_id = form.get("test_client_id", "").strip()
    if test_client_id:
        selected_policies = _resolve_client_policies(config, test_client_id)
        if not selected_policies:
            return HTMLResponse(f'<div class="notice error">Client {escape(test_client_id)} not found or has no policies.</div>')
    else:
        selected_policies = _resolve_selected_policies(config, form)

    from rampart.app.policy.engine import PolicyEngine
    engine = PolicyEngine(config, selected_policies)
    start_time = time.time()
    response = await engine.evaluate(openai_request)
    eval_ms = int((time.time() - start_time) * 1000)

    policy_results = _build_policy_results(selected_policies, response)

    log_prompt(PromptLogEntry(
        source="playground",
        user=openai_request.get("user") or actor,
        client_id=test_client_id or None,
        model=openai_request.get("model"),
        messages=openai_request.get("messages", []),
        decision="fail" if any(r["status"] == "match" for r in policy_results) else "accept",
        policy_results=build_policy_results(selected_policies, response.violations),
        violations=[v.model_dump() for v in response.violations],
        applied_policies=[p.id for p in selected_policies],
        eval_ms=eval_ms,
        warnings=response.warnings or [],
    ))

    llm_response_html = ""
    if action in ("send", "force_send"):
        has_blocking = any(
            r["status"] == "match" and _policy_action(r["policy_id"], selected_policies) == "block"
            for r in policy_results
        )
        if has_blocking and action != "force_send":
            llm_response_html = _blocked_response_html()
        else:
            # Show results immediately with a loading placeholder; JS will fetch LLM response
            llm_response_html = '<div id="pg-llm-pending" class="pg-loading">Sending to LLM...</div>'
    else:
        llm_response_html = '<div class="muted">Not sent to upstream &mdash; use "Evaluate &amp; Send" to see LLM response.</div>'

    results_html = _render_results(response, policy_results, eval_ms, llm_response_html)
    return HTMLResponse(results_html)


@router.post("/ui/playground/llm", response_class=HTMLResponse)
async def playground_llm(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        return redirect
    config = get_config()
    form = await _parse_form(request)

    try:
        openai_request = _build_openai_request(form)
    except ValueError as e:
        return HTMLResponse(f'<div class="notice error">{escape(str(e))}</div>')

    # Re-run evaluation to get sanitized request (lightweight, no LLM calls needed for this)
    test_client_id = form.get("test_client_id", "").strip()
    if test_client_id:
        selected_policies = _resolve_client_policies(config, test_client_id)
    else:
        selected_policies = _resolve_selected_policies(config, form)
    from rampart.app.policy.engine import PolicyEngine
    engine = PolicyEngine(config, selected_policies)
    response = await engine.evaluate(openai_request)

    html = await _send_upstream(config, form, openai_request, response)
    return HTMLResponse(html)


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
        image_urls = []
        for j in range(20):
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


def _build_openai_request(form: dict[str, str]) -> dict[str, Any]:
    """Build an OpenAI-compatible request dict based on the selected scenario template."""
    scenario = form.get("scenario_type", "prompt")

    if scenario == "raw_json":
        raw = form.get("raw_json", "").strip()
        try:
            request = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        if not isinstance(request, dict) or "messages" not in request:
            raise ValueError("Request must include a messages array")
        return request

    messages = _build_messages(form)
    request: dict[str, Any] = {"messages": messages}

    model_override = form.get("model_override", "").strip()
    if model_override:
        request["model"] = model_override

    user_field = form.get("user_field", "").strip()
    if user_field:
        request["user"] = user_field

    if scenario == "tools":
        tool_names_raw = form.get("tool_names", "").strip()
        if tool_names_raw:
            names = [n.strip() for n in tool_names_raw.split(",") if n.strip()]
            if names:
                request["tools"] = [
                    {
                        "type": "function",
                        "function": {
                            "name": name,
                            "description": "",
                            "parameters": {"type": "object", "properties": {}},
                        },
                    }
                    for name in names
                ]

    return request


def _resolve_selected_policies(config, form: dict[str, str]) -> list[PolicyConfig]:
    selected: list[PolicyConfig] = []
    for policy in config.policies:
        if form.get(f"policy_{policy.id}") == "on":
            p = policy.model_copy()
            p.enabled = True
            selected.append(p)
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
                description="Ad-hoc LLM rule",
                action=action,
                checks=[CheckConfig(type="llm", instruction=instruction)],
            ))
    return selected


def _build_policy_results(policies: list[PolicyConfig], response) -> list[dict[str, Any]]:
    violation_map: dict[str, list] = {}
    for v in response.violations:
        violation_map.setdefault(v.policy_id, []).append(v)
    selected_ids = {p.id for p in policies}
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
    # Surface any violations not mapped to a selected policy (e.g. llm-evaluator-unavailable)
    for policy_id, violations in violation_map.items():
        if policy_id not in selected_ids:
            results.append({
                "policy_id": policy_id,
                "severity": violations[0].severity,
                "action": "block",
                "description": violations[0].message,
                "status": "match",
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
      <div class="muted">Blocked by policy &mdash; not sent to upstream.</div>
      <button type="button" class="button small danger" onclick="pgForceSend()" style="margin-top:8px">Force Send Anyway</button>
    """


def _source_breakdown(policy_results: list[dict]) -> str:
    sources: dict[str, int] = {}
    for pr in policy_results:
        for v in pr.get("violations", []):
            src = v.source if hasattr(v, "source") else "deterministic"
            sources[src] = sources.get(src, 0) + 1
    if not sources:
        return "no violations"
    parts = []
    for src in ["deterministic", "llm", "vision"]:
        count = sources.get(src, 0)
        if count:
            parts.append(f"{count} {src}")
    return ", ".join(parts) + " violation" + ("s" if sum(sources.values()) != 1 else "")


def _render_results(response, policy_results: list[dict], eval_ms: int, llm_response_html: str) -> str:
    has_match = any(r["status"] == "match" for r in policy_results)
    decision_class = "blocked" if has_match else "accepted"
    decision_label = "BLOCKED" if has_match else "ACCEPTED"

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

    sanitized_html = ""
    if response.sanitized_request:
        san_json = json.dumps(response.sanitized_request, indent=2, sort_keys=False, ensure_ascii=False)
        san_json_escaped = escape(san_json).replace("[REDACTED]", '<span class="redacted">[REDACTED]</span>')
        sanitized_html = f'<div class="pg-json">{san_json_escaped}</div>'
    else:
        sanitized_html = '<div class="muted">No modifications &mdash; original request passes clean.</div>'

    return f"""
      <div class="pg-results">
        <div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--muted);margin-bottom:8px">Policy Results</div>
          <div class="pg-decision {decision_class}">{decision_label}</div>
          {"".join(f'<div style="padding:8px 12px;border-radius:6px;background:var(--warning-bg);border:1px solid var(--warning-border);color:var(--warning);font-size:12px;margin-bottom:8px">{escape(w)}</div>' for w in (response.warnings or []))}
          {"".join(policy_items)}
          <div class="muted" style="font-size:11px;margin-top:12px">Policy evaluation: {eval_ms}ms &mdash; {_source_breakdown(policy_results)}</div>
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
