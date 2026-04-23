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
                <button type="button" class="button small danger" onclick="pgRemoveMessage(this)" title="Remove message" style="padding:5px 8px">&#10005;</button>
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
  row.innerHTML='<select class="pg-msg-role" name="msg_role_'+idx+'"><option value="system">system</option><option value="user" selected>user</option><option value="assistant">assistant</option></select><div style="flex:1;display:flex;flex-direction:column;gap:6px"><textarea class="pg-msg-text" name="msg_text_'+idx+'" rows="3" placeholder="Enter message..."></textarea><div class="pg-msg-images" id="pg-imgs-'+idx+'"></div><div><a href="#" onclick="pgAddImage('+idx+');return false" style="font-size:12px;color:var(--primary)">+ Add Image URL</a></div></div><button type="button" class="button small danger" onclick="pgRemoveMessage(this)" title="Remove" style="padding:5px 8px">&#10005;</button>';
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
  div.innerHTML='<input name="msg_img_'+msgIdx+'_'+c+'" placeholder="https://example.com/image.png" style="flex:1;font-size:12px" onblur="pgPreviewImg(this)"><img src="" style="max-height:60px;border-radius:4px;display:none"><button type="button" class="button small danger" onclick="this.parentNode.remove()" style="padding:3px 6px;font-size:11px">&#10005;</button>';
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
