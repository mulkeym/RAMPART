from __future__ import annotations

from html import escape
from typing import Any, Optional
from urllib.parse import parse_qs, quote

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import ValidationError

from rampart.app.client_store import ClientRecord, create_client, get_client, list_clients, rotate_client_key, set_client_enabled, update_client
from rampart.app.config import CheckConfig, PolicyConfig, get_config, get_policy_path
from rampart.app.policy_store import delete_policy, get_policy, upsert_policy
from rampart.app.security.audit import audit_event
from rampart.app.security.auth import authenticate, clear_session_cookie, read_session_user, require_ui_user, set_session_cookie
from rampart.app.security.credentials import change_password
from rampart.app.settings_store import RuntimeSettings, load_settings, save_settings
from rampart.app.tracking import load_evaluation_events, summarize_customers, summarize_policies

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def redirect_home() -> RedirectResponse:
    return RedirectResponse("/ui/policies", status_code=303)


@router.get("/login", response_class=HTMLResponse)
async def login_form(next: str = "/ui/policies", error: Optional[str] = None) -> HTMLResponse:
    return HTMLResponse(_login_page(next, error))


@router.post("/login", response_class=HTMLResponse)
async def login(request: Request) -> HTMLResponse:
    body = (await request.body()).decode("utf-8")
    form = {key: values[-1] for key, values in parse_qs(body, keep_blank_values=True).items()}
    username = form.get("username", "")
    password = form.get("password", "")
    next_url = _safe_next_url(form.get("next", "/ui/policies"))
    if not authenticate(username, password):
        audit_event(request, "auth.login", actor=username or None, result="failure", detail="invalid credentials")
        return HTMLResponse(_login_page(next_url, "Invalid username or password."), status_code=401)

    response = RedirectResponse("/change-password" if _password_change_pending(username) else next_url, status_code=303)
    set_session_cookie(response, username)
    audit_event(request, "auth.login", actor=username, result="success")
    return response


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_form(request: Request, error: Optional[str] = None) -> HTMLResponse:
    actor = read_session_user(request)
    if not actor:
        return RedirectResponse("/login?next=/change-password", status_code=303)
    return HTMLResponse(_change_password_page(actor, error))


@router.post("/change-password", response_class=HTMLResponse)
async def update_password(request: Request) -> HTMLResponse:
    actor = read_session_user(request)
    if not actor:
        audit_event(request, "auth.password_change", result="failure", detail="unauthorized")
        return RedirectResponse("/login?next=/change-password", status_code=303)

    body = (await request.body()).decode("utf-8")
    form = {key: values[-1] for key, values in parse_qs(body, keep_blank_values=True).items()}
    current_password = form.get("current_password", "")
    new_password = form.get("new_password", "")
    confirm_password = form.get("confirm_password", "")
    if new_password != confirm_password:
        audit_event(request, "auth.password_change", actor=actor, result="failure", detail="confirmation mismatch")
        return HTMLResponse(_change_password_page(actor, "New password and confirmation do not match."), status_code=400)

    error = change_password(actor, current_password, new_password, get_config().auth)
    if error:
        audit_event(request, "auth.password_change", actor=actor, result="failure", detail=error)
        return HTMLResponse(_change_password_page(actor, error), status_code=400)

    response = RedirectResponse("/ui/policies?message=Password+changed", status_code=303)
    set_session_cookie(response, actor, password_change_pending=False)
    audit_event(request, "auth.password_change", actor=actor, result="success")
    return response


@router.post("/logout", response_class=HTMLResponse)
async def logout(request: Request) -> RedirectResponse:
    actor = read_session_user(request)
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(response)
    audit_event(request, "auth.logout", actor=actor, result="success")
    return response


@router.get("/ui", response_class=HTMLResponse)
async def redirect_ui(request: Request) -> RedirectResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui")
        return redirect
    return RedirectResponse("/ui/policies", status_code=303)


@router.get("/ui/policies", response_class=HTMLResponse)
async def policies_index(request: Request, message: Optional[str] = None, error: Optional[str] = None) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/policies")
        return redirect
    config = get_config()
    events = load_evaluation_events(config.tracking.log_path)
    rows = "\n".join(_policy_row(policy) for policy in config.policies)
    body = f"""
      <section class="toolbar">
        <div>
          <h1>Policies</h1>
          <p>{escape(str(get_policy_path()))}</p>
        </div>
        <a class="button primary" href="/ui/policies/new">New Policy</a>
      </section>
      {_notice(message, error)}
      {_policy_stats_cards(config, events)}
      <section class="panel">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Status</th>
              <th>Severity</th>
              <th>Category</th>
              <th>Action</th>
              <th>Checks</th>
              <th></th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
      </section>
    """
    return HTMLResponse(_page("RAMPART Policies", body, read_session_user(request)))


@router.get("/ui/violations", response_class=HTMLResponse)
async def violations_index(request: Request, customer: Optional[str] = None, client_id: Optional[str] = None) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/violations")
        return redirect

    config = get_config()
    events = load_evaluation_events(config.tracking.log_path)
    customer_rows = "\n".join(_customer_summary_row(summary) for summary in summarize_customers(events))
    policy_rows = "\n".join(_policy_summary_row(summary) for summary in summarize_policies(events, customer, client_id))
    selected = ""
    if customer or client_id:
        selected = f"<p>Filtered by customer <code>{escape(customer or '*')}</code> and client <code>{escape(client_id or '*')}</code>.</p>"
    body = f"""
      <section class="toolbar">
        <div>
          <h1>Violations</h1>
          <p>{escape(config.tracking.log_path)}</p>
          {selected}
        </div>
      </section>
      {_violation_stats_cards(events)}
      <section class="panel">
        <table>
          <thead>
            <tr>
              <th>Customer</th>
              <th>Client</th>
              <th>Failed Requests</th>
              <th>Violations</th>
              <th>High/Critical</th>
              <th>Last Seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>{customer_rows or _empty_row(7, "No violation events recorded yet.")}</tbody>
        </table>
      </section>
      <section class="toolbar secondary">
        <div>
          <h1>Policy Breakdown</h1>
          <p>Counts are grouped by customer, client, policy, severity, and category.</p>
        </div>
      </section>
      <section class="panel">
        <table>
          <thead>
            <tr>
              <th>Customer</th>
              <th>Client</th>
              <th>Policy</th>
              <th>Severity</th>
              <th>Category</th>
              <th>Count</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>{policy_rows or _empty_row(7, "No policy violations match this view.")}</tbody>
        </table>
      </section>
    """
    return HTMLResponse(_page("RAMPART Violations", body, read_session_user(request)))


@router.get("/ui/settings", response_class=HTMLResponse)
async def settings_page(request: Request, message: Optional[str] = None, error: Optional[str] = None) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/settings")
        return redirect
    config = get_config()
    settings = load_settings(config.settings.path)
    return HTMLResponse(_settings_form(config, settings, message=message, error=error, actor=read_session_user(request)))


@router.post("/ui/settings", response_class=HTMLResponse)
async def update_settings(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "settings.update", result="failure", detail="unauthorized")
        return redirect
    actor = read_session_user(request)
    config = get_config()
    form = await _form_data(request)
    try:
        settings = RuntimeSettings(
            llm_evaluator_base_url=form.get("llm_evaluator_base_url", "").strip(),
            llm_evaluator_model=form.get("llm_evaluator_model", "").strip(),
            llm_evaluator_timeout_seconds=_optional_float(form.get("llm_evaluator_timeout_seconds", "")),
            vision_evaluator_enabled=form.get("vision_evaluator_enabled") == "on",
            vision_evaluator_base_url=form.get("vision_evaluator_base_url", "").strip(),
            vision_evaluator_model=form.get("vision_evaluator_model", "").strip(),
            vision_evaluator_timeout_seconds=_optional_float(form.get("vision_evaluator_timeout_seconds", "")),
            upstream_enabled=form.get("upstream_enabled") == "on",
            upstream_base_url=form.get("upstream_base_url", "").strip(),
            upstream_model=form.get("upstream_model", "").strip(),
            upstream_api_key=form.get("upstream_api_key", "").strip(),
            upstream_timeout_seconds=_optional_float(form.get("upstream_timeout_seconds", "")),
        )
    except ValueError as error:
        audit_event(request, "settings.update", actor=actor, result="failure", detail=str(error))
        return HTMLResponse(_settings_form(config, load_settings(config.settings.path), error=str(error), actor=actor), status_code=400)
    save_settings(settings, config.settings.path)
    audit_event(request, "settings.update", actor=actor, result="success")
    return RedirectResponse("/ui/settings?message=Settings+saved", status_code=303)


@router.get("/ui/clients", response_class=HTMLResponse)
async def clients_index(request: Request, message: Optional[str] = None, api_key: Optional[str] = None) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/clients")
        return redirect
    rows = "\n".join(_client_row(client) for client in list_clients(get_config().clients.path))
    key_notice = _api_key_notice(api_key)
    body = f"""
      <section class="toolbar">
        <div>
          <h1>API Keys</h1>
          <p>{escape(get_config().clients.path)}</p>
        </div>
        <a class="button primary" href="/ui/clients/new">New API Key</a>
      </section>
      {_notice(message, None)}
      {key_notice}
      <section class="panel">
        <table>
          <thead>
            <tr>
              <th>Client ID</th>
              <th>Customer</th>
              <th>App</th>
              <th>Owner</th>
              <th>Status</th>
              <th>Last Used</th>
              <th></th>
            </tr>
          </thead>
          <tbody>{rows or _empty_row(7, "No API keys have been created yet.")}</tbody>
        </table>
      </section>
    """
    return HTMLResponse(_page("RAMPART API Keys", body, read_session_user(request)))


@router.get("/ui/clients/new", response_class=HTMLResponse)
async def new_client(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/clients/new")
        return redirect
    return HTMLResponse(_client_form(None, "Create API Key", "/ui/clients/new", actor=read_session_user(request)))


@router.post("/ui/clients/new", response_class=HTMLResponse)
async def create_client_route(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "client.create", result="failure", detail="unauthorized")
        return redirect
    actor = read_session_user(request)
    form = await _form_data(request)
    client_id = _clean_policy_id(form.get("id", ""))
    if not client_id or not form.get("customer", "").strip() or not form.get("app_name", "").strip():
        return HTMLResponse(_client_form(None, "Create API Key", "/ui/clients/new", "Client ID, customer, and app name are required.", actor, form), status_code=400)
    try:
        created = create_client(
            client_id=client_id,
            customer=form.get("customer", "").strip(),
            app_name=form.get("app_name", "").strip(),
            owner_name=form.get("owner_name", "").strip(),
            owner_email=form.get("owner_email", "").strip(),
            team=form.get("team", "").strip(),
            environment=form.get("environment", "production").strip() or "production",
            upstream_base_url=form.get("upstream_base_url", "").strip(),
            upstream_model=form.get("upstream_model", "").strip(),
            upstream_api_key=form.get("upstream_api_key", "").strip(),
            upstream_timeout_seconds=_optional_float(form.get("upstream_timeout_seconds", "")),
            notes=form.get("notes", "").strip(),
            policy_ids=_selected_policy_ids(form),
            path=get_config().clients.path,
        )
    except ValueError as error:
        audit_event(request, "client.create", actor=actor, result="failure", detail=str(error))
        return HTMLResponse(_client_form(None, "Create API Key", "/ui/clients/new", str(error), actor, form), status_code=400)
    audit_event(request, "client.create", actor=actor, target=created.client.id, result="success")
    return RedirectResponse(f"/ui/clients?message=API+key+created&api_key={quote(created.api_key)}", status_code=303)


@router.get("/ui/clients/{client_id}", response_class=HTMLResponse)
async def edit_client(client_id: str, request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target=f"/ui/clients/{client_id}")
        return redirect
    client = get_client(client_id, get_config().clients.path)
    if not client:
        return HTMLResponse(_page("Client Not Found", f"<p>Client <code>{escape(client_id)}</code> was not found.</p>", read_session_user(request)), status_code=404)
    return HTMLResponse(_client_form(client, f"Edit {client.id}", f"/ui/clients/{client.id}", actor=read_session_user(request)))


@router.post("/ui/clients/{client_id}", response_class=HTMLResponse)
async def update_client_route(client_id: str, request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "client.update", target=client_id, result="failure", detail="unauthorized")
        return redirect
    actor = read_session_user(request)
    existing = get_client(client_id, get_config().clients.path)
    if not existing:
        return HTMLResponse(_page("Client Not Found", f"<p>Client <code>{escape(client_id)}</code> was not found.</p>", actor), status_code=404)
    form = await _form_data(request)
    existing.customer = form.get("customer", "").strip()
    existing.app_name = form.get("app_name", "").strip()
    existing.owner_name = form.get("owner_name", "").strip()
    existing.owner_email = form.get("owner_email", "").strip()
    existing.team = form.get("team", "").strip()
    existing.environment = form.get("environment", "production").strip() or "production"
    existing.upstream_base_url = form.get("upstream_base_url", "").strip()
    existing.upstream_model = form.get("upstream_model", "").strip()
    existing.upstream_api_key = form.get("upstream_api_key", "").strip()
    existing.upstream_timeout_seconds = _optional_float(form.get("upstream_timeout_seconds", ""))
    existing.notes = form.get("notes", "").strip()
    existing.policy_ids = _selected_policy_ids(form)
    existing.enabled = form.get("enabled") == "on"
    if not existing.customer or not existing.app_name:
        return HTMLResponse(_client_form(existing, f"Edit {client_id}", f"/ui/clients/{client_id}", "Customer and app name are required.", actor), status_code=400)
    update_client(existing, get_config().clients.path)
    audit_event(request, "client.update", actor=actor, target=client_id, result="success")
    return RedirectResponse(f"/ui/clients?message=Client+{client_id}+saved", status_code=303)


@router.post("/ui/clients/{client_id}/toggle", response_class=HTMLResponse)
async def toggle_client(client_id: str, request: Request) -> RedirectResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "client.toggle", target=client_id, result="failure", detail="unauthorized")
        return redirect
    client = get_client(client_id, get_config().clients.path)
    if client:
        set_client_enabled(client_id, not client.enabled, get_config().clients.path)
        audit_event(request, "client.toggle", actor=read_session_user(request), target=client_id, result="success", detail=f"enabled={not client.enabled}")
    return RedirectResponse("/ui/clients?message=Client+status+updated", status_code=303)


@router.post("/ui/clients/{client_id}/rotate", response_class=HTMLResponse)
async def rotate_client(client_id: str, request: Request) -> RedirectResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "client.rotate_key", target=client_id, result="failure", detail="unauthorized")
        return redirect
    created = rotate_client_key(client_id, get_config().clients.path)
    audit_event(request, "client.rotate_key", actor=read_session_user(request), target=client_id, result="success")
    return RedirectResponse(f"/ui/clients?message=API+key+rotated&api_key={quote(created.api_key)}", status_code=303)


@router.get("/ui/policies/new", response_class=HTMLResponse)
async def new_policy(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/policies/new")
        return redirect
    policy = PolicyConfig(
        id="",
        checks=[
            CheckConfig(
                type="llm",
                instruction="Describe the policy in plain language. The evaluator will apply this rule by meaning and context.",
            )
        ],
    )
    return HTMLResponse(_policy_form(policy, "Create Policy", "/ui/policies/new", actor=read_session_user(request)))


@router.post("/ui/policies/new", response_class=HTMLResponse)
async def create_policy(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "policy.create", result="failure", detail="unauthorized")
        return redirect
    actor = read_session_user(request)
    policy, error = await _policy_from_form(request)
    if error or policy is None:
        audit_event(request, "policy.create", actor=actor, result="failure", detail=error)
        return HTMLResponse(_policy_form(policy or PolicyConfig(id=""), "Create Policy", "/ui/policies/new", error, actor), status_code=400)
    if get_policy(policy.id) is not None:
        audit_event(request, "policy.create", actor=actor, target=policy.id, result="failure", detail="duplicate policy")
        return HTMLResponse(_policy_form(policy, "Create Policy", "/ui/policies/new", f"Policy '{policy.id}' already exists.", actor), status_code=400)
    upsert_policy(policy)
    audit_event(request, "policy.create", actor=actor, target=policy.id, result="success")
    return RedirectResponse(f"/ui/policies?message=Policy+{policy.id}+created", status_code=303)


@router.get("/ui/policies/{policy_id}", response_class=HTMLResponse)
async def edit_policy(policy_id: str, request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target=f"/ui/policies/{policy_id}")
        return redirect
    policy = get_policy(policy_id)
    if policy is None:
        return HTMLResponse(_page("Policy Not Found", f"<p>Policy <code>{escape(policy_id)}</code> was not found.</p>", read_session_user(request)), status_code=404)
    return HTMLResponse(_policy_form(policy, f"Edit {policy.id}", f"/ui/policies/{policy.id}", actor=read_session_user(request)))


@router.post("/ui/policies/{policy_id}", response_class=HTMLResponse)
async def update_policy(policy_id: str, request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "policy.update", target=policy_id, result="failure", detail="unauthorized")
        return redirect
    actor = read_session_user(request)
    policy, error = await _policy_from_form(request, original_id=policy_id)
    if error or policy is None:
        fallback = get_policy(policy_id) or policy or PolicyConfig(id=policy_id)
        audit_event(request, "policy.update", actor=actor, target=policy_id, result="failure", detail=error)
        return HTMLResponse(_policy_form(fallback, f"Edit {policy_id}", f"/ui/policies/{policy_id}", error, actor), status_code=400)
    if policy.id != policy_id and get_policy(policy.id) is not None:
        audit_event(request, "policy.update", actor=actor, target=policy_id, result="failure", detail="duplicate policy")
        return HTMLResponse(_policy_form(policy, f"Edit {policy_id}", f"/ui/policies/{policy_id}", f"Policy '{policy.id}' already exists.", actor), status_code=400)
    if policy.id != policy_id:
        delete_policy(policy_id)
    upsert_policy(policy)
    audit_event(request, "policy.update", actor=actor, target=policy.id, result="success")
    return RedirectResponse(f"/ui/policies?message=Policy+{policy.id}+saved", status_code=303)


@router.post("/ui/policies/{policy_id}/delete", response_class=HTMLResponse)
async def remove_policy(policy_id: str, request: Request) -> RedirectResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "policy.delete", target=policy_id, result="failure", detail="unauthorized")
        return redirect
    actor = read_session_user(request)
    delete_policy(policy_id)
    audit_event(request, "policy.delete", actor=actor, target=policy_id, result="success")
    return RedirectResponse("/ui/policies?message=Policy+deleted", status_code=303)


async def _policy_from_form(request: Request, original_id: Optional[str] = None) -> tuple[Optional[PolicyConfig], Optional[str]]:
    form = await _form_data(request)
    try:
        checks_data = yaml.safe_load(form.get("checks_yaml", "[]")) or []
        if not isinstance(checks_data, list):
            return None, "Checks YAML must be a list."
        validation_error = _validate_checks_data(checks_data)
        if validation_error:
            return None, validation_error
        policy = PolicyConfig(
            id=_clean_policy_id(form.get("id", "")),
            enabled=form.get("enabled") == "on",
            severity=form.get("severity", "medium"),
            category=form.get("category", "policy").strip() or "policy",
            description=form.get("description", "").strip(),
            action=form.get("action", "block"),
            checks=[CheckConfig.model_validate(check) for check in checks_data],
        )
    except (ValidationError, yaml.YAMLError, TypeError, ValueError) as error:
        return None, str(error)

    if not policy.id:
        return None, "Policy ID is required."
    if original_id and "/" in policy.id:
        return None, "Policy ID cannot contain '/'."
    return policy, None


async def _form_data(request: Request) -> dict[str, str]:
    body = (await request.body()).decode("utf-8")
    parsed = parse_qs(body, keep_blank_values=True)
    form = {key: values[-1] for key, values in parsed.items()}
    if "policy_ids" in parsed:
        form["policy_ids"] = ",".join(value for value in parsed["policy_ids"] if value)
    return form


def _validate_checks_data(checks_data: list[Any]) -> Optional[str]:
    for index, check in enumerate(checks_data):
        if not isinstance(check, dict):
            return f"Check {index + 1} must be a mapping."
        check_type = check.get("type")
        if check_type == "regex" and not str(check.get("pattern") or "").strip():
            return f"Check {index + 1} is a regex check and requires a pattern."
        if check_type == "llm" and not str(check.get("instruction") or "").strip():
            return f"Check {index + 1} is an LLM check and requires an instruction."
        if check_type == "tool_allowlist" and not isinstance(check.get("allowed_tools"), list):
            return f"Check {index + 1} is a tool allowlist and requires allowed_tools."
        if check_type == "tool_denylist" and not isinstance(check.get("denied_tools"), list):
            return f"Check {index + 1} is a tool denylist and requires denied_tools."
        if check_type == "model_allowlist" and not isinstance(check.get("allowed_models"), list):
            return f"Check {index + 1} is a model allowlist and requires allowed_models."
        if check_type == "max_chars" and not isinstance(check.get("max_chars"), int):
            return f"Check {index + 1} is a max_chars check and requires an integer max_chars."
    return None


def _clean_policy_id(value: str) -> str:
    return value.strip().replace(" ", "-")


def _policy_form(policy: PolicyConfig, title: str, action_url: str, error: Optional[str] = None, actor: Optional[str] = None) -> str:
    checks_yaml = yaml.safe_dump(
        [check.model_dump(exclude_none=True) for check in policy.checks],
        sort_keys=False,
        allow_unicode=False,
    ).strip()
    checked = "checked" if policy.enabled else ""
    body = f"""
      <section class="toolbar">
        <div>
          <h1>{escape(title)}</h1>
          <p>Changes are validated and saved to the active policy YAML file.</p>
        </div>
        <a class="button" href="/ui/policies">Back</a>
      </section>
      {_notice(None, error)}
      <form class="panel form" method="post" action="{escape(action_url)}">
        <label>Policy ID<input name="id" value="{escape(policy.id)}" required></label>
        <label class="checkbox"><input type="checkbox" name="enabled" {checked}> Enabled</label>
        <label>Severity{_select("severity", ["low", "medium", "high", "critical"], policy.severity)}</label>
        <label>Category<input name="category" value="{escape(policy.category)}"></label>
        <label>Action{_select("action", ["block", "warn"], policy.action)}</label>
        <label>Description<textarea name="description" rows="3">{escape(policy.description)}</textarea></label>
        <label>Checks YAML<textarea name="checks_yaml" rows="14" spellcheck="false">{escape(checks_yaml)}</textarea></label>
        <div class="hint">
          Use <code>type: llm</code> with an <code>instruction</code> for context-aware policy rules.
          Use <code>type: regex</code> with a <code>pattern</code> for exact deterministic matches.
        </div>
        <div class="actions">
          <button class="button primary" type="submit">Save Policy</button>
        </div>
      </form>
    """
    return _page(title, body, actor)


def _policy_row(policy: PolicyConfig) -> str:
    status = "enabled" if policy.enabled else "disabled"
    return f"""
      <tr>
        <td><code>{escape(policy.id)}</code><div class="muted">{escape(policy.description)}</div></td>
        <td><span class="pill {status}">{status}</span></td>
        <td>{_severity_pill(policy.severity)}</td>
        <td>{escape(policy.category)}</td>
        <td>{escape(policy.action)}</td>
        <td>{len(policy.checks)}</td>
        <td class="row-actions">
          <a class="button small" href="/ui/policies/{escape(policy.id)}">Edit</a>
          <form class="confirm-action" method="post" action="/ui/policies/{escape(policy.id)}/delete" data-confirm-title="Delete Policy?" data-confirm-message="Are you sure you want to delete {escape(policy.id)}? This cannot be undone.">
            <button class="button small danger" type="submit">Delete</button>
          </form>
        </td>
      </tr>
    """


def _client_row(client: ClientRecord) -> str:
    status = "enabled" if client.enabled else "disabled"
    toggle_label = "Disable" if client.enabled else "Enable"
    toggle_class = "button small danger" if client.enabled else "button small success"
    owner = client.owner_email or client.owner_name
    return f"""
      <tr>
        <td><code>{escape(client.id)}</code><div class="muted">{escape(client.team)}</div></td>
        <td>{escape(client.customer)}</td>
        <td>{escape(client.app_name)}<div class="muted">{escape(client.environment)}</div></td>
        <td>{escape(owner)}</td>
        <td><span class="pill {status}">{status}</span></td>
        <td><code>{escape(client.last_used_at or "")}</code></td>
        <td class="row-actions">
          <a class="button small" href="/ui/clients/{escape(client.id)}">Edit</a>
          <form class="confirm-action" method="post" action="/ui/clients/{escape(client.id)}/toggle" data-confirm-title="{toggle_label} Client?" data-confirm-message="Are you sure you want to {toggle_label.lower()} client {escape(client.id)}?">
            <button class="{toggle_class}" type="submit">{toggle_label}</button>
          </form>
          <form class="confirm-action" method="post" action="/ui/clients/{escape(client.id)}/rotate" data-confirm-title="Rotate API Key?" data-confirm-message="This will invalidate the current API key for {escape(client.id)}. The new key will be shown only once.">
            <button class="button small danger" type="submit">Rotate</button>
          </form>
        </td>
      </tr>
    """


def _settings_form(config, settings: RuntimeSettings, message: Optional[str] = None, error: Optional[str] = None, actor: Optional[str] = None) -> str:
    get_value = lambda field, default="": escape(_string_value(getattr(settings, field, default)))
    body = f"""
      <section class="toolbar">
        <div>
          <h1>Settings</h1>
          <p>{escape(config.settings.path)}</p>
        </div>
      </section>
      {_notice(message, error)}
      <form class="panel form" method="post" action="/ui/settings">
        <fieldset class="fieldset">
          <legend>Context Analysis LLM</legend>
          <div class="hint">Used for context-aware policy evaluation.</div>
          <label>Base URL<input name="llm_evaluator_base_url" value="{get_value("llm_evaluator_base_url", config.llm_evaluator.base_url)}" placeholder="{escape(config.llm_evaluator.base_url)}"></label>
          <label>Model<input name="llm_evaluator_model" value="{get_value("llm_evaluator_model", config.llm_evaluator.model)}" placeholder="{escape(config.llm_evaluator.model)}"></label>
          <label>Timeout Seconds<input name="llm_evaluator_timeout_seconds" value="{get_value("llm_evaluator_timeout_seconds", config.llm_evaluator.timeout_seconds)}" inputmode="decimal"></label>
        </fieldset>
        <fieldset class="fieldset">
          <legend>Vision Evaluator LLM</legend>
          <div class="hint">Used for evaluating image content against policies. Requires a vision-capable model.</div>
          <div>
            <label style="display:flex;align-items:center;gap:8px;font-weight:600;font-size:13px;color:var(--text-secondary)">Enabled <input type="checkbox" name="vision_evaluator_enabled" {"checked" if config.vision_evaluator.enabled else ""} style="width:auto"></label>
            <div class="hint" style="margin-top:4px">When enabled, images in requests are evaluated against LLM policies using this vision model.</div>
          </div>
          <label>Base URL<input name="vision_evaluator_base_url" value="{get_value("vision_evaluator_base_url", config.vision_evaluator.base_url)}" placeholder="{escape(config.vision_evaluator.base_url)}"></label>
          <label>Model<input name="vision_evaluator_model" value="{get_value("vision_evaluator_model", config.vision_evaluator.model)}" placeholder="{escape(config.vision_evaluator.model)}"></label>
          <label>Timeout Seconds<input name="vision_evaluator_timeout_seconds" value="{get_value("vision_evaluator_timeout_seconds", config.vision_evaluator.timeout_seconds)}" inputmode="decimal"></label>
        </fieldset>
        <fieldset class="fieldset">
          <legend>Default Pass-Through LLM</legend>
          <div class="hint">Used by /v1/chat/completions when an API key does not override backend settings.</div>
          <div>
            <label style="display:flex;align-items:center;gap:8px;font-weight:600;font-size:13px;color:var(--text-secondary)">Enabled <input type="checkbox" name="upstream_enabled" {"checked" if config.upstream.enabled else ""} style="width:auto"></label>
            <div class="hint" style="margin-top:4px">When disabled, requests are evaluated but not forwarded to any upstream LLM. Anonymous users cannot use the LLM.</div>
          </div>
          <label>Base URL<input name="upstream_base_url" value="{get_value("upstream_base_url", config.upstream.base_url)}" placeholder="{escape(config.upstream.base_url)}"></label>
          <label>Model<input name="upstream_model" value="{get_value("upstream_model", config.upstream.model)}" placeholder="{escape(config.upstream.model)}"></label>
          <label>API Key<input name="upstream_api_key" value="{get_value("upstream_api_key", config.upstream.api_key)}" autocomplete="off"></label>
          <label>Timeout Seconds<input name="upstream_timeout_seconds" value="{get_value("upstream_timeout_seconds", config.upstream.timeout_seconds)}" inputmode="decimal"></label>
        </fieldset>
        <div class="actions"><button class="button primary" type="submit">Save Settings</button></div>
      </form>
    """
    return _page("RAMPART Settings", body, actor)


def _client_form(client: Optional[ClientRecord], title: str, action_url: str, error: Optional[str] = None, actor: Optional[str] = None, form: Optional[dict[str, str]] = None) -> str:
    form = form or {}
    get_value = lambda field, default="": escape(_string_value(form.get(field, getattr(client, field, default) if client else default)))
    enabled = "checked" if (client.enabled if client else True) else ""
    readonly_id = "readonly" if client else ""
    selected_policy_ids = _selected_policy_ids(form) if form else (client.policy_ids if client else [])
    policy_checkboxes = _policy_assignment_checkboxes(selected_policy_ids)
    body = f"""
      <section class="toolbar">
        <div>
          <h1>{escape(title)}</h1>
          <p>API keys are stored as hashes. Raw keys are shown only once.</p>
        </div>
        <a class="button" href="/ui/clients">Back</a>
      </section>
      {_notice(None, error)}
      <form class="panel form" method="post" action="{escape(action_url)}">
        <label>Client ID<input name="id" value="{get_value("id")}" required {readonly_id}></label>
        <label>Customer<input name="customer" value="{get_value("customer")}" required></label>
        <label>App Name<input name="app_name" value="{get_value("app_name")}" required></label>
        <label>Owner Name<input name="owner_name" value="{get_value("owner_name")}"></label>
        <label>Owner Email<input name="owner_email" value="{get_value("owner_email")}"></label>
        <label>Team<input name="team" value="{get_value("team")}"></label>
        <label>Environment<input name="environment" value="{get_value("environment", "production")}"></label>
        <fieldset class="fieldset">
          <legend>Backend LLM API</legend>
          <div class="hint">Leave blank to use the global upstream endpoint.</div>
          <label>Base URL<input name="upstream_base_url" value="{get_value("upstream_base_url")}" placeholder="http://192.168.1.181:8081"></label>
          <label>Model<input name="upstream_model" value="{get_value("upstream_model")}" placeholder="gemma4-e2b"></label>
          <label>API Key<input name="upstream_api_key" value="{get_value("upstream_api_key")}" autocomplete="off"></label>
          <label>Timeout Seconds<input name="upstream_timeout_seconds" value="{get_value("upstream_timeout_seconds")}" inputmode="decimal"></label>
        </fieldset>
        <label class="checkbox"><input type="checkbox" name="enabled" {enabled}> Enabled</label>
        <fieldset class="fieldset">
          <legend>Applied Policies</legend>
          <div class="hint">If no policies are selected, all enabled policies apply.</div>
          {policy_checkboxes}
        </fieldset>
        <label>Notes<textarea name="notes" rows="4">{get_value("notes")}</textarea></label>
        <div class="actions"><button class="button primary" type="submit">Save</button></div>
      </form>
    """
    return _page(title, body, actor)


def _selected_policy_ids(form: dict[str, str]) -> list[str]:
    raw = form.get("policy_ids", "")
    return [policy_id for policy_id in raw.split(",") if policy_id]


def _string_value(value) -> str:
    if value is None:
        return ""
    return str(value)


def _optional_float(value: str) -> Optional[float]:
    value = value.strip()
    if not value:
        return None
    return float(value)


def _policy_assignment_checkboxes(selected_policy_ids: list[str]) -> str:
    selected = set(selected_policy_ids)
    items = []
    for policy in get_config().policies:
        if not policy.enabled:
            continue
        checked = "checked" if policy.id in selected else ""
        items.append(
            f"""
            <label class="checkbox policy-option">
              <input type="checkbox" name="policy_ids" value="{escape(policy.id)}" {checked}>
              <span><code>{escape(policy.id)}</code><span class="muted">{escape(policy.description)}</span></span>
            </label>
            """
        )
    return "".join(items) or '<div class="muted">No enabled policies are available.</div>'


def _api_key_notice(api_key: Optional[str]) -> str:
    if not api_key:
        return ""
    return f"""
      <div class="notice success">
        <strong>Copy this API key now. It will not be shown again.</strong>
        <div><code>{escape(api_key)}</code></div>
      </div>
    """


def _customer_summary_row(summary) -> str:
    return f"""
      <tr>
        <td>{escape(summary.customer)}</td>
        <td>{escape(summary.client_id)}</td>
        <td>{summary.failed_requests}</td>
        <td>{summary.violation_count}</td>
        <td>{summary.high_critical_count}</td>
        <td><code>{escape(summary.last_seen or "")}</code></td>
        <td><a class="button small" href="/ui/violations?customer={quote(summary.customer)}&client_id={quote(summary.client_id)}">View</a></td>
      </tr>
    """


def _policy_summary_row(summary) -> str:
    return f"""
      <tr>
        <td>{escape(summary.customer)}</td>
        <td>{escape(summary.client_id)}</td>
        <td><code>{escape(summary.policy_id)}</code></td>
        <td>{escape(summary.severity)}</td>
        <td>{escape(summary.category)}</td>
        <td>{summary.count}</td>
        <td><code>{escape(summary.last_seen or "")}</code></td>
      </tr>
    """


def _empty_row(colspan: int, message: str) -> str:
    return f'<tr><td colspan="{colspan}" class="muted">{escape(message)}</td></tr>'


def _severity_pill(severity: str) -> str:
    return f'<span class="pill severity-{escape(severity)}">{escape(severity)}</span>'


def _policy_stats_cards(config, events: list) -> str:
    from rampart.app.client_store import list_clients

    total_policies = len(config.policies)
    enabled_policies = sum(1 for p in config.policies if p.enabled)
    clients = list_clients(config.clients.path)
    total_clients = len(clients)
    active_clients = sum(1 for c in clients if c.enabled)
    failed_events = [e for e in events if e.get("decision") == "fail"]
    total_violations = sum(len(e.get("violations", [])) for e in failed_events)
    high_critical = sum(
        1 for e in failed_events for v in (e.get("violations") or [])
        if v.get("severity") in {"high", "critical"}
    )
    return f"""
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Policies</div>
          <div class="stat-value">{total_policies}</div>
          <div class="stat-sub success">{enabled_policies} enabled</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">API Keys</div>
          <div class="stat-value">{total_clients}</div>
          <div class="stat-sub success">{active_clients} active</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Violations</div>
          <div class="stat-value" style="color:{'var(--danger)' if total_violations > 0 else 'var(--text)'}">{total_violations}</div>
          <div class="stat-sub {'danger' if high_critical > 0 else 'muted'}">{high_critical} high/critical</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Failed Requests</div>
          <div class="stat-value" style="color:{'var(--warning)' if len(failed_events) > 0 else 'var(--text)'}">{len(failed_events)}</div>
          <div class="stat-sub muted">all time</div>
        </div>
      </div>
    """


def _violation_stats_cards(events: list) -> str:
    failed_events = [e for e in events if e.get("decision") == "fail"]
    total_violations = sum(len(e.get("violations", [])) for e in failed_events)
    high_critical = sum(
        1 for e in failed_events for v in (e.get("violations") or [])
        if v.get("severity") in {"high", "critical"}
    )
    customers = set(e.get("customer", "default") for e in failed_events)
    policies = set(
        v.get("policy_id", "unknown")
        for e in failed_events for v in (e.get("violations") or [])
    )
    return f"""
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Violations</div>
          <div class="stat-value" style="color:{'var(--danger)' if total_violations > 0 else 'var(--text)'}">{total_violations}</div>
          <div class="stat-sub muted">across all clients</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">High / Critical</div>
          <div class="stat-value" style="color:{'var(--danger)' if high_critical > 0 else 'var(--text)'}">{high_critical}</div>
          <div class="stat-sub {'danger' if high_critical > 0 else 'muted'}">require attention</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Customers Affected</div>
          <div class="stat-value">{len(customers)}</div>
          <div class="stat-sub muted">unique customers</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Policies Triggered</div>
          <div class="stat-value">{len(policies)}</div>
          <div class="stat-sub muted">unique policies</div>
        </div>
      </div>
    """


def _select(name: str, options: list[str], selected: str) -> str:
    items = []
    for option in options:
        selected_attr = "selected" if option == selected else ""
        items.append(f'<option value="{escape(option)}" {selected_attr}>{escape(option)}</option>')
    return f'<select name="{escape(name)}">{"".join(items)}</select>'


def _notice(message: Optional[str], error: Optional[str]) -> str:
    if error:
        return f'<div class="notice error">{escape(error)}</div>'
    if message:
        return f'<div class="notice success">{escape(message)}</div>'
    return ""


def _safe_next_url(value: str) -> str:
    if not value.startswith("/") or value.startswith("//"):
        return "/ui/policies"
    return value


def _login_page(next_url: str, error: Optional[str]) -> str:
    body = f"""
      <section class="login">
        <h1>RAMPART Login</h1>
        {_notice(None, error)}
        <form class="panel form" method="post" action="/login">
          <input type="hidden" name="next" value="{escape(_safe_next_url(next_url))}">
          <label>Username<input name="username" autocomplete="username" autofocus required></label>
          <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
          <div class="actions"><button class="button primary" type="submit">Log In</button></div>
        </form>
      </section>
    """
    return _page("Login", body, None)


def _change_password_page(actor: str, error: Optional[str]) -> str:
    body = f"""
      <section class="login">
        <h1>Change Password</h1>
        <p>The initial local admin password must be changed before managing policies.</p>
        {_notice(None, error)}
        <form class="panel form" method="post" action="/change-password">
          <label>Current Password<input name="current_password" type="password" autocomplete="current-password" autofocus required></label>
          <label>New Password<input name="new_password" type="password" autocomplete="new-password" required></label>
          <label>Confirm New Password<input name="confirm_password" type="password" autocomplete="new-password" required></label>
          <div class="actions"><button class="button primary" type="submit">Change Password</button></div>
        </form>
      </section>
    """
    return _page("Change Password", body, actor)


def _password_change_pending(username: str) -> bool:
    from rampart.app.security.credentials import password_change_required

    return password_change_required(username, get_config().auth)


def _page_script() -> str:
    return """<script>
(function(){
  var overlay=document.createElement('div');
  overlay.className='modal-overlay';
  overlay.innerHTML='<div class="modal"><h2 id="modal-title"></h2><p id="modal-msg"></p><div class="actions"><button class="button" id="modal-cancel">Cancel</button><button class="button danger" id="modal-confirm">Confirm</button></div></div>';
  document.body.appendChild(overlay);
  var pendingForm=null;
  document.getElementById('modal-cancel').onclick=function(){overlay.classList.remove('active');pendingForm=null;};
  overlay.onclick=function(e){if(e.target===overlay){overlay.classList.remove('active');pendingForm=null;}};
  document.querySelectorAll('form.confirm-action').forEach(function(form){
    form.addEventListener('submit',function(e){
      e.preventDefault();
      pendingForm=form;
      document.getElementById('modal-title').textContent=form.dataset.confirmTitle||'Are you sure?';
      document.getElementById('modal-msg').textContent=form.dataset.confirmMessage||'This action cannot be undone.';
      overlay.classList.add('active');
    });
  });
  document.getElementById('modal-confirm').onclick=function(){
    overlay.classList.remove('active');
    if(pendingForm){pendingForm.classList.remove('confirm-action');pendingForm.submit();}
  };
  document.querySelectorAll('form.panel.form').forEach(function(form){
    var inputs=form.querySelectorAll('input[required],textarea[required]');
    inputs.forEach(function(input){
      input.addEventListener('blur',function(){validateField(input);});
    });
    form.addEventListener('submit',function(e){
      var valid=true;
      inputs.forEach(function(input){if(!validateField(input))valid=false;});
      if(!valid)e.preventDefault();
    });
  });
  function validateField(input){
    var err=input.parentNode.querySelector('.field-error');
    if(!input.value.trim()){
      input.classList.add('invalid');
      if(!err){err=document.createElement('div');err.className='field-error';err.textContent=input.previousElementSibling?input.previousElementSibling.textContent+' is required':'This field is required';input.parentNode.appendChild(err);}
      return false;
    }else{
      input.classList.remove('invalid');
      if(err)err.remove();
      return true;
    }
  }
})();
</script>"""


def _page(title: str, body: str, actor: Optional[str] = None) -> str:
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
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)} - RAMPART</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='0' y2='1'%3E%3Cstop offset='0' stop-color='%2338bdf8'/%3E%3Cstop offset='1' stop-color='%230e7490'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath d='M32 2L6 14v18c0 16.6 11.1 31.1 26 34 14.9-2.9 26-17.4 26-34V14L32 2z' fill='%230b0f14' stroke='url(%23g)' stroke-width='3'/%3E%3Cpath d='M32 12L14 20v12c0 11 7.4 20.7 18 22.6 10.6-1.9 18-11.6 18-22.6V20L32 12z' fill='none' stroke='%2338bdf8' stroke-width='1.5' opacity='.3'/%3E%3Cpath d='M26 30h12M26 36h12M26 42h8' stroke='%2338bdf8' stroke-width='2.5' stroke-linecap='round'/%3E%3Ccircle cx='21' cy='30' r='2' fill='%234ade80'/%3E%3Ccircle cx='21' cy='36' r='2' fill='%234ade80'/%3E%3Ccircle cx='21' cy='42' r='2' fill='%23f87171'/%3E%3Cpath d='M32 12L14 20v12c0 11 7.4 20.7 18 22.6' fill='%2338bdf8' opacity='.06'/%3E%3C/svg%3E">
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0b0f14;
      --bg-header: #111820;
      --panel: #151d27;
      --panel-hover: #1c2737;
      --text: #e2e8f0;
      --text-secondary: #94a3b8;
      --muted: #64748b;
      --border: rgba(255,255,255,0.08);
      --border-strong: rgba(255,255,255,0.12);
      --primary: #38bdf8;
      --primary-hover: #22d3ee;
      --primary-text: #0b0f14;
      --success: #4ade80;
      --success-bg: rgba(74,222,128,0.08);
      --success-border: rgba(74,222,128,0.2);
      --danger: #f87171;
      --danger-bg: rgba(248,113,113,0.08);
      --danger-border: rgba(248,113,113,0.2);
      --warning: #fbbf24;
      --warning-bg: rgba(251,191,36,0.08);
      --warning-border: rgba(251,191,36,0.2);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.5;
    }}
    header {{
      background: var(--bg-header);
      color: #ffffff;
      padding: 14px 28px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid rgba(56,189,248,0.15);
    }}
    header a {{ color: rgba(255,255,255,0.55); text-decoration: none; font-weight: 600; font-size: 13px; transition: color 0.15s; }}
    header a:hover {{ color: var(--primary); }}
    header a.active {{ color: var(--primary); font-weight: 600; border-bottom: 2px solid var(--primary); padding-bottom: 2px; }}
    .brand {{ display: flex; gap: 10px; align-items: baseline; }}
    .brand-name {{ font-weight: 700; color: var(--primary); letter-spacing: 1.5px; font-size: 15px; }}
    .brand-full {{ color: rgba(255,255,255,0.4); font-size: 13px; font-weight: 400; }}
    header nav {{ display: flex; gap: 18px; align-items: center; }}
    header form {{ margin: 0; display: flex; gap: 12px; align-items: center; }}
    header button {{ background: transparent; color: #ffffff; border: 1px solid rgba(255,255,255,.35); border-radius: 6px; padding: 6px 10px; cursor: pointer; font-size: 12px; transition: filter 0.15s; }}
    header button:hover {{ filter: brightness(1.3); }}
    .nav-links {{ display: flex; gap: 12px; align-items: center; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    h1 {{ margin: 0; font-size: 26px; font-weight: 700; letter-spacing: 0; color: var(--text); }}
    p {{ margin: 6px 0 0; color: var(--muted); }}
    .toolbar {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 18px; }}
    .toolbar.secondary {{ margin-top: 28px; }}
    .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: top; }}
    th {{ font-size: 11px; text-transform: uppercase; color: var(--muted); background: var(--panel-hover); letter-spacing: 0.5px; }}
    tr:last-child td {{ border-bottom: 0; }}
    tbody tr {{ transition: background 0.15s; }}
    tbody tr:nth-child(even) {{ background: rgba(255,255,255,0.02); }}
    tbody tr:hover {{ background: rgba(255,255,255,0.04); }}
    code {{ font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; color: var(--primary); }}
    .muted {{ color: var(--muted); margin-top: 4px; max-width: 520px; }}
    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 36px;
      padding: 7px 14px;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 6px;
      background: rgba(255,255,255,0.06);
      color: var(--text-secondary);
      text-decoration: none;
      font: inherit;
      cursor: pointer;
      white-space: nowrap;
      transition: filter 0.15s;
    }}
    .button:hover {{ filter: brightness(1.15); }}
    .button.primary {{ background: var(--primary); border-color: var(--primary); color: var(--primary-text); font-weight: 600; }}
    .button.small {{ min-height: 30px; padding: 5px 9px; font-size: 13px; }}
    .button.danger {{ background: var(--danger-bg); color: var(--danger); border-color: var(--danger-border); }}
    .button.success {{ background: var(--success-bg); color: var(--success); border-color: var(--success-border); }}
    .row-actions {{ display: flex; gap: 6px; align-items: center; justify-content: flex-end; }}
    .row-actions form {{ margin: 0; }}
    .pill {{ display: inline-flex; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; border: 1px solid var(--border); }}
    .pill.enabled {{ color: var(--success); background: rgba(74,222,128,0.12); }}
    .pill.disabled {{ color: var(--muted); background: rgba(100,116,139,0.15); }}
    .pill.severity-critical {{ color: var(--danger); background: var(--danger-bg); border-color: var(--danger-border); }}
    .pill.severity-high {{ color: #fb923c; background: rgba(251,146,60,0.08); border-color: rgba(251,146,60,0.2); }}
    .pill.severity-medium {{ color: var(--warning); background: var(--warning-bg); border-color: var(--warning-border); }}
    .pill.severity-low {{ color: var(--text-secondary); background: rgba(148,163,184,0.08); border-color: rgba(148,163,184,0.2); }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .stat-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
    .stat-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); margin-bottom: 8px; }}
    .stat-value {{ font-size: 28px; font-weight: 700; color: var(--text); }}
    .stat-sub {{ font-size: 13px; margin-top: 4px; }}
    .stat-sub.success {{ color: var(--success); }}
    .stat-sub.danger {{ color: var(--danger); }}
    .stat-sub.warning {{ color: var(--warning); }}
    .stat-sub.muted {{ color: var(--muted); }}
    .form {{ padding: 20px; display: grid; gap: 16px; }}
    label {{ display: grid; gap: 5px; font-weight: 600; font-size: 13px; color: var(--text-secondary); }}
    .checkbox {{ display: flex; align-items: center; gap: 8px; }}
    .policy-option {{ align-items: flex-start; font-weight: 400; }}
    .policy-option input {{ width: auto; margin-top: 3px; }}
    .fieldset {{ border: 1px solid var(--border); border-radius: 6px; padding: 12px; display: grid; gap: 10px; }}
    .fieldset legend {{ font-weight: 600; padding: 0 6px; color: var(--text-secondary); }}
    input, select, textarea {{
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 9px 10px;
      font: inherit;
      background: var(--bg);
      color: var(--text);
      transition: border-color 0.15s, box-shadow 0.15s;
    }}
    input:focus, select:focus, textarea:focus {{ outline: none; border-color: rgba(56,189,248,0.5); box-shadow: 0 0 0 3px rgba(56,189,248,0.08); }}
    input.invalid, textarea.invalid {{ border-color: rgba(248,113,113,0.5); box-shadow: 0 0 0 3px rgba(248,113,113,0.08); }}
    .field-error {{ color: var(--danger); font-size: 12px; font-weight: 400; }}
    textarea {{ resize: vertical; font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; }}
    .actions {{ display: flex; justify-content: flex-end; }}
    .hint {{ color: var(--muted); font-size: 13px; margin-top: -8px; }}
    .notice {{ padding: 11px 13px; border-radius: 6px; margin-bottom: 16px; animation: fadeIn 0.2s ease-out; }}
    .notice.success {{ background: var(--success-bg); border: 1px solid var(--success-border); color: var(--success); }}
    .notice.error {{ background: var(--danger-bg); border: 1px solid var(--danger-border); color: var(--danger); white-space: pre-wrap; }}
    .login {{ max-width: 420px; margin: 48px auto; }}
    .login h1 {{ color: var(--primary); }}
    .pg-layout {{ display: flex; flex-direction: column; gap: 18px; }}
    .pg-input {{ display: flex; gap: 16px; }}
    .pg-messages {{ flex: 3; display: flex; flex-direction: column; gap: 10px; min-width: 0; }}
    .pg-policies {{ flex: 2; display: flex; flex-direction: column; align-items: stretch; min-width: 0; }}
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
    .modal-overlay {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 1000; align-items: center; justify-content: center; }}
    .modal-overlay.active {{ display: flex; }}
    .modal {{ background: var(--panel); border: 1px solid var(--border-strong); border-radius: 10px; padding: 28px; max-width: 480px; width: 90%; animation: fadeIn 0.2s ease-out; }}
    @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
    @media (max-width: 760px) {{
      main {{ padding: 18px; }}
      .toolbar {{ align-items: stretch; flex-direction: column; }}
      table {{ display: block; overflow-x: auto; }}
      .row-actions {{ justify-content: flex-start; }}
      .stats-grid {{ grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }}
      .pg-input {{ flex-direction: column; }}
      .pg-results {{ flex-direction: column; }}
      .pg-results > div {{ max-height: none; }}
    }}
  </style>
</head>
<body>
  <header><a class="brand" href="/ui/policies"><span class="brand-name">RAMPART</span><span class="brand-full">Request And Model Prompt Analysis &amp; Routing Tool</span></a><nav>{auth_nav}</nav></header>
  <main>{body}</main>
  {_page_script()}
</body>
</html>"""
