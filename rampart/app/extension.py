from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from rampart.app.security.auth import read_session_user, require_ui_user
from rampart.app.security.audit import audit_event
from rampart.app.ui import _page

router = APIRouter(include_in_schema=False)

EXTENSION_DIR = Path(__file__).resolve().parents[2] / "extension"


@router.get("/ui/extension", response_class=HTMLResponse)
async def extension_page(request: Request) -> HTMLResponse:
    redirect = require_ui_user(request)
    if redirect:
        audit_event(request, "ui.unauthorized", result="failure", target="/ui/extension")
        return redirect
    actor = read_session_user(request)
    server_url = f"{request.url.scheme}://{request.headers.get('host', 'localhost:8080')}"
    body = f"""
      <section class="toolbar">
        <div>
          <h1>Chrome Extension</h1>
          <p>Intercept and evaluate ChatGPT prompts with RAMPART policies.</p>
        </div>
      </section>
      <section class="panel" style="padding:24px">
        <h2 style="font-size:18px;margin-bottom:16px;color:var(--text)">Setup Instructions</h2>
        <ol style="color:var(--text-secondary);line-height:2;padding-left:20px">
          <li>Click the download button below to get the extension ZIP</li>
          <li>Unzip the downloaded file</li>
          <li>Open Chrome and go to <code>chrome://extensions</code></li>
          <li>Enable <strong>Developer mode</strong> (top right toggle)</li>
          <li>Click <strong>Load unpacked</strong> and select the unzipped folder</li>
          <li>The RAMPART icon appears in your toolbar &mdash; click it to verify the connection</li>
          <li>Visit <a href="https://chatgpt.com" target="_blank" style="color:var(--primary)">chatgpt.com</a> and your prompts will be evaluated automatically</li>
        </ol>
        <div style="margin-top:20px;display:flex;gap:12px;align-items:center">
          <a class="button primary" href="/ui/extension/download" style="text-decoration:none">Download Extension (.zip)</a>
          <span class="muted" style="font-size:12px">Pre-configured for <code>{server_url}</code></span>
        </div>
      </section>
    """
    return HTMLResponse(_page("RAMPART Extension", body, actor))


@router.get("/ui/extension/download")
async def download_extension(request: Request):
    redirect = require_ui_user(request)
    if redirect:
        return redirect

    server_url = f"{request.url.scheme}://{request.headers.get('host', 'localhost:8080')}"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(EXTENSION_DIR.rglob('*')):
            if file_path.is_file():
                rel_path = file_path.relative_to(EXTENSION_DIR)
                content = file_path.read_bytes()
                # Inject server URL into popup.js
                if rel_path.name == 'popup.js':
                    content = content.replace(
                        b"'http://localhost:8080'",
                        f"'{server_url}'".encode()
                    )
                zf.writestr(f"rampart-extension/{rel_path}", content)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=rampart-extension.zip"},
    )
