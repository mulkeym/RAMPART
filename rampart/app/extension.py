from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response, StreamingResponse

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
          <h1>Browser Extension</h1>
          <p>Intercept and evaluate AI prompts with RAMPART policies. Supports Chrome and Firefox.</p>
        </div>
      </section>
      <section class="panel" style="padding:24px">
        <h2 style="font-size:18px;margin-bottom:16px;color:var(--text)">Chrome / Edge Setup</h2>
        <ol style="color:var(--text-secondary);line-height:2;padding-left:20px">
          <li>Download the Chrome extension below</li>
          <li>Unzip the downloaded file</li>
          <li>Open Chrome and go to <code>chrome://extensions</code></li>
          <li>Enable <strong>Developer mode</strong> (top right toggle)</li>
          <li>Click <strong>Load unpacked</strong> and select the unzipped folder</li>
        </ol>
        <div style="margin-top:16px;display:flex;gap:12px;align-items:center">
          <a class="button primary" href="/ui/extension/download" style="text-decoration:none">Download for Chrome (.zip)</a>
          <span class="muted" style="font-size:12px">Pre-configured for <code>{server_url}</code></span>
        </div>
      </section>
      <section class="panel" style="padding:24px;margin-top:16px">
        <h2 style="font-size:18px;margin-bottom:16px;color:var(--text)">Firefox Setup</h2>
        <ol style="color:var(--text-secondary);line-height:2;padding-left:20px">
          <li>Download the Firefox extension below</li>
          <li>Unzip the downloaded file</li>
          <li>Open Firefox and go to <code>about:debugging#/runtime/this-firefox</code></li>
          <li>Click <strong>Load Temporary Add-on</strong> and select <code>manifest.json</code> inside the unzipped folder</li>
        </ol>
        <div style="margin-top:16px;display:flex;gap:12px;align-items:center">
          <a class="button primary" href="/ui/extension/download/firefox" style="text-decoration:none">Download for Firefox (.zip)</a>
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


@router.get("/ui/extension/download/firefox")
async def download_extension_firefox(request: Request):
    redirect = require_ui_user(request)
    if redirect:
        return redirect

    server_url = f"{request.url.scheme}://{request.headers.get('host', 'localhost:8080')}"
    firefox_manifest = EXTENSION_DIR / "manifest.firefox.json"
    if not firefox_manifest.exists():
        return Response("Firefox manifest not found", status_code=404)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(EXTENSION_DIR.rglob('*')):
            if file_path.is_file():
                rel_path = file_path.relative_to(EXTENSION_DIR)
                # Skip Chrome manifest and Firefox-specific manifest source
                if rel_path.name == 'manifest.json' or rel_path.name == 'manifest.firefox.json':
                    continue
                content = file_path.read_bytes()
                if rel_path.name == 'popup.js':
                    content = content.replace(
                        b"'http://localhost:8080'",
                        f"'{server_url}'".encode()
                    )
                zf.writestr(f"rampart-extension-firefox/{rel_path}", content)
        # Use the Firefox manifest as manifest.json
        zf.writestr("rampart-extension-firefox/manifest.json", firefox_manifest.read_bytes())
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=rampart-extension-firefox.zip"},
    )


LIVE_CONTENT_TYPES = {
    ".js": "application/javascript",
    ".css": "text/css",
}

LIVE_ALLOWED_FILES = {"content.js", "styles.css"}


@router.get("/ui/extension/live/{filename}")
async def serve_live_file(filename: str):
    """Serve extension files for auto-updating. No auth required."""
    if filename not in LIVE_ALLOWED_FILES:
        return Response("Not found", status_code=404)
    file_path = EXTENSION_DIR / filename
    if not file_path.exists():
        return Response("Not found", status_code=404)
    content_type = LIVE_CONTENT_TYPES.get(file_path.suffix, "application/octet-stream")
    return Response(
        file_path.read_bytes(),
        media_type=content_type,
        headers={
            "Cache-Control": "no-cache, must-revalidate",
            "Access-Control-Allow-Origin": "*",
        },
    )
