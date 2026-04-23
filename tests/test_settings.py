import json

from fastapi.testclient import TestClient
import httpx
import yaml

from rampart.app.config import load_config
from rampart.app.main import app
from rampart.app.security.auth import create_session_token
from rampart.app.security.passwords import hash_password
from rampart.app.settings_store import RuntimeSettings, load_settings, save_settings


def test_save_settings_and_merge_into_config(monkeypatch, tmp_path):
    settings_path = tmp_path / "settings.json"
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "settings": {"path": str(settings_path)},
                "llm_evaluator": {"enabled": True, "base_url": "http://old-analysis", "model": "old-analysis-model"},
                "upstream": {"enabled": True, "base_url": "http://old-upstream", "model": "old-upstream-model"},
                "policies": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    save_settings(
        RuntimeSettings(
            llm_evaluator_base_url="http://analysis",
            llm_evaluator_model="analysis-model",
            upstream_base_url="http://upstream",
            upstream_model="upstream-model",
        ),
        str(settings_path),
    )
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))

    config = load_config()

    assert config.llm_evaluator.base_url == "http://analysis"
    assert config.llm_evaluator.model == "analysis-model"
    assert config.upstream.base_url == "http://upstream"
    assert config.upstream.model == "upstream-model"


def test_settings_gui_saves_runtime_settings(monkeypatch, tmp_path):
    settings_path = tmp_path / "settings.json"
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "settings": {"path": str(settings_path)},
                "auth": {
                    "admin_username": "admin",
                    "admin_password_hash": hash_password("secret", iterations=1000),
                    "session_secret": "test-secret",
                    "auth_state_path": str(tmp_path / "auth.json"),
                    "audit_log_path": str(tmp_path / "audit.jsonl"),
                },
                "policies": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))
    monkeypatch.setenv("RAMPART_SESSION_SECRET", "test-secret")
    token = create_session_token("admin")

    response = TestClient(app).post(
        "/ui/settings",
        cookies={"rampart_session": token},
        data={
            "llm_evaluator_base_url": "http://analysis",
            "llm_evaluator_model": "analysis-model",
            "llm_evaluator_timeout_seconds": "22",
            "upstream_base_url": "http://upstream",
            "upstream_model": "upstream-model",
            "upstream_api_key": "upstream-key",
            "upstream_timeout_seconds": "55",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    settings = load_settings(str(settings_path))
    assert settings.llm_evaluator_model == "analysis-model"
    assert settings.upstream_model == "upstream-model"
    assert settings.upstream_timeout_seconds == 55


def test_global_upstream_model_override_is_forwarded(monkeypatch, tmp_path):
    captured = {}

    async def fake_post(self, url, json, headers):
        captured["json"] = json
        return httpx.Response(
            200,
            json={"id": "chatcmpl-test", "choices": [{"message": {"role": "assistant", "content": "ok"}}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    settings_path = tmp_path / "settings.json"
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "settings": {"path": str(settings_path)},
                "llm_evaluator": {"enabled": False},
                "upstream": {"enabled": True, "base_url": "http://upstream"},
                "policies": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    save_settings(RuntimeSettings(upstream_model="global-model"), str(settings_path))
    monkeypatch.setenv("RAMPART_POLICY_FILE", str(policy_path))

    response = TestClient(app).post(
        "/v1/chat/completions",
        json={"model": "request-model", "messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 200
    assert captured["json"]["model"] == "global-model"
