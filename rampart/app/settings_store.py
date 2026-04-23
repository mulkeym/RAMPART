from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from pydantic import BaseModel


class RuntimeSettings(BaseModel):
    llm_evaluator_base_url: str = ""
    llm_evaluator_model: str = ""
    llm_evaluator_timeout_seconds: Optional[float] = None
    vision_evaluator_enabled: Optional[bool] = None
    vision_evaluator_base_url: str = ""
    vision_evaluator_model: str = ""
    vision_evaluator_timeout_seconds: Optional[float] = None
    upstream_enabled: Optional[bool] = None
    upstream_base_url: str = ""
    upstream_model: str = ""
    upstream_api_key: str = ""
    upstream_timeout_seconds: Optional[float] = None


def load_settings(path: str) -> RuntimeSettings:
    settings_path = Path(path)
    if not settings_path.exists():
        return RuntimeSettings()
    with settings_path.open("r", encoding="utf-8") as settings_file:
        return RuntimeSettings.model_validate(json.load(settings_file))


def save_settings(settings: RuntimeSettings, path: str) -> None:
    settings_path = Path(path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    with settings_path.open("w", encoding="utf-8") as settings_file:
        json.dump(settings.model_dump(exclude_none=True), settings_file, indent=2, sort_keys=True)
        settings_file.write("\n")
