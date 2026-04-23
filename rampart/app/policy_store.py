from __future__ import annotations

from typing import Optional, Union
from pathlib import Path

from rampart.app.config import AppConfig, PolicyConfig, load_config, save_config


def list_policies(path: Optional[Union[str, Path]] = None) -> list[PolicyConfig]:
    return load_config(path).policies


def get_policy(policy_id: str, path: Optional[Union[str, Path]] = None) -> Optional[PolicyConfig]:
    for policy in list_policies(path):
        if policy.id == policy_id:
            return policy
    return None


def upsert_policy(policy: PolicyConfig, path: Optional[Union[str, Path]] = None) -> AppConfig:
    config = load_config(path)
    policies = []
    replaced = False
    for existing in config.policies:
        if existing.id == policy.id:
            policies.append(policy)
            replaced = True
        else:
            policies.append(existing)
    if not replaced:
        policies.append(policy)
    config.policies = policies
    save_config(config, path)
    return config


def delete_policy(policy_id: str, path: Optional[Union[str, Path]] = None) -> AppConfig:
    config = load_config(path)
    config.policies = [policy for policy in config.policies if policy.id != policy_id]
    save_config(config, path)
    return config
