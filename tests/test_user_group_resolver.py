from rampart.app.config import UserGroupResolverConfig, KeycloakConfig


def test_resolver_config_defaults():
    cfg = UserGroupResolverConfig()
    assert cfg.enabled is False
    assert cfg.provider == "keycloak"
    assert cfg.cache_ttl_seconds == 900
    assert cfg.cache_max_size == 20000
    assert cfg.cache_persist_interval_seconds == 60
    assert cfg.cache_path == "data/user_group_cache.json"
    assert cfg.mappings_path == "data/group_mappings.json"


def test_keycloak_config_defaults():
    cfg = KeycloakConfig()
    assert cfg.base_url == ""
    assert cfg.realm == ""
    assert cfg.client_id == ""
    assert cfg.client_secret == ""
