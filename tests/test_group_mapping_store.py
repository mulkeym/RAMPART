import pytest
from rampart.app.group_mapping_store import (
    GroupMapping,
    list_mappings,
    get_mapping,
    create_mapping,
    update_mapping,
    delete_mapping,
)


@pytest.fixture
def store_path(tmp_path):
    return str(tmp_path / "group_mappings.json")


def test_list_mappings_empty(store_path):
    assert list_mappings(store_path) == []


def test_create_and_list(store_path):
    m = create_mapping("DHA-Clinical", "clinical-staff", path=store_path)
    assert m.external_group == "DHA-Clinical"
    assert m.rampart_group_id == "clinical-staff"
    assert m.enabled is True
    assert m.id
    mappings = list_mappings(store_path)
    assert len(mappings) == 1
    assert mappings[0].id == m.id


def test_get_mapping(store_path):
    m = create_mapping("DHA-Admin", "admin-group", path=store_path)
    found = get_mapping(m.id, store_path)
    assert found is not None
    assert found.external_group == "DHA-Admin"


def test_get_mapping_not_found(store_path):
    assert get_mapping("nonexistent", store_path) is None


def test_update_mapping(store_path):
    m = create_mapping("DHA-Clinical", "clinical-staff", path=store_path)
    m.rampart_group_id = "new-group"
    m.enabled = False
    update_mapping(m, store_path)
    found = get_mapping(m.id, store_path)
    assert found.rampart_group_id == "new-group"
    assert found.enabled is False


def test_update_not_found(store_path):
    m = GroupMapping(id="bad-id", external_group="X", rampart_group_id="Y")
    with pytest.raises(ValueError, match="not found"):
        update_mapping(m, store_path)


def test_delete_mapping(store_path):
    m = create_mapping("DHA-Clinical", "clinical-staff", path=store_path)
    delete_mapping(m.id, store_path)
    assert list_mappings(store_path) == []


def test_delete_not_found(store_path):
    with pytest.raises(ValueError, match="not found"):
        delete_mapping("bad-id", store_path)
