import pytest
from rampart.app.group_providers import GroupProvider


def test_group_provider_is_abstract():
    with pytest.raises(TypeError):
        GroupProvider()


@pytest.mark.asyncio
async def test_group_provider_subclass_works():
    class FakeProvider(GroupProvider):
        async def lookup_groups(self, user_id: str) -> list[str]:
            return ["group-a", "group-b"]

    provider = FakeProvider()
    groups = await provider.lookup_groups("test@example.com")
    assert groups == ["group-a", "group-b"]
