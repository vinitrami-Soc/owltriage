import pytest


@pytest.fixture(autouse=True)
def _no_installed_rules_pack(tmp_path, monkeypatch):
    """Tests never see a rules pack installed on the machine running them (or install into it)."""
    monkeypatch.setenv("OWLTRIAGE_RULES_PACK_DIR", str(tmp_path / "rules-pack"))
