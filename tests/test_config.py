import pytest
from core.config import ToolkitConfig


class TestConfig:
    def test_default_config(self):
        config = ToolkitConfig()
        assert config.attack.default_rate == 1000
        assert config.defense.rate_limit == 100
        assert config.ui.theme == "dark"
        assert config.log_level == "INFO"

    def test_config_get_set(self):
        config = ToolkitConfig()
        assert config.get("attack.default_rate") == 1000
        config.set("attack.default_rate", 5000)
        assert config.attack.default_rate == 5000

    def test_config_nested_get(self):
        config = ToolkitConfig()
        assert config.get("defense.waf_enabled") is True
        assert config.get("nonexistent.key", "default") == "default"
