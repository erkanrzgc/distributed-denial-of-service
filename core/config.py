import os
from pathlib import Path
from typing import Any, Optional

import structlog
import yaml
from pydantic import BaseModel, Field

CONFIG_DIR = Path(os.environ.get("DDOS_CONFIG_DIR", Path.home() / ".config" / "ddos-toolkit"))
CONFIG_FILE = CONFIG_DIR / "config.yaml"

logger = structlog.get_logger(__name__)


class AttackConfig(BaseModel):
    default_rate: int = Field(default=1000, ge=1)
    default_concurrency: int = Field(default=100, ge=1, le=10000)
    default_duration: int = Field(default=30, ge=1)
    spoof_enabled: bool = False
    user_agents: list[str] = Field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ])


class DefenseConfig(BaseModel):
    proxy_listen: str = "0.0.0.0:8080"
    proxy_backend: str = "http://localhost:3000"
    rate_limit: int = Field(default=100, ge=1)
    rate_window: int = Field(default=60, ge=1)
    block_duration: int = Field(default=300, ge=1)
    challenge_enabled: bool = True
    waf_enabled: bool = True
    data_guard_max_body: int = Field(default=10485760, ge=1)


class AlertConfig(BaseModel):
    webhook_url: Optional[str] = None
    email: Optional[str] = None
    slack_webhook: Optional[str] = None
    threshold_rps: int = Field(default=5000, ge=1)
    threshold_concurrent: int = Field(default=1000, ge=1)


class UIConfig(BaseModel):
    theme: str = "dark"
    refresh_rate: int = Field(default=250, ge=50, le=5000)
    mouse_support: bool = True
    show_sparklines: bool = True


class ToolkitConfig(BaseModel):
    attack: AttackConfig = Field(default_factory=AttackConfig)
    defense: DefenseConfig = Field(default_factory=DefenseConfig)
    alert: AlertConfig = Field(default_factory=AlertConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    log_level: str = "INFO"
    log_format: str = "json"

    @classmethod
    def load(cls) -> "ToolkitConfig":
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            if CONFIG_FILE.exists():
                data = yaml.safe_load(CONFIG_FILE.read_text()) or {}
                return cls(**data)
        except Exception as e:
            logger.warning("config_load_failed", error=str(e))
        return cls()

    def save(self) -> None:
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            CONFIG_FILE.write_text(yaml.dump(self.model_dump(), default_flow_style=False))
            logger.info("config_saved", path=str(CONFIG_FILE))
        except Exception as e:
            logger.error("config_save_failed", error=str(e))

    def get(self, path: str, default: Any = None) -> Any:
        keys = path.split(".")
        data = self.model_dump()
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key, default)
            else:
                return default
        return data

    def set(self, path: str, value: Any) -> None:
        keys = path.split(".")
        obj: Any = self
        for key in keys[:-1]:
            obj = getattr(obj, key)
        if hasattr(obj, keys[-1]):
            setattr(obj, keys[-1], value)
        self.save()


global_config: Optional[ToolkitConfig] = None


def get_config() -> ToolkitConfig:
    global global_config
    if global_config is None:
        global_config = ToolkitConfig.load()
    return global_config
