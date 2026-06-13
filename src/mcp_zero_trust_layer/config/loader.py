from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.errors import ConfigError


def load_config(path: str | Path) -> MCPZTConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"config file not found: {config_path}")

    try:
        raw = yaml.safe_load(config_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {config_path}: {exc}") from exc

    try:
        config = MCPZTConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
    return config.model_copy(update={"config_base_dir": str(config_path.parent.resolve())})
