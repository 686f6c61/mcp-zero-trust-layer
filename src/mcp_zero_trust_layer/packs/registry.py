from __future__ import annotations

from importlib import resources
from pathlib import Path

PACK_PACKAGE = "mcp_zero_trust_layer.packs"
PACK_SUFFIX = ".yaml"


def list_packs() -> list[str]:
    root = resources.files(PACK_PACKAGE)
    return sorted(
        path.name.removesuffix(PACK_SUFFIX) for path in root.iterdir() if path.name.endswith(PACK_SUFFIX)
    )


def read_pack(name: str) -> str:
    filename = _filename(name)
    return resources.files(PACK_PACKAGE).joinpath(filename).read_text(encoding="utf-8")


def add_pack(name: str, output: str | Path) -> Path:
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(read_pack(name), encoding="utf-8")
    return target


def _filename(name: str) -> str:
    normalized = name.removesuffix(PACK_SUFFIX)
    available = set(list_packs())
    if normalized not in available:
        raise KeyError(name)
    return f"{normalized}{PACK_SUFFIX}"
