from __future__ import annotations

from mcp_zero_trust_layer.packs import add_pack, list_packs, read_pack


def test_bundled_packs_are_listed_and_readable(tmp_path) -> None:
    packs = list_packs()
    assert "github-readonly" in packs

    content = read_pack("github-readonly")
    assert "github-read-only" in content

    target = add_pack("github-readonly", tmp_path / "github.yaml")
    assert target.read_text(encoding="utf-8") == content

