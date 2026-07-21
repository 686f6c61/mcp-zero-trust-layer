from __future__ import annotations

import pytest

from mcp_zero_trust_layer.packs import read_pack
from mcp_zero_trust_layer.packs.registry import _filename


def test_read_pack_unknown_raises_key_error() -> None:
    with pytest.raises(KeyError):
        read_pack("does-not-exist")


def test_filename_strips_suffix_for_known_pack() -> None:
    assert _filename("github-readonly.yaml") == "github-readonly.yaml"
