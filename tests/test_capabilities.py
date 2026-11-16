"""
ti://capabilities is read by downstream clients (e.g. TriageLoop) to record Athena's version per case.
"""
import asyncio
import json
import tomllib

import pytest
from mcp import types

import server


def _read(uri):
    return asyncio.run(server.handle_read_resource(types.AnyUrl(uri)))


def test_capabilities_resource_is_readable():
    manifest = json.loads(_read("ti://capabilities"))
    assert manifest["athena_version"]
    assert manifest["output_contract"]["version"] == "1.2"  # response schema unchanged


def test_listed_resource_uri_is_readable():
    """Every URI advertised by list_resources must actually be readable."""
    for resource in asyncio.run(server.handle_list_resources()):
        assert json.loads(_read(str(resource.uri)))


def test_capabilities_version_matches_package_version():
    with open("pyproject.toml", "rb") as f:
        package_version = tomllib.load(f)["project"]["version"]
    assert json.loads(_read("ti://capabilities"))["athena_version"] == package_version


@pytest.mark.parametrize("uri", ["ti://unknown", "ti://capabilities-x"])
def test_unknown_resource_still_rejected(uri):
    with pytest.raises(ValueError, match="Unknown resource"):
        _read(uri)


def test_wrong_scheme_rejected():
    with pytest.raises(ValueError, match="Unsupported URI scheme"):
        _read("https://capabilities")
