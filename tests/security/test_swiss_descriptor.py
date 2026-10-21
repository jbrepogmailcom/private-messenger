"""Operator-page fixtures: changes must not silently select another router."""

import importlib.util
import sys
from pathlib import Path

import pytest


@pytest.fixture
def launcher(monkeypatch):
    scripts = Path(__file__).parents[2] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location("swiss_demo_launcher", scripts / "demo_swiss.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop("swiss_demo_launcher", None)


def test_matches_only_the_existing_router_pin(launcher):
    uri = launcher.SERVER.replace("@", ":fixture-password@")
    uri = uri.replace(":5224", ",example.onion:5224")
    assert launcher.public_router_password(f"<p>{uri}</p>") == b"fixture-password"
    for bad in (
        uri.replace("Ltow", "Mtow"),
        uri.replace("5224", "5223"),
        uri.replace("urban-network.dyndns.org", "attacker.invalid"),
        launcher.SERVER,
    ):
        with pytest.raises(ValueError):
            launcher.public_router_password(bad)


def test_rejects_cross_origin_or_insecure_redirects(launcher):
    handler = launcher.SameOriginHTTPS()
    for bad in ("http://urban-network.ch/services/simplex", "https://attacker.invalid/"):
        with pytest.raises(ValueError):
            handler.redirect_request(None, None, 302, "Found", {}, bad)
