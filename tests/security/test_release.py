import importlib.util
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def test_release_signature_and_substitution():
    path = Path(__file__).parents[2] / "scripts/release.py"
    spec = importlib.util.spec_from_file_location("release_tools", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    key = ed25519.Ed25519PrivateKey.generate()

    def public(k):
        return k.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    manifest = module.canonical({"source_commit": "test fixture", "artifact_sha256": {}})
    signature = module.sign_manifest(manifest, key)
    module.verify_manifest(manifest, signature, public(key))
    with pytest.raises(InvalidSignature):
        module.verify_manifest(manifest + b"changed", signature, public(key))
    with pytest.raises(InvalidSignature):
        module.verify_manifest(manifest, signature, public(ed25519.Ed25519PrivateKey.generate()))


def test_artifact_hash_and_path_validation(tmp_path):
    path = Path(__file__).parents[2] / "scripts/release.py"
    spec = importlib.util.spec_from_file_location("release_tools", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    artifact = tmp_path / "package.whl"
    artifact.write_bytes(b"test release artifact")
    manifest = module.canonical(
        {
            "format": "private-messenger-release-v1",
            "artifact_sha256": {"package.whl": module.digest(artifact)},
        }
    )
    module.verify_artifacts(manifest, tmp_path)
    artifact.write_bytes(b"tampered")
    with pytest.raises(ValueError):
        module.verify_artifacts(manifest, tmp_path)
    unsafe = module.canonical(
        {"format": "private-messenger-release-v1", "artifact_sha256": {"../outside": "0" * 64}}
    )
    with pytest.raises(ValueError):
        module.verify_artifacts(unsafe, tmp_path)
