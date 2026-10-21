"""Invalid credential files must be rejected before any network contact."""

from private_messenger.cli import main
from private_messenger.identity import register
from private_messenger.storage.vault import Vault


def test_insecure_router_password_never_reaches_network(tmp_path, monkeypatch, capsys):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    vault_path = directory / "test.vault"
    password = directory / "vault-password"
    password.write_text("vault test secret")
    password.chmod(0o600)
    with Vault(vault_path, "vault test secret", create=True) as vault:
        register(vault, "Test")

    def forbidden(*args, **kwargs):
        raise AssertionError("credential validation must happen before network access")

    monkeypatch.setattr("private_messenger.cli.Client", forbidden)
    auth = directory / "router-auth"
    auth.write_bytes(b"router-creation-secret")
    auth.chmod(0o644)
    command = [
        "--vault",
        str(vault_path),
        "--passphrase-file",
        str(password),
        "smp",
        "create",
        "test",
        "smp://" + "A" * 43 + "=@example.invalid",
        "--basic-auth-file",
        str(auth),
    ]
    assert main(command) == 1
    assert "router-creation-secret" not in capsys.readouterr().err
    auth.chmod(0o600)
    auth.write_bytes(b"\n")
    assert main(command) == 1
