"""Local identity/vault commands and explicit milestone-1 SMP diagnostic commands."""

import argparse
import getpass
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from nacl.exceptions import CryptoError
from OpenSSL import SSL

from private_messenger import __version__
from private_messenger.config import Server, b64, unb64
from private_messenger.crypto.backend import SUITE, CryptoUnavailable, operation
from private_messenger.identity import public_profile, register
from private_messenger.networking.connection import Network
from private_messenger.networking.tor import configured_network, messaging_network
from private_messenger.smp.client import AmbiguousSendError, Client
from private_messenger.smp.queues import ReceiveQueue
from private_messenger.storage.vault import Vault, read_private

CAPABILITIES = {
    "native_smp": "implemented: v11-v20, TLS pinning and channel binding",
    "queue_storage": "implemented: encrypted vault, durable storage before ACK, router-ID dedup",
    "end_to_end_messenger": "signed one-use invitations; mandatory fingerprint verification",
    "crypto_suite": SUITE,
    "initial_kem": "ML-KEM-1024: differs from the requested initial ML-KEM-768",
    "double_ratchet": "upstream libsignal; bounded behavioral PFS/PCS tests, not an audit",
    "pq_ratchet": "upstream SPQR v1 ML-KEM-768; passive snapshot recovery test",
    "delivery": "atomic ratchet/history/outbox, application replay detection, encrypted receipts",
    "tor": "chat default: owned Tor or configured proxy, remote DNS, isolation, no DIRECT fallback",
    "mixnet": "BLOCKED: no verified compatible deployed adapter",
    "whole_vault_rollback": "UNPROTECTED: requires external monotonic state",
    "production_ready": False,
}


def output(value) -> None:
    print(json.dumps(value, sort_keys=True), flush=True)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Experimental independent SMP transport; NOT audited")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--vault", type=Path, default=Path.home() / ".private-messenger/state.vault")
    p.add_argument(
        "--passphrase-file", type=Path, help="0600 secret file; otherwise prompt securely"
    )
    subs = p.add_subparsers(dest="command", required=True)
    subs.add_parser("register").add_argument("name")
    for name in ("unlock", "identity", "status", "quit"):
        subs.add_parser(name)
    s = subs.add_parser("servers")
    s.add_argument("uri", nargs="?", help="add a pinned router")
    s.add_argument(
        "--basic-auth-file", type=Path, help="0600 router NEW password, obtained out of band"
    )
    n = subs.add_parser("network")
    n.add_argument("mode", choices=["DIRECT", "TOR"], nargs="?")
    n.add_argument("--proxy-host", default="127.0.0.1")
    n.add_argument("--proxy-port", type=int, default=9050)
    subs.add_parser("backup").add_argument("destination", type=Path)
    restore = subs.add_parser("restore")
    restore.add_argument("source", type=Path)
    smp = subs.add_parser("smp", help="opaque ciphertext transport diagnostics")
    actions = smp.add_subparsers(dest="action", required=True)
    ping = actions.add_parser("ping")
    ping.add_argument("server")
    create = actions.add_parser("create")
    create.add_argument("name")
    create.add_argument("server")
    create.add_argument(
        "--basic-auth-file",
        type=Path,
        help="user-owned 0600 file with the router's queue-creation password",
    )
    create.add_argument(
        "--legacy-security",
        action="store_true",
        help="recipient KEY instead of sender SKEY; use Python API to set key",
    )
    for name in ("address", "delete"):
        actions.add_parser(name).add_argument("name")
    secure = actions.add_parser("secure")
    secure.add_argument("name")
    secure.add_argument("address", help="PMQ1 transport descriptor, not a contact invitation")
    send = actions.add_parser("send")
    send.add_argument("name")
    send.add_argument("ciphertext_file", type=Path)
    for name in ("get", "subscribe"):
        receive = actions.add_parser(name)
        receive.add_argument("name")
        receive.add_argument("--no-ack", action="store_true", help="test redelivery")
    address = subs.add_parser("address", help="create a one-use signed contact invitation")
    address.add_argument("--server")
    connect = subs.add_parser("connect")
    connect.add_argument("invitation")
    connect.add_argument("--name", default="")
    for name in ("requests", "contacts", "listen", "inbox"):
        subs.add_parser(name)
    for name in ("accept", "verify", "history"):
        item = subs.add_parser(name)
        item.add_argument("id")
        if name == "verify":
            item.add_argument(
                "--confirm", help="fingerprint compared over a trusted independent channel"
            )
    send = subs.add_parser("send")
    send.add_argument("id")
    send.add_argument("message", nargs="+")
    subs.add_parser(
        "rotate", help="BLOCKED: authenticated queue rotation is not integrated"
    ).add_argument("id")
    return p


def passphrase(args) -> str:
    if args.passphrase_file:
        return read_private(args.passphrase_file, 4096).decode("utf-8").rstrip("\n")
    secret = getpass.getpass("Vault passphrase: ")
    if args.command == "register" and getpass.getpass("Repeat passphrase: ") != secret:
        raise ValueError("passphrases do not match")
    return secret


def network(vault: Vault) -> Network:
    return configured_network(vault)


def receive(vault: Vault, client: Client, name: str, queue, delivery, no_ack: bool) -> None:
    if delivery is None:
        output({"event": "empty", "new": False})
        return
    fresh = vault.record_delivery(name, delivery)
    if not no_ack:
        client.acknowledge(queue, delivery.message_id)
        vault.acknowledged(name, delivery.message_id)
    output(
        {
            "event": "received",
            "new": fresh,
            "acknowledged": not no_ack,
            "ciphertext_sha256": hashlib.sha256(delivery.ciphertext).hexdigest(),
        }
    )


def smp_command(args, vault: Vault) -> None:
    if args.action == "ping":
        with Client(Server.parse(args.server), network(vault)) as client:
            client.ping()
            output({"event": "pong", "version": client.version})
        return
    if args.action == "create":
        if vault.get("queue:" + args.name):
            raise ValueError("queue name already exists")
        server = Server.parse(args.server)
        basic_auth = None
        if args.basic_auth_file is not None:
            basic_auth = read_private(args.basic_auth_file, 257).rstrip(b"\r\n")
            if not 1 <= len(basic_auth) <= 255:
                raise ValueError("router password must contain 1..255 bytes")
        with Client(server, network(vault)) as client:
            queue = client.create_queue(
                sender_can_secure=not args.legacy_security,
                basic_auth=basic_auth,
            )
            try:
                vault.put("queue:" + args.name, {"server": server.uri, "queue": queue.export()})
            except BaseException:
                client.delete_queue(queue)
                raise
            output({"event": "created", "version": client.version})
        return
    if args.action == "secure":
        if not args.address.startswith("PMQ1:") or len(args.address) > 4096:
            raise ValueError("expected PMQ1 transport descriptor")
        descriptor = json.loads(unb64(args.address[5:]))
        server = Server.parse(descriptor["server"])
        sid = unb64(descriptor["sender_id"])
        if len(sid) != 24:
            raise ValueError("invalid sender ID")
        old = vault.get("sender:" + args.name)
        if old is None:
            key = ed25519.Ed25519PrivateKey.generate()
            old = {
                "server": server.uri,
                "sender_id": b64(sid),
                "auth_private": b64(key.private_bytes_raw()),
                "state": "securing",
            }
            vault.put("sender:" + args.name, old)
        elif old["server"] != server.uri or old["sender_id"] != b64(sid):
            raise ValueError("sender name already assigned to another queue")
        key = ed25519.Ed25519PrivateKey.from_private_bytes(unb64(old["auth_private"]))
        with Client(server, network(vault)) as client:
            client.secure_sender(sid, key)
        old["state"] = "secured"
        vault.put("sender:" + args.name, old)
        output({"event": "secured"})
        return
    if args.action == "send":
        record = vault.get("sender:" + args.name)
        if record is None or record["state"] != "secured":
            raise ValueError("secure sender credentials first")
        with args.ciphertext_file.open("rb") as stream:
            ciphertext = stream.read(16049)
        if not 1 <= len(ciphertext) <= 16048:
            raise ValueError("ciphertext must contain 1..16048 bytes")
        digest = hashlib.sha256(ciphertext).hexdigest()
        delivery_key = "outbox:" + args.name + ":" + digest
        if vault.get(delivery_key):
            raise ValueError("ciphertext already attempted; inspect acceptance state before retry")
        key = ed25519.Ed25519PrivateKey.from_private_bytes(unb64(record["auth_private"]))
        with Client(Server.parse(record["server"]), network(vault)) as client:
            vault.put(delivery_key, {"state": "acceptance_unknown"})
            client.send_ciphertext(unb64(record["sender_id"]), ciphertext, key)
            vault.put(delivery_key, {"state": "server_accepted"})
        output({"event": "server_accepted", "recipient_delivery": "unconfirmed"})
        return
    record = vault.get("queue:" + args.name)
    if record is None:
        raise ValueError("unknown receive queue")
    queue = ReceiveQueue.restore(record["queue"])
    if args.action == "address":
        if not queue.sender_can_secure:
            raise ValueError("this queue requires recipient KEY authorization")
        descriptor = {"server": record["server"], "sender_id": b64(queue.sender_id)}
        output({"address": "PMQ1:" + b64(json.dumps(descriptor).encode())})
        return
    with Client(Server.parse(record["server"]), network(vault)) as client:
        if args.action == "delete":
            client.delete_queue(queue)
            with vault.transaction() as db:
                db.execute("DELETE FROM state WHERE key=?", ("queue:" + args.name,))
            output({"event": "deleted"})
        elif args.action == "get":
            receive(vault, client, args.name, queue, client.get(queue), args.no_ack)
        elif args.action == "subscribe":
            delivery = client.subscribe(queue)
            output({"event": "subscribed"})
            if delivery is None:
                delivery = client.next_delivery(queue)
            receive(vault, client, args.name, queue, delivery, args.no_ack)


def secure_command(args, messenger) -> None:
    if args.command == "address":
        output(messenger.address(args.server))
    elif args.command == "connect":
        cid = messenger.connect(args.invitation, args.name)
        output({"event": "request_sent", "id": cid, **messenger.fingerprint(cid)})
    elif args.command == "accept":
        messenger.accept(args.id)
        output({"event": "accepted", **messenger.fingerprint(args.id)})
    elif args.command == "verify":
        output(messenger.fingerprint(args.id, args.confirm))
    elif args.command in ("contacts", "requests"):
        contacts = messenger.all_contacts()
        if args.command == "requests":
            contacts = [c for c in contacts if c["state"] == "requested"]
        output([{key: c[key] for key in ("id", "name", "state", "verified")} for c in contacts])
    elif args.command == "send":
        mid = messenger.send(args.id, " ".join(args.message))
        status = next(item["status"] for item in messenger.history(args.id) if item["id"] == mid)
        output({"event": status, "id": mid, "recipient_delivery": "unconfirmed"})
    elif args.command == "history":
        output(messenger.history(args.id))
    elif args.command == "inbox":
        output(
            [
                {"contact": c["id"], **item}
                for c in messenger.all_contacts()
                for item in messenger.history(c["id"])
                if item["direction"] == "in"
            ]
        )


def execute(args, vault: Vault, messenger=None) -> None:
    if args.command == "register":
        output(register(vault, args.name))
    elif args.command == "identity":
        identity = vault.get("identity")
        if identity is None:
            raise ValueError("no local identity")
        output(public_profile(identity))
    elif args.command == "status":
        try:
            backend = operation("metadata")
        except CryptoUnavailable:
            backend = {"available": False, "reason": "build pinned native crypto; no fallback"}
        output(
            {
                "capabilities": CAPABILITIES,
                "crypto_backend": backend,
                "network": network(vault).mode,
            }
        )
    elif args.command == "servers":
        servers = vault.get("servers", [])
        if args.uri:
            uri = Server.parse(args.uri).uri
            if args.basic_auth_file:
                password = read_private(args.basic_auth_file, 257).rstrip(b"\r\n")
                if not 1 <= len(password) <= 255:
                    raise ValueError("router password must contain 1..255 bytes")
                vault.put("router-auth:" + uri, b64(password))
            if uri not in servers:
                servers.append(uri)
                vault.put("servers", servers)
        elif args.basic_auth_file:
            raise ValueError("a pinned server URI is required with --basic-auth-file")
        output(servers)
    elif args.command == "network":
        if args.mode:
            configuration = {
                "mode": args.mode,
                "proxy_host": args.proxy_host,
                "proxy_port": args.proxy_port,
            }
            Network(**configuration)
            vault.put("network", configuration)
        output({"mode": network(vault).mode})
    elif args.command == "backup":
        vault.backup(args.destination)
        output({"event": "backup_created"})
    elif args.command == "smp":
        smp_command(args, vault)
    elif args.command in ("unlock", "listen"):
        from private_messenger.messaging.secure_terminal import run_shell

        run_shell(vault, interactive=args.command == "unlock")
    elif args.command in (
        "address",
        "connect",
        "requests",
        "accept",
        "verify",
        "contacts",
        "send",
        "inbox",
        "history",
    ):
        if messenger is not None:
            secure_command(args, messenger)
        else:
            from private_messenger.messaging.service import Messenger

            if args.command in ("address", "connect", "accept", "send"):
                with messaging_network(vault) as route, Messenger(vault, network=route) as service:
                    secure_command(args, service)
            else:
                with Messenger(vault) as service:
                    secure_command(args, service)
    elif args.command != "quit":
        raise ValueError(f"{args.command}: BLOCKED; authenticated queue rotation is not integrated")


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "quit":
            return 0
        secret = passphrase(args)
        if args.command == "restore":
            Vault.restore(args.source, args.vault, secret)
            output({"event": "restored"})
            return 0
        with Vault(args.vault, secret, create=args.command == "register") as vault:
            execute(args, vault)
        return 0
    except AmbiguousSendError:
        print(
            "Error: SEND acceptance unknown; stored state prevents automatic retry.",
            file=sys.stderr,
        )
        return 3
    except (
        ValueError,
        OSError,
        ConnectionError,
        EOFError,
        CryptoError,
        SSL.Error,
        CryptoUnavailable,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
