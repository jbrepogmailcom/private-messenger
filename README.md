# Private Messenger — experimental independent SMP client

Working Python 3.12+ source, independent of SimpleX Chat and its agent. **Milestone 1
is implemented and verified against public routers. This is not yet a usable
authenticated end-to-end messenger and is not production-ready.**

The Python client speaks SMP directly over TCP/TLS (normally port 5223). It does
not use WebSocket, a messaging engine, SimpleX CLI, an agent library, or an existing
user database. The upstream source was consulted as a wire-format reference only.

## Implemented

- Pinned certificate-path authentication, TLS 1.3 / X25519 /
  ChaCha20-Poly1305, ALPN `smp/1`, TLS Finished channel binding.
- SMP versions 11–20; highest compatible version; versions below 11 rejected.
- 16,384-byte blocks, batching, binary encodings, signed router session key,
  SMP HKDF-SHA-512 transport encryption chains.
- Ed25519 command authorization; NEW, KEY, SKEY, SEND, GET, SUB, ACK, DEL, PING.
- Separate per-queue recipient authentication, recipient DH and sender keys.
- Offline queues, explicit reconnect with bounded backoff, redelivery handling,
  durable storage before ACK and router-message-ID deduplication.
- Local identity generation, encrypted persistence, backup/restore, no registration
  request to a server and no transmission of the local identity.
- Argon2id and XChaCha20-Poly1305 encrypted SQLite snapshots, process locking,
  restrictive permissions and atomic fsync/replace.
- DIRECT and fail-closed SOCKS/TOR adapters with remote DNS and fresh isolation
  credentials on each connection. Test scope is in [VERIFICATION.md](VERIFICATION.md).
- Multiple explicitly pinned router configurations, property tests, static checks,
  hashed dependency locks and release-manifest/signature tools.

## Explicitly unavailable

Authenticated contact invitations, acceptance, verification, conversational E2E
encryption, ML-KEM-768 hybrid key establishment, Double Ratchet, skipped keys,
application replay protection, PFS/PCS between contacts, PQ ratcheting, conversation
queue rotation, redundant routing, delivery receipts and cover traffic are **not
implemented**. MIXNET is blocked pending a real compatible adapter.

The CLI gates messenger commands with a clear BLOCKED error. No static-key or
homemade ratchet is substituted. See [MILESTONES.md](MILESTONES.md) and
[SECURITY.md](SECURITY.md). SMP transport encryption is not conversational E2E
security; a router knows its own transport and delivery-layer keys.

## Ubuntu installation

Ubuntu 24.04 or later, Python 3.12+, native libsodium and OpenSSL-compatible wheels:

```bash
sudo apt install python3 python3-venv python3-pip libsodium23 git iproute2
cd private-messenger
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-dev.lock
.venv/bin/pip install --require-hashes -r requirements-build.lock
.venv/bin/pip install --no-deps --no-build-isolation -e .
```

The build backend is pinned in `pyproject.toml`; install `requirements-build.lock`
before using `--no-build-isolation`. If the system Python cannot bootstrap pip,
an existing `uv` installation can create the environment and install the same
hashed lockfiles. The development session used `uv` with Python 3.12.7.

`libsodium23` is used through a narrow native HSalsa20 binding; no primitive is
implemented in Python. System-package version and security updates are part of
the trusted platform, separately from Python lockfiles.

## Real Alice/Bob transport demo

On the configured development machine, a single command runs the Swiss-router
test, prepares temporary Alice/Bob profiles and automatically fetches the
operator's published queue-creation password over HTTPS:

```bash
bash scripts/demo_swiss.sh
```

It requires the already verified router certificate identity; a changed identity
or an unexpected website redirect stops the test. It uses direct TLS and sends
only encrypted random test payloads. Temporary profiles and queues are cleaned up.
This remains an opaque transport test; there is no text-chat interface yet.

Czech walkthrough: [two separate clients](TEST_TWO_CLIENTS_CS.md) and
[server selection / Iceland investigation](SERVER_SELECTION_CS.md).

```bash
bash scripts/demo_alice_bob.sh --server \
  'smp://u2dS9sG8nMNURyZwqASV4yROM28Er0luVTx5X1CsMrU=@smp4.simplex.im'
```

The advertised identity above comes from the upstream router list; check a trusted
source before relying on a router identity. The demo launches separate Alice and
Bob Python processes, uses encrypted random test payloads and ephemeral encrypted
vaults, verifies offline retrieval, an unacknowledged redelivery after process exit,
single local insertion, ACK deletion and concurrent online delivery. It deletes
its queue afterwards. It does not establish a conversational encryption session.

The `PMQ1:` transport descriptor carries the pinned server and sender queue ID.
It is an explicitly application-specific diagnostic descriptor, **not** an SMP
command/field, authenticated contact invitation or SimpleX Chat invitation. No
invented fields are sent to an SMP router. Senders can race to secure a fresh
queue if this descriptor leaks; authenticated invitations are a later milestone.

## Local identity and storage

```bash
.venv/bin/private-messenger register Alice
.venv/bin/private-messenger identity
.venv/bin/private-messenger servers \
  'smp://u2dS9sG8nMNURyZwqASV4yROM28Er0luVTx5X1CsMrU=@smp4.simplex.im'
.venv/bin/private-messenger status
.venv/bin/private-messenger unlock
```

Passphrases are prompted with `getpass`. `unlock` opens an in-process command
shell, and `quit` drops references to keys and closes the database. Other commands
prompt independently; nothing is cached by a daemon. An optional
`--passphrase-file PATH` requires a user-owned 0600 regular file. Never supply a
passphrase in command arguments or commit it.

The default vault is `~/.private-messenger/state.vault`; its directory must be 0700.
For separate profiles use `--vault /private/path/alice.vault` before the command.

```bash
.venv/bin/private-messenger backup /private/backup/alice.vault
.venv/bin/private-messenger --vault /private/recovered/alice.vault \
  restore /private/backup/alice.vault
```

Restore authenticates the snapshot, never overwrites an existing vault and needs
the original passphrase. Backups contain all historical credentials/state; protect
them accordingly. Whole-vault rollback cannot be detected without an external
monotonic reference. Recovered identities/sessions require future protocol-specific
recovery handling before conversational use.

## SMP diagnostic CLI

Use `private-messenger smp --help`. Supported commands:

```text
smp ping SERVER
smp create NAME SERVER [--basic-auth-file PATH]
smp address NAME
smp secure SENDER_NAME PMQ1_DESCRIPTOR
smp send SENDER_NAME CIPHERTEXT_FILE
smp get NAME [--no-ack]
smp subscribe NAME [--no-ack]
smp delete NAME
```

`send` accepts already encrypted opaque bytes, at most 16,048 bytes. This low-level
API cannot establish that caller-supplied bytes are encrypted or authenticated.
CLI receive output contains only status and a ciphertext digest, not body contents.
A successful SEND means **server acceptance**, not confirmed recipient delivery.
Unknown acceptance is persisted and automatic retries of identical ciphertext
are refused. No authenticated recipient receipts exist yet. Duplicate detection
uses router IDs and therefore does not defeat malicious republishing with new IDs.

Routers requiring a password for NEW can use `--basic-auth-file PATH`, a user-owned
0600 file. Only its filename appears in process arguments; the password is sent
inside the pinned encrypted SMP connection for NEW, never in invitations or sender
commands, and is not copied into queue state. The same flag is accepted by the
Alice/Bob demo. This router password is separate from the local vault passphrase.

The diagnostic `subscribe` receives one delivery; callers of the Python API can
continue receiving and ACKing. GET and SUB cannot be mixed on one queue connection.
`reconnect()` never replays SEND; applications must resubscribe after reconnect.
Automatic loss recovery for an entire messenger conversation is not implemented.

## TOR

```bash
.venv/bin/private-messenger network TOR --proxy-host 127.0.0.1 --proxy-port 9050
.venv/bin/private-messenger network DIRECT
```

Supply a literal local proxy IP. The adapter sends destination hostnames through
SOCKS5 without local DNS lookup; fresh usernames/passwords allow Tor isolation when
`IsolateSOCKSAuth` is enabled. It never tries DIRECT on a proxy error. Each CLI
queue operation opens a new connection. Tor's presence does not prevent global
traffic correlation or prove who controls an endpoint. DIRECT exposes source IP
to the router. Router operators still see timing, queues and traffic volume.

## Verification and releases

```bash
bash scripts/check.sh
PM_PUBLIC_SMP_SERVER='smp://PIN@HOST:PORT' .venv/bin/pytest -q -m public
.venv/bin/python scripts/test_local_reference.py /path/to/unmodified/smp-server
.venv/bin/python scripts/test_real_tor.py --server 'smp://PIN@HOST:PORT'
```

Public tests are opt-in; tests against an unmodified local router have a separate
marker. The local runner uses a disposable unprivileged network namespace and
requires user namespaces to be enabled. The Tor runner uses an already installed
Tor, an ephemeral private directory and only its own process. Neither installs a
system service. [VERIFICATION.md](VERIFICATION.md) records actual runs and gaps.

See [RELEASING.md](RELEASING.md) for reproducible build scope, signed manifests and
the future multi-party/transparency design. Source license: AGPL-3.0-or-later.
