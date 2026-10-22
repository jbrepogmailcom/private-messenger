# Private Messenger 0.2 — independent experimental SMP messenger

Python 3.12+ speaks SMP directly to unmodified public routers, over **TCP/TLS, not
WebSocket**. No SimpleX Chat engine, CLI, agent, database or Signal messaging
service is used. A small Rust extension calls pinned upstream **cryptography only**:
libsignal-protocol for authenticated hybrid establishment and its Triple Ratchet.
All SMP transport, queues, contacts, networking and persistence are our code.

**Experimental and unaudited.** Working remote pairing and bidirectional encrypted
messages are verified; this is not a production security recommendation.

The selected upstream backend uses **X25519 + ML-KEM-1024 initially**, then a
Double Ratchet combined with **SPQR v1 / ML-KEM-768**. The original requirement of
ML-KEM-768 for the *initial* exchange remains unsatisfied. We preserve upstream
cryptography instead of inventing a replacement. No Signal application or PQXDH
interoperability certification is claimed. See [crypto dependencies](CRYPTO_DEPENDENCIES.md).

## Two terminals, or two separate computers

On Bob's terminal:

```bash
./chat Bob
```

Choose Bob's own password. Enter `address`, then send the returned **whole PMS2:
invitation** to Alice through an independently trusted channel. Bob also sees a
local contact `id`; names are not server-side addresses.

On Alice's terminal, independently:

```bash
./chat Alice
```

Choose Alice's own password, paste Bob's invitation and press Enter. Bob sees a
request and runs `accept ID` using the ID shown in **Bob's** window. Alice and Bob
run `verify ID` using their respective local IDs, compare the 60-digit fingerprint
in person or over another authenticated channel, then each enters:

```text
verify ID --confirm THE_60_DIGITS
```

Alice can now type `Ahoj Bobe!`; Bob sees it and can reply by typing text. With
multiple contacts use `send ID TEXT`. `history ID` shows delivery states; `quit`
exits. `server_accepted` is distinct from the encrypted `recipient_received`
receipt. These receipts confirm application processing, not that a human read it.
Offline messages wait at the router while its retention/quota permits.

[Podrobný český návod](TEST_TWO_CLIENTS_CS.md). Each profile is created separately
in `~/.local/share/private-messenger/secure-profiles/`; passwords need not match.
The old same-computer demo remains available as `./chat-legacy` in its original
`terminal-demo/` directory. Its static Box keys have no PFS/PCS/PQ protection.
There is no automatic migration, shared setup, or overwrite of existing profiles.

## Ubuntu source installation

On Ubuntu 24.04+, install Python 3.12+, a C toolchain, protoc and libsodium:

```bash
sudo apt install python3 python3-venv python3-pip libsodium23 git build-essential protobuf-compiler
cd private-messenger
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-dev.lock
.venv/bin/pip install --require-hashes -r requirements-build.lock
```

Install Rust using the [official rustup instructions](https://rustup.rs/), verify
the downloaded installer using the official checksum, then install the pinned
Rust **1.98.1** toolchain. Build and install:

```bash
rustup toolchain install 1.98.1 --profile minimal --component rustfmt --component clippy
bash scripts/build_crypto.sh
.venv/bin/pip install --no-deps --no-build-isolation -e .
./chat Alice
```

Cargo uses `native/Cargo.lock` and an exact upstream git revision. The installed
compiler must support edition 2024; protoc must be on PATH (or set `PROTOC`). The
verified development build used protoc 33.1; system versions are not all tested.
The build script also recognizes the private, ignored `.work-crypto` toolchain
used during development. It never downloads a messenger engine or changes a
system service. Without the compiled extension, secure messaging fails closed.

## Implemented and tested

- Native SMP v11–20 negotiation, TLS 1.3, validated pinned certificate identity,
  signed ephemeral server key, Finished channel binding, fixed 16,384-byte framing.
- NEW, KEY/SKEY, SEND, GET, SUB, ACK, DEL, PING, separate recipient/sender credentials,
  public-router offline storage, reconnect and authenticated delivery-layer decoding.
- Local identity; fresh identity/prekeys/queue for every contact; signed, expiring,
  one-use QR-compatible invitations; requests, acceptance and mandatory fingerprints.
- Upstream hybrid establishment, Double/Triple Ratchet and ongoing PQ epochs; real
  native out-of-order, replay, tamper, key-retirement and compromise-recovery tests.
- Atomic encrypted ratchet/history/outbox transitions before ACK/SEND; bounded
  retries of the same ciphertext; application IDs and cross-router-ID replay detection.
- Argon2id + XChaCha20-Poly1305 encrypted vault, 0700/0600 files, process locking,
  atomic fsync/replace, encrypted backup. Restore retains history and **disables old
  sessions** until fresh pairing to avoid resuming stale sending state.
- DIRECT and fail-closed TOR/SOCKS5 with remote DNS and fresh isolation credentials.
  TOR depends on `IsolateSOCKSAuth` at the proxy and does not defeat global correlation.

The application wrapper has no independent review. Strong whole-vault rollback
protection, guaranteed memory/disk erasure, authenticated queue/identity rotation,
cover traffic, redundant routers, MIXNET and an authenticated production release
channel remain unavailable. No perfect security, anonymity or comparative superiority
is claimed. See [threat model](THREAT_MODEL.md) and [milestones](MILESTONES.md).

## CLI and configuration

`private-messenger --vault PATH COMMAND` uses a specified encrypted profile;
`private-chat NAME` is the installed equivalent of `./chat NAME`. The default
one-shot CLI vault is `~/.private-messenger/state.vault`, distinct from chat profiles.
Commands: `register NAME`, `unlock`, `identity`, `address [--server URI]`,
`connect INVITATION`, `requests`, `accept ID`, `verify ID [--confirm FINGERPRINT]`,
`contacts`, `send ID TEXT`, `listen`, `inbox`, `history ID`, `network`, `servers`,
`status`, `backup PATH`, `restore PATH`, `quit`. `rotate ID` explicitly reports BLOCKED.
`register` is local only. `unlock` opens a shell; `listen` receives without stdin.

The default router is the independently operated Swiss Urban-Network relay:

```text
smp://LtowhzwGvh3lqlFvMqxCTPmZ_OzcwOq_NCsNG7ya1lc=@urban-network.dyndns.org:5224
```

Geography is not a security guarantee; see [server evidence](SERVER_SELECTION_CS.md).
`servers URI` adds an explicit pin. New local receive queues use the first configured
router; invitations contain the peer's receive router. No availability fallback is
performed. A password required for NEW can be imported with
`servers URI --basic-auth-file PATH` (private 0600 file). This public router creation
password is distinct from the vault secret, not included in invitations.
The default operator password is fetched over CA-validated HTTPS only if not cached.
Its website can block Tor; import credentials out of band in that case. **No DIRECT
fallback occurs**, including for website discovery.

Quit the shell before changing network mode for that profile:

```bash
.venv/bin/private-messenger --vault "$HOME/.local/share/private-messenger/secure-profiles/alice.vault" network TOR --proxy-host 127.0.0.1 --proxy-port 9050
./chat Alice
```

A literal proxy IP prevents proxy-host DNS lookup. DIRECT reveals the source IP to
the router. Tor conceals that IP from the router under its assumptions, while
routers still observe queue activity, timing and volume. No telemetry or analytics.

`backup PATH` writes an encrypted snapshot protected by the same passphrase.
`restore SOURCE` requires a new destination vault and the original passphrase.
It does not overwrite files. Re-pair restored contacts using new invitations.
History, backups and Python memory can retain plaintext/keys; PFS does not erase them.

Low-level `smp --help` commands remain available for opaque transport diagnostics.
They do not establish or certify application encryption and are distinct from `send ID`.
The automated `scripts/demo_alice_bob.sh` and `scripts/demo_swiss.sh` are transport
fixtures, not the new authenticated chat flow.

## Verification and releases

```bash
bash scripts/check.sh
bash scripts/check_crypto.sh
PM_PUBLIC_SECURE_MESSENGER=1 .venv/bin/pytest -q tests/integration/test_secure_messenger.py -k DIRECT
# Real Tor proxy plus an independently obtained optional private NEW password file:
PM_PUBLIC_SECURE_MESSENGER=1 PM_SECURE_TOR_PORT=9050 PM_ROUTER_AUTH_FILE=/private/new-password .venv/bin/pytest -q tests/integration/test_secure_messenger.py -k TOR
.venv/bin/python scripts/bench_crypto.py
```

Real public/local-reference integration tests are opt-in and labeled separately
from mock-relay application tests. [VERIFICATION.md](VERIFICATION.md) records actual
results. [RELEASING.md](RELEASING.md) covers platform wheels, source builds, manifests,
signing tools and remaining reproducibility limits. No established production
signing identity or automatic updater exists. Own source is AGPL-3.0-or-later;
the combined native backend includes AGPL-3.0-only dependencies and notices.
