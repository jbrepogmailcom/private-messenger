# Private Messenger 0.2.4 — independent experimental SMP messenger

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

Choose Bob's own password. The launcher starts Tor and waits for `Tor: 100%`
before connecting to SMP. The `tqdm` progress bar updates on one terminal line.
Enter `/address`, then send the returned **whole `/add Bob PMS2:…` command** to Alice
through an independently trusted channel. Names are local labels, not server-side addresses.

On Alice's terminal, independently:

```bash
./chat Alice
```

Choose Alice's own password, paste the generated `/add Bob PMS2:…` command and
press Enter. `/add PMS2:…` and `/add {"invitation": "PMS2:…", …}` are also accepted;
`/connect` remains an alias. Bob sees a request and types `/accept`.
Both type `/verify`, compare the entire displayed
fingerprint in person or over another authenticated channel, and only when it
matches, each types:

```text
/ano
```

Alice can now type `Ahoj Bobe!`; Bob sees it and can reply by typing text. With
multiple contacts use `/chat` or `/contacts` to see a numbered list, then `/chat 2`
to select its second contact. `/chat Bob` selects a unique name; `/send Bob TEXT`
sends explicitly. `/history` shows the selected conversation. Ambiguous names
require selecting a displayed number or an explicit ID. Menu numbers refer to the
last displayed list, so new incoming requests cannot silently renumber that list.
On restart a single existing contact is selected automatically. `/quit` exits.
The chat explains whether acceptance or verification is still missing.
`server_accepted` is distinct from the encrypted `recipient_received`
receipt. These receipts confirm application processing, not that a human read it.
Offline messages wait at the router while its retention/quota permits.

The one-shot CLI still supports `verify ID --confirm FINGERPRINT` for scripts.
All **in-chat commands require a leading `/`**, including `/ano` and `/ne` for
verification. Ordinary text is a message, even if it is the word `help` or `quit`.
Unknown slash commands never become messages. Pasted invitations, JSON invitation
exports and long Base32 fragments are blocked from messages and direct the user
to `/add`, preventing accidental forwarding to the selected contact.

The guided `/ano` confirmation is available after displaying `/verify`;
changing conversations cancels that confirmation. It never bypasses fingerprint
comparison or automatically trusts an invitation's self-signature.

To add Charlie while Alice already chats with Bob, Charlie runs `./chat Charlie`
and `/address`. Alice pastes Charlie's generated `/add Charlie PMS2:…` command;
Charlie accepts with `/accept`; both compare `/verify` and confirm with `/ano`.
Alice can then switch between Bob and Charlie using the numbered `/chat` list.
Each contact has its own encrypted conversation.

To reset a contact, use `/del Charlie` (or `/del 2` from the displayed list, or
`/del` for the selected contact), then explicitly confirm `/ano`; `/ne` cancels.
This removes that contact's local history, ratchet/prekeys, outgoing credentials,
outbox and replay/delivery records, closes its sender connection, stops its
receiver, and deletes **your own incoming SMP queue**. A deleted recipient is
cleared from the prompt; another contact is never silently selected instead.
To test from scratch, delete the corresponding contact on both endpoints, then
generate a fresh `/address` and repeat `/add`, `/accept`, `/verify` and `/ano`.
The local profile and unrelated contacts remain intact. `/contacts --all` also
lists unused local invitations, which can be deleted by their displayed number.

Deletion first durably retires local conversation state. If network/server deletion
fails, a visible `deleting` record retains only encrypted queue credentials needed
to retry `/del` (including after restart); no old session or queued message resumes.
Only `OK` is reported as server-confirmed deletion. `AUTH` permits local cleanup
but is reported as unconfirmed, since it cannot distinguish a missing queue from
rejected credentials. Local deletion does not erase another device's copy, existing
backups, or guarantee physical erasure on SSDs/in Python. See [security](SECURITY.md).

If a server remains unavailable, `/del NAME --local` followed by `/ano` discards
all remaining local contact data **without contacting the server**. The confirmation
explicitly says that the remote queue will remain and its access keys will be lost.
This is an opt-in local operation, not an automatic substitute for server deletion.

[Podrobný český návod](TEST_TWO_CLIENTS_CS.md). Each profile is created separately
in `~/.local/share/private-messenger/secure-profiles/`; passwords need not match.
The old same-computer demo remains available as `./chat-legacy` in its original
`terminal-demo/` directory. Its static Box keys have no PFS/PCS/PQ protection.
There is no automatic migration, shared setup, or overwrite of existing profiles.

## Ubuntu source installation

On Ubuntu 24.04+, install Python 3.12+, a C toolchain, protoc and libsodium:

```bash
sudo apt install python3 python3-venv python3-pip libsodium23 git build-essential protobuf-compiler tor
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
- TOR by default, including migration of earlier DIRECT chat profiles at login.
  Owned Tor starts automatically; external SOCKS is configurable. Remote DNS,
  fresh isolation credentials and no DIRECT fallback. Tor does not defeat global correlation.

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
The operator-published public NEW credential is bundled with the pinned default
router (verified 2026-10-22); normal chat performs no operator-website fetch. This
is public relay configuration, not a profile password/private key. Update via
a reviewed source change or import a current credential if the operator rotates it.
There is no automatic HTTP refresh or DIRECT fallback.

`./chat NAME` selects TOR before any messaging connection, including for profiles
that previously stored DIRECT. Restart existing processes to apply an update.
The launcher starts only its own installed Tor process; it changes no system Tor
service. Bootstrap failure stops startup, with no direct router connection. Normal
quit stops that owned Tor. Guard state is restored/saved in the encrypted vault;
Tor runtime files live in a private 0700 RAM directory under `/dev/shm`.
An unclean crash may leave RAM files until reboot and lose the newest guard state;
memory/swap and correlation limitations still apply.

To use an existing local Tor proxy instead:

```bash
./chat Alice --tor-proxy-host 127.0.0.1 --tor-proxy-port 9050
```

That proxy configuration persists and must remain available; an external proxy
error never starts a different route. Its `IsolateSOCKSAuth` configuration is the
operator's responsibility. For an explicitly requested IP-exposing diagnostic
chat only, `./chat Alice --network DIRECT` is available. Ordinary `./chat Alice`
selects TOR again on the next login. The one-shot CLI `network DIRECT` is an
explicit saved opt-in for its commands, not the chat launcher's default.

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
# Real Tor proxy for external-Tor tests and managed-client test cleanup:
PM_PUBLIC_SECURE_MESSENGER=1 PM_SECURE_TOR_PORT=9050 .venv/bin/pytest -q tests/integration/test_secure_messenger.py -k TOR
.venv/bin/python scripts/bench_crypto.py
```

Real public/local-reference integration tests are opt-in and labeled separately
from mock-relay application tests. [VERIFICATION.md](VERIFICATION.md) records actual
results. [RELEASING.md](RELEASING.md) covers platform wheels, source builds, manifests,
signing tools and remaining reproducibility limits. No established production
signing identity or automatic updater exists. Own source is AGPL-3.0-or-later;
the combined native backend includes AGPL-3.0-only dependencies and notices.
