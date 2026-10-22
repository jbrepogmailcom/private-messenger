# Private Messenger 0.2.5 — independent, open-source SMP messenger

[Install](#ubuntu-source-installation) · [Start chatting](#two-terminals-or-two-separate-computers) ·
[Features](#security-and-privacy-features) · [Comparison](#comparison-with-other-messengers) ·
[Trust boundaries](#independence-across-the-communication-chain)

Private Messenger addresses selected limitations of conventional messengers:
mandatory phone-number registration, shared cross-contact identifiers, dependence
on one messaging provider, optional network privacy, and unverified contact keys.
It combines local identities, independent per-contact credentials, mandatory
fingerprint verification, hybrid ratcheting encryption and Tor-by-default delivery
through independently operated, open-source SMP servers.

**No single messaging company has to operate the entire communication chain.**
Users control their local identities and keys; clients can be inspected and forked;
the transport protocol is public; relay operators can be chosen independently.
The [SMP server source](https://github.com/simplex-chat/simplexmq) and
[wire protocol specification](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md)
are public; our client communicates with those routers without their chat engine.
This is architectural independence, not a claim that every dependency is free of
maintainer, infrastructure or government influence. The default configuration
currently uses one relay and has no automatic failover.

Python 3.12+ speaks SMP directly to unmodified public routers, over **TCP/TLS, not
WebSocket**. No SimpleX Chat engine, CLI, agent, database or Signal messaging
service is used. A small Rust extension calls pinned upstream **cryptography only**:
libsignal-protocol for authenticated hybrid establishment and its Triple Ratchet.
All SMP transport, queues, contacts, networking and persistence are our code.
This is a separate application protocol: SimpleX Chat contact invitations and
user databases are not interchangeable with this messenger's `PMS2:` invitations.

**Experimental and unaudited.** Working remote pairing and bidirectional encrypted
messages are verified; this is not a production security recommendation.

The selected upstream backend uses **X25519 + ML-KEM-1024 initially**, then a
Double Ratchet combined with **SPQR v1 / ML-KEM-768**. The original requirement of
ML-KEM-768 for the *initial* exchange remains unsatisfied. We preserve upstream
cryptography instead of inventing a replacement. No Signal application or PQXDH
interoperability certification is claimed. See [crypto dependencies](CRYPTO_DEPENDENCIES.md).

## Independence across the communication chain

The objective is independent choices at each layer, rather than replacing one
central messaging platform with another. An open protocol does not require one
company's hosted API, login service or approved application. An independently
implemented compatible client can use an unmodified SMP router.

| Layer | Independence provided | Remaining dependency or trust boundary |
| --- | --- | --- |
| Application | AGPL source, local builds and forks; our SMP client does not use SimpleX Chat or a remote messaging engine. | This implementation is currently maintained in one project and has not had an independent audit. |
| Identity | Keys are created locally; no phone, email, payment, central account or identity provider. | The device, operating system, random generator and vault password must be trustworthy. |
| Contact discovery and authentication | One-time public invitations and fingerprints exchanged through a user-chosen channel; separate identity keys per contact. | An invitation's self-signature does not identify a person. Users must compare fingerprints independently. |
| Cryptography | Public upstream specifications and pinned open-source implementations; no connection to Signal's service. | We depend on libsignal/SPQR, their maintainers, other cryptographic libraries and correct integration. We do not implement substitute primitives. |
| Network privacy | Tor uses relays operated by different parties; managed Tor or a configured external SOCKS proxy, with no direct fallback. | Tor implementation, directory authorities, relays and Internet access remain dependencies; global correlation resistance is not established. |
| Messaging transport | Direct Python implementation of the documented SMP wire protocol, authenticated with an explicit router certificate pin. | SMP's design/specification has upstream governance. Pin provenance and correct transport implementation matter. |
| Message relays | Open-source routers from independently selected operators; each receive queue names its router, so the two directions can use different operators. A compatible router can also be self-hosted. | Each existing queue depends on its selected router. Multiple configured servers are not automatic redundant delivery, queue rotation or failover. |
| Hosting and naming | No specific cloud company or country is required by SMP; operators can choose their own hosts. | Hosting providers, hostname/DNS operators, jurisdictions and network blocking can affect availability. A pin prevents accepted identity substitution, not denial of service. |
| Local storage | User-held encrypted vault and encrypted backups; no mandatory provider-hosted history archive. | Endpoints and backup copies can expose saved history; whole-vault rollback and guaranteed physical erasure are not solved. |
| Source and distribution | GitHub hosts the source, but running the chat needs no GitHub account or runtime GitHub API; source can be mirrored, rebuilt and forked. | Hosting and software distribution can be censored or compromised. Multi-party release approval, a transparency log and independently reproduced native releases are not deployed. |

There is **no central messaging account authority** whose permission is required
to create a profile or whose infrastructure must carry every conversation.
Individual router operators can still refuse service, and software maintainers
still influence updates. No claim of government immunity, censorship immunity,
fully decentralized development or absence of trusted components is made.

## Security and privacy features

The following describes the current `chat` implementation, not future roadmap
items. Exact assumptions and test evidence are in [SECURITY.md](SECURITY.md),
[THREAT_MODEL.md](THREAT_MODEL.md) and [VERIFICATION.md](VERIFICATION.md).

### Identity, contacts and authentication

- Local cryptographic identity creation without a server-side user account.
- No required telephone number, email, payment or centralized user directory.
- Fresh, independently generated identity keys, prekeys, protocol addresses and
  queue credentials for each contact; no common public user identifier across contacts.
- The global local identity and contact list are never sent to routers.
- Signed, seven-day, one-use public invitations containing routing and public
  keys, not vault passwords, private keys or permission to read the queue.
- QR-compatible invitation encoding; QR image rendering is not implemented.
- Explicit request acceptance and mandatory fingerprint verification before text
  messages flow. `/verify` displays the full fingerprint; `/yes` confirms the
  current unchanged fingerprint, and `/no` declines. Compare through an independently
  trusted channel: blind confirmation does not authenticate the person.
- Separate sender and recipient credentials for each unidirectional SMP queue.

### Content encryption and key evolution

- End-to-end encryption and authentication between client devices; the router's
  transport keys do not give it the application session's content keys.
- Upstream authenticated hybrid establishment with X25519 + ML-KEM-1024.
- Upstream Double/Triple Ratchet with fresh message keys and DH updates.
- Ongoing Sparse Post-Quantum Ratchet updates using SPQR v1 / ML-KEM-768;
  post-quantum protection is not limited to the initial exchange.
- Forward secrecy for past network ciphertext under key-erasure assumptions;
  this does not erase plaintext history or backups.
- Post-compromise recovery under the documented one-time exposure model, after
  attacker access ends and fresh honest exchanges occur; healing is not immediate.
- Out-of-order processing with bounded skipped-key storage, replay rejection,
  ciphertext integrity checks and authenticated conversation/context checks.
- Superseded setup/session state is retired; native owned serialized secret
  buffers are zeroized where supported. Python and allocator copies prevent a
  guaranteed memory-erasure claim.
- Pinned upstream cryptographic code through a crypto-only Rust binding. No
  messaging service, homemade cipher, KEM arithmetic or custom ratchet construction.

### Network privacy and server authentication

- Tor by default for ordinary `./chat NAME` sessions, including older DIRECT profiles.
- Automatic startup of an owned Tor process, or an explicitly configured external
  Tor SOCKS proxy; failure never triggers a direct connection or another proxy.
- Destination DNS resolution through SOCKS, with a literal proxy IP to avoid a
  separate proxy-host DNS lookup.
- Fresh SOCKS isolation credentials per connection; the managed Tor enables
  `IsolateSOCKSAuth`. External proxies must provide the corresponding isolation.
- Private RAM runtime directories for managed Tor and encrypted guard-state
  persistence on clean exit; crashes and swap still have limitations.
- Pinned TLS 1.3 server authentication, signed ephemeral SMP server keys and TLS
  Finished channel binding, with no insecure ALPN fallback.
- Highest supported compatible SMP version in v11–20; incompatible ranges are
  rejected instead of silently enabling an unsupported legacy version.
- Fixed 16,384-byte SMP transport blocks. This is limited padding, not cover
  traffic or proof against timing and volume correlation.
- No application telemetry, analytics or persistent network/debug logs.

### Local data and delivery safety

- Argon2id password derivation and XChaCha20-Poly1305 authenticated encryption of
  local SQLite snapshots. XChaCha here describes the vault; message encryption
  preserves the upstream authenticated cipher composition.
- Private directories/files, process locking, symlink rejection, authenticated
  snapshot metadata and bounded input handling.
- Atomic durable persistence of ratchet state, history, replay records and
  receipts before ACK; outgoing ratchet/ciphertext persistence before SEND.
- Bounded retries of the same saved ciphertext, with router-message and
  application-message deduplication across redelivery/reconnect.
- Offline encrypted storage at public SMP routers and subscription reconnection,
  subject to the chosen router's availability, quotas and retention policy.
- Separate server-acceptance and authenticated recipient-processing states;
  neither is represented as confirmation that a human read the message.
- Encrypted backups. Explicit restore keeps history but disables old sessions
  and pending sends until fresh pairing, avoiding deliberate stale-ratchet reuse.
- Confirmed `/del` retires local conversation state and deletes the user's own
  incoming queue; interrupted deletion can be resumed. `/del NAME --local` is an
  explicit alternative which leaves the server queue behind.
- Frozen numbered contact menus, explicit recipient selection after deletion,
  accidental invitation-paste blocking and terminal-control escaping reduce
  wrong-recipient and terminal-injection mistakes.

### Software integrity and verification

- Open-source application, crypto dependencies and compatible reference servers.
- Pinned/hash-locked Python dependencies, Cargo checksums and exact upstream revisions.
- Automated unit, property, security and opt-in integration tests; mock results
  are explicitly distinguished from actual public/local-reference router tests.
- Static analysis and known-vulnerability scanning, with dated results and limits.
- Source/artifact manifests and Ed25519 release-signature verification tools;
  trusted production signing governance is still incomplete.
- Documented deterministic build inputs and earlier same-machine wheel comparison;
  independent native build reproducibility is not established.

## Comparison with other messengers

This project addresses **selected limitations and default-policy tradeoffs**, not
every weakness of every messenger. Several alternatives already provide strong
E2E encryption, open source, decentralization or anonymous routing. Their
cryptographic and implementation assurance must not be equated with this
experimental integration's development tests. This is a comparison of ordinary
personal text messaging, not calls, public channels, business bots or group protocols.
Official documentation was checked on **2026-10-22**; deployments can change.

| Messenger | Limitation or tradeoff addressed here | This project's approach and qualification |
| --- | --- | --- |
| Telegram | Ordinary Cloud Chats are not end-to-end encrypted; its hosted service is centrally operated, and server source is not published. | E2E for every supported conversation, local registration, independent SMP operators and Tor by default. Telegram Secret Chats already have E2E, and its clients/API are open; openness alone is not our unique advantage. [Official FAQ](https://telegram.org/faq). |
| Signal | Registration still requires a phone number, despite usernames allowing contacts to connect without sharing it; ordinary use depends on Signal's messaging service. | No phone-number registration, independently keyed contacts and independently selectable SMP operators. Signal also publishes source and already has SPQR/Triple Ratchet; stronger encryption than Signal is not demonstrated. [Registration](https://signal.org/blog/phone-number-privacy-usernames/), [server source](https://github.com/signalapp/Signal-Server), [SPQR](https://signal.org/blog/spqr/). |
| Meta / Facebook Messenger | Dependence on Meta's application/account/service infrastructure. | Local identities, open-source client, user-selected relay operators and Tor-default routing. Personal Messenger chats have default E2E; our claimed distinction is control and architecture, not the absence of encryption there. [Official E2E explanation](https://about.fb.com/news/2024/03/end-to-end-encryption-on-messenger-explained/). |
| SimpleX Chat | Different application defaults and implementation dependencies; Tor and manual verification are available as choices in its documented settings. | Independent Python SMP implementation, automatically managed Tor by default and mandatory manual fingerprint confirmation. SimpleX already offers open source, independent relays, no global user IDs and post-quantum encryption. No overall security or anonymity improvement over SimpleX has been established. [Features](https://simplex.chat/messaging/), [security settings](https://simplex.chat/docs/guide/privacy-security.html). |
| Session | Sharing one Account ID across contacts creates a reusable identifier. Its current FAQ describes PFS restoration and PQ support as work for Protocol V2. | Independent contact identities and an implemented ongoing hybrid ratchet. Session already has open-source code, decentralized routing and onion requests; decentralization is a shared benefit. The cryptographic comparison must be revisited when V2 is deployed. [FAQ](https://getsession.org/faq), [network](https://docs.getsession.org/session-network). |
| WhatsApp | Phone-number registration and dependence on Meta's service; its policy describes collection of account, usage and diagnostic information. | Local registration without phone/email, no application telemetry, independent contact keys and configurable SMP operators. WhatsApp personal messages already have default E2E; E2E alone is not an improvement over it. [Privacy policy](https://www.whatsapp.com/legal/privacy-policy), [messaging guidelines](https://www.whatsapp.com/legal/messaging-guidelines). |
| Matrix / Element | A Matrix account is associated with a homeserver and a reusable Matrix identity; federation has different metadata and administrative tradeoffs. | Local-only profile creation and pairwise routing identities without a common user address sent to routers. Matrix is already open and decentralized, supports E2E and has many clients; this project does not claim to improve every federation or group use case. [Introduction](https://matrix.org/docs/guides/introduction/), [open specification](https://spec.matrix.org/latest/). |
| Briar | A different peer-to-peer design and connectivity model, rather than a centralized-provider limitation. | SMP router store-and-forward delivery is this project's approach to offline recipients. Briar already offers open-source, decentralized, E2E and Tor-based communication; no general privacy superiority over Briar is established. [Architecture](https://briarproject.org/how-it-works/), [project](https://briarproject.org/). |

Open source enables independent inspection and continuation of a project; it does
not itself prove the running binary or a remote server is honest. Hosting on
GitHub does not prevent malicious updates. An operator's country is not a security
guarantee. The useful property is **separation of control and minimized trust**,
not an unsupported promise of independence from every authority.

## Current security limits

- No independent audit of this application or its complete cryptographic integration;
  it is not production-ready and comparative superiority is not proven.
- No protection for open messages while an attacker controls an unlocked endpoint.
- Identity signatures remain classical: post-quantum confidentiality mechanisms
  do not establish post-quantum authentication against active signature forgery.
- No proven resistance to global traffic correlation, no mixnet or cover traffic,
  and no guarantee against router deletion, censorship or denial of service.
- No automatic redundant delivery, authenticated in-place queue/identity rotation
  or migration of established queues when the configured server list changes.
- No detection of malicious rollback to a valid old whole-vault snapshot, or
  guaranteed memory/SSD/backup erasure. PFS does not conceal saved local history.
- No deployed multi-party release approval, transparency log, trusted production
  signing identity or independently verified reproducible native releases.

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
/yes
```

Alice can now type `Hello Bob!`; Bob sees it and can reply by typing text. With
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
All **in-chat commands require a leading `/`**, including `/yes` and `/no` for
verification. Ordinary text is a message, even if it is the word `help` or `quit`.
Unknown slash commands never become messages. Pasted invitations, JSON invitation
exports and long Base32 fragments are blocked from messages and direct the user
to `/add`, preventing accidental forwarding to the selected contact.

The guided `/yes` confirmation is available after displaying `/verify`;
changing conversations cancels that confirmation. It never bypasses fingerprint
comparison or automatically trusts an invitation's self-signature.

To add Charlie while Alice already chats with Bob, Charlie runs `./chat Charlie`
and `/address`. Alice pastes Charlie's generated `/add Charlie PMS2:…` command;
Charlie accepts with `/accept`; both compare `/verify` and confirm with `/yes`.
Alice can then switch between Bob and Charlie using the numbered `/chat` list.
Each contact has its own encrypted conversation.

To reset a contact, use `/del Charlie` (or `/del 2` from the displayed list, or
`/del` for the selected contact), then explicitly confirm `/yes`; `/no` cancels.
This removes that contact's local history, ratchet/prekeys, outgoing credentials,
outbox and replay/delivery records, closes its sender connection, stops its
receiver, and deletes **your own incoming SMP queue**. A deleted recipient is
cleared from the prompt; another contact is never silently selected instead.
To test from scratch, delete the corresponding contact on both endpoints, then
generate a fresh `/address` and repeat `/add`, `/accept`, `/verify` and `/yes`.
The local profile and unrelated contacts remain intact. `/contacts --all` also
lists unused local invitations, which can be deleted by their displayed number.

Deletion first durably retires local conversation state. If network/server deletion
fails, a visible `deleting` record retains only encrypted queue credentials needed
to retry `/del` (including after restart); no old session or queued message resumes.
Only `OK` is reported as server-confirmed deletion. `AUTH` permits local cleanup
but is reported as unconfirmed, since it cannot distinguish a missing queue from
rejected credentials. Local deletion does not erase another device's copy, existing
backups, or guarantee physical erasure on SSDs/in Python. See [security](SECURITY.md).

If a server remains unavailable, `/del NAME --local` followed by `/yes` discards
all remaining local contact data **without contacting the server**. The confirmation
explicitly says that the remote queue will remain and its access keys will be lost.
This is an opt-in local operation, not an automatic substitute for server deletion.

[Step-by-step two-client guide](TEST_TWO_CLIENTS.md). Each profile is created separately
in `~/.local/share/private-messenger/secure-profiles/`; passwords need not match.
The old same-computer demo remains available as `./chat-legacy` in its original
`terminal-demo/` directory. Its static Box keys have no PFS/PCS/PQ protection.
There is no automatic migration, shared setup, or overwrite of existing profiles.

## Ubuntu source installation

On Ubuntu 24.04+, install Python 3.12+, a C toolchain, protoc and libsodium:

```bash
sudo apt install python3 python3-venv python3-pip libsodium23 git build-essential protobuf-compiler tor
git clone https://github.com/jbrepogmailcom/private-messenger.git
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

Geography is not a security guarantee; see [server evidence](SERVER_SELECTION.md).
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
