# Verification record — 2026-10-21

These are development-session results, not an independent audit or proof of
cryptographic security. Integration results are distinguished from synthetic
fixtures and unit tests.

## Environment

Python 3.12.7, SQLite 3.46.1, pyOpenSSL 26.4.0 using OpenSSL 4.0.3,
cryptography 50.0.2, PyNaCl 1.6.2, native libsodium 1.0.18, Tor 0.4.8.14,
uv 0.11.7, Linux x86-64. Exact Python dependencies and hashes are in the locks.

## Actual public infrastructure

Router: `smp4.simplex.im:5223`, advertised identity
`u2dS9sG8nMNURyZwqASV4yROM28Er0luVTx5X1CsMrU=` from the
[upstream README](https://github.com/simplex-chat/simplexmq/blob/27a37387be98d9c7ec0e62373e125539675d0095/README.md).
This router offered versions 14–22. The client selected v20, its highest supported
version. Deployed TLS certificates were Ed448. Queues were temporary and deleted.

`PM_PUBLIC_SMP_SERVER=… pytest -q -m public` — **8 passed**:

- Real Alice/Bob processes exchange opaque encrypted random payloads. Bob's process
  exits completely before offline SEND and restarts to retrieve the stored bytes.
- Bob exits without ACK; after another restart the redelivered bytes retain the
  same router ID and do not create a second local record. ACK then empties the queue.
- Bob's subscribed process and Alice's separate sending process run concurrently
  for online delivery.
- Version-specific NEW/IDS/service-auth formats exercised at v14, 15, 16, 17,
  18, 19 and 20. Each creates, secures and deletes a real queue.
- Wrong sender signature, use of sender ID for recipient command, wrong ACK ID,
  disconnect/reconnect, exact ciphertext recovery and redelivery were tested.

This verifies opaque transport. It does not verify a conversational KEX, contact
authentication, application AEAD headers or a ratchet. Router acceptance is not a
recipient receipt. Published payload digests/queue credentials are intentionally
omitted from this report.

The standalone two-process online/offline/redelivery demo also passed against a
second actual public router, `smp5.simplex.im`, pinned to
`hpq7_4gGJiilmz5Rf-CswuU5kZGkm_zOIooSw6yALRg=`, negotiating v20. Its temporary
queue was deleted. The version-matrix pytest run was on smp4 only.

## Unmodified local reference server

Official release asset `smp-server-ubuntu-24_04-x86-64`, tag `v6.5.0`;
binary reports `SMP server v6.5.0.17 / ba6af65`.
SHA-256 `0ec0984a9f15d8a140c96e0c84948e37f581ed0a0140e6fc1d5677dcc9e5144c`,
matched GitHub's asset digest. This is asset integrity evidence, not an independent
signed-release verification of the upstream executable.

`python scripts/test_local_reference.py /path/to/binary` — **7 passed**.
The server ran in a disposable unprivileged network namespace, no external
interface or service installation, with ordinary temporary configuration only.
No server code/binary was modified. v11, 14, 15, 16, 17 and 18 passed the real queue,
authorization, send/get/ACK and disconnect/redelivery path. The server offers v6–18;
a client requiring v19 correctly rejected it rather than downgrading.

## Real Tor versus SOCKS fixtures

`python scripts/test_real_tor.py --server …smp4.simplex.im` — **passed** after an
actual Tor circuit reached 100% bootstrap. A disposable, already installed Tor
process with `IsolateSOCKSAuth` carried pinned TLS/SMP v20 PING, NEW and DEL.
Only that test's own Tor process was stopped and its temporary directory removed.

Separate synthetic local SOCKS5 wire tests verify destination domain-name encoding,
no destination `getaddrinfo`, distinct auth credentials per connection and no
DIRECT fallback when SOCKS fails. Those tests are not represented as real Tor
interoperability or packet-capture proof of all possible DNS leakage. No broad
traffic-correlation, onion-service or global-adversary experiment was performed.

## Local, property and security tests

Default `pytest -q` — **33 passed, 15 skipped** (real infrastructure is opt-in).

Covered: local identities/persistence, binary framing/bounds, property-generated
padding and batches, property comparison with libsodium's DH box, published
NaCl/libsodium box vector, transport chain key progression, transport replay and
tampering rejection, certificate identity/path and signed-key failures, synthetic
handshake channel binding, command-signature context binding, queue serialization,
invalid delivery ciphertext/flags, vault wrong passphrase/tampering/recovery,
process lock, duplicate-ID conflict, failed write rollback, restrictive permissions,
private-file symlinks, release signature modification/key substitution and artifact
hash/path checks.

Synthetic handshake/certificate/proxy fixtures are unit/security tests, not
reference-server tests. Hypothesis checks use its default bounded example counts;
they are not exhaustive formal verification or sustained fuzzing.

Ruff lint/format and Bandit on application source passed. Runtime and development
pip-audit scans found no known vulnerabilities on the test date. The first build
audit found `PYSEC-2026-3447` in setuptools 82.0.1; the backend and build lock were
updated to patched setuptools 84.2.1 (wheel 0.48.0); its final scan found no known
vulnerabilities either. No OS/native-package vulnerability scan or
independent code audit is implied.

## Built distributions

Source commit `1385d85` produced a wheel and sdist in `dist/`. A second wheel build
from a fresh `git archive` directory using the same pinned tools, Python 3.12 and
SOURCE_DATE_EPOCH was byte-identical. Both wheel SHA-256 values:
`0ee9eaa0fa1eeb0cb97b0dad7481d19bef24a216b76eb5873d62ad937643da68`.
This verifies reproducibility on this machine with these inputs, not independent
multi-party reproducibility. The sdist was built but not reproducibility-compared.

The wheel was installed with hash-verified runtime dependencies in a separate
clean Python 3.13 environment; register, identity and status passed. The full test
suite and network integrations used Python 3.12. A canonical source/artifact
manifest and throwaway-key development signature were generated and verified.
The development public key proves no publisher identity and is explicitly labeled
untrusted for updates. No release private key was retained or production key
distribution established. `dist/` is generated and excluded from Git.

## Earlier follow-up transport tests

The follow-up one-command `scripts/demo_swiss.sh` launcher also passed its real
Swiss-router run. It downloads only the operator's public configuration over
validated HTTPS, pins the known router identity and performs the existing
two-process transport demo. Two additional fixture tests verify rejection of
changed router identity/host/port and insecure or cross-origin redirects. These
fixture tests passed, as did Ruff. Its temporary profiles and queue were cleaned
up; it does not implement text chat or create permanent user accounts.

Follow-up on the same date: a full two-process demo passed on the independent
Urban-Network relay (`urban-network.dyndns.org:5224`, v18) using its operator's
published queue-creation password. Online/offline delivery, redelivery/deduplication,
ACK and cleanup passed. A narrow CLI/demo option loads router creation credentials
from a private file, validates it before network contact and does not put the
password in process arguments or invitations. The updated default suite passed
**34 tests, 15 skipped**; Ruff and Bandit passed. The original public/local matrix
results above remain historical runs of their stated source. Detailed geographic
evidence and operator-trust limits are in SERVER_SELECTION.md. The distributions
described above predate this follow-up and do not include this CLI option.

## Interactive local-pairing demo (2026-10-21)

The new executable `chat` launcher was verified against the unchanged public
Urban-Network SMP router in Switzerland (v18), with two independently running
Python clients. No mocks or local forwarding transport were used for these runs.

Two opt-in integration tests passed separately:

```bash
PM_PUBLIC_TERMINAL_DEMO=1 .venv/bin/pytest -q \
  tests/integration/test_terminal_demo.py
```

- Two-process online Unicode text delivery and replies, idle SUB beyond the normal
  operation timeout without reconnect, Bob's complete exit and restart, offline
  delivery, processing the next message returned by ACK, encrypted history
  restoration, and republishing the identical authenticated application ciphertext
  twice under distinct router IDs. Bob retained one history row and displayed the
  replay fixture once; its queue was empty after ACK. This test passed in 35.03s.
- Two actual controlling pseudo-terminals launching the executable `./chat`, first
  setup via hidden password/confirmation prompts, Bob's login with the same
  password, and typed text in both directions. The password was absent from both
  terminal outputs. This test passed in 11.97s.

All test queues were deleted and all test profiles used temporary directories;
no persistent Alice/Bob profiles or password were installed for the user. First
normal use asks the user to choose a password. The default source suite passed
**43 tests** (16 integration skips at that point, before the additional opt-in PTY
test was added). Seven new local message tests cover out-of-order static-key
messages, Unicode/size bounds, standard Box interoperability, tampering, reflection,
conversation-context mismatch, replay/conflicting IDs, restored history, failed
snapshot rollback before ACK, and terminal-control escaping. These are not ratchet
tests. Ruff lint/format, Bandit on source and shell syntax checks passed.

The launcher uses locally provisioned standard NaCl Box payload keys; it does not
implement the planned reviewed hybrid session establishment or ratchet. The new
message/context envelope has no independent audit. Its results prove the stated
test behavior on this router, not PFS/PCS/PQ properties or remote pairing security.
Existing generated distributions predate these source changes; use the source
checkout's `chat` launcher. There is no newly signed production release.

Follow-up: `/address` and offline `chat Bob --address` display only the receiving
router URI, sender queue ID and payload public key. All nine focused local-message
tests passed, including two added assertions that recipient credentials/private
keys are absent and that the offline command neither accesses the network nor
changes the encrypted vault snapshot. Existing user profiles were not decrypted
or modified for these tests. The previously verified public-message transport is
unchanged; no additional public-router test was needed for the local display.

## New session implementation

The earlier results above describe the legacy source at the stated dates. The
2026-10-22 results and remaining gaps are recorded below.

## Secure remote messenger candidate — 2026-10-22

New `chat` uses separate profile generation and passwords. The old static-key
same-computer fixture is retained as `chat-legacy`. Real cryptographic operations
use the pinned native backend, not mocks: libsignal commit
`b369755533ef5a3fae9b31b989114f22e074dfab`, SPQR v1.6.0,
Rust 1.98.1, protoc 33.1, PyO3 0.30.1. No upstream crypto modifications.
**Initial ML-KEM-1024 differs from the originally required ML-KEM-768.**
The ongoing ratchet is SPQR v1 / ML-KEM-768 plus upstream Double Ratchet.
No Signal application/PQXDH interoperability certification or external audit.

### Actual public router, separate processes

Pinned Swiss Urban-Network `urban-network.dyndns.org:5224`, negotiated SMP v18,
unchanged server. Command:

```bash
PM_PUBLIC_SECURE_MESSENGER=1 .venv/bin/pytest -q tests/integration/test_secure_messenger.py -k DIRECT
```

**1 passed in 17.59s** after the PyO3 security update (an earlier backend run
also passed). The subsequent actual TOR test exercised the new executable `chat`
launcher with the same core scenario, **1 passed in 36.71s**:

- Bob generates a signed public invitation; independently created Alice connects
  using only it; Bob receives/accepts; both compute and confirm the matching
  60-digit fingerprint before application text can be sent.
- Bidirectional encrypted Unicode text and authenticated recipient receipts.
- Bob fully exits; Alice sends two messages accepted into his router queue; Alice
  exits too; Bob restarts and decrypts, Alice restarts and receives receipts.
- Test republishes identical application ciphertext with a fresh router message ID;
  Bob's history retains one copy, and his subsequent encrypted reply is received.
- Independent vault directories/passwords; no shared setup or SimpleX/Signal engine.
  All test queues deleted and temporary profiles cleaned up. Existing user profiles
  were not decrypted or modified. Test passwords/keys are absent from this record.

The TOR run used an owned disposable Tor 0.4.8.14 process, actual 100% circuit
bootstrap, local SOCKS with IsolateSOCKSAuth. Client setup, SMP operations, replay
injection and queue cleanup all used TOR, without DIRECT fallback. The operator's
HTTPS site returned a 200 antibot challenge to Tor (no router descriptor); that
attempt failed closed. The successful run supplied the public NEW password to
both encrypted test profiles out of band. Its test harness fetched that public
credential over DIRECT HTTPS **before client execution**; this preparatory fetch
is not represented as anonymous or Tor website interoperability. Normal TOR
clients never perform that direct fetch. No global packet-capture anonymity proof.

### Native cryptography and state tests

Real upstream encryption/decryption tests include out-of-order initial messages,
replay rejection, corrupted ciphertext without state mutation, signed-prekey/
legacy-KEM downgrade rejection, one-use setup-key retirement, mandatory fingerprint
verification and the published upstream fingerprint v2 vector. A 2003-message
same-chain experiment confirms skipped keys are bounded: a retained middle key
works and the evicted oldest key cannot decrypt. A current protocol state cannot
decrypt a consumed earlier packet after further DH steps (logical erasure test).

Classical PCS experiment: a snapshot initially decrypts a subsequent response,
then fails after honest fresh DH exchange. Honest peers still communicate.
Full Triple Ratchet exchanges progress beyond PQ epoch 3/4 and require SPQR v1.
A separate **native Rust SPQR-only** experiment removes classical DH entirely:
attacker receives a complete earlier endpoint state and sees all subsequent
protocol messages, but has no future endpoint/RNG control. It initially derives
56 reply keys, then loses access at round 56 after fresh KEM entropy. This test
passed on PyO3 0.30.1's locked dependency tree (1.45s test time). Healing delay is
this fixture's result, not a guaranteed universal number of messages.

These are behavior experiments with real cryptography, not formal PFS/PCS proofs,
quantum simulations or independent inter-implementation vectors for hybrid KEX.
No new cryptographic construction was substituted for unavailable functionality.

Application unit tests use a **mock relay**, explicitly distinguished from the
public integration above, but real native crypto/vault. They verify exact-byte
ambiguous-SEND retries, cross-ID duplicate handling, failed snapshot atomic rollback
including generated receipt/ratchet, fingerprint mismatch, and restore invalidation
of old sessions while retaining history. Property tests generate real native
binary-message round trips, parser inputs and bounded compressed invitation data.
SQLite secure-delete tests check superseded private records are absent from the
current serialized snapshot, not physical media/memory erasure.

### Performance and supply chain

A local benchmark (`scripts/bench_crypto.py`, 160 rounds, 320 messages, 256-byte
payload) measured packet size min 366, max 2054, mean 399.94 bytes **including the
37-byte app header, excluding SMP's fixed 16-KiB framing**. Median encrypt/decrypt
5.735/6.357 ms includes JSON binding/state serialization, excludes vault KDF/I/O
and network. Hardware/environment dependent development sample, not a throughput
or latency guarantee. Native status showed session v4 and SPQR v1 negotiated,
Alice epoch4/send3, Bob epoch3/send3.

Ruff/Bandit and Rust fmt/clippy (`-D warnings`) passed. Python runtime pip-audit
found no known vulnerabilities. Rust audit first found PyO3 RUSTSEC-2026-0176 and
0177 at 0.27.2; upgraded to **0.30.1** and rebuilt/retested. Final cargo-audit 0.22.2
reported **zero known vulnerabilities**, plus one maintenance warning:
`proc-macro-error2` 2.0.1, RUSTSEC-2026-0173 (unmaintained), through hax-lib-macros
in the all-target dependency graph. It was not selected in the active Linux
build tree. This warning is documented, not ignored or called a clean audit.
No independent audit of native system packages/compiler was performed.

### Remaining gaps

Exact initial ML-KEM-768; independent hybrid/Signal-app interoperability vectors;
independent application/security audit; malicious whole-file rollback detection;
guaranteed secret deletion; PQ authentication; authenticated queue/identity rotation;
cover traffic; redundant delivery; real mixnet; broad correlation resistance;
seamless historical ratchet recovery; multi-party release governance/transparency;
and independent native reproducibility remain unavailable or unverified.

Final source checks after secret-buffer retirement hardening: **68 passed,
19 skipped** in 44.18s; skipped tests require explicit public/local-reference
infrastructure opt-in. Native fmt/clippy and SPQR experiment passed; runtime,
development and build Python dependency audits found no known vulnerabilities.
The Rust maintenance warning above remains. Wrapper-owned serialized private
buffers are zeroized best effort on retirement/drop; this is not a memory-proof.
The 0.2 platform wheel and source archive built successfully: wheel contains its
native backend and is not marked pure Python; sdist contains Cargo source/lock and
tests and excludes compiled binaries/target directories. Independent reproduction
and a trusted signature on these new development artifacts remain unverified.

Final DIRECT integration of the executable launcher passed in **18.01s**, also
exercising delayed verification: Alice sends while Bob has not yet confirmed the
fingerprint; Bob rejects without ACK/history insertion, then his explicit valid
verification resumes the queued ciphertext and delivers it without restarting.
TOR evidence above predates this additional UI recovery assertion; it retains
its stated successful online/offline/receipt/replay scope.

Build/verification scripts now explicitly select the Rust channel from the native
toolchain file and reject a mismatched compiler even when invoked from the project
root. Rebuild, fmt/clippy, SPQR test and audit passed with that enforcement. The
platform wheel also passed an import smoke test from its extracted contents,
independently of the editable source import. The final benchmark above was rerun
on the zeroizing 0.30.1 binding; its timings are environment-dependent.

## TOR-by-default correction — 0.2.1, 2026-10-22

The previous chat default was DIRECT and did not implement the user's requested
ordinary Tor workflow. Corrected: `./chat NAME` selects TOR after unlock, before
any messaging connection, even if this profile previously saved DIRECT. Existing
processes require quit/restart; prior IP exposure cannot be undone. DIRECT chat
requires an explicit `--network DIRECT` on that invocation. Configured external
Tor proxy parameters are retained, and errors never change to managed Tor or DIRECT.

Without external proxy configuration, chat starts an owned installed Tor process
with isolated SOCKS authentication and waits for 100% bootstrap. It changes no
system service and terminates only its own process on exit/failure. The documented
Tor `__OwningControllerProcess` option monitors owner death (15-second polling).
A private RAM directory under `/dev/shm` contains runtime files; guard state is
retained inside the encrypted vault on clean shutdown and restored next time.
Crashes can leave RAM files/new guard state unsaved; swap/erasure limits remain.
Full Tor logs are discarded; only bootstrap percentages reach the terminal.

The default relay's **public** NEW credential was independently refreshed from
the operator's CA-validated HTTPS descriptor, checking the exact existing relay
pin/host/port. It is bundled public configuration, not a user secret or private
key. Runtime chat now performs no operator-web fetch, so that site's Tor antibot
challenge requires neither a direct request nor extra setup. A changed operator
credential requires a reviewed configuration update or explicit file import.

Actual unmodified public Swiss SMP, default launcher test:
`test_secure_remote_pairing_online_offline_restart_and_replay[MANAGED_TOR]`
— **1 passed in 182.44s**, no supplied router-password file. Alice/Bob started with
separate encrypted profiles deliberately configured DIRECT, then logged in through
plain `./chat NAME` without a network override. Both were automatically switched
to TOR, each started its own actual Tor, and asserted the TOR network status. Signed pairing,
fingerprints (including delayed verification), Unicode traffic, encrypted receipts,
Bob completely offline, both-process restart, replay with fresh router IDs and
single history insertion all passed. Their encrypted guard state survived restart.
Temporary profiles and queues were cleaned up. A separate owned real Tor SOCKS
proxy carried the test's injection/cleanup traffic; no test SMP path used DIRECT.
All test-owned Tor processes were stopped. Existing user profiles were not opened.

Default suite: **74 passed, 20 skipped in 29.71s**. Six new policy/lifecycle tests
use explicit synthetic Tor child fixtures, not claimed as real Tor experiments:
old DIRECT migration, external proxy preservation, invalid ports without writes,
no DNS/direct/alternate-proxy fallback, missing Tor, early exit/bootstrap timeout,
owned child cleanup and encrypted/restored guard metadata. Existing SOCKS wire
fixtures verify remote DNS and isolation. Ruff lint/format, Bandit, runtime
pip-audit passed. Native cryptography was unchanged by this network correction.
No global packet-capture or traffic-correlation resistance claim is added.

## Guided chat correction — 0.2.2, 2026-10-22

The reported failure was reproducible UI behavior: pasting the complete invitation
export was shell-split, `verify` required an unexplained local ID, and unaccepted
or unverified contacts produced a generic English send error. The terminal now
accepts the whole JSON export or the PMS2 token, supports unique contact names,
bare `accept`/`verify`/`history`, and explicitly guides acceptance and verification.
After displaying a fingerprint it offers `ano`/`ne`; only an explicit confirmation
of the unchanged displayed contact sets verification. Conversation changes cancel
that prompt. Ordinary messages preserve quotes and apostrophes without shell parsing.
Human output shows pairing/delivery states and redraws the prompt once per event.

Actual unmodified Urban-Network SMP over real Tor: **2 passed in 97.09s**:

- `test_guided_two_real_terminals_over_tor_online_offline_and_restart` uses two
  independent Python processes attached to actual pseudo-terminals, exercising the
  human-facing interface. A complete JSON invitation crosses terminal input;
  sending before acceptance is blocked; Bob types bare `accept`; Alice uses
  `verify Bob` and Bob bare `verify`; the test independently compares their full
  fingerprints before typing `ano`. Unicode/quotes/apostrophes arrive intact in
  both directions with authenticated receipts. Bob exits completely; an offline
  message survives both-process exit/restart; the resumed single contact needs no
  ID. Bob's history has exactly two incoming messages.
- `test_secure_remote_pairing_online_offline_restart_and_replay[TOR]` repeats
  the existing machine-readable CLI regression through actual Tor, including
  complete JSON paste, delayed recipient verification/resubscription, authenticated
  receipts, offline delivery, both-process restart and replay deduplication.

Both clients in this run used a configured external SOCKS port backed by the
test's own installed Tor process, with per-connection SOCKS isolation. Bootstrap
reached 100%; no direct SMP fallback was used. Temporary queues/profiles were
cleaned up and only that test-owned Tor was stopped. User profiles were untouched.
The two-owned-Tor default-launcher result above remains a historical 0.2.1 run;
it was not repeated as part of this UI correction. A preceding disposable Tor
attempt had timed out at 56%, illustrating that independent Tor bootstrap can be
slow; this update does not claim to fix network bootstrap delays.

Default suite: **87 passed, 21 skipped in 71.40s**. Added application fixtures use
real native cryptography and encrypted vaults with a **mock relay**, separately
from the two real-infrastructure tests. They cover copied exports without trusting
outer metadata, malformed exports without network/queue effects, guided pairing,
refusal before verification, negative confirmation, duplicate-name ambiguity,
cancelled verification after contact selection, restart selection and short parser
errors. Final follow-up UI checks also cover repeated acceptance and ambiguity
during acceptance. These are bounded functional checks, not a security audit.

Pinned `tqdm` 4.70.1 supplies the one-line Tor thermometer. A manual 80-column PTY
check verified carriage-return redraws, one final newline, a partial bar on failure
and idempotent close. Redirected output retains ordinary event lines. Runtime and
development dependency scans found no known vulnerabilities. Native primitives,
ratchet composition and their documented security limitations are unchanged.

## Slash commands and multiple contacts — 0.2.3, 2026-10-22

All interactive chat commands now require `/`, including `/quit`, `/verify` and
the explicit fingerprint confirmation or rejection commands. Bare words such
as `help`, `verify` and `quit` are ordinary message content. Unknown slash commands
fail instead of becoming messages. The separate one-shot shell CLI is unchanged.

`/address` generates a complete `/add NAME PMS2:…` command ready to copy into the
peer's terminal. `/add INVITATION`, `/add NAME INVITATION`, `/add JSON_EXPORT` and the existing
`/connect` alias initiate an independently keyed contact without sending the code
to the selected conversation. A guard blocks invitation markers/JSON exports and
long Base32 fragments before message encryption/history/outbox insertion, including
the reported plain-text invitation-paste mistake and accidental `/send Bob INVITATION`.

`/chat` and `/contacts` display numbered saved contacts, excluding unused local
invitations. `/chat NUMBER`, `/chat NAME` and `/chat ID` select the recipient shown
in the prompt. Number-to-contact mappings are frozen to the displayed list;
new incoming contacts cannot silently shift the meaning of `/chat 2`. Showing a
new list refreshes the mapping. Duplicate names still require an unambiguous
number or ID. Acceptance and fingerprint verification remain mandatory.

Actual public Urban-Network SMP over real Tor: **2 passed in 90.53s**:

- `test_three_real_terminals_add_contact_choose_recipient_offline_restart` runs
  Alice, Bob and Charlie in three independent Python processes attached to real
  pseudo-terminals. After authenticated Alice/Bob pairing and bidirectional text,
  Charlie generates `/address`. Alice's reported bare invitation-paste input is
  blocked while Bob is selected, and the actual generated `/add Charlie …`
  command initiates a separate conversation. The test compares complete native
  fingerprints independently before explicit confirmation. `/contacts` lists Bob and Charlie;
  `/chat 1` and `/chat 2` update the prompt and deliver separate messages only to
  their intended recipient. Charlie replies; his history contains exactly his
  one intended incoming message; Bob's contains his three intended messages,
  including offline delivery after Bob and Alice exit/restart. Charlie's invitation
  is absent from Bob's output. No mocked network or cryptographic backend is used.
- `test_secure_remote_pairing_online_offline_restart_and_replay[TOR]` passes
  with slash-prefixed machine-readable commands, including whole-JSON invitation
  import, delayed verification, receipt/resubscription, restart and replay checks.

Clients used a configured external SOCKS port backed by the test's own actual
installed Tor. It reached 100% bootstrap; all SMP/injection/cleanup connections
used TOR with per-connection isolation, without DIRECT fallback. Temporary queues
were deleted, profiles discarded and that test-owned Tor stopped. User profiles
were not opened. This does not add evidence about global traffic correlation or
guarantee future Tor bootstrap speed.

Default checks: **91 passed, 21 skipped in 74.31s**, Ruff lint/format and Bandit
passed; runtime pip-audit found no known vulnerabilities. Application fixtures
use real native cryptography and encrypted vaults with an explicitly mock relay.
New assertions cover strict slash parsing versus plain words, adding Charlie
while Bob is selected, rejected invitation pastes without side effects, duplicate
invitation guidance, frozen menu numbers after another stored contact appears,
out-of-range selection, and distinct per-contact message histories. These fixtures
are separate from the actual three-terminal public-infrastructure run above.

## Contact removal and fresh pairing — 0.2.4, 2026-10-22

`/del NAME`, `/del NUMBER` (from the displayed menu), and `/del` for the selected
contact require explicit confirmation; rejection or intervening commands cancel the prompt.
The immutable local contact ID is bound to the confirmation. `/contacts --all`
also exposes unused local invitations for the same deletion workflow.

Deletion has two durable steps. First, one encrypted transaction removes messages,
outbox, replay/delivery records, prekeys, outgoing credentials and native session
state; a non-messaging `deleting` record retains queue credentials for DEL. The
sender connection closes and the contact-specific receiver is signalled to stop.
Already queued delivery/ACK/connection/reconnect/fatal events are rejected for
retired contacts before touching state. Receiver workers are given only the ID,
incoming server and SMP receive credentials, never application ratchet state.
Then native Python SMP sends authenticated DEL through the configured pinned/Tor
transport, and a second transaction discards the final contact/queue credentials.
AUTH allows local cleanup but is explicitly reported as unconfirmed, not proof
of remote erasure. Other failures retain the visible retirement record for retry
after restart, without restoring old messages or session keys.

An explicit `/del NAME --local` requires its own confirmation, including when a
remote deletion was previously confirmed but remains pending. It discards the
final local credentials without contacting the server and warns that the remote
queue remains. There is no silent local-only or DIRECT fallback. Deleting the
selected contact blocks implicit recipient selection until the user chooses a
contact; even a single remaining Bob cannot receive the next text by accident.

Default checks: **98 passed, 21 skipped in 66.01s**, Ruff lint/format and Bandit
passed; runtime pip-audit found no known vulnerabilities. Seven focused deletion
tests passed, including final follow-up checks for explicit recipient selection
and keeping native session state out of subscription workers. These tests use
real native cryptography and encrypted vaults with a **mock relay**, not claimed
as public-server interoperability. Assertions cover complete removal of relevant
table records, preserved unrelated contacts/profile, new native identity and queue
keys after fresh pairing, cancellation and stale confirmation, deletion of unused
invitations, receiver event races, network failure and serialized retirement-state
restoration, initial disk failure without side effects, final disk failure after
DEL with an AUTH retry, and forbidden router contact for both ordinary and pending
explicit local-only deletion. Logical state deletion does not prove physical
memory/SSD erasure, remove old backups, or erase the other endpoint's history.

Actual public Urban-Network SMP v18 over real Tor: the extended
`test_three_real_terminals_add_contact_choose_recipient_offline_restart` passed
in **150.97s**. Alice, Bob and Charlie ran in independent Python processes with
real pseudo-terminals. Both sides confirmed contact deletion; authenticated DEL
returned success and subsequent GET with the retired recipient credentials
returned AUTH. Alice retained Bob, then paired with Charlie using a new invitation,
new queue IDs, new identity keys and a different verified fingerprint. Fresh
bidirectional messages, intended-recipient selection, Bob's offline delivery and
restart, and absence of old contact records in all relevant tables passed.
These observations do not prove a server discarded every copy of stored bytes.

This run used a test-owned installed Tor as an explicitly configured external
SOCKS proxy, with per-connection isolation and no DIRECT fallback. The harness
allowed 300 seconds for Tor bootstrap; the application's 180-second default was
unchanged. Earlier attempts encountered a bootstrap timeout or a PTY test timeout;
the harness now drains Alice's long invitation command output before waiting for
Charlie's request, avoiding producer backpressure and surfacing sender errors.
The separate existing non-TTY public-Tor pairing/offline/replay test also passed
during this follow-up. Temporary profiles and test-owned Tor were cleaned up;
user profiles were not opened. This does not establish reliable bootstrap times
or resistance to global traffic correlation.

## English interface and publication documentation — 0.2.5, 2026-10-22

All current application, legacy-demo and Tor status/error/help/password prompts
are in English. Interactive confirmations use `/yes` and `/no`; the previous
localized aliases are no longer commands. Ordinary text and Unicode message
content remain unchanged. The existing verification, selection, cancellation,
deletion, pending-state retry and invitation-paste protections remain in place.
Historical sections above describe the interface at their stated source version.

README now lists the implemented security/privacy properties, maps independence
and remaining trust dependencies at each communication/distribution layer, and
compares Telegram, Signal, Meta Messenger, SimpleX, Session, WhatsApp, Matrix and
Briar using dated primary sources. It explicitly avoids claiming superiority over
already encrypted/decentralized alternatives or independence from all authorities.
The two-client and server-selection guides were translated into English and
renamed; their local documentation/packaging references were updated.

`bash scripts/check.sh`: **98 passed, 21 skipped in 77.80s**. Ruff lint/format,
Bandit and runtime pip-audit passed; no known runtime vulnerabilities were found.
The absent public-infrastructure opt-in accounts for integration skips; the
application fixture tests use real native crypto and encrypted vaults with a
mock relay, not public SMP. Subsequent lint/format and local Markdown link checks
also passed after documentation and integration expectation updates.

Actual public Urban-Network SMP v18 through real Tor:

- The three-real-terminal Alice/Bob/Charlie test passed with English verification,
  `/yes` confirmations, contact selection, deletion, fresh identities/queues and
  fingerprints, new messages, restart and offline delivery. The initial combined
  run reported one pass/one failure in 217.69s because the separate non-TTY test
  still expected an old localized network-status string; it was a test expectation
  mismatch, with the process emitting the correct English status.
- After updating the non-TTY status and receipt expectations, its existing
  pairing/late-verification/offline/restart/replay test passed in **34.79s**.

Both runs used an explicitly configured external SOCKS port backed by their own
installed test-owned Tor, with isolation and no DIRECT fallback. Bootstrap allowed
300 seconds in the test harness; the application default remains 180 seconds.
Temporary profiles/queues were cleaned up and only test-owned Tor processes were
stopped. User profiles were not accessed. These are development checks, not an
independent audit, managed-Tor bootstrap guarantee or anonymity proof.

A limited pre-publication scan of 193 unique historical Git blobs found no
high-confidence private-key/token markers or sensitive vault/key filenames.
This is not a complete secret audit. The bundled default-router NEW authorization
is intentionally public operator configuration, not a user's private credential.
