# Security status — 0.2 experimental candidate

No independent implementation or cryptographic integration audit has taken place.
This source is not production-ready. Native cryptography is upstream code, but
that does not verify our invitations, binding, state handling or complete system.

The new `chat` has authenticated remote pairing and upstream Double/Triple Ratchet
with ongoing SPQR. Initial X25519 + **ML-KEM-1024** differs from the requested
ML-KEM-768; SPQR uses ML-KEM-768. Exact initial parameter compatibility and Signal
application interoperability are not claimed. See CRYPTO_DEPENDENCIES.md.
The old `chat-legacy` uses static NaCl Box keys and has no PFS/PCS/PQ protection.

## Authentication and trust

Contact removal uses a confirmed `/del` action. One encrypted atomic transaction
deletes history, outbox, replay/delivery records, prekeys and native ratchet state,
retaining a non-messaging `deleting` record with queue credentials for the DEL
operation. The receiver is signalled to stop; already queued events for retired
contacts are ignored before decryption/ACK/storage. Successful authenticated DEL
is followed by a second atomic transaction removing the final queue credentials.
A crash or network/disk failure cannot resume the old session; retrying `/del`
finishes retirement, including after restart. AUTH is reported as unconfirmed,
not proof of queue erasure: [SMP's DEL and error semantics](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md#delete-queue).

Removal affects this profile and its own recipient queue, not another device's
history or existing backups. A malicious server can retain copies despite OK;
there is no cryptographic proof of server erasure. SQLite logical deletion and
retiring native key state do not guarantee wiping Python objects, SSDs, swap,
snapshots or backup media. Re-pair using a new invitation and fresh fingerprints.
An explicitly confirmed `/del NAME --local` skips network deletion and discards
the final local credentials. It warns that the remote queue remains and cannot
subsequently be deleted with those lost credentials. There is no automatic
local-only fallback after authentication, pinning or network failures.

Trust the OS, interpreter/compiler, dependency sources/binaries, CSPRNG, libraries,
trusted out-of-band invitation/fingerprint exchange and authentic SMP certificate
pin. Global local cryptographic identity/contact lists are never given to a router.
Each contact gets a fresh identity, prekeys, protocol address and queue credentials.
A chosen display name is sent to peers inside encrypted setup, not as a router ID.

The invitation signature authenticates consistency of public routing/capabilities
and keys, not a human name. Compare the official 60-digit fingerprint over an
independently authenticated channel. Both sides must confirm it before text flows.
A leaked invitation can be claimed first by an attacker; use a new invitation.
Classical identity signatures are **not post-quantum authentication**. An active
quantum attacker capable of forging these signatures is outside current guarantees.

The native crypto-only binding calls official key establishment, encrypt/decrypt
and fingerprint APIs. No KEM, cipher arithmetic, KDF/ratchet construction or random
number generator is implemented by us. Upstream AES-256-CBC plus its authenticated
MAC composition is preserved; we do not claim message encryption uses XChaCha.
The vault separately uses XChaCha20-Poly1305. The native backend has no network,
filesystem or configured logging backend. Application errors omit native secret/
identity diagnostics. Dependency/binary compromise can defeat every property.

## Forward secrecy and compromise recovery

The upstream Double Ratchet supplies fresh message keys and DH updates; SPQR
adds sparse ML-KEM-768 updates using the reviewed upstream construction. Initial
PQ establishment alone is not claimed to supply indefinite PQ PCS/PFS.
Behavioral tests exercise consumed-key rejection, bounded skipped keys, classical
snapshot recovery after honest fresh DH, PQ epoch progression and standalone
SPQR snapshot recovery without classical DH. These are **bounded tests, not proofs**
or simulations of a quantum computer. Upstream proofs have their own model/scope.

PFS statements concern recorded network ciphertext after superseded secret keys
are erased. They do not hide plaintext saved in history or backups. The upstream
cache retains up to 2000 skipped keys; messages whose keys remain cached have
weaker erasure properties. Setup private prekeys are removed from live serialized
state after establishing a session. SQLite secure_delete is enabled so replaced
private state does not intentionally remain in serialized free pages.
The binding zeroizes its owned serialized private-key/session buffers on
retirement/drop using the established zeroize crate. JSON/Python/upstream copies
still prevent a guaranteed memory-erasure claim.

PCS assumes a one-time protocol-state exposure, trusted recovered endpoint code,
fresh unpredictable OS randomness, continued bidirectional exchanges, authenticated
peer identity and no continuing attacker access. Healing is not immediate. Active
control, cloned identity use, a compromised OS/update, retained vault password/key
plus future disk access, or a malicious RNG can defeat recovery. Reverify/re-pair
contacts after a suspected compromise. No protection while the device is controlled.

## SMP and networking

Direct independent SMP over TLS 1.3, ChaCha20-Poly1305, X25519 group, ALPN smp/1.
Pinned certificate-path validation occurs before SMP exchange. The SMP hello chain
must match TLS; the signed ephemeral key verifies under its Ed25519/Ed448 leaf,
and the session binds the reference protocol's local TLS Finished. This is SMP's
existing mechanism, not an RFC 5929 TLS-1.3 exporter claim. No TLS session reuse or
insecure ALPN fallback. Highest compatible v11–20 is selected, below 11 rejected;
no claim that every optional command/version or deployed chain has been tested.
SMP details/spec discrepancies are in PROTOCOL_NOTES.md.

Command authorization uses separate Ed25519 sender/recipient keys. SMP boxes use
reference libsodium HSalsa20 / XSalsa20-Poly1305 and HKDF-SHA-512 transport chains,
not the conversational ratchet. Transport/delivery keys are known to routers;
only the application session protects content from them. Operators can withhold,
delete, delay, duplicate, correlate or deny messages and falsely acknowledge SEND.
SKEY does not itself authenticate a person or prevent a leaked-invitation race.

DIRECT exposes source IP. TOR uses SOCKS5 remote DNS, literal proxy IP, new auth
credentials per connection and no DIRECT fallback. Isolation requires the proxy's
IsolateSOCKSAuth. Chat now defaults to TOR even for older DIRECT profiles. It
starts an owned Tor with isolation enabled unless an external proxy is configured.
No system Tor configuration is changed. Bootstrap failure is fatal before SMP.
Owned Tor runtime files use a private RAM directory; its guard state is stored in
the encrypted profile on clean exit and restored on the next start. This helps
retain guards across ordinary restarts; a crash can lose newer guard state and
leave private RAM files until reboot. Tor monitors its owning process and exits
after owner death (documented 15-second polling), but no instantaneous cleanup
or wiping guarantee is claimed. Tor logs are drained without persistence; only
bootstrap percentages are displayed. A failed explicitly configured external
proxy never causes managed-Tor or DIRECT fallback. The public default-router
NEW credential is bundled, with no runtime operator-website fetch. Queue connections
can still be linked by routers/timing. Tor is not a mixnet and does not establish
resistance to broad/global traffic correlation. Fixed SMP blocks are not cover
traffic. MIXNET, cover traffic, queue rotation and redundancy remain unavailable.

## Storage, replay and crashes

Argon2id uses 64 MiB, 3 iterations, parallelism 1 and 32-byte output; random 16-byte
salt. Each entire SQLite RAM snapshot uses a new random 24-byte nonce and
XChaCha20-Poly1305; format header/salt are authenticated. Fixed KDF parameters and
64-MiB size bound limit malformed input. Files/locks are user-owned 0600, private
directories 0700, symlinks rejected, process lock exclusive, persistence fsync +
atomic replace. Metadata such as file length/timestamps remains visible.

Ratchet, history, replay index and encrypted receipt persist atomically before
ACK. Outgoing ratchet/ciphertext persist before SEND; at most three identical-byte
attempts, no stale re-encryption. Receipt means recipient client processing, not
reading. Exact replay with another router ID produces one history row; conflicting
IDs/context fail closed. Invalid content can block a queue, an availability risk.
The UI escapes terminal control characters. No persistent network/debug logs,
telemetry or analytics are enabled; requested message/history display is plaintext.

Ordinary restart resumes the latest durable session. **Explicit backup restore
never resumes old ratchets**: it keeps history, invalidates sessions/pending sends
and requires fresh invitations and fingerprints. This sacrifices transparent
conversation recovery to avoid stale-chain reuse. An attacker restoring a valid
old whole vault outside this restore command remains undetectable: external
monotonic rollback protection is not implemented. Running cloned snapshots also
breaks the single-writer/fresh-state assumption. The AEAD cannot prevent rollback.

Python immutable strings/bytes, JSON and SQLite copies, native buffers/allocators,
swap, core dumps, hibernation, side channels and backup snapshots prevent guaranteed
erasure. Clearing references/SQLite free cells does not prove physical wiping.
No secure deletion guarantee on SSDs or constant-time Python orchestration claim.
Full disk encryption and trusted endpoint operation are outside this application.

## Supply chain and reporting

Python hash locks, Cargo lock/git pins, static checks, audit tools and manifest/
Ed25519 release-signature tooling are present. There is no established production
release key, automatic updater, threshold release policy or deployed transparency
log. Publication of source and valid signatures do not prevent malicious updates.
Native reproducibility across independent machines is unverified. See RELEASING.md
and VERIFICATION.md for dated scans and remaining dependency maintenance warnings.

Report vulnerabilities privately to the repository owner through an authenticated
channel. No dedicated reporting service, address or response SLA has been created.

Interrupted invitation/SKEY setup can leave a retained encrypted contact in a
new/securing state and an unused router queue. Automatic setup repair and expired
queue cleanup are not implemented; new pairing may be required. Established
session reconnect is tested separately. Do not delete credentials merely because
setup failed or assume a server-side operation was undone.
