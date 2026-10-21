# Security status

Experimental transport implementation, not independently audited. Do not use it
for sensitive conversations. There is no completed end-to-end messenger protocol.

The implementation trusts the OS, Python runtime, cryptography/OpenSSL, libsodium,
Argon2 implementation, dependency supply chain, CSPRNG and the out-of-band router
certificate identity. It does not trust public Web PKI for router authentication.
Validation of the pinned router certificate chain occurs before any SMP data is
read or sent. The SMP hello chain must match TLS and its signed X25519 key must
verify under the TLS leaf certificate. The SMP session must equal the local TLS
Finished message used by the reference protocol. This is SMP's existing binding;
it is not a claim of an RFC 5929 TLS 1.3 exporter construction.

TLS is restricted to 1.3 and ChaCha20-Poly1305; the negotiated group must be
X25519. The client offers OpenSSL's group list and aborts if another group is
selected. Both Ed25519 and Ed448 certificate signatures are accepted explicitly
for deployed-router interoperability. No TLS sessions are reused, tickets are
disabled and no insecure ALPN/version fallback is attempted. See
[PROTOCOL_NOTES.md](PROTOCOL_NOTES.md) for specification discrepancies.

Queue command authorization uses Ed25519 (not the optional deniable authenticator).
Every generated queue and sender has fresh credentials. Global local identity
material is never passed to the network client. Queue SKEY authorization does not
authenticate a human contact or prevent a descriptor-leak race during setup.

The SMP box composition is reproduced from the specified/reference protocol,
using libsodium HSalsa20 and PyNaCl XSalsa20-Poly1305. It has a published NaCl
interoperability vector and property tests against libsodium's DH box. Transport
chain keys use the reference HKDF-SHA-512 salt/info/ordering. This is not a custom
conversation ratchet. Transport chain erasure in Python is only best effort, and
transport forward secrecy is distinct from contact-to-contact PFS or PCS.

## Local storage

Vault v1 uses Argon2id (64 MiB, 3 iterations, parallelism 1, 32-byte output), a fresh
16-byte salt and XChaCha20-Poly1305 with a fresh 24-byte nonce per snapshot. Header
and salt are authenticated associated data. KDF parameters are fixed by the format
version; a file cannot request unbounded KDF resource use. Snapshots are capped at
64 MiB. SQLite lives in memory and only authenticated ciphertext is written to
disk, with fsync and atomic replace and an exclusive process lock. The parent
directory must be user-owned 0700; vault, locks and passphrase files must be 0600.
Vault/private-file symlinks are rejected.

Vault length, existence, modification times, a random salt and nonce remain
visible. The whole snapshot is rewritten per transaction: scalability and
availability are deliberately limited. Authenticated snapshots do not stop a
storage attacker restoring a previously valid file. No externally anchored
rollback resistance is implemented. This also prevents claims of safe future
ratchet recovery from an old backup without further work.

Python immutable byte/string copies, SQLite memory pages, TLS/library buffers,
swap, core dumps, hibernation, debugging and side channels can expose secrets.
Native temporary HSalsa output is wiped; dropping Python references does not
guarantee zeroization. SSD wear-leveling, filesystem snapshots and backups prevent
guaranteed secure deletion. Disk encryption and a trusted device remain necessary
assumptions, not features supplied by this application.

## Failure behavior

- Cryptographic/protocol failures stop processing; invalid deliveries are not ACKed.
- Ciphertext is durably stored before ACK. A crash after storage or after an ACK
  request can cause redelivery, which has a unique database constraint.
- Same queue/ID with changed contents is rejected. Malicious servers can still
  delete, withhold, reorder, duplicate under new IDs or falsely acknowledge SEND.
- A failed command discards the connection's encryption chains. Bounded reconnect
  preserves server identity, minimum version and network mode. SEND is never
  automatically replayed; unknown acceptance is explicit.
- TOR errors fail closed. SOCKS isolation depends on the proxy's configuration.
- There are no analytics, device telemetry, automatic updates or network logs in
  the application. Diagnostic ciphertext digests can correlate test events; do
  not publish diagnostic output for sensitive traffic.

## Cryptographic integration blockers

The reviewed Double Ratchet/Sparse PQ/Triple Ratchet specification is at
https://signal.org/docs/specifications/doubleratchet/ . libsignal's maintained
bindings target Java, Swift and TypeScript; the upstream project states external
use is unsupported: https://github.com/signalapp/libsignal . No reviewed Python
hybrid session implementation has been integrated or vetted in this project.
That is an integration/review blocker, not proof that no candidate library exists.

Before milestones 2–4 can be claimed, select and review the dependency/license and
serialization, integrate authenticated X25519+ML-KEM-768 key establishment with
contact-specific authentication, obtain independent vectors/interoperability,
bind conversation/header context, add atomic ratchet state transitions, skipped
key bounds, malicious-input limits, compromise/recovery tests and external review.
Do not claim Signal PQXDH compatibility without testing. PQ initial exchange alone
does not give long-lived post-quantum PFS or PCS. No quantum-resistance claim is
made for this release.

Do not submit secrets to a public issue. This local repository has no published
security-reporting address yet; arrange a private report with its maintainer.
