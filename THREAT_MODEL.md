# Threat model and testable limits

Scope: milestone-1 opaque ciphertext transport, local storage and the separately
identified same-computer text demo described below. Confidentiality,
authentication, availability and anonymity are separate properties. There is no
claim of perfect security, superiority, audited correctness or protection against
a nation-state adversary with broad visibility.

| Adversary/event | Implemented protection | Residual limitation / assertion |
|---|---|---|
| Passive network observer | TLS 1.3, authenticated router identity, fixed SMP blocks | DIRECT discloses router/source IP, timing, duration and volume; no cover traffic |
| Active network MITM | Pinned validated certificate path, signed session key, Finished binding | Authentic source of pin and trusted OS are required; invalid pin/binding tests fail |
| Malicious SMP operator or compromised router | Separate sender/recipient IDs and credentials; authenticated client commands; caller's opaque bytes are forwarded | Router knows transport/delivery keys and routing relationships; no conversational E2E protocol exists; can delete or fabricate queue behavior |
| Stolen global local identity key | No global key transmitted; per-queue credentials independently random | Stolen whole unlocked vault exposes queue credentials too; contact authentication not yet implemented |
| Stolen past message/session key | No conversational claim | No Double Ratchet, PFS/PCS, skipped-key or compromise-recovery guarantees |
| Quantum adversary / harvest now decrypt later | None claimed | Current transport is classical X25519/EdDSA; hybrid KEX and PQ ratcheting blocked |
| Replay, reordering, duplication | Transport chain authentication; router-ID UNIQUE constraint; wrong ACK IDs rejected | Malicious router can assign new IDs; authenticated application IDs and out-of-order ratchet handling not implemented |
| Crash before ACK | Encrypted transaction durably persists before ACK, then deduplicates redelivery | ACK result may be unknown; once-only insertion is tested for same router ID, not arbitrary adversarial republishes |
| Router outage/deletion | Explicit bounded reconnect and offline queue retrieval | Availability depends on router retention/quota; no redundant delivery, censorship resistance or indefinite retention |
| Database theft | Argon2id and XChaCha20-Poly1305, authenticated header, 0600 files | Weak passphrases, brute force, file metadata and backups remain relevant; no whole-file rollback protection |
| Database corruption/tampering | AEAD authentication, SQLite integrity/schema checks, bounded file size | Corruption can deny availability; recover from an independently held authenticated backup |
| Temporary device compromise | None claimed during compromise | Attacker can read memory, alter code and credentials; no implemented PCS healing |
| Broad traffic correlation | Optional remote-DNS SOCKS/TOR, fresh SOCKS auth per connection | Tor is not a mixnet; entry/exit/global observers and routers can correlate timing; isolation requires proxy support |
| Malicious software update | Hashed locks, manifests and explicit trusted-key signature tools; no updater | Signing-key theft or collusion can ship malicious software; public source alone prevents neither malicious binaries nor malicious updates |
| Side channels / memory forensics | Native primitives; best-effort reference dropping | No constant-time Python orchestration, guaranteed wiping, swap/core-dump or physical-device protection |

Network clients do not take the local identity as input and do not transmit profile
names or contact lists. The demo's Alice/Bob names remain inside encrypted local
vaults. Every NEW generates fresh recipient authentication and delivery-DH keys;
sender authorization is generated independently. CLI operations use separate TLS
connections. This minimizes some reusable identifiers but does not establish
sender/recipient anonymity against operators who observe those connections.

Test evidence and untested requirements are tracked in
[VERIFICATION.md](VERIFICATION.md). Future ratchet assertions must name compromise
time, retained keys, attacker access duration, authenticated fresh entropy, skipped
key bounds, restoration behavior and what is assumed erased. Those assertions
cannot be inferred from the current transport tests.

The optional `chat` launcher locally provisions Alice/Bob on the same trusted
computer and encrypts text with standard PyNaCl Box before SMP SEND. For this demo
only, a malicious router does not know payload keys, ciphertext tampering fails,
conversation/direction mismatches fail, and persisted authenticated application IDs
deduplicate replay even with new router IDs. Tests exercise those bounded assertions.
The router can still delete, reorder, delay or correlate traffic; DIRECT exposes
the IP. Whole-vault rollback can erase replay memory. Shared setup/password and a
compromise of the host expose both demo profiles. Static payload-key theft exposes
past and future messages; there is no ratchet, PFS, PCS or quantum protection.
Local provisioning does not authenticate a remote person or establish safe remote
pairing. The main threat table's absent messenger-session protections remain absent.
