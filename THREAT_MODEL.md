# Threat model and testable limits

Scope: independent SMP transport and the experimental v2 messenger described in
SESSION_PROTOCOL.md. Confidentiality, authentication, availability and anonymity
are separate. No perfect security, superiority or broad nation-state resistance
is claimed. Tests are development evidence, not an external audit.

| Adversary/event | Implemented mechanism / testable assertion | Residual limits |
|---|---|---|
| Passive network observer | Pinned TLS 1.3, fixed SMP blocks, upstream application hybrid/Triple Ratchet | DIRECT reveals IP/router/timing/volume; no cover traffic |
| Active network MITM | Certificate path/pin, signed ephemeral key, Finished binding; wrong binding/signature fails | Pin provenance, trusted OS and endpoint code required |
| Malicious SMP operator/compromised router | Application ciphertext encrypted before SEND; tampering/context mismatch rejected | Knows queue relationships and transport keys; can delete, delay, lie about acceptance, correlate and deny availability |
| Stolen global identity key alone | Never transmitted; contact identities/credentials independently random | Whole-vault theft while unlocked exposes much more, including history and contact keys |
| Stolen contact identity/prekey | Fingerprint pins peer; obsolete setup records retired | Contact impersonation possible after identity theft; no automatic revocation; re-pair/reverify; self-signatures are not human authentication |
| Stolen past/current session state | Upstream key evolution; consumed-packet rejection and fresh-DH snapshot recovery tests | Skipped keys, retained backups, plaintext history and continuing compromise are excluded; healing needs fresh honest entropy |
| Quantum record-now/decrypt-later | Initial X25519 + ML-KEM-1024 and ongoing SPQR ML-KEM-768 | Exact required initial ML-KEM-768 not provided; security assumes upstream primitives/model; no PQ authentication against active signature forgery |
| Replay, reordering, duplication | Upstream skipped-key processing; packet/app-ID dedup across fresh router IDs; tampering never commits state | Upstream bounds (2000 skipped keys, 25000 forward jump); adversary can exceed bounds or block a queue; rollback removes replay memory |
| Crash before/after ACK | Ratchet/history/receipt atomic snapshot before ACK; restart and duplicate integration tests | Exactly-once local insertion under durable-state assumptions, not exactly-once terminal display or indefinite router retention |
| Uncertain SEND acceptance | Exact ciphertext saved before SEND, bounded retry, separate encrypted receipt | Router acceptance is not recipient delivery; exhausted attempts need inspection; no redundant routing |
| Router outage/deletion | Offline router queue and receiver reconnect to same pinned endpoint/mode | No censorship/availability guarantee, retention quota or independent-router failover |
| Local database theft | Argon2id + authenticated XChaCha snapshots, restrictive permissions | Weak secret/offline guessing, metadata, stolen backups and known master key remain relevant |
| Corruption/tampering | AEAD + database checks and bounded input; failed durable write rolls state back | Deletion/corruption can deny availability; valid old-file rollback undetected |
| Explicit historical backup recovery | Old sessions disabled; history retained; fresh pairing required and tested | No seamless ratchet recovery; malicious replacement bypassing restore remains unprotected |
| Temporary device compromise | Classical state-snapshot test and independent SPQR-only recovery experiment | No protection during control; future RNG/code/network must be honest; attacker with future disk access and vault secret defeats PCS |
| Broad/global traffic correlation | Optional fail-closed TOR, remote DNS, fresh SOCKS isolation credentials | Tor is not a mixnet; router/entry/exit/global observations can correlate; no traffic analysis experiment establishes anonymity |
| Malicious software update | Pinned dependencies, scans, manifests and explicit trusted-key signature tools, no updater | Signing authority/dependency/compiler compromise can ship malicious code; threshold/log/reproducible native governance incomplete |
| Side channels/memory forensic access | Vetted native primitives; SQLite free-page clearing | Python/FFI copies and allocators not guaranteed wiped; no SSD erasure, physical-device or side-channel guarantee |

One contact's protocol address/identity cannot derive another; every invitation
has fresh keys/queue credentials. Reuse within one contact, chosen names/content,
same-host DIRECT connections and timing still create links. Names/contact lists
are not router registration fields. Initial requests contain encrypted display
names before manual fingerprint verification, so trust invitation delivery too.

The terminal's guided verification displays the complete fingerprint and accepts
an explicit `/ano` only for that displayed contact and unchanged fingerprint.
Selecting another conversation cancels the prompt. A unique name, local ID or
number from the last displayed menu selects a contact; duplicate names fail closed.
Number-to-ID mappings are frozen until another list is displayed, so a concurrent
incoming contact cannot change the recipient of `/chat 2`. Every chat command
requires `/`; unknown slash commands never become messages. An outbound-message
guard rejects invitation markers, invitation exports and long Base32 fragments
before encryption/history/outbox insertion, directing users to `/add` instead.
This prevents the reported accidental forwarding, not deliberate disclosure or
arbitrary secret detection. A copied JSON invitation export
does not supply trusted metadata: only its signed PMS2 content is used. These UI
rules do not authenticate a human automatically; users must compare fingerprints
through an independently trusted channel. Blindly confirming defeats that check.

PFS concerns network transcripts after key erasure, not plaintext saved locally.
PCS experiments model a passive attacker after a one-time snapshot, not a persistent
active clone. SPQR-only recovery test isolates fresh KEM entropy from classical DH;
it is not a mathematical proof or quantum-adversary implementation. The exact
assumptions and experimental results are in SECURITY.md and VERIFICATION.md.

The retained `chat-legacy` demo has a narrower model: trusted same-computer setup,
shared test password and static NaCl Box keys. Compromise of its payload key exposes
past/future messages. It has no remote contact authentication, PFS, PCS or PQ claims.
New features do not retroactively secure old conversations.
