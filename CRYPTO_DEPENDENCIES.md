# Cryptographic dependency decision — experimental candidate

The original requirements prohibit custom hybrid/ratchet cryptography. We use the
maintained upstream implementation through a narrow binding rather than a Python
port. This is not an independent review of our application composition.

| Component | Pinned source / use | Review and license limits |
|---|---|---|
| libsignal-protocol | `signalapp/libsignal` commit `b369755533ef5a3fae9b31b989114f22e074dfab`; feature `mlkem1024` | Official upstream cryptographic library; external use is explicitly unsupported; AGPL-3.0-only |
| SPQR | `signalapp/SparsePostQuantumRatchet`, v1.6.0, commit `06959b4708f9b7b1e94d0f8cc835f3958c077e94` | Official Sparse PQ ratchet using ML-KEM-768, not a new construction by this project; AGPL-3.0-only |
| PyO3 | 0.30.1, Python ABI floor 3.12 | Binding infrastructure; not a cryptographic protocol |
| Other Rust inputs | Exact resolved versions, git revisions and registry checksums in `native/Cargo.lock` | Transitive licenses/notices and compiler remain trusted supply-chain inputs |
| Python primitives | Hashed requirements locks, cryptography, libsodium/PyNaCl, Argon2 | Existing SMP primitives and encrypted vault; no handwritten primitive arithmetic |

The initial standard KEM available in this pinned libsignal backend is
**ML-KEM-1024**, not the required ML-KEM-768. Legacy Kyber variants are not treated
as standardized ML-KEM. This deviation remains explicit in status, invitations
and documentation. Achieving the exact original parameter set is still BLOCKED
without a suitable vetted implementation and interoperability evidence. No
upstream cryptographic source was patched to change the KEM or its KDF labels.

The native extension implements only key generation, signed prekey bundle
handling, official session encrypt/decrypt, XEdDSA signing/verification and official
fingerprints. Its ephemeral stores are rebuilt from serialized state; successful
candidate state returns to Python for one encrypted transaction. It contains no
network connection management, Signal service client or messaging engine. No
SimpleX agent or SimpleX Chat code is linked. The Python SMP transport is independent.

Upstream message encryption/authentication is used as a whole. We do not bolt
XChaCha onto the ratchet or select a different cipher internally merely to match
an example primitive. The pinned upstream message cipher is AES-256-CBC with its authenticated MAC composition; XChaCha20-Poly1305 is used for local vault snapshots. Public
invitation/envelope formats are application glue requiring independent review.
There are no claimed interoperability tests with Signal applications or other
PQXDH implementations; our peers use the same pinned library. The published
fingerprint vector is tested separately from round-trip interoperability.

Primary specifications and source:

- [PQXDH](https://signal.org/docs/specifications/pqxdh/)
- [Double Ratchet, Sparse PQ and Triple Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/)
- [Pinned libsignal source](https://github.com/signalapp/libsignal/tree/b369755533ef5a3fae9b31b989114f22e074dfab)
- [Pinned SPQR source](https://github.com/signalapp/SparsePostQuantumRatchet/tree/06959b4708f9b7b1e94d0f8cc835f3958c077e94)

Upstream review/verification claims concern their stated components and threat
models; they do not establish that this binding, persistent state handling,
invitation authentication or complete application is correct. No external audit
has been performed here. Combining AGPL-3.0-or-later project code with these
AGPL-3.0-only components requires distribution under compatible AGPLv3 terms and
corresponding source/notices, including upstream sources and modifications (none
to their cryptography). Dependency license inventory is not legal certification.
