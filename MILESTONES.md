# Milestone ledger — 2026-10-22

| Milestone | State | Evidence and remaining work |
|---|---|---|
| 1: Native SMP interoperability | COMPLETE for ordinary-client subset | Independent processes, unmodified public v18/v20 routers and local reference matrix; framing/auth, online/offline, ACK/replay, separate keys, reconnect; optional router operations remain outside subset |
| 2: Authenticated encrypted messenger | WORKING candidate, exact KEM requirement open | Real independent profiles, signed one-use invitations, requests/acceptance, mandatory fingerprints, encrypted bidirectional chat/history/receipts. Official backend initial ML-KEM-1024 differs from requested ML-KEM-768; no independent application review or Signal-app interoperability |
| 3: PFS and PCS | IMPLEMENTED upstream; bounded behavior verified | Real native Triple/Double Ratchet, out-of-order, 2000-key retention limit, replay/tamper, logical key retirement, atomic state, session restart, passive snapshot DH recovery. Whole-file rollback, physical erasure and persistent active compromise remain unprotected |
| 4: Post-quantum | WORKING upstream candidate, incomplete original exit criterion | Standard initial ML-KEM-1024, ongoing SPQR v1 ML-KEM-768, epoch progression, SPQR-only passive snapshot recovery, benchmark. Exact initial768 parameter and independent hybrid interoperability vectors/review remain open; no PQ authentication claim |
| 5: Anonymity improvements | PARTIAL | Real Tor circuit secure-chat online/offline test, remote DNS/isolation/no fallback; chat defaults to TOR with owned-process bootstrap and encrypted guard persistence; bundled public NEW configuration avoids operator website. Queue rotation, cover traffic, redundant routing and real mixnet adapter unavailable; correlation resistance unproven |
| 6: Hardening | PARTIAL | Encrypted vault/backup, restore invalidation, transaction tests, Python properties/static/audits, Cargo fmt/clippy/audit, pinned builds, manifests/signature tools. Native independent reproducibility, external audit, production key, threshold signing/transparency and broader fuzzing remain open |

The native cryptographic dependency is not an external messaging engine; see
CRYPTO_DEPENDENCIES.md. Working candidate milestones are not declarations of
production security or satisfaction of every original requirement. Exact initial
ML-KEM-768 remains BLOCKED instead of substituted custom cryptography. No automatic
legacy migration. Version-control commits record source and verification evidence.
