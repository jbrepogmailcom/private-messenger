# Milestone ledger

| Milestone | State | Evidence / remaining work |
|---|---|---|
| 1: Native SMP interoperability | COMPLETE for the implemented ordinary-client command subset | Separate Python processes, public v20 router, online/offline opaque payloads, ACK/redelivery, persistence, reconnect and sender-key separation; see verification report |
| 2: Authenticated encrypted messenger | PARTIAL / BLOCKED | Local identities/vault work. Separate same-computer Alice/Bob text demo uses locally provisioned standard NaCl Box keys, encrypted history and application-ID deduplication. Reviewed hybrid session integration, remote invitations/contact verification and receipts remain absent; demo is not this milestone's exit criterion |
| 3: PFS and PCS | BLOCKED | No vetted ratchet integrated; no application skipped-key, out-of-order, compromise/recovery or rollback-safe ratchet tests |
| 4: Post-quantum | BLOCKED | No reviewed hybrid KEX/PQ ratchet integrated or interoperable vectors; no PQ claims |
| 5: Anonymity improvements | PARTIAL | DIRECT/TOR adapters, remote DNS and SOCKS isolation; no traffic-correlation resistance proof, cover traffic, queue rotation, redundant routing or real mixnet adapter |
| 6: Hardening | PARTIAL | Encrypted vault/recovery, locking, property/static checks, dependency scans and release tooling; independent review, full fuzzing, authenticated release governance and transparency remain open |

Milestone 1 is a transport result. It does not satisfy milestones 2–6 by implication.
Textual specification discrepancies and all unsupported commands are explicit.
Use a reviewed candidate cryptographic dependency and independent vectors before
implementing the messenger protocol. Do not paper over the blockers with invented
hybrid or ratchet composition.
