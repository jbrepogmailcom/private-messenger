# Application session protocol v2

This document describes implemented application data, not new SMP fields. SMP
continues to forward opaque bytes using the normative router protocol.

## Identity and invitations

A local profile has an independently random local identity, never sent to SMP.
Every `address` or `connect` generates a new contact-specific native identity,
registration identifier, EC prekeys, signed prekey, ML-KEM prekey, 32-byte protocol
address and distinct incoming SMP credentials. Contacts cannot use one contact's
public identifier to derive another. The chosen display name is sent only inside
the encrypted request/accept message; sharing names/content with peers can still
link people. Queues remain reusable within a contact until a future rotation module.

An invitation consists of `PMS2:` plus unpadded uppercase Base32 of zlib-compressed
canonical JSON `{data,signature}`. Decompressed input is capped at 8192 bytes and
text at 4296 alphanumeric QR characters. Compression is only for public invitation
data, never a mixed-secret adaptive message compression scheme.

Signed `data` fields: `v=2`, exact `suite`, random conversation `id`, `expires`,
random contact `address`, pinned `server`, `sender_id`, and public `bundle`.
The bundle contains registration ID, identity, one-time EC prekey, signed EC prekey
and signature, ML-KEM-1024 prekey and signature. Binary values are Base64url.
Signatures use upstream identity signing over the domain
`private-messenger invitation v2\0` and canonical data. Native prekey signatures
are independently checked before network access. The initial KEM discriminator
must be standard ML-KEM-1024 (0x0A); no legacy Kyber/classical downgrade is allowed.

Expiry is seven days on creation, at most eight days accepted relative to the
local clock. Clock integrity is an assumption. Anyone holding an invitation can
race to secure its queue. The first successful request consumes it; fingerprint
verification, rather than possession of a self-signed invitation, authenticates
who the human peer is. An attacker can occupy a leaked invitation and cause denial
of service. Issue a fresh invitation in that case. No directory or username lookup.

## Pairing and packets

Alice validates Bob's invitation, creates her own return queue, pins Bob's contact
identity and calls official `process_prekey_bundle`. She secures Bob's sender
queue (SKEY) and sends an encrypted request containing her return route/name.
Bob decrypts via the upstream prekey path and atomically records the contact and
new ratchet before ACK. `accept` secures Alice's sender queue and sends an encrypted
acceptance binding Alice's request ID. Both sides must independently confirm their
matching official 60-digit fingerprint before text send/receive is allowed.
The fixed device ID is local protocol glue, not a device identifier sent globally.

Opaque application packet bytes: `PM2\x01`, message type byte (2 or 3), 32-byte
sender protocol address, then upstream serialized ciphertext. The total is capped
at SMP's 16048-byte application payload limit. These 37 outer bytes are public.
The upstream authenticated message header remains unchanged. Decrypted canonical
JSON binds `v`, `suite`, conversation, random 32-byte application message `id`,
`from`, `to`, `kind`, `body`. Outer sender/context must match these authenticated
values before application state is committed. Message kinds are `request`, `accept`,
`text`, `receipt`. Text is at most 8192 UTF-8 bytes. No application compression.

Official session version 4 and nonempty SPQR state with minimum v1 are mandatory.
No complete session resets or identity changes are silently accepted. SPQR v1
negotiation/epochs are observable locally through a read-only metadata projection.
Setup private prekey records are dropped once a session exists. The upstream
Double Ratchet retains at most 2000 skipped keys and bounds forward jumps at 25000;
retained skipped keys deliberately weaken erasure for those undelivered messages.
Upstream limits are pinned behavior, not independently invented ratchet parameters.

## Persistence, retries and restoration

Before SEND, one encrypted transaction persists new ratchet state plus the exact
outbox ciphertext and application ID. At most three attempts use the **same bytes**;
uncertain server acceptance never re-encrypts an old message with stale keys.
Backoff is bounded. Exhausted entries remain queued/acceptance_unknown with their
attempt count; no recipient-delivered claim is inferred. A permanent router error
marks rejected. No automatic switch of router, protocol suite or network mode.

Before ACK, one encrypted transaction persists candidate ratchet, history,
SHA-256 digest/application-ID replay index, router-ID delivery and any encrypted
receipt with its own ratchet advancement. Failed snapshot writes restore old RAM
state and leave the packet unacknowledged. Exact packets replayed under fresh
router IDs are ACKed without ratchet advancement or duplicate history. Conflicting
IDs/context/tampering are rejected. Receipts bind the outgoing application ID and
mean client processing, never human reading. Replaying after whole-vault rollback
is outside this protection. Terminal display across a crash is not exactly once.

SUB workers own their connections; the main thread alone owns SQLite. Reconnect
preserves pin and mode, and resumes queued delivery. ACK can immediately yield the
next message. Invalid authenticated content can stop a queue without ACK; this is
an availability limitation, and fingerprint verification/restart can resume it.

Explicit backup restore marks all old sessions recovery_required, disables their
private session/sender state and pending outbox, and retains history. Fresh
invitations/fingerprints are required; it never resumes an old sending chain.
A malicious storage rollback bypassing restore remains undetectable without an
external monotonic anchor. Keeping old backups or live memory copies invalidates
strong erasure assumptions. See SECURITY.md for precise compromise limitations.
