# Wire reference and interoperability decisions

Reference: [SMP specification v20, 2026-05-25](https://github.com/simplex-chat/simplexmq/blob/27a37387be98d9c7ec0e62373e125539675d0095/protocol/simplex-messaging.md).
Reference source revision consulted: `27a37387be98d9c7ec0e62373e125539675d0095`.
No upstream implementation is imported, linked or invoked by the Python client.
The unmodified upstream router executable is used only as an integration-test server.

The document and deployed/reference behavior have discrepancies. These are exposed
here instead of being described as exact textual-spec compliance:

1. Some prose calls identity an SPKI hash and other prose calls it a certificate
   fingerprint. `Transport/Client.hs:validateCertificateChain` and
   `Transport/Shared.hs:chainIdCaCerts` pin **SHA-256 of complete DER certificate at
   index 1 of the leaf-first chain** for 2–4 certificates. This matches the public
   router identity. OpenSSL validates the supplied path to its included root;
   each signature/issuer and the root self-signature are additionally checked.
   Larger-chain descriptions are inconsistent with the reference's identity
   indexing; 3/4-certificate deployed interoperability remains unverified.
2. TLS prose restricts signatures to Ed25519, while the advertised public
   `smp4.simplex.im` uses Ed448 leaf and root certificates. The reference explicitly
   supports both. This client accepts Ed25519 and Ed448, and rejects other types.
   Ed25519 is used for all generated client queue-authentication keys.
3. Prose describes `clientKey` as proxy-only. `Transport.hs:blockEncryption` and
   `smpTHandleClient` require a client X25519 key to activate v11+ block encryption
   for ordinary clients. The client sends a fresh key, sets proxy=false from v14,
   and sends no service credentials from v16. Encryption is never disabled.
4. `signedRouterKey` is a DER SignedExact object: signed SEQUENCE wrapping a SPKI,
   signature algorithm, BIT STRING signature. The signature covers the wrapper,
   not the unwrapped SPKI. Only canonical DER is accepted.
5. The symmetric SMP box first derives HSalsa20(key, zero16), then uses
   XSalsa20-Poly1305 with the supplied 24-byte nonce. A naked PyNaCl SecretBox(raw
   key) is not wire-compatible. A native libsodium binding performs the extra
   preprocessing. For raw X25519 secrets this agrees with standard NaCl crypto_box.
   No Salsa, Poly1305 or elliptic-curve code is written here.
6. v11 block chain initialization is HKDF-SHA-512(salt=TLS session,
   IKM=raw X25519 secret, info=`SimpleXSbChainInit`, L=64). First 32 bytes are the
   server's send chain; the client reverses directions. Every block uses
   HKDF-SHA-512(empty salt, chain, `SimpleXSbChain`, L=88), split next-chain32,
   encryption-key32, nonce24. Pad to 16,368 bytes, then encrypt to 16,384.
7. Commands sign short(session) || short(correlation24) || short(entity) || command.
   Session bytes are omitted on wire, never omitted from authentication. From
   v16 a present authorization is followed by optional service signature `0` for
   this non-service client; unsigned commands/responses omit that field entirely.
8. NEW/IDS structures change at v15 (optional queue/link data), v16 (service ID
   and optional transmission service signature), v17 (notification credentials).
   The sender-security boolean is used for v11–14. Each path has actual-router tests.

The public router offered a range newer than the documented v20. The client still
chooses only its highest implemented version (v20); it never claims v21/v22 support.
SMP proxy forwarding, services, notification queues, resolver commands, short links
and optional deniable authentication are outside this milestone's supported subset.
Unexpected responses fail closed. Existing unsupported protocol data is not
silently reinterpreted as a different command format.
