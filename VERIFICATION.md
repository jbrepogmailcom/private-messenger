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

## Requirements still unverified or unavailable

- E2E identity/contact authentication, bidirectional conversational encryption,
  ML-KEM/hybrid KEX, PQXDH compatibility and PQ ratchets: not implemented.
- Double Ratchet key updates, out-of-order/skipped-key bounds, application replay
  attacks, PFS/PCS compromise/recovery and safe ratchet restoration: no tests or claims.
- Whole-vault rollback, secure Python/SSD erasure, side-channel resistance and
  temporary device compromise recovery: not provided.
- Deployed 3/4-certificate chains and all optional SMP commands: not verified.
- Queue rotation, redundancy, receipts, bounded authenticated application retries,
  padding schedules, cover traffic, mixnet and correlation resistance: absent.
- Multi-party signing, deployed transparency and an established independently
  authenticated release key: absent. Manifest/signature tests alone do not supply them.
