# Releases and software integrity

No trusted production release or automatic updater exists. Release signing
tooling is implemented; a signing key's authenticity must be established outside
the downloaded release. Do not trust a public key just because it arrived in the
same archive. Signatures do not prove that signed code is safe.

## Locked installation and checks

Python dependencies (including transitives) are pinned with SHA-256 hashes in
`requirements.lock`, `requirements-dev.lock` and `requirements-build.lock`.
`pyproject.toml` pins direct dependencies and the build backend. `scripts/check.sh`
runs Ruff, Bandit, pytest and pip-audit for runtime dependencies. Audit development
and build locks before release too. Vulnerability-database coverage and freshness
are limitations; a clean scan is not an implementation audit. Hashes ensure
consistency with the chosen package artifacts, not absence of malicious packages.

```bash
.venv/bin/pip install --require-hashes -r requirements-build.lock
bash scripts/check.sh
.venv/bin/pip-audit -r requirements-dev.lock --disable-pip
.venv/bin/pip-audit -r requirements-build.lock --disable-pip
```

The native libsodium, system C library, OS, Python and OpenSSL wheels are also
trusted inputs. Record their versions for every release. No binaries from the
upstream messenger/agent enter this package.

## Build and independent comparison

Commit the source first. Use a clean tree, a fixed Python/OS architecture,
hash-verified dependency artifacts, and identical pinned build tools:

```bash
bash scripts/build.sh --no-isolation
.venv/bin/python scripts/release.py manifest --output dist/manifest.json
```

`build.sh` fixes SOURCE_DATE_EPOCH to the commit timestamp, PYTHONHASHSEED, TZ and
locale. Build independently in two clean source directories and compare wheel
SHA-256 values. Wheel reproducibility has a narrower scope than reproducing the
OS, interpreter and dependency wheels. The sdist may have gzip/tar timestamps;
do not claim its reproducibility unless independently compared or normalized.
Manifest JSON uses sorted keys and contains source file hashes, commit, epoch
and artifact hashes. It is rejected if tracked source changes are uncommitted.

## Sign and verify

```bash
mkdir -m 700 /private/release-keys
.venv/bin/python scripts/release.py keygen \
  /private/release-keys/signing.pem /private/release-keys/public.pem
.venv/bin/python scripts/release.py sign dist/manifest.json \
  --key /private/release-keys/signing.pem --output dist/manifest.sig.json
.venv/bin/python scripts/release.py verify dist/manifest.json dist/manifest.sig.json \
  --trusted-key /independently/verified/release-public.pem
```

Signing uses Ed25519 and a protocol-specific signing prefix. Private key material
is encrypted PKCS#8 and mode 0600; passphrases are prompted interactively. Verify
manifest signatures and the listed artifact hashes before installing. Unit tests
cover signature validity, manifest modification and public-key substitution.
There is no established production release key, key-distribution channel or signed
Git tag yet. Development builds are not authenticated production releases.

## Future release governance — not implemented

Publish a separately authenticated roster of independent maintainers and require
a threshold (for example, 2 of 3 ordinary independent Ed25519 signatures) over the
same canonical manifest. This is a policy over established signatures, not a new
threshold-cryptography primitive. Require independent rebuild attestations from
separate machines, a monotonically increasing version, expiry and explicit key
rotation/revocation records. An update verifier must pin this policy and reject
rollback, stale metadata and insufficient signatures.

Publish manifests, signatures and reproducible-build attestations to an existing
auditable transparency system with append-only proofs and independent witnesses.
Verify inclusion/consistency and checkpoint freshness before acceptance. A server
that merely serves a JSON log is not sufficient. Network privacy of update/log
queries and recovery from log/key compromise need review. Until these mechanisms
are implemented and independently verified, do not claim resistance to colluding
maintainers, targeted malicious signed releases or transparency-log equivocation.

## Version 0.2 native cryptographic backend

The package now includes a locally built Rust extension, **cryptography only**, not
an external messenger engine. `native/Cargo.lock` pins registry checksums and exact
libsignal/SPQR source revisions; `native/rust-toolchain.toml` pins Rust 1.98.1.
Review upstream AGPL-3.0-only source/notices and the combined distribution terms in
CRYPTO_DEPENDENCIES.md. Preserve corresponding source for redistributed binaries;
our source archive contains the binding and pins, not a vendored dependency tree.
For an offline source release, separately vendor and include the full pinned
Cargo dependency sources/notices using Cargo's supported vendoring workflow.

`bash scripts/build.sh --no-isolation --outdir dist/0.2.3` builds the backend before
packaging. Wheels contain `_crypto_native.abi3.so` and are **platform tagged** (the
current setuptools build conservatively tags its building Python version).
They must not be represented as pure Python universal wheels. Source archives
exclude compiled `.so` files and include Rust source/lock/toolchain and tests.
Unpack and follow README's explicit native-build prerequisites before source
installation. A missing backend refuses secure messaging, with no static-key fallback.

`bash scripts/check_crypto.sh` runs Rust fmt, clippy with warnings denied, the real
SPQR snapshot-compromise experiment and cargo-audit. Install cargo-audit separately
from a verified pinned source; development used 0.22.2. It is not a runtime dependency.
Audit findings/warnings require review, not automatic suppression. Python test
checks explicitly require the backend so absent crypto tests cannot silently skip
in the documented verification workflow. Infrastructure tests still require opt-in.

SOURCE_DATE_EPOCH does not make arbitrary native builds reproducible. Record Rust,
LLVM/linker, protoc, architecture/CPU flags, Cargo sources, Python ABI, native
libraries, paths and environment; independently compare clean builds. Protoc 33.1
was used here (official Linux x86-64 archive SHA-256
`f3340e28a83d1c637d8bafdeed92b9f7db6a384c26bca880a6e5217b40a4328b`).
Native cross-machine bit-for-bit reproducibility and independently verified
release signatures have not been established for 0.2. No production signing key
was generated or silently entrusted during development. Existing older 0.1
distributions/manifests do not represent the new source or secure messenger.

Version 0.2.1 changes normal chat to TOR by default and requires the separately
installed Tor executable (or an explicitly configured external proxy). The binary
is a networking dependency, not bundled messenger code. Record/audit its package
provenance separately; testing used installed Tor 0.4.8.14.
