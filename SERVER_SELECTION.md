# SMP server selection — observations from 2026-10-21

The initial preference was an independent third-party router outside the EU and
USA, ideally in Iceland. A Swiss Urban-Network service was tested as a practical
alternative, including the complete two-process transport demo.

Distinguish a published router address/pin, successful SMP connectivity, permission
to create queues, the hosting company, and the router operator's identity and
jurisdiction. IP geolocation and PONG alone do not establish all of these. A public
catalog supplies candidates, not proof of trustworthiness or physical location.
These are dated observations, not continuous monitoring or a jurisdictional audit.

## Tested alternative — Urban-Network, Switzerland

```text
smp://LtowhzwGvh3lqlFvMqxCTPmZ_OzcwOq_NCsNG7ya1lc=@urban-network.dyndns.org:5224
```

The operator publishes its SMP address, onion alternative and queue-creation
password on its [service page](https://urban-network.ch/services/simplex).
This client normalizes the address to one hostname and supplies NEW authorization
separately, without changing the certificate pin.

Our independent Python client verified TLS/SMP authentication, v18 negotiation,
NEW, SKEY, two-process online transfer, offline delivery, restart/redelivery,
deduplication, ACK, an empty queue after processing and DEL. Temporary test queues
were deleted. The public NEW password was used only to create queues and was
stored in a temporary 0600 file, not in process arguments or public invitations.
Later encrypted-chat/Tor results are recorded separately in [VERIFICATION.md](VERIFICATION.md).

During the original test DNS resolved to `46.126.186.32`.
[RIPE RDAP](https://rdap.db.ripe.net/ip/46.126.186.32) recorded the range
`CH-UPC-20100818`, country CH. The [operator's team page](https://urban-network.ch/equipe)
described the Swiss Alps/Lake Geneva region. These are registry/operator statements,
not independent verification of physical location, ownership, legal identity or
actual server behavior. No equivalence between Swiss and Icelandic privacy
protection has been independently established.

Swiss privacy protections coexist with lawful surveillance powers. The historical
research consulted the [Swiss privacy regulator](https://www.edoeb.admin.ch/en/telecommunications-confidentiality-and-surveillance-of-telecommunications),
a [government notice dated 2026-02-11](https://www.bazg.admin.ch/fr/newnsb/EXv-JkPBAZuL)
and a [September 2026 parliamentary inquiry](https://ws-old.parlament.ch/affairs/20267879).
This project claims no immunity from government access, legal process or blocking.

Normal chat bundles the operator-published public NEW credential with this pinned
default router. It performs no operator-website fetch at runtime. If a credential
changes, review the new configuration or import it from a private file.

For a low-level transport demo with an explicitly imported public NEW password:

```bash
.venv/bin/python - <<'PY'
from getpass import getpass
from pathlib import Path
from private_messenger.storage.vault import atomic_write
path = Path.home() / '.private-messenger-router-auth/urban-network.auth'
atomic_write(path, getpass('Public NEW password from Urban-Network: ').encode(), overwrite=False)
print('Created a 0600 file.')
PY

bash scripts/demo_alice_bob.sh \
  --server 'smp://LtowhzwGvh3lqlFvMqxCTPmZ_OzcwOq_NCsNG7ya1lc=@urban-network.dyndns.org:5224' \
  --basic-auth-file "$HOME/.private-messenger-router-auth/urban-network.auth"
```

This is a temporary opaque-transport test, not the authenticated interactive chat.
NEW authorization and the local vault password are different credentials.
Use [the two-client guide](TEST_TWO_CLIENTS.md) for encrypted conversations.

Other historical candidates: `simplex.notrustverify.ch` and `simplex.cercatrova.me`
did not connect within six seconds. Norway's `smp.borgen.org` passed router
authentication and v20 PING, but unauthenticated NEW returned `ERR AUTH`.
These timeouts do not prove permanent unavailability.

## Icelandic candidate — queue creation was not authorized

`athenasmp.2023.crabdance.com:5223`:

- The public community catalog advertised pin
  `rgz35gHOh2vlLm_LjUgGl6f00V834d_WndNwpiRjYB8=`.
- The native client validated that pin, completed TLS/SMP, negotiated v18 and
  received PONG.
- NEW returned `ERR AUTH`. No queue was created and no online/offline exchange
  was demonstrated. A password or queue-creation restriction is a possible
  explanation; the exact policy was not established. No password guessing or
  authentication bypass was attempted.
- DNS resolved to `93.95.229.234`. RIPE recorded `THE-1984-VPS1-NET`, country IS,
  organization 1984 ehf. Address-allocation records do not independently prove
  the router's physical location.
- The SMP operator's identity/jurisdiction was not verified. This is not a
  recommendation to trust the candidate for real conversations.

Other Iceland-listed candidates `smp01.almanac6826.com` and `89.147.109.86`
did not complete TCP within four seconds; `93.95.225.18` refused the connection.
The historically advertised `simplex.hackliberty.org` did not resolve during the
test. These observations do not establish permanent failure or the absence of
other public routers.

## Self-hosting with more explicit hosting provenance

1984 Hosting advertises Icelandic jurisdiction, 1984 ehf. in Reykjavik, and VPS
hosting in Icelandic data centers. A standard unmodified open-source `smp-server`
could run there while this Python client remains independent of the SimpleX Chat
engine and agent. This would be operating your own router, not using an already
operating third-party public service. No VPS was purchased or deployed.

## Configure a router

Use the actual available SMP URI including an independently verified certificate
pin. Inside an unlocked chat:

```text
/servers smp://PIN@HOST:PORT
```

For a server requiring NEW authorization, add `--basic-auth-file PATH`. The file
must be a user-owned regular 0600 file, not a symlink, containing 1–255 bytes.
Validation occurs before network contact. Credentials in the server URI are not
supported. The low-level Python API also accepts `create_queue(basic_auth=...)`.

The server list does not migrate existing queues. New local receive queues use
the first configured router unless explicitly selected; each peer's invitation
names its receive router. Multiple configured servers do not implement automatic
failover, redundancy or queue rotation. Unknown passwords are not bypassed and
router authentication is never disabled.

## Sources for the dated observations

- [Public community catalog](https://simplex-catalog.asriyan.me/): candidate
  availability can differ from a direct test; Athena PING worked despite its
  catalog failure status.
- [RIPE RDAP for 93.95.229.234](https://rdap.db.ripe.net/ip/93.95.229.234).
- [1984 company and jurisdiction](https://1984.hosting/about/).
- [1984 VPS/data-center information](https://1984.hosting/).
- [Historical Hack Liberty announcement](https://forum.hackliberty.org/t/welcome-to-hack-liberty/5/).
