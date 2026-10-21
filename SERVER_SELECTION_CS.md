# Výběr SMP serveru — ověření 21. 10. 2026

Požadavek: nezávislá třetí strana, preference Islandu, mimo EU a USA.
Po prověření Islandu byla jako praktická alternativa otestována švýcarská služba
Urban-Network; její plné dvouprocesové demo prošlo.

Odděluj adresu a otisk routeru, skutečnou dostupnost SMP, povolení vytvářet fronty,
hostingovou společnost a totožnost/jurisdikci správce SMP. IP geolokace ani PONG
samostatně všechny podmínky nepotvrzují. Katalog je zdroj kandidátů, nikoli důkaz
důvěryhodnosti nebo fyzického umístění.

## Funkční alternativa pro test — Urban-Network, Švýcarsko

```text
smp://LtowhzwGvh3lqlFvMqxCTPmZ_OzcwOq_NCsNG7ya1lc=@urban-network.dyndns.org:5224
```

Provozovatel publikuje úplnou SMP adresu, onion alternativu a heslo pro vytvoření
fronty na [vlastní stránce služby](https://urban-network.ch/services/simplex).
Pro náš klient je výše uvedená adresa normalizována na jeden hostname; heslo se
předává odděleně pomocí `--basic-auth-file`. Otisk se nemění.

Ověřeno naším nezávislým Python klientem: certifikát a TLS/SMP handshake, v18,
NEW, SKEY, online přenos mezi dvěma procesy, offline doručení, redelivery po
restartu, deduplikace, ACK, vyprázdnění fronty a DEL. Testovací fronta byla smazána.
Veřejné heslo bylo použito jen při NEW a během testu uloženo v dočasném souboru
0600; nikdy nebylo součástí argumentů procesu nebo publikovaného PMQ1 descriptoru.

DNS při testu: `46.126.186.32`. [RIPE](https://rdap.db.ripe.net/ip/46.126.186.32)
eviduje rozsah `CH-UPC-20100818`, zemi CH. Profil na
[webu provozovatele](https://urban-network.ch/equipe) uvádí švýcarské Alpy/Léman.
Jde o veřejné údaje provozovatele a registru, ne audit fyzické polohy, vlastnické
struktury, právní identity nebo chování serveru. Přímé nezávislé srovnání celkové
ochrany soukromí Švýcarska s Islandem nemáme.

Švýcarský [dozorový úřad](https://www.edoeb.admin.ch/en/telecommunications-confidentiality-and-surveillance-of-telecommunications)
popisuje ústavní ochranu soukromí a komunikace podle čl. 13 a současně zákonné
pravomoci sledování komunikace. [Vládní zpráva z 11. 2. 2026](https://www.bazg.admin.ch/fr/newnsb/EXv-JkPBAZuL)
uvádí přepracování návrhu souvisejících prováděcích předpisů a plán další
konzultace; [parlamentní dotaz ze září 2026](https://ws-old.parlament.ch/affairs/20267879)
se ptá na stav těchto prací. Netvrdíme obecnou imunitu před zákonným přístupem.

Příprava souboru s heslem zveřejněným na stránce provozovatele:

```bash
.venv/bin/python - <<'PY'
from getpass import getpass
from pathlib import Path
from private_messenger.storage.vault import atomic_write
path = Path.home() / '.private-messenger-router-auth/urban-network.auth'
atomic_write(path, getpass('Heslo pro NEW z webu Urban-Network: ').encode(), overwrite=False)
print('Soubor 0600 vytvořen.')
PY
```

Samostatný test dvou procesů, bez vytvoření trvalého uživatelského profilu:

```bash
bash scripts/demo_alice_bob.sh \
  --server 'smp://LtowhzwGvh3lqlFvMqxCTPmZ_OzcwOq_NCsNG7ya1lc=@urban-network.dyndns.org:5224' \
  --basic-auth-file "$HOME/.private-messenger-router-auth/urban-network.auth"
```

Pro ruční postup v dokumentu TEST_TWO_CLIENTS_CS.md nastav tento SMP_SERVER a
Bobův příkaz pro vytvoření fronty rozšiř:

```bash
bob smp create od-alice "$SMP_SERVER" \
  --basic-auth-file "$HOME/.private-messenger-router-auth/urban-network.auth"
```

Heslo pro NEW a heslo lokálního vaultu jsou různé věci. Alici se heslo pro NEW
nepředává, pokud si na stejném serveru nevytváří vlastní přijímací frontu.

Další prověřené alternativy: `simplex.notrustverify.ch` a `simplex.cercatrova.me`
nedokončily spojení v limitu 6 s; norský `smp.borgen.org` prošel ověřením routeru
a PING při v20, ale NEW bez hesla vrátil `ERR AUTH`. Nejde o důkaz trvalé
nedostupnosti ostatních služeb.

## Nalezený islandský kandidát — zatím nepoužitelný bez autorizace

`athenasmp.2023.crabdance.com:5223`:

- Otisk publikovaný veřejným komunitním katalogem:
  `rgz35gHOh2vlLm_LjUgGl6f00V834d_WndNwpiRjYB8=`.
- Nativní klient ověřil certifikát proti tomuto otisku, TLS/SMP handshake a PONG,
  vyjednána verze 18.
- NEW vrací `ERR AUTH`. Nevznikla fronta; online/offline demo proto neprošlo.
  Pravděpodobným vysvětlením je požadované heslo nebo omezené vytváření front,
  přesnou politiku správce neznáme. Heslo se nehádalo ani neobcházelo.
- DNS při testu ukazovalo na `93.95.229.234`. RIPE eviduje rozsah
  `THE-1984-VPS1-NET`, zemi IS a organizaci 1984 ehf. Jde o evidenci přidělení
  adresního rozsahu; není to nezávislý audit fyzické polohy routeru.
- Totožnost a jurisdikce samotného správce SMP nebyla ověřena. Nejde proto o
  doporučený důvěryhodný veřejný server pro skutečné konverzace.

Další prověření kandidáti z islandských záznamů katalogu:
`smp01.almanac6826.com` a `89.147.109.86` nedokončily TCP připojení v limitu 4 s,
`93.95.225.18` odmítl připojení. Historicky publikovaný
`simplex.hackliberty.org` se při testu nepodařilo přeložit v DNS. Tato pozorování
neprokazují trvalou nedostupnost ani neexistenci jiných veřejných serverů.

## Cesta s doložitelnějším hostingem

1984 Hosting uvádí islandskou jurisdikci, společnost 1984 ehf. v Reykjavíku a VPS
v islandských datacentrech. Na takovém VPS lze provozovat standardní nezměněný
`smp-server`; Python klient zůstane nezávislý na SimpleX Chat enginu a agentu.
To by ale znamenalo vlastní provoz routeru, nikoli použití již provozovaného
veřejného SMP třetí strany. Žádný VPS nebyl objednán ani nasazen.

## Nastavení v klientovi

Po získání skutečné adresy a ověřeného otisku dostupného serveru:

```bash
SMP_SERVER='SEM_VLOZ_SKUTECNOU_ADRESU_SMP_VCETNE_OTISKU'
.venv/bin/private-messenger servers "$SMP_SERVER"
.venv/bin/private-messenger smp ping "$SMP_SERVER"
.venv/bin/private-messenger smp create testovaci-fronta "$SMP_SERVER"
```

Příkazy předpokládají založený lokální profil a vyžádají si heslo vaultu.
`servers` pouze eviduje seznam. Fronta používá server z explicitního argumentu
`smp create`; již existující fronty se přidáním dalšího serveru nepřesunou.

CLI přijímá jeden hostname na adresu a nepodporuje vložení hesla pro NEW přímo do
serverové URI. Heslo podporuje pomocí `--basic-auth-file PATH` u `smp create` i
automatického dema. Soubor musí být běžný soubor 0600 vlastněný uživatelem, nesmí
být symlink, heslo musí mít 1 až 255 bajtů. Ověření souboru proběhne před síťovým
připojením. Python API podporuje `create_queue(basic_auth=...)` přímo.
Neznámé heslo se neobchází a ověřování routeru se nevypíná.

Postup pro oddělené klienty: [TEST_TWO_CLIENTS_CS.md](TEST_TWO_CLIENTS_CS.md).

Zdroje:

- [Veřejný komunitní katalog](https://simplex-catalog.asriyan.me/) a jeho veřejná
  data. Stav katalogu se může lišit od přímého testu; u Atheny uváděl neúspěch,
  přesto náš PING fungoval.
- [RIPE RDAP pro 93.95.229.234](https://rdap.db.ripe.net/ip/93.95.229.234).
- [1984 — společnost a jurisdikce](https://1984.hosting/about/).
- [1984 — VPS a umístění datacenter](https://1984.hosting/).
- [Historická publikace Hack Liberty](https://forum.hackliberty.org/t/welcome-to-hack-liberty/5/).
