# Výběr SMP serveru — ověření 21. 10. 2026

Požadavek: nezávislá třetí strana, preference Islandu, mimo EU a USA.

Odděluj adresu a otisk routeru, skutečnou dostupnost SMP, povolení vytvářet fronty,
hostingovou společnost a totožnost/jurisdikci správce SMP. IP geolokace ani PONG
samostatně všechny podmínky nepotvrzují. Katalog je zdroj kandidátů, nikoli důkaz
důvěryhodnosti nebo fyzického umístění.

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

CLI této verze přijímá jeden hostname na adresu a nepodporuje vložení hesla pro
NEW do serverové URI. Python API parametr `create_queue(basic_auth=...)` má.
Bez získaného oprávnění a odpovídající podpory CLI nelze chráněný server používat
pro plné dvouprocesové demo. Nejde o důvod vypnout ověřování routeru.

Postup pro oddělené klienty: [TEST_TWO_CLIENTS_CS.md](TEST_TWO_CLIENTS_CS.md).

Zdroje:

- [Veřejný komunitní katalog](https://simplex-catalog.asriyan.me/) a jeho veřejná
  data. Stav katalogu se může lišit od přímého testu; u Atheny uváděl neúspěch,
  přesto náš PING fungoval.
- [RIPE RDAP pro 93.95.229.234](https://rdap.db.ripe.net/ip/93.95.229.234).
- [1984 — společnost a jurisdikce](https://1984.hosting/about/).
- [1984 — VPS a umístění datacenter](https://1984.hosting/).
- [Historická publikace Hack Liberty](https://forum.hackliberty.org/t/welcome-to-hack-liberty/5/).
