# Test dvou oddělených klientů

Nejjednodušší ověření na tomto počítači — jeden příkaz, bez ruční konfigurace:

```bash
bash /home/janbenes/private-messenger/scripts/demo_swiss.sh
```

Sám založí dočasné profily Alice/Bob, získá zveřejněné heslo švýcarského routeru,
otestuje online/offline přenos a uklidí. Níže je ruční varianta pro vlastní profily.

Testuje se transport náhodných dat. Konverzační E2E šifrování a ratchet dosud
nejsou implementované; nejde ještě o textový chat.

Lze použít dva terminály na jednom počítači nebo dva různé počítače. Na každém
musí být nainstalovaný tento projekt podle README. Každý klient používá vlastní
vault. Soukromé vaulty ani hesla mezi klienty nekopíruj.

## 1. Společné nastavení v obou terminálech

Přejdi do adresáře projektu. Na tomto počítači:

```bash
cd /home/janbenes/private-messenger
```

Nastav úplnou adresu vybraného SMP serveru, včetně ověřeného otisku. Například
následující již otestovaný veřejný server lze použít k ověření funkce klienta;
není tím označen za islandský:

```bash
SMP_SERVER='smp://u2dS9sG8nMNURyZwqASV4yROM28Er0luVTx5X1CsMrU=@smp4.simplex.im'
```

Pro islandský nebo jiný server změň hodnotu této proměnné na jeho skutečnou,
důvěryhodně získanou adresu. Samotné přidání příkazem `servers` nastavuje seznam;
server pro novou frontu se vybírá explicitně příkazem `smp create`.
Funkční švýcarská alternativa Urban-Network a postup pro její zveřejněné heslo
jsou v [SERVER_SELECTION_CS.md](SERVER_SELECTION_CS.md). U chráněného serveru
přidej `--basic-auth-file PATH` k Bobovu `smp create` i k automatickému demu.

## 2. Terminál B — Bob, příjemce

```bash
bob() {
  .venv/bin/private-messenger \
    --vault "$HOME/.private-messenger-bob/state.vault" "$@"
}

bob register Bob
bob servers "$SMP_SERVER"
bob smp ping "$SMP_SERVER"
bob smp create od-alice "$SMP_SERVER"
bob smp address od-alice
```

`register` spusť pouze při prvním založení profilu. Zvol vlastní heslo. Každý další
příkaz se na něj znovu zeptá. `created` potvrzuje vytvoření fronty. `ERR AUTH` při
vytváření znamená, že vytvoření nebylo autorizováno; PONG sám přístup k frontám
nedokazuje.

Poslední příkaz vypíše JSON s položkou `address`. Předej Alici pouze celý řetězec
začínající `PMQ1:`. Je to diagnostický přístup k frontě, ne ověřená identita člověka.

Po skončení příkazu už Bobův klient neběží. Pro offline test ho zatím nespouštěj.

## 3. Terminál A — Alice, odesílatel

```bash
alice() {
  .venv/bin/private-messenger \
    --vault "$HOME/.private-messenger-alice/state.vault" "$@"
}

alice register Alice
alice smp secure bob 'PMQ1:SEM_VLOZ_CELY_BOBUV_RETEZEC'

PAYLOAD="$(mktemp)"
head -c 1024 /dev/urandom > "$PAYLOAD"
sha256sum "$PAYLOAD"
alice smp send bob "$PAYLOAD"
```

Nahraď ukázkový řetězec skutečným Bobovým `address`. Soubor obsahuje pouze náhodná
testovací data. Výstup `server_accepted` znamená přijetí routerem, nikoli potvrzení
od Boba. Uchovej si vypsaný SHA-256 pro porovnání na druhém klientovi.

## 4. Terminál B — offline stažení a opakované doručení

```bash
bob smp get od-alice --no-ack
```

Očekávej `event: received`, `new: true`, `acknowledged: false`.
`ciphertext_sha256` se musí shodovat s Aliciným `sha256sum`.
Příkaz uloží data do šifrovaného vaultu, ale nepotvrdí je routeru, a pak skončí.

Spusť nový proces:

```bash
bob smp get od-alice
```

Očekávej stejný otisk, `new: false`, `acknowledged: true`. Jde o opětovné doručení
stejných dat bez druhého záznamu v úložišti. Nyní už Bob poslal ACK.

```bash
bob smp get od-alice
```

Očekávej `event: empty`.

## 5. Online varianta

Nejprve si na Alici připrav nový blok, ale ještě ho neodesílej:

```bash
head -c 1024 /dev/urandom > "$PAYLOAD"
```

Na Bobovi spusť:

```bash
bob smp subscribe od-alice
```

Po výstupu `subscribed` spusť na Alici:

```bash
alice smp send bob "$PAYLOAD"
```

Aktuální subscribe čeká na jednu zprávu a má síťový timeout přibližně 20 sekund.
Pokud vyprší, spusť subscribe znovu nebo použij offline GET. Při dalším testu
vytvoř nový náhodný blok: opakované odeslání stejného obsahu CLI záměrně odmítá.

## 6. Druhý směr a úklid

Pro Bob → Alice vytvoří Alice vlastní přijímací frontu, předá Bobovi svůj PMQ1
řetězec a Bob vytvoří oddělené odesílací přihlašovací údaje stejným postupem.
Oba směry mohou používat různé SMP routery.

Testovací frontu Alice → Bob po ověření smaže Bob:

```bash
bob smp delete od-alice
```

Pro automatický test samostatných procesů včetně úklidu:

```bash
bash scripts/demo_alice_bob.sh --server "$SMP_SERVER"
```
