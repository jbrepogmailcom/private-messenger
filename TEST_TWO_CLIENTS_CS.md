# Alice a Bob ve dvou oknech

Nový `./chat` používá samostatné profily, vzdálené párování a ratchet. Obě okna
mohou běžet na různých počítačích. Hesla se nemusí shodovat. Nejde o auditovanou
produkční aplikaci. Sestavení je popsané v README; na vývojovém počítači už je hotové.

1. V prvním okně spusť `cd /home/janbenes/private-messenger` a `./chat Bob`.
   Zvol Bobovo heslo. Napiš `/address`.
2. Z výstupu zkopíruj celý příkaz začínající `/add Bob PMS2:`.
   To je Bobova jednorázová adresa pro tento kontakt. Předej ji Alici důvěryhodnou cestou.
3. Ve druhém okně spusť `cd /home/janbenes/private-messenger` a `./chat Alice`.
   Zvol Alicino heslo. Vlož celý příkaz `/add Bob PMS2:…` a stiskni Enter.
   Máš-li jen kód, napiš `/add PMS2:…`; celý JSON export lze vložit za `/add`.
4. Bob napíše **`/accept`**.
5. Oba napíšete **`/verify`**. Zobrazený otisk porovnejte osobně nebo jiným
   důvěryhodným kanálem. Pokud se celý shoduje, oba napište **`/ano`**.
   Při neshodě napište `/ne` a ověřte původ pozvánky.
6. Alice napíše `Ahoj Bobe!`. Bob zprávu uvidí a může stejným způsobem odpovědět.
   Zprávy pište přímo, bez příkazů. Fungují i uvozovky a apostrofy.

Není potřeba opisovat ID kontaktů ani otisk do příkazu. Při čekání chat vypíše,
který krok ještě chybí. Po restartu se jediný existující kontakt vybere automaticky.
Se stejnou již použitou pozvánkou znovu nezačínej; původní konverzace zůstává uložená.

**Všechny příkazy v chatu začínají `/`.** Text bez lomítka je zpráva vybrané
protistraně. Pokud obsahuje pozvánku nebo dlouhý Base32 kód, chat odeslání zadrží
a připomene `/add`. Neznámý příkaz s lomítkem se také nikdy neodešle jako zpráva.

`/contacts` nebo `/chat` ukáže očíslovaný seznam; `/chat 2` vybere druhý kontakt;
`/chat Bob` vybere Boba jménem; `/history` ukáže historii; `/send Bob TEXT` pošle
konkrétnímu kontaktu; `/quit` ukončí klienta. Při stejných jménech vyber číslem.
Čísla patří naposledy zobrazenému seznamu a nový příchozí kontakt je neposune.
Příkazy s ID a `/verify ID --confirm OTISK` nadále fungují.
`server_accepted` znamená přijetí routerem. Teprve `recipient_received` / „Příjemce
potvrdil zprávu“ označuje autentizované potvrzení klienta. Neznamená přečtení člověkem.

Offline test: Bob napíše `/quit`; Alice odešle zprávu. Bob znovu spustí `./chat Bob`,
zadá své heslo a zprávu přijme. Alice musí být spuštěná, aby přijala jeho potvrzení;
pokud je vypnutá, potvrzení počká v její frontě. Doručení závisí na retenci routeru.

## Přidání Charlieho a přepínání protistrany

1. Charlie spustí `./chat Charlie` a napíše `/address`.
2. Alice vloží **celý vypsaný příkaz `/add Charlie PMS2:…`** do svého okna.
   Lze také napsat `/add Charlie KÓD`, kde KÓD je celá pozvánka s `PMS2:`.
3. Charlie napíše `/accept`; Alice a Charlie každý `/verify`, porovnají otisk
   a při shodě napíšou `/ano`.
4. Alice napíše `/chat`. Uvidí například:

   ```text
   1. Bob · připraveno k psaní
   2. Charlie · připraveno k psaní
   ```

5. `/chat 2` přepne na Charlieho, `/chat 1` zpět na Boba. Prompt ukazuje například
   `Alice → Charlie>`, takže před odesláním vidíš příjemce. Každý kontakt má vlastní konverzaci.

## Smazání kontaktu a nový test od začátku

V okně Alice napiš `/del Charlie`, pak potvrď `/ano`. V okně Charlie napiš
`/del Alice` a `/ano`. `/ne` smazání zruší. Lze také použít `/del ČÍSLO`
z naposledy vypsaného seznamu nebo samotné `/del` pro právě vybraný kontakt.

Příkaz odstraní místní historii, konverzační klíče, neodeslané zprávy a záznamy
doručení daného kontaktu. Zastaví jeho příjem a smaže vlastní příchozí frontu
na SMP serveru. Ostatní kontakty a profil zůstanou zachované. Smazaný vybraný
kontakt se z promptu odstraní a jiný se za něj automaticky nevybere.

Potom Charlie napíše `/address`. Alice vloží **nově vypsaný** příkaz `/add Charlie …`.
Charlie použije `/accept`; oba `/verify`, porovnají nový otisk a při shodě `/ano`.
Vzniknou nové kontaktní klíče, nové fronty a prázdná historie této konverzace.

Nepoužité pozvánky uvidíš přes `/contacts --all` a smažeš také pomocí `/del ČÍSLO`.
Pokud server neodpovídá, místní historie a konverzační klíče už jsou odstraněné,
ale kontakt ukáže „čeká na dokončení smazání fronty“. Zůstávají jen šifrované
přístupové údaje k frontě pro dokončení smazání. Opakuj `/del JMÉNO` nebo uvedené
ID, případně i po restartu; již potvrzené smazání se znovu nepotvrzuje.
Pokud chceš zahodit i zbývající místní přístupové údaje bez kontaktování serveru,
použij `/del JMÉNO --local` a potvrď `/ano`. Fronta na serveru tím zůstane
a bez zahozených klíčů už ji tímto klientem nesmažeš. Tato varianta je výslovná,
nepoužije se automaticky při selhání sítě.
Odpověď AUTH se nevydává za potvrzené smazání serverem. Starší zálohy a kopie
u protistrany příkaz nesmaže; fyzický přepis dat na SSD ani v paměti Pythonu nezaručuje.

## Co přesně je adresa a vzdálené párování

`/address` pokaždé vytvoří novou frontu, nový náhodný kontaktový identifikátor,
kontaktový klíč identity, klasické prekeys a ML-KEM klíč. Router náhodně přidělí
identifikátory fronty. Pozvánka obsahuje adresu routeru, jeho certifikátový otisk,
**odesílací** ID fronty, veřejné klíče, kryptografickou sadu, expiraci a podpis.
Neobsahuje Bobovo heslo, soukromé klíče ani oprávnění číst jeho frontu.

Pozvánka je komprimovaný Base32 řetězec kompatibilní s alfanumerickým QR kódem
(do kapacity QR 40-L); vykreslování QR zatím není součástí CLI. Platí sedm dní a
je pro jeden kontakt. Nevystavuj ji veřejně: první držitel může obsadit frontu.
`/address` není vyhledávání uživatele jménem Bob ani registrace na serveru.

Vzdálené párování znamená, že si Alice a Bob předají jen veřejnou pozvánku. Každý
vygeneruje vlastní soukromé klíče na svém zařízení. Neprovádí se společný lokální
setup a nepotřebují sdílené heslo. Porovnání otisku chrání spojení s konkrétním člověkem.

## Verze a zbývající omezení

Použitá oficiální knihovna má při navázání X25519 + **ML-KEM-1024**, potom Double
Ratchet + průběžný SPQR s **ML-KEM-768**. To se liší od původně požadovaného
ML-KEM-768 také při navázání. Vlastní kryptografickou náhradu jsme nevytvořili.
PFS/PCS mají předpoklady a omezení uvedené v SECURITY.md; nejde o dokonalou ochranu.

Nové profily jsou v `~/.local/share/private-messenger/secure-profiles/`.
Předchozí lokální demo zůstává v `terminal-demo/` a lze je spustit `./chat-legacy`.
Není automaticky převedené; staré Box konverzace ratchet zpětně nezískají.
Nevypisuj soukromý obsah vaultů ani neposílej někomu jejich hesla.

Výchozí síť je **TOR**. `./chat Alice` a `./chat Bob` si každý spustí vlastní Tor,
ukazují teploměr knihovny `tqdm` na jednom řádku, počkají na `Tor: 100%`
a teprve potom se připojí k SMP. Tor musí být nainstalovaný;
na vývojovém počítači už je. Při jeho selhání se klient přímo k routeru nepřipojí.
Starší profil s DIRECT se při tomto spuštění po odemknutí přepne na TOR. Běžící
starou verzi nejprve ukonči pomocí `/quit`. Dřívější přímá spojení změna neskryje.

Vlastní proxy lze nastavit například `./chat Alice --tor-proxy-port 9050`.
Takto nastavená proxy se zachová i příště; při její nedostupnosti se nic nenahrazuje.
Režim DIRECT (odhalující IP routeru) vyžaduje výslovné `--network DIRECT`.

Veřejné heslo pro zakládání front na výchozím routeru je přibalené jako veřejné
nastavení serveru. Chat kvůli němu neotevírá web provozovatele. Pro jiný router nebo
změněné heslo použij `/servers URI --basic-auth-file SOUBOR`. Nejde o heslo profilu.
Tor nezaručuje ochranu před globální korelací provozu; země provozu sama soukromí nezaručuje.
