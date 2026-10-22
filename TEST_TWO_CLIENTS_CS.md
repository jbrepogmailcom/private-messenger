# Alice a Bob ve dvou oknech

Nový `./chat` používá samostatné profily, vzdálené párování a ratchet. Obě okna
mohou běžet na různých počítačích. Hesla se nemusí shodovat. Nejde o auditovanou
produkční aplikaci. Sestavení je popsané v README; na vývojovém počítači už je hotové.

1. V prvním okně spusť `cd /home/janbenes/private-messenger` a `./chat Bob`.
   Zvol Bobovo heslo. Napiš `address`.
2. Z výstupu zkopíruj celou hodnotu začínající `PMS2:` — bez okolních uvozovek.
   To je Bobova jednorázová adresa pro tento kontakt. Předej ji Alici důvěryhodnou cestou.
3. Ve druhém okně spusť `cd /home/janbenes/private-messenger` a `./chat Alice`.
   Zvol Alicino heslo. Vlož pozvánku `PMS2:…` a stiskni Enter.
4. Bob uvidí žádost a příkaz například `accept a1b2c3d4e5f60718`. Proveď **příkaz,
   který skutečně vypíše jeho okno**. Lokální ID Alice a Boba se liší.
5. Každý napište `verify ID` se svým lokálním ID. Zobrazených 60 číslic porovnejte
   osobně nebo jiným ověřeným kanálem. Potom každý napište:

   ```text
   verify ID --confirm SKUTECNY_60MISTNY_OTISK
   ```

6. Alice napíše `Ahoj Bobe!`. Bob zprávu uvidí a může stejným způsobem odpovědět.
   Po ověření je tento kontakt vybraný; s více kontakty piš `send ID TEXT`.

`contacts` ukáže ID kontaktů; `history ID` historii; `quit` ukončí klienta.
`server_accepted` znamená přijetí routerem. Teprve `recipient_received` / „Příjemce
potvrdil zprávu“ označuje autentizované potvrzení klienta. Neznamená přečtení člověkem.

Offline test: Bob napíše `quit`; Alice odešle zprávu. Bob znovu spustí `./chat Bob`,
zadá své heslo a zprávu přijme. Alice musí být spuštěná, aby přijala jeho potvrzení;
pokud je vypnutá, potvrzení počká v její frontě. Doručení závisí na retenci routeru.

## Co přesně je adresa a vzdálené párování

`address` pokaždé vytvoří novou frontu, nový náhodný kontaktový identifikátor,
kontaktový klíč identity, klasické prekeys a ML-KEM klíč. Router náhodně přidělí
identifikátory fronty. Pozvánka obsahuje adresu routeru, jeho certifikátový otisk,
**odesílací** ID fronty, veřejné klíče, kryptografickou sadu, expiraci a podpis.
Neobsahuje Bobovo heslo, soukromé klíče ani oprávnění číst jeho frontu.

Pozvánka je komprimovaný Base32 řetězec kompatibilní s alfanumerickým QR kódem
(do kapacity QR 40-L); vykreslování QR zatím není součástí CLI. Platí sedm dní a
je pro jeden kontakt. Nevystavuj ji veřejně: první držitel může obsadit frontu.
`address` není vyhledávání uživatele jménem Bob ani registrace na serveru.

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

Výchozí síť je DIRECT a švýcarský router vidí zdrojovou IP. Pro TOR nejprve ukonči
chat a nastav profil příkazem uvedeným v README. Web provozovatele může Tor blokovat;
veřejné heslo pro NEW lze dodat přes `servers URI --basic-auth-file SOUBOR`.
Nikdy se automaticky nepřechází na DIRECT. Země provozu sama o sobě soukromí nezaručuje.
