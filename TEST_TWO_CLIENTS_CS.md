# Alice a Bob ve dvou terminálech

Na tomto počítači spusť v **prvním okně**:

```bash
/home/janbenes/private-messenger/chat Alice
```

Při prvním spuštění zvol heslo a zopakuj ho. Oba testovací profily se připraví
samy. Počkej na `Příjem připraven`.

Ve **druhém okně** spusť:

```bash
/home/janbenes/private-messenger/chat Bob
```

Zadej stejné heslo. Teď v Alicině okně napiš:

```text
Ahoj Bobe!
```

Stiskni Enter. Bob uvidí:

```text
Alice: Ahoj Bobe!
```

Bob může rovnou napsat odpověď. `/quit` ukončí klienta, `/history` zobrazí historii.
Stejnými příkazy se znovu přihlásíš. Když je Bob vypnutý, zpráva počká na SMP
serveru, dokud ji nevyzvedne (v mezích jeho dostupnosti, kvóty a retenční doby).

Bobovu přijímací adresu zobrazíš příkazem `/address` v Bobově chatu. Po aktualizaci
starší běžící klient restartuj. Případně Boba ukonči přes `/quit` a spusť:

```bash
/home/janbenes/private-messenger/chat Bob --address
```

Po zadání hesla vypíše pouze server, ID fronty pro odesílatele a veřejný šifrovací
klíč. Tento výpis se k síti nepřipojuje. Při první společné přípravě se tyto údaje
uložily Alici automaticky; jméno Bob se na serveru nevyhledává. Výpis zatím není
pozvánkou pro nové kontakty: fronta už je zabezpečená pro Alicin odesílací klíč.

Jde o test na **jednom počítači**, se dvěma samostatnými procesy a skutečným
švýcarským SMP serverem Urban-Network. Klíče se předají při místní přípravě;
zprávy přes síť chrání standardní NaCl Box a historie je šifrovaná heslem.
Ratchet, PFS/PCS, postkvantová ochrana a párování vzdálených zařízení dosud chybí.
Režim je DIRECT: server vidí IP. Potvrzení serveru není potvrzením od příjemce.

Profily zůstávají v `~/.local/share/private-messenger/terminal-demo/`;
starší profily se nepřepisují. Podrobnosti a omezení: [SECURITY.md](SECURITY.md).
Automatický test transportu pro vývojáře: `bash scripts/demo_swiss.sh`.
