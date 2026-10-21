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

Jde o test na **jednom počítači**, se dvěma samostatnými procesy a skutečným
švýcarským SMP serverem Urban-Network. Klíče se předají při místní přípravě;
zprávy přes síť chrání standardní NaCl Box a historie je šifrovaná heslem.
Ratchet, PFS/PCS, postkvantová ochrana a párování vzdálených zařízení dosud chybí.
Režim je DIRECT: server vidí IP. Potvrzení serveru není potvrzením od příjemce.

Profily zůstávají v `~/.local/share/private-messenger/terminal-demo/`;
starší profily se nepřepisují. Podrobnosti a omezení: [SECURITY.md](SECURITY.md).
Automatický test transportu pro vývojáře: `bash scripts/demo_swiss.sh`.
