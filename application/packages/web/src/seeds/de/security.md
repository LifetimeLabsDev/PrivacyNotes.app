---
id: 5ec1
title: Wie deine Notizen geschützt sind
---

> [!info]- Jede Notiz wird auf deinem Gerät verschlüsselt, bevor sie irgendwo gespeichert wird.
> &nbsp;

![Die Notiz-Tabelle in unserer echten Datenbank. Jeder Notiztext ist ein langer Block aus unlesbarem Text.](/onboarding/database.webp)

Das ist unsere echte Datenbank in Zürich, keine Zeichnung davon. Deine Notiz landet in der Spalte `ciphertext`. Verschlüsselte Bytes sind alles, was wir speichern, egal welche Möglichkeit du unten wählst.

## Was passiert, wenn du eine Notiz schreibst

1. Deine 12-Wort-Phrase wird zu einem Schlüssel. Das passiert auf deinem Gerät.
2. Die Notiz wird mit diesem Schlüssel verschlüsselt, auf deinem Gerät. So wird sie auf deiner eigenen Festplatte gespeichert, und so reist sie zu uns.
3. Wir bekommen die verschlüsselte Notiz und speichern sie. Das Bild oben zeigt, wie das aussieht.
4. Jedes Gerät mit derselben Phrase erzeugt denselben Schlüssel und öffnet die Notiz.

## Wer deinen Schlüssel hat

Jede Möglichkeit hält deine Notizen auf deinem Gerät verschlüsselt. Sie unterscheiden sich darin, wo deine Phrase liegt.

| Möglichkeit | Wo deine Phrase liegt | Was du davon hast |
| --- | --- | --- |
| **Login, Schlüssel bei uns** | Auf unserem Server, verschlüsselt | Ein neues Gerät meldet sich allein mit dem Login an |
| **Login, Schlüssel auf deinem Gerät** | Bei dir, sonst nirgends | Mit Google, Apple oder GitHub anmelden und den Schlüssel trotzdem behalten |
| **Nur Phrase, kein Login** | Bei dir, sonst nirgends | Keine E-Mail, kein Name, gar kein Login |

Bei den unteren beiden könnten wir eine Notiz nicht lesen, selbst wenn man uns dazu zwänge. Die erste tauscht das gegen Bequemlichkeit: Deine Phrase liegt auf unserem Server unter einem Schlüssel von uns, also braucht ein neues Gerät nichts außer deinem Login. Würde unser Server je angegriffen, könnte dieser Schlüssel offengelegt werden.

Mit Google, Apple oder GitHub angemeldet? Zwischen den ersten beiden kannst du später wechseln, unter **Einstellungen > Sicherheit > Deine Phrase**. Bei einem reinen Phrasen-Konto bleibt die Phrase immer bei dir.

> [!warning] Behalte eine eigene Kopie der Phrase
> Deine Phrase öffnet deine Notizen. Wenn du sie verlierst, kann sie niemand wiederherstellen, wir eingeschlossen. <span style="color: #e03131">Schreib sie heute auf Papier.</span>

## Prüf es selbst

[Ausführliche Anleitung zum Nachprüfen auf GitHub](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md)

- [ ] Öffne den Netzwerk-Tab deines Browsers und bearbeite dann eine Notiz. Sieh dir an, was bei uns ankommt: ein Block aus unlesbarem Text.
- [ ] Lies den Verschlüsselungscode. Er ist öffentlich und kurz genug, um ihn in einem Zug zu lesen.

| Was | Wo |
| --- | --- |
| Die Verschlüsselung selbst | [crypto.ts](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts) |
| Was unser Server empfängt | [VERIFY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md#tier-1-one-minute-no-tools) |
| Was ein Angreifer kann und was nicht | [THREAT_MODEL.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md) |
| Wie man eine Lücke meldet | [SECURITY.md](https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md) |

> [!info] Ein Schloss deckt alles ab
> Notizen, Tagebucheinträge, Lesezeichen, Tresor-Einträge und Dateianhänge werden genauso verschlüsselt. [[Einzug]] zeigt, wie du jedes davon herüberholst.
