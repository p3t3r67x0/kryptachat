# Krypta: isolierte Identity State Machine

Stand: 8. Oktober 2026. **Entwicklungsprototyp, kein produktiver Messenger,
kein unabhängig auditiertes Protokoll.** Die vier bestehenden
Sicherheitsdokumente bleiben unverändert. Die Einordnung ihrer Anforderungen,
Annahmen und Abweichungen steht im
[Implementierungsreview](../security/identity-implementation-review.md).

## Geltungsbereich und Architektur

Das Package `src/secure_messenger/identity/` verwaltet genau eine lokale,
frisch erzeugte Identität und ihre signierte Gerätehistorie im Arbeitsspeicher.
Es stellt keine Netzwerkverbindung her und implementiert keine Nachrichten,
Relays, Kontaktverifikation, Transparenzserver, Backups oder Wiederherstellung.

| Modul | Aufgabe |
|---|---|
| `models.py` | Strenge, unveränderliche Pydantic-v2-Modelle; geschlossene Schemata |
| `codec.py` | Beschränkte kanonische Codierung, Größen- und Duplikatprüfung |
| `signatures.py` | Native Schlüsselgenerierung, Ed25519-Prüfung, SHA-256-Hashes, Domänen |
| `authority.py` | Reine Rollenprüfung gegen den authentifizierten Vorgänger |
| `transitions.py` | Reine Berechnung eines möglichen Folgezustands |
| `history.py` | Unveränderliche Folge aus Genesis, Zuständen und signierten Änderungen |
| `consistency.py` | Lokaler Replay-, Rollback-, Versions- und Fork-Schutz |
| `freshness.py` | Konfigurierbare Fristen und explizite externe Prüferschnittstelle |
| `revocation.py` | Irreversible lokale Widerrufseinträge |
| `state_machine.py` | Prüfung, Sperre für parallele Aufrufe, atomare Übernahme |
| `errors.py` | Unterscheidbare Ablehnungsgründe ohne private Schlüssel |

Das öffentliche Modell und die Historie sind unveränderlich. Privatschlüssel
werden separat als native Bibliotheksobjekte zurückgegeben und nicht in
Zustände, Historie oder Serialisierung aufgenommen. Der Host ist verantwortlich
für Schutz und bewusste Verwendung dieser Schlüssel. Es gibt keinen OS-Keystore,
keine Festplattenpersistenz und keine zugesicherte Speicherlöschung.

## Schlüssel und Kennungen

Die Root Authority und jedes Gerät erhalten separate Ed25519-Schlüssel über
`cryptography`. Vor jeder Ed25519-Verifikation prüft die native libsodium-
Funktion `crypto_core_ed25519_is_valid_point` über PyNaCl zusätzlich den
öffentlichen Punkt. Das Profil benötigt PyNaCl ab 1.6.2 mit gepatchter,
gebündelter libsodium-Version; ein eigener Punktalgorithmus oder ein Fallback
auf die ältere Systembibliothek existiert nicht. Jedes Gerät generiert
außerdem einen eigenen X25519-Schlüssel.
Dieser ist ausschließlich ein **Platzhalter für die noch offene
Messaging-Anbindung**: keine DH-Verwendung, kein Ratchet, kein PQXDH, keine
Umwandlung von Ed25519-Schlüsseln und kein Nachweis eines vollständigen
Messaging-Handshakes. Der Gerätebesitznachweis bezieht sich auf den
Authentifizierungsschlüssel und bindet die angegebenen öffentlichen Daten;
er beweist nicht unabhängig den Besitz des X25519-Privatschlüssels.

Geräte- und Action-IDs bestehen aus 16 zufälligen Bytes (`secrets`), Challenges
aus 32. Die Identitätskennung ist SHA-256 über die Identitätsdomäne und den
kanonischen, genau 32 Byte langen Root-Public-Key. Sie enthält keine
Serveradresse, Telefonnummer oder menschliche Identitätsbehauptung.

Root-, Geräte- und Sitzungsschlüssel dürfen im gesamten bekannten Verzeichnis,
einschließlich widerrufener Einträge, nicht identisch sein. Ein widerrufener
Gerätebezeichner wird nicht wiederverwendet. Die historische Schlüsselbindung
verhindert keine unbemerkte Kompromittierung eines noch aktiven Geräts.

## Prototypformat und Domänentrennung

Profil: Protokollversion 1, Policyversion 1 und ausschließlich die Suite
`KRYPTA-IDENTITY-PROTOTYPE-ED25519-SHA256-V1`. Es gibt keine automatische
Versionsverhandlung, Migration, Downgrade- oder Suite-Ausweichlogik.

Das Format ist ein festes **kanonisches ASCII-JSON-Subset**, kein Anspruch auf
RFC-8785-Kompatibilität und keine Produktionsstandardisierung:

- Lexikografisch sortierte Objektfelder; keine Leerzeichen; `,` und `:` als Trenner.
- Modelle werden mit sämtlichen definierten Feldern einschließlich Defaults und
  `null` serialisiert. Die Eingabe muss bytegleich zu dieser Ausgabe sein.
- Nur feste ASCII-Tokens, kleingeschriebene Hexwerte, begrenzte Integer,
  Arrays und geschlossene Objekte; keine frei eingegebenen Texte, Floats oder NaN.
- Zähler und Zeitwerte liegen zwischen 0 und `2**53-1`; Python-`bool` wird nicht
  als Integer akzeptiert. Reihenfolgen von Geräten und Rechten sind festgelegt.
- Höchstens 65.536 Byte pro eingelesenem Objekt; maximal 64 Geräte inklusive
  Widerrufseinträge; doppelte Felder, IDs, Rechte, zusätzliche Felder und
  nichtkanonische Darstellungen werden abgelehnt.
- Auch Python-Modellobjekte werden strikt erneut validiert. Die Validierung
  findet **vor** der Serialisierung statt, damit Serializer keine unzulässigen
  Werte normalisieren, etwa ein über `model_copy` eingeschleustes `True` zu `1`.

Jede Signatur ist `Ed25519(domain || canonical(object))`, jeder Hash
`SHA256(domain || canonical(object))`; beim Identitäts-Hash wird das feste
32-Byte-Schlüsselencoding verwendet. Alle Domänen beginnen mit
`KRYPTA/IDENTITY/PROTOTYPE/V1/` und enden mit einem Nullbyte:

| Zweck | Domänensuffix |
|---|---|
| Identitätskennung | `IDENTITY-ID` |
| Zustands-Hash | `STATE-HASH` |
| Action-Hash einschließlich Genesis | `ACTION-HASH` |
| Autor einer Änderung | `TRANSITION-AUTHOR` |
| Besitznachweis eines neuen Geräts | `ADD-DEVICE-POSSESSION` |
| Besitznachweis eines bestehenden Geräts bei Manageränderung | `EXISTING-DEVICE-POSSESSION` |
| Genesis-Root-Freigabe | `GENESIS-ROOT` |
| Genesis-Gerätefreigabe | `GENESIS-DEVICE` |

Die signierte Action bindet Version, Suite, Policyversion, Identitätskennung,
zufällige Action-ID, nächste Generation, Vorgänger-Hash, Autorrolle und
Autor-Gerätekennung, Ziel, Rechte und Gültigkeitsfenster. Die Signatur-Hülle
enthält Autor-Signatur und gegebenenfalls eine gesonderte Besitzsignatur.
Eine vom Absender angegebene Autor-Public-Key-Behauptung existiert nicht:
Prüfschlüssel stammen ausschließlich aus dem bereits bekannten Vorgänger.

Der Zustand enthält Root, Identität, Generation, Vorgänger-Hash, Action-ID und
Action-Hash sowie sortierte Geräte und den Status. Die signierte Action und
ihre Signaturen liegen in der Historie; ein nackter Zustands-Hash genügt nicht
als Autorisierungsbeweis. Signaturbytes selbst gehören nicht zum Zustands-Hash.

## Zustandsübergänge und Autorisierung

| Übergang | Zulässiger Autor | Zusätzliche Bedingung |
|---|---|---|
| Initialisieren, Generation 0 | Lokal neu erzeugter Root und erstes Gerät | Beide signieren Genesis; keine alten Schlüssel importierbar |
| Neues Gerät aufnehmen | Aktives Gerät mit `device_management` | Neues Gerät ausschließlich `messaging`; eigene Besitzsignatur |
| Messaging-Recht ändern | Aktiver Device Manager | Ziel bereits aktiv; keine implizite Änderung anderer Rollen |
| Managerrolle hinzufügen oder entfernen | Root | Ziel bereits aktiv; dessen Besitzsignatur über exakt diese neue Action |
| Gerät widerrufen | Aktiver Device Manager | Ziel aktiv; Widerruf irreversibel |
| Letztes aktives Gerät widerrufen | Aktiver Device Manager | Identität wird terminal `retired` |
| Recovery, Root-Rotation, Schlüsselersatz, Historien-/Backup-Import | Niemand | Kein unterstützter Übergang |

Das initiale Gerät erhält `device_management` und `messaging` ausdrücklich.
Keine der Rollen schließt die andere ein. `identity_recovery` ist als
Berechtigungsname bekannt, aber im Profil `NO_RECOVERY` niemals zulässig.
Ein Manager kann keine Managerrechte vergeben. Der Root kann kein neues
Gerät anlegen und kein widerrufenes Gerät reaktivieren. Nach vollständiger
Widerrufung blockiert der terminale Zustand auch Root-Aktionen.

`initialize()` erzeugt immer einen frischen Root und eine neue Identitätskennung;
ein zweiter Aufruf derselben Instanz scheitert. Es gibt keine API zum Import
alter Root-Privatschlüssel oder alter Zustände. Tatsächlicher Geräteverlust
ist aus öffentlichen Daten nicht feststellbar: Die Anwendung darf bei Verlust
aller Geräte keine vorhandene Identität nachbilden. Ein Besitznachweis belegt
nutzbaren Schlüsselbesitz, keine vertrauenswürdige Hardware oder Anwesenheit
eines bestimmten Menschen. Gestohlene noch aktive Schlüssel bleiben ein Risiko.

### Prüfung und atomare Übernahme

1. Strenge Modell- und Byteprüfung; bekannte Versionen und passende Identität.
2. Action-ID noch nicht verwendet; Vorgänger in authentifizierter lokaler Historie.
3. Generation genau `parent.generation + 1`; Autor-Signatur mit gepinntem Schlüssel.
4. Gesonderte Rollenprüfung; erforderliche Besitzsignatur mit eigener Domäne.
5. Kandidatenzustand vollständig berechnen und seine Invarianten prüfen.
6. Bekannten Vorgänger mit aktuellem Head vergleichen; authentische konkurrierende
   Nachfolger sind ein Fork, keine automatische Zusammenführung.
7. Signiertes Autorisierungsfenster prüfen; externe Aktualitätsbestätigung prüfen.
8. Zustand während der externen Prüfung unverändert und Action weiterhin gültig;
   erneute mutierende Aufrufe aus dem Prüfer sind gesperrt.
9. Unter `RLock` eine einzige neue Snapshot-Referenz setzen: Historie, Zustand
   und Entfernung ausstehender Challenges werden zusammen übernommen.

`validate_transition()` führt ausschließlich lokale Prüfungen aus und gibt
einen Kandidaten zurück. Es aktiviert kein Gerät. `check_known_state()` kann
bekannte Rollbacks erkennen; ein fremder nackter Zustand wird weder importiert
noch als authentischer Fork ausgegeben. `apply()` ist die einzige
Übernahmefunktion. Ablehnungen lassen Geräte, Generation und Historie exakt
unverändert; fehlgeschlagene Nachweise verbrauchen keine Action-ID.

Ein authentischer Fork wird erst nach Signatur- und Autorisierungsprüfung gegen
den historischen Vorgänger gemeldet. Damit kann eine bloß kaputte Signatur
keinen authentischen Fork vortäuschen. Ein verwendeter Action-Bezeichner wird
als Replay abgelehnt. Unbekannter Vorgänger oder Versionssprung bedeutet
Konflikt; fehlende Historie wird nicht automatisch übersprungen.

Ein `ForkError` verlangt eine Sperre/Quarantäne durch die spätere Anwendung.
Diese State Machine implementiert keine Kontakt- oder Versandzustände und
speichert deshalb auch keine automatische Versandquarantäne. Sie löst Forks
nicht auf. Der Host darf den Fehler nicht als harmlosen Retry ignorieren.

## Aktualität: drei ausdrücklich getrennte Aussagen

**Lokale Prüfung:** Signatur, Rollen, Hashbindung und Frist sind anhand des
bekannten Zustands korrekt. Das bedeutet nicht, dass kein Widerruf fehlt.

**Lokale Konsistenz:** Die Änderung verlängert genau die bekannte Historie.
Das bedeutet nicht, dass ein Relay anderen Clients keinen Fork zeigt.

**Externe Bestätigung:** Ein explizit konfigurierter `FreshnessVerifier` muss
externen Beleg authentifizieren und daraus `ExternalConfirmation` liefern.
Der Core prüft Bindung an Identität, exakten **Kandidatenzustand**, Generation
und zufällige Anfrage-Nonce. Ein `verified=True` oder Server-Timestamp ist
kein zulässiger Ersatz. Die Schnittstelle enthält weder Netzwerkcode noch
einen produktiven Prüfer oder Transparenzdienst.

Die Erstellung einer Anfrage prüft zunächst den lokalen Kandidaten und speichert
eine monotone Startzeit. Default-Fristen: Challenge maximal 30 Sekunden,
bestätigte Gültigkeitsdauer maximal 30 Sekunden. Werte sind konfigurierbar
von 1 bis 300 Sekunden. Ein Prüfer darf eine kürzere Frist verlangen.
Bei Erreichen der Frist, negativer verstrichener Zeit oder nicht endlicher
Uhrzeit wird abgelehnt. Alle Übernahmen nach Genesis verlangen diesen Nachweis;
es gibt keinen Schalter für lokale Fail-Open-Übernahme.

Die monotone Uhr begrenzt nur die Dauer einer begonnenen Anfrage. Die Wanduhr
prüft ausschließlich das signierte Action-Fenster `[issued_at, expires_at)`
mit maximal 300 Sekunden Länge. **Keine dieser Uhren beweist Zustandsfrische.**
Die Fristen laufen seit Challenge-Beginn, nicht seit Empfang eines Belegs.
Ein Prüfer muss Nonce-Antworten, vertrauenswürdige aktuelle Heads und die
Bedeutung ihrer Gültigkeitsdauer selbst korrekt spezifizieren. Er ist eine
zusätzliche Vertrauensgrenze; ein lügender/kompromittierter Prüfer kann dieses
Profil täuschen. Ein Beleg über einen Head zum Antwortzeitpunkt ist außerdem
keine globale atomare Zusage gegen gleichzeitige Änderungen während seiner
Gültigkeit. Konsens, Widerrufslatenz und eine belastbare Lease-Semantik fehlen.

Standardmäßig fehlt dieser Prüfer: initialisieren und lokal prüfen ist möglich,
**jede spätere Übernahme bleibt gesperrt**. Tests benutzen einen Ed25519-signierenden
Test-Witness mit gepinntem Testschlüssel. Das simuliert die Adapterintegration,
keinen realen Aktualitäts- oder Nicht-Äquivokationsnachweis.

## Offline- und Konfliktreaktionen

| Simulation | Nachvollziehbare Reaktion |
|---|---|
| Altes Gerät kennt eine neue Aufnahme nicht | Lokale Prüfung kann bestehen; ohne passenden externen Beleg keine Übernahme |
| Server hält einen Widerruf zurück | Test-Witness verweigert den veralteten Kandidaten; Fail Closed |
| Widerruf trifft verspätet ein | Vollständiger signierter nächster Übergang nötig; danach alte Autorrolle abgewiesen |
| Bekanntes älteres Verzeichnis wird angeboten | `RollbackError`, keine Zustandsänderung |
| Zwei autorisierte Änderungen desselben Vorgängers | Höchstens eine lokal übernommen; andere als authentischer Fork abgewiesen |
| Zwei signierte widersprüchliche Sichten | Erkennung erst, wenn beide lokal sichtbar sind; kein globales Erkennungsversprechen |
| Wiederverbindung nach einer Woche | Abgelaufene Action abweisen; keine Historienlücke stillschweigend übergehen |
| Fehlender, falscher oder abgelaufener Nachweis | Übernahme sperren; alter Zustand bleibt erhalten |

Die Offline-Kopien in Tests stammen aus einem bereits vertrauenswürdigen,
unveränderlichen In-Memory-Snapshot. Es gibt dafür keine öffentliche Import-API.
Archivierte abgelaufene Änderungen lassen sich in diesem engen Prototyp nicht
zum langfristigen Catch-up verwenden. Sichere historische Prüfung, gepinnte
Checkpoints, Persistenz und Wiederanbindung bestehender Geräte brauchen eine
separate Spezifikation. Ein nackter aktueller Head darf die Lücke nicht ersetzen.

## Nutzung und Prüfungen

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy src
```

Bei einem schreibgeschützten Standardcache kann `UV_CACHE_DIR` auf ein
beschreibbares Verzeichnis gesetzt werden. `uv.lock` ist für reproduzierbare
Auflösung vorgesehen, wurde wegen der dokumentierten Downloadblockade noch
nicht erzeugt. Die alte `requirements.txt` gehört zum ursprünglichen
App-Konzept und wird für diesen Prototyp nicht verwendet.

Minimaler Einstieg ohne externen Prüfer:

```python
from secure_messenger.identity import IdentityStateMachine

machine = IdentityStateMachine()
keys = machine.initialize()  # Geheimnisse separat geschützt halten!
assert machine.state.generation == 0
assert machine.state.recovery_policy == "NO_RECOVERY"
# Spätere apply()-Aufrufe bleiben ohne externen Prüfer und Beleg gesperrt.
```

Die tatsächlichen Testresultate und noch offenen Freigabehürden stehen im
[Implementierungsreview](../security/identity-implementation-review.md).

## Grenzen vor jeder Produktintegration

Kein vollständiges sicheres Pairing: Die Action-ID und Besitzsignatur binden
den einmaligen Vorgang und die angegebenen Schlüssel, ersetzen jedoch keinen
analysierten gegenseitigen QR-/MITM-Handshake oder bewusste Nutzerbestätigung.
Kein sicherer Messaging-Empfängerausschluss oder Group-Rekey nach Widerruf.
Kein Vertraulichkeits-, Forward-Secrecy-, Post-Compromise-, Quanten- oder
Anonymitätsnachweis. Die Identität und Gerätehistorie sind für berechtigte
Empfänger korrelierbar; Zugriff und Verteilung sind noch nicht spezifiziert.

Maximal 64 Geräte inklusive Tombstones, 128 ausstehende Challenges;
Historie wächst unbeschränkt und Prüfungen durchsuchen sie linear. Es gibt
noch keine dauerhafte Ressourcen-, Rate-Limit- oder DoS-Strategie und keine
Bereinigung ausstehender Anfragen. Der Host und der externe Prüfer gehören
zum vertrauenswürdigen Prozess. Python-Frozen-Modelle schützen nicht gegen
Codeausführung oder direkten Eingriff in private Attribute. Auch native
Schlüsselobjekte garantieren keine sichere Löschung aller Heap-Kopien.

Technische Primärquellen: [Ed25519-API von cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/),
[libsodium-Punktvalidierung](https://doc.libsodium.org/advanced/point-arithmetic),
[PyNaCl-Changelog](https://github.com/pyca/pynacl/blob/main/CHANGELOG.rst),
[Pydantic Strict Mode](https://pydantic.dev/docs/validation/latest/concepts/strict_mode/),
[Python-JSON-API](https://docs.python.org/3/library/json.html).
