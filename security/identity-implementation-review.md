# Identity State Machine: internes Implementierungsreview

Datum: 8. Oktober 2026. **Entwicklungsprototyp; Selbstprüfung des implementierenden
Entwicklers, kein unabhängiges Audit und kein Sicherheitszertifikat.**

## Gelesene Grundlagen und Vorrang

Vollständig gelesen: `threat-model.md`, `identity-protocol.md`,
`identity-authority-policy.md`, `review-2026-10-08.md`. Diese vier Dateien sowie
ihre Referenzen und Archive bleiben unverändert. Die ausdrückliche aktuelle
Aufgabe autorisiert einen **isolierten Python-Prototyp** trotz offener
Freigabekriterien; sie entscheidet diese Kriterien nicht für ein Produkt.

Verbindlich sind Python 3.13+, native Kryptoprimitive, serverunabhängige
Identitäten, eigene Geräteschlüssel, explizite Rollen, signierte Zustandsfolgen,
lokale Konflikterkennung, `NO_RECOVERY`, Fail Closed und offene Nicht-Garantien.
Nicht jeder MUSS-Punkt des gesamten Messenger-Bedrohungsmodells liegt im
Geltungsbereich dieses isolierten Pakets.

## Widersprüche, offene Entscheidungen und unvollständige Mechanismen

| Befund | Grundlage | Behandlung im Prototyp |
|---|---|---|
| Alte Recovery-Vorschläge widersprechen `NO_RECOVERY` | Review SR-01/02; Policy §§ 5, 8 | Ausschließlich aktive Projektfassungen gelten; keine Recovery-/Import-API |
| Frühere Rust-API widerspricht gewählter Python-Logik | Review SR-03; Policy § 9 | Python 3.13+, Pydantic v2, native `cryptography` |
| Archiv verlangt zusätzliche Root-Freigabe für jede Aufnahme | Review SR-04 | Nicht aktiv; expliziter Manager kann ausschließlich Messaging-Geräte aufnehmen |
| Identitätsprotokoll nennt verbleibendes autorisiertes Gerät für Widerruf; Policy präzisiert Managerrolle | Identity § 8; Policy § 5 | Spezifische Managerregel wird angewendet, Messaging allein reicht nicht |
| Signierte Hashkette beweist weder Aktualität noch globale Konsistenz | Review SR-05, SEC-I05, D-06 | Lokale Erkennung; externe Schnittstelle, standardmäßig gesperrte Übernahmen |
| Root-/Messaging-Schlüsselbindung und Root-Rotation sind offen | Review SR-06 | Keine Rotation; X25519 nur separater unbenutzter Platzhalter |
| Pairing-Handshake, gegenseitige Bestätigung und Vergleichswerte fehlen | Policy § 6; Identity § 7 | Besitzsignatur bindet neue Action; vollständiger Handshake/UX bleibt fehlend |
| Veröffentlicht bedeutet nicht aktiv | Review SR-08 | Keine Transportfunktion; nur vollständige Prüfung kann übernehmen |
| Kompromittierter aktiver Manager kann gültige Aufnahme signieren | Review SR-09 | Rechte strikt begrenzt; keine Behauptung, Rollen lösen Endpoint-Kompromittierung |
| Entfernen von Managerrechten, Entzug von Messaging und terminaler Zustand nicht vollständig definiert | Policy § 5; Identity § 3 | Explizite konservative Prototypregeln unten; keine stille Produktionsfestlegung |
| Sichere langfristige Offline-Synchronisation und Historienpersistenz fehlen | Policy §§ 4, 7 | Signierte nächste Änderung nur innerhalb ihrer Frist; kein Import/Skip |
| Gültigkeitsdauer externer Nachweise, Witness-Vertrauen, Datenschutz und Quorum fehlen | D-06; Policy § 11 | Adaptervertrag ausdrücklich als zusätzliches Vertrauen dokumentiert; kein Produktmechanismus |

Weitere Architekturentscheidungen D-01 bis D-05 und D-07 bis D-10 aus dem
Bedrohungsmodell betreffen Relays, Messaging-/Gruppenprotokoll, Anonymisierung,
Aufbewahrung, Plattform, Backups, Push und Release-Prozess. Sie bleiben offen.
Alle Freigabekriterien aus Identity § 13 und Gates G0 bis G3 gelten weiterhin;
dieses Paket erfüllt keinen vollständigen Messenger-Freigabegate.

## Ausdrückliche Annahmen und Prototypentscheidungen

1. Vertrauenswürdiger lokaler Prozess, Betriebssystem-Zufallsquelle,
   Bibliotheksimplementierungen und sichere Übergabe privater Schlüssel.
   Kein Schutz gegen willkürliche Codeausführung im Prozess.
2. Ed25519/SHA-256 als festes experimentelles Identitätsprofil.
   Öffentliche Ed25519-Punkte werden zusätzlich mit PyNaCl ab 1.6.2 und
   gebündelter gepatchter libsodium validiert. Kein Post-Quanten-Schutz;
   keine selbst geschriebene Kryptoprimitive oder Punktarithmetik.
3. Ein festes kanonisches ASCII-JSON-Subset mit geschlossenen Pydantic-Schemata.
   Das erfüllt eindeutige Signaturbytes im Prototyp, legt keinen finalen
   Binärstandard fest und behauptet keine RFC-8785-Kompatibilität.
4. Initiales Gerät ausdrücklich mit Messaging- und Managerrolle; Aufnahme
   danach ausschließlich Messaging. Managerrollenänderung in **beide
   Richtungen** erfordert Root plus vorhandenen Zielgeräte-Besitznachweis.
   Messaging-Rechte darf ein Manager unabhängig ändern. No-op wird abgelehnt.
   Die zusätzliche Zielzustimmung bei Managerentzug ist eine konservative
   Einschränkung: ohne Zielschlüssel bleibt der Widerruf durch einen Manager.
5. `retired` nach Widerruf des letzten aktiven Geräts ist terminal. Verlust
   ohne Widerruf kann nicht festgestellt werden. Root allein kann keine
   Aufnahme durchführen; frischer Besitz eines aktiven Zielschlüssels ist
   bei Managervergabe Pflicht, aber kein menschlicher Verfügbarkeitsbeweis.
6. Genesis nur lokal mit neu generierten Schlüsseln; keine Restore-/Import-API.
   Neue Identität widerruft die alte nicht und verifiziert keine Kontakte.
7. Signierte Actions haben maximal 300 Sekunden Autorisierungsfenster.
   Ein vertrauenswürdiger lokaler Wallclock-Wert ist nur dessen Deadline-Prüfung.
   Manipulierte Uhren und nicht bekannte Widerrufe werden dadurch nicht gelöst.
8. Jede Übernahme nach Genesis verlangt einen externen Beleg für den genauen
   Kandidaten-Head und eine zuvor lokal erzeugte Nonce. Der konfigurierte
   Prüfer ist vertrauenswürdig, authentifiziert den Beleg und garantiert die
   von ihm behauptete Bedeutung. Es existiert **kein produktiver Prüfer**.
   Fristen ab Challenge-Beginn beschränken nur die lokale Antwortdauer.
   Globale Wahrheit, Konsens und race-freie Widerrufsleases folgen daraus nicht.
9. Reine lokale Validierung darf ohne Aktualitätsbeleg einen Kandidaten
   berechnen, übernimmt ihn aber nie. Forks werden nur anhand tatsächlich
   beobachteter authentischer Alternativen erkannt. Anwendungsquarantäne nach
   Fork und Kontaktneuverifikation bleiben außerhalb dieses Kerns.
10. In-Memory-Historie ist vertrauenswürdig und unveränderlich. Langfristiges
    Catch-up abgelaufener Änderungen, sichere Checkpoints, Crash-Recovery,
    Schlüsselablage und geräteübergreifender Austausch fehlen ausdrücklich.

## Anforderungszuordnung

| Anforderung | Umsetzung / Prüfung | Verbleibende Grenze |
|---|---|---|
| SEC-C04, Policy § 9 | Native Ed25519/X25519, Standard-SHA-256 | Neue Protokollkomposition ungeprüft; keine Messenger-Krypto |
| SEC-C05, Policy § 4 | Versions-/Suiteprüfung, getrennte Domänen, kanonische Bytes | Sichere Migration noch nicht implementiert |
| SEC-I01 | Lokal frische Root-/Geräteschlüssel und zufällige IDs | Keine menschliche Identitätsprüfung |
| SEC-I03, ID-T01/05/06 | Manager-Autorisierung, gebundene Besitzsignatur, Frist, einmalige Action-ID | Vollständiges Pairing und bewusste UI-Bestätigung fehlen |
| SEC-I04 | Separate Geräteschlüssel, Generationen, irreversible Tombstones | Ratchet/Session-/Gruppen-Rekey und Empfängerausschluss fehlen |
| SEC-I05, ID-T02/03 | Lokale History, Replay/Rollback/Fork/VersionConflict; externe Fail-Closed-Grenze | Keine globale Nicht-Äquivokation oder reale Freshness-Garantie |
| SEC-I07, ID-T09/10 | Keine Recovery-/Root-Import-/Backup-/Genesis-Replay-API; terminaler Zustand | Gestohlene aktive Schlüssel, Kontakt-Neuverifikation außerhalb |
| Policy §§ 3–5 | Unabhängige Rechte; Signaturprüfung und Autorisierung getrennt | Root-Lifecycle und Quorum ungeprüft |
| SEC-I02/06, SEC-E03 | Keine automatische Kontakt-/Serverautorität im Kern | Kontaktverwaltung, Einladungen und Sicherheits-UX nicht implementiert |
| SEC-E01/04/05, ID-T07/11 | Keine private Schlüsselserialisierung oder Datenspeicherung | Kein Keystore, lokaler Datenschutz, Backup oder Endpoint-Härtung |
| SEC-C01/02/03/06/07, SEC-G01–05 | Außerhalb des isolierten Kerns | Keine Nachrichten-/Gruppen-/PQ-Garantien |
| SEC-M01–07, SEC-S01–06, ID-T12–14 | Kein Netzwerk, Relay oder Directory implementiert | Keine Anonymitäts-, Zustell-, Release-/Supply-Chain-Garantie |

ID-T04 erfordert einen realen Pairing-/MITM-Test und bleibt offen; ID-T08
erfordert Quarantäne und Endpoint-Integration. Alle 14 Gesamtszenarien sind
damit eingeordnet, **nicht** als vollständig implementiert oder bestanden erklärt.

## Interne Prüfung und Testergebnisse

Die Tests prüfen echte native Ed25519-Signaturen, strenge Wire-Eingaben,
Rechtebegrenzung, Root-only-Umgehungen, frischen Zielbesitz, irreversible
Widerrufe, unbekannte Signierer, Fristen, externe Belegbindung und parallele
Änderungen. Ablehnungen vergleichen die ursprünglichen State-/History-Objekte
auf Identität; fehlgeschlagene Prüfungen dürfen keinen Teilzustand übernehmen.

Offline-Simulationen behandeln alte Geräte, zurückgehaltene Updates, verspätete
Widerrufe, Wiederverbindung nach einer Woche und widersprüchliche signierte
Änderungen. Ein Test-Witness benutzt ausschließlich Testschlüssel und eigene
Testdomänen. Er ist keine Implementierung eines Transparenzdienstes.

Hypothesis-Tests sind implementiert: Signaturbit-Manipulation, nachträgliche
Rechteänderung, beliebige Wire-Bytes und eine zustandsbasierte Lifecycle-Prüfung
mit unabhängigem Mitgliedschafts-/Rollenmodell.

Bei einer zusätzlichen nativen Kryptoprüfung akzeptierte der ursprüngliche
Verifikationspfad für degenerierte Public-Key-Encodings (`00…00`, `01…00`)
konstruierbare Signaturen. Die ursprünglichen 69 Tests deckten dies nicht ab.
Deshalb wird vor jeder Verifikation eine native Punktvalidierung ergänzt;
PyNaCl ist eine begründete zusätzliche Abhängigkeit über den verlangten Stack
hinaus. Regressionstests prüfen direkte Verifikation und Gerätebesitznachweis.
Kein selbst entwickelter Blacklist- oder Punktarithmetikalgorithmus wird benutzt.
Die Herkunft der eingebundenen libsodium-Builds muss vor Release separat
kontrolliert werden; die PyNaCl-Version allein prüft keinen lokalen Systembuild.
Die [PyNaCl-Änderungshistorie](https://github.com/pyca/pynacl/blob/main/CHANGELOG.rst)
beschreibt die Aktualisierung des gebündelten libsodium in 1.6.2; dessen
[Punktvalidierungs-API](https://doc.libsodium.org/advanced/point-arithmetic)
begründet die zusätzliche Eingangsprüfung.

### Aktualisierte tatsächliche Prüfläufe: adversariales Review am 2026-10-08

Diese Ergebnisse ersetzen die früheren Blockade-/69-Test-Angaben. Grundlage ist
GitHub PR #1, Head `7951cf44a2c278b39e695018fea429e785e21416`, zuzüglich der im
[Security Review](identity-security-review-2026-10-08.md) dokumentierten Korrekturen.
CPython 3.13.15, uv 0.12.5, `UV_CACHE_DIR=/tmp/krypta-identity-uv-cache`.
Der inzwischen vollständige vorhandene Benutzer-Cache wurde in den beschreibbaren
Cache kopiert. Tests laufen in einer frisch angelegten Review-venv mit dem
Review-Quellpfad. Wegen blockiertem PyPI-DNS wird lokal `UV_OFFLINE=true` gesetzt.
Browser-/GitHub-Abfragen für aktuelle Advisories waren hingegen möglich.

| Prüfung | Tatsächliches Ergebnis |
|---|---|
| Ausgangsstand: `uv run pytest -q` | 76 bestanden |
| Drei neue Fehlerreproduktionen vor Korrektur | Alle drei fehlgeschlagen: Fristlücke, Uhr-Reentrancy, volle abgelaufene Challenge-Liste |
| `uv sync --locked` | Erfolgreich aus vollständigem Cache, einschließlich lokalem PEP-517-Build |
| `uv run pytest -v` | 94 bestanden; keine übersprungenen Tests |
| `uv run ruff check .` | Erfolgreich, keine Befunde |
| `uv run mypy src` | Erfolgreich, 13 Quelldateien |
| `uv lock --check` | Erfolgreich; 23 aufgelöste Packages einschließlich Projekt |
| `git diff --check` | Erfolgreich |
| Ungecachter Netzwerk-`uv sync --locked` | PyPI-DNS blockiert; keine erfolgreiche Online-Installation behauptet |

Hypothesis läuft mit `derandomize=True`, ohne lokale Beispieldatenbank;
sechs Property-/Stateful-Tests sind enthalten. Ablehnungen prüfen jetzt die
Identität des **gesamten Snapshots**, einschließlich ausstehender Challenges.
Zusätzliche Tests betreffen Commit-Deadline, Allokationsfehler, rekursive
Uhr-/Prüferaufrufe, falsche Adapterantworttypen, alle Signaturdomänenpaare,
Ed25519-Skalarmalleability und native Punktvalidierungsvektoren.
Bekannte Grenzen bei konkurrierenden externen Heads und kompromittierten
Managern sind als ausführbare Grenzen dokumentiert, nicht als behoben erklärt.

`uv.lock` wird erstmals im Review-Branch versioniert. Native Kryptografie darf
bei uv-Installation nur aus Wheels kommen; Build-Backend und seine Abhängigkeiten
sind zusätzlich gepinnt. Das ist keine vollständige Herkunftsattestierung.

### Git-/PR-Stand und CI

Das Repository existiert inzwischen: `p3t3r67x0/kryptachat`, PR #1 als Draft
gegen `main`. Dieses Review arbeitet auf
`security/identity-state-machine-review` im beschreibbaren Checkout
`/tmp/krypta-identity-review`, mit neuem Draft-PR gegen
`feat/identity-state-machine`. Änderungen werden in den Workspace gespiegelt;
sein geschütztes `.git` wird nicht verändert. Kein automatischer Merge.

`.github/workflows/identity-security.yml` führt alle fünf Prüfungen aus,
mit überprüften vollständigen Action-SHAs, `contents: read`, ohne gespeicherte
Checkout-Credentials, Secrets, Cache oder privilegierte Events. Der Remote-Lauf
ist vor Veröffentlichung nicht ausgeführt; sein tatsächlicher Status wird am
Draft-PR und im Abschlussbericht gemeldet. Lokale Ergebnisse sind keine
behaupteten GitHub-CI-Ergebnisse.

## Offene Sicherheitsrisiken und nächste Prüfungen

- Externe aktuelle Heads und fork-resistente Bestätigung mit definierter
  Widerrufslatenz/Lease-Semantik spezifizieren; Witness-Kompromittierung,
  Ausfall, Linkability und Quorum analysieren. Kein Default-Bypass hinzufügen.
- Pairing, bewusste Nutzerfreigabe und frische Verfügbarkeit vorhandener
  Geräte an ein geprüftes Verfahren binden; Signatur allein genügt nicht.
- Sichere Root-Ablage und Rotation, Schlüsselkompromittierung, Manager-Quorum
  und dauerhafte Quarantäne vor Produktintegration festlegen.
- History-Persistenz und autorisierte alte Änderungen von aktueller Freigabe
  unterscheiden; gepinnte Checkpoints ohne Recovery-Umgehung entwickeln.
- Messaging-Protokollbindung, Post-Compromise-Schutz, Empfängerausschluss,
  Kontaktverifikation, Gruppen-Epochen und plattformnative Keystores fehlen.
- Ressourcen- und DoS-Strategie fehlt: 64 Geräte inklusive Tombstones,
  128 offene Challenges (abgelaufene werden bei neuer Anfrage bereinigt),
  unbeschränkt wachsende In-Memory-Historie.
- Abhängigkeitspinning und lokale Tests sind keine Supply-Chain-Prüfung,
  keine reproduzierbaren signierten Releases und kein unabhängiges Audit.

Produktive Sicherheitsbehauptungen und Nutzung als Schutzlösung für
gefährdete Menschen bleiben ausdrücklich ausgeschlossen.
