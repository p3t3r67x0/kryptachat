# KryptaChat – adversariales Identity Security Review

**Datum:** 2026-10-08. **Status:** internes Review mit reproduzierten Befunden und
Regressionstests; kein unabhängiges Audit. Die Implementierung bleibt ein
**nicht produktionsreifer Entwicklungsprototyp**, keine Schutzlösung für
Journalisten, Aktivisten oder andere gefährdete Menschen.

## Umfang, belegter Ausgangsstand und Methode

Geprüft wurde [PR #1](https://github.com/p3t3r67x0/kryptachat/pull/1),
Head `7951cf44a2c278b39e695018fea429e785e21416`, gegen
`main` / `7af83603aa7288e4191395fc43ad223b9dac45f3`. GitHub-Compare und lokaler
Drei-Punkt-Diff stimmen überein: drei Commits, 38 neue Dateien, 4.133 neue
Zeilen; weder Lockfile noch Workflow im PR. Lokales `uv.lock` war vorhanden,
aber unversioniert. `main` enthält nur den initialen Repository-Stand.

Vollständig gelesen wurden `security/threat-model.md`, `identity-protocol.md`,
`identity-authority-policy.md`, `review-2026-10-08.md`,
`identity-implementation-review.md`, `docs/identity-state-machine.md`, alle
Dateien unter `src/secure_messenger/identity/` und `tests/`. Dazu wurden
Package-/Build-Konfiguration, README, Legacy-Abhängigkeiten und Lock-Metadaten
untersucht. Methode: manuelle Datenfluss-/Autorisierungsprüfung, echte native
Signaturen, gezielte Fehlerreproduktionen, Offline-/Konkurrenzsimulationen,
Property-/Stateful-Tests und aktuelle öffentliche Sicherheitsquellen.

Der Reviewer hat den ursprünglichen Prototyp mitentwickelt. Diese Selbstprüfung
ersetzt deshalb ausdrücklich keine unabhängige Prüfung. Betrachtet werden
untrusted Wire-Daten und Relays, kompromittierte autorisierte Manager und
fehlerhafte lokale Adapter. Willkürliche Codeausführung, direkte Änderung
privater Attribute und ein bösartiges Betriebssystem sind außerhalb der
Garantien. Lokale Uhren und der konfigurierte externe Verifier sind zusätzliche
Vertrauensannahmen. Die Tests instrumentieren diese Schnittstellen absichtlich.

**Ergebnis:** Keine neue CRITICAL-/HIGH-Implementierungslücke nachgewiesen.
Drei MEDIUM-Implementierungsfehler und zwei LOW-Integrations-/Exception-Safety-Fehler wurden reproduziert
und behoben. Fehlendes Dependency-Pinning/CI wurde ergänzt. Bekannte HIGH-
Architekturrisiken werden unten gesondert als weiterhin offene Release-Blocker
geführt. Aus fehlenden weiteren Befunden folgt keine Vollständigkeitsgarantie.

Datei-/Zeilenangaben bei Befunden beziehen sich auf den oben genannten PR-Head,
sofern nicht ausdrücklich „Review-Stand“ angegeben. Fix-Zeilen beziehen sich
auf diesen Review-Branch. Die vier normativen Ausgangsdokumente bleiben
bytegleich; Architekturentscheidungen werden nicht durch dieses Review geändert.

## CRITICAL

Keine bestätigte Lücke dieser Kategorie innerhalb des geprüften Umfangs.
Das ist kein Ausschluss unbekannter kritischer Lücken.

## HIGH

### KISR-H01 – Beobachteter Head ist keine globale Lease

**Art/Status:** bestätigte, bereits dokumentierte Architekturgrenze; offen.
Keine neu entdeckte Verletzung einer zugesagten globalen Garantie.

- **Dateien/Zeilen:** `freshness.py:13–20, 43–66`,
  `state_machine.py:238–247`, `tests/helpers.py:32–58`;
  `docs/identity-state-machine.md`, Abschnitt „Aktualität“.
- **Technik:** Ein authentischer Nonce-Nachweis bindet Identität, Generation
  und Kandidatenhash, attestiert aber nur die behauptete Beobachtung. Er
  serialisiert keine konkurrierenden Änderungen. Der Test-Witness prüft seinen
  Head bei Ausstellung, nicht atomar gegen alle späteren Commits. Eine echte
  Transparency-/Konsens-/Widerrufslease existiert nicht.
- **Voraussetzungen:** Zwei berechtigte Änderungen desselben Vorgängers,
  getrennte Offline-Snapshots; ein Relay verzögert den älteren, noch lokal
  gültigen Nachweis. Alternativ ein fehlerhafter oder kompromittierter Verifier.
- **Auswirkung:** Beide Clients können verschiedene Generation-1-Heads
  übernehmen. Ein bereits attestierter, anschließend überholter Gerätezustand
  kann lokal weiter akzeptiert werden. Ein zurückgehaltener Widerruf ist durch
  die Hashkette alleine nicht auffindbar. Keine Messaging-Funktion vorhanden,
  daher keine hier nachgewiesene Offenlegung von Nachrichten.
- **Reproduktion:** `test_previously_confirmed_fork_is_still_accepted_on_an_unaware_offline_copy`:
  erst A attestieren, dann B attestieren/übernehmen, anschließend A offline
  übernehmen. Beide Heads sind gültig und verschieden; nach Sichtbarkeit von
  B erkennt der Offline-Client den authentischen Fork.
- **Empfehlung:** Vor Integration Konsistenz-/Witness-Quorum, atomare
  Autorisierung oder belastbare Lease-Semantik, Widerrufslatenz, Datenschutz
  und Fork-Quarantäne ausdrücklich entscheiden und extern prüfen. Kein lokaler
  Timestamp- oder `verified=True`-Ersatz.
- **Regression:** Genannter Test dokumentiert heute die Grenze. Ein späteres
  spezifiziertes Konsensverfahren muss zusätzlich nachweisen, dass nicht beide
  konkurrierenden Änderungen globale Aktivierungsrechte erhalten. Nicht als
  „behoben“ markieren, solange nur lokale Sperren existieren.

### KISR-H02 – Kompromittierter Manager besitzt breite Aufnahme-/Widerrufsmacht

**Art/Status:** bestätigtes, bewusst akzeptiertes Policy-Risiko (SR-09); offen.
Keine Privilege Escalation außerhalb seiner expliziten Rechte.

- **Dateien/Zeilen:** `authority.py:24–44, 63–65`,
  `state_machine.py:103–135`, Policy §§ 5, 7; Review SR-09.
- **Technik:** Ein Manager darf allein Messaging-Geräte aufnehmen und jedes
  aktive Gerät widerrufen, auch andere Manager. Initiale Messaging- und
  Managerrechte sind ausdrücklich gemeinsam vergeben. Separate Root-/Session-
  Schlüssel begrenzen diese Management-Rechte nicht nachträglich.
- **Voraussetzungen:** Nutzbarer aktiver Manager-Privatschlüssel und erforderliche
  externe Bestätigung für den Kandidaten. Bei Standardkonfiguration ohne
  Verifier bleiben auch diese Übernahmen gesperrt.
- **Auswirkung:** Unerwünschte, aber formal autorisierte Messaging-Geräte;
  Entzug legitimer Geräte und mögliche irreversible Stilllegung. Manager kann
  weiterhin keine Managerrechte selbst vergeben oder Root-only-Recovery nutzen.
- **Reproduktion:** `test_compromised_manager_can_add_messaging_and_revoke_another_manager_within_policy`.
  Zusätzlich zeigen Terminal-/NO_RECOVERY-Tests die Irreversibilität des
  letzten Widerrufs.
- **Empfehlung:** Unabhängige Freigabe/Quorum oder stärkere Geräteverwaltungs-UX
  als Architekturvorschlag bewerten; Hardware-/OS-Isolation der Schlüssel.
  Keine eigenmächtige zweite Root-Signatur für alle Aufnahmen eingeführt.
- **Regression:** Aktueller Test erhält die beschlossene Policy und zeigt die
  Grenze. Nach ausdrücklich beschlossener Quorumpolicy muss alleinige
  kompromittierte Manager-Autorisierung negativ getestet werden.

## MEDIUM

### KISR-M01 – Freshness-Frist nicht am letzten Übernahmepunkt geprüft

**Art/Status:** bestätigter Implementierungsfehler; behoben.

- **Dateien/Zeilen:** `freshness.py:62–66`, `state_machine.py:240–247`.
  Fix: Review-Stand `freshness.py:42–54, 81–86`, `state_machine.py:254–261`.
- **Technik:** Die monotone Frist wurde vor der letzten Wanduhrprüfung und vor
  dem Aufbau der neuen Historie geprüft. Ablauf während dieser Arbeit wurde
  nicht erkannt; gültige Action konnte trotz inzwischen abgelaufenem Nachweis
  übernommen werden.
- **Voraussetzungen:** Gültige autorisierte Action und anfangs gültiger Beleg;
  Verzögerung durch Uhr-Adapter, Historienallokation oder Scheduling an der
  Fristgrenze. Ein Relay kann die Einreichung nahe an die Frist verzögern.
- **Auswirkung:** Verletzung der zugesagten lokalen Nachweisfrist. Keine
  Signaturfälschung und keine dadurch neu bewiesene globale Widerrufsgarantie.
- **Reproduktion:** Challenge bei monotonic=100, Beleg mit 20 s Laufzeit;
  letzte Wanduhrprüfung setzt monotonic=120. Der Ausgangsstand übernahm.
- **Behebung:** Explizite lokale Deadline zurückgeben; Snapshot vorab aufbauen;
  danach Action-Fenster und monotone Nachweisfrist unmittelbar vor Übernahme
  erneut prüfen. Das ist keine Echtzeitgarantie gegen OS-Preemption nach der
  letzten Uhrablesung und keine globale Lease.
- **Regression:** `test_confirmation_expiring_during_final_wall_clock_check_never_commits`,
  `test_expiry_during_history_allocation_never_commits`, Hypothesis
  `test_expiry_at_commit_boundary_preserves_the_entire_snapshot` (40 Beispiele).

### KISR-M02 – Abgelaufene Challenges sperren dauerhaft den lokalen Automaten

**Art/Status:** bestätigter Verfügbarkeitsfehler; behoben.

- **Dateien/Zeilen:** `state_machine.py:197–215`.
  Fix: Review-Stand `state_machine.py:207–228`.
- **Technik:** Das Limit 128 zählte abgelaufene Challenges unverändert mit.
  Nach Ablauf aller Nachweise konnte kein Commit mehr erfolgen, aber auch
  keine neue Challenge angelegt werden. Keine öffentliche Bereinigung vorhanden.
- **Voraussetzungen:** Host startet wiederholt Freshness-Prüfungen für eine
  gültig signierte, autorisierte Action; z. B. Relay-Replay/Retry ohne erhaltenen
  Nachweis. Unsignierte beliebige Requests erreichen diesen Cache nicht.
- **Auswirkung:** Dauerhafte lokale Blockade ohne private Snapshot-Manipulation
  oder Verlust/Neuanlage der In-Memory-Identität.
- **Reproduktion:** 128 Challenges anlegen, monotone Uhr 30 s vorziehen,
  nächste Challenge versuchen. Ausgangsstand: „too many outstanding requests“.
- **Behebung:** Vor Kapazitätsprüfung abgelaufene Einträge in einem temporären
  Tuple herausfiltern und nur bei erfolgreicher neuer Anfrage übernehmen.
  Negative/ungültige Uhrdifferenz sperrt geschlossen. Keine Historie löschen.
- **Regression:** `test_expired_challenge_capacity_can_be_reused_without_resetting_identity`,
  `test_pruning_failure_does_not_replace_snapshot_and_valid_clock_can_retry`.
  128 gleichzeitig lebende Challenges bleiben begrenzt; Rate-Limiting fehlt.

### KISR-M03 – Reentrancy-Sperre deckt Uhr-Callbacks nicht ab

**Art/Status:** bestätigter Exception-Safety-Fehler an lokaler Integrationsgrenze;
behoben. Kein allein durch Wire-Daten erreichbarer Geräteimport.

- **Dateien/Zeilen:** `state_machine.py:82–86, 137–141, 224–247`.
  Fix: Review-Stand `state_machine.py:85–95` und öffentliche Operationsaufrufe.
- **Technik:** `RLock` erlaubt Wiederaufrufe desselben Threads; `_verifying`
  blockierte Mutationen nur während des externen Verifiers. Ein lokaler Uhr-
  Callback konnte während `_validate` rekursiv `apply` erfolgreich aufrufen
  und danach im äußeren Aufruf eine Exception auslösen.
- **Voraussetzungen:** Fehlerhafter/reentrant konfigurierter lokaler Uhr-Adapter
  mit Zugang zur Instanz und zu einem gültigen vollständigen Übergang.
  Bösartiger lokaler Code könnte ohnehin private Attribute ändern; diese
  Abwehr adressiert Integrationsfehler, nicht beliebige Codeausführung.
- **Auswirkung:** Abgelehnter äußerer Aufruf hinterlässt eine veränderte History
  durch den inneren Commit; die zugesagte Atomarität war damit nicht vollständig.
- **Reproduktion:** Erste Wanduhrablesung führt einmal rekursiven vollständigen
  Commit aus und wirft anschließend `RuntimeError`. Ausgangsstand: Generation
  bereits erhöht, obwohl äußerer Aufruf fehlschlug.
- **Behebung:** Operationsguard umfasst Initialisierung, lokale Validierung,
  Konsistenzprüfung, Challenge-Erstellung und vollständigen Commit einschließlich
  aller Callbacks. `finally` räumt Guard auf. `state`/`history` bleiben lesbar.
- **Regression:** `test_wall_clock_reentry_cannot_commit_inside_a_rejected_outer_operation`,
  vorhandene Verifier-Reentrancy-Tests sowie
  `test_history_allocation_failure_and_guard_reset_are_atomic`.
  Ablehnungshelper prüft den gesamten Snapshot inklusive Pending-Cache.

### KISR-M04 – PR ohne versionierte Auflösung und automatische Qualitätsgrenze

**Art/Status:** bestätigte Supply-Chain-/Prozesslücke; behoben für diesen Branch.
Keine konkret manipulierte Abhängigkeit nachgewiesen.

- **Dateien/Zeilen:** `pyproject.toml:1–13`, `.gitignore:1–11`;
  `uv.lock` und `.github/workflows/` fehlen vollständig im Ausgangs-PR-Diff.
- **Technik:** Breite Versionsbereiche und ungepinntes Build-Backend ohne
  eingecheckte Auflösung erlaubten verschiedene Neuinstallationen. Lokale
  Testergebnisse waren nicht automatisch am PR nachvollziehbar.
- **Voraussetzungen:** Frische Installation, neue Upstream-Version oder Zugriff
  auf eine Abhängigkeit/Build-Lieferkette. Kein remote ausnutzbarer Policy-Bypass
  allein durch das fehlende Lockfile.
- **Auswirkung:** Ungeprüfte Codeversionen/native Builds können im lokalen
  Entwicklerprozess laufen; fehlerhafte Änderungen haben keine CI-Prüfgrenze.
- **Reproduktion:** `git ls-tree -r 7951cf44 -- uv.lock .github/workflows` liefert
  keine Einträge; zwei Auflösungen sind nicht auf denselben Stand festgelegt.
- **Behebung:** Lokale Auflösung prüfen und versionieren; CI mit `--locked` und
  Lock-Konsistenzprüfung. Build-Backend/Build-Abhängigkeiten separat pinnen;
  native Kryptobibliotheken dürfen durch uv nur aus Wheels kommen. Mindest-
  pytest-Version auf die veröffentlichte gepatchte Reihe anheben.
- **Regression:** Alle fünf CI-Kommandos; Änderungen an Dependency-Metadaten
  ohne passenden Lock-Update müssen bei `uv sync --locked`/`uv lock --check`
  scheitern. SHA-Pins und minimale Permissions bleiben Review-Pflicht.

### KISR-M05 – Langfristige Ressourcen-/Historienstrategie fehlt

**Art/Status:** bestätigte, bereits dokumentierte Prototypgrenze; offen.
Keine automatische History-Kompaktion oder Tombstone-Löschung eingeführt.

- **Dateien/Zeilen:** `history.py:11–26`, `models.py:90–110`,
  `consistency.py:9–13`, `state_machine.py:154–179`.
- **Technik:** Jede Historie kopiert wachsende Tuples; Vorgänger-/Replay-/Fork-
  Suche ist linear und hasht gespeicherte Zustände wiederholt. Keine Grenze
  für Zahl der Änderungen; 64 Geräte einschließlich Tombstones begrenzen
  dagegen lebenslange Geräteaufnahmen, nicht die Historienlänge.
- **Voraussetzungen:** Langer gültiger Verlauf oder berechtigter Manager mit
  vielen bestätigten Änderungen; untrusted Anfragen erhöhen Prüfkosten einer
  bereits großen Historie. Kein Angreifer kann ohne Autorisierung History
  direkt vergrößern.
- **Auswirkung:** Speicher-/CPU-Verbrauch und nach 64 registrierten IDs keine
  weitere Geräteaufnahme. Verfügbarkeit ist nicht langfristig zugesichert.
- **Reproduktion:** Wiederholt Messaging-Rechte ändern, jede Action gültig
  übernehmen; `len(history.states)` wächst ohne Budget. 64 Einträge erfüllen
  das Schema, ein 65. Eintrag wird geschlossen abgewiesen.
- **Empfehlung:** Ressourcenbudget, Hash-/Action-Indizes und sichere persistente
  Checkpoints spezifizieren; Tombstones niemals zur scheinbaren Behebung von
  NO_RECOVERY-/Schlüsselreuse-Regeln löschen.
- **Regression:** Nach beschlossener Budget-/Checkpoint-Policy lange Verläufe,
  Kapazitätsgrenzen und festgelegtes CPU-/Speicherbudget testen. Dieser
  Zukunftstest fehlt bewusst, weil noch keine sichere Policy beschlossen ist;
  Stateful-Lifecycle prüft heute Ketten-/Replay-Invarianten, keine DoS-Garantie.

## LOW

### KISR-L01 – Falscher Verifier-Antworttyp entgeht der Adapterfehlerbehandlung

**Art/Status:** bestätigter Integrationsfehler; behoben.

- **Dateien/Zeilen:** `freshness.py:51–61`;
  Fix: Review-Stand `freshness.py:68–76`.
- **Technik:** `checked()` revalidierte den dynamischen Modelltyp der Antwort,
  nicht zwingend `ExternalConfirmation`. Ein `FreshnessChallenge` konnte so
  die Prüfung passieren und anschließend außerhalb des `try` einen
  `AttributeError` auslösen.
- **Voraussetzungen:** Fehlerhafter lokaler Adapter; bei korrekt implementiertem
  Verifier kein Angriff nur durch externe Belegbytes.
- **Auswirkung:** Unklassifizierter Fehler statt `FreshnessError`, mögliches
  Host-Absturz-/Fehlerbehandlungsproblem. Zustand blieb unverändert; kein
  erfolgreicher ungültiger Commit nachgewiesen.
- **Reproduktion:** Verifier liefert die angefragte Challenge selbst zurück.
- **Behebung:** Vor weiterer Verarbeitung strikt gegen das fest vorgeschriebene
  `ExternalConfirmation`-Schema validieren, Fehler geschlossen kapseln.
- **Regression:** `test_ill_typed_verifier_result_is_a_typed_atomic_rejection`.

### KISR-L02 – Pinning ist keine vollständige Build-/Native-Herkunftsprüfung

**Art/Status:** bestätigte Lieferkettenbegrenzung; teilweise mitigiert, offen.
Keine infizierte Binärdatei nachgewiesen.

- **Dateien/Zeilen:** `signatures.py:10, 92–103`, `pyproject.toml:1–13`;
  Review-Stand `pyproject.toml:15–28`, `uv.lock`, Workflow SHA-Pins.
- **Technik:** PyNaCl-Versionsnummer allein beweist bei System-/Source-Builds
  keinen gepatchten libsodium-Stand. Offizielle Wheels bündeln native Bibliotheken.
  `uv.lock` enthält Projektartefakthashes, aber kein vollständiges SBOM,
  keine Signatur-/Provenanceprüfung jedes nativen Builds. Separate PEP-517-
  Build-Auflösung wird nun versionsgebunden, nicht komplett durch die
  Projekt-Wheel-Hashes attestiert. Runner-Image bleibt veränderlich.
- **Voraussetzungen:** Manipulierte lokale Installation, kompromittierter
  Hersteller-/Build-Prozess oder Installationsweg außerhalb des uv-Profils.
- **Auswirkung:** Vertrauen in native Punkt-/Signaturprüfung oder Build-Code
  kann wegfallen. Ein Hash erkennt Änderung gegenüber dem festgelegten
  Artefakt, keine bereits im Artefakt enthaltene Schadfunktion.
- **Reproduktion:** PyNaCl kann laut Hersteller mit `SODIUM_INSTALL=system`
  gebaut werden. Das Review-uv-Profil verbietet diesen Source-Fallback;
  vorhandene manipulierte Pakete kann es nicht als vertrauenswürdig beweisen.
- **Empfehlung:** Frische isolierte Wheel-Installation, Hash-/Attestierungsprüfung,
  plattformspezifisches SBOM, signierte/reproduzierbare Releases; automatische
  Advisory-Prüfung in separatem, unprivilegiertem Update-Prozess ergänzen.
- **Regression:** Native Punktvektoren und Signatur-Skalartest plus
  `uv sync --locked` auf frischem Runner. Künftige Herkunftsprüfung muss auch
  falsche System-Builds testen; einige Vektoren allein sind keine Attestierung.

### KISR-L03 – Genesis wird vor Allokation der Schlüsselrückgabe übernommen

**Art/Status:** bestätigte Exception-Safety-Lücke unter injiziertem
Allokationsfehler; behoben. Keine Remote-Ausnutzung nachgewiesen.

- **Dateien/Zeilen:** `state_machine.py:134–135`; Fix: Review-Stand
  `state_machine.py:142–144`.
- **Technik:** Initialisierung setzte den Snapshot, bevor `BootstrapKeys`
  erzeugt wurde. Scheitert diese Allokation, liefert der Aufruf keine Schlüssel,
  hinterlässt jedoch eine initialisierte Identität und verhindert erneuten Start.
- **Voraussetzungen:** Speicher-/Allokationsfehler exakt beim Rückgabeobjekt;
  Test injiziert `MemoryError` am entsprechenden Konstruktor. Das ist eine
  lokale Fehlerbedingung, kein nachgewiesener fremder Zustandsimport.
- **Auswirkung:** Teilweise erfolgreiche Initialisierung ohne erhaltene
  Privatschlüssel; verletzte Ausnahme-Atomarität, mögliche lokale Stilllegung.
- **Reproduktion:** `BootstrapKeys`-Konstruktor im Test durch eine
  `MemoryError`-werfende Funktion ersetzen; Ausgangsstand besitzt nach Ablehnung
  dennoch einen Snapshot.
- **Behebung:** Schlüsselrückgabe vor dem einzigen Snapshot-Commit anlegen.
- **Regression:**
  `test_bootstrap_result_allocation_failure_never_initializes_partial_identity`;
  Snapshot bleibt `None`, Guard wird zurückgesetzt, erneuter frischer Start gelingt.

## INFORMATIONAL

### KISR-I01 – Messaging-Schlüsselbindung und sichere Kopplung nicht implementiert

**Art/Status:** bestätigte ausdrücklich benannte Integrationslücke; offen.

- **Dateien/Zeilen:** `models.py:61–75`, `signatures.py:67–89`,
  `state_machine.py:160–174`; Policy § 6, Identity Protocol §§ 2, 7, 13.
- **Technik:** Besitznachweis bezieht sich auf Ed25519 und bindet den angegebenen
  X25519-Public-Key. Er beweist keinen Besitz des X25519-Privatschlüssels;
  beliebige 32-Byte-Sessionwerte werden nicht als DH-Schlüssel geprüft.
  Gegenseitiger QR-/MITM-Handshake und Nutzerbestätigung fehlen.
- **Voraussetzungen:** Legitim oder kompromittiert autorisierender Manager plus
  Ed25519-Zielschlüssel; bei späterer DH-Integration problematische Sessionwerte.
- **Auswirkung:** Heute keine DH-/Nachrichtenfunktion und deshalb kein
  nachgewiesener Inhaltsexploit. Keine sichere Messaging-/Pairing-Garantie
  ableitbar; Integration ohne separate Prüfung wäre sicherheitskritisch.
- **Reproduktion:** `Device` mit anderem 64-stelligen Session-Hexwert ist
  modellierbar; mit Ed25519 lassen sich diese Daten binden, ohne Sessionbesitz.
- **Empfehlung:** Geprüftes Messaging-/Pairing-Verfahren auswählen, kryptografische
  Bindung und Kurven-/Handshakeprüfungen in dessen Vertrag festlegen.
- **Regression:** Künftig Sessionbesitz, Low-Order-/Null-DH, MITM, UI-Freigabe und
  Rollenbindung integrieren. Aktuelle Tests beweisen nur den Ed25519-Besitznachweis.

### KISR-I02 – Offline-Catch-up und sichere Persistenz fehlen

**Art/Status:** bestätigte, dokumentierte Verfügbarkeits-/Integrationsgrenze; offen.

- **Dateien/Zeilen:** `state_machine.py:137–179`, `history.py:11–31`,
  `tests/test_freshness.py:161–169`.
- **Technik:** Dieselbe aktuelle Autorisierungsfrist gilt für nächste historische
  Änderungen. Nach einer Woche werden korrekt signierte, damals gültige
  Actions abgewiesen. Keine Import-/Restore-/Checkpoint-API existiert.
- **Voraussetzungen:** Längere Offline-Zeit oder Prozessverlust; unterdrückte
  Zwischenänderungen können nicht durch einen nackten aktuellen Head ersetzt werden.
- **Auswirkung:** Kein langlebiger Multidevice-Betrieb. Dafür kein unberechtigter
  Zustandssprung oder Wiederherstellungsweg zur Behebung dieses Problems.
- **Reproduktion/Regression:**
  `test_long_offline_reconnection_rejects_expired_authorization_without_skipping_history`.
- **Empfehlung:** Historische Autorisierungsprüfung getrennt von aktueller
  Aktivierungsfreigabe spezifizieren; persistente monotone Pins und Crash-
  Recovery bestehender verfügbarer Geräte prüfen. Kein Backup-Import laufender
  Identitäten oder Root-only-Recovery ohne neue ausdrückliche Entscheidung.

## Kryptografische und Zustandsprüfung im Detail

| Prüfaspekt | Beobachtung und verbleibende Bedingung |
|---|---|
| Ed25519 | Native OpenSSL-Verifikation nach nativer libsodium-Punktprüfung; kein eigener Kurvenalgorithmus |
| Public-Key-Eingang | 32 Byte/lowercase Hex an Modellgrenzen; kanonischer Hauptgruppenpunkt zusätzlich vor jeder Signaturprüfung |
| Degenerierte Schlüssel | Vorhandene 0/1-Vektoren sowie zusätzliche upstream Nichtkanonizitäts-/Nichtuntergruppenvektoren negativ |
| Signature Malleability | Test mit `S+L` wird durch cryptography und libsodium abgewiesen; keine mathematisch äquivalenten nichtkanonischen Skalare angenommen |
| Domain Separation | Fünf Signaturzwecke, unterschiedliche Hashzwecke, Nullabschluss; alle 20 geordneten Signaturdomänenpaare negativ mit gleichem Schlüssel/Payload |
| Kanonisierung | Geschlossene Pydantic-Schemata, feste Reihenfolge, Größenlimits, doppelte Felder/Unicode/Floats/NaN/Boolean-Counter abgewiesen; kein RFC-8785-Claim |
| Python-Modelle | Revalidierung vor Serialisierung schließt vorhandenen `model_copy`-Boolean-Bypass; keine Garantie gegen beliebige eigene Python-Klassen/Codeausführung |
| Hashkette | Action bindet vorherigen Hash und nächste Generation; Zustand bindet Actionhash. Signaturen bleiben im authentifizierten Verlauf, nackter Hash ist kein Authentisierungsnachweis |
| Key-Pinning | Autor-Public-Key ausschließlich aus bekanntem Vorgänger; unbekannter Autor abgewiesen |
| Rollen | Signaturprüfung getrennt von Autorisierung; Messaging, Management und Recovery implizieren einander nicht |
| Aufnahme | Aktiver Manager plus neue zielgebundene Besitzsignatur; ausschließlich Messaging; keine Manager-Selbstausweitung |
| Manageränderung | Root plus bereits aktives Ziel mit eigener gebundener Besitzsignatur; kein neues Gerät auf diesem Pfad |
| Widerruf | Aktiver Manager, irreversibler Tombstone; gleiche ID oder alte Schlüssel auch mit anderer ID unzulässig |
| Replay/Rollback/Fork | Einmalige Action-ID inkl. Genesis, bekannte ältere Zustände abgewiesen; authentischer alternativer Nachfolger nach Crypto/Authority als Fork; unbekannte nackte Zustände nur Konflikt |
| Gleichzeitigkeit | Ein Instanz-Lock serialisiert Threads: genau ein gleichzeitiger Nachfolger übernommen, anderer Fork. Keine globale Konsistenz hieraus |
| Atomarität | Ein Snapshot-Commit nach allen Prüfungen; neue Allokations-/Uhr-/Adaptertests plus Snapshot-Identität auch in Property-Tests. Keine Disk-Transaktion oder Crash-Garantie |
| Fristen | Action-Wanduhr und monotone lokale Antwortfrist getrennt; erneute Commit-Prüfung. Uhren können fehlende Widerrufe nicht beweisen |
| Externe Bindung | Exact identity_id/generation/state_hash/nonce plus lokale action_id/parent_hash-Zuordnung; falscher Nachweis, unbekannte Nonce und abgelaufene Bestätigung abgewiesen |
| Ungültiger Zustand + Verifier | `begin_freshness_check`/`apply` prüfen den Übergang vor Verifier; Verifier ersetzt keine Signatur-/Rechteprüfung. Ein lügender Prüfer kann aber gültige veraltete Zweige bestätigen |
| NO_RECOVERY | Neue Genesis immer neu generierte Root-/Geräteschlüssel; keine Root-/State-Import-, Rotation-, Backup- oder Recovery-Transition; letzter Widerruf terminal |

`NO_RECOVERY` gilt innerhalb dieser APIs. Physisch verlorene, öffentlich noch
aktive Geräte sind nicht automatisch erkennbar; gestohlene weiterhin gültige
Privatschlüssel können ihre Rechte ausüben. Neue Identität widerruft alte Geräte
nicht und verifiziert keine Kontakte. Historie/Prozesssnapshot dürfen später
nicht als unkontrollierter Restore-Pfad exportiert werden. Identitätsbezeichner
sind domain-separierte Hashes, keine implementierte DID-Methode.

## Spezifikationsabgleich und nicht erfüllte Freigabekriterien

| Grundlage | Bewertung |
|---|---|
| SEC-C04/05, Policy § 4 | Native Primitive, Version/Suite/Policy, kanonische Bytes und getrennte Domänen implementiert; keine produktive Kryptokomposition oder Migration |
| SEC-I01 | Lokale CSPRNG-Genesis und unabhängige Kennungen implementiert |
| SEC-I03 | Rollen-/Besitz-/Action-Replay-Prüfung implementiert; gegenseitige Kopplung und bewusste Bestätigung fehlen (I01) |
| SEC-I04 | Separate Auth-/Sessionwerte, Generationen und irreversible Widerrufe; kein Ratchet-/Gruppen-Rekey oder Ausschluss im Messaging |
| SEC-I05 | Lokale bekannte Rollbacks/Forks erkannt; globale Nicht-Äquivokation, unbekannte Widerrufe und echte Freshness fehlen (H01) |
| SEC-I07 | Kein Recovery-/Importpfad; terminaler Zustand geprüft; menschlicher Geräteverlust/gestohlene aktive Schlüssel außerhalb beweisbarer API-Eigenschaften |
| SEC-I02/06, SEC-E03 | Kontaktverifikation, privater Invite-Modus und sicherheitskritische UI fehlen; kein Server kann diese im Kern automatisch freigeben |
| SEC-E01/04/05 | Kein Keystore, lokale Verschlüsselung, sichere Speicherlöschung, Backup oder Endpoint-Härtung |
| SEC-S04/05/06 | Challenge-Leak behoben; weitere Ressourcen-/Release-/Provenanceanforderungen offen. Lock und minimale CI sind Teilmaßnahmen |
| SEC-C01–03/06/07, SEC-G01–05, SEC-M01–07, übrige Relay-Anforderungen | Außerhalb isoliertem Identity-Core; nicht als erfüllt erklärt |

Frühere Rust-/Recovery-/Root-bei-jeder-Aufnahme-Widersprüche sind bereits durch
SR-01 bis SR-04 aufgelöst, nicht erneut entschieden. Offene D-01 bis D-10 bleiben
offen. Weiterhin explizite Prototypabweichungen: ASCII-JSON statt finalem
Wire-Standard; Root+Zielbesitz auch beim Managerentzug; aktiver Manager als
Widerrufsautor; letzter Gerätewiderruf terminal; Actions maximal 300 s; externe
Bestätigung für Kandidaten statt implementiertem Transparency-System; 64 Geräte,
In-Memory-History ohne Catch-up. Keine dieser Regeln wird hier still geändert.

## Dependencies, Herkunft und aktuelle Sicherheitsinformationen

Lock enthält 23 Packages inklusive Projekt. Herkunft aller Fremdpakete:
`https://pypi.org/simple`, Artefakte unter `files.pythonhosted.org` mit SHA-256.
Keine Git-/URL-/lokalen Fremdabhängigkeiten im Lock. Runtime: Pydantic,
cryptography, PyNaCl; die übrigen direkten Tools sind Development-Abhängigkeiten.

| Packages im Lock | Versionen |
|---|---|
| Projekt | krypta-identity-prototype 0.1.0 |
| Runtime direkt | pydantic 2.13.5; cryptography 50.0.2; pynacl 1.6.2 |
| Runtime transitiv | annotated-types 0.8.0; pydantic-core 2.46.5; typing-extensions 4.16.0; typing-inspection 0.4.4; cffi 2.1.1; pycparser 3.0 |
| Dev direkt | pytest 9.1.1; hypothesis 6.168.5; ruff 0.16.10; mypy 1.20.2 |
| Dev transitiv | colorama 0.4.6 (Windows); iniconfig 2.3.1; packaging 26.3; pluggy 1.6.0; pygments 2.21.0; sortedcontainers 2.4.0; librt 0.16.0; mypy-extensions 1.1.0; pathspec 1.1.1 |

Zusätzliche separate Build-Constraints: hatchling 1.32.4, editables 0.6,
packaging 26.3, pathspec 1.1.1, pluggy 1.6.0, tomlkit 0.15.1,
trove-classifiers 2026.9.21.13. Diese sind im Lock als Build-Constraints erfasst;
der getrennte Build-Resolver wird nicht als vollständig hashattestiert dargestellt.
Bei fehlenden Crypto-Wheels scheitert uv statt gegen unbekannte Systembibliotheken
zu bauen. Das schränkt bewusst die Plattformverfügbarkeit ein.

Lokaler nativer Runtime-Befund: cryptography meldet **OpenSSL 4.0.3,
29 Sep 2026**; PyNaCl 1.6.2 installiert. Seine Bindings exportieren hier keine
`sodium_version_string`-API. Kein exakter Patch-/Buildhash von libsodium wurde
zur Laufzeit attestiert. Herstellerangaben und native Negativvektoren wurden
geprüft; ihre Grenzen stehen in L02.

Aktuelle öffentliche Quellen waren über Browser/GitHub verfügbar und wurden
am Reviewtag geprüft. PyPI-Downloads aus dem Shell-Prozess sind DNS-blockiert;
Installation aus dem inzwischen vorhandenen Cache gelang. Ein vollständiger
automatischer OSV-/pip-audit-Abgleich aller transitiven Versionen wurde **nicht**
ausgeführt; die Advisory-API war über den Browser nicht zugänglich. Die manuelle
Prüfung ausgewählter Maintainer-/GitHub-Advisories ist keine pauschale
„keine CVEs“-Bescheinigung für alle oben genannten Pakete.

| Verifizierte Quelle | Einordnung der festgelegten Version |
|---|---|
| [PyNaCl GHSA-mrfv-m5wm-5w6w / CVE-2025-69277](https://github.com/advisories/GHSA-mrfv-m5wm-5w6w) und [Maintainer-Changelog](https://github.com/pyca/pynacl/blob/main/CHANGELOG.rst) | PyNaCl <1.6.2 betroffen; 1.6.2 enthält aktualisierte gebündelte libsodium. Systembuild nicht daraus beweisbar |
| [cryptography GHSA-g6cj-pr64-35w5](https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5) | PKCS#7-Oracle ab 50.0.0 behoben; 50.0.2 außerhalb betroffener Reihe, keine PKCS#7-Funktion im Core |
| [cryptography GHSA-537c-gmf6-5ccf](https://github.com/pyca/cryptography/security/advisories/GHSA-537c-gmf6-5ccf) | Betroffene ältere gebündelte OpenSSL-Wheels; 50.0.2 liegt nach benannter gepatchter Reihe |
| [cryptography GHSA-m2h6-j472-rp4c](https://github.com/pyca/cryptography/security/advisories/GHSA-m2h6-j472-rp4c), [GHSA-jwv3-5hgf-82ww](https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww) | X.509-Probleme bis 48.0.0, ab 49.0.0 behoben; diese APIs werden hier nicht genutzt |
| [pytest GHSA-6w46-j5rx-g56g](https://github.com/advisories/GHSA-6w46-j5rx-g56g) | <9.0.3 betroffen; Lock 9.1.1, neue Untergrenze 9.0.3 |
| [uv GHSA-4gg8-gxpx-9rph](https://github.com/astral-sh/uv/security/advisories/GHSA-4gg8-gxpx-9rph) | <0.11.15 betroffen; genutztes 0.12.5 liegt außerhalb |
| [uv GHSA-2cv4-cqwr-gwf7](https://github.com/astral-sh/uv/security/advisories/GHSA-2cv4-cqwr-gwf7) | Windows-Problem betrifft >=0.12.7,<0.12.18; festgelegtes 0.12.5 nicht in dieser Reihe |

Zusätzlich wurden [Pydantic-Advisories](https://github.com/pydantic/pydantic/security/advisories)
und [cryptography-Maintainer-Advisories](https://github.com/pyca/cryptography/security/advisories)
gesichtet. Die historische `requirements.txt` enthält einen ungeprüften alten
App-Stack (u. a. cryptography 43.0.1) und wird nicht durch uv/CI installiert.
Sie bleibt unverändert; keine Sicherheitsfreigabe dieser alten Liste. Vor
Produktarbeit entfernen/archivieren oder separat aktualisieren und prüfen.

## CI, Tests und reproduzierbare Ausführung

Workflow: `.github/workflows/identity-security.yml`. Nur `pull_request` und
`push`, `contents: read`, GitHub-gehosteter Ubuntu-24.04-Runner, Timeout 10 min,
kein `pull_request_target`, `workflow_run`, OIDC, Secrets oder persistierte
Checkout-Credentials. Cache deaktiviert. PR-Daten werden nicht in Shell-Code
interpoliert. Untrusted PR-Code läuft auf dem kurzlebigen Runner; Abhängigkeiten
und Testcode sind weiterhin auszuführender, nicht automatisch vertrauenswürdiger Code.

Überprüfte offizielle Tags, Commit-Metadaten mit GitHub-verified Signatur und
`action.yml`-Inputs:

- [actions/checkout v7.0.0](https://github.com/actions/checkout/commit/9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0):
  `9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0`.
- [astral-sh/setup-uv v10.2.0](https://github.com/astral-sh/setup-uv/commit/c18668ad3cf93ea998bef934396af7bb5c839dc7):
  `c18668ad3cf93ea998bef934396af7bb5c839dc7`.

Python 3.13.15 und uv 0.12.5 sind festgelegt; keine `latest`-Installation.
SHA-/Signaturprüfung hier bedeutet überprüfte Referenzherkunft, kein Vollreview
aller gebündelten Action-/Node-Abhängigkeiten. Keine signierten Releases erstellt.

Lokale Umgebung: CPython 3.13.15, frische Review-venv und beschreibbarer Cache.
`UV_OFFLINE=true` wegen Shell-DNS-Blockade, `UV_CACHE_DIR=/tmp/krypta-identity-uv-cache`.
Baseline: 76 Tests erfolgreich. Drei gezielt hinzugefügte Fehlerreproduktionen
schlugen am unveränderten Ausgangscode fehl, danach erfolgreich. Eine vierte
Fault-Injection belegte zusätzlich die Genesis-Allokationslücke L03. Final:

| Kommando | Ergebnis |
|---|---|
| `uv sync --locked` | Erfolgreich einschließlich lokalem Build |
| `uv run pytest -v` | 94 bestanden, keine übersprungenen Tests |
| `uv run ruff check .` | Erfolgreich |
| `uv run mypy src` | Erfolgreich, 13 Quelldateien |
| `uv lock --check` | Erfolgreich, 23 Packages |
| `git diff --check` | Erfolgreich |

Hypothesis: sechs Property-/Stateful-Tests, deterministische Exploration
(`derandomize=True`, keine lokale Datenbank), zusätzlich 40 Deadline-Beispiele
und 60 Manipulationen fast gültiger Wire-Daten mit gültigem Ausgangsnachweis.
Testschlüssel/Nonces stammen weiter aus der echten CSPRNG; keine Testassertion
hängt von ihren konkreten Zufallswerten ab. Threadtests nutzen Barrieren statt
Sleep-Timing. Kleine Punktvektor-/Skalartests verwenden native Bibliotheken;
die Testkonstruktion einer ungültigen `S+L`-Signatur ist kein eigener produktiver
Kryptoalgorithmus.

Remote-CI ist vor Veröffentlichung dieses Berichtes noch nicht gelaufen. Ihr
Live-Ergebnis wird am neuen Draft-PR und im Abschlussbericht nach Veröffentlichung
geprüft; lokale Ergebnisse werden nicht als Remote-CI-Ergebnis ausgegeben.
`actionlint` war lokal nicht installiert; Workflow wurde manuell geprüft, seine
GitHub-Ausführbarkeit muss der echte Remote-Lauf bestätigen.

## Empfehlung und weitere Prüfung

Review-Korrekturen im separaten Draft-PR gegen `feat/identity-state-machine`
prüfen, keine automatische Zusammenführung. Danach unabhängiger Spezialisten-
Review der Root-/Manager-Policy und nativen Kryptografieintegration, formales
Zustands-/Forkmodell, spezifizierte globale Aktualität, sichere Pairing-/Messaging-
Komposition, persistente monotone Zustände, Ressourcenbudget und Lieferketten-
Attestierung. Mobile Keystores, Endpoint-Schutz und quantitative Metadatenanalyse
bleiben eigene Prüfaufgaben. Vor Hochrisiko-Einsatz gelten unverändert G0–G3.

**Ein bestandener Testlauf ist kein vollständiger Sicherheitsnachweis.**
