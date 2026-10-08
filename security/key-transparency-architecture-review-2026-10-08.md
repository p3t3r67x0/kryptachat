# KryptaChat – adversariales Key-Transparency-Architekturreview

**Datum:** 2026-10-08. **Auftrag:** [Issue #4](https://github.com/p3t3r67x0/kryptachat/issues/4).
**Status:** internes Architekturreview, kein unabhängiges Audit. KryptaChat bleibt
ein **nicht produktionsreifer Entwicklungsprototyp**. Ein Dokumentationsmerge
erteilt keine Implementierungs- oder Produktfreigabe.

## Ergebnis und Grenzen der Prüfung

Keine bestätigte CRITICAL-Lücke im begrenzten Umfang dieses **nicht
implementierten** Entwurfs. Drei bestätigte Dokumentationsfehler werden
korrigiert. Sechs HIGH-Architektur-/Policy-Risiken bleiben ausdrücklich
**Release-Blocker**; drei weitere MEDIUM-Verträge bleiben offen. Fehlende
Protokollentscheidungen sind keine nachgewiesenen Remote-Exploits einer
existierenden Transparency-Implementierung: eine solche existiert nicht.

**Go:** Präzisierungen als Discussion Draft zur weiteren Prüfung veröffentlichen.
**No-Go:** produktive Transparency-Integration, Sicherheitsversprechen oder
Hochrisiko-Einsatz. **Merge-Kette angehalten:** Für PR #2 fehlt die in Issue #4
geforderte wirklich unabhängige Prüfung der Fixes M01/M02/M03/L01/L03.
Dieser Reviewer hat den Prototyp und diese Fixes mitentwickelt; eine erneute
Selbstprüfung oder ein eigener Approval würde dieses Gate nicht erfüllen.

## 1. Neu abgerufene Baseline

GitHub-PRs, Compare, Reviews, Branches, Rulesets, Check-Runs und Workflow-Runs
wurden am Reviewtag neu gelesen. Ausgangsstand:

| PR | Head und Base | Status / tatsächlich geprüfte Checks |
|---|---|---|
| [#1](https://github.com/p3t3r67x0/kryptachat/pull/1) | `feat/identity-state-machine`: `7951cf44a2c278b39e695018fea429e785e21416` → `main`: `7af83603aa7288e4191395fc43ad223b9dac45f3` | Open Draft; keine eingereichten Reviews; finaler Integrationsstand existiert noch nicht |
| [#2](https://github.com/p3t3r67x0/kryptachat/pull/2) | `security/identity-state-machine-review`: `544b2372e600e604277595ee4d75b084594e04f6` → Feature-Head `7951cf44a2c278b39e695018fea429e785e21416` | Open Draft; Reviews `[]`; beide `identity`-Check-Runs am exakten Head erfolgreich |
| [#3](https://github.com/p3t3r67x0/kryptachat/pull/3) | `architecture/key-transparency-v0.1`: `2cab479ad867f036986ae1a47a90f1f45c62f152` → Review-Head `544b2372e600e604277595ee4d75b084594e04f6` | Open Draft; Reviews `[]`; kein Workflow-Run für diesen Head |

PR-#3-Merge-Base ist `544b2372e600e604277595ee4d75b084594e04f6`;
ein Commit voraus, keiner zurück. Tatsächlicher Ausgangsdiff: ausschließlich
`security/key-transparency-device-consistency-v0.1.md`, 200 neue Zeilen.
PR #2 ist auf PR #1 aufgebaut; dessen Merge-Base ist der genannte Feature-Head.
PR #1 ist auf dem genannten `main`-Head aufgebaut. Lokaler Checkout enthält
die exakten GitHub-Commit- und Tree-Objekte, nicht nur ähnlich benannte Branches.

Nachprüfbare PR-#2-CI:
[Pull-request-Lauf](https://github.com/p3t3r67x0/kryptachat/actions/runs/37808971199),
[Push-Lauf](https://github.com/p3t3r67x0/kryptachat/actions/runs/37808928884).
Beide referenzieren `544b2372e600e604277595ee4d75b084594e04f6` und enden mit
`success`. Sie werden **nicht** als CI für PR #3 oder einen späteren
Integrationscommit ausgegeben. Der bestehende Workflow filtert PR-Bases auf
`main`/`feat/identity-state-machine` und Pushes auf diese plus den Review-Branch;
der aktuelle PR-#3-Branch und seine Base werden nicht erfasst.

Repository-Rulesets lieferten `[]`, die Branch-Liste für alle vier Branches
`protected: false`. Ein zusätzlicher Read von `main/protection` lieferte
HTTP 403 wegen fehlender Administration-Berechtigung der Integration. Das ist
kein Beleg einer erfolgreich geprüften Schutzregel und kein Anlass zum Bypass.
Unmittelbar vor jedem späteren Merge müssen effektive Regeln, erforderliche
Reviews, neuer Head und dessen Checks erneut geprüft werden.

## 2. Methode, Grundlagen und Spezifikationsabgleich

Vollständig gelesen: `security/threat-model.md`, `identity-protocol.md`,
`identity-authority-policy.md`, `review-2026-10-08.md`,
`identity-security-review-2026-10-08.md`, das PR-#3-ADR und
`docs/identity-state-machine.md`. Erneut geprüft wurden die Integrationsgrenzen
in `freshness.py`, `state_machine.py`, `consistency.py`, `history.py`,
`authority.py`, Workflow und Package-Konfiguration. Bestehende native,
Property-, Reentrancy-, Deadline- und Konkurrenztests wurden neu ausgeführt.

Der Review nutzt gegnerische Ablaufargumente, keine formale Verifikation eines
noch unbekannten Konsensprotokolls. Angreifer: untrusted Relay/Log, kolludierende
Witnesses, Partitionierung, kontrollierte Discovery, kompromittierter aktiver
Manager sowie Crash-/Cache-Rollback. Beliebige lokale Codeausführung und
vollständige Endpoint-Kompromittierung bleiben außerhalb der Prototypgarantien.

| Verbindliche Grundlage | ADR / tatsächlicher Kern / offene Lücke |
|---|---|
| SEC-I05: keine stillen alten oder widersprüchlichen Gerätelisten | Lokale bekannte Rollbacks/Forks erkannt; globaler aktueller Head, S/D und Widerrufslatenz fehlen weiterhin, KISR-H01 |
| SEC-M01/03/04, Einladung statt globaler Datenbank | Kein Netzwerk/Directory implementiert; ADR enthält nun Risikomatrix, noch keine geprüfte private Lookup-Konstruktion |
| Signaturprüfung getrennt von Rollen | Kern prüft beide; Witness darf diese Autorisierung nicht überschreiben |
| Messaging, Management, Recovery unabhängig | Manager darf Messaging-Geräte aufnehmen/widerrufen; nur Root + aktives Ziel ändern Managerrolle; Transparency ändert diese Regeln nicht |
| NO_RECOVERY, SR-01/02 | Keine alte Root-/Genesis-Import-API; letzte Revocation terminal; Log-Replay darf diesen Zustand nicht restaurieren |
| Python mit nativer Kryptografie, SR-03 | Bestehender Python-Kern mit cryptography/PyNaCl bleibt unverändert; kein eigener Merkle-/Signaturalgorithmus hinzugefügt |
| SEC-G03, SR-08: Empfängerausschluss nach Widerruf | Keine Messaging-/Rekey-Implementierung; ADR bindet jetzt auch bestehende Sessions an das zukünftige Versandgate |
| Normative G0–G3 / unabhängiges Audit | ADR-Arbeitsschritte heißen jetzt KT-G0–KT-G3; kein Ersatz der Projektfreigaben |

Unveränderte Prototypabweichungen: ASCII-JSON-Profil, Action-Fenster maximal
300 s, 64 Geräte einschließlich Tombstones, RAM-History, kein historischer
Catch-up, kein QR-Pairing, kein DH-Besitznachweis für den Session-Platzhalter,
kein Messaging, keine sichere Persistenz und keine DID-Methode. Eine neue
Identität widerruft gestohlene aktive Schlüssel der alten Identität nicht.

## 3. Befunde

Orte/Zeilen beziehen sich auf das **ursprüngliche ADR am Head `2cab479…`**,
Datei `security/key-transparency-device-consistency-v0.1.md`, außer ausdrücklich
anders angegeben. Änderungen verschieben die Zeilen; Abschnittsnamen bleiben
zur Zuordnung angegeben. Tests mit `KT-*` sind **vorgeschlagene Abnahmeszenarien**,
keine bereits implementierten Transparency-Tests.

### CRITICAL

Keine bestätigte Lücke dieser Kategorie im geprüften Dokumentationsumfang.
Ohne konkretes Protokoll kann weder dessen Sicherheit noch Abwesenheit
kritischer Implementierungslücken bewiesen werden.

### HIGH

#### KTAR-H01 – Serialisierte Aktivierung hat noch keinen Exklusivitätsvertrag

- **Art/Status:** bestätigte Spezifikationslücke; offen, Release-Blocker. S bleibt Vorschlag.
- **Ort:** ADR §§ 6.A, 7, Zeilen 84–89, 118–124; KISR-H01.
- **Voraussetzungen:** zwei gültige Manager-Änderungen desselben Parents; Log nimmt beide auf, Clients getrennt.
- **Auswirkung:** zwei verschiedene aktive Device-Heads trotz gültiger Inclusion/Consistency und Witness-Signaturen. Ein verteilter Log ist noch kein vergleichender State-Commit.
- **Nachweis:** Logfolge `[P, A, B]` ist append-only, obwohl A und B jeweils P referenzieren. Witnesses können diese Logfolge ehrlich bestätigen. Nur ein separater exklusiver Aktivierungsslot kann S erfüllen. Kontaktlabels dürfen denselben Root nicht in unabhängige Slots aufspalten.
- **Behebung/offene Entscheidung:** S oder D entscheiden; bei S autorisierte Parent-CAS-Semantik, persistente Konsens-/View-/Epoch-Regeln und Zertifikatsbindung spezifizieren. Ein zentraler CAS-Koordinator wäre technisch eine Möglichkeit, aber konzentriert Ausfall-/Metadatenrisiken; keine Auswahl durch dieses Review.
- **Regression:** KT-04/16, echte Mehrclient-/Partitionssimulation. Der bestehende Test `test_previously_confirmed_fork_is_still_accepted_on_an_unaware_offline_copy` dokumentiert die heutige Grenze, keine Lösung.

#### KTAR-H02 – Widerrufslatenz und Empfängerfrische sind nicht beweisbar begrenzt

- **Art/Status:** bestätigte offene Garantie-/Integrationslücke; Release-Blocker.
- **Ort:** ADR §§ 1, 6.B/E, Zeilen 14, 91–96, 110–114; `freshness.py:42–86`.
- **Voraussetzungen:** Relay hält Widerruf zurück; Sender besitzt alten gültigen Nachweis oder schon bestehende Session; Publikation/Partition kann unbegrenzt dauern.
- **Auswirkung:** ein zukünftig integrierter Sender könnte weiter an entzogenes Gerät verschlüsseln. Ein Nonce-Antwortfenster misst nur Antwortdauer, nicht Vollständigkeit oder Exklusivität der Beobachtung.
- **Nachweis:** Widerrufsabsicht bei t0, alte Head-Attestierung bei t1, späterer Konflikt unsichtbar bis t2. Ohne ehrliche aktuelle Beobachtung und Verzögerungsgrenzen folgt aus `t2-t1 < 30 s` keine globale Widerrufsfrist. S allein aktualisiert offline Sender nicht.
- **Behebung/offene Entscheidung:** Beginn der Widerrufswirksamkeit, Publikations-/Konsensgrenze, Beobachtungsalter, Empfangsverzögerung, Uhr-/Suspend-Modell und Gate jeder neuen Verschlüsselung spezifizieren. Eine Lease müsste alte Freigaben und neue Widerrufe explizit koordinieren. Unbeschränkte Partition bedeutet Fail Closed statt versprochener Versandverfügbarkeit.
- **Regression:** KT-01/07/11/18; gequeueute alte Ciphertexte gesondert prüfen. Deadline-Fixes M01 verhindern lokale Fristüberschreitung, lösen dieses Risiko nicht.

#### KTAR-H03 – Witness-Auswahl, Quorum und Rotation sind nicht festgelegt

- **Art/Status:** bestätigte Spezifikationslücke; Release-Blocker, konkrete Topologie Forschungs-/Entscheidungsfrage.
- **Ort:** ADR §§ 2, 5, 7, 9, Zeilen 32–37, 75, 121, 139–140.
- **Voraussetzungen:** Relay bietet eigene Witness-Schlüssel an, Betreiber kontrolliert mehrere scheinbar unabhängige Instanzen oder trennt Quoren/alte und neue Epochen.
- **Auswirkung:** gefälschte Vertrauensbasis, Doppelaktivierung oder unerkannter Split View mit formal gültigen Signaturen; Ausfall aller erforderlichen ehrlichen Mitglieder sperrt Verfügbarkeit.
- **Nachweis:** `n=3,q=2,f=1`: `{ehrlich A, bösartig B}` und `{B, ehrlich C}` können verschiedene Nachfolger bestätigen; B ist der einzige Schnitt. Bloße Mehrheit reicht hier nicht. Signieren A/C nur Log-Roots, gilt sogar die zusätzliche Aktivierungsschutzregel noch nicht.
- **Behebung/offene Entscheidung:** gepinnte Roster-/Log-Konfiguration, Fehlerbudget, echte organisatorische Unabhängigkeit, Sybil-Abwehr, dauerhaftes Nicht-Doppelsignieren, sichere Rotation und Cross-Epoch-Konsistenz entscheiden. Keine Roster-Ersetzung allein durch neue selbst attestierende Schlüssel. Bedingungen und Beispielquorum im ADR sind keine gewählte Konfiguration.
- **Regression:** KT-05/08/16/20/21, einschließlich doppelter Stimmen, Witness-Neustart, gemeinsamem Betreiber und nicht überlappenden Epochen.

#### KTAR-H04 – Private Labels allein bieten keinen nachgewiesenen Metadatenschutz

- **Art/Status:** bestätigte Designlücke; Release-Blocker; konkrete Privacy-Konstruktion offen.
- **Ort:** ADR §§ 5, 9, Zeilen 70, 132–143.
- **Voraussetzungen:** Operator/Auditor sieht Zustandsdaten, deterministische Hashes, gleiche Keys/Roots oder korrelierbare Lookup-/Update-Muster; Kontakte geben Belege weiter.
- **Auswirkung:** Verknüpfung von Kontakten, Geräten und föderierten Identitäten trotz verschiedener Labelnamen. Ein neues DID oder ein öffentliches Lookup-Verzeichnis kann dieselben Links erweitern.
- **Nachweis:** zwei verschiedene Labels enthalten denselben sichtbaren State-Hash/Root-Key; einfache Gleichheit verknüpft die Einträge. Ein unsalziger Hash versteckt bekannte State-Daten nicht. Ein seltener Log-Endpunkt, gleichzeitige Polls und Geräteupdates bleiben Nebenkanäle.
- **Behebung/offene Entscheidung:** Datenminimierung, Proof-Zugriff, Discovery-Bindung, Query-Privacy, Transport, Retention, Churn, Padding und Messgrößen spezifizieren. Verifikation der Manager-/Aktivierungsregeln durch Witnesses kann mit deren gewünschter Unkenntnis des Identity-Bindings kollidieren; ein geprüfter Ansatz muss diese Komposition lösen.
- **Regression:** KT-09/13/14/20, kontrollierte Enumeration und Korrelationsmessung pro Rolle. Die ergänzte Risikomatrix belegt Risiken, keine erfüllten Datenschutzgarantien.

#### KTAR-H05 – Inclusion eines States ist kein authentifizierter aktueller Lookup

- **Art/Status:** bestätigte fehlende Head-/Suchsemantik; Release-Blocker.
- **Ort:** ADR §§ 3, 5, 6.B, Zeilen 42–43, 70–76, 93–94.
- **Voraussetzungen:** Log/Relay zeigt alten gültigen State A in aktuellem Checkpoint C; späterer Widerruf B ist ebenfalls enthalten, wird aber beim Lookup verborgen.
- **Auswirkung:** alte Geräteauswahl kann alle beschriebenen Log-Proofs erfüllen. Ein falscher Discovery-Pfad könnte stattdessen zu einem konsistenten Angreiferaccount führen.
- **Nachweis:** Inclusion(A,C) und Consistency(Calt,C) sagen nichts darüber aus, ob B eine spätere relevante Identity-Änderung ist. Ein frischer Nonce auf C ergänzt diese fehlende Aussage nicht.
- **Behebung/offene Entscheidung:** authentifizierte aktuelle Zuordnung oder vollständig überprüfbare Such-/Monitoringsemantik auswählen; erwarteten Kontakt-Pin bis Label und ausgewähltem State binden. Aktueller globaler Log-Head und aktueller Identity-Head separat nachweisen. Inclusion/Consistency nicht zu einem vermeintlichen Latest-Proof umdeuten.
- **Regression:** KT-01/03/09/20: neuen Checkpoint mit alter Inclusion, ausgelassenem Widerruf und fremdem konsistentem Account anbieten; keine Aktivierung/Empfängerfreigabe.

#### KTAR-H06 – Transparenz verhindert formal erlaubten Manager-Missbrauch nicht

- **Art/Status:** bestätigtes vorhandenes Policy-Risiko KISR-H02/SR-09; offen, Release-Blocker für Hochrisiko-Freigabe; kein neuer Rechte-Bypass.
- **Ort:** ADR § 8, Zeilen 128–130; `authority.py:24–65`, Authority Policy §§ 5, 7.
- **Voraussetzungen:** kompromittierter aktiver Manager und alle sonst erforderlichen Belege.
- **Auswirkung:** gültige Aufnahme eines fremden Messaging-Geräts oder Widerruf legitimer Geräte, möglicherweise terminale Stilllegung. Eine korrekte Transparenzprüfung kann diese gültige Action bestätigen.
- **Nachweis:** bestehender `test_compromised_manager_can_add_messaging_and_revoke_another_manager_within_policy` erfolgreich erneut ausgeführt. Root/Device/Session-Schlüsseltrennung ändert die expliziten Managerrechte nicht.
- **Behebung/offene Entscheidung:** zusätzliche unabhängige Bestätigung/Quorum, Hardware-Isolation und letzte-Manager-Regeln gesondert entscheiden. Keine neue Root-Unterschrift oder andere Managerpolicy in diesem Dokumentationsreview eingeführt.
- **Regression:** KT-10 und vorhandene Manager-/NO_RECOVERY-Tests. Erst nach ausdrücklichem Policyentscheid zusätzliche Pflichtfreigaben testen.

### MEDIUM

#### KTAR-M01 – Ungültiger Proof und spätere Fork-Erkennung wurden überinterpretiert

- **Art/Status:** bestätigte unbedingte Dokumentaussage korrigiert; konkrete Proof-/Quarantäne-/Gossip-Policy offen.
- **Ort:** ADR §§ 6.D, 7, Test KT-02; Zeilen 104–108, 122, 158.
- **Voraussetzungen:** Relay liefert kaputten Proof oder trennt ehrliche Clients dauerhaft; beide behalten intern konsistente Sichten.
- **Auswirkung:** falsche portable Schuldzuweisung/Quarantäne oder unbegründete Zusage späterer Erkennung. Falsche dauerhafte Quarantäne wäre ein DoS-Pfad.
- **Nachweis:** unsignierte Zufallsbytes können nicht beweisen, dass ein Log zwei Sichten signiert hat. Verschiedene Baumgrößen können normale Erweiterungen sein. Zwei gültige Device-Siblings sind ein Identity-Fork, nicht zwingend ein Log-Fork.
- **Behebung:** ADR trennt authentische Beweisklassen, Ablehnung und Verdacht. Gleich große authentische Log-Heads mit verschiedener Root bei gleicher Konfiguration sind direkte Konfliktbelege; weitergehende Fälle brauchen spezifizierte Proofs. Gossip benötigt einen ehrlichen erreichbaren Vergleichspfad; kein garantierter Alarm bei dauerhafter Zensur. Quarantäne blockiert neue Aktivierung/Verschlüsselung für die strittige Identität ohne Pin-Reset.
- **Regression:** KT-02/17/22; kompatible Heads und unauthentische Behauptungen dürfen keinen bewiesenen Incident erzeugen.

#### KTAR-M02 – Überschrittene Kollusionsannahmen sind nicht zwingend sichtbar

- **Art/Status:** bestätigter Dokumentationsfehler, korrigiert; Trust-Risiko H03 bleibt.
- **Ort:** ADR Test KT-05, Zeile 161.
- **Voraussetzungen:** genug kolludierende Log-/Witness-Schlüssel für die vom Client verlangten Signaturen; ehrlicher Vergleich verhindert.
- **Auswirkung:** Client akzeptiert eine intern konsistente falsche Sicht ohne irgendeinen lokal sichtbaren Beweis einer Annahmeverletzung.
- **Nachweis:** dieselbe Folge signierter Antworten kann lokal aus einer ehrlichen Welt mit nur diesen Zuständen oder einer kolludierenden Welt mit verborgenem Fork stammen. Der Client kann diese Abläufe ohne zusätzliche Beobachtung nicht unterscheiden.
- **Behebung:** KT-05 verspricht nur noch Safety innerhalb eines ausdrücklich beschlossenen Fehlerbudgets; außerhalb davon keine garantierte Erkennung. Witness-Unabhängigkeit als begrenzte Annahme dokumentiert.
- **Regression:** KT-05/22 müssen die nicht unterscheidbaren Fälle modellieren; kein Test darf „Annahmeverletzung sichtbar“ ohne erreichbaren zusätzlichen Beobachter voraussetzen.

#### KTAR-M03 – RAM-Atomarität reicht nicht für Checkpoint-/Identity-Persistenz

- **Art/Status:** bestätigte offene Integrationslücke; kein neu reproduzierter Core-Fehler.
- **Ort:** ADR § 10, Zeilen 149–151; `state_machine.py:254–266`, `history.py:1–26`.
- **Voraussetzungen:** Crash zwischen getrennten Writes, zurückgesetzter Cache oder Host setzt Pins vor abgeschlossener Autorisierung.
- **Auswirkung:** Head/Pins/Quarantäne inkonsistent; wiederholte alte Zustände oder vorzeitig freigegebene Empfänger nach Neustart.
- **Nachweis:** Core committet nur eine RAM-Referenz. `save(checkpoint); apply(action)` und die umgekehrte Folge sind beide ohne gemeinsame Transaktion crashanfällig. Ein monotonic-Startwert hat über Neustarts keine definierte identische Zeitbasis.
- **Behebung/offene Entscheidung:** dauerhaften Gesamtcommit mit Identity-History/Tombstones, High-Watermark, Roster, Freigabebeleg und Incidentstatus spezifizieren; nur danach verschlüsseln. Rollback-Resistenz verlangt eine zusätzliche vertrauenswürdige Speicher-/Ankerannahme; Verschlüsselung allein erkennt alte gültige Datenträgerkopien nicht.
- **Regression:** KT-12/18/19, Fault-Injection an jeder Persistenzgrenze; alte Ciphertexte/Backups dürfen Pins nicht zurücksetzen.

#### KTAR-M04 – Proof-Vertrag und Ressourcenbudgets sind noch nicht ausführbar

- **Art/Status:** bestätigte offene Spezifikationslücke, keine heute erreichbare Transparency-Parser-Lücke.
- **Ort:** ADR §§ 5, 10, Test KT-13; Zeilen 68–79, 149–151, 169.
- **Voraussetzungen:** adversariales Relay liefert übergroße/nichtkanonische Proofs, große Baumzähler, tiefe Strukturen, Algorithmusverwechslung oder lange Historien.
- **Auswirkung:** CPU-/Speicher-DoS, Cross-Context-Replay oder fehlerhafte Verifikation bei späterer naiver Integration.
- **Nachweis:** kein Wire-Schema, Baumbudget oder Parser existiert. Das Core-Limit 65.536 Byte ersetzt weder Proof-Knotenzahl noch Gesamtbudget für Catch-up. KISR-M05 beschreibt bereits unbeschränkte RAM-History.
- **Behebung/offene Entscheidung:** etablierte Suite/Encoding, getrennte Signaturzwecke, Log-/Epoch-/Policy-Bindung, Leaf-Index-/Tree-Size-Grenzen, Knotenzahl, Byte-/Zeit-/History-Budgets, fehlende/überzählige Elemente und Deduplikation definieren. Ablehnung muss alle Pins unverändert lassen; keine stillen Tombstone-Löschungen.
- **Regression:** KT-13/21; bekannte Fremdvektoren plus fuzz/property Tests erst nach entschiedenem Schema. Kein erfundenes kryptografisches Format oder eigener Merkle-Algorithmus ergänzt.

#### KTAR-M05 – Historischer Catch-up darf nicht zum Recovery-/Authority-Bypass werden

- **Art/Status:** bestätigte fehlende Integrationsspezifikation; Architektur enthält ausdrücklich NO_RECOVERY, kein gegenwärtiger Bypass nachgewiesen.
- **Ort:** ADR §§ 6.C, 10, KT-15; Zeilen 98–102, 147–151, 171; KISR-I02.
- **Voraussetzungen:** zukünftiger Host importiert alte Genesis/History, verwirft Terminalstatus/Tombstones oder hält historischen Nachweis für aktuelle Geräteautorisierung.
- **Auswirkung:** unzulässige Wiederherstellung alter Identität oder Reaktivierung entzogener Schlüssel; derzeitiger Kern stellt keinen Import bereit.
- **Nachweis:** historische Signaturen belegen eine damalige Action, nicht heute nutzbare private Geräteschlüssel oder heutigen aktuellen Head. `apply()` lehnt abgelaufene Actions bewusst ab; ein neuer Catch-up-Pfad muss historische Prüfung von neuer Aktivierung trennen.
- **Behebung/offene Entscheidung:** Read-/Monitoring-Catch-up strikt von schlüsselhaltender Geräteverwaltung trennen; Terminalstatus und Schlüsselreuse-Regeln dauerhaft erhalten. Nach Verlust aller autorisierten Geräte nur neue Identität und Kontaktverifikation, kein Root-only-/Server-/Log-Restore.
- **Regression:** KT-06/15/19; alle heutigen Terminal-, Key-Reuse- und Root-only-Negativtests erhalten. Reinstallation darf keine alternative alte Genesis erlauben.

### LOW

#### KTAR-L01 – Gate-Namen und behaupteter Dokumentationsstand waren missverständlich

- **Art/Status:** bestätigter Dokumentationsfehler, korrigiert.
- **Ort:** ADR § 12, Zeilen 177–182; Threat Model Release-Gates G0–G3.
- **Voraussetzungen:** Reviewer verwechselt gleich benannte ADR-Schritte mit verbindlichen Projektgates oder liest „Privacy-Matrix dokumentiert“ als erfülltes Gate.
- **Auswirkung:** irrtümliche Freigabe trotz fehlender Matrix, Quorumpolicy und unabhängiger Prüfung.
- **Nachweis:** ursprüngliches ADR benannte G3 als Testnetz, während Projektgates eigene Freigabekriterien besitzen; § 9 bestand lediglich aus Fragen.
- **Behebung:** KT-G0–KT-G3 als zusätzliche Schritte benannt, offenen Status angegeben, minimale Risikomatrix ergänzt und Dokumentationsmerge ausdrücklich von Implementierungs-/Produktfreigabe getrennt.
- **Regression:** Dokumentreview muss KT-G1 offen und normative G0–G3 unverändert vorfinden. Keine maschinellen Tests für reine Textpräzisierung eingeführt.

### INFORMATIONAL

#### KTAR-I01 – Referenzprotokolle liefern keine automatische KryptaChat-Garantie

Geprüft am Reviewtag: [IETF Key Transparency Architecture, Revision 10](https://www.ietf.org/ietf-ftp/internet-drafts/draft-ietf-keytrans-architecture-10.html),
2026-10-07, **Internet-Draft / Work in Progress**, angestrebter Status
Informational. Besonders §§ 3.3, 4, 7–9: Fork-Vergleich, deploymentabhängige
Monitoring-/Trust-/Zustandserhaltungsannahmen, Privacy und Discovery-Bindung.
Diese Voraussetzungen sind für KryptaChat nicht implementiert. Die nötigen
Erreichbarkeits-/Nichtkollusionsannahmen dürfen nicht still übernommen werden.

[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) ist ein
**Experimental RFC**, kein Internet Standard. §§ 2.1.3/2.1.4 unterscheiden
Inclusion und Append-only-Consistency; § 11.3 behandelt Log-Missverhalten.
CT protokolliert Zertifikate: seine Baumbeweise wählen keinen aktuellen
KryptaChat-Geräte-Head und serialisieren keine Manageränderungen. Keine direkte
Übernahme als neue Projektnorm oder Komplettlösung vorgeschlagen.

## 4. Bedingtes Quorum- und Partitionsargument

Eigenes Mengenargument, **keine** Implementierung eines Konsensalgorithmus:
Bei einem festen authentifizierten Roster mit n Mitgliedern und q verschiedenen
Stimmen pro Zertifikat ist der kleinste Schnitt zweier Quoren `2q-n`.
Bei höchstens f byzantinischen Mitgliedern muss `2q-n > f` gelten, damit der
Schnitt mindestens ein ehrliches Mitglied enthält. Dieses darf widersprüchliche
Aktivierungen desselben Slots nicht signieren, auch nicht nach Crash/Viewwechsel.
Für Fortschritt ohne f ausgefallene Stimmen ist zusätzlich `q <= n-f` nötig.

`n=4,f=1,q=3` erfüllt diese Mengenbedingungen. Sie allein spezifizieren weder
Leaderwahl, sichere Locks, Epoch-Übergänge, Partitionsheilung noch Liveness.
Das ist ausdrücklich **kein gewähltes KryptaChat-Quorum**. Unterschiedliche
Roster oder Aktivierungsslots pro Kontaktlabel machen das Argument ungültig.
Für Availability auf jeder dauerhaft isolierten Seite gleichzeitig mit globaler
Exklusivität fehlt die erforderliche gemeinsame Entscheidung. Fail Closed bei
fehlendem exklusiven Zertifikat ist dann eine Produktfolge, keine Log-Störung,
die durch lokale Mehrheits-/Timestampauswahl umgangen werden darf.

## 5. Korrekturen und noch erforderliche Entscheidungen

Geändert werden ausschließlich das ADR und dieser neue Bericht. Korrekturen:
Beweisklassen/Gossipgrenzen; Kollusions-Test ohne garantierte Erkennung;
eindeutige KT-Gates. Ergänzte offene Verträge: S-Quorum/Bootstrap/Rotation,
aktueller Lookup, Frist an bestehender Session, atomare Persistenz, NO_RECOVERY,
Privacy-Risikomatrix und KT-16 bis KT-22. Kein Code, neuer Test, Lock- oder
Workflow-Änderung; keine neue DID-/Manager-/Recovery-/Kryptosuiteentscheidung.

Vor Implementierungsfreigabe erforderlich: explizites S/D-Modell; überprüfte
Trust-/Konsens-/Epoch-Regeln; frischer authentifizierter Lookup; definierte
Widerrufswirksamkeit und Uhr-/Offlinegrenzen; gemessene Privacy-Konstruktion;
persistente atomare Pins samt Budget; getrennt entschiedene Managerhärtung;
unabhängiges Designreview. Nicht als erledigt markieren, weil Anforderungen nun
präziser aufgeschrieben sind. Die KT-Testmatrix beschreibt zukünftige Arbeit.

## 6. Neue lokale Prüfungen und Änderungsintegrität

Ausgeführt im exakten PR-#3-Checkout plus Dokumentationspräzisierungen:
CPython 3.13.15, uv 0.12.5; `UV_OFFLINE=true`, beschreibbarer Cache
`UV_CACHE_DIR=/tmp/krypta-identity-uv-cache`, frische isolierte venv aus Lock.
Ein erster Aufruf ohne Cache-Override scheiterte am read-only Standardcache;
nach korrektem Override wurden alle geforderten Kommandos erfolgreich ausgeführt.

| Kommando | Ergebnis |
|---|---|
| `uv sync --locked` | 23 Packages aufgelöst, 22 installierte Fremdpakete geprüft |
| `uv run pytest -v` | 94 bestanden, keine übersprungen; deterministisches Hypothesis-Profil |
| `uv run ruff check .` | Erfolgreich |
| `uv run mypy src` | Erfolgreich, 13 Quelldateien |
| `uv lock --check` | Erfolgreich, 23 Packages |
| `git diff --check` | Erfolgreich |

M01/M02/M03/L01/L03-Regressionstests bestehen auf unverändertem PR-#2-Code;
das ist keine unabhängige Review-Freigabe. Keine künftigen KT-Tests behauptet.
Die vier normativen Dateien bleiben bytegleich zum PR-#3-Ausgangsstand:

| Datei | SHA-256 |
|---|---|
| `security/threat-model.md` | `0e965c3b075973cfb898dcab955bc5b56f06c5369b9a337c92773353c91f68b2` |
| `security/identity-protocol.md` | `60e4e3c2c104af8a38384b6e580278cbc3822224487ec5a24407adfa07f97ddd` |
| `security/identity-authority-policy.md` | `c9c85658d7a166a6a9c90875717ff29c71845916b27e1dee656e49cd3966b7f5` |
| `security/review-2026-10-08.md` | `682bd00fb37d53d818a7e0f2262bd6b59b72800142d69dddb3668a74ab118f13` |

Source, Tests, `pyproject.toml`, `uv.lock`, Workflow und bestehende Reviews sind
unverändert. Nur zwei Markdown-Dateien sind im Review-Commit enthalten; keine
Privatschlüssel, Zugangsdaten oder ausführbaren Payloads hinzugefügt.
Lock-/Wheel-/Provenancegrenzen KISR-M04/L02 bleiben wie dokumentiert; keine
erneute vollständige Advisory-/Native-Build-Attestierung in diesem Architekturreview.

## 7. Merge-Gates und nächste Schritte

| Gate aus Issue #4 | Bewertung / erforderlicher nächster Schritt |
|---|---|
| PR #2: unabhängige Prüfung M01/M02/M03/L01/L03 | **BLOCKIERT**: Reviews-Liste leer; Reviewer dieses Berichts nicht unabhängig. Externer Reviewer muss Fixes und Reproduktionen am aktuellen Head prüfen |
| PR #2: aktueller Head und CI grün | Erfüllt für oben genannten Head; vor späterem Merge neu prüfen |
| PR #3: Architekturreview, keine ungelöste bestätigte CRITICAL, HIGH als Release-Blocker | Dokumentationsumfang geprüft; drei Textfehler korrigiert, sechs HIGH explizit offen. Kein Gesamt-Sicherheitsnachweis oder unabhängiger Approval |
| PR #3: Base/Diff nach PR-#2-Merge prüfen | **NICHT BEGONNEN**, weil #2 nicht gemergt. Base bleibt bewusst Review-Branch; nicht vorzeitig retargeten |
| PR #1: finaler integrierter Head, alle fünf Checks + aktuelle CI | **NICHT ERREICHT**: keine Integration; PR-#2-CI ist kein Ersatz |
| Branch Protection / Required Reviews | Branch-Liste meldet `protected:false`, Rulesets leer; detaillierter Protection-Read nicht autorisiert. Vor späterem Merge effektive Regeln und Issue-Gates erneut prüfen; keine Umgehung |

Keine PRs gemergt, kein Merge-SHA entstanden, keine Drafts auf Ready gesetzt,
keine eigenen unabhängigen Approvals, kein Force-Push. Review-Korrekturen werden
als neuer Commit auf dem vorhandenen PR-#3-Branch veröffentlicht; dessen exakter
neuer Head und Live-Checks stehen im PR und Abschlussbericht. Bei konkurrierendem
Branch-Update muss neu verglichen werden, kein Überschreiben.

Nach tatsächlich unabhängiger Freigabe: PR #2 nach Feature mergen; PR #3 auf
Feature-Base kontrolliert abgleichen, Diff/Tests/aktuellen CI-Lauf erneut prüfen;
erst dann #3 integrieren. Anschließend PR #1 am finalen Feature-Head vollständig
testen und alle erforderlichen Checks/Reviews vor `main` erfüllen.

**Ein bestandener Testlauf und dieses interne Review sind kein vollständiger
Sicherheitsnachweis.**
