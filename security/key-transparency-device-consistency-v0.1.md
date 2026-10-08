# KryptaChat — Key Transparency & Device Consistency Protocol v0.1

**Status:** Architekturvorschlag / Discussion Draft, 2026-10-08. **Nicht implementiert, nicht auditiert, keine Sicherheitsgarantie.**  
**Scope:** Kryptografisch überprüfbare Veröffentlichung, Beobachtung und Konsistenz von Geräteautorisationen für asynchrone, föderierte Kontakte. Kein Relay, kein produktiver Witness, keine Messaging-Kryptografie.  
**Normative Projektgrundlagen:** [Threat Model](threat-model.md), [Identity Protocol](identity-protocol.md), [Identity Authority Policy](identity-authority-policy.md), [Identity Security Review](identity-security-review-2026-10-08.md), besonders SEC-I05, SEC-M01/03/04, KISR-H01/H02 und `NO_RECOVERY`. Diese Dokumente werden durch diesen Draft **nicht** geändert.

## 1. Problem und Nichtziele

Der lokale Python-Kern prüft Signaturen, Rollen, Generationen, Hash-Verkettung und atomare Übernahmen. Ein vertrauenswürdiger `FreshnessVerifier` kann die Beobachtung eines bestimmten Candidate-Hash bestätigen. Dies beweist **weder**, dass alle anderen Clients denselben Head sehen, **noch**, dass parallel keine weitere gültige Änderung bestätigt wurde, **noch**, dass ein Widerruf überall angekommen ist. Eine signierte, alte Liste ist weiterhin signiert.

**Schutzziele:**
- Unerlaubte Schlüsselersetzung, Rollback und nachweisbare widersprüchliche Ansichten erkennen.
- Bereits geprüfte Checkpoints lokal pinnen; kein stilles Zurückfallen.
- Eine nachvollziehbare Obergrenze für *beobachtbare* Staleness festlegen, einschließlich Offline-Fall.
- Keine öffentliche Liste personenbezogener Accounts, Kontaktgraphen oder DIDs voraussetzen.
- Relay-Server als vollständig nicht vertrauenswürdig behandeln.
- Privaten Kontakten ermöglichen, Zustandsbelege über E2EE auszutauschen, ohne einen globalen Identifikator öffentlich zu verbreiten.

**Nichtziele / explizite Nicht-Garantien:**
- Keine absolute globale Gleichzeitigkeit oder sofortiger Widerruf bei Netzwerkpartition/Offline-Clients.
- Kein Schutz gegen vollständige Kontrolle eines aktiven Endgeräts.
- Kein garantierter Metadatenschutz gegen einen globalen passiven Beobachter.
- Kein `NO_RECOVERY`-Bypass: verlorene oder terminale Identität kann durch Transparenzsystem nie restauriert werden.
- Dieser Draft beschließt **noch keine** konkreten Lease-Zeiten, Auditor-Quoren, Log-Kryptosuite oder DID-Methode.

## 2. Angreifer, Vertrauen, Grenzen

| Akteur | Kann | Darf nicht stillschweigend als vertrauenswürdig gelten |
|---|---|---|
| Relay | Antworten blockieren, zurückhalten, wiederholen, umordnen, Clients isolieren | Geräteautorisation, Frische, Log-Zustand |
| Directory/Log-Operator | Split Views, veraltete Checkpoints, verweigerte Proofs liefern | Alleiniger Wahrheitseigentümer |
| Auditor/Witness | Eigene Sicht zurückhalten, falsch signieren, mit Operator kolludieren | Unfehlbar oder unabhängig ohne überprüfte Annahme |
| Kontakt/Client | Offline sein, alte Checkpoints behalten, authentische Belege verteilen | Stets erreichbar oder ehrlich |
| Berechtigter Manager | Laut aktueller Policy Messaging-Geräte hinzufügen und andere Geräte widerrufen | Schutz vor Kompromittierung allein durch Key Transparency |
| Netzwerkgegner | Polls korrelieren, verzögern, blockieren | Unfähigkeit zur Staleness durch Partitionsangriff |

**Zwingend zu dokumentierende Annahmen:** vertrauenswürdiger lokal gepinnter Root/Checkpoint, sichere Signaturprüfung, lokale monotone Zeitbasis nur für Antwortfenster; unabhängig verifizierbare Zeitschranken erfordern zusätzliche Annahmen über Uhr und Zeitatttestierung. Witness-Anzahl ersetzt keine belegte Nichtkollusion.

## 3. Abgrenzung der drei unterschiedlichen Aussagen

1. **Authorization-valid:** Ein Transition wurde mit dem korrekten vorherigen Zustand und den nach Policy nötigen Signaturen geprüft.
2. **Consistency-valid:** Der angebotene Zustand hängt nachweisbar von einem zuvor gepinnten Log-Checkpoint ab und referenziert eine überprüfbare identitätsbezogene Historie. Ein Inclusion-Proof ist kein Consistency-Proof.
3. **Fresh-enough:** Ein überprüfbarer Beobachtungsbeleg erfüllt die spezifizierte Alters- und Witness-Policy. Selbst dann ist kein universell sofortiger Widerruf bewiesen.

**Nie** ein einziges Boolean wie `verified=true` für alle drei Eigenschaften verwenden.

## 4. Vorläufiges Rollenmodell

```text
Identity State Machine (Python, local and authoritative for policy)
    | signed candidate state, prev hash, generation
    v
Privacy-preserving Transparency Publication (design undecided)
    | inclusion + consistency + checkpoint evidence
    v
Independent Witness/Auditor observations (separate trust domain)
    | authenticated attestations + fork alarms
    v
Client Proof Verifier -> pinned persistent checkpoint + recipient-specific decision
    |
    +-- E2EE session/device selection: allow or fail closed
```

Relay und Transparenzdienst bleiben getrennt. Log-Operator und Witness können organisatorisch getrennt betrieben werden; die tatsächlich angenommene Unabhängigkeit muss überprüfbar beschrieben werden. Ein zentrales frei durchsuchbares Accountverzeichnis widerspricht dem Threat Model.

## 5. Log- und Zustandsschnittstelle (noch kein Wire-Standard)

Vorläufige abstrakte Datentypen; **keine** verbindliche JSON-/Python-Schemafestlegung:

- `IdentityStateCommitment`: versionierte, domänengetrennte Bindung an Identity Root, Generation, State Hash und vorherigen State Hash. Kontaktspezifische Pseudonyme nur nach Privacy-Review.
- `SignedTransitionProof`: schon bestehende Signaturen/Autorisierungen; kein Server als Authorizer.
- `LogCheckpoint`: Log-ID, Protokoll-/Cipher-Suite, monotoner Baumzustand/Sequenz, Root Digest, Signatur und ggf. attestierte Zeit.
- `InclusionProof`: belegt die Aufnahme eines konkreten Commitments in einen benannten Checkpoint.
- `ConsistencyProof`: belegt, dass ein neuer Checkpoint die bisher gepinnte Historie fortsetzt.
- `WitnessStatement`: Signatur über exakt Log-ID, Checkpoint-Digest, Epoch und kontextgebundene Gültigkeitsbehauptung.
- `FreshnessObservation`: Challenge-Nonce, Kandidaten-Hash, Identity Binding und die dafür erforderlichen Belege; keine globale Lease allein wegen einer kurzen Laufzeit.
- `EquivocationEvidence`: zwei nicht vereinbare, authentisch beweisbare Ansichten.

Alle Belege müssen Domain Separation, Versions-/Algorithmusbindung und strenge Größenlimits besitzen. Canonical Encoding, Hashfunktion, Key-ID/Rotation und Migrationsstrategie sind **offen**. Keine selbst entwickelte Merkle-Kryptografie implementieren.

## 6. Protokollabläufe (Entwurf)

### A. Veröffentlichung einer Geräteänderung
1. Client validiert lokal den signierten Candidate gegen den gepinnten Parent.
2. Client reicht den Candidate bzw. ein minimiertes Commitment über einen noch zu prüfenden Privacy-Kanal ein.
3. Der Dienst liefert erst eine Einreichungsquittung; **Quittung bedeutet nicht Aktivierung**.
4. Ein überprüfbarer Checkpoint bindet die Veröffentlichung ein. Client prüft Inclusion und Consistency gegen seinen vorigen gepinnten Checkpoint.
5. Unabhängige Witness-Beobachtungen werden entsprechend einer **noch festzulegenden** Sicherheitsregel geprüft.
6. Erst nach erfolgreichem lokalem Autorisierungs-, Konsistenz- und Aktualitätsgate kann das Produktgerät den Candidate aktivieren. Bei unbestätigter Aufnahme: **nicht als aktiv markieren**.

### B. Neues Empfängergerät / neue Sitzung
1. Absender verwendet nur den lokal verifizierten Kontakt-Vertrauensanker.
2. Holen und prüfen der autorisierten Gerätezustandsfolge einschließlich eventuell geänderter Widerrufe.
3. Proofs gegen lokal gepinnte Checkpoints und die erforderliche Freshness-Policy prüfen.
4. Erst dann die Empfängergeräte auswählen und E2EE-Sitzungen vorbereiten.
5. Bei fehlender Frische/inkonsistentem Proof **kein** neues Verschlüsseln an die ungeprüften Geräte. Lokal gespeicherte Nachrichten dürfen lesbar bleiben.

### C. Wiedereinstieg nach langer Offline-Zeit
1. Gespeicherten letzten vertrauenswürdigen Checkpoint beibehalten.
2. Vollständige überprüfbare Brücke vom gepinnten zum neuen Checkpoint verlangen; unverifizierte Snapshot-Übernahme ist verboten.
3. Große Historien nur über **separat spezifizierte** persistente, verifizierbare Checkpoints kompaktieren, niemals still Tombstones/NO_RECOVERY-Sperren entfernen.
4. Kann kein konsistenter, ausreichend frischer Beleg geliefert werden: Fail Closed für Empfängerauswahl und kritische Management-Aktionen; Offline-Lesen bleibt möglich.

### D. Fork oder widersprüchliche Witness-Ansichten
1. Zwei authentische inkompatible Views als Security Incident behandeln.
2. Belege und lokalen Checkpoint unveränderbar sichern; keine automatische Auswahl nach höherer Generation, jüngerer lokaler Uhr oder Mehrheit ohne spezifizierte Policy.
3. Identität/Verbindung in Quarantäne; neue Schlüsselannahme und Versand an strittige Geräte blockieren.
4. Bei bestätigten Kontakten Hinweis mit konkreter Verifikationshandlung; Wiederaufnahme nur nach explizit definiertem und reviewtem Verfahren.

### E. Widerruf
1. Autorisierter Client signiert Widerruf nach bestehenden Rollenregeln.
2. Log/Witness-Policy muss Veröffentlichung und beobachtbare Verzögerung gesondert definieren.
3. Bis zur nachgewiesenen aktuellen Sicht kann ein isolierter Absender widerrufenes Gerät weiter als gültig ansehen. Das ist eine **unvermeidbare Grenze** des asynchronen Modells.
4. Nach Beobachtung des Widerrufs keine neue Empfängerverschlüsselung an widerrufenes Gerät; bestehende Sessions/Groups benötigen separate Rekey-Regeln.

## 7. Schlüsselrisiko KISR-H01: Zwei gültige konkurrierende Heads

Ein reines Append-only-Log kann auch **beide** konkurrierenden, jeweils korrekt signierten Änderungen archivieren. Das beweist Nachvollziehbarkeit, aber nicht, welcher Zustand aktiviert werden darf.

Vor produktiver Freigabe ist **eine** klare Semantik zu entscheiden und extern zu prüfen:
- **Option S (serialisierte Aktivierung):** linearisiert autorisierte, vergleichende State-Updates mit atomischer Parent-Check-Regel; Ausgabe eines eindeutig gebundenen Aktivierungsnachweises. Erfordert eine konkret spezifizierte Koordinationsinstanz/Konsensannahme.
- **Option D (Erkennung mit Quarantäne):** konkurrierende gültige Heads können zeitweise auftreten; Log/Gossip/Witnesses liefern später beweisbare Konflikte, und Clients blockieren strittige Identitäten. Keine Behauptung strikt einheitlicher Aktivierung.

**Empfehlung zur Prüfung:** Option S als Sicherheitsziel für neue Geräte und Widerrufe, Option D als erforderliche Fehlermodus-Abwehr. Vor dem Commit prüfen, ob S ohne zentralen Identitäts- und Metadatenanker innerhalb akzeptabler Partitionstoleranz erreichbar ist. Keine künstliche `current_head`-Abfrage als Konsensersatz.

## 8. Schlüsselrisiko KISR-H02: Kompromittierter Device Manager

Transparenz kann eine innerhalb der bestehenden Policy *gültige*, aber bösartige Aufnahme sichtbar machen; sie **verhindert** den Missbrauch einer gültigen Manager-Signatur nicht.

Separater Policy-Entscheid erforderlich: unabhängige zusätzliche Gerätebestätigung, Hardware-/OS-isolierter Manager, Mehrfachfreigabe für privilegierte Aktionen und Behandlung des letzten aktiven Managers. Nicht still in dieses Transparenzprotokoll hineinimplementieren.

## 9. Datenschutz und Föderation: offene Gate-Fragen

- Welche persistenten Label-/Checkpoint-Metadaten werden einem Log-Operator sichtbar?
- Wie werden Identität, Kontaktbeziehungen, Geräteanzahl, Updatezeiten und IP-Adressen gegen Verknüpfung geschützt?
- Wie können Clients aktuelle Zustände abrufen, ohne ein globales, durchsuchbares Namensverzeichnis aufzubauen?
- Haben verschiedene Kontakte eigene Lookup-Labels, und wie wird ohne Wiederverwendung desselben öffentlichen Schlüssels dennoch die richtige Gerätebindung nachgewiesen?
- Dürfen Auditoren private Labels sehen? Welche Zero-Knowledge-/Commitment-Ansätze wären notwendig und tatsächlich überprüft?
- Wie routet eine selbstgehostete, föderierte Identität zu ihrem Log, ohne eine zentrale Vertrauenswurzel einzuführen?
- Wie werden Trust Anchors, Witness-Schlüsselwechsel, Audit-Disputes und Log-Migration gesichert?
- Welche Nebenkanäle entstehen durch Lookup-Frequenz, Timing und ungewöhnliche Privacy-Modi?

**Freigabekriterium:** Eine Datenfluss-/Metadatenmatrix pro Rolle, inklusive Retention, Suchbarkeit, Korrelation, Churn und DoS. Keine unkritisch wiederverwendeten Identitätskennungen als öffentliche Directory-Labels.

## 10. Python-Integrationsvertrag (Entwurf, nicht implementieren)

Künftige getrennte Module: `transparency/models.py`, `proofs.py`, `checkpoints.py`, `witness.py`, `policy.py`, `client.py`. Keine Änderung der bestehenden `identity/`-Vertragslogik in diesem PR.

Eine Adapterantwort soll **typisiert** getrennte Resultate für `authorization`, `inclusion`, `consistency`, `witness_policy` und `freshness` liefern. Aktivierung nur bei vollständiger positiver Policy-Entscheidung; unbekannte Methoden, Algorithmen und fehlende Proofs sind Fehler.

Persistent gespeicherte Trust Anchors, High-Watermark und zuletzt gepinnter Checkpoint müssen Crash-/Rollback-resistent sein; ein RAM-only-Cache genügt nicht. Reentrancy, Ressourcengrenzen und Deadline-Probleme aus PR #2 bleiben explizite Regressionsthemen.

## 11. Testmatrix für spätere Implementierung

| ID | Adversariales Szenario | Erwartetes Resultat |
|---|---|---|
| KT-01 | Log sendet gültigen alten Checkpoint | Aktualitätsgate verweigert Freigabe |
| KT-02 | Checkpoint springt auf inkonsistenten Merkle-Verlauf | Ablehnen + prüfbarer Incident |
| KT-03 | Inclusion ohne Consistency | Keine Aktivierung |
| KT-04 | Zwei authentische konkurrierende Device-Heads | Keine stille Auswahl; nach S kein Doppel-Aktivierungsbeleg |
| KT-05 | Zwei kolludierende Witnesses / korrupte Quorum-Annahme | Annahmeverletzung sichtbar; keine unbegründete Garantie |
| KT-06 | Offline-Client nach 30 Tagen | Verifizierbarer Catch-up oder Fail Closed |
| KT-07 | Relay hält Widerruf zurück | Keine Falschbehauptung über Widerrufsfrische |
| KT-08 | Manipulierter Witness-Schlüssel/Rotation | Fail Closed |
| KT-09 | Geänderter kontaktbezogener Label-/Key-Binding-Proof | Fail Closed |
| KT-10 | Gültiger bösartiger Manager-Commit | Nur nach expliziter Manager-Policy; Transparenz allein nicht ausreichend |
| KT-11 | Netzwerkpartition / Zensur aller Auditoren | Sicherheit vor Verfügbarkeit, ohne unendliche Frische |
| KT-12 | Absturz nach neuer Quittung vor Checkpoint-Persistenz | Kein Rollback / keine unbestätigte Aktivierung |
| KT-13 | Riesige Proofs, lange Historien, Label-Enumeration | Budget und Datenschutzanforderungen |
| KT-14 | Mehrere DIDs desselben Schlüssels oder gleiche Labels | Korrelation erkennen, kein Privacy-Versprechen |
| KT-15 | Wiederkehr nach letztem Geräteverlust | `NO_RECOVERY`, nur neue Identität |

Tests müssen echte gegnerische Mehrclient-/Mehrserver-Simulationen enthalten; nur lokale Unit-Tests genügen nicht.

## 12. Release-Gates und Reihenfolge

**G0 (diese ADR):** Angreifermodell, Privacy-Matrix, offene Aktivierungssemantik und Quorum-Annahmen dokumentiert.  
**G1 (Protokollentscheid):** formale Aussage über Safety/Liveness/Partitionen, Witness-Konfiguration, Fristen, Serialisierung, Schlüsselbindung, Recovery-Verbot und föderierte Log-Routing-Regeln; unabhängiges Designreview.  
**G2 (isolierter Proof-Verifier):** Python-Tests mit offiziellen/fremden Testvektoren, Negativfälle, deterministische Multi-Client-Simulation und Fuzzing. Keine Netzwerkinfrastruktur nötig.  
**G3 (Testnetz):** getrennte Operatoren, Datenschutzmessung, Partition/Offline/Widerrufs-Latenz, Incident-Übungen und unabhängiges Security Audit vor Hochrisiko-Einsatz.

**Kein Produkt-Release durch Erreichen von G0–G2 allein.**

## 13. Noch ausdrücklich zu entscheidende Punkte

1. Option S versus D und Sicherheits-/Verfügbarkeitskompromiss bei Netzwerkpartitionen.
2. Fehlertoleranz und Unabhängigkeit der Auditoren/Witnesses; keine willkürliche Quorum-Zahl.
3. Belegbare maximale Veröffentlichungslatenz, Staleness-Toleranz und Uhrannahmen.
4. Private Lookup-Labels und minimale öffentliche Informationen bei föderierten Servern.
5. Checkpoint-/History-Persistenz, langfristiger Offline-Catch-up und Kryptosuite.
6. Policy-Härtung gegen aktive Managerkompromittierung (separate ADR).
7. Integrationspfad zur State Machine ohne Verlust bestehender atomarer Guards.

## 14. Hintergrundquellen (keine automatische Normativität)

- IETF *Key Transparency Architecture*, Internet-Draft, Stand 2026-10-07; Work in Progress: https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/
- RFC 9162, *Certificate Transparency Version 2.0*, Merkle Inclusion/Consistency und Split-View-Grenzen: https://www.rfc-editor.org/rfc/rfc9162
- Vorhandene KryptaChat-Quellen: `security/threat-model.md`, `security/identity-protocol.md`, `security/identity-authority-policy.md`, `security/identity-security-review-2026-10-08.md`.

**Achtung:** Dies ist eine Architekturhypothese, keine Kombination bereits geprüfter Protokolle. Kein eigener Merkle-/Signaturalgorithmus und kein produktiver Dienst wird durch dieses Dokument autorisiert.
