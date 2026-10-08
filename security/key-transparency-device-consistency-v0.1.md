# KryptaChat — Key Transparency & Device Consistency Protocol v0.1

**Status:** Architekturvorschlag / Discussion Draft, 2026-10-08. **Nicht implementiert, nicht auditiert, keine Sicherheitsgarantie.**  
**Scope:** Kryptografisch überprüfbare Veröffentlichung, Beobachtung und Konsistenz von Geräteautorisationen für asynchrone, föderierte Kontakte. Kein Relay, kein produktiver Witness, keine Messaging-Kryptografie.  
**Normative Projektgrundlagen:** [Threat Model](threat-model.md), [Identity Protocol](identity-protocol.md), [Identity Authority Policy](identity-authority-policy.md), [Identity Security Review](identity-security-review-2026-10-08.md), besonders SEC-I05, SEC-M01/03/04, KISR-H01/H02 und `NO_RECOVERY`. Diese Dokumente werden durch diesen Draft **nicht** geändert.

**Review:** [Adversariales Architekturreview vom 2026-10-08](key-transparency-architecture-review-2026-10-08.md). Die folgenden Präzisierungen korrigieren unbedingte Erkennungsbehauptungen und benennen fehlende Verträge. S/D, Quorum, Fristen, Labels und Kryptosuite bleiben unentschieden. Alle dort aufgeführten HIGH-Befunde sind offene Release-Blocker; das Dokument ist keine Implementierungsfreigabe.

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

Ein Inclusion-Proof über einen alten Gerätezustand in einem **neuen** Checkpoint beweist nicht, dass dies der neueste Zustand dieser Identität ist. Vor Freigabe muss zusätzlich festgelegt werden, wie eine authentifizierte Suche bzw. vollständige identitätsbezogene Historie die Head-Auswahl und fehlende spätere Änderungen überprüfbar macht. Log-Konsistenz, Identitätskonsistenz, aktueller Lookup und Aktivierungsexklusivität sind verschiedene Eigenschaften.

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
- `WitnessStatement`: Signatur über exakt Log-ID, Checkpoint-Digest, Konfigurations-/Roster-Epoch und kontextgebundene Gültigkeitsbehauptung. Signaturzweck, Policyversion und Schlüsselkennung müssen eindeutig gebunden werden; mehrfache Signaturen desselben Witness zählen nicht mehrfach.
- `FreshnessObservation`: Challenge-Nonce, Kandidaten-Hash, Identity Binding, Generation, Parent-Bindung und die dafür erforderlichen Belege; keine globale Lease allein wegen einer kurzen Laufzeit. Ein Beleg für einen anderen Log, eine andere Policy/Epoch oder einen anderen Prüfzweck darf nicht wiederverwendet werden.
- `EquivocationEvidence`: zwei nicht vereinbare, authentisch beweisbare Ansichten.

Alle Belege müssen Domain Separation, Versions-/Algorithmusbindung und strenge Größenlimits besitzen. Canonical Encoding, Hashfunktion, Key-ID/Rotation und Migrationsstrategie sind **offen**. Keine selbst entwickelte Merkle-Kryptografie implementieren.

Einreichungsquittungen, auch signierte, erteilen keine Geräteberechtigung. Ein zukünftiges Aktivierungszertifikat müsste separat Identität, Parent, Generation, Kandidat und Konfiguration binden. Ein neuer Nonce-Nachweis bestätigt nur die spezifizierte Beobachtung; er macht ein historisches Commitment nicht automatisch zum aktuellen Head.

## 6. Protokollabläufe (Entwurf)

### A. Veröffentlichung einer Geräteänderung
1. Client validiert lokal den signierten Candidate gegen den gepinnten Parent.
2. Client reicht den Candidate bzw. ein minimiertes Commitment über einen noch zu prüfenden Privacy-Kanal ein.
3. Der Dienst liefert erst eine Einreichungsquittung; **Quittung bedeutet nicht Aktivierung**.
4. Ein überprüfbarer Checkpoint bindet die Veröffentlichung ein. Client prüft Inclusion und Consistency gegen seinen vorigen gepinnten Checkpoint.
5. Unabhängige Witness-Beobachtungen werden entsprechend einer **noch festzulegenden** Sicherheitsregel geprüft.
6. Erst nach erfolgreichem lokalem Autorisierungs-, Konsistenz-, Head-Lookup- und Aktualitätsgate sowie der **erst noch zu entscheidenden** S/D-Aktivierungsregel und dauerhafter atomarer Speicherung darf aktiviert werden. Dieser Ablauf ist heute nicht ausführbar spezifiziert. Bei unbestätigter Aufnahme: **nicht als aktiv markieren**.

### B. Neues Empfängergerät / neue Sitzung
1. Absender verwendet nur den lokal verifizierten Kontakt-Vertrauensanker.
2. Holen und prüfen der autorisierten Gerätezustandsfolge einschließlich eventuell geänderter Widerrufe.
3. Proofs gegen lokal gepinnte Checkpoints und die erforderliche Freshness-Policy prüfen.
4. Erst dann die Empfängergeräte auswählen und E2EE-Sitzungen vorbereiten.
5. Bei fehlender Frische/inkonsistentem Proof **kein** neues Verschlüsseln an die ungeprüften Geräte. Lokal gespeicherte Nachrichten dürfen lesbar bleiben.

Das künftige Produkt muss das Aktualitäts-/Widerrufsgate auch vor weiterer Nachrichtenverschlüsselung auf **bestehenden** Sessions prüfen. Eine einmal freigegebene Sitzung ist kein zeitlich unbegrenzter Empfängerstatus. Verhalten bei Warteschlangen, Suspend/Reboot und Ablauf zwischen Prüfung und Verschlüsselung ist separat zu spezifizieren.

### C. Wiedereinstieg nach langer Offline-Zeit
1. Gespeicherten letzten vertrauenswürdigen Checkpoint beibehalten.
2. Vollständige überprüfbare Brücke vom gepinnten zum neuen Checkpoint verlangen; unverifizierte Snapshot-Übernahme ist verboten.
3. Große Historien nur über **separat spezifizierte** persistente, verifizierbare Checkpoints kompaktieren, niemals still Tombstones/NO_RECOVERY-Sperren entfernen.
4. Kann kein konsistenter, ausreichend frischer Beleg geliefert werden: Fail Closed für Empfängerauswahl und kritische Management-Aktionen; Offline-Lesen bleibt möglich.

### D. Fork oder widersprüchliche Witness-Ansichten
1. Zwei authentische inkompatible Views als Security Incident behandeln. Ein kaputter oder fehlender Proof führt zu Fail Closed, ist allein aber **kein** kryptografischer Beweis für Log-Äquivokation.
2. Belege und lokalen Checkpoint unveränderbar sichern; keine automatische Auswahl nach höherer Generation, jüngerer lokaler Uhr oder Mehrheit ohne spezifizierte Policy.
3. Betroffene Identität/Verbindung in Quarantäne; bis zur geprüften Auflösung keine neuen Geräteaktivierungen oder neue Verschlüsselung für diese strittige Identität. Kein automatischer Reset der Pins.
4. Bei bestätigten Kontakten Hinweis mit konkreter Verifikationshandlung; Wiederaufnahme nur nach explizit definiertem und reviewtem Verfahren.

**Beweisklassen:** Zwei nach bestehender Authority Policy verifizierte Nachfolger desselben Identity-Parents bilden einen Gerätehistorien-Fork; ein Log, das beide archiviert, hat damit nicht notwendigerweise seine Append-only-Regel verletzt. Zwei gültig signierte Checkpoints desselben Log-Schlüssels und derselben Konfiguration mit gleicher Baumgröße, aber verschiedenen Roots sind dagegen direkt vergleichbare Log-Äquivokationsbelege. Verschiedene Baumgrößen oder verschiedene Log-IDs sind allein kein Konfliktbeweis. Weitere portable Beweise benötigen den noch festzulegenden Proof-/Signaturvertrag. Witness-Signaturen über verschiedene, kompatible Fortschritte sind kein Beweis einer Doppelabstimmung über denselben Aktivierungsslot.

**Erkennungsgrenze:** Getrennte Clients können dauerhaft intern konsistente Forks sehen. Spätere Erkennung setzt einen erreichbaren ehrlichen Vergleichspfad, geeignete gespeicherte Belege und die spezifizierte Monitoring-/Gossip-Policy voraus. Zensiertes Gossip, dauerhafte Partitionen und Kollusion außerhalb des Fehlermodells haben keine garantierte Erkennungsfrist. Der Fehler eines untrusted Relays darf nicht ohne authentischen Beleg eine dauerhafte Äquivokationsquarantäne fremder Kontakte auslösen.

### E. Widerruf
1. Autorisierter Client signiert Widerruf nach bestehenden Rollenregeln.
2. Log/Witness-Policy muss Veröffentlichung und beobachtbare Verzögerung gesondert definieren.
3. Ein isolierter Absender kann einen unbekannten Widerruf nicht erkennen. Er darf deshalb nur innerhalb einer **separat zu begründenden** Empfänger-Gültigkeitsgrenze verschlüsseln; ohne erforderlichen Nachweis oder nach deren Ablauf muss er sperren. Unvermeidbar ist die fehlende Kenntnis, nicht unbegrenzter weiterer Versand.
4. Nach Beobachtung des Widerrufs keine neue Empfängerverschlüsselung an widerrufenes Gerät; bestehende Sessions/Groups benötigen separate Rekey-Regeln.

**Keine derzeit beweisbare globale Maximalfrist:** Widerrufsabsicht, autorisierte Einreichung, globale Aktivierung und Kenntnis eines Absenders sind getrennte Ereignisse. Für eine Grenze ab Einreichung wären begrenzte Publikations-/Konsensverzögerung, ehrliche aktuelle Head-Beobachtung, begrenzte Empfängerfreigabe, überprüfte Zeitbasis und Prüfung an jeder Verschlüsselung nötig. Unter unbeschränkter Partition ist Veröffentlichung nicht zeitlich garantiert. Ein optionales späteres Lease-Verfahren müsste auch festlegen, wann ein Widerruf im Verhältnis zu noch gültigen alten Leases wirksam wird. Ein lokaler 30-Sekunden-Timer erfüllt das nicht; bereits verschlüsselte Inhalte werden nicht rückwirkend entzogen.

## 7. Schlüsselrisiko KISR-H01: Zwei gültige konkurrierende Heads

Ein reines Append-only-Log kann auch **beide** konkurrierenden, jeweils korrekt signierten Änderungen archivieren. Das beweist Nachvollziehbarkeit, aber nicht, welcher Zustand aktiviert werden darf.

Vor produktiver Freigabe ist **eine** klare Semantik zu entscheiden und extern zu prüfen:
- **Option S (serialisierte Aktivierung):** linearisiert autorisierte, vergleichende State-Updates mit atomischer Parent-Check-Regel; Ausgabe eines eindeutig gebundenen Aktivierungsnachweises. Erfordert eine konkret spezifizierte Koordinationsinstanz/Konsensannahme.
- **Option D (Erkennung mit Quarantäne):** konkurrierende gültige Heads können zeitweise auftreten; Log/Gossip/Witnesses liefern später beweisbare Konflikte, und Clients blockieren strittige Identitäten. Keine Behauptung strikt einheitlicher Aktivierung.

**Empfehlung zur Prüfung:** Option S als Sicherheitsziel für neue Geräte und Widerrufe, Option D als erforderliche Fehlermodus-Abwehr. Vor dem Commit prüfen, ob S ohne zentralen Identitäts- und Metadatenanker innerhalb akzeptabler Partitionstoleranz erreichbar ist. Keine künstliche `current_head`-Abfrage als Konsensersatz.

### Bedingungen an Option S, keine Auswahl eines Konsensprotokolls

- Checkpoint-Co-Signing attestiert einen Log-Verlauf, nicht automatisch einen exklusiven Geräte-Head. S benötigt eine eigene autorisierte State-Update-/Aktivierungssemantik mit Vergleich gegen den erwarteten Parent; dieselbe Identität darf nicht über verschiedene Kontaktlabels verschiedene Aktivierungsslots erhalten.
- Für ein **festes** Roster mit `n` Witnesses, bis zu `f` byzantinischen Mitgliedern und Zertifikaten mit `q` verschiedenen Stimmen haben zwei Quoren mindestens `2q-n` gemeinsame Mitglieder. Exklusivität über einen ehrlichen Schnitt braucht `2q-n > f` **und** eine dauerhafte Regel gegen widersprüchliche Abstimmungen im gleichen Konfliktbereich, einschließlich sicherer View-/Epoch-Wechsel. Für Fortschritt bei `f` nicht antwortenden Mitgliedern ist `q <= n-f` eine notwendige, allein nicht hinreichende Bedingung. Beispiel `n=4, f=1, q=3` illustriert nur diese Mengenargumente, keine beschlossene Policy oder vollständigen Konsensbeweis. Ein einfaches Mehrheitsquorum kann nur byzantinische Schnittmitglieder haben.
- Ohne gemeinsames exklusives Zertifikat müssen Partitionen Aktivierungen sperren. Globale Exklusivität und garantierter Fortschritt auf jeder getrennten Seite werden nicht gleichzeitig zugesagt. Synchronie-, Leader-/View-Wechsel- und Ausfallannahmen sind offene Entscheidungen.
- Selbsthosting/Föderation können die Infrastruktur verteilen, beseitigen aber keine Vertrauensannahmen. Ein einzelner Koordinator konzentriert Verfügbarkeit und Metadaten; mehrere Namen/Server desselben Betreibers sind keine unabhängigen Witnesses. Auswahl, Sybil-Abwehr, gemeinsame Betreiber-/Cloud-/Jurisdiktionsrisiken und Einblick in Geräteänderungen bleiben prüfpflichtig.
- Roster-/Log-/Schlüsselwechsel dürfen nicht durch das untrusted Relay bestimmt werden. Bootstrap-Pins, authentifizierte Konfiguration, Epoch-Übergang und fortgesetzte Konsistenz müssen eine Prüfung erlauben, die nicht allein neuen Schlüsseln vertraut. Ein Joint-Quorum-Verfahren wäre ein zu prüfender Vorschlag, keine hier beschlossene Konstruktion. Neue Auditoren belegen nicht automatisch die ganze alte Historie.

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

### Minimale Risikomatrix, keine beschlossene Datenschutzkonstruktion

| Datenfluss / Rolle | Mögliche Sichtbarkeit ohne zusätzliche Maßnahmen | Suchbarkeit / Korrelation | Retention und offene Entscheidung |
|---|---|---|---|
| Einladung / Kontakt | Root-Pin, Gerätehistorie, Log-/Witness-Routing; Inhalt nur für eingeladene Kontakte vorgesehen | Derselbe Root/Key/State-Hash verknüpft Kontakte bei Weitergabe | Lokale Aufbewahrung und Missbrauch durch Kontakte offen |
| Veröffentlichung / Operator | Labels, Commitments bzw. Zustandswerte je nach Konstruktion, Updatefolge, IP/Timing | Verschiedene private Labels schützen nicht bei identischen sichtbaren Keys/Hashes | Zugriff, Verschlüsselung/Commitment-Öffnungen, Batching/Padding und Löschbarkeit offen |
| Lookup / Operator oder Proxy | Ziel-Label, Quell-IP bzw. Proxy-IP, Frequenz, Response-Größe | Wiederholte Lookups und gleichzeitige Updates können Beziehungen offenlegen | Einladungsgebundener Zugriff, Query-Privacy, Cache-Fristen und Nichtprotokollierung offen |
| Audit / Witness | Mindestens Checkpoints und Update-Muster; bei vollständiger Rollenprüfung eventuell Gerätehistorien | Quorum-/Aktivierungsprüfung kann Labels oder Identitätsbindungen benötigen | Welche Aussagen ohne Klartext belegbar sind, muss ein geprüftes Verfahren zeigen |
| Gossip / Kontakt oder Auditor | Vergleichene Checkpoints und je nach Beleg betroffene Identity/Keys | Ungefilterte Konfliktbelege können Kontakt- oder Identitätsmetadaten veröffentlichen | Empfängerkreis, minimierte Belege und Aufbewahrung offen |
| Netzwerkbeobachter | Log-Endpunkte, Verbindungszeiten, Volumen und Ausfälle | Seltenes selbstgehostetes Log oder spezielle Privacy-Modi erleichtern Zuordnung | Transportanonymisierung, Cover-Traffic und quantitative Messung offen |

Diese Matrix beschreibt Risiken; sie weist keine Reduktion der Leaks nach. Ein ungesalzener State-Hash ist bei bekannten Zustandsdaten kein automatisch versteckendes Commitment. Private Labels, DIDs oder andere Namen schaffen allein keine Unverknüpfbarkeit. Discovery muss den eingeladenen Kontakt-Pin bis zum verifizierten Lookup binden; eine unautorisierte Umleitung auf einen konsistenten fremden Account bleibt ein Angriff. Kein globales öffentlich durchsuchbares Identitätsverzeichnis und keine neue DID-Methode beschlossen. Privacy-Verfahren mit VRF/Commitments/ZK sind mögliche Forschungsgegenstände, kein Auftrag für eigene Primitive.

## 10. Python-Integrationsvertrag (Entwurf, nicht implementieren)

Künftige getrennte Module: `transparency/models.py`, `proofs.py`, `checkpoints.py`, `witness.py`, `policy.py`, `client.py`. Keine Änderung der bestehenden `identity/`-Vertragslogik in diesem PR.

Eine Adapterantwort soll **typisiert** getrennte Resultate für `authorization`, `inclusion`, `consistency`, `witness_policy` und `freshness` liefern. Aktivierung nur bei vollständiger positiver Policy-Entscheidung; unbekannte Methoden, Algorithmen und fehlende Proofs sind Fehler.

Der Identity-Kern muss Signatur-, Besitz-, Rollen- und Parent-Prüfung selbst behalten; ein Adapterresultat `authorization` darf diese nicht ersetzen. `ExternalConfirmation` ist heute nur die typisierte Antwort eines zusätzlich vertrauenswürdigen Prüfers, kein fertig implementierter transparenter Aktivierungsvertrag. Ein künftiger Adapter muss Challenge, Generation, Parent, Kandidat und vertrauenswürdige Log-/Policy-Konfiguration zusammen prüfen; sein Netzwerkcode gehört außerhalb einer mutierenden State-Machine-Operation.

Persistent gespeicherte Trust Anchors, High-Watermark und zuletzt gepinnter Checkpoint müssen Crash-/Rollback-resistent sein; ein RAM-only-Cache genügt nicht. Reentrancy, Ressourcengrenzen und Deadline-Probleme aus PR #2 bleiben explizite Regressionsthemen.

Identity-Head, Geräte-Tombstones, Checkpoint/High-Watermark, Witness-Konfiguration, Aktivierungsbeleg und Quarantänestatus benötigen einen überprüften gemeinsamen Persistenz-/Crash-Vertrag **vor** Empfängerfreigabe. `apply()` übernimmt heute nur einen In-Memory-Snapshot; ein getrenntes Speichern vor/nach `apply()` erzeugt keine Disk-Atomarität. Ein Neustart darf keine alten monotonic-Startwerte zu neuen Nachweisen umdeuten. Historische Prüfung abgelaufener Actions und aktuelle Aktivierung sind getrennt zu spezifizieren; der jetzige Kern hat keine Offline-Import-API.

Log-Replay darf historische Autorisierung prüfen, aber weder private Geräteschlüssel ersetzen noch Geräteverlust als neue Genesis unter altem Root kaschieren. Terminalstatus, alte Schlüsselbindungen und Widerrufe dürfen durch Compaction, alte Checkpoints oder Log-Migration nicht verschwinden. Vorhandene gestohlene aktive Schlüssel bleiben ein Risiko; Transparenz kann menschlichen Geräteverlust nicht beweisen. `NO_RECOVERY` gilt auch nach Verlust des letzten lokalen Checkpoints.

## 11. Testmatrix für spätere Implementierung

| ID | Adversariales Szenario | Erwartetes Resultat |
|---|---|---|
| KT-01 | Log sendet gültigen, nach festgelegter Policy zu alten Checkpoint oder nur alte Identity-Inclusion im neuen Baum | Keine Freigabe ohne aktuellen authentifizierten Head-Lookup; Alter nicht aus Signatur allein ableiten |
| KT-02 | Inkonsistenter, fehlender oder manipulierter Proof | Fail Closed; prüfbarer Äquivokationsbeleg nur bei ausreichender authentischer Evidenz |
| KT-03 | Inclusion ohne Consistency | Keine Aktivierung |
| KT-04 | Zwei authentische konkurrierende Device-Heads | Keine stille Auswahl; nach S kein Doppel-Aktivierungsbeleg |
| KT-05 | Kolludierende Witnesses | Innerhalb beschlossener Fehlergrenze Safety prüfen; außerhalb davon keine garantierte Sichtbarkeit einer Annahmeverletzung |
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
| KT-16 | Mehrheitsquoren mit ausschließlich byzantinischem Schnitt; derselbe Root unter zwei Labels | Keine Doppelaktivierung in S; keine Behauptung allein wegen Checkpoint-Signaturen |
| KT-17 | Gleich große signierte Log-Heads mit verschiedenen Roots; kompatible verschiedene Größen | Ersteren Beweis prüfen; letztere nicht allein als Äquivokation melden |
| KT-18 | Vorhandene Session nach Ablauf, Suspend/Reboot oder verstecktem Widerruf | Verschlüsselungsgate erneut prüfen; keine erneuerte Frist durch Cache-/Uhrreset |
| KT-19 | Crash zwischen Identity-/Checkpoint-/Quarantäne-Persistenz | Keine Aktivierung ohne vollständigen dauerhaften Commit; sicherer Neustart oder Fail Closed |
| KT-20 | Discovery führt zu fremdem konsistentem Account, neue Witness-Epoch nur vom Relay | Kontakt-/Konfigurationsbindung verweigert Freigabe |
| KT-21 | Falsche Signaturdomäne, Algorithmus, Baumindex, Proof-Länge, doppelte Witness-Stimme oder Nonce | Strikte Budget-/Bindungsprüfung vor Zustandsübernahme; keine teilweise veränderten Pins |
| KT-22 | Zensiertes Gossip bei dauerhaft getrennten gültigen Sichten | Keine garantierte Entdeckungsfrist; Auflösung nie durch Reset oder höchsten Zähler |

Tests müssen echte gegnerische Mehrclient-/Mehrserver-Simulationen enthalten; nur lokale Unit-Tests genügen nicht.

## 12. Release-Gates und Reihenfolge

Diese **KT-Gates** sind zusätzliche Arbeitsschritte; sie ersetzen oder ändern nicht die normativen Gates G0–G3 im Threat Model.

**KT-G0 (Architekturerfassung):** Angreifermodell, Risikomatrix, offene Aktivierungssemantik und bedingte Quorum-Annahmen dokumentieren. Dieser Draft ist eine Arbeitsgrundlage, kein Nachweis einer beschlossenen sicheren Architektur.

**KT-G1 (Protokollentscheid):** formale Aussage über Safety/Liveness/Partitionen, Witness-Konfiguration, Fristen, Serialisierung, Schlüsselbindung, Recovery-Verbot und föderierte Log-Routing-Regeln; unabhängiges Designreview. **Offen, keine Implementierungsfreigabe.**

**KT-G2 (isolierter Proof-Verifier):** erst nach KT-G1 Python-Tests mit offiziellen/fremden Testvektoren, Negativfälle, deterministische Multi-Client-Simulation und Fuzzing. Keine Netzwerkinfrastruktur nötig. **Nicht begonnen.**

**KT-G3 (Testnetz):** getrennte Operatoren, Datenschutzmessung, Partition/Offline/Widerrufs-Latenz, Incident-Übungen und unabhängiges Security Audit vor Hochrisiko-Einsatz. **Nicht begonnen.**

**Kein Produkt-Release durch Erreichen von KT-G0–KT-G2 allein.** Ein Dokumentationsmerge kann trotz expliziter HIGH-Release-Blocker zulässig sein; er ist keine Protokollentscheidung. Die Merge-Gates aus Issue #4 gelten separat, einschließlich unabhängiger Prüfung von PR #2 vor der Merge-Kette.

## 13. Noch ausdrücklich zu entscheidende Punkte

1. Option S versus D und Sicherheits-/Verfügbarkeitskompromiss bei Netzwerkpartitionen.
2. Fehlertoleranz und Unabhängigkeit der Auditoren/Witnesses; keine willkürliche Quorum-Zahl.
3. Belegbare maximale Veröffentlichungslatenz, Staleness-Toleranz und Uhrannahmen.
4. Private Lookup-Labels und minimale öffentliche Informationen bei föderierten Servern.
5. Checkpoint-/History-Persistenz, langfristiger Offline-Catch-up und Kryptosuite.
6. Policy-Härtung gegen aktive Managerkompromittierung (separate ADR).
7. Integrationspfad zur State Machine ohne Verlust bestehender atomarer Guards.

## 14. Hintergrundquellen (keine automatische Normativität)

- IETF *Key Transparency Architecture*, `draft-ietf-keytrans-architecture-10`, 2026-10-07, angestrebter Status Informational; **Internet-Draft / Work in Progress, kein finaler Standard**: [versionierte Primärquelle](https://www.ietf.org/ietf-ftp/internet-drafts/draft-ietf-keytrans-architecture-10.html), insbesondere §§ 3.3, 4, 7–9. Deployment-/Monitoringannahmen dürfen nicht als KryptaChat-Eigenschaften übernommen werden.
- RFC 9162, *Certificate Transparency Version 2.0*, **Experimental RFC, kein Internet Standard**: [Primärquelle](https://www.rfc-editor.org/rfc/rfc9162.html), insbesondere §§ 2.1.3–2.1.4 und 11.3. Inclusion/Consistency dienen als Referenz; die Zertifikatslog-Semantik spezifiziert keinen aktuellen KryptaChat-Geräte-Head und kein Aktivierungsquorum.
- Vorhandene KryptaChat-Quellen: `security/threat-model.md`, `security/identity-protocol.md`, `security/identity-authority-policy.md`, `security/identity-security-review-2026-10-08.md`.

**Achtung:** Dies ist eine Architekturhypothese, keine Kombination bereits geprüfter Protokolle. Kein eigener Merkle-/Signaturalgorithmus und kein produktiver Dienst wird durch dieses Dokument autorisiert.
