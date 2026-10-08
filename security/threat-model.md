# Secure Messenger — Threat Model v1.0

**Datum:** 2026-10-08  
**Status:** Architekturentwurf / normative Anforderungen vorgeschlagen; **keine Sicherheitszertifizierung**  
**Zielgruppe:** Journalist:innen, Aktivist:innen, Whistleblower und weitere gefährdete Personen  
**Produktziel:** Hohe Alltagstauglichkeit bei konsequent sicherheitsorientierter Architektur  
**Änderungskontrolle:** Änderungen am Bedrohungsmodell erfordern ein dokumentiertes Security Review.  
**Projektfassung:** Vollständige Vorlage übernommen; Anpassungen an `NO_RECOVERY` sind im [Security Review](review-2026-10-08.md) dokumentiert. [Unveränderte Vorlage](references/secure-messenger-threat-model-v1.0.md).

## 1. Geltungsbereich und Ausgangslage

Das System umfasst Clients (Android, iOS, Desktop), lokale Datenspeicherung, kryptografische Identitäten und Geräteidentitäten, Paarung, Kontakteinladungen, Einzel- und Gruppenchats, verschlüsselte Nachrichten/Dateien, temporäre Offline-Postfächer, unabhängige Relay-Server, optional anonymisierende Transportschichten, Sicherheitsupdates und den Umgang mit Identitätsverlust. Für die erste Version gilt `NO_RECOVERY`: Nach Verlust aller autorisierten Geräte wird eine neue Identität angelegt und Kontakte müssen erneut verifizieren. Identitätserhaltende Wiederherstellung ist nicht Bestandteil dieser Version. Anrufe und öffentliche Communities sind spätere Ausbaustufen, müssen aber im Bedrohungsmodell berücksichtigt werden.

Beschlossene Produktgrundsätze: keine Telefonnummer, E-Mail oder zentrale Registrierung; private Kontakte standardmäßig; optionale widerrufbare öffentliche Kontaktadressen; unabhängige Multidevice-Nutzung; standardmäßig E2EE; keine Werbung oder verpflichtende Telemetrie; offene Implementierung; keine Wiederherstellung der alten Identität nach Totalausfall; eine gegebenenfalls zugelassene Wiederherstellung von Chat-Backups ist davon getrennt.

**Nicht bewiesen:** Ob eine Verbindung etablierter E2EE-Protokolle mit einer neuen Zustellschicht kompositionssicher ist. Bis zum Nachweis gilt kein konkreter Protokoll-Stack als freigegeben.

## 2. Schutzobjekte (Assets)

| ID | Schutzobjekt | Schutzbedarf |
|---|---|---|
| AS-01 | Klartext von Nachrichten, Anhängen und Anrufen | Kritisch |
| AS-02 | Identitäts-, Geräte-, Sitzungs- und Gruppenschlüssel | Kritisch |
| AS-03 | Kontaktgraph und Gruppenmitgliedschaften | Kritisch |
| AS-04 | IP-Adressen, Online-Zeiten, Nachrichtenlängen, Zustellmuster | Hoch |
| AS-05 | Geräteautorisierungen, Widerrufe, Verifikationsstatus | Kritisch |
| AS-06 | Lokale Nachrichtenhistorie und Benachrichtigungsdaten | Hoch |
| AS-07 | Unabhängige Backup-Schlüssel und gesicherte Backups; Recovery-Geheimnisse nur bei später ausdrücklich geänderter Architektur | Kritisch |
| AS-08 | Software-Signaturen, Updates, Build-Pipeline | Kritisch |
| AS-09 | Verfügbarkeit von Relay-Postfächern | Hoch |
| AS-10 | Kontakt-Einladungsadressen und öffentliche Eingangskanäle | Hoch |

## 3. Angreifermodell

Angreifer können sich kombinieren und adaptiv handeln. Wir betrachten außerdem einen Angreifer, der Ciphertexte über viele Jahre aufbewahrt.

| ID | Angreifer | Fähigkeiten | Annahme/Grenze |
|---|---|---|---|
| A1 | Lokaler / regionaler Netzwerkgegner | Mithören, Blockieren, Paket-Injektion, DNS/IP-Analyse | Beherrscht nicht zwingend sämtliche Pfade |
| A2 | Vollständig kompromittierter Relay-Betreiber | Nachrichten-/Queue-Metadaten sehen, löschen, verspätet ausliefern, Clients täuschen | Kennt keine Client-Privatschlüssel allein durch Serverkontrolle |
| A3 | Mehrere kolludierende Betreiber | Logs und beobachtete Zustellungen korrelieren | Kann wesentliche Teile des Netzes beobachten |
| A4 | Externer Geräteangreifer | Gesperrtes/verlorenes Gerät stehlen, Offline-Angriffe auf Datenspeicher | Nicht automatisch Kontrolle über entsperrtes Betriebssystem |
| A5 | Zielgerichteter Endpoint-Angreifer | Malware, Root/Jailbreak, Screenshots, Keylogging, Exfiltration | Kompromittierter aktiver Endpoint ist außerhalb voll garantierbarer Inhaltsvertraulichkeit |
| A6 | Bösartiger Kontakt oder Gruppenmitglied | Weiterleiten, Screenshots, falsche Meldungen, absichtlich veröffentlichen | Legitim empfangenen Klartext kann Kryptografie nicht kontrollieren |
| A7 | Lieferkettenangreifer | Abhängigkeit, Build, Release, Updates manipulieren | Vertrauensanker Build-/Signierverfahren |
| A8 | Globaler passiver Beobachter | Korreliert Verbindungen vieler Netzbereiche, Zeitfenster und Größen | Starker Anonymitätsgegner; einfache Tor-/Relay-Nutzung bietet keine vollständige Garantie |
| A9 | Zensur-/DoS-Akteur | Knoten blockieren, Spam, Traffic-Flooding, gezielte Zustellverweigerung | Uneingeschränkte Verfügbarkeit nicht garantierbar |
| A10 | Zukunftsangreifer | Aufgezeichnete Ciphertexte später mit neuer Kryptanalyse/Quantenkapazität angreifen | Sicherheitsbehauptungen müssen zeit- und primitivspezifisch sein |

## 4. Vertrauensgrenzen

1. **Client ↔ lokales Betriebssystem:** Betriebssystem-/Hardware-Schutz hilft, ersetzt keinen Schutz vor kompromittiertem aktivem Endgerät.
2. **Client ↔ Transport:** Netzwerkpfade sind feindlich; Transportverschlüsselung alleine genügt nicht.
3. **Client ↔ Relay:** Relay kann vollständig bösartig sein; niemals Klartext- oder E2EE-Privatschlüssel vertrauen.
4. **Relay ↔ Relay:** Federation ist kein implizites Vertrauensverhältnis. Datenweitergabe und Korrelation sind Angriffsflächen.
5. **Verifiziertes Gerät ↔ neues Gerät:** Geräteaufnahme ist sicherheitskritische Änderung, keine harmlose Synchronisation.
6. **Kontakt ↔ Kontakt:** Verifikation bestätigt Schlüsselbindung, nicht menschliche Vertrauenswürdigkeit.
7. **Client ↔ Update-Kanal:** Angreifer dürfen keine unsignierte/maliziöse Version einschleusen.
8. **Identitätsverlust ↔ gewöhnlicher Nachrichtenbetrieb:** `NO_RECOVERY` darf nicht durch Root-Rotation, Manager-Ernennung, Backup-Import oder erneute Ersteinrichtung unterlaufen werden. Backup-Schlüssel dürfen keine Geräte- oder Identitätsrechte verleihen.

## 5. Sicherheitsziele und überprüfbare Anforderungen

*MUSS* = für erste sicherheitsbeanspruchende Veröffentlichung verpflichtend. *SOLL* = stark priorisiert, Abweichung dokumentieren. *FORSCHUNGSZIEL* = gewünschte Eigenschaft, noch keine nachgewiesene Garantie.

### 5.1 Inhalte und Kryptografie

- **SEC-C01 MUSS:** Alle privaten Chat-Nachrichten und Anhänge vor Verlassen des Geräts authentifiziert Ende-zu-Ende verschlüsseln; Server dürfen niemals Klartext oder Entschlüsselungsschlüssel erhalten.
- **SEC-C02 MUSS:** Nachrichten müssen gegen unbemerkte Veränderung, Replay und ungültige Kontextzuordnung geschützt werden.
- **SEC-C03 MUSS:** Authentifizierter Sitzungsaufbau und der beabsichtigten Bedrohung angemessene Forward Secrecy; Bedingungen für Post-Compromise Security explizit modellieren und testen.
- **SEC-C04 MUSS:** Ausschließlich gut analysierte Protokolle und gepflegte Kryptobibliotheken; keine eigene Erfindung kryptografischer Primitive.
- **SEC-C05 MUSS:** Versionierung, Domänentrennung und sichere Migration zwischen Protokollversionen, Schutz gegen Downgrades.
- **SEC-C06 SOLL:** Gegen spätere Entschlüsselung gespeicherter Handshakes durch Quantenangreifer abgesicherte, überprüfte hybride Schlüsselaushandlung; die Grenzen der Authentifizierung ausdrücklich dokumentieren.
- **SEC-C07 MUSS:** Anhänge mit unabhängigen Schlüsseln, authentifizierter Verschlüsselung, geschützten Dateinamen/Thumbnails und begrenzter Dateigröße; Schlüssel nur über E2EE-Kanal verteilen.

### 5.2 Identitäten, Kontakte und Geräte

- **SEC-I01 MUSS:** Keine Telefonnummer, Mailadresse oder zentrale Registrierung erforderlich. Identität lokal mit kryptografisch sicherer Zufallsquelle erzeugen.
- **SEC-I02 MUSS:** Direkte kryptografische Schlüsselverifikation (z.B. QR-Code / Sicherheitsvergleich) ermöglichen; bei unerwarteten Änderungen einer **verifizierten** Identität Versand blockieren bis zur erneuten Bestätigung.
- **SEC-I03 MUSS:** Neues Gerät nur durch gültige ausdrückliche Autorisierung eines noch verfügbaren berechtigten Geräts; kein identitätserhaltender Recovery-Prozess in dieser Version; Kopplungs-Sitzung an beide Endpunkte und Ablaufzeit binden.
- **SEC-I04 MUSS:** Jedes Gerät erhält eigene langfristige Geräte- und Sitzungsschlüssel; Widerruf, Epochenwechsel und Behandlung bereits kompromittierter Gerätezustände festlegen.
- **SEC-I05 MUSS:** Gegen widersprüchliche oder zurückgerollte Gerätestände (Equivocation/Rollback) schützen; Konsistenzprüfung oder äquivalenter Mechanismus noch zu spezifizieren.
- **SEC-I06 MUSS:** Private Einladungen als Standard, widerrufbare öffentliche Kontaktadressen freiwillig; kein global durchsuchbares Adressverzeichnis.
- **SEC-I07 MUSS:** Nach Verlust aller autorisierten Geräte neue Identität und erneute Kontaktverifikation; keine Wiederherstellung der alten Identität. Ein alter Root-Key, angeblicher Recovery-Key, Backup, Server-Reset, Telefon oder E-Mail darf diese Regel nicht umgehen. Eine Neuanlage widerruft die alte Identität nicht automatisch; erreichbare Kontakte müssen den alten Kontakt über einen authentischen unabhängigen Kanal sperren.

### 5.3 Metadatenschutz

- **SEC-M01 MUSS:** Keine absichtliche serverseitige Speicherung zentraler Kontaktlisten oder globaler persönlicher Nutzerkennungen.
- **SEC-M02 MUSS:** Minimierung und dokumentierte Lebensdauer aller Relay-Daten, Queues, Logs, Telemetrie, Push-Kennungen.
- **SEC-M03 MUSS:** Für jede Netzrolle dokumentieren, welche Informationen aus Queue-ID, IP, TLS-Session, Größe, Zeitpunkt, Abholintervall und Zustellung ableitbar bleiben.
- **SEC-M04 FORSCHUNGSZIEL:** Gegen einzelne Relay-Betreiber weitgehende Unverkettbarkeit verschiedener Kontaktbeziehungen, einschließlich Sender-/Empfänger-Korrelation.
- **SEC-M05 FORSCHUNGSZIEL:** Gegen kolludierende Betreiber und starke Netzwerkbeobachtung Schutz durch Maßnahmen wie Traffic Padding, Mixing, Cover Traffic, anonyme Abholung; Wirksamkeit empirisch bewerten, inklusive Bandbreite/Latenz/Akku.
- **SEC-M06 MUSS:** Klar kommunizieren, dass Tor, Föderation, wechselnde Queue-IDs und E2EE allein keine Anonymität gegenüber globaler Verkehrsanalyse beweisen.
- **SEC-M07 MUSS:** Push-Benachrichtigungen ohne Nachrichtenklartext; Offenlegung von Push-Metadaten, Geräte-Tokens und eventueller Plattformabhängigkeit transparent behandeln.

### 5.4 Speicherung, Backups und Endpoint

- **SEC-E01 MUSS:** Verschlüsselte lokale Speicherung mit angemessener Schlüsselablage und Gerätesperren; keine Klartextdaten in Diagnose-Logs, Crashreports oder ungeschützten Benachrichtigungen.
- **SEC-E02 MUSS:** Lösch- und Ablaufregeln für Relay- und Clientdaten; explizit keine Garantie gegen Screenshots, externe Kopien, Speicherforensik oder kompromittierte Geräte.
- **SEC-E03 MUSS:** Sicherheitskritische Aktionen wie Hinzufügen eines Geräts oder Neuanlage nach Identitätsverlust deutlich bestätigen; keine stille Übernahme.
- **SEC-E04 SOLL:** Plattformhärtung und Sicherheitsprüfung anhand OWASP MASVS/MASTG, einschließlich lokaler Daten, Authentifizierung, Kryptografie, Netzwerk, Plattform und Privatsphäre.
- **SEC-E05 MUSS:** Backup-Verschlüsselung unabhängig von Transport-/Nachrichten-/Identitätsschlüsseln, Schutz vor Offline-Brute-Force und Rollen-/Schlüsseltrennung.

### 5.5 Server, Verfügbarkeit und Lieferkette

- **SEC-S01 MUSS:** Keine Relay-Abhängigkeit für Entschlüsselung/Authentizität; Einzelserverkompromittierung darf Nachrichtenklartext nicht offenlegen.
- **SEC-S02 MUSS:** Integritätsprüfung, idempotente Zustellung, Replay-Abwehr, Ablaufregeln und nachvollziehbare Behandlung von Queue-Löschungen.
- **SEC-S03 SOLL:** Relay-Wechsel, Zustellredundanz und klare Erkennung/Anzeige möglicher Zustellausfälle.
- **SEC-S04 MUSS:** Rate Limits, Ressourcenlimits und Missbrauchsschutz ohne obligatorische Identitätsdaten oder dauerhaftes Tracking; verbleibende Trade-offs dokumentieren.
- **SEC-S05 MUSS:** Signierte Releases, getrennte Berechtigungen, Supply-Chain-Pinning, überprüfbare Release-Herkunft, Incident-Response und koordinierte Schwachstellenmeldung.
- **SEC-S06 SOLL:** Reproduzierbare Builds und externe Audits vor Hochrisiko-Freigabe.

### 5.6 Gruppen

- **SEC-G01 MUSS:** Mitgliedschaftsänderungen kryptografisch autorisieren und für betroffene Clients erkennbar machen.
- **SEC-G02 MUSS:** Gruppennachrichten Ende-zu-Ende verschlüsseln; nie durch Administratoren deaktivierbar.
- **SEC-G03 MUSS:** Ausgeschlossene Mitglieder erhalten keine nach dem Ausschluss neu abgeleiteten Gruppenschlüssel; bereits erhaltene Klartexte nicht rückholbar.
- **SEC-G04 MUSS:** Device↔Member-Abbildung, Epoch-Synchronisierung, Konkurrenzkonflikte und bösartiger Delivery Service spezifizieren.
- **SEC-G05 MUSS:** Keine pauschale Metadatenanonymität durch MLS behaupten; Schutz von Gruppenstatus und Mitgliedschaften gesondert analysieren.

## 6. Angriffsszenarien, Gegenmaßnahmen und Restrisiken

| ID | Szenario | Vorgesehene Abwehr / Kontrolle | Restrisiko |
|---|---|---|---|
| T-01 | Relay liest gespeicherte Nachrichten | E2EE, separate clientseitige Schlüssel, Authenticated Encryption | Zeitpunkt/Größe/Queues sichtbar |
| T-02 | Relay ersetzt Kontakt- oder Geräte-Schlüssel | Verifikation, signierte Geräteautorisation, Konsistenz-/Rollback-Schutz | Nicht verifizierte Erstkontakte bleiben angreifbar |
| T-03 | Nachrichten werden manipuliert, vertauscht, wiederholt | AEAD, Sitzungs-/Nachrichtenbindung, Replay-/Order-Logik | Selektive Unterdrückung möglich |
| T-04 | Angreifer stiehlt später Sitzungsschlüssel | Ratcheting, Löschung alter Schlüssel, frische Entropie | Aktive Endpoint-Kompromittierung kann Sicherheit verhindern |
| T-05 | Server korrelieren Sender und Empfänger | Getrennte Queues, anonyme Transportoptionen, minimierte Logs | Traffic-Korrelation bleibt möglich |
| T-06 | Globaler Beobachter korreliert Zeit und Pakete | Forschungsziel Padding, Mixing, Cover Traffic, batched polling | Starker Gegner kann Beziehungen eventuell rekonstruieren |
| T-07 | Gerät gestohlen (gesperrt) | Datenbankverschlüsselung, OS-Schutz, Geräteschlüssel, Widerruf | Schwache Gerätesperre/Forensik/alte lokale Daten |
| T-08 | Gerät wird mit Malware infiziert | Härtung, Berechtigungsminimierung, Sperre, Updates | Klartext auf aktivem Gerät kann abgegriffen werden |
| T-09 | Angreifer koppelt heimlich weiteres Gerät | Explizite signierte Gerätefreigabe, Warnung, Konsistenzbeweis | Wenn bestehendes Gerät vollständig übernommen wurde, möglich |
| T-10 | Angreifer umgeht `NO_RECOVERY` über angeblichen Recovery-Key, alten Root-Key oder Backup | Keine Wiederherstellungstransition; Root allein darf nach Totalausfall keine Geräte hinzufügen; alle alternativen Autorisierungspfade prüfen | Bereits gestohlene aktive Geräteschlüssel können ihre bestehenden Rechte innerhalb der dokumentierten Grenzen missbrauchen |
| T-11 | Öffentliche Kontaktadresse wird gespammt | Widerrufbare Adressen, Kontingente, Abuse Controls | Angreifer kann Verfügbarkeit beeinträchtigen |
| T-12 | Bösartiges Gruppenmitglied leakt Inhalte | Keine vollständige kryptografische Abwehr | Insider-Risiko bleibt |
| T-13 | Manipuliertes App-Update | Signierte Releases, unabhängige Audits, Build-Provenienz | Signierschlüssel-/CI-Kompromittierung möglich |
| T-14 | Staatlich angeordnete Serverblockade | Unabhängige Server, Relay-Wechsel, alternative Wege | Vollständige Netzsperre nicht sicher zu umgehen |
| T-15 | Selektive Zustellverweigerung | Retry, Redundanz, Statusanzeigen, Zeitüberschreitung | Zustellung bei globaler Zensur nicht garantierbar |
| T-16 | Kompromittierter Server erstellt widersprüchliche Gerätezustände | Append-only/verifizierbare Zustandsfolgen oder gleichwertiges Konsistenzverfahren | Entwurf und unabhängige Prüfung erforderlich |

## 7. Explizite Nicht-Garantien

- Keine garantierte Geheimhaltung gegenüber einem vollständig kompromittierten, aktiven Endgerät.
- Kein technischer Schutz gegen das Weitergeben von Klartext durch berechtigte Empfänger.
- Keine nachgewiesene vollständige Unbeobachtbarkeit von Kommunikationsbeziehungen gegenüber globalen Traffic-Analysten.
- Keine garantierte Erreichbarkeit gegen umfassende Zensur, Netzwerkabschaltung oder DDoS.
- Keine Garantie, dass „Löschen“ Kopien/Screenshots/forensisch rekonstruierbare Daten rückwirkend beseitigt.
- Keine garantierte menschliche Identität allein durch QR-Schlüsselbestätigung, wenn der QR-Code aus unzuverlässiger Quelle stammt.
- Kein pauschaler Schutz gegen Quantenangreifer ohne präzise spezifizierten, nachweislich passenden Protokoll-Stack.

## 8. Sicherheitsrelevante Entscheidungen, die noch **offen** sind

| ID | Frage | Entscheidungskriterium |
|---|---|---|
| D-01 | SimpleX-Protokoll/Komponenten übernehmen, anpassen oder eigenen Relay-Layer bauen? | Protokoll-Audit, Lizenzen, Metadatenprofil, Implementationsrisiko |
| D-02 | Einzelchat: konkrete PQXDH/Double-Ratchet/Triple-Ratchet-Komposition? | Bibliotheksreife, multi-device, Interoperabilität, formale Analyse |
| D-03 | Gruppen: konkrete MLS-Suite und Delivery-Service-Integration? | Membership-Integrität, Rechte und Gerätezuordnung |
| D-04 | Anonymisierung verpflichtend oder optional? | Threat Model, UX, Performance, Anonymitätsmengen, Gefahr durch Abweichler |
| D-05 | Aufbewahrungsdauer, Message Padding und Polling-Kadenz? | Bedrohungsziel vs. Akku/Bandbreite/Latenz |
| D-06 | Account-/Gerätestatus ohne zentrale Vertrauensinstanz? | Equivocation-Schutz, Offline-Clients, Geräteverlust bei `NO_RECOVERY` |
| D-07 | Welche Plattform zuerst? | OS-Sicherheitsfunktionen, Review-Kapazität, reale Hochrisiko-Anforderungen |
| D-08 | Backups im Hochsicherheitsmodus? | Exfiltrationsrisiko vs. Benutzbarkeit |
| D-09 | Push-Modell und Notification Privacy? | Plattform-Metadaten und Zustellbarkeit |
| D-10 | Transparenz-/Sicherheitsupdatepolitik? | Maintainer, unabhängige Schlüssel, Release-Prozess |

## 9. Abnahmetests für einen ersten sicherheitsprüfbaren Prototyp

1. **Relay unter Kontrolle des Testers:** Ciphertexte, private Nachrichtenschlüssel, Anhänge und Klartext bleiben geheim; Transport-Metadaten werden dokumentiert.
2. **Manipulation:** Ciphertext-Änderungen, Replay, falscher Gesprächskontext und Protokoll-Downgrade führen zu sicherem Abbruch.
3. **Schlüsseltausch:** Unangekündigter Identitätswechsel bei verifizierten Kontakten stoppt Versand auf allen betroffenen Geräten.
4. **Neues Gerät:** Ohne gültige Autorisierung darf kein weiteres Gerät hinzugefügt werden; testweise manipulierte QR-Codes scheitern.
5. **Widerruf:** Entzogene Geräte können keine neuen Epochen-/Nachrichtenschlüssel erhalten; verbliebene Geräte und Kontakte sehen konsistente Zustände.
6. **Offline-Zustellung:** Mehrstündige Offline-Zeit, doppelte Zustellungen, Reihenfolgenwechsel und Relay-Abbruch ohne Klartextverlust und ohne stillschweigende Integritätsfehler behandeln.
7. **Gruppenwechsel:** Hinzufügen/Ausschließen von Gruppenmitgliedern, konkurrierende Updates, Replay und gesperrte Geräte testen.
8. **Lokales Gerät:** OS-Backups, Logs, Sperrbildschirm, Dateivorschau, Debugging und Speicherpfade auf Klartextlecks testen.
9. **Traffic-Analyse:** Messung, was einzelne Relays, kooperierende Relays und ein Netzwerkbeobachter über Kontakte lernen; Ergebnisse quantitativ veröffentlichen.
10. **NO_RECOVERY:** Nach Verlust aller autorisierten Geräte keine Fortsetzung der alten Identität über Root-Key, Backup, Server oder Recovery-Behauptung zulassen. Neue Identität erfordert neue Kontaktverifikation. Unabhängige Backup-Schlüssel dürfen keine Verwaltungsrechte verleihen; Gerätewiderruf bei noch verfügbaren berechtigten Geräten getrennt testen.
11. **Supply Chain:** Signaturen, Abhängigkeitsintegrität, CI-Zugriff, SBOM und Release-Artefakte unabhängig überprüfen.
12. **Externer Audit:** Alle kritischen Befunde beheben und Regressionstests dokumentieren, bevor Hochrisiko-Produktionsreife behauptet wird.

## 10. Risikoannahme und Freigabegates

- **Gate G0 — Design:** Bedrohungsmodell, Datenflussdiagramme, konkreter kryptografischer Protokollentwurf, Metadatenprofil, offene Bedrohungen dokumentiert.
- **Gate G1 — Prototyp:** Crypto- und Identity-Tests bestehen; kein selbstgebauter Kryptoprimitiv, Relay kann Nachrichten nicht lesen.
- **Gate G2 — Alpha:** Multidevice-/NO_RECOVERY-/Gruppen-Fuzzing, Netzwerkmanipulationstests, Endgerätprüfungen, dokumentierte Lieferkette.
- **Gate G3 — Hochrisiko-Einsatz:** Unabhängiges Audit, behobene kritische Befunde, Incident-Response, transparente Nicht-Garantien und quantitative Privacy-Messung.

Bis G3 ist die Software **experimentell und nicht für gefährdete Personen als vertrauenswürdige Sicherheitslösung zu empfehlen**.

## 11. Standards / Primärreferenzen

- Signal: PQXDH – https://signal.org/docs/specifications/pqxdh/
- Signal: Double Ratchet – https://signal.org/docs/specifications/doubleratchet/
- Signal: Dokumentation inklusive Sesame – https://signal.org/docs/
- MLS: RFC 9420 – https://www.rfc-editor.org/rfc/rfc9420.html
- MLS-Architektur: RFC 9750 – https://www.rfc-editor.org/rfc/rfc9750.html
- SimpleX Messaging Protocol – https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md
- SimpleX Security – https://github.com/simplex-chat/simplexmq/blob/stable/protocol/security.md
- OWASP MASVS – https://mas.owasp.org/MASVS/

## 12. Kurzfazit

Die höchste technische Hürde ist nicht die Grundverschlüsselung, sondern ihre sichere Kombination mit einer dezentralen, offlinefähigen Zustellinfrastruktur, Multi-Device-Identitäten und belegbarem Metadatenschutz. Keine Sicherheitsgarantien behaupten, bevor ihr jeweiliger Angreifer- und Systemkontext spezifiziert und geprüft ist.
