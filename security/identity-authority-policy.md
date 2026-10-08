# Secure Messenger — Identity Authority Policy v1.0

**Datum:** 2026-10-08  
**Status:** Normativer ArchitekturENTWURF; nicht implementiert, nicht auditiert.  
**Implementierungssprache:** Python 3.13+ für Anwendungslogik und Server, geprüfte native Kryptografie-Bindings für kryptografische Verfahren; durch Nutzerentscheidung bestätigt.  
**Abhängigkeiten:** [Threat Model v1.0](threat-model.md), [Identity Protocol v1.0](identity-protocol.md).  
**Projektfassung:** Vollständige Vorlage übernommen; `NO_RECOVERY` ersetzt ihre Recovery-Standards. Anpassungen und offene Widersprüche: [Security Review](review-2026-10-08.md). [Unveränderte Vorlage](references/secure-messenger-identity-authority-policy-v1.0.md).

## 1. Zweck und Geltungsbereich

Diese Richtlinie definiert, wer die Identität verwalten darf und wie Clientsoftware die Autorisierung prüft. Sie gilt für Geräteanlage, Gerätesperre/-widerruf, Schlüsselrotation, Recovery und Kontaktverifikation. Sie definiert **keinen** endgültigen Kryptografie-Wire-Standard, keine Messenger-E2EE-Ratchets und keine garantierte Anonymität. Bestehende Normen sollen vor Eigenentwicklungen bevorzugt werden.

Normative Sprache: **MUSS** = Sicherheitsanforderung vor Freigabe; **SOLL** = priorisierte Anforderung; **OFFEN** = nicht entschieden; **NICHT GARANTIERT** = explizite Grenze.

## 2. Schutzmodell

- Der Relay-Server ist für Authentifizierung und Integrität **nicht vertrauenswürdig**. Er kann Nachrichten verändern, zurückhalten, verzögern, wiederholen und unterschiedliche Sichten ausliefern.
- Ein kompromittierter Messaging-Geräteschlüssel darf nicht automatisch einen neuen Device-Management-Schlüssel oder eine neue Root Authority autorisieren.
- Ein Angreifer mit Zugriff auf einen **entsperrten, vollständig kompromittierten Client** kann dort Klartext und ggf. nutzbare Schlüssel abgreifen. Ein System kann keine absolute Sicherheit dafür versprechen.
- Identity, Device, Session, Recovery und Backup verwenden **getrennte kryptografische Domänen**. Eine Recovery-Berechtigung darf keine historischen Nachrichten entschlüsseln.
- Kontaktidentitäten und Gerätewechsel werden als lokale **gepinnt-verifizierte** Zustände behandelt. Alle kritischen Abweichungen führen zu einer Sicherheitswarnung und, falls die zugehörigen Garantien nicht mehr bestehen, zu einem Versandstopp.

## 3. Rollen und Berechtigungen

| Rolle / Schlüssel | Mindestberechtigung | Nicht automatisch erlaubt |
|---|---|---|
| `identity_authority` (offline/selten verwendet) | anfängliche Identitäts-/Policy-Freigabe, Root-Rotation gemäß Policy | Nachrichten lesen; beliebige Netzwerk-Routingdaten einsehen |
| `device_messaging` (je Gerät) | eigene Messaging-Sitzungen und Postfächer | neue Geräte zulassen, Recovery, Root-Rotation |
| `device_manager` (explizit je Gerät) | Gerätehinzufügung und Widerruf gemäß gültiger Policy | alleinige Root-Rotation und Recovery |
| `recovery_authority` | In dieser Version keine aktive Rolle | Keine Geräte-, Root-, Backup- oder Wiederherstellungsrechte; `NO_RECOVERY` ist verbindlich |
| `backup_authority` (optional) | separat erlaubte historische Backup-Wiederherstellung | Identity Recovery oder Geräteverwaltung |
| `relay` | Annahme, Zwischenspeicherung und Auslieferung verschlüsselter Pakete | Autorisierung irgendeiner Identitätsaktion |

**Designentscheid:** Es werden **keine universellen Admin-Geräteschlüssel** eingeführt, die allein Root-Rotation, Recovery und Nachrichtenentschlüsselung kombinieren.

## 4. Autorisierungszustand und Replay-Schutz

Kritische Aktionen enthalten eine **domänenseparierte**, signierte Transaktion mit mindestens:

- Protokollversion, `identity_id`, `action_type`, Action-ID (zufällig), Schlüsselgeneration und erwarteter bisheriger `state_hash`.
- Ziel (`device_id`, ggf. neues Public-Key-Material), expliziter Berechtigungsumfang, Gültigkeitsfenster und signierter Policy-Version.
- Kanonische serialisierte Bytes (Encoding **OFFEN**; Schema muss eindeutig sein), die exakt signiert und verifiziert werden.

Regeln:

1. Clients MÜSSEN Signatur, Rollenzuständigkeit, Schlüsselgeneration, Policy-Version und erwarteten Vorgängerzustand prüfen.
2. Bei fehlender, veralteter, widersprüchlicher oder übersprungener Historie darf **kein stillschweigendes Akzeptieren** stattfinden.
3. Jede Action-ID darf pro Identität nur einmal wirksam werden; ein Widerruf ist irreversibel für dieselbe Gerätekennung.
4. Clients MÜSSEN Split Views und Rollbacks erkennen, soweit sie ihnen bekannte Zustände widersprechen; **globale Erkennung** erfordert zusätzliche Mechanismen (Transparenzlog, Witnesses, Gossip oder andere überprüfte Methode) und ist noch **OFFEN**.
5. Ein Relay darf niemals per HTTP-Status oder Datenbankeintrag eine bereits fehlgeschlagene Autorisierungsprüfung ersetzen.

## 5. Autorisierungsmatrix

| Aktion | Standardregel (Entwurf) | Zusätzliche Bedingungen |
|---|---|---|
| Neue Identität erstellen | Lokale Erzeugung eines neuen Vertrauensankers mit `identity_authority` | Keine Netzwerkregistrierung; sichere Schlüsselgenerierung; keine erneute Genesis unter einer bereits verifizierten alten Identität |
| Neues Messaging-Gerät hinzufügen | Signierte Zustimmung eines aktuell berechtigten `device_manager` | Gegenseitige Kopplungsbestätigung mit kurzlebiger Challenge und Anzeige der Berechtigungen; kein blindes QR-Scannen |
| Manager-Berechtigung vergeben | **Nicht** allein durch vorhandenen Manager | Standard: Root-Autorisierung nur für ein bereits aktiv autorisiertes, noch verfügbares Gerät mit frischem Besitznachweis; dadurch kein neues Gerät anlegen. Keine Erteilung nach Verlust aller autorisierten Geräte. Eine Mehrparteienpolitik wäre gesondert festzulegen. |
| Bestehendes Gerät widerrufen | Berechtigter `device_manager` | Frischer Zustand; andere Geräte und Kontakte über potenziell kritische Änderung informieren |
| Root Authority rotieren | Signatur nach gültiger Root-Rotationspolicy | Standard: bisheriger Root und separat gesicherte Bestätigung eines noch verfügbaren berechtigten Geräts; keine Rotation als Recovery nach Totalausfall. Konstruktion und Eignung bei Root-Kompromittierung bleiben OFFEN. |
| Alle autorisierten Geräte verloren | Neue Identität; alte Identität nicht wiederherstellen | Neuer Vertrauensanker, erneute Kontaktverifikation und authentische Information zur lokalen Sperre des alten Kontakts; kein Recovery-Sonderpfad |
| Backup entschlüsseln | Ausschließlich separater `backup_authority`-Schlüssel | Keine Ableitung aus Root- oder Recovery-Secret; keine Wiederherstellung laufender Identitäts-, Manager- oder Ratchet-Zustände |
| Verifiziertes Kontaktprofil ändern | Lokale Benutzerbestätigung nach kryptografischem Nachweis | Keine Server-Autobestätigung |
| Öffentliche Einladung widerrufen | Berechtigter Client nach expliziter Policy | Widerruf ggf. nur für künftig neue Verbindungen; bereits zugestellte Einladungsdaten nicht rückholbar |

**Offene Spannung:** Der ursprünglich gewünschte Satz „Jedes weitere Gerät lässt sich durch ein bestehendes Gerät hinzufügen“ wird präzisiert: Es muss ein **explizit als Device Manager autorisiertes** bestehendes Gerät sein. Standardmäßig kann das initiale Smartphone diese Rolle besitzen; reine Desktop-Messaging-Geräte nicht.

**Restrisiko:** Ein vollständig kompromittierter aktiver `device_manager` kann innerhalb seiner Rechte gültige Geräteaufnahmen signieren. Die Trennung von Messaging- und Managerschlüsseln schützt nicht, wenn ein kompromittiertes Betriebssystem beide benutzen kann. Ob für Hochrisiko-Kontakte eine zusätzliche unabhängige Bestätigung erforderlich ist, bleibt ausdrücklich zu entscheiden; sie wird durch diesen Import nicht automatisch eingeführt.

## 6. Sicheres Geräte-Pairing (Zustandsautomat)

`PROPOSED` → `CHALLENGED` → `USER_CONFIRMED` → `SIGNED` → `PUBLISHED` → `ACTIVE`; jeder Fehler → `REJECTED`.

`PUBLISHED` beschreibt nur die Transportveröffentlichung. Der Übergang nach `ACTIVE` erfordert auf dem prüfenden Client gültige Autorisierung, erfolgreichen Besitz- und Bindungsnachweis sowie die festgelegten Zustands- und Aktualitätsprüfungen. Ein HTTP-Erfolg oder Relay-Datenbankeintrag genügt nicht.

- Zielgerät generiert seine **eigenen** Geräteschlüssel lokal; QR-Code enthält nur öffentliche notwendige Daten, Ablaufzeit und Nonce.
- Manager verifiziert einen kryptografischen Bindungsnachweis der Pairing-Session; beide Benutzeroberflächen zeigen den Berechtigungsumfang und einen gegenseitig überprüfbaren Vergleichswert.
- Manager signiert nur nach expliziter Bestätigung und unter Bindung an den zuletzt verifizierten Gerätezustand.
- Neugerät und bestehende Clients prüfen denselben Folgezustand. Verspätete oder widersprüchliche Zustände führen zum Abbruch.
- **OFFEN:** Konkreter, extern geprüfter Pairing-Handshake mit MITM-/Replay-Schutz; keine Eigenkonstruktion für die Produktion.

## 7. Gerätewiderruf

- Widerruf veröffentlicht eine signierte, fortlaufende Zustandsänderung mit höherer Generation und unverwechselbarer Action-ID.
- Andere autorisierte Geräte MÜSSEN nach Verarbeitung des gültigen Widerrufs neue Nutzdaten für den widerrufenen Empfänger sperren und betroffene Messaging-Sessions und Gruppen-Schlüsselzustände sicher erneuern. Kann das gewählte Protokoll den Ausschluss nicht sicher durchsetzen, MUSS der betroffene Versand gesperrt bleiben; eine fehlende Protokollfunktion ist keine Ausnahme von `SEC-G03`.
- Das entzogene Gerät kann **bereits heruntergeladene** Nachrichten lesen, kann offline bleiben und Widerrufe ignorieren. Widerruf garantiert keine Fernlöschung.
- Bei offline gebliebenen Kontakten besteht ein **Zeitfenster unsicherer Zustandskenntnis**; Zustandsfrische, Nachrichtenstopp und maximale Staleness sind **OFFEN**.
- Kritische Änderung eines verifizierten Kontakts führt zu `BLOCKED_PENDING_REVERIFICATION`, bis die erforderliche Verifikation erfolgt.

## 8. NO_RECOVERY und Schutz vor alternativen Wiederherstellungspfaden

**Beschlossen für die erste Version:** Nach Verlust aller autorisierten Geräte wird eine neue Identität angelegt. Es gibt weder einen optionalen Recovery-Key noch Threshold-Recovery oder einen identitätserhaltenden Server-Reset.

1. Neues Gerät erzeugt neue Schlüssel und einen neuen Vertrauensanker; der bisherige `identity_id` wird nicht übernommen.
2. Kontakte verifizieren die neue Identität unabhängig und sperren den alten Kontakt lokal nach authentischer Information.
3. Der alte Root-Key allein darf keine neue Gerätezulassung auslösen. Manager-Ernennung darf ausschließlich ein noch verfügbares, bereits aktives autorisiertes Gerät betreffen; Root-Rotation darf den Totalausfall nicht umgehen.
4. Backup-Import darf keine laufende Identität, Managerrolle, alte Action-Historie oder alte Ratchet-Zustände reaktivieren. Ein separat zugelassener Verlaufsexport ist eine andere Funktion und bleibt gesondert zu prüfen.
5. Neuanlage widerruft alte Geräte nicht automatisch. Gegen noch nicht informierte Kontakte, bereits kompromittierte Geräte und aufgezeichnete alte Zustände bleiben die dokumentierten Zeit- und Endpoint-Grenzen bestehen.

**Geräteersatz bei verbleibenden Geräten:** Ein noch verfügbarer gültiger `device_manager` kann nach Abschnitt 5 neue Messaging-Geräte autorisieren. Wenn nur ein gültiges Nachrichtengerät verfügbar ist, darf der vorhandene Root dessen ausdrücklich bestätigte Manager-Ernennung autorisieren; Schlüsselbesitz, aktueller Zustand und Schutz bei Verdacht auf Kompromittierung sind zu prüfen. Das ist keine Erlaubnis für Root allein, ein neues Gerät hinzuzufügen. Ohne verfügbares autorisiertes Gerät bleibt ausschließlich die Neuanlage einer Identität.

**OFFEN:** Kryptografisch genaue Bindung dieser Nachweise, ihre Aktualität und die Konfliktbehandlung bei gestohlenen, weiterhin nutzbaren Geräteschlüsseln. `NO_RECOVERY` darf nicht mit Schutz vor Missbrauch bereits kompromittierter aktiver Geräte verwechselt werden.

Eine spätere identitätserhaltende Recovery-Funktion braucht eine neue ausdrückliche Produktentscheidung und ein dokumentiertes unabhängiges Security Review. Die ursprünglichen Vorschläge sind ausschließlich in der unveränderten Referenzvorlage enthalten.

## 9. Python-Implementierungsrichtlinie

**Beschlossen:** Python-Anwendungslogik mit geprüften nativen Kryptobibliotheken. Die vorangegangene Rust-API-Erwähnung ist durch die ausdrückliche Nutzerentscheidung ersetzt. Auswahl und Integration der konkreten Bibliotheken bleiben vor Implementierungsfreigabe zu prüfen.

- **Python 3.13+** für Policy-State-Machine, strenge Datenmodelle, Validierung, API-Orchestrierung und Tests.
- `uv` für reproduzierbares Dependency-Management, `pytest`/`hypothesis` für Sicherheits- und Zustandsprüfungen, `mypy`/`ruff` für Qualitätskontrollen.
- `cryptography` als Kandidat für **bewährte Primitive** (z. B. Ed25519-Signaturprüfungen), nicht als Beweis einer vollständigen Messenger-Protokollimplementierung.
- Niemals eigene Kryptoprimitive, Ratchets, Secret-Sharing-Algorithmen oder MLS-Implementierung in Python schreiben. Auswahl bestehender Bibliotheken erst nach Sicherheits-, Lizenz- und Wartungsprüfung.
- Hardware-/OS-Keystore bevorzugen; normale Python-Heap-Objekte können Geheimnisse kopieren und nicht garantiert löschen.
- Bei kompromittiertem Endgerät keine Garantien gegen lokale Klartextabgriffe behaupten.
- Relay (z. B. FastAPI/asyncio) muss für Autorisierungsprüfungen nur signierte Daten transportieren, **nicht die Vertrauensinstanz** sein.
- Mobile Clients sind gesondert zu evaluieren: Python-Core auf Android/iOS ist **nicht** automatisch sicher oder einfach distribuierbar; native Keystore-Adapter müssen sorgfältig integriert werden.

## 10. Sicherheitsprüfungen / Negativtests

| Testfall | Erwartetes Verhalten |
|---|---|
| Unsigniertes `ADD_DEVICE` | Abweisen |
| `ADD_DEVICE` von reinem Messaging-Gerät | Abweisen |
| Alte gültige Signatur mit altem `previous_state_hash` | Abweisen / Konflikt melden |
| Doppelte Action-ID | Nicht erneut anwenden |
| `REVOKED` wieder zu `ACTIVE` für dieselbe ID | Abweisen |
| Falsche `identity_id` oder Domain Separation | Abweisen |
| Manipulierter Berechtigungsumfang nach Signatur | Abweisen |
| Veralteter Zustand nach bereits bekannter Generation | Warnung und fail-closed |
| Unterschiedliche Geräteverzeichnisse gleicher Generation | Alarm; Split View nicht automatisch auflösbar |
| Relay liefert falschen neuen Geräteschlüssel | Signatur-/Pinningfehler, keine stillschweigende Akzeptanz |
| Jede identitätserhaltende Recovery-Anfrage in dieser Version, auch mit signiertem angeblichem Recovery-Nachweis | Abweisen gemäß `NO_RECOVERY` |
| Recovery-Schlüssel versucht Backup zu öffnen | Abweisen |
| Verifizierter Kontakt hat unerklärten Root-Wechsel | Nachrichtenstopp und Re-Verifikation |
| Offline-Gerät nach Widerruf | Keine Behauptung garantierter Fernlöschung |
| Alter Root-Key versucht nach Totalausfall ein neues Messaging-Gerät hinzuzufügen | Abweisen; neue Identität erforderlich |
| Root vergibt Managerrecht an neues oder nicht mehr verfügbares Gerät | Abweisen; kein Umgehen der Geräteaufnahme |
| Backup oder erneute Genesis reaktiviert alte Identitäts-/Manager-/Ratchet-Zustände | Abweisen beziehungsweise neue Verifikation und neue Identität gemäß Verlustfall verlangen |
| Relay bestätigt Veröffentlichung, aber Autorisierung oder Aktualitätsnachweis fehlt | Gerät nicht als `ACTIVE` akzeptieren |
| Widerruf verarbeitet, aber Protokoll kann neuen Empfängersatz nicht sicher herstellen | Betroffenen Versand sperren; keine neue Nachricht für widerrufenen Empfänger verschlüsseln |

## 11. Entscheidungsregister und Release-Gates

- **BESCHLOSSEN:** `NO_RECOVERY` nach Verlust aller autorisierten Geräte; Rollen- und Schlüsseltrennung; keine serverseitige Identitätsautorität; privilegierte Geräteverwaltung.
- **BESCHLOSSENE SPRACHE:** Python-Anwendungslogik und Server mit geprüften nativen Kryptobibliotheken; kein handgeschriebenes Python-Kryptoprotokoll.
- **OFFEN / Release-Blocker:** Wire-Encoding, genaue Keys/Suites (inkl. PQ-Strategie), sichere Root-Rotation, Durchsetzung von `NO_RECOVERY` über alle Autorisierungspfade, nicht äquivokationsfähiger Gerätehistorien-Nachweis, Pairing-Handshake, Zustandsfrische bei Offline-Geräten, plattformkonforme mobile Keystores, Integration der Chat-E2EE- und Gruppenprotokolle.
- **Release-Gate:** Kein Produktclaim „sicher für Whistleblower/Journalisten“ ohne unabhängiges Review, Integrationstests, Abuse-/Traffic-Analyse, transparente Known Limitations und externe Prüfung.

## 12. Quellen / Normative Referenzen

- OWASP Key Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet
- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- IETF MLS RFC 9420: https://www.rfc-editor.org/rfc/rfc9420
- Signal Double Ratchet: https://signal.org/docs/specifications/doubleratchet/

*Dieses Dokument ist ein prüfbarer Entwurf, keine Implementierung und kein Sicherheitszertifikat.*
