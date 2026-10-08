# Secure Messenger — Identity Protocol v1.0

**Datum:** 2026-10-08  
**Status:** Architekturentwurf; **nicht implementiert, nicht formal verifiziert, nicht auditiert**  
**Abhängigkeit:** [Threat Model v1.0](secure-messenger-threat-model-v1.0.md)  
**Geltungsbereich:** Identitäten, Geräte, Kontakte, Verifikation, Widerruf und Recovery. Nicht: vollständiger Entwurf des Nachrichten-, Relay- oder MLS-Protokolls.

## 1. Normative Sprache und Designziele

**MUSS** bezeichnet eine verbindliche Sicherheitsanforderung vor einem sicherheitsbeanspruchenden Release; **SOLL** eine stark priorisierte Anforderung; **OFFEN** eine noch zu prüfende Entscheidung. Kein hier genanntes Verfahren ist allein dadurch sicher implementiert.

- Keine Telefonnummer, E-Mail-Adresse, zentrale Registrierung oder globale Suchbarkeit.
- Private Kontaktaufnahme per QR/Einladung als Standard; freiwillige widerrufbare öffentliche Kontaktadressen.
- Geräte sind unabhängig onlinefähig, haben individuelle Schlüssel und werden explizit autorisiert.
- Relays sind untrusted, einschließlich aktiver Manipulation, Verzögerung, Replay, Split View, Zensur und Metadatenanalyse.
- Kontoverwaltung, Nachrichteninhalte, Backups und Relay-Routing erhalten getrennte Schlüssel und Vertrauensdomänen.
- Jeder behauptete Schutz gegen Metadatenkorrelation bedarf eines eigenen Nachweises.

## 2. Vertrauensobjekte und Schlüsselklassen

| Kennung | Objekt | Aufgabe / Schutz |
|---|---|---|
| `identity_id` | Lokal erzeugter, aus einem kanonisch codierten öffentlichen Vertrauensanker abgeleiteter Bezeichner (domain-separated Hash) | Keine Personenkennung und keine routbare Serveradresse; nur bei Bedarf Kontakten mitteilen |
| `identity_authority` | Langfristiger öffentlicher Autorisierungsschlüssel und geschütztes privates Gegenstück | Bestätigt initiale Geräteautorität und geregelte Schlüsselrotation; **nicht** für gewöhnliche Nachrichten verwenden |
| `device_id` | Zufällige, nicht sprechende Kennung pro Gerät | Nur im notwendigem Geltungsbereich teilen; globale Korrelation vermeiden |
| `device_auth_key` | Gerätespezifischer Signaturschlüssel | Signiert sicherheitskritische Geräteaktionen unter festgelegter Autorisierungspolitik |
| `session_identity` | Pro Gerät geeigneter Identitäts-/Handshake-Schlüssel gemäß gewähltem Nachrichtenprotokoll | Nicht stillschweigend mit obigem Signaturschlüssel austauschbar |
| `prekeys` | Kurz- oder einmalig verwendbare Handshake-Materialien | Signatur, Gültigkeit, Lifecycle und Löschung nach Protokollspezifikation |
| `recovery_secret` | Optional, hochentropisch, getrennt geschützt | Ausschließlich zur autorisierten Identitätsrettung, nie direkt als Chat- oder Backup-Schlüssel |
| `backup_key` | Optional und unabhängig | Schutz explizit zugelassener Backups; alte Nachrichten bleiben ohne separaten Backup-Zugang unzugänglich |

**Kritische Integrationsfrage:** PQXDH verwendet in seiner Spezifikation einen X25519/XEdDSA-Identitätsbezug; ein vorgeschlagener Ed25519-Geräte- oder Root-Signaturschlüssel ist **nicht** automatisch derselbe Schlüssel. Die genaue kryptografische Bindung zwischen Account-Identität, Protokoll-Identität und Geräteschlüsseln muss vor Code-Freigabe spezifiziert und unabhängig überprüft werden. Keine ad-hoc-Konvertierung, kein unanalysierter Schlüsseltausch zwischen Rollen.

## 3. Zustandsmodell

Identität: `ACTIVE` → `RECOVERY_PENDING` → `ACTIVE` mit neuer autorisierter Gerätegeneration; zusätzlich `RETIRED` (Identität nicht mehr genutzt).  
Gerät: `PROPOSED` → `AUTHORIZED` → `REVOKED`. `REVOKED` ist irreversibel für dieselbe Gerätekennung.  
Kontakt: `UNVERIFIED` → `VERIFIED`; kritischer Identitäts-/Gerätebruch → `BLOCKED_PENDING_REVERIFICATION`. Der Status `VERIFIED` darf nicht durch einen Server-Reply allein wiederhergestellt werden.

Alle Zustandsübergänge müssen eine explizite, prüfbare Autorisierung, Bindung an die Identität, Versions-/Generationskontrolle und Replay-Schutz besitzen.

## 4. Kanonisches Geräteverzeichnis

Vorgeschlagenes *logisches* Schema (keine finale Wire-Encoding-Festlegung):

```json
{
  "schema": "identity-device-state-v1",
  "identity_id": "<derived-id>",
  "generation": 12,
  "previous_state_hash": "<hash>",
  "authorized_devices": [
    {
      "device_id": "<random>",
      "device_auth_public_key": "<encoded-key>",
      "session_identity_public_key": "<encoded-key>",
      "capabilities": ["messaging"]
    }
  ],
  "revoked_device_ids": ["<device-id>"],
  "authorization": "<verifiable-authority-proof>"
}
```

**MUSS:** Signaturen über eine eindeutig kanonisierte Binärdarstellung (inkl. Protokollkennung, Version, Zweck, Identität, Generation und vorherigem Hash); keine unbestimmte JSON-Signatur über Text. Validierung von Größen, Duplikaten, Reihenfolge, Algorithmen und Versionsabfolgen. Kritische Datensätze benötigen eine konfliktresistente monotone Verlaufskontrolle.

**MUSS:** Relay-induzierte Rollbacks, Forks und Split Views erkennen bzw. sicher behandeln. Ein einfacher Hash-Chain-Verlauf verhindert **nicht** allein, dass ein Server verschiedenen Empfängern unterschiedliche gültig signierte Verläufe präsentiert. Als Kandidaten prüfen: unabhängige Witnesses, Gossip zwischen verifizierten Geräten/Kontakten, append-only Transparency-Logs mit überprüfbarer Konsistenz. Datenschutz-/Linkability-Kosten dieser Techniken getrennt evaluieren.

**Fail closed:** Bei neuer unbekannter Gerätegeneration, ungültiger Signatur, Rollback oder nicht auflösbarem Fork keine neuen sensitiven Nachrichten an strittige Geräte versenden. Bestehende verifizierte sichere Zustände dürfen nicht stillschweigend ersetzt werden.

## 5. Identität erstellen

1. Lokal mit betriebssystemgestützter CSPRNG Schlüssel und Zufallskennungen erzeugen.
2. Identitäts-Vertrauensanker und mindestens einen autorisierten Geräteschlüssel initialisieren.
3. `generation=0` signiert und lokal geschützt anlegen.
4. Private Identitäts- und Geräteschlüssel niemals zu einem Relay hochladen.
5. Recovery nur nach informierter Entscheidung aktivieren, mit getrennter Hochentropie-Sicherung.
6. Privaten Kontaktmodus und minimale Sichtbarkeit als Default setzen.

**OFFEN:** Lebenszyklus/Verfügbarkeit der Root-Autorität (offline root vs. Hardware-gebundener Wiederherstellungsanker), konkrete Algorithmen und Kanonisierung. Root-Verfügbarkeit darf nicht unbemerkt mit dem Verlust eines einzelnen Endgeräts gekoppelt sein.

## 6. Privater Kontaktaufbau und Verifikation

1. Ersteller erzeugt einen zufälligen, zweckgebundenen, optional einmaligen und zeitlich begrenzten Einladungs-Token.
2. QR-Code enthält nur erforderliche Kontaktaufnahme- und Authentisierungsinformationen; keine versteckte Kontaktliste.
3. Kontakt erhält eine Einladungsanfrage; vor Freigabe keine automatische Offenlegung weiterer Kontakte oder Geräteinformationen.
4. Beide Seiten vergleichen über einen *authentisierten* Kanal eine kanonisch abgeleitete Identitätsbindung (z. B. QR in Person). Ein QR-Code aus einem manipulierten digitalen Kanal ist alleine kein Identitätsbeweis.
5. Erfolgreiche Verifikation wird lokal als Identitätsanker (inkl. bestätigter Version/Schlüsselbindung) gespeichert.
6. Änderungen am verifizierten Vertrauensanker, unerwartete Gerätezusätze oder nicht auflösbare Zustandskonflikte blockieren Versand bis zur erneuten Prüfung.

**OFFEN:** Separater, konsistenter UX-Pfad für geplante Geräteergänzungen: Kontaktwarnung bei jeder Ergänzung vs. automatisch akzeptierte, nachgewiesen legitimierte Ergänzung mit gut sichtbarem Verlauf. Für Hochrisikokontakte gilt konservativer Blockiermodus.

## 7. Neues Gerät autorisieren

1. Neues Gerät generiert seine privaten Schlüssel *selbst* und zeigt einen kurzlebigen Pairing-QR-Code mit öffentlichem Schlüssel, Nonce und Sitzungsbindung.
2. Autorisiertes Gerät scannt den Code. Beide Geräte prüfen eine wechselseitige, gegen MITM abgesicherte Bindung; idealerweise mit zusätzlichem lokalem Bestätigungsschritt.
3. Nutzer bestätigt Geräteart, Fingerprint und geplante Rechte bewusst am autorisierten Gerät.
4. Signierte Autorisierung enthält Gerätekennung, Schlüssel, Zweck, Ablaufgrenzen, Generation, Nonces und Anti-Replay-Bindung.
5. Neuer Gerätezustand wird konflikt- und rollback-sicher veröffentlicht; andere eigene Geräte verifizieren und übernehmen ihn.
6. Kontakte behandeln die Geräteänderung nach ihrer Verifikationspolitik; unbestätigte Änderungen dürfen nicht still in vertrauliche Kommunikation gelangen.

**MUSS:** Relay allein kann keine gültige Autorisierung erzeugen. QR-Code ist nicht selbst Autorisierung. Gerät darf nach Ablauf/Replay oder fehlender Bestätigung nicht aufgenommen werden.

## 8. Gerätewiderruf und kompromittierte Geräte

- Ein verbleibendes autorisiertes Gerät kann nach einer noch festzulegenden, eskalationsfesten Autorisierungspolitik einen Widerruf auslösen.
- Neuer Zustand entfernt das Gerät aus aktivem Empfängersatz; neue Sitzungen und Gruppengeheimnisse müssen sicher neu abgeleitet/verteilt werden.
- Kontakte und andere Geräte müssen Widerruf und neue Generation verifizieren. Solange der Widerruf nicht überall angekommen ist, besteht ein Zustellfenster.
- Gerätewiderruf kann zuvor lokal gespeicherte Klartexte oder bereits heruntergeladene Schlüssel **nicht** zurückholen.
- Bei vermutetem kompromittiertem autorisiertem Gerät muss ein stärkeres Quarantäne- und Re-Key-Verfahren greifen; ein einfacher Signatur-Nachweis durch dieses Gerät genügt dann nicht als Vertrauensanker.
- **OFFEN:** Angreifer kann ein autorisiertes Gerät kontrollieren und konkurrierende gültige Zustandsupdates signieren. Policy für Konflikt, Root-Quorum, Identitätsrettung und Kontaktneuverifikation ist vor Implementierung festzulegen.

## 9. Wiederherstellung ohne zentralen Betreiber

Drei Modi:

- `NO_RECOVERY`: Verlust aller Geräte/Schlüssel bedeutet Verlust der Identität.
- `RECOVERY_KEY`: Optional lokal generiertes, ausreichend zufälliges Recovery-Geheimnis, das separat und offline verwahrt wird. Kein passwortabgeleiteter Low-Entropy-Key ohne starkes zusätzliches Schutzmodell.
- `THRESHOLD_RECOVERY`: Aufteilung in unabhängige Anteile (z. B. 2-von-3), verteilt auf eigenständige Verwahrungsorte/Personen mit ausdrücklichem Einverständnis.

**MUSS:** Recovery ist ein privilegierter Übergang mit an Nutzer und Kontakte sichtbarer Gerätegeneration, Sperrung aller verlorenen Geräte, Replay-/Fork-Schutz und definiertem Umgang mit verlorenen/gestohlenen Recovery-Anteilen. Recovery ist kein gewöhnlicher Login.

**MUSS:** Ohne separates Backup kann Recovery **keine** alten Nachrichten wiederherstellen. Separate E2EE-Backup-Architektur benötigt ein eigenes Threat Model.

**OFFEN / besonders kritisch:** Recovery-Autorität versus Alltags-Geräteautorität, Umgehung durch kompromittiertes altes Gerät, Missbrauch gestohlener Recovery-Anteile, Frist-/Quorumverfahren und anonyme Veröffentlichung der Recovery-Ereignisse. Bis zur Lösung keine verbindliche Aussage, dass Wiederherstellung und kompromittierte Geräte gleichzeitig sicher beherrscht werden.

## 10. Öffentliche Kontaktadressen

- Explizites Opt-in, getrennt von `identity_id` und privaten Relays/Postfächern.
- Mehrere unabhängig widerrufbare Einladungsendpunkte, Spam- und Abuse-Schutz ohne verpflichtende Telefonnummer.
- Korrelation durch Wiederverwendung, Hostnamen, Anfragezeitpunkte und Zustellwege bleibt möglich.
- Öffentliche Einladung bestätigt keine menschliche Identität und darf nicht automatisch Kontaktverifikation herstellen.

## 11. Netzwerk-, Relay- und Log-Datenschutz

- In Identitätsobjekten keine IP-Adressen, Klarnamen, Postfach-URLs oder dauerhaften global routbaren Kennungen festschreiben.
- Verteilung von Geräteverzeichnissen nur an berechtigte Kontakte; Zugriffskontrolle/Lookup darf nicht selbst den Kontaktgraphen offenlegen.
- Netzweganonymität und Traffic-Korrelation gehören ins folgende Relay Protocol und erhalten eigenständige Nachweise.
- Sicherheitstelemetrie standardmäßig aus; sicherheitsrelevante lokale Audit-Ereignisse ohne unnötige identifizierende Serverlogs.
- Keine Sicherheitsbehauptung, dass bloßer Verzicht auf Telefonnummer oder Verwendung von Tor vollständige Anonymität bietet.

## 12. Konkrete Angriffsfälle und erwartetes Verhalten

| Fall | Angriff | Erwartung |
|---|---|---|
| ID-T01 | Relay liefert fremden Device-Key | Ablehnung; keine Nachricht an nicht autorisierten Schlüssel |
| ID-T02 | Replay einer gültigen alten Geräteliste | Rollback erkannt oder sicher blockiert |
| ID-T03 | Relay zeigt Alice und Bob unterschiedliche signierte Zustände | Fork-Erkennung durch explizites Konsistenzverfahren; bis dahin keine starke Split-View-Garantie |
| ID-T04 | Manipulierter QR-Code | MITM-Prüfung/Verifikationsschritt verhindert unbemerkte falsche Identitätsbindung |
| ID-T05 | Wiederverwendung eines Pairing-Tokens | Zweite Nutzung abgelehnt |
| ID-T06 | Bösartiger Server ergänzt neues Gerät | Ohne gültige Autorisierung unmöglich |
| ID-T07 | Gestohlenes, gesperrtes Gerät | Hardware-/OS-Schutz und Datenverschlüsselung greifen innerhalb der dokumentierten Grenzen |
| ID-T08 | Kompromittiertes entsperrtes Gerät | Keine unrealistische Klartextgarantie; Quarantäne/Widerruf/Rotation möglich |
| ID-T09 | Alte Gerätegeneration nach Recovery | Neue Nachrichten werden nicht an alte Geräte verschlüsselt, sobald neue Generation verifiziert ist |
| ID-T10 | Recovery-Key wird gestohlen | Sicherheitsfolgen transparent; restriktive Policy/Schutzmechanismen notwendig, noch OFFEN |
| ID-T11 | Backup-Server kompromittiert | Ohne unabhängigen Backup-Key keine alten Nachrichten entschlüsselbar |
| ID-T12 | Angreifer enumeriert öffentliche Einladungen | Hohe Entropie, Rate Limits, widerrufbare Adressen; Abuse-Prüfung |
| ID-T13 | Verbindung wird beobachtet | Inhalte geschützt, Linkability nur soweit durch Relay-/Transportnachweis gedeckt |
| ID-T14 | Gerät widerrufen, Offline-Messages liegen noch im Netz | Schlüssel-/Empfängervalidierung und explizite Rest-Risiko-Erklärung |

## 13. Verbindliche Abnahmekriterien vor Implementierungsfreigabe

- [ ] Kryptografische Bindung von Root-, Geräte- und PQXDH-/Messaging-Identitäten spezifiziert und begutachtet.
- [ ] Autorisierungsregeln für Hinzufügen, Widerruf, Rotation und Recovery sind deterministisch; keine widersprüchlichen Signaturpfade.
- [ ] Konsistenzmodell gegen Rollback/Fork/Split View einschließlich Datenschutzanalyse festgelegt.
- [ ] Client-Zustandsmaschine mit Fail-Closed-Übergängen definiert; kein unbemerkter Vertrauensverlust.
- [ ] Kanonische Codierung, Schlüssel-/Signaturalgorithmen, Domain Separation und Versionsverhandlung definiert.
- [ ] Pairing-Protokoll mit MITM-, Replay- und Race-Tests spezifiziert.
- [ ] Recovery-Protokoll und Grenzen bei vollständiger Gerätekompromittierung separat geprüft.
- [ ] Automatisierte Negativtests für sämtliche Fälle ID-T01 bis ID-T14.
- [ ] Unabhängiges Security Review vor Nutzung durch Hochrisikopersonen.

## 14. Nächste Architekturentscheidungen (in dieser Reihenfolge)

1. **Authority Policy:** Offline Root / Recovery Root / Gerätequorum – welche Akteure können welche Zustände verbindlich ändern?
2. **Device State Consistency:** Welcher konkrete Mechanismus verhindert unbemerkte Forks bei bösartigen Relays, ohne den Kontaktgraphen unnötig offenzulegen?
3. **Cryptographic Binding:** Wie werden Messaging-Protokollidentitäten sauber an Geräte und Identität gebunden?
4. **Wire Format + Rust API:** Erst nach den obigen drei Entscheidungen festlegen; Prototypen dürfen keine produktiven Sicherheitszusagen machen.

## Quellen zur technischen Einordnung

- Signal, PQXDH: https://signal.org/docs/specifications/pqxdh/
- Signal-Protokoll-Spezifikationen inkl. Sesame: https://signal.org/docs/
- IETF RFC 9420, Messaging Layer Security: https://www.rfc-editor.org/rfc/rfc9420
- Übergeordnetes Bedrohungsmodell: `security/threat-model.md` (im künftigen Repository)

**Hinweis:** Dieses Dokument ist ein *Design- und Prüfkatalog*, kein fertiger eigener kryptografischer Standard. Einzelne Anforderungen sind bewusst als OFFEN gekennzeichnet; insbesondere Recovery, Gerätequorum und Konsistenzschutz dürfen nicht mit bloßen Implementierungsdetails verwechselt werden.
