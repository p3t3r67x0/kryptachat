# Krypta – Identity Authority Policy v1.0

**Stand:** 8. Oktober 2026  
**Status:** Arbeitsentwurf zur gemeinsamen Entscheidung; nicht implementiert und nicht auditiert  
**Archivstatus:** Früherer Vorschlag, keine aktive Projektrichtlinie. Die relativen Verweise zeigen auf die heutigen Projektfassungen.  
**Grundlagen:** [Bedrohungsmodell](../threat-model.md) und [Identitätskonzept](../identity-protocol.md)

Dieses Dokument schlägt vor, wer Geräte hinzufügen, Rechte ändern und Schlüssel
widerrufen darf. Die Entscheidung gegen eine Wiederherstellung der alten
Identität nach Verlust aller Geräte ist bereits festgelegt. Die übrige
Berechtigungspolitik ist ein konkreter Vorschlag zur Prüfung. Die Kennungen
`AP-*` und `AT-*` wurden hier neu vergeben; die Zuordnung zum vollständigen
Bedrohungsmodell steht noch aus.

## 1. Sicherheitsbedingungen und Grenzen

Die Ziele gegenüber A1 und A2 setzen korrekte Endgeräte, geheim gehaltene
Schlüssel, sichere Zufallsquellen, gültige kryptografische Annahmen und eine
authentische Kontaktprüfung voraus. Serverbehauptungen begründen kein Vertrauen.
Ein berechtigter Empfänger kann Klartext weitergeben; das Protokoll kann ihm
dies technisch nicht untersagen. Ein dauerhaft kompromittiertes Endgerät
kann Inhalte und seine eigenen Rechte missbrauchen.

Forward Secrecy schützt aufgezeichneten Netzwerkverkehr nach Löschung alter
Nachrichtenschlüssel. Sie schützt nicht automatisch gespeicherte Chatverläufe
oder Backups. Schlüsselautorisierung und Nachrichtenverschlüsselung sind
verschiedene Funktionen.

Die Widerstandsfähigkeit setzt mindestens einen erreichbaren funktionierenden
Zustellweg voraus. Ein Server kann Nachrichten oder Widerrufe unterdrücken.
Die Richtlinie darf daher keine sofortige globale Wirksamkeit bei
vollständiger Isolation behaupten.

## 2. Vorgeschlagene Autorisierungsarchitektur

### 2.1 Rollen

| Rolle | Rechte | Einschränkung |
|---|---|---|
| Identitäts-Vertrauensanker | Bestätigt die erstmalige Politik, neue Geräte und Verwaltungsrechte | Sein privater Schlüssel wird getrennt von gewöhnlichen Nachrichtenclients geschützt; allein kann er nach der Einrichtung keine neuen Geräte zulassen |
| Verwaltungsgerät | Beantragt und bestätigt Geräteänderungen im ausdrücklich gewährten Umfang | Besitzt ein eigenes Verwaltungsrecht; jede Erweiterung braucht zusätzlich den Vertrauensanker |
| Nachrichtengerät | Sendet und empfängt mit eigenen Geräte- und Sitzungsschlüsseln | Darf keine weiteren Geräte, Verwaltungsrechte oder Ersatzanker autorisieren |
| Kontaktgerät | Prüft den Kontaktanker und die Geräteberechtigungen seines Gegenübers | Übernimmt keine Rechte allein aufgrund einer Relay-Antwort |
| Relay | Puffert und transportiert geschützte Daten | Keine Identitäts-, Geräte- oder Wiederherstellungsrechte |

Das erste Verwaltungsgerät wird bei der lokalen Ersteinrichtung ausdrücklich
bestimmt. Die Einrichtung schafft eine neue Identität; sie stellt keine
bereits verifizierte Identität wieder her. Kontakte müssen den entstehenden
Vertrauensanker authentisch prüfen, bevor vertrauliche Kommunikation beginnt.
Ein bereits verifizierter Kontakt darf eine erneute Ersteinrichtung unter
seinem bisherigen Anker nicht als Ersatz seines gespeicherten Zustands
akzeptieren. Der anfängliche Prüfablauf bindet auch die Politik und den
aktuellen Gerätezustand.

### 2.2 Zwei Bestätigungen für Rechteerweiterungen

Nach der Ersteinrichtung braucht ein neues Gerät:

1. nachgewiesenen Besitz seiner neu erzeugten Geräteschlüssel;
2. eine ausdrückliche Bestätigung durch ein gültiges Verwaltungsgerät;
3. eine zusätzliche Bestätigung durch den geschützten Identitäts-Vertrauensanker;
4. die erfolgreiche Übernahme des authentischen aktuellen Gerätezustands;
5. die in Abschnitt 4 definierte Freigabe durch bestehende Kontakte.

Das sind zwei Autorisierungsrollen einer Person, kein Mehrpersonenprinzip.
Ihre kryptografische Umsetzung wird aus geprüften Verfahren ausgewählt;
dieses Dokument entwirft kein eigenes Schwellensignaturverfahren.

Die beiden Autorisierungsgeheimnisse müssen in getrennten Schutzbereichen
liegen. Zwei Schlüssel im selben kompromittierten Nachrichtenprozess erfüllen
diesen Schutz nicht. Die konkrete Umsetzung mit separatem Gerät oder
geeignetem Sicherheitsschlüssel und deren Bedienbarkeit bleibt festzulegen.
Die Bestätigung am Anker muss den konkreten Vorgang auf einer vertrauenswürdigen
Anzeige erkennen lassen. Ein unbeschrifteter Tastendruck allein belegt keine
informierte Gerätefreigabe; die Eignung gewöhnlicher Hardwaretoken ist daher
nicht vorausgesetzt.

Ein kompromittiertes Nachrichtengerät kann seine Nachrichten lesen, aber keine
neuen Geräte hinzufügen. Ein kompromittiertes Verwaltungsgerät kann
Änderungen beantragen, ohne den Vertrauensanker jedoch keine Rechte erweitern.
Ein gestohlener Anker allein reicht ebenfalls nicht zur Geräteerweiterung.
Sind beide Autorisierungsrollen kompromittiert, lässt sich eine unerlaubte
Freigabe nicht allein anhand ihrer gültigen Bestätigungen unterscheiden.

### 2.3 Entscheidungen je Vorgang

| Vorgang | Erforderliche Autorisierung | Reaktion anderer Clients |
|---|---|---|
| Neues Nachrichtengerät | Verwaltungsgerät und Vertrauensanker; Besitznachweis des neuen Geräts | Änderung prüfen; Kontaktfreigabe abwarten; neue Sitzungen aufbauen |
| Neues Verwaltungsgerät oder Rechteerweiterung | Verwaltungsgerät und Vertrauensanker; ausdrückliche Anzeige der erweiterten Rechte | Keine automatische Vererbung von Verwaltungsrechten |
| Geräteersatz oder Wechsel eines Geräteidentitätsschlüssels | Wie Aufnahme eines neuen Geräts; bisheriges Gerät gesondert widerrufen | Versand bis zur vorgesehenen Bestätigung pausieren |
| Eigenes Gerät widerrufen | Betroffenes Gerät selbst oder gültiges Verwaltungsgerät | Nach gültiger Verarbeitung nicht mehr als neuer Empfänger zulassen |
| Anderes Nachrichtengerät widerrufen | Gültiges Verwaltungsgerät | Sitzungen und betroffene Gruppen aktualisieren |
| Verwaltungsgerät widerrufen | Vertrauensanker zusammen mit einem anderen gültigen Verwaltungsgerät oder Selbstwiderruf | Verbleibende Verwaltungsfähigkeit ausdrücklich prüfen |
| Vertrauensanker ersetzen | Für diese erste Richtlinie neue Identität und unabhängige erneute Kontaktverifikation | Keine automatische Kontinuität aufgrund einer Signatur des alten Ankers |
| Routinewechsel von Prekeys und Sitzungsschlüsseln | Berechtigtes Gerät nach Regeln des geprüften Messaging-Protokolls | Kein Ersatz des Kontaktankers und keine neuen Rechte |
| Relay oder Offline-Postfach wechseln | Betroffenes berechtigtes Gerät authentisiert die Transportänderung | Identität bleibt erhalten; keine Erweiterung der Empfängerrechte |
| Alle autorisierten Geräte verloren | Neue Identität | Kontakte prüfen erneut; kein Reset auf die alte Identität |

Widerrufe sind bewusst leichter als Rechteerweiterungen. Ein kompromittiertes
Verwaltungsgerät kann dadurch berechtigte Nachrichtengeräte ausschließen
und die Kommunikation stören. Es erhält dadurch keine Leserechte für neue
Geräte. Ein Angreifer kann ebenso einen Selbstwiderruf auslösen. Dieser
Verfügbarkeitsnachteil ist eine ausdrückliche Konsequenz des Vorschlags.

Wenn nur Nachrichtengeräte verbleiben und sämtliche Verwaltungsrechte verloren
sind, dürfen die verbleibenden Geräte im Rahmen ihrer noch gültigen Rechte
kommunizieren. Sie können sich nicht selbst zu Verwaltungsgeräten machen.
Für eine spätere Erweiterung ist eine neue Identität mit erneuter Verifikation
nötig. Auch dies ist eine strengere, noch zu bestätigende Produktentscheidung.

Nach Verlust aller Geräte widerruft die Neuanlage einer Identität die alte
Identität nicht automatisch. Kontakte müssen über einen authentischen
unabhängigen Kanal informiert werden und den alten Kontakt lokal sperren.
Noch nicht informierte Kontakte können innerhalb der verbleibenden Gültigkeit
weiter für alte Geräte verschlüsseln. Ein früherer Identitätsanker darf dabei
nicht unbemerkt als Vertrauensanker der neuen Identität verwendet werden.

## 3. Geräteberechtigungen und Zustandsänderungen

Eine Geräteberechtigung muss den Identitätskontext, die konkreten öffentlichen
Geräteschlüssel, die erlaubten Aktionen, Protokollversion und Algorithmensuite
authentisch binden. Der Besitz eines Geräteschlüssels beweist allein keine
Verwaltungsberechtigung. Koppeln darf private Geräte-, Anker- oder
Ratchet-Schlüssel nicht klonen.

Jede Änderung betrifft den vollständigen maßgeblichen Gerätezustand mit
Version, Vorgängerbindung, aktiven Geräten, Rechten und Gültigkeitsbedingungen.
Die Bestätigungen müssen genau dieselbe Änderung autorisieren. Eine Freigabe
für Gerät A darf nicht für Gerät B oder für weitergehende Rechte verwendbar sein.
Die Verwaltungsinstanz muss Konflikte und parallele Anträge ausdrücklich
auflösen; sie darf dieselbe Zustandsversion nicht widersprüchlich freigeben.

Frische, einmalige Kopplungsanfragen und authentisch geprüfte Kanäle verhindern
das Wiederverwenden alter Kopplungsfreigaben. Exakte Formate, Bindungen und
atomare Zustandsübernahme müssen vor Implementierungsfreigabe spezifiziert
werden. Eine Versionsnummer oder Hashkette allein ist kein Konsensverfahren.

Gerätezustand und unverarbeitete Freigaben dürfen nach einem Absturz oder
Backup-Rückspielen nicht unbemerkt zurückgesetzt werden. Ein Client ohne
verlässlichen Ausgangszustand muss diesen erneut authentisch prüfen und neue
Nachrichtensitzungen aufbauen. Alte Ratchet-Zustände werden nicht zum Versand
reaktiviert.

## 4. Kontaktverifikation und Änderungen

Vertrauliche Nutzdaten werden erst nach authentischer Zuordnung des
Kontaktankers und Prüfung der zugelassenen Geräte freigegeben. Eine Einladung,
ein Anzeigename oder ein vom Relay gelieferter QR-Code beweist keine Person.
Die Prüfung erfolgt persönlich oder über einen bereits authentischen
unabhängigen Kanal und bindet beide Gesprächspartner, Schlüssel und Kontext.

Im vorgeschlagenen strengen Profil muss ein bestehender Kontakt jedes neue
Empfängergerät bewusst über einen authentischen Prüfkanal bestätigen. Bis
dahin pausiert der Versand im betroffenen Kontakt. Diese zusätzliche Hürde
begrenzt auch Schäden einer kompromittierten Autorisierungsarchitektur; sie
schützt nicht, wenn die Kontaktprüfung selbst auf einem kompromittierten
Endgerät durchgeführt wird.

| Lokaler Zustand | Nutzdatenversand |
|---|---|
| Angefragt oder unverifiziert | Gesperrt; nur notwendige Prüfprotokolldaten zulässig |
| Verifiziert mit gültigem Gerätezustand | Für die bestätigten aktiven Geräte erlaubt |
| Kritische Änderung ausstehend | Betroffener Kontakt pausiert bis zur Bestätigung |
| Gerätezustand abgelaufen oder Zeit unprüfbar | Gesperrt bis zur Aktualisierung |
| Widerspruch oder bekannte Rücksetzung erkannt | Gesperrt bis zur unabhängigen Klärung |
| Kontakt beendet | Gesperrt |

Die Zustände sind lokale Bewertungen. „Verifiziert“ darf nicht behaupten,
dass kein noch unbekannter Widerruf existiert. Ein Vertrauensankerwechsel nach
Kompromittierung braucht ein bereinigtes Gerät und eine neue unabhängige
Verifikation; eine Signatur des gestohlenen alten Ankers genügt nicht.

## 5. Aktualität, Widersprüche und Widerrufe

Eine Signatur beweist Herkunft und Unverändertheit, nicht Aktualität.
Clients verwerfen Rückschritte gegenüber ihrem akzeptierten Zustand und
sperren bei zwei unvereinbaren authentischen Zuständen derselben Version
im selben Identitätskontext. Neue Clients können eine alte, aber korrekt
signierte Historie ohne authentischen Ausgangspunkt nicht als aktuell erkennen.

Für zurückgehaltene, noch unbekannte Widerrufe brauchen wir eine gesonderte
Aktualitätspolitik. Vor Freigabe werden konkrete Werte für maximale
Zustandsgültigkeit `T_state`, zulässige Uhrenabweichung `E_clock`, Prüfzeitpunkte
und Neustartverhalten festgelegt. Nach Ablauf oder bei unprüfbarer Zeit
sperrt der Client neue Nutzdaten. Vom Relay behauptete Zeit genügt nicht.

Eine maximale Widerrufsverzögerung wird erst unter diesen festgelegten
Zeitannahmen zugesagt und gemessen. Bis dahin gibt es keine quantitative
Garantie. Kürzere Gültigkeit reduziert Offline-Komfort und kann durch
Unterdrückung neuer Zustände zur Kommunikationssperre führen.

Sobald ein Client einen gültigen Widerruf verarbeitet, darf er keine neuen
Nutzdaten für das widerrufene Gerät verschlüsseln. Alle betroffenen
Nachrichtensitzungen und Gruppen müssen nach ihren Protokollregeln erneuert
werden. Bereits gelesene Inhalte und verteilte Schlüssel lassen sich nicht
zurückholen. Verzögerte Nachrichten vor dem Widerruf brauchen eine eigene
Empfangspolitik im Messaging-Protokoll.

Zusätzliche Zustandsvergleiche über unabhängige Wege oder Key Transparency
werden geprüft. Sie benötigen explizite Annahmen zur Erreichbarkeit und zu
gegebenenfalls unabhängigen Prüfstellen. Vollständige Isolation verhindert
eine unbedingte Erkennungsgarantie für unterschiedliche Ansichten. Die
Konsistenzprüfung darf keine öffentlich verknüpfbare globale Identitäts- oder
Gerätedatenbank schaffen.

## 6. Datenschutz und Schlüsselablage

Identität und Verwaltungsrechte hängen nicht vom Relay ab. Transportänderungen
werden authentisiert, ohne den Kontaktanker zu ersetzen. Kontaktaufnahme
erfolgt standardmäßig über Einladungen. Die öffentliche Bereitstellung einer
globalen Identitätsdatenbank ist ausgeschlossen.

Kontaktanker, Gerätelisten, Freigaben und Verwaltungsnachrichten müssen
gegenüber Relays geschützt sein. TLS allein verbirgt einen Identitätsheader
nicht vor dem Server. Auch gleiche öffentliche Anker können Kontakte
untereinander verknüpfen; die Wahl von Personas und kontextbezogenen
Kennungen bleibt deshalb Teil der Identitätsprüfung.

Geheime Schlüssel und lokale Zustände erhalten plattformspezifisch geschützte
Speicherung. Hardwareunterstützung darf nur für tatsächlich unterstützte
Algorithmen und Geräte zugesagt werden. Crash-Berichte, Diagnoselogs und
Benachrichtigungen dürfen keine Schlüssel, Kopplungsgeheimnisse oder
ungeschützten Kontaktverzeichnisse enthalten. Schutz gegen physische Angriffe
hängt von der konkret freigegebenen Plattform und ihren Schutzmechanismen ab.

Neue Geräte erhalten neue Sitzungen. Sie bekommen durch die Kopplung weder
alte Nachrichtenschlüssel noch automatisch Chatverläufe. Ein Recovery-Key
existiert für die Wiederherstellung der alten Identität nach Totalausfall in
der ersten Version nicht. Ein späterer Verlaufsexport wäre eine eigenständige
Sicherheitsentscheidung.

## 7. Anforderungen des Arbeitsentwurfs

„MUSS“ und „DARF NICHT“ sind vorgeschlagene normative Anforderungen.
Die übermittelten Identitätsgrundsätze und die Entscheidung gegen
Wiederherstellung bei Totalausfall bilden die bereits festgelegte Grundlage.
Die konkreten Ergänzungen dieser Richtlinie, insbesondere die zwei
Autorisierungsrollen und die Kontaktbestätigung jedes neuen Geräts, sind vor
Implementierung gemeinsam festzulegen und unabhängig zu prüfen.

| Kennung | Anforderung |
|---|---|
| AP-01 | Server DÜRFEN NICHT Identitäten, Geräte oder Rechte beglaubigen; Relaywechsel MUSS die Identität erhalten. |
| AP-02 | Vertrauliche Nutzdaten MÜSSEN bis zur authentischen Kontakt- und Geräteprüfung gesperrt bleiben. |
| AP-03 | Geräte MÜSSEN eigene Schlüssel und Sitzungszustände besitzen; Kopplung DARF diese nicht klonen. |
| AP-04 | Neue Geräte und Rechteerweiterungen MÜSSEN die Bestätigung eines Verwaltungsgeräts und des getrennt geschützten Vertrauensankers erhalten. |
| AP-05 | Geräte MÜSSEN Schlüsselbesitz nachweisen; Rechte, Kontext, Version und Suite MÜSSEN authentisch gebunden sein. |
| AP-06 | Nachrichtenrechte DÜRFEN NICHT automatisch Verwaltungsrechte verleihen. |
| AP-07 | Kopplungsfreigaben MÜSSEN frisch, einmalig und an die konkreten Schlüssel und Rechte gebunden sein. |
| AP-08 | Verifizierte Kontakte MÜSSEN bei neuen Empfängergeräten und Ankerwechseln bis zur vorgesehenen erneuten Bestätigung pausieren. |
| AP-09 | Bekannte Rückschritte und unvereinbare authentische Gerätezustände MÜSSEN zur Sperre führen. |
| AP-10 | Clients MÜSSEN definierte Aktualitätsbedingungen prüfen und bei Ablauf oder unprüfbarer Zeit den Versand sperren. |
| AP-11 | Nach Verarbeitung eines gültigen Widerrufs DÜRFEN neue Nutzdaten NICHT für das widerrufene Gerät verschlüsselt werden. |
| AP-12 | Berechtigungsänderungen MÜSSEN alle betroffenen Sitzungen und Gruppen nach deren Protokollregeln aktualisieren. |
| AP-13 | Unsichere Backup- oder Zustandswiederherstellung MUSS neue Prüfung und Sitzungen auslösen; alte Ratchet-Zustände DÜRFEN NICHT zum Versand reaktiviert werden. |
| AP-14 | Neue Geräte DÜRFEN NICHT automatisch alte Nachrichtenschlüssel oder Chatverläufe erhalten. |
| AP-15 | Nach Verlust aller autorisierten Geräte MUSS eine neue Identität entstehen; Recovery-Key, Telefon, E-Mail und Support DÜRFEN NICHT die alte Identität wiederherstellen. |
| AP-16 | Identitäts- und Verwaltungsdaten MÜSSEN gegenüber Relays geschützt werden; eine öffentliche globale Identitätsdatenbank DARF NICHT entstehen. |
| AP-17 | Geheime Schlüssel und Kopplungsgeheimnisse DÜRFEN NICHT in Diagnoselogs oder Crash-Berichten erscheinen. |
| AP-18 | Sicherheitsrelevante Zustandsänderungen MÜSSEN atomar gespeichert werden; Fehler DÜRFEN NICHT einen stillen Downgrade auslösen. |

## 8. Angriffsszenarien und Prüfkriterien

Diese Testplanung beschreibt erwartetes Verhalten. Es existieren noch keine
erfolgreich ausgeführten Implementierungstests. Sie ist nicht die ausstehende
Liste von 14 Szenarien aus der angekündigten Identitätsspezifikation.

| Test | Angriff oder Prüffall | Erwartetes Ergebnis | Anforderungen |
|---|---|---|---|
| AT-01 | Relay ersetzt den verifizierten Kontaktanker. | Sperre; kein Nutzdatenversand an Ersatzschlüssel. | AP-01/02/08 |
| AT-02 | Einladungslink oder QR-Code wird ausgetauscht; unabhängiger Prüfkanal ist authentisch. | Kein automatisches Vertrauen; unabhängige Prüfung erkennt falsche Zuordnung. | AP-02/05 |
| AT-03 | Kompromittiertes Nachrichtengerät fügt ein Gerät hinzu. | Fehlende Verwaltungsrechte führen zur Ablehnung. | AP-04/06 |
| AT-04 | Verwaltungsgerät oder Vertrauensanker wird einzeln kompromittiert. | Rechteerweiterung ohne die andere gültige Autorisierung wird abgewiesen. | AP-04/05 |
| AT-05 | Alte Kopplungsfreigabe wird wiederverwendet oder auf andere Schlüssel angewendet. | Keine Autorisierung entsteht. | AP-05/07 |
| AT-06 | Relay liefert bekannte alte oder unvereinbare authentische Geräteinformationen. | Bekannter Rückschritt oder Konflikt führt zur Sperre. | AP-09 |
| AT-07 | Relay hält einen unbekannten Widerruf zurück; Zeit wird manipuliert oder Gerät isoliert. | Versand folgt der festgelegten Zeitpolitik; Ablauf und unprüfbare Zeit sperren; Verzögerung wird gemessen. | AP-10 |
| AT-08 | Gültiger Widerruf wird verarbeitet. | Keine neuen Nutzdaten an widerrufenen Schlüssel; Sitzungs- und Gruppenwechsel werden geprüft. | AP-11/12 |
| AT-09 | Frischer Client oder zurückgespieltes Backup erhält eine alte authentische Historie. | Keine ungeprüfte Zustandsübernahme oder Reaktivierung alter Ratchets. | AP-09/10/13 |
| AT-10 | Neues Gerät versucht alte Nachrichten zu lesen. | Kopplung liefert weder alte Schlüssel noch Verlauf. | AP-03/14 |
| AT-11 | Totalausfall; Angreifer verwendet Server-Reset, E-Mail oder angeblichen Recovery-Key. | Neue Identität und Kontaktprüfung erforderlich; alte Kontinuität nicht hergestellt. | AP-15 |
| AT-12 | Relaywechsel sowie Transport- und Crash-Aufzeichnung während der Kopplung. | Kontaktanker bleibt gleich; keine freigegebenen Geheimnisse oder ungeschützten Verwaltungsdaten beim Relay. | AP-01/16/17 |
| AT-13 | Geräteantrag erweitert Rechte oder verändert Suite, Version oder Kontext. | Authentische Prüfung schlägt fehl; keine Rechteausweitung oder Abwertung. | AP-05/06/18 |
| AT-14 | Parallele Anträge, Absturz oder Versand während eines Widerrufs. | Keine widersprüchlichen Freigaben oder halb übernommenen Zustände; atomare Verarbeitung. | AP-09/11/12/18 |

Die Tests benötigen definierte Plattformen, Angriffsumgebungen und dokumentierte
Ergebnisse. Positive Tests allein beweisen keine Protokollsicherheit.
Zustandsmaschine, Schlüsselbindung und kryptografische Integration müssen
zusätzlich unabhängig untersucht werden.

## 9. Vorhandene Verfahren als Grundlage

Unsere konkrete Autorisierungspolitik ist ein eigener Anwendungsentwurf.
Die folgenden Quellen begründen relevante Eigenschaften und Grenzen vorhandener
Verfahren, keine Sicherheitsgarantie für diesen Entwurf.

- [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/): Schlüsselprüfung über einen authentischen Kanal ist vorgesehen. Die Authentifizierung dieser Revision ist nicht post-quanten-sicher; Identitätsverwechslungen müssen zusätzlich betrachtet werden.
- [Signal Sesame](https://signal.org/docs/specifications/sesame/): Asynchrone Sitzungsverwaltung für mehrere Geräte; ersetzt keine Prüfung unserer Berechtigungs- und Datenschutzpolitik.
- [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html): Gerätezuordnung und Zugriffsregeln liegen bei der Anwendung. Neue MLS-Clients erhalten keine Historie automatisch; ein zusätzlicher Verlaufstransfer kann FS- und PCS-Eigenschaften schwächen.
- [Signal Key Transparency](https://signal.org/blog/automatic-key-verification/): Konsistenzprüfungen, unabhängige Prüfstellen und laufende Überwachung haben verschiedene Aufgaben; Konsistenz ist kein Nachweis einer bürgerlichen Identität.
- [Google Key Transparency](https://github.com/google/keytransparency/blob/master/docs/design.md): Dauerhafte Netzwerkisolation kann unterschiedliche Ansichten verbergen; Vergleichbarkeit ist eine notwendige Annahme für deren Erkennung.
- [SimpleX SMP](https://github.com/simplex-chat/simplexmq/blob/stable/protocol/simplex-messaging.md): Gerichtete Warteschlangen verwenden getrennte Sender- und Empfängerkennungen; deren Eignung für unsere Geräteverwaltung wird gesondert geprüft.

Quellenstand: 8. Oktober 2026. Veränderliche Spezifikationen und Bibliotheken
müssen vor Implementierung auf konkrete Revisionen festgelegt werden.
Die Wahl post-quanten-fähiger Verschlüsselung garantiert nicht automatisch
post-quanten-sichere Identitätsauthentifizierung.

## 10. Offene Entscheidungen vor Freigabe

1. Volltexte von Bedrohungsmodell und Identitätsspezifikation übernehmen und alle Anforderungen abgleichen.
2. Die zwei Autorisierungsrollen, ihren getrennten Schutz und die unabhängige Kontaktbestätigung neuer Geräte bestätigen oder begründet ändern.
3. Verwaltungsgeräteverlust, Notfallwiderruf und mögliche Verfügbarkeitseinbußen ausdrücklich entscheiden.
4. Konkrete Aktualitätsparameter, Uhrenannahmen, Neustartverhalten und den erlaubten Zeitraum veralteter Rechte festlegen.
5. Konsistenzverfahren und etwaige unabhängige Prüfstellen samt Vertrauensannahmen und Datenschutzwirkung auswählen.
6. Kontaktkontexte, Personas und Gruppenidentitäten festlegen; Verknüpfbarkeit und Bedienbarkeit prüfen.
7. Unterstützte Plattformen, sichere Speichermechanismen und geprüfte Protokollbibliotheken mit festen Versionen auswählen; aktive Quantenangreifer und Abstreitbarkeit gesondert bewerten.
8. Exakte Formate, Übergänge, Fehlerverhalten und atomare Speicherung spezifizieren und unabhängig prüfen.

Darauf bauen Messaging- und Relay-Spezifikation auf. Die Rust-Implementierung
beginnt erst nach Festlegung und Prüfung dieser Sicherheitsgrundlagen.
