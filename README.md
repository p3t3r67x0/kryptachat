# Krypta – Konzept für einen sicheren dezentralen Messenger

Krypta soll vertraute Chatbedienung mit konsequenter Ende-zu-Ende-Verschlüsselung,
dezentraler Zustellung und Schutz von Kommunikationsmetadaten verbinden.
Die Zielgruppe sind Journalisten, Aktivisten, Whistleblower und Menschen mit
erhöhtem Schutzbedarf. Architekturentscheidungen richten sich nach dem
Bedrohungsmodell und werden vor der Umsetzung nachvollziehbar geprüft.

## Projektstand

Stand: 8. Oktober 2026. Das Projekt befindet sich in der Konzeptphase.
Die Verzeichnisse `app/` und `core/` sind leer. Es gibt noch keinen lauffähigen
Messenger und keinen Sicherheitsnachweis.

Festgelegt sind Python-Anwendungslogik und Server mit geprüften nativen
Kryptobibliotheken. Konkrete Plattformen, Bibliotheken und Protokoll-Stack
werden vor Implementierung geprüft und festgelegt. Die bisherige
`requirements.txt` ist keine freigegebene Abhängigkeitsauswahl.

## Sicherheitsdokumentation

- [Threat Model v1.0](security/threat-model.md): vollständige Projektfassung mit Assets, Angreifern, Anforderungen, Szenarien und Release-Gates.
- [Identity Protocol v1.0](security/identity-protocol.md): vollständige Projektfassung für Identitäten, Geräte, Kontakte und Widerruf.
- [Identity Authority Policy v1.0](security/identity-authority-policy.md): vollständige Projektfassung für Rollen, Managerrechte, Pairing und Autorisierungsprüfungen.
- [Security Review der Dokumentübernahme](security/review-2026-10-08.md): dokumentierte Anpassungen, Konflikte, Originalhashwerte und offene Entscheidungen.

Festgelegt ist `NO_RECOVERY`: Nach Verlust aller autorisierten Geräte wird eine
neue Identität angelegt. Kontakte müssen erneut verifizieren. Root-Key,
Backup, Server-Reset und Manager-Ernennung dürfen die Verlustentscheidung nicht
umgehen. Geräteersatz bei noch vorhandenem berechtigtem Gerät bleibt möglich.

Die Dokumente sind Architekturentwürfe und wurden nicht unabhängig auditiert.
Die [Originalvorlagen](security/references/README.md) sind unverändert aufbewahrt.
Der [frühere Autorisierungsvorschlag](security/archive/README.md) ist archiviert
und keine aktive Richtlinie. Für Projektentscheidungen gelten die drei
Projektfassungen und das Review.

## Weitere Konzeptarbeit

Wir klären Geräteverwaltungsrechte, Root-Rotation sowie Aktualitäts- und
Konsistenzbedingungen. Darauf bauen Messaging- und Relay-Protokoll auf.
Vor Hochrisiko-Einsatz gelten die im Bedrohungsmodell beschriebenen
Release-Gates einschließlich unabhängiger Prüfung und belegtem Metadatenschutz.
