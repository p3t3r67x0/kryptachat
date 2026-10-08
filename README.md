# Krypta – Konzept für einen sicheren dezentralen Messenger

Krypta soll vertraute Chatbedienung mit konsequenter Ende-zu-Ende-Verschlüsselung,
dezentraler Zustellung und Schutz von Kommunikationsmetadaten verbinden.
Die Zielgruppe sind Journalisten, Aktivisten, Whistleblower und Menschen mit
erhöhtem Schutzbedarf. Architekturentscheidungen richten sich nach dem
Bedrohungsmodell und werden vor der Umsetzung nachvollziehbar geprüft.

## Projektstand

Stand: 8. Oktober 2026. Neben den Architekturentwürfen gibt es einen ersten
isolierten Python-Identitätsprototyp unter `src/secure_messenger/identity/`.
Die Verzeichnisse `app/` und `core/` sind weiterhin leer. Es gibt keinen
lauffähigen Messenger und keinen unabhängigen Sicherheitsnachweis.

Der Prototyp verwendet Python 3.13+, Pydantic v2 und native Ed25519-Primitiven
über `cryptography`. Zustandsübernahmen nach Genesis bleiben standardmäßig
gesperrt, bis ein expliziter externer Aktualitätsprüfer eingebunden ist.
Es gibt keinen produktiven Prüfer, keine Nachrichten, keine Netzwerkfunktion
und keine Recovery. Die bisherige `requirements.txt` gehört zum alten
App-Konzept und wird für diesen Prototyp nicht verwendet.

## Prototyp entwickeln

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy src
```

Architektur und Nutzung: [Identity State Machine](docs/identity-state-machine.md).
Annahmen, Abweichungen, Risiken und Prüfergebnisse:
[Implementierungsreview](security/identity-implementation-review.md).
Der Prototyp ist keine Schutzlösung für gefährdete Menschen und wurde nicht
unabhängig sicherheitsgeprüft. Der abschließende Gesamttest und `uv.lock` fehlen
noch, da PyNaCl und Hypothesis im lokalen Cache fehlen und der Download in
der Ausführungsumgebung blockiert ist. Einzelheiten stehen im Review.

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
