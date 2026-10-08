# Draft-PR-Vorlage: isolierte Python Identity State Machine

**Vorgesehener Titel:** `feat: add isolated fail-closed identity state machine prototype`

**Status:** Lokal vorbereitet. Es existiert laut Nutzer kein GitHub-Repository;
es wurde kein Pull Request angelegt und nichts veröffentlicht.
Branch: `feat/identity-state-machine`.

## Zusammenfassung

Der bisherige Identitätsentwurf erhält einen isolierten Python-3.13+-Kern.
Er initialisiert neue Identitäten, prüft signierte Geräteaufnahmen,
Berechtigungsänderungen und irreversible Widerrufe und führt eine lokale
authentifizierte Historie. Ungültige oder konkurrierende Änderungen ersetzen
keinen bestehenden Zustand. Jede Übernahme nach Genesis verlangt einen
explizit eingebundenen externen Aktualitätsprüfer und einen gebundenen Beleg;
ohne ihn bleibt die Funktion gesperrt.

Keine Nachrichten, Netzwerkanbindung, Relays, Transparenzserver oder Recovery.
Entwicklungsprototyp, nicht produktionsreif und nicht unabhängig auditiert.

## Sicherheitsrelevante Designentscheidungen

- Native Ed25519-Signaturen über `cryptography`, zusätzliche native
  öffentliche Punktvalidierung über PyNaCl/libsodium, getrennte Domänen.
- Kanonisches beschränktes ASCII-JSON mit strengen Pydantic-v2-Modellen;
  Version, Policy, Identität, Action-ID, Generation, Vorgänger und Rechte signiert.
- Signaturprüfung und Rollenprüfung getrennt; unbekannte Schlüssel nicht vertraut.
- Manager nimmt ausschließlich Messaging-Geräte auf; Managerrollenänderung
  erfordert Root und frischen Besitznachweis des schon aktiven Zielgeräts.
- `NO_RECOVERY`: kein Import alter Root-/History-/Backup-Zustände, kein Root-only
  Gerätezusatz, irreversible Tombstones, terminaler Zustand nach letztem Widerruf.
- Lokale Konsistenz ist ausdrücklich von externer Frische getrennt. Ein
  Server-Timestamp oder lokaler Uhrwert ist kein Nachweis eines aktuellen Heads.
- Unveränderliche Kandidaten und Historie, eine einzige Übernahmestelle unter
  Sperre; mutierende Wiedereintritte aus dem externen Prüfer werden abgewiesen.

## Validierung

Vorgesehene Pflichtprüfungen: `uv sync`, `uv run pytest`, `uv run ruff check .`,
`uv run mypy src`. Die tatsächlich erreichten Endergebnisse und eventuelle
Umgebungsblockaden stehen im
[Implementierungsreview](../security/identity-implementation-review.md).

Unit-, Negativ-, Offline- und Parallelitätstests sowie Hypothesis-Tests sind
vorhanden. Die zustandsbasierte Prüfung verwendet ein unabhängiges Rollen-
und Mitgliedschaftsmodell. Ein ausschließlich in Tests vorhandener signierender
Witness simuliert die externe Prüfgrenze.

## Abweichungen und offene Risiken

Die vier bestehenden Sicherheitsdokumente sind unverändert. Die neue
[Architekturdokumentation](identity-state-machine.md) und das
[Implementierungsreview](../security/identity-implementation-review.md)
begründen die Prototypannahmen: konkrete Suite/Encoding, verpflichtende
Frischeprüfung für sämtliche Folgeübernahmen, Root plus Zielbesitz auch beim
Managerentzug, terminale vollständige Widerrufung und enge Action-Fristen.
PyNaCl ist wegen degenerierter Ed25519-Public-Keys eine zusätzliche Abhängigkeit.

Kein geprüfter Produktions-Witness oder globaler Konsistenzmechanismus.
Aktive Managerkompromittierung, unbekannte Widerrufe, Witness-Kompromittierung
und Rennen innerhalb einer bestätigten Gültigkeitsdauer bleiben ungelöst.
Vollständiges Pairing/UX, Kontaktquarantäne, Keystores, persistente Checkpoints,
Langzeit-Offlinesynchronisation, Root-Rotation und Messaging-Schlüsselbindung
fehlen. X25519-Material ist lediglich ein unbenutzter separater Platzhalter.
Kein Beweis eines vollständigen Messenger-Freigabegates.
