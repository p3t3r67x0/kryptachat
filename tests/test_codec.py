import json

import pytest

from secure_messenger.identity.codec import MAX_WIRE_BYTES, canonical, parse
from secure_messenger.identity.errors import EncodingError, UnsupportedVersion
from secure_messenger.identity.models import SignedTransition

from .helpers import Scenario, reject


def raw_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def test_canonical_roundtrip_and_signed_wire_commit():
    s = Scenario()
    t, _ = s.addition()
    raw = canonical(t)
    assert parse(raw, SignedTransition) == t
    assert canonical(parse(raw, SignedTransition)) == raw
    challenge, evidence = s.proof(t)
    s.machine.apply(raw, challenge=challenge, evidence=evidence)


@pytest.mark.parametrize("version_field", ["protocol_version", "policy_version"])
def test_unknown_versions_are_explicitly_rejected(version_field):
    s = Scenario()
    t, _ = s.addition()
    data = t.model_dump(mode="json")
    data["action"][version_field] = 2
    reject(s.machine, raw_json(data), UnsupportedVersion)


@pytest.mark.parametrize(
    "mutation",
    [
        "spaces",
        "duplicate",
        "float",
        "bool",
        "extra",
        "missing_signature",
        "nan",
        "uppercase",
        "unicode",
        "future_action",
        "too_large",
        "trailing",
        "not_object",
        "string_integer",
        "duplicate_permissions",
        "unsorted_permissions",
        "unknown_suite",
    ],
)
def test_invalid_serialization_never_commits(mutation):
    s = Scenario()
    t, _ = s.addition()
    data = t.model_dump(mode="json")
    if mutation == "spaces":
        raw = json.dumps(data).encode("ascii")
    elif mutation == "duplicate":
        raw = canonical(t).replace(b'{"action":', b'{"action":null,"action":', 1)
    elif mutation == "too_large":
        raw = b" " * (MAX_WIRE_BYTES + 1)
    elif mutation == "trailing":
        raw = canonical(t) + b"{}"
    elif mutation == "not_object":
        raw = b"[]"
    elif mutation == "unicode":
        raw = b'"\xff"'
    else:
        if mutation == "float":
            data["action"]["generation"] = 1.0
        elif mutation == "bool":
            data["action"]["generation"] = True
        elif mutation == "string_integer":
            data["action"]["generation"] = "1"
        elif mutation == "extra":
            data["verified_by_server"] = True
        elif mutation == "missing_signature":
            del data["author_signature"]
        elif mutation == "nan":
            data["action"]["generation"] = float("nan")
        elif mutation == "uppercase":
            data["author_signature"] = data["author_signature"].upper()
        elif mutation == "future_action":
            data["action"]["kind"] = "recover_identity"
        elif mutation == "duplicate_permissions":
            data["action"]["device"]["permissions"] = ["messaging", "messaging"]
        elif mutation == "unsorted_permissions":
            data["action"]["device"]["permissions"] = ["messaging", "device_management"]
        elif mutation == "unknown_suite":
            data["action"]["suite"] = "unknown"
        raw = raw_json(data)
    reject(s.machine, raw, EncodingError)
