"""Prototype canonical ASCII JSON subset, NOT RFC 8785 or a production wire standard."""

import json

from pydantic import ValidationError

from .errors import EncodingError
from .models import FrozenModel

MAX_WIRE_BYTES = 65_536


def canonical(model: FrozenModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _unique_object(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise EncodingError("duplicate object member")
        result[key] = value
    return result


def _reject_number(value: str) -> object:
    raise EncodingError("floating point and non-finite numbers are prohibited")


def parse[ModelT: FrozenModel](raw: bytes, model_type: type[ModelT]) -> ModelT:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_WIRE_BYTES:
        raise EncodingError("invalid serialized size or type")
    try:
        text = raw.decode("ascii")
        json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
        model = model_type.model_validate_json(raw, strict=True)
        if canonical(model) != raw:
            raise EncodingError("serialization is not canonical")
        return model
    except (ValueError, UnicodeError, RecursionError, ValidationError) as exc:
        raise EncodingError("invalid serialized object") from exc


def checked[ModelT: FrozenModel](model: ModelT) -> ModelT:
    """Revalidate even objects created with model_copy/model_construct bypasses."""
    try:
        validated = type(model).model_validate(model, strict=True)
        return parse(canonical(validated), type(model))
    except (ValueError, TypeError, AttributeError, ValidationError) as exc:
        raise EncodingError("invalid model") from exc
