"""Minimal pydantic v2-compatible shim: BaseModel, ConfigDict, Field.

WHY THIS EXISTS: this sandbox has no network access, so `pip install
pydantic` is not possible (verified empirically -- no cached wheel
anywhere on disk, `pip cache list` empty). This is not a mock of what
app.testing.models.py's classes DO -- it is a real enough implementation
of the specific pydantic surface those classes actually use (checked
against models.py's source directly: BaseModel with plain type-hinted
fields, `Field(default_factory=...)`, `ConfigDict(use_enum_values=True)`,
optional fields defaulting to None) that the REAL, UNMODIFIED
app/testing/models.py, RequestEvidence/ResponseEvidence/TestResult
included, imports and runs against it unchanged.

NOT a general pydantic reimplementation: no validation, no coercion, no
nested-model parsing beyond what these three classes need. If a future
model added a validator or a nested BaseModel field, this shim would need
extending -- that is a deliberate, documented scope boundary, not an
oversight. See the project's before/after report for exactly what was
verified through this shim versus what still needs the real package.
"""
from __future__ import annotations

import enum
import typing


class _FieldSpec:
    __slots__ = ("default", "default_factory", "has_default")

    def __init__(self, default=None, default_factory=None, has_default=True):
        self.default = default
        self.default_factory = default_factory
        self.has_default = has_default


def Field(default=..., default_factory=None, **_kwargs):
    if default_factory is not None:
        return _FieldSpec(default_factory=default_factory)
    if default is ...:
        return _FieldSpec(has_default=False)
    return _FieldSpec(default=default)


def ConfigDict(**kwargs):
    return dict(kwargs)


class HttpUrl(str):
    """Minimal stand-in: real pydantic's HttpUrl validates and normalizes
    URLs; this shim only needs it importable and usable as a plain string
    for schemas/run.py's type hints (this project's own request/response
    validation of URLs happens elsewhere, not exercised through this
    shim). Extending this shim's scope beyond models.py, which is all it
    was originally built for -- see this module's own docstring."""

    def __new__(cls, value):
        return str.__new__(cls, value)


def _is_optional(hint) -> bool:
    origin = typing.get_origin(hint)
    if origin is typing.Union:
        return type(None) in typing.get_args(hint)
    # PEP 604 `X | None` shows up as types.UnionType at runtime
    try:
        import types as _types

        if isinstance(hint, _types.UnionType):
            return type(None) in typing.get_args(hint)
    except AttributeError:
        pass
    return False


_MISSING = object()  # sentinel: distinguishes "no class attribute at all" from
                     # "class attribute exists and its value is None" -- using
                     # `None` itself as getattr's fallback (an earlier version
                     # of this shim did exactly that) conflates the two and
                     # wrongly raises "field is required" for any field
                     # declared as `x: Any = None` (a bare None default,
                     # not Field(default=None)) -- found via this project's
                     # own fault-injection tests (a ResponseEvidence built
                     # as ResponseEvidence(error=...) with body left at its
                     # documented default of None), not by inspection.


class BaseModel:
    model_config: dict = {}

    def __init__(self, **data):
        hints = typing.get_type_hints(type(self))
        use_enum_values = type(self).model_config.get("use_enum_values", False)

        for name, hint in hints.items():
            if name.startswith("_") or name == "model_config":
                continue
            class_default = getattr(type(self), name, _MISSING)

            if name in data:
                value = data[name]
            elif isinstance(class_default, _FieldSpec):
                if class_default.default_factory is not None:
                    value = class_default.default_factory()
                elif class_default.has_default:
                    value = class_default.default
                else:
                    raise TypeError(f"{type(self).__name__}.{name} is required")
            elif class_default is not _MISSING:
                # Covers BOTH a plain non-None default (`x: str = "a"`) AND
                # a plain `x: Any = None` default -- the class attribute
                # exists either way, so its actual value (None included) is
                # exactly what an unset field should become.
                value = class_default
            elif _is_optional(hint):
                value = None
            else:
                raise TypeError(f"{type(self).__name__}.{name} is required")

            if use_enum_values and isinstance(value, enum.Enum):
                value = value.value

            setattr(self, name, value)

        # Fields with a plain default of None assigned via class attribute
        # (not Field(...)) that get_type_hints picked up but weren't in
        # hints' declared-order pass above for some MRO edge case are
        # already handled by the loop over `hints`, which is exactly
        # every annotated field -- nothing further to do here.

    def model_dump(self, *, mode: str = "python", **_ignored) -> dict:
        # Real pydantic v2 accepts mode="python"|"json" (plus many other keyword
        # options this shim does not need). "json" additionally converts
        # datetimes to ISO-8601 strings; the production code path (runner.py,
        # api/v1/runs.py) calls model_dump(mode="json") everywhere, which is why
        # the real TestRunner could not run under this shim before this fix.
        return {k: _dump_value(v, mode) for k, v in self.__dict__.items()}

    def model_dump_json(self, **_ignored) -> str:
        import json

        return json.dumps(self.model_dump(mode="json"), default=str)

    def __repr__(self) -> str:
        fields = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items())
        return f"{type(self).__name__}({fields})"

    def __eq__(self, other) -> bool:
        return type(self) is type(other) and self.__dict__ == other.__dict__


def _dump_value(v, mode: str = "python"):
    import datetime as _dt

    if isinstance(v, BaseModel):
        return v.model_dump(mode=mode)
    if isinstance(v, enum.Enum):
        return v.value
    if isinstance(v, dict):
        return {k: _dump_value(x, mode) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_dump_value(x, mode) for x in v]
    if mode == "json" and isinstance(v, (_dt.datetime, _dt.date)):
        return v.isoformat()
    return v
