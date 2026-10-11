"""Public schema table bounds agree with the final V1 compiler and node."""

import pytest
from iroha_python.client import ContractEntrypointDescriptor


_BOOLEAN = ("bool", [{"kind": "Leaf", "value": {"kind": "Bool", "value": None}}])
_UNIT = ("()", [{"kind": "Unit", "value": None}])


def _tuple(width):
    return (
        "(" + ", ".join(["bool"] * width) + ")",
        [{"kind": "Tuple", "value": width}] + _BOOLEAN[1] * width,
    )


def _parse(fields, returns=_UNIT):
    return ContractEntrypointDescriptor.from_payload({
        "name": "inspect",
        "kind": {"kind": "View", "value": None},
        "authorization": {"kind": "Anyone", "value": None},
        "params": [{"name": f"arg_{index}", "type_name": ty[0]} for index, ty in enumerate(fields)],
        "argument_schema": {"fields": [
            {"name": f"arg_{index}", "ty": {"nodes": ty[1]}} for index, ty in enumerate(fields)
        ]} if fields else None,
        "return_type": returns[0],
        "return_schema": {"nodes": returns[1]},
    })


def test_wide_arguments_and_returns_use_table_words():
    value = _parse([_BOOLEAN] * 64, _tuple(64))
    assert sum(field.type.word_count for field in value.argument_schema.fields) == 64
    assert value.return_schema.word_count == 64


def test_argument_field_count_has_inclusive_8192_bound():
    assert len(_parse([_BOOLEAN] * 8192).argument_schema.fields) == 8192
    with pytest.raises(TypeError):
        _parse([_BOOLEAN] * 8193)


def test_argument_bound_counts_flattened_words_across_fields():
    fields = [_tuple(128)] * 64
    assert sum(field.type.word_count for field in _parse(fields).argument_schema.fields) == 8192
    with pytest.raises(TypeError):
        _parse(fields + [_BOOLEAN])


def test_table_calling_preserves_type_schema_node_bound():
    assert _parse([], _tuple(255)).return_schema.word_count == 255
    with pytest.raises(TypeError):
        _parse([], _tuple(256))


def test_empty_named_products_keep_nominal_identity_and_one_word():
    empty = ("struct CallTable::Empty", [{"kind": "Struct", "value": {"name": "CallTable::Empty", "fields": []}}])
    listed = ("List<struct CallTable::Empty, 2>", [{"kind": "List", "value": {"capacity": 2}}] + empty[1])
    value = _parse([empty], listed)
    assert value.argument_schema.fields[0].type.word_count == 1
    assert value.return_schema.word_count == 1
    assert value.argument_schema.fields[0].type.canonical_type_name == "struct CallTable::Empty"
