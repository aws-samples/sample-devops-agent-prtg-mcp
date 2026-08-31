"""The tool schema and the handler dispatch table must agree exactly.

This is the test that makes ``tools.py`` a genuine single source of truth. Without
it, the "cannot drift" claim is only a convention, and a contributor adding a tool
in one place but not the other would ship a schema the agent trusts and the
handler rejects - a failure that only appears mid-investigation.
"""

from __future__ import annotations

import inspect

import pytest

from prtg_mcp import handler, tools


def test_every_declared_tool_has_an_implementation() -> None:
    declared = set(tools.tool_names())
    implemented = set(handler.TOOL_IMPLEMENTATIONS)
    assert declared - implemented == set(), (
        "Declared in tools.TOOL_SPECS but not implemented in handler.TOOL_IMPLEMENTATIONS"
    )


def test_every_implementation_is_declared() -> None:
    declared = set(tools.tool_names())
    implemented = set(handler.TOOL_IMPLEMENTATIONS)
    assert implemented - declared == set(), (
        "Implemented in handler.TOOL_IMPLEMENTATIONS but not declared in tools.TOOL_SPECS. "
        "An undeclared tool is unreachable, because the Gateway never advertises it."
    )


def test_tool_names_are_unique() -> None:
    names = tools.tool_names()
    assert len(names) == len(set(names))


@pytest.mark.parametrize("spec", tools.TOOL_SPECS, ids=lambda s: s["name"])
def test_implementation_signature_accepts_every_declared_parameter(spec: dict) -> None:
    """Each schema property must map to a keyword parameter of the implementation.

    Catches the case where a parameter is renamed in the schema but not in the
    function, which would surface at runtime as a TypeError inside a tool call.
    """
    impl = handler.TOOL_IMPLEMENTATIONS[spec["name"]]
    signature = inspect.signature(impl)
    parameters = set(signature.parameters) - {"client"}

    declared = set(spec["input_schema"].get("properties", {}))
    assert declared <= parameters, (
        f"{spec['name']} declares {sorted(declared - parameters)} in its schema, but the "
        f"implementation does not accept them"
    )


@pytest.mark.parametrize("spec", tools.TOOL_SPECS, ids=lambda s: s["name"])
def test_required_parameters_have_no_default(spec: dict) -> None:
    """A required schema parameter must not be optional in the implementation."""
    impl = handler.TOOL_IMPLEMENTATIONS[spec["name"]]
    signature = inspect.signature(impl)
    for name in spec["input_schema"].get("required", []):
        parameter = signature.parameters[name]
        assert parameter.default is inspect.Parameter.empty, (
            f"{spec['name']}.{name} is required by the schema but has a default in the "
            "implementation, so an omitted value would silently take the default instead of "
            "being rejected"
        )


@pytest.mark.parametrize("spec", tools.TOOL_SPECS, ids=lambda s: s["name"])
def test_schema_is_well_formed(spec: dict) -> None:
    schema = spec["input_schema"]
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False, (
        "additionalProperties must be False so the agent gets an explicit error for an "
        "invented parameter rather than silently unfiltered results"
    )
    assert spec["description"].strip(), "An empty description leaves the agent guessing"
    for name in schema.get("required", []):
        assert name in schema["properties"], f"required lists {name}, which is not a declared property"


@pytest.mark.parametrize("spec", tools.TOOL_SPECS, ids=lambda s: s["name"])
def test_every_property_is_described(spec: dict) -> None:
    """Undescribed parameters produce poor tool calls; the agent has only this text."""
    for name, prop in spec["input_schema"].get("properties", {}).items():
        assert prop.get("description", "").strip(), f"{spec['name']}.{name} has no description"


def test_gateway_schema_uses_camel_case_input_schema() -> None:
    rendered = tools.as_gateway_tool_schema()
    assert len(rendered) == len(tools.TOOL_SPECS)
    for entry in rendered:
        assert set(entry) == {"name", "description", "inputSchema"}


def test_count_parameters_are_bounded() -> None:
    """Unbounded page sizes cost PRTG CPU, Lambda memory, and agent tokens."""
    for spec in tools.TOOL_SPECS:
        count = spec["input_schema"].get("properties", {}).get("count")
        if count is not None:
            assert count["maximum"] == tools.MAX_COUNT
            assert count["minimum"] == 1


# --- Surviving the Gateway's schema normalisation ---------------------------


class TestConstraintsAreDiscoverable:
    """Constrained parameters must state their constraint in the description.

    Established by testing against a deployed Gateway: AgentCore Gateway normalises
    the tool schema when it republishes it over MCP. A ``tools/list`` response
    preserves only ``type``, ``description`` and ``required``. ``enum``, ``pattern``,
    ``minimum``, ``maximum``, ``minLength``, ``maxLength``, ``default`` and
    ``additionalProperties`` are all stripped, regardless of how they were supplied.

    The handler still enforces them, so an invalid call is rejected with a useful
    message. But the agent has no way to *know* the constraint unless the description
    says so - otherwise it guesses, gets corrected, and burns a round trip
    mid-investigation.

    These tests keep the description text and the machine-readable constraints in
    step, which is a thing that would otherwise rot silently: nothing else fails when
    someone adds an enum value and forgets the prose.
    """

    def _properties(self):
        for spec in tools.TOOL_SPECS:
            for name, prop in spec["input_schema"].get("properties", {}).items():
                yield spec["name"], name, prop

    def test_every_enum_value_appears_in_its_description(self) -> None:
        checked = 0
        for tool_name, param, prop in self._properties():
            if "enum" not in prop:
                continue
            checked += 1
            description = prop.get("description", "")
            for value in prop["enum"]:
                assert value in description, (
                    f"{tool_name}.{param} allows {value!r} but does not mention it in its "
                    "description. The Gateway strips `enum`, so the description is the only way "
                    "the agent learns the valid values."
                )
        assert checked >= 3, "expected at least three enum-constrained parameters"

    def test_numeric_bounds_are_mentioned_in_their_description(self) -> None:
        checked = 0
        for tool_name, param, prop in self._properties():
            if prop.get("type") != "integer" or "maximum" not in prop:
                continue
            checked += 1
            description = prop.get("description", "")
            assert str(prop["maximum"]) in description.replace(",", ""), (
                f"{tool_name}.{param} caps at {prop['maximum']} but does not say so in its "
                "description. The Gateway strips `maximum`."
            )
        assert checked >= 2, "expected at least two bounded integer parameters"

    def test_pattern_constrained_parameters_describe_the_expected_format(self) -> None:
        checked = 0
        for tool_name, param, prop in self._properties():
            if "pattern" not in prop:
                continue
            checked += 1
            description = prop.get("description", "")
            # A literal example is what the agent can copy; the regex never reaches it.
            assert "YYYY" in description or "e.g." in description, (
                f"{tool_name}.{param} is pattern-constrained but its description gives no example "
                "format. The Gateway strips `pattern`."
            )
        assert checked >= 2, "expected at least two pattern-constrained parameters"

    def test_required_parameters_survive_and_are_declared(self) -> None:
        """`required` is one of the three keys the Gateway does preserve, so it is
        worth relying on."""
        with_required = [s for s in tools.TOOL_SPECS if s["input_schema"].get("required")]
        assert with_required, "no tool declares required parameters"
        for spec in with_required:
            for name in spec["input_schema"]["required"]:
                assert name in spec["input_schema"]["properties"]
