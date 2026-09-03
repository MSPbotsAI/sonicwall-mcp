"""tools/list snapshot + error-envelope mapping tests.

No network calls: tool enumeration goes through FastMCP's in-process
list_tools(), and the error-code mapping is tested directly against
SonicWallError, independent of any real HTTP request.
"""

import json

import pytest
from mcp.server.fastmcp import FastMCP

from sonicwall_mcp.api_client import SonicWallError
from sonicwall_mcp.config import Settings
from sonicwall_mcp.server import create_mcp_server

# name -> (required params, expected annotation hint set to True)
EXPECTED_TOOLS = {
    "sonicwall_list_tenants": (set(), {"readOnlyHint"}),
    "sonicwall_list_devices": (set(), {"readOnlyHint"}),
    "sonicwall_list_vulnerable_devices": (set(), {"readOnlyHint"}),
    "sonicwall_get_device_status": ({"serial"}, {"readOnlyHint"}),
    "sonicwall_get_security_services_status": ({"serial"}, {"readOnlyHint"}),
    "sonicwall_list_firewall_zones": ({"serial"}, {"readOnlyHint"}),
    "sonicwall_get_system_logs": ({"serial"}, {"readOnlyHint"}),
    "sonicwall_get_attack_analytics": ({"serial", "dimension"}, {"readOnlyHint"}),
}


@pytest.mark.asyncio
async def test_tools_list_snapshot():
    mcp = create_mcp_server(Settings())
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == set(EXPECTED_TOOLS), f"unexpected tool set: {names}"

    by_name = {t.name: t for t in tools}
    for name, (expected_required, expected_hints) in EXPECTED_TOOLS.items():
        tool = by_name[name]
        required = set(tool.inputSchema.get("required", []))
        assert required == expected_required, f"{name}: required={required}"

        description = tool.description or ""
        assert len(description) <= 500, f"{name}: description too long ({len(description)})"
        first_line = description.strip().splitlines()[0] if description.strip() else ""
        assert len(first_line) <= 100, f"{name}: first line too long: {first_line!r}"
        assert "GET /" not in description and "POST /" not in description, (
            f"{name}: leaked implementation detail"
        )

        annotations = tool.annotations
        actual_hints = set()
        if annotations is not None:
            for hint in ("readOnlyHint", "destructiveHint", "idempotentHint"):
                if getattr(annotations, hint, None) is True:
                    actual_hints.add(hint)
        assert actual_hints == expected_hints, f"{name}: hints={actual_hints}"


@pytest.mark.asyncio
async def test_service_instructions_present_and_bounded():
    mcp = create_mcp_server(Settings())
    assert mcp.instructions
    assert len(mcp.instructions) <= 1500


@pytest.mark.parametrize(
    "status_code,expected_code,expected_retryable",
    [
        (0, "upstream_error", True),
        (400, "invalid_argument", False),
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (503, "upstream_error", True),
    ],
)
def test_error_envelope_mapping(status_code, expected_code, expected_retryable):
    err = SonicWallError(status_code, "boom")
    envelope = json.loads(err.to_envelope())
    assert envelope["error"]["code"] == expected_code
    assert envelope["error"]["retryable"] is expected_retryable
    assert envelope["error"]["message"] == "boom"


@pytest.mark.asyncio
async def test_no_credentials_returns_not_configured_without_calling_api():
    from sonicwall_mcp.tools import devices

    mcp = FastMCP(name="test")
    devices.register(mcp, lambda: None)
    result = await mcp.call_tool("sonicwall_list_tenants", {})
    text = result[0][0].text if isinstance(result, tuple) else str(result)
    assert "not_configured" in text


@pytest.mark.asyncio
async def test_attack_analytics_dispatches_to_correct_path_per_dimension():
    """Confirms the dimension enum actually selects a different upstream
    path per value, via a stub client recording what path/serial it saw.
    """
    from sonicwall_mcp.tools import security

    captured = {}

    class _StubClient:
        async def get(self, path, serial=None, params=None):
            captured["path"] = path
            captured["serial"] = serial
            captured["params"] = params
            return {"ok": True}

    mcp = FastMCP(name="test")
    security.register(mcp, lambda: _StubClient())
    await mcp.call_tool(
        "sonicwall_get_attack_analytics",
        {"serial": "ABC123", "dimension": "initcountry"},
    )
    assert captured["path"] == "/api/manager/systemevent/analytics/initcountry"
    assert captured["serial"] == "ABC123"
    assert captured["params"] == {"limit": "50", "sort": "time"}
