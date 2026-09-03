"""Tenant/device discovery + per-device status — read only.

Endpoint shapes come from reading github.com/GTalksTech/sonicwall-mcp's
source directly (a real, if young and otherwise unvetted, implementation
against SonicWall's NSM SaaS cloud API) — see api_client.py's module
docstring for why. Never exercised against a real live tenant — see README
Known Gaps.
"""

from collections.abc import Callable
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import SonicWallClient, SonicWallError
from ._common import NO_TOKEN, SERIAL_DESC


def register(mcp: FastMCP, client_factory: Callable[[], SonicWallClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def sonicwall_list_tenants() -> str:
        """List the tenants this MySonicWall API key can see.

        Only needed when the credential covers more than one tenant (e.g.
        an MSP account managing several customers) — call this first to
        find the tenant name to pass as X-Sonicwall-Tenant-Name. Cheaper
        than every other tool here: this alone doesn't need the NSM token
        exchange, just the API key.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.list_tenants()
            return dump_json_capped(result)
        except SonicWallError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def sonicwall_list_devices() -> str:
        """List the firewalls this NSM tenant manages.

        Use to find a device's serial number before calling
        sonicwall_get_device_status, sonicwall_get_security_services_status,
        sonicwall_list_firewall_zones, sonicwall_get_system_logs, or
        sonicwall_get_attack_analytics.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get("/api/manager/devices/tenant")
            return dump_json_capped(result)
        except SonicWallError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def sonicwall_list_vulnerable_devices() -> str:
        """List devices with known vulnerabilities, tenant-wide.

        Tenant-scoped, not per-device — no serial number needed.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get("/api/manager/devices/vulnerable")
            return dump_json_capped(result)
        except SonicWallError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def sonicwall_get_device_status(
        serial: Annotated[str, Field(description=SERIAL_DESC)],
    ) -> str:
        """Get one firewall's live system status (uptime, load, and similar
        on-box health fields — exact fields are whatever the firewall
        currently reports).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/api/manager/firewall/reporting/status/system", serial=serial
            )
            return dump_json_capped(result)
        except SonicWallError as e:
            return e.to_envelope()
