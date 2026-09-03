"""Per-device security posture, config reads, and attack analytics.

Endpoint shapes and the SYSEVENT_REQUIRED_PARAMS requirement come from
reading github.com/GTalksTech/sonicwall-mcp's source directly — see
api_client.py's module docstring and tools/_common.py. Never exercised
against a real live tenant — see README Known Gaps.
"""

from collections.abc import Callable
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..api_client import SonicWallClient, SonicWallError
from ._common import NO_TOKEN, SERIAL_DESC, SYSEVENT_REQUIRED_PARAMS

_ANALYTICS_PATHS = {
    "initiators": "/api/manager/systemevent/analytics/initiators",
    "targets": "/api/manager/systemevent/analytics/targets",
    "fwaction": "/api/manager/systemevent/analytics/fwaction",
    "portsinfo": "/api/manager/systemevent/analytics/portsinfo",
    "initcountry": "/api/manager/systemevent/analytics/initcountry",
    "respcountry": "/api/manager/systemevent/analytics/respcountry",
}
_ANALYTICS_DIMENSION_DESC = (
    "Which attack-analytics breakdown to return: "
    '"initiators" — top attacking source IPs; "targets" — top attacked '
    'destination IPs; "fwaction" — counts by firewall action taken; '
    '"portsinfo" — top targeted ports; "initcountry" — top attacking '
    'countries; "respcountry" — top attacked (responding) countries.'
)


def register(mcp: FastMCP, client_factory: Callable[[], SonicWallClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def sonicwall_get_security_services_status(
        serial: Annotated[str, Field(description=SERIAL_DESC)],
    ) -> str:
        """Get one firewall's security services status (gateway AV,
        intrusion prevention, app control, and similar subscription-based
        services — whether each is licensed/enabled/current).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(
                "/api/manager/firewall/reporting/status/security-services", serial=serial
            )
            return dump_json_capped(result)
        except SonicWallError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def sonicwall_list_firewall_zones(
        serial: Annotated[str, Field(description=SERIAL_DESC)],
    ) -> str:
        """List one firewall's configured security zones (LAN/WAN/DMZ and
        any custom zones), read-only.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get("/api/manager/firewall/zones", serial=serial)
            return dump_json_capped(result)
        except SonicWallError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def sonicwall_get_system_logs(
        serial: Annotated[str, Field(description=SERIAL_DESC)],
        limit: Annotated[
            int | None,
            Field(description="Max rows to return. Omit for the API's own default (50)."),
        ] = None,
    ) -> str:
        """Get one firewall's NSM-collected event log.

        This is NSM's own longer-retention collected log, not the on-box
        log view — a separate data source, may not match on-box log output
        1:1.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        params = dict(SYSEVENT_REQUIRED_PARAMS)
        if limit is not None:
            params["limit"] = str(limit)
        try:
            result = await client.get(
                "/api/manager/systemevent/logs", serial=serial, params=params
            )
            return dump_json_capped(result)
        except SonicWallError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def sonicwall_get_attack_analytics(
        serial: Annotated[str, Field(description=SERIAL_DESC)],
        dimension: Annotated[
            Literal["initiators", "targets", "fwaction", "portsinfo", "initcountry", "respcountry"],
            Field(description=_ANALYTICS_DIMENSION_DESC),
        ],
        limit: Annotated[
            int | None,
            Field(description="Max rows to return. Omit for the API's own default (50)."),
        ] = None,
    ) -> str:
        """Get one firewall's attack/threat analytics, sliced by one
        dimension at a time (who's attacking, what's being targeted, which
        ports, which countries, what action the firewall took).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        params = dict(SYSEVENT_REQUIRED_PARAMS)
        if limit is not None:
            params["limit"] = str(limit)
        try:
            result = await client.get(_ANALYTICS_PATHS[dimension], serial=serial, params=params)
            return dump_json_capped(result)
        except SonicWallError as e:
            return e.to_envelope()
