import contextvars
from collections.abc import Callable
from typing import NamedTuple

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .api_client import SonicWallClient
from .config import Settings

_DEFAULT_NSM_REGION = "uswest"


class _GatewayCreds(NamedTuple):
    msw_api_key: str
    tenant_name: str | None
    nsm_region: str


# Per-request credential isolation via contextvars.
# GatewayTokenMiddleware sets this before the MCP handler runs.
# Python asyncio copies context per task, so concurrent SSE connections are isolated.
# SonicWall's NSM SaaS has no gateway-brokered auth layer to delegate to — the
# tenant's own MySonicWall API key *is* the long-lived credential, and this
# server runs the full API-key -> NSM-bearer-token exchange itself per call
# (see api_client.SonicWallClient), never caching a token beyond one request.
_gateway_creds_var: contextvars.ContextVar[_GatewayCreds | None] = contextvars.ContextVar(
    "sonicwall_gateway_creds", default=None
)


def get_client_from_context(settings: Settings) -> SonicWallClient | None:
    """Resolve the active SonicWallClient for the current request context."""
    creds = _gateway_creds_var.get()
    if not creds:
        return None
    return SonicWallClient(creds.msw_api_key, creds.tenant_name, creds.nsm_region)


class GatewayTokenMiddleware:
    """ASGI middleware.

    Reads X-Sonicwall-Msw-Api-Key (required) plus the optional
    X-Sonicwall-Tenant-Name and X-Sonicwall-Nsm-Region from request headers
    and stores them in the contextvar. Returns 401 if the required header is
    missing on /mcp requests.
    """

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        msw_api_key = request.headers.get("x-sonicwall-msw-api-key")
        if not msw_api_key:
            response = JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": (
                        "This server requires the X-Sonicwall-Msw-Api-Key header "
                        "(the customer's long-lived MySonicWall API key)."
                    ),
                    "required_headers": ["X-Sonicwall-Msw-Api-Key"],
                    "optional_headers": ["X-Sonicwall-Tenant-Name", "X-Sonicwall-Nsm-Region"],
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        tenant_name = request.headers.get("x-sonicwall-tenant-name") or None
        nsm_region = request.headers.get("x-sonicwall-nsm-region") or _DEFAULT_NSM_REGION

        ctx_token = _gateway_creds_var.set(_GatewayCreds(msw_api_key, tenant_name, nsm_region))
        try:
            await self.app(scope, receive, send)
        finally:
            _gateway_creds_var.reset(ctx_token)


def create_mcp_server(settings: Settings) -> FastMCP:
    """Build the FastMCP server instance and register all SonicWall tools."""
    # DNS-rebinding protection is a browser-oriented safeguard that rejects
    # non-localhost Host headers with 421. Disable it so the server works
    # correctly behind a reverse proxy or docker network.
    mcp = FastMCP(
        name="sonicwall-mcp",
        instructions=(
            "SonicWall is a firewall vendor; this server reaches a customer's "
            "firewalls through SonicWall's own NSM SaaS cloud platform, NOT by "
            "connecting to the firewall directly — so it only works for "
            "firewalls actually managed through an NSM SaaS tenant. Typical "
            "flow: sonicwall_list_tenants if the credential covers more than "
            "one tenant; sonicwall_list_devices to find a device's serial "
            "number; then sonicwall_get_device_status / "
            "sonicwall_get_security_services_status / "
            "sonicwall_list_firewall_zones / sonicwall_get_system_logs / "
            "sonicwall_get_attack_analytics scoped to that serial. "
            "sonicwall_list_vulnerable_devices needs no serial — it's "
            "tenant-wide. All tools are read-only; there are no "
            "configuration-change or restart tools in this service."
        ),
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
        json_response=True,
    )

    client_factory: Callable[[], SonicWallClient | None] = lambda: get_client_from_context(
        settings
    )

    from .tools import devices, security

    devices.register(mcp, client_factory)
    security.register(mcp, client_factory)

    return mcp
