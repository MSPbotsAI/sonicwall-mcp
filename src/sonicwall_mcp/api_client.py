"""Client for SonicWall's NSM SaaS cloud API.

This talks to SonicWall's own cloud (mysonicwall.com / api.mysonicwall.com /
nsm-<region>.sonicwall.com) — never directly to a customer's on-prem
firewall. That only works for firewalls actually managed through an NSM SaaS
tenant; a firewall the customer owns but never onboarded to NSM is invisible
to this API. See README for why this path was chosen over the local SonicOS
on-box API (the same customer-must-expose-their-network problem as
unifi-network-mcp).

Every field/endpoint shape here that isn't cited to SonicWall's own official
docs comes from reading a real (if young and otherwise unvetted) working
implementation — github.com/GTalksTech/sonicwall-mcp, both server.py and
nsm_auth.py read directly, not inferred — because SonicWall's own docs
describe the call chain (host, method) but not the actual JSON field names
several steps need (e.g. the bearer token arrives nested at
response["status"]["info"][0]["message"], not response["access_token"] —
not guessable from the docs alone). None of this has been exercised against
a real MySonicWall account — see README Known Gaps.
"""

import asyncio
from typing import Any

import httpx

from ._json import error_envelope

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_MAX_BACKOFF_SECONDS = 20.0

# Step 1 deliberately uses the BARE host, not api.mysonicwall.com. SonicWall's
# own official docs (msw-api_guide) say api.mysonicwall.com for this specific
# call — but GTalksTech/sonicwall-mcp's code carries an explicit comment that
# the bare host is what actually works, which reads as a real, empirically-
# hit bug fix rather than a typo. Neither side of this has been independently
# confirmed by us — see README Known Gaps.
_MSW_TENANTS_URL = "https://mysonicwall.com/api/hgms/get-cloud-tenants"
_MSW_API_BASE = "https://api.mysonicwall.com"
_NSM_SERVICE_NAME = "NGMGMT"  # NSM's internal service id; the display name is "Network Security Manager"

# One shared connection pool for the process lifetime. No credentials are
# ever stored on it — the MySonicWall API key is passed per-call and used
# only to run a fresh 3-step token exchange for that call (see
# SonicWallClient._login), and the resulting bearer token is attached
# per-request via a header rather than carried as client-level state. This
# makes sharing the pool across tenants/requests safe (see server.py's
# contextvar-based credential isolation, which is what actually keeps
# tenants apart).
_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True)
    return _http_client


# status_code -> (error code, retryable). status_code 0 means a network/
# connection-level failure (no response at all).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def _classify(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    return "invalid_argument", False


class SonicWallError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"SonicWall NSM API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = _classify(self.status_code)
        return error_envelope(code, self.message, retryable)


class SonicWallClient:
    """Async httpx client wrapping SonicWall's NSM SaaS cloud API.

    Auth is a 3-step chain from a long-lived MySonicWall API key to a
    short-lived NSM bearer token (valid ~8 hours per SonicWall's own docs,
    with a 15-minute inactivity timeout):

      1. GET  https://mysonicwall.com/api/hgms/get-cloud-tenants
             (header X-API-KEY) -> tenant list, each with a productGroupID
             and a nested NSM ("NGMGMT") cloudServices entry carrying its
             own tenantSerial.
      2. POST https://api.mysonicwall.com/api/generate-cscaccesscode
             (header X-API-KEY, body {tenantId: productGroupID,
             tileName: "ISNSMSAFEENABLED"}) -> a short-lived access code.
      3. POST https://nsm-<region>.sonicwall.com/api/manager/auth/sso
             (body {tenantSerial, code}) -> the actual bearer token, nested
             at response["status"]["info"][0]["message"].

    Never caches the resulting token: every call runs this full chain and
    discards it afterward, trading three extra HTTP round trips per call for
    full statelessness — the same "re-authenticate every call" discipline
    used for every other vendor in this fleet whose token isn't itself the
    long-lived credential (datto-rmm-mcp, easydmarc-mcp, oitvoip-mcp,
    ingrammicro-mcp). A cached token would also have to be keyed per-tenant
    to avoid leaking one tenant's session to another's request, which a
    stateless per-call exchange sidesteps entirely.
    """

    def __init__(self, msw_api_key: str, tenant_name: str | None, nsm_region: str):
        self._api_key = msw_api_key
        self._tenant_name = tenant_name
        self._nsm_host = f"https://nsm-{nsm_region.strip().lower()}.sonicwall.com"

    async def _post_or_get(self, method: str, url: str, **kwargs) -> httpx.Response:
        client = _get_http_client()
        try:
            return await client.request(method, url, **kwargs)
        except httpx.RequestError as e:
            raise SonicWallError(0, f"{e or type(e).__name__} (url={url})") from e

    async def _get_cloud_tenants(self) -> dict:
        # mysonicwall.com is a web app, not a pure API host: an invalid or
        # missing X-API-KEY doesn't get a clean 401 JSON error here — it
        # silently 302-redirects to an HTML login page, which still answers
        # 200. Confirmed live (dummy key -> redirect chain ending at
        # /muir/login). follow_redirects=False so that redirect itself
        # becomes the signal, instead of us parsing a login page as if it
        # were an empty-but-valid tenant list.
        resp = await self._post_or_get(
            "GET",
            _MSW_TENANTS_URL,
            headers={
                "X-API-KEY": self._api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            follow_redirects=False,
        )
        if resp.status_code in (301, 302, 303, 307, 308):
            raise SonicWallError(
                401,
                "get-cloud-tenants redirected to a login page instead of "
                "returning JSON — the X-Sonicwall-Msw-Api-Key is very likely "
                "invalid or missing required NSM scope.",
            )
        if resp.status_code >= 400:
            raise SonicWallError(resp.status_code, self._extract_error(resp))
        data = self._parse_body(resp) or {}
        if "raw_response" in data:
            raise SonicWallError(
                0, "get-cloud-tenants returned non-JSON content instead of the expected payload"
            )
        if data.get("operationStatus") == "FAILURE":
            raise SonicWallError(0, data.get("msgDesc") or "get-cloud-tenants failed")
        return data.get("content") or {}

    def _find_tenant(self, content: dict) -> dict:
        tenants = content.get("arrTenants") or []
        wanted = (self._tenant_name or "").lower()
        if not wanted:
            if len(tenants) == 1:
                return tenants[0]
            available = ", ".join(repr(t.get("name")) for t in tenants)
            raise SonicWallError(
                0,
                f"This MySonicWall API key sees {len(tenants)} tenants; "
                f"set X-Sonicwall-Tenant-Name to disambiguate. "
                f"Available: {available}",
            )
        for tenant in tenants:
            if wanted in (tenant.get("name") or "").lower():
                return tenant
        available = ", ".join(repr(t.get("name")) for t in tenants)
        raise SonicWallError(
            0, f"No tenant matching {self._tenant_name!r}. Available: {available}"
        )

    def _find_nsm_service(self, tenant: dict) -> dict:
        for service in tenant.get("cloudServices") or []:
            if service.get("serviceName") == _NSM_SERVICE_NAME:
                return service
            if "network security manager" in (service.get("serviceNameDisp") or "").lower():
                return service
        raise SonicWallError(
            0,
            f"Tenant {tenant.get('name')!r} has no NSM service — "
            "it may not be an NSM SaaS-managed tenant.",
        )

    async def _resolve_tenant(self) -> tuple[str, str]:
        content = await self._get_cloud_tenants()
        tenant = self._find_tenant(content)
        service = self._find_nsm_service(tenant)
        tenant_id = str(tenant.get("productGroupID") or "")
        tenant_serial = service.get("tenantSerial") or ""
        if not tenant_id or not tenant_serial:
            raise SonicWallError(0, "Could not resolve tenant_id/tenant_serial from get-cloud-tenants")
        return tenant_id, tenant_serial

    async def _get_access_code(self, tenant_id: str) -> str:
        resp = await self._post_or_get(
            "POST",
            f"{_MSW_API_BASE}/api/generate-cscaccesscode",
            headers={
                "X-API-KEY": self._api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json={"tenantId": tenant_id, "tileName": "ISNSMSAFEENABLED"},
        )
        if resp.status_code >= 400:
            raise SonicWallError(resp.status_code, self._extract_error(resp))
        body = self._parse_body(resp) or {}
        code = (body.get("content") or {}).get("accessCode")
        if not code:
            raise SonicWallError(0, "generate-cscaccesscode returned no accessCode")
        return code

    async def _get_nsm_token(self, tenant_serial: str, code: str) -> str:
        resp = await self._post_or_get(
            "POST",
            f"{self._nsm_host}/api/manager/auth/sso",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json={"tenantSerial": tenant_serial, "code": code},
        )
        if resp.status_code >= 400:
            raise SonicWallError(resp.status_code, self._extract_error(resp))
        body = self._parse_body(resp) or {}
        try:
            token = body["status"]["info"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise SonicWallError(0, f"auth/sso response shape unexpected: {body}") from exc
        if not token:
            raise SonicWallError(0, "auth/sso succeeded but returned no token")
        return token

    async def _login(self) -> str:
        tenant_id, tenant_serial = await self._resolve_tenant()
        code = await self._get_access_code(tenant_id)
        return await self._get_nsm_token(tenant_serial, code)

    async def list_tenants(self) -> Any:
        """The raw get-cloud-tenants payload — needs only the API key, no
        NSM token exchange (this is the cheapest possible call, and useful
        for an operator to discover tenant names before anything else).
        """
        return await self._get_cloud_tenants()

    def _clean_params(self, params: dict | None) -> dict:
        if not params:
            return {}
        return {k: v for k, v in params.items() if v is not None}

    async def get(self, path: str, serial: str | None = None, params: dict | None = None) -> Any:
        token = await self._login()
        client = _get_http_client()
        url = f"{self._nsm_host}{path}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if serial:
            headers["X-Device-ID"] = serial
        params = self._clean_params(params)

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = await client.get(url, headers=headers, params=params)
            except httpx.RequestError as e:
                last_exc = e
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(min(2**attempt, _MAX_BACKOFF_SECONDS))
                    continue
                raise SonicWallError(0, f"{e or type(e).__name__} (url={url})") from e

            if resp.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                await asyncio.sleep(self._retry_delay(resp, attempt))
                continue

            self._raise_for_status(resp)
            return self._parse_body(resp)

        # Unreachable in practice (loop always returns or raises above), but
        # keeps type checkers happy and guards against future edits.
        if last_exc:
            raise SonicWallError(0, f"{last_exc}") from last_exc
        raise SonicWallError(0, "request failed with no response")

    def _retry_delay(self, resp: httpx.Response, attempt: int) -> float:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), _MAX_BACKOFF_SECONDS)
            except ValueError:
                pass
        return min(2**attempt, _MAX_BACKOFF_SECONDS)

    def _extract_error(self, resp: httpx.Response) -> str:
        try:
            detail = resp.json()
            if isinstance(detail, dict):
                return str(
                    detail.get("msgDesc") or detail.get("message") or detail.get("error") or detail
                )
            return str(detail)
        except ValueError:
            return resp.text

    def _parse_body(self, resp: httpx.Response) -> Any:
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw_response": resp.text}

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            raise SonicWallError(resp.status_code, self._extract_error(resp))
