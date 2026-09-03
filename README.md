# sonicwall-mcp

MCP server for **SonicWall** firewalls — device inventory, security posture,
config reads, and attack analytics — over the
[Model Context Protocol](https://modelcontextprotocol.io/) (Streamable
HTTP/SSE transport), built against SonicWall's **NSM SaaS cloud API**.

Built for [PRD-17726](https://app.clickup.com/t/2280862/PRD-17726) after two
other candidates were ruled out:

- The community repo [`gensecaihq/Sonicwall-MCP-Server`](https://github.com/gensecaihq/Sonicwall-MCP-Server)
  doesn't work at all — a real `docker build && docker run` reproduced a
  container that can't start (wrong entrypoint file), and its API client
  fabricates fake log/threat data on a connection failure instead of
  erroring. Not fixable with a small patch; effectively a full rewrite.
- SonicWall's own blog announced an official open-source MCP at
  `github.com/sonicwall/sonicwall-mcp` — that URL 404s right now (checked via
  the GitHub API, a direct HTTP request, and the Wayback Machine, which has
  no snapshot of it either). The announcement is real; the repo it links to
  currently isn't reachable.

## Why NSM SaaS instead of the local SonicOS on-box API

SonicOS also has its own official REST API (`POST /api/sonicos/auth`, RFC
2617 Basic Auth) — but that API lives on the firewall's own management IP,
normally on the customer's LAN behind NAT, same reachability problem as
`unifi-network-mcp`. **NSM SaaS is different: it's SonicWall's own
cloud-hosted fleet-management platform**, and a firewall managed through it
maintains its own outbound connection to NSM — this server never needs to
reach the customer's network directly, only SonicWall's cloud
(`mysonicwall.com` / `api.mysonicwall.com` / `nsm-<region>.sonicwall.com`).

**The one precondition this doesn't remove**: the firewall has to actually
be onboarded to an NSM SaaS tenant. A SonicWall a customer owns but never
registered with NSM is invisible to this API — confirm with the customer
that they're an NSM SaaS subscriber before assuming this will work.

## Tools

授权需要 `X-Sonicwall-Msw-Api-Key` 请求头（见下方授权说明）。

| Tool | 功能 | 参数 |
|---|---|---|
| `sonicwall_list_tenants` | 列出该 API Key 能看到的租户（仅当账号下有多个租户时需要用来消歧义） | 无 |
| `sonicwall_list_devices` | 列出该 NSM 租户管理的全部防火墙 | 无 |
| `sonicwall_list_vulnerable_devices` | 列出存在已知漏洞的设备（租户级，不需要 serial） | 无 |
| `sonicwall_get_device_status` | 获取某台防火墙的实时系统状态 | `serial`(必填) |
| `sonicwall_get_security_services_status` | 获取某台防火墙的安全服务（网关AV/IPS等）状态 | `serial`(必填) |
| `sonicwall_list_firewall_zones` | 列出某台防火墙配置的安全区域 | `serial`(必填) |
| `sonicwall_get_system_logs` | 获取某台防火墙的 NSM 采集日志 | `serial`(必填)、`limit`(可选) |
| `sonicwall_get_attack_analytics` | 按维度获取攻击/威胁分析（发起方/目标/端口/国家/处置动作） | `serial`(必填)、`dimension`(必填)、`limit`(可选) |

全部只读，没有配置修改或重启类工具。

## Quick Start

### Docker (recommended)

```bash
docker compose up --build
```

The server starts on `http://localhost:8080`.

### Local (uv)

```bash
uv sync
python -m sonicwall_mcp
```

## Health Check

```bash
curl http://localhost:8080/health
# {"status": "ok"}
```

No credentials are required for the health endpoint.

## 授权参数说明 (Authentication)

Every request to `/mcp` must include the following HTTP headers (provided by the
MCP caller/gateway):

| Header | 类型 | 是否必填 | 字段描述 |
|---|---|---|---|
| `X-Sonicwall-Msw-Api-Key` | string | 必填 | 客户的长期 MySonicWall API Key（mysonicwall.com → My Workspace → User Groups → User list → Generate My API Key），建议用一个 NSM 角色为 ReadOnly 的专用账号生成。 |
| `X-Sonicwall-Tenant-Name` | string | 可选 | 仅当这个 API Key 能看到多个租户时（例如 MSP 账号管理多个客户）才需要，按名称子串（大小写不敏感）匹配；账号下只有一个租户时可省略。 |
| `X-Sonicwall-Nsm-Region` | string | 可选，默认 `uswest` | NSM SaaS 是多区域的（对应 `nsm-<region>.sonicwall.com`，欧洲客户用 `eucentral`），按客户 NSM 租户实际所在区域填写。 |

Missing the required header returns `401 Unauthorized`.

**认证机制**：本服务收到 API Key 后，自己走完 SonicWall 官方文档描述的 3 步换 token 流程（`GET mysonicwall.com/api/hgms/get-cloud-tenants` → `POST api.mysonicwall.com/api/generate-cscaccesscode` → `POST nsm-<region>.sonicwall.com/api/manager/auth/sso`），再拿换到的 NSM bearer token 去调真正的业务接口——不是网关代发 token。**每次调用都重新走一遍这 3 步，从不缓存**（哪怕 NSM token 官方文档说有效期约 8 小时）——多租户场景下缓存 token 容易在并发请求间串号，这跟 fleet 里其它厂商（`datto-rmm-mcp`/`easydmarc-mcp`/`oitvoip-mcp`/`ingrammicro-mcp`）的处理原则一致。

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MCP_HTTP_PORT` | `8080` | Listening port |
| `MCP_HTTP_HOST` | `0.0.0.0` | Listening host |

## MCP Endpoint

```
POST http://localhost:8080/mcp
```

Connect your MCP client with:
- Transport: `http` (Streamable HTTP / SSE)
- Headers: `X-Sonicwall-Msw-Api-Key` (required), `X-Sonicwall-Tenant-Name` / `X-Sonicwall-Nsm-Region` (optional)

## 测试示例 (Test Example)

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Sonicwall-Msw-Api-Key: <customer-mysonicwall-api-key>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": { "name": "sonicwall_list_tenants", "arguments": {} }
  }'
```

> ⚠️ 本仓库为公开仓库，请勿在任何提交的文件中写入真实的客户 API Key，
> 上面的占位符仅为示意。

## Known Gaps

- **What was actually verified live, and how.** No real MySonicWall account
  was available, so nothing here has succeeded end-to-end against real
  data — but running this server for real with a **dummy** API key did
  confirm something concrete, not assumed:
  - `GET https://mysonicwall.com/api/hgms/get-cloud-tenants` is real and
    reachable — but a bad key doesn't get a clean JSON 401. It gets a
    `302` redirect to an HTML login page (`login.aspx?ReturnUrl=...` →
    `/muir/login`, confirmed in this server's own httpx request log). This
    server explicitly detects that redirect and turns it into a clear
    `unauthorized` error — the first version of this code instead followed
    the redirect, parsed the login page as empty JSON, and silently
    returned `{}` as if the tenant list were genuinely empty. Fixed before
    this was pushed, but it's a sign this endpoint's failure modes are not
    fully mapped; a *real* invalid-but-well-formed key might behave
    differently than the placeholder string used here.
  - This means `api.mysonicwall.com` (official docs' stated host for this
    same call) was never itself tried — this build uses the bare
    `mysonicwall.com` host instead, per the next point.
- **A real documentation/implementation conflict, not resolved.**
  SonicWall's own official docs (`msw-api_guide`) state
  `get-cloud-tenants` lives at `api.mysonicwall.com`. A real (if young)
  working implementation — [`GTalksTech/sonicwall-mcp`](https://github.com/GTalksTech/sonicwall-mcp),
  created 2026-09-01 — carries an explicit code comment that the bare
  `mysonicwall.com` host is what actually works, reading like a real,
  empirically-hit bug fix rather than a typo. This build follows the
  working implementation's choice (bare host), since "docs say X, real
  code found Y" is exactly the kind of thing worth trusting the tested
  code over — but **neither side of this has been independently confirmed
  by us against a real account**. If every tool starts failing at the
  tenant-resolution step, this is the first thing to check.
- **Every response-shape detail beyond the top-level call chain comes from
  reading that same third-party implementation's source directly** (both
  `server.py` and `nsm_auth.py`), not from SonicWall's own docs, because
  the docs describe the call chain (host, method) but not field names like
  `productGroupID` (the tenant ID field), `cloudServices` (not `services`)
  holding a `serviceName: "NGMGMT"` entry (not matched by the "Network
  Security Manager" display name alone), or the bearer token arriving
  nested at `response["status"]["info"][0]["message"]` instead of a
  top-level `access_token` field. None of this is guessable from the
  official docs alone, and none of it has been independently verified by
  us — it's only as trustworthy as that one implementation's own testing.
- **`X-Device-ID` header for per-device scoping is unverified.** The
  reference implementation uses this header to proxy a manager-plane call
  through to one specific firewall by serial number; never exercised here
  against a real device.
- **`SYSEVENT_REQUIRED_PARAMS` (`limit=50&sort=time`) is a real but
  narrow finding.** The reference implementation's own comments say
  `/systemevent/*` endpoints return HTTP 422 naming whichever required
  parameter is missing, and that `limit` is typed as a boolean gate in
  SonicWall's own swagger rather than an actual row cap (one sample
  returned 3,140 rows despite `limit=50`) — meaning `sonicwall_get_system_logs`
  and `sonicwall_get_attack_analytics`'s `limit` parameter may not do what
  its name implies. Passed through as-documented rather than guessed at,
  but not independently confirmed.
- **MVP-scoped by explicit decision, not a full port.** The reference
  implementation exposes on the order of 50 distinct NSM endpoints
  (interfaces, NAT, VPN policies, SSL-VPN, wireless/SonicPoint status,
  HA/failover, DNS, NTP, local users, config-audit diff/history, Analyzer
  NG reports). This build covers device/tenant discovery, one live status
  read, one config read (zones), and attack analytics/logs — the subset
  that maps most directly to PRD-17726's stated ask. Any of the rest can
  be added on request, but each one should be treated with the same
  "borrowed, not verified" caution as everything above.
- **No write/config-push endpoints are wrapped, and none are planned** —
  this service is read-only by design, matching the reference
  implementation's own "ideally a ReadOnly NSM role" recommendation.
