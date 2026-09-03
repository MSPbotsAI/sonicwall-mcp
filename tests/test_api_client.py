"""Unit tests for the tenant/NSM-service resolution logic in
SonicWallClient — the part of the 3-step auth chain with real branching
(ambiguous tenant, missing NSM service) worth verifying deterministically,
independent of any real HTTP call.
"""

import pytest

from sonicwall_mcp.api_client import SonicWallClient, SonicWallError


def _client(tenant_name=None):
    return SonicWallClient("dummy-api-key", tenant_name, "uswest")


def test_find_tenant_returns_sole_tenant_when_unambiguous():
    content = {"arrTenants": [{"name": "Acme MSP"}]}
    tenant = _client()._find_tenant(content)
    assert tenant["name"] == "Acme MSP"


def test_find_tenant_raises_when_multiple_and_no_name_given():
    content = {"arrTenants": [{"name": "Acme MSP"}, {"name": "Widgets Inc"}]}
    with pytest.raises(SonicWallError) as exc_info:
        _client()._find_tenant(content)
    assert "Acme MSP" in exc_info.value.message
    assert "Widgets Inc" in exc_info.value.message


def test_find_tenant_matches_by_case_insensitive_substring():
    content = {"arrTenants": [{"name": "Acme MSP"}, {"name": "Widgets Inc"}]}
    tenant = _client("widgets")._find_tenant(content)
    assert tenant["name"] == "Widgets Inc"


def test_find_tenant_raises_when_no_match():
    content = {"arrTenants": [{"name": "Acme MSP"}]}
    with pytest.raises(SonicWallError):
        _client("nonexistent")._find_tenant(content)


def test_find_nsm_service_matches_by_service_name():
    tenant = {"cloudServices": [{"serviceName": "NGMGMT", "tenantSerial": "abc123"}]}
    service = _client()._find_nsm_service(tenant)
    assert service["tenantSerial"] == "abc123"


def test_find_nsm_service_falls_back_to_display_name():
    tenant = {
        "cloudServices": [
            {"serviceName": "SOMETHING_ELSE", "serviceNameDisp": "Network Security Manager"}
        ]
    }
    service = _client()._find_nsm_service(tenant)
    assert service["serviceNameDisp"] == "Network Security Manager"


def test_find_nsm_service_raises_when_tenant_not_nsm_managed():
    tenant = {"name": "Acme MSP", "cloudServices": [{"serviceName": "CSE"}]}
    with pytest.raises(SonicWallError) as exc_info:
        _client()._find_nsm_service(tenant)
    assert "Acme MSP" in exc_info.value.message
