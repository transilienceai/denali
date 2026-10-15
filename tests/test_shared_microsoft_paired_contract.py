"""Optional offline wire test against the paired Platform source on PYTHONPATH.

Denali has no runtime dependency on Platform's Python package. The paired PR
gate explicitly supplies both reviewed source trees; normal Denali CI reports
the unavailable paired package as a skip, never as provider acceptance.
"""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.testclient import TestClient

pytest.importorskip(
    "transilience_platform", reason="paired Platform source is required on PYTHONPATH"
)

from test_shared_gcp_api import Authenticator, Repository  # noqa: E402
from test_shared_microsoft import (  # noqa: E402
    APP,
    ID,
    PRINCIPAL,
    SUBSCRIPTION,
    TENANT,
    Native,
    Sink,
    audit_items,
    audit_parameters,
    connection,
)
from test_shared_microsoft_api import AUTH, payload  # noqa: E402
from transilience_platform.azure_api import register_azure_routes  # noqa: E402
from transilience_platform.entra_api import register_entra_routes  # noqa: E402
from transilience_platform.entra_connector import EntraBroker  # noqa: E402

from denali.api.app import create_app  # noqa: E402
from denali.integrations import shared_connections_client  # noqa: E402
from denali.integrations.shared_connections_client import (  # noqa: E402
    SharedConnectionsClient,
    SharedConnectionsError,
)
from denali.integrations.shared_microsoft import (  # noqa: E402
    MicrosoftCollectorRouter,
    MicrosoftValidatorRouter,
    SharedEntraReader,
)


class Registry:
    def __init__(self, provider):
        self.provider, self.state, self.reads = provider, None, []
        self.bound = {
            "id": UUID(ID),
            "clerk_org_id": "org_alpha",
            "created_by_app_id": "denali",
            "tenant_id": TENANT,
            "operator_client_id": APP,
            "display_name": "Shared Microsoft",
            "lifecycle_state": "active",
            "setup_state": "pending",
            "health_state": "unknown",
            "credential_state": "unknown",
            "subscriptions": [{"id": SUBSCRIPTION, "name": "Selected"}],
            "declared_scopes": payload(provider)["declared_scopes"],
        }

    def create_shared_azure(self, app, plan, operator):
        assert app == "denali" and plan["clerk_org_id"] == "org_alpha" and operator == APP
        return {"id": ID, "setup_state": "pending"}

    create_shared_entra = create_shared_azure

    def get_shared_azure(self, org, identifier, app):
        return (
            self.bound if org == "org_alpha" and str(identifier) == ID and app == "denali" else None
        )

    def get_shared_entra(self, org, identifier):
        return self.get_shared_azure(org, identifier, "denali")

    def create_azure_setup_state(self, app, org, identifier, state):
        binding = self.get_shared_azure(org, identifier, app)
        if binding:
            self.state = state
        return binding

    create_entra_setup_state = create_azure_setup_state

    def consume_azure_setup_state(self, state, tenant, consented, operator):
        if (
            not self.state
            or state != self.state
            or tenant != TENANT
            or not consented
            or operator != APP
        ):
            return False
        self.state = None
        self.bound["setup_state"] = "ready"
        return True

    def consume_entra_setup_state(self, *args):
        return (
            {"job_id": str(uuid4()), "state": "queued"}
            if self.consume_azure_setup_state(*args)
            else None
        )

    def enqueue_azure_validation(self, app, org, identifier):
        assert self.get_shared_azure(org, identifier, app) and self.bound["setup_state"] == "ready"
        self.bound.update(health_state="healthy", credential_state="passed")
        return {"job_id": str(uuid4()), "state": "queued"}

    def enqueue_entra_validation(self, org, identifier, *, app_id):
        return self.enqueue_azure_validation(app_id, org, identifier)

    def azure_validation_status(self, app, org, identifier):
        assert self.get_shared_azure(org, identifier, app)
        return {
            "setup_state": self.bound["setup_state"],
            "health_state": self.bound["health_state"],
            "job_state": "succeeded",
        }

    def entra_validation_status(self, org, identifier, *, app_id):
        return self.azure_validation_status(app_id, org, identifier)

    def azure_read_candidate(self, app, org, identifier, subscription, scope, resource_type):
        return (
            self.get_shared_azure(org, identifier, app)
            if subscription == SUBSCRIPTION and scope in self.bound["declared_scopes"]
            else None
        )

    def entra_read_candidate(self, app, org, identifier, scope):
        return (
            self.get_shared_azure(org, identifier, app)
            if scope in self.bound["declared_scopes"]
            else None
        )

    def record_azure_read(self, *args):
        self.reads.append(args)
        return True

    record_entra_read = record_azure_read

    def retire_shared_azure(self, app, org, identifier, *, delete=False, confirmation_name=None):
        binding = self.get_shared_azure(org, identifier, app)
        if (
            not binding
            or delete
            and (
                binding["lifecycle_state"] != "disabled"
                or confirmation_name != binding["display_name"]
            )
        ):
            return False
        binding["lifecycle_state"] = "deleted" if delete else "disabled"
        return True

    retire_shared_entra = retire_shared_azure


class Provider:
    config = SimpleNamespace(client_id=APP)

    def consent_url(self, tenant_or_binding, state):
        tenant = (
            tenant_or_binding["tenant_id"]
            if isinstance(tenant_or_binding, dict)
            else tenant_or_binding
        )
        provider = "entra" if isinstance(tenant_or_binding, dict) else "azure"
        path = "adminconsent" if provider == "azure" else "v2.0/adminconsent"
        return f"https://login.microsoftonline.com/{tenant}/{path}?" + urlencode(
            {
                "state": state,
                "client_id": APP,
                "redirect_uri": f"https://platform.example/internal/v1/connections/{provider}/setup/callback",
            }
        )

    def read(self, binding, *args, **kwargs):
        azure = args[0] == SUBSCRIPTION
        operation = args[1] if azure else args[0]
        items = []
        if operation == "subscription_metadata":
            items = [{"subscriptionId": SUBSCRIPTION, "tenantId": TENANT}]
        elif operation == "service_principals":
            items = [{"id": PRINCIPAL, "appId": APP, "displayName": "GitHub Copilot"}]
        result = {
            "operation": operation,
            "tenant_id": TENANT,
            "items": items,
            "next_page_token": "",
        }
        if azure:
            result["subscription_id"] = SUBSCRIPTION
        return result


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_denali_and_platform_router_wire_contract_create_setup_attach_read_and_retire(
    provider, monkeypatch
):
    monkeypatch.setenv(f"DENALI_PLATFORM_{provider.upper()}_ENABLED", "true")
    platform, registry = FastAPI(), Registry(provider)
    dispatched = []

    def entitled(authorization, org):
        if authorization != "Bearer offline-machine" or org != "org_alpha":
            raise HTTPException(403, "machine/org mismatch")
        return "denali"

    register = register_azure_routes if provider == "azure" else register_entra_routes
    register(platform, registry, entitled, Provider(), dispatched.append)

    @platform.get("/v1/connections")
    def listing(clerk_org_id: str = Query(), authorization: str | None = Header(default=None)):
        entitled(authorization, clerk_org_id)
        bound = registry.bound
        ready = bound["health_state"] == "healthy" and bound["setup_state"] == "ready"
        return {
            "items": [
                {
                    **bound,
                    "id": ID,
                    "connection_kind": f"shared_{provider}",
                    "provider": provider,
                    "availability": "disabled"
                    if bound["lifecycle_state"] != "active"
                    else "ready"
                    if ready
                    else "needs_setup",
                    "validated_scopes": bound["declared_scopes"] if ready else [],
                }
            ]
        }

    bridge = SharedConnectionsClient(
        "https://platform.example",
        "offline-machine",
        allowed_clerk_org_ids=frozenset({"org_alpha"}),
    )
    bridge._clerk = SimpleNamespace(
        m2m=SimpleNamespace(create_token=lambda **kwargs: SimpleNamespace(token="offline-machine"))
    )
    # Each request uses actual Platform route/body validation in a fresh offline client.
    monkeypatch.setattr(
        shared_connections_client.httpx, "Client", lambda **kwargs: TestClient(platform)
    )
    repo = Repository()
    denali = create_app(
        repository=repo,
        auth_mode="clerk",
        authenticator=Authenticator(),
        shared_connections_client=bridge,
        migrate_on_start=False,
    )
    with TestClient(denali) as browser:
        base = f"/v1/shared/connections/{provider}"
        created = browser.post(base, headers=AUTH, json=payload(provider))
        assert created.status_code == 201 and created.json()["id"] == ID
        launch = browser.post(f"{base}/{ID}/setup", headers=AUTH)
        assert launch.status_code == 200
        query = parse_qs(urlsplit(launch.json()["consent_url"]).query)
        assert query["redirect_uri"] == [
            f"https://platform.example/internal/v1/connections/{provider}/setup/callback"
        ]
        if provider == "azure":
            script = browser.get(f"{base}/{ID}/setup.sh", headers=AUTH)
            assert script.status_code == 200 and SUBSCRIPTION in script.text and APP in script.text
        with TestClient(platform) as callback:
            completed = callback.get(
                f"/internal/v1/connections/{provider}/setup/callback",
                params={"state": query["state"][0], "tenant": TENANT, "admin_consent": "True"},
            )
            assert completed.status_code == 200 and registry.state is None
        assert browser.post(f"{base}/{ID}/validate", headers=AUTH).status_code == 202
        assert (
            browser.get(f"{base}/{ID}/validation", headers=AUTH).json()["health_state"] == "healthy"
        )
        attached = browser.post(
            f"{base}/{ID}/use-in-denali",
            headers=AUTH,
            json={"declared_scopes": payload(provider)["declared_scopes"]},
        )
        assert attached.status_code == 201
        target = connection(provider)
        target["configuration"] = attached.json()["configuration"]
        assert (
            MicrosoftValidatorRouter(provider, Native(), bridge).validate(target)["health_state"]
            == "healthy"
        )
        sink = Sink()
        assert (
            MicrosoftCollectorRouter(provider, Native(), bridge).collect(
                tenant_id=repo.resolve_tenant("org_alpha"), connection=target, repository=sink
            )["state"]
            == "complete"
        )
        assert sink.inventory and sink.activity and registry.reads
        assert browser.post(f"{base}/{ID}/disable", headers=AUTH).status_code == 200
        assert (
            browser.request(
                "DELETE",
                f"{base}/{ID}",
                headers=AUTH,
                json={"confirmation_name": "Shared Microsoft"},
            ).status_code
            == 200
        )
    assert dispatched


def entra_graph_bridge(monkeypatch, respond):
    """Use the real broker projection/cursor, route and private Denali bridge offline."""
    monkeypatch.setenv("DENALI_PLATFORM_ENTRA_ENABLED", "true")
    platform, registry = FastAPI(), Registry("entra")
    registry.bound.update(setup_state="ready", health_state="healthy")
    requests = []

    def graph(request):
        requests.append(request)
        return respond(request)

    config = SimpleNamespace(
        client_id=APP,
        callback_url="https://platform.example/internal/v1/connections/entra/setup/callback",
        cursor_key=b"offline-paired-entra-cursor-fixture",
        token=lambda tenant, scope: "offline-provider-token",
    )
    provider = EntraBroker(config, http=httpx.Client(transport=httpx.MockTransport(graph)))

    def entitled(authorization, org):
        if authorization != "Bearer offline-machine" or org != "org_alpha":
            raise HTTPException(403, "machine/org mismatch")
        return "denali"

    register_entra_routes(platform, registry, entitled, provider, None)
    bridge = SharedConnectionsClient(
        "https://platform.example",
        "offline-machine",
        allowed_clerk_org_ids=frozenset({"org_alpha"}),
    )
    bridge._clerk = SimpleNamespace(
        m2m=SimpleNamespace(create_token=lambda **kwargs: SimpleNamespace(token="offline-machine"))
    )
    monkeypatch.setattr(
        shared_connections_client.httpx, "Client", lambda **kwargs: TestClient(platform)
    )
    return bridge, registry, requests


@pytest.mark.parametrize("count", [103, 200, 201])
def test_real_paired_broker_and_denali_directory_audit_response_envelope(count, monkeypatch):
    bridge, registry, requests = entra_graph_bridge(
        monkeypatch, lambda request: httpx.Response(200, json={"value": audit_items(count)})
    )
    reader = SharedEntraReader(connection("entra"), client=bridge)
    if count > 200:
        with pytest.raises(SharedConnectionsError) as caught:
            reader.read("directory_audits", page_size=100, **audit_parameters())
        assert caught.value.status_code == 502
        assert registry.reads == []
    else:
        response = reader.read("directory_audits", page_size=100, **audit_parameters())
        assert [item["id"] for item in response["items"]] == [
            f"synthetic-audit-{index}" for index in range(count)
        ]
        assert len(registry.reads) == 1
    assert len(requests) == 1
    assert requests[0].url.params["$top"] == "100"


def test_real_paired_directory_audit_pagination_is_lossless_and_record_cap_is_preserved(
    monkeypatch,
):
    def graph(request):
        continued = "$skiptoken" in request.url.params
        payload = {"value": audit_items(103, offset=103 if continued else 0)}
        if not continued:
            payload["@odata.nextLink"] = str(
                request.url.copy_add_param("$skiptoken", "opaque-offline-next-page")
            )
        return httpx.Response(200, json=payload)

    bridge, _registry, requests = entra_graph_bridge(monkeypatch, graph)
    reader = SharedEntraReader(connection("entra"), client=bridge)
    result = reader._list("directory_audits", limit=206, **audit_parameters())
    assert [item["id"] for item in result] == [f"synthetic-audit-{index}" for index in range(206)]
    assert len(requests) == 2
    assert requests[1].url.params["$skiptoken"] == "opaque-offline-next-page"
    assert all(request.url.params["$top"] == "100" for request in requests)
    with pytest.raises(ValueError, match="record limit reached"):
        reader._list("directory_audits", limit=205, **audit_parameters())
    assert len(requests) == 4


def test_real_paired_103_non_ai_audits_complete_six_planes_without_inventing_inventory(
    monkeypatch,
):
    def graph(request):
        if request.url.path.endswith("servicePrincipals"):
            items = [{"id": PRINCIPAL, "appId": APP, "displayName": "Finance Portal"}]
        elif request.url.path.endswith("directoryAudits"):
            items = audit_items(103)
        else:
            items = []
        return httpx.Response(200, json={"value": items})

    bridge, _registry, requests = entra_graph_bridge(monkeypatch, graph)
    sink = Sink()
    result = MicrosoftCollectorRouter("entra", Native(), bridge).collect(
        tenant_id="local-tenant", connection=connection("entra"), repository=sink
    )
    assert result["state"] == "complete" and result["coverage_complete"] == 6
    assert result["coverage_failed"] == result["coverage_partial"] == 0
    assert result["matched_ai_applications"] == result["activity_events"] == 0
    assert sink.inventory[0][1].assets == () and sink.activity[0][1].activities == ()
    audits = [request for request in requests if request.url.path.endswith("directoryAudits")]
    assert len(audits) == 1 and audits[0].url.params["$top"] == "100"
