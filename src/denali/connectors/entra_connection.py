"""Tenant-bound Microsoft Entra inventory and activity collection."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from denali.connections.entra import EntraAdminConsentClient
from denali.connectors.entra_ai import EntraAiConnector
from denali.domain import ActivityBatch, CoverageState, InventoryBatch


class EntraCollectionRepository(Protocol):
    def ingest(self, tenant_id: str, batch: InventoryBatch) -> dict[str, int]: ...

    def ingest_activity(self, tenant_id: str, batch: ActivityBatch) -> dict[str, int]: ...


class EntraConnectionCollector:
    """Collect one consented customer tenant without retaining its access token."""

    def __init__(
        self,
        consent_client: EntraAdminConsentClient,
        *,
        lookback_hours: int = 168,
        now: Callable[[], datetime] | None = None,
    ):
        if not 1 <= lookback_hours <= 24 * 90:
            raise ValueError("Microsoft Entra lookback must be between 1 and 2160 hours")
        self._consent_client = consent_client
        self._lookback_hours = lookback_hours
        self._now = now or (lambda: datetime.now(UTC))

    def collect(
        self,
        *,
        tenant_id: str,
        connection: dict[str, Any],
        repository: EntraCollectionRepository,
    ) -> dict[str, Any]:
        entra_tenant_id = str(connection["configuration"]["tenant_id"])
        graph = self._consent_client.graph_client(entra_tenant_id)
        connector = EntraAiConnector(entra_tenant_id=entra_tenant_id, graph_client=graph)
        end = self._now()
        inventory = connector.collect_inventory(connection_id=str(connection["id"]))
        activity = connector.collect_activity(
            start_time=end - timedelta(hours=self._lookback_hours),
            end_time=end,
            connection_id=str(connection["id"]),
        )
        inventory_result = repository.ingest(tenant_id, inventory)
        activity_result = repository.ingest_activity(tenant_id, activity)
        coverage = (*inventory.coverage, *activity.coverage)
        complete = sum(item.state is CoverageState.COMPLETE for item in coverage)
        failed = sum(item.state is CoverageState.FAILED for item in coverage)
        partial = len(coverage) - complete - failed
        state = (
            "complete"
            if complete == len(coverage)
            else "failed"
            if failed == len(coverage)
            else "partial"
        )
        return {
            "connection_id": str(connection["id"]),
            "state": state,
            "completed_at": self._now().isoformat(),
            "lookback_hours": self._lookback_hours,
            "matched_ai_applications": sum(
                item.asset.kind.value == "ai_application" for item in inventory.assets
            ),
            "activity_events": len(activity.activities),
            "coverage_complete": complete,
            "coverage_partial": partial,
            "coverage_failed": failed,
            "inventory": inventory_result,
            "activity": activity_result,
        }
