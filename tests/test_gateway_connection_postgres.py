"""PostgreSQL isolation and bounded projection for gateway connection reads."""

from __future__ import annotations

import os
import uuid

import psycopg
import pytest

from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


def test_connection_capability_pages_are_bounded_and_never_load_private_fields() -> None:
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    marker = uuid.uuid4().hex
    alpha = repo.resolve_tenant(f"org_ConnectionCapabilityAlpha{marker}")
    beta = repo.resolve_tenant(f"org_ConnectionCapabilityBeta{marker}")
    secret_marker = f"never-expose-{marker}"
    with psycopg.connect(DSN) as connection:
        connection.execute(
            """
            INSERT INTO provider_connection
              (tenant_id, provider, display_name, credential_type,
               credential_reference, declared_scopes, configuration)
            SELECT %s::uuid, 'aws', 'MCP page ' || series,
                   'aws_assume_role',
                   jsonb_build_object('role_arn', 'arn:aws:iam::123456789012:role/test',
                                      'private_marker', %s::text),
                   '["aws.bedrock_agents"]'::jsonb,
                   jsonb_build_object('private_marker', %s::text)
            FROM generate_series(1, 137) AS series
            """,
            (alpha, secret_marker, secret_marker),
        )
        other_id = connection.execute(
            """
            INSERT INTO provider_connection
              (tenant_id, provider, display_name, credential_type,
               credential_reference, configuration)
            VALUES (%s::uuid, 'aws', 'Other tenant', 'aws_assume_role',
                    jsonb_build_object('private_marker', %s::text),
                    jsonb_build_object('private_marker', %s::text))
            RETURNING id
            """,
            (beta, secret_marker, secret_marker),
        ).fetchone()[0]

    first, has_more = repo.list_connection_summaries(alpha, limit=100, offset=0)
    second, final_has_more = repo.list_connection_summaries(alpha, limit=100, offset=100)
    assert (len(first), len(second), has_more, final_has_more) == (100, 37, True, False)
    assert {row["id"] for row in first}.isdisjoint({row["id"] for row in second})
    assert [row["id"] for row in first + second] == sorted(row["id"] for row in first + second)
    assert all(row["provider"] == "aws" for row in first + second)
    assert all(
        set(row)
        == {
            "id",
            "provider",
            "display_name",
            "lifecycle_state",
            "health_state",
            "declared_scopes",
            "created_at",
            "updated_at",
            "last_validated_at",
        }
        for row in first + second
    )
    assert secret_marker not in str(first + second)
    assert repo.get_connection_summary(alpha, str(other_id)) is None
    beta_page, beta_has_more = repo.list_connection_summaries(beta, limit=100, offset=0)
    assert [row["id"] for row in beta_page] == [other_id]
    assert beta_has_more is False
    other = repo.get_connection_summary(beta, str(other_id))
    assert other is not None and other["display_name"] == "Other tenant"
    assert secret_marker not in str(other)

    for limit, offset in ((0, 0), (101, 0), (1, -1), (1, 100001)):
        with pytest.raises(ValueError, match="invalid connection summary page"):
            repo.list_connection_summaries(alpha, limit=limit, offset=offset)
