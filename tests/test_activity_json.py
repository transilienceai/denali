from denali.connectors.activity_json import ActivityJsonConnector
from denali.domain import AssetKind, AssetRef


def test_workspace_expands_every_event_in_one_report_record() -> None:
    document = {
        "items": [
            {
                "id": {"time": "2026-08-27T12:00:00Z", "uniqueQualifier": "q1"},
                "actor": {"email": "user@example.com"},
                "events": [
                    {"name": "generate", "type": "gemini"},
                    {"name": "summarize", "type": "gemini"},
                ],
            }
        ]
    }
    batch = ActivityJsonConnector().collect(
        document,
        format_name="google-workspace-gemini",
        connection_id="workspace",
        run_id="run-1",
        scope_key="customer",
        source_locator="file:///events.json",
    )
    assert [item.source_uid for item in batch.activities] == ["q1:0:generate", "q1:1:summarize"]
    assert batch.coverage[0].state.value == "complete"


def test_entra_normalization_does_not_turn_sign_in_into_a_finding() -> None:
    batch = ActivityJsonConnector().collect(
        {
            "value": [
                {
                    "id": "signin-1",
                    "createdDateTime": "2026-08-27T12:00:00Z",
                    "appId": "copilot-app",
                    "appDisplayName": "Microsoft Copilot",
                    "userPrincipalName": "user@example.com",
                    "status": {"errorCode": 0},
                }
            ]
        },
        format_name="entra-ai-signin",
        connection_id="entra",
        run_id="run-1",
        scope_key="tenant",
        source_locator="file:///signins.json",
    )
    event = batch.activities[0]
    assert event.category.value == "ai_app_sign_in"
    assert event.outcome.value == "success"
    assert event.entities[1].asset is None
    assert event.evidence.payload["userPrincipalName"] == "user@example.com"


def test_entra_missing_status_is_unknown_not_success() -> None:
    batch = ActivityJsonConnector().collect(
        {
            "value": [
                {
                    "id": "signin-unknown",
                    "createdDateTime": "2026-08-27T12:00:00Z",
                    "appId": "copilot-app",
                    "userId": "user-object-1",
                }
            ]
        },
        format_name="entra-ai-signin",
        connection_id="entra",
        run_id="run-unknown",
        scope_key="tenant",
        source_locator="file:///signins.json",
    )

    assert batch.activities[0].outcome.value == "unknown"


def test_aws_evidence_keeps_correlation_fields_but_not_prompt_content() -> None:
    batch = ActivityJsonConnector().collect(
        {
            "Records": [
                {
                    "eventID": "event-1",
                    "eventName": "Converse",
                    "eventTime": "2026-08-27T12:00:00Z",
                    "awsRegion": "ap-south-1",
                    "recipientAccountId": "331145994818",
                    "userIdentity": {
                        "type": "AssumedRole",
                        "arn": "arn:aws:sts::331145994818:assumed-role/AnnaRole/session",
                        "sessionContext": {
                            "sessionIssuer": {"arn": "arn:aws:iam::331145994818:role/AnnaRole"}
                        },
                    },
                    "requestParameters": {
                        "modelId": "global.anthropic.claude-sonnet",
                        "messages": [{"content": "do-not-retain"}],
                    },
                }
            ]
        },
        format_name="aws-bedrock-cloudtrail",
        connection_id="aws",
        run_id="run-1",
        scope_key="account",
        source_locator="aws://cloudtrail/ap-south-1/event-history",
    )

    payload = batch.activities[0].evidence.payload
    assert payload["eventID"] == "event-1"
    assert payload["requestIdentifiers"] == {"modelId": "global.anthropic.claude-sonnet"}
    assert "do-not-retain" not in str(payload)


def test_vertex_bad_sibling_is_visible_as_partial_coverage() -> None:
    batch = ActivityJsonConnector().collect(
        {
            "entries": [
                {
                    "insertId": "vertex-1",
                    "timestamp": "2026-08-27T12:00:00Z",
                    "protoPayload": {
                        "methodName": "google.cloud.aiplatform.v1.PredictionService.Predict",
                        "resourceName": "projects/p/locations/l/endpoints/e",
                        "authenticationInfo": {"principalEmail": "user@example.com"},
                    },
                },
                {"insertId": "broken"},
            ]
        },
        format_name="gcp-vertex-audit",
        connection_id="vertex",
        run_id="run-1",
        scope_key="project-p",
        source_locator="file:///vertex.json",
    )
    assert len(batch.activities) == 1
    assert batch.coverage[0].state.value == "partial"


def test_vertex_publisher_model_and_service_account_use_exact_inventory_keys() -> None:
    batch = ActivityJsonConnector().collect(
        {
            "entries": [
                {
                    "insertId": "vertex-model-1",
                    "timestamp": "2026-09-01T12:00:00Z",
                    "protoPayload": {
                        "methodName": (
                            "google.cloud.aiplatform.v1.PredictionService.GenerateContent"
                        ),
                        "resourceName": (
                            "projects/vertex-api/locations/us-central1/publishers/"
                            "google/models/gemini-2.5-flash"
                        ),
                        "authenticationInfo": {
                            "principalEmail": (
                                "summit@vertex-api.iam.gserviceaccount.com"
                            )
                        },
                    },
                }
            ]
        },
        format_name="gcp-vertex-audit",
        connection_id="vertex",
        run_id="run-1",
        scope_key="project-vertex-api",
        source_locator="file:///vertex.json",
    )

    activity = batch.activities[0]
    by_role = {entity.role.value: entity for entity in activity.entities}
    assert by_role["actor"].asset == AssetRef(
        AssetKind.IDENTITY,
        "gcp:service-account:summit@vertex-api.iam.gserviceaccount.com",
    )
    assert by_role["model"].asset == AssetRef(
        AssetKind.AI_MODEL, "gcp:vertex:model:gemini-2.5-flash"
    )
