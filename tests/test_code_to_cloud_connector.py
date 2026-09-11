from pathlib import Path

from denali.connectors.code_to_cloud import (
    CodeToCloudConnector,
    DeploymentTarget,
    _deployment_declarations,
    _local_imports,
    _local_module_graph,
)
from denali.domain import (
    AssertionType,
    CoverageState,
    DeploymentIdentifier,
    DeploymentIdentity,
    RelationshipKind,
)

SOURCE = """
const fn = new nodejs.NodejsFunction(this, 'AgentFn', {
  functionName: 'ni-sales-agent',
  entry: 'src/handler.ts',
});
const task = new ecs.FargateTaskDefinition(this, 'ProposalWorkerTask', {});
const containerName = 'proposal-worker';
task.addContainer('ProposalWorkerContainer', {
  containerName,
  image: ecs.ContainerImage.fromAsset('.', { file: 'src/worker/Dockerfile' }),
});
"""


def target(
    *,
    natural_key: str,
    display_name: str,
    service: str,
    logical_id: str,
    containers=(),
    deployment_artifact=None,
) -> DeploymentTarget:
    return DeploymentTarget(
        natural_key=natural_key,
        display_name=display_name,
        service=service,
        identity=DeploymentIdentity(
            provider="aws",
            runtime_kind=(
                "serverless_function" if service == "lambda" else "container_task"
            ),
            identifiers=(
                DeploymentIdentifier("cloudformation_logical_id", logical_id),
                *(
                    (DeploymentIdentifier("function_name", display_name),)
                    if service == "lambda"
                    else tuple(
                        DeploymentIdentifier("container_name", item)
                        for item in containers
                    )
                ),
            ),
        ),
        evidence_locator=f"aws://fixture/{natural_key}",
        evidence_payload={
            "container_names": list(containers),
            **({"deployment_artifact": deployment_artifact} if deployment_artifact else {}),
        },
    )


def write_artifact_fixture(root: Path) -> None:
    (root / "package.json").write_text("{}")
    (root / "src" / "worker").mkdir(parents=True)
    (root / "src" / "shared.ts").write_text("export const shared = true;\n")
    (root / "src" / "handler.ts").write_text(
        "import { shared } from './shared.js';\nexport const handler = () => shared;\n"
    )
    (root / "src" / "worker" / "main.ts").write_text(
        "import { shared } from '../shared.js';\nvoid shared;\n"
    )
    (root / "src" / "worker" / "Dockerfile").write_text(
        "FROM node:24 AS build\n"
        "RUN esbuild src/worker/main.ts \\\n"
        "    --bundle --platform=node --outfile=dist/worker.cjs\n"
    )


def write_cdk_manifest(root: Path) -> None:
    output = root / "cdk.out"
    output.mkdir()
    (output / "Stack.assets.json").write_text(
        """
{
  "version": "54.0.0",
  "files": {
    "lambda-asset": {
      "displayName": "AgentFn/Code",
      "source": {"path": "asset.lambda-asset", "packaging": "zip"},
      "destinations": {
        "fixture": {"bucketName": "cdk-assets", "objectKey": "lambda-asset.zip"}
      }
    }
  },
  "dockerImages": {
    "worker-asset": {
      "displayName": "ProposalWorkerTask/Container/AssetImage",
      "source": {"directory": "asset.worker-asset", "dockerFile": "src/worker/Dockerfile"},
      "destinations": {
        "fixture": {"repositoryName": "worker", "imageTag": "worker-asset"}
      }
    }
  }
}
"""
    )


def test_discovers_literal_lambda_and_ecs_declarations() -> None:
    declarations, warnings = _deployment_declarations(SOURCE, "infra/stack.ts")

    assert warnings == []
    assert [(item.service, item.construct_id, item.deployment_name) for item in declarations] == [
        ("lambda", "AgentFn", "ni-sales-agent"),
        ("ecs", "ProposalWorkerTask", "proposal-worker"),
    ]
    assert declarations[0].entry == "src/handler.ts"
    assert declarations[1].build_context == "."
    assert declarations[1].build_file == "src/worker/Dockerfile"


def test_discovers_literal_gcp_terraform_declarations() -> None:
    source = '''
resource "google_cloud_run_v2_service" "agent" {
  project  = "denali-test"
  location = "us-central1"
  name     = "denali-ai"

  template {
    containers {
      image = "us-central1-docker.pkg.dev/denali-test/apps/agent:latest"
    }
  }
}

resource "google_cloudfunctions2_function" "worker" {
  project  = "denali-test"
  location = "us-central1"
  name     = "denali-worker"
}
'''

    declarations, warnings = _deployment_declarations(source, "infra/main.tf")

    assert warnings == []
    assert [item.service for item in declarations] == [
        "cloud_run",
        "cloud_functions",
    ]
    assert [item.identity.provider for item in declarations] == ["gcp", "gcp"]
    assert declarations[0].identity.runtime_kind == "container_service"
    assert declarations[0].identity.match_basis() == [
        "literal_gcp_project_id",
        "literal_gcp_location",
        "literal_cloud_run_service_name",
    ]
    assert declarations[1].construct_id == (
        "google_cloudfunctions2_function.worker"
    )


def test_dynamic_gcp_terraform_scope_is_visible_but_not_correlated() -> None:
    source = '''
resource "google_cloud_run_v2_service" "agent" {
  project  = var.project_id
  location = "us-central1"
  name     = "denali-ai"
}
'''

    declarations, warnings = _deployment_declarations(source, "infra/main.tf")

    assert declarations == []
    assert warnings == [
        "infra/main.tf:2: Terraform GCP project, location, and name must each resolve "
        "to one literal"
    ]


def test_discovers_literal_aws_terraform_declarations() -> None:
    source = '''
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["123456789012"]
}

resource "aws_lambda_function" "agent" {
  function_name = "denali-agent"
}

resource "aws_ecs_task_definition" "worker" {
  family = "denali-worker"
}

resource "aws_eks_cluster" "models" {
  name = "denali-models"
}

resource "aws_sagemaker_endpoint" "model" {
  name = "denali-endpoint"
}
'''

    declarations, warnings = _deployment_declarations(source, "infra/aws.tf")

    assert warnings == []
    assert [item.service for item in declarations] == [
        "lambda",
        "ecs",
        "eks",
        "sagemaker",
    ]
    assert [item.identity.runtime_kind for item in declarations] == [
        "serverless_function",
        "container_task",
        "kubernetes_cluster",
        "model_endpoint",
    ]
    assert declarations[1].identity.match_basis() == [
        "literal_aws_account_id",
        "literal_aws_region",
        "literal_aws_task_family",
    ]


def test_aws_terraform_requires_literal_account_region_boundary() -> None:
    source = '''
provider "aws" {
  region = var.region
}
resource "aws_lambda_function" "agent" {
  function_name = "denali-agent"
}
'''

    declarations, warnings = _deployment_declarations(source, "infra/aws.tf")

    assert declarations == []
    assert "single allowed_account_ids" in warnings[0]


def test_terraform_resolves_single_valued_module_bindings_across_files(
    tmp_path: Path,
) -> None:
    (tmp_path / "variables.tf").write_text(
        '''
variable "account_id" {
  default = "123456789012"
}
variable "region" {
  default = "us-east-1"
}
variable "function_name" {
  default = "denali-agent"
}
locals {
  resolved_name = var.function_name
}
'''
    )
    (tmp_path / "provider.tf").write_text(
        '''
provider "aws" {
  region              = var.region
  allowed_account_ids = [var.account_id]
}
'''
    )
    (tmp_path / "main.tf").write_text(
        '''
resource "aws_lambda_function" "agent" {
  function_name = local.resolved_name
}
'''
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/terraform-bindings",
        targets=(),
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    summary = batch.assets[0].attributes["correlation_summary"]
    assert summary["declarations"] == 1
    assert summary["unmatched"] == 1
    candidate = batch.assets[0].attributes["correlation_candidates"][0]
    assert candidate["deployment_identifier"] == "denali-agent"
    assert candidate["match_basis"] == [
        "literal_aws_account_id",
        "literal_aws_region",
        "literal_aws_function_name",
    ]


def test_terraform_local_module_inherits_one_provider_scope_and_literal_arguments(
    tmp_path: Path,
) -> None:
    (tmp_path / "modules" / "agent").mkdir(parents=True)
    (tmp_path / "main.tf").write_text(
        '''
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["123456789012"]
}
module "agent" {
  source        = "./modules/agent"
  function_name = "denali-agent"
}
'''
    )
    (tmp_path / "modules" / "agent" / "main.tf").write_text(
        '''
variable "function_name" {
  type = string
}
resource "aws_lambda_function" "agent" {
  function_name = var.function_name
}
'''
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/terraform-module",
        targets=(),
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    summary = batch.assets[0].attributes["correlation_summary"]
    assert summary["declarations"] == 1
    assert summary["unmatched"] == 1


def test_terraform_module_with_multiple_argument_values_stays_partial(
    tmp_path: Path,
) -> None:
    (tmp_path / "modules" / "agent").mkdir(parents=True)
    (tmp_path / "main.tf").write_text(
        '''
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["123456789012"]
}
module "first" {
  source        = "./modules/agent"
  function_name = "first-agent"
}
module "second" {
  source        = "./modules/agent"
  function_name = "second-agent"
}
'''
    )
    (tmp_path / "modules" / "agent" / "main.tf").write_text(
        '''
variable "function_name" {
  type = string
}
resource "aws_lambda_function" "agent" {
  function_name = var.function_name
}
'''
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/terraform-ambiguous",
        targets=(),
    ).collect()

    assert batch.relationships == ()
    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert batch.assets[0].attributes["correlation_summary"]["declarations"] == 0
    assert "function_name must each resolve to one literal" in (
        batch.coverage[0].detail or ""
    )


def test_terraform_module_never_inherits_ambiguous_cross_account_scope(
    tmp_path: Path,
) -> None:
    (tmp_path / "env-one").mkdir()
    (tmp_path / "env-two").mkdir()
    (tmp_path / "modules" / "agent").mkdir(parents=True)
    for directory, account in (("env-one", "111111111111"), ("env-two", "222222222222")):
        (tmp_path / directory / "main.tf").write_text(
            f'''
provider "aws" {{
  region              = "us-east-1"
  allowed_account_ids = ["{account}"]
}}
module "agent" {{
  source        = "../modules/agent"
  function_name = "denali-agent"
}}
'''
        )
    (tmp_path / "modules" / "agent" / "main.tf").write_text(
        '''
variable "function_name" {
  type = string
}
resource "aws_lambda_function" "agent" {
  function_name = var.function_name
}
'''
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/terraform-cross-account",
        targets=(),
    ).collect()

    assert batch.relationships == ()
    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert batch.assets[0].attributes["correlation_summary"]["declarations"] == 0
    assert "allowed_account_ids" in (batch.coverage[0].detail or "")


def test_terraform_module_provider_mapping_never_uses_the_default_scope(
    tmp_path: Path,
) -> None:
    (tmp_path / "modules" / "agent").mkdir(parents=True)
    (tmp_path / "main.tf").write_text(
        '''
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["111111111111"]
}
provider "aws" {
  alias               = "other"
  region              = "us-west-2"
  allowed_account_ids = ["222222222222"]
}
module "agent" {
  source = "./modules/agent"
  providers = {
    aws = aws.other
  }
  function_name = "denali-agent"
}
'''
    )
    (tmp_path / "modules" / "agent" / "main.tf").write_text(
        '''
variable "function_name" {
  type = string
}
resource "aws_lambda_function" "agent" {
  function_name = var.function_name
}
'''
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/terraform-provider-map",
        targets=(),
    ).collect()

    assert batch.relationships == ()
    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert batch.assets[0].attributes["correlation_summary"]["declarations"] == 0


def test_discovers_sam_function_with_denali_boundary_metadata() -> None:
    source = '''
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Metadata:
  Denali:
    AccountId: '123456789012'
    Region: us-east-1
Resources:
  AgentFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: denali-agent
      Handler: app.handler
'''

    declarations, warnings = _deployment_declarations(source, "template.yaml")

    assert warnings == []
    assert len(declarations) == 1
    declaration = declarations[0]
    assert declaration.framework == "sam_cloudformation"
    assert declaration.service == "lambda"
    assert declaration.identity.values("account_id") == ("123456789012",)
    assert declaration.identity.values("region") == ("us-east-1",)
    assert declaration.identity.values("function_name") == ("denali-agent",)


def test_exact_aws_terraform_and_sam_identities_create_deployment_edges(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.tf").write_text(
        '''
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["123456789012"]
}
resource "aws_eks_cluster" "models" {
  name = "denali-models"
}
'''
    )
    (tmp_path / "template.yaml").write_text(
        '''
Metadata:
  Denali:
    AccountId: '123456789012'
    Region: us-east-1
Resources:
  Agent:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: denali-agent
'''
    )
    targets = (
        DeploymentTarget(
            natural_key="arn:aws:eks:us-east-1:123456789012:cluster/denali-models",
            display_name="denali-models",
            service="eks",
            identity=DeploymentIdentity(
                provider="aws",
                runtime_kind="kubernetes_cluster",
                identifiers=(
                    DeploymentIdentifier("account_id", "123456789012"),
                    DeploymentIdentifier("region", "us-east-1"),
                    DeploymentIdentifier("cluster_name", "denali-models"),
                ),
            ),
            evidence_locator="aws://eks/us-east-1/denali-models",
            evidence_payload={},
        ),
        DeploymentTarget(
            natural_key="arn:aws:lambda:us-east-1:123456789012:function:denali-agent",
            display_name="denali-agent",
            service="lambda",
            identity=DeploymentIdentity(
                provider="aws",
                runtime_kind="serverless_function",
                identifiers=(
                    DeploymentIdentifier("account_id", "123456789012"),
                    DeploymentIdentifier("region", "us-east-1"),
                    DeploymentIdentifier("function_name", "denali-agent"),
                ),
            ),
            evidence_locator="aws://lambda/us-east-1/denali-agent",
            evidence_payload={},
        ),
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/aws-agent",
        targets=targets,
    ).collect()

    assert len(batch.relationships) == 2
    assert {item.attributes["deployment_framework"] for item in batch.relationships} == {
        "terraform",
        "sam_cloudformation",
    }
    assert all(item.attributes["provider"] == "aws" for item in batch.relationships)


def test_exact_gcp_scope_and_service_create_deployed_by_edge(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        '''
resource "google_cloud_run_v2_service" "agent" {
  project  = "denali-test"
  location = "us-central1"
  name     = "denali-ai"
}
'''
    )
    target = DeploymentTarget(
        natural_key=(
            "//run.googleapis.com/projects/denali-test/locations/"
            "us-central1/services/denali-ai"
        ),
        display_name="denali-ai",
        service="cloud_run",
        identity=DeploymentIdentity(
            provider="gcp",
            runtime_kind="container_service",
            identifiers=(
                DeploymentIdentifier("project", "denali-test"),
                DeploymentIdentifier("location", "us-central1"),
                DeploymentIdentifier("service_name", "denali-ai"),
                DeploymentIdentifier("revision", "denali-ai-00001-abc"),
            ),
        ),
        evidence_locator="gcp://cloudasset/run/denali-ai",
        evidence_payload={
            "deployment_artifact": {
                "kind": "container_image",
                "image": "us-central1-docker.pkg.dev/denali-test/apps/agent@sha256:abc",
            }
        },
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/gcp-agent",
        targets=(target,),
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    assert len(batch.relationships) == 1
    relationship = batch.relationships[0]
    assert relationship.source.natural_key == target.natural_key
    assert relationship.attributes["provider"] == "gcp"
    assert relationship.attributes["runtime_kind"] == "container_service"
    assert relationship.attributes["deployment_framework"] == "terraform"
    assert relationship.attributes["artifact_inclusion_method"] == "not_evaluated"
    assert relationship.attributes["artifact_identity_status"] == "not_evaluated"


def test_cloud_run_export_yaml_uses_immutable_project_number() -> None:
    source = '''
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: denali-ai
  namespace: '123456789012'
  labels:
    cloud.googleapis.com/location: us-central1
spec:
  template:
    spec:
      containers:
        - image: us-central1-docker.pkg.dev/denali-test/apps/agent:latest
'''

    declarations, warnings = _deployment_declarations(source, "deploy/service.yaml")

    assert warnings == []
    assert len(declarations) == 1
    declaration = declarations[0]
    assert declaration.framework == "cloud_run_service_yaml"
    assert declaration.identity.match_basis() == [
        "literal_gcp_project_number",
        "literal_gcp_location",
        "literal_cloud_run_service_name",
    ]
    assert declaration.identity.values("project_number") == ("123456789012",)


def test_discovers_literal_azure_terraform_declarations() -> None:
    source = '''
provider "azurerm" {
  features {}
  subscription_id = "8cd2b4cc-c789-466d-a8f7-8f51fb20985d"
}

resource "azurerm_container_app" "agent" {
  name                = "denali-ai"
  resource_group_name = "Denali-Test"
  location            = "West US 2"
}

resource "azurerm_linux_function_app" "worker" {
  name                = "denali-worker"
  resource_group_name = "Denali-Test"
  location            = "West US 2"
}
'''

    declarations, warnings = _deployment_declarations(source, "infra/main.tf")

    assert warnings == []
    assert [item.service for item in declarations] == [
        "azure_container_apps",
        "azure_functions",
    ]
    assert declarations[0].identity.provider == "azure"
    assert declarations[0].identity.runtime_kind == "container_service"
    assert declarations[0].identity.match_basis() == [
        "literal_azure_subscription_id",
        "literal_azure_resource_group",
        "literal_azure_location",
        "literal_azure_container_app_name",
    ]
    assert declarations[1].identity.runtime_kind == "serverless_function"


def test_discovers_exact_azure_resource_export_json() -> None:
    source = (
        "{\n"
        '  "id": "/subscriptions/8cd2b4cc-c789-466d-a8f7-8f51fb20985d/'
        "resourceGroups/Denali-Test/providers/Microsoft.App/containerApps/denali-ai\",\n"
        '  "name": "denali-ai",\n'
        '  "type": "Microsoft.App/containerApps",\n'
        '  "location": "West US 2"\n'
        "}\n"
    )

    declarations, warnings = _deployment_declarations(
        source, "deploy/container-app.resource.json"
    )

    assert warnings == []
    assert len(declarations) == 1
    declaration = declarations[0]
    assert declaration.framework == "azure_resource_json"
    assert declaration.service == "azure_container_apps"
    assert declaration.identity.match_basis() == [
        "literal_azure_subscription_id",
        "literal_azure_resource_group",
        "literal_azure_location",
        "literal_azure_container_app_name",
    ]


def test_discovers_literal_azure_bicep_declarations() -> None:
    source = '''
metadata denaliSubscriptionId = '8cd2b4cc-c789-466d-a8f7-8f51fb20985d'
metadata denaliResourceGroup = 'Denali-Test'

resource app 'Microsoft.App/containerApps@2025-02-02-preview' = {
  name: 'denali-ai'
  location: 'westus2'
}
'''

    declarations, warnings = _deployment_declarations(source, "infra/main.bicep")

    assert warnings == []
    assert len(declarations) == 1
    assert declarations[0].framework == "bicep"
    assert declarations[0].deployment_name == "denali-ai"


def test_dynamic_azure_terraform_scope_is_visible_but_not_correlated() -> None:
    source = '''
provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}
resource "azurerm_container_app" "agent" {
  name                = "denali-ai"
  resource_group_name = "Denali-Test"
  location            = "West US 2"
}
'''

    declarations, warnings = _deployment_declarations(source, "infra/main.tf")

    assert declarations == []
    assert warnings == [
        "infra/main.tf:6: Terraform Azure provider subscription_id and resource "
        "resource_group_name, location, and name must each resolve to one literal"
    ]


def test_cloud_run_yaml_matches_target_with_project_number(tmp_path: Path) -> None:
    (tmp_path / "service.yaml").write_text(
        '''
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: denali-ai
  namespace: '123456789012'
  labels:
    cloud.googleapis.com/location: us-central1
'''
    )
    target = DeploymentTarget(
        natural_key=(
            "//run.googleapis.com/projects/denali-test/locations/"
            "us-central1/services/denali-ai"
        ),
        display_name="denali-ai",
        service="cloud_run",
        identity=DeploymentIdentity(
            provider="gcp",
            runtime_kind="container_service",
            identifiers=(
                DeploymentIdentifier("project", "denali-test"),
                DeploymentIdentifier("project_number", "123456789012"),
                DeploymentIdentifier("location", "us-central1"),
                DeploymentIdentifier("service_name", "denali-ai"),
            ),
        ),
        evidence_locator="gcp://cloudasset/run/denali-ai",
        evidence_payload={},
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/gcp-agent",
        targets=(target,),
    ).collect()

    assert len(batch.relationships) == 1
    assert batch.relationships[0].attributes["deployment_framework"] == (
        "cloud_run_service_yaml"
    )


def test_task_parser_does_not_borrow_a_later_tasks_container() -> None:
    source = """
const first = new ecs.FargateTaskDefinition(this, 'FirstTask', {});
const second = new ecs.FargateTaskDefinition(this, 'SecondTask', {});
second.addContainer('Worker', {
  containerName: 'second-worker',
});
"""

    declarations, warnings = _deployment_declarations(source, "infra/stack.ts")

    assert [(item.construct_id, item.deployment_name) for item in declarations] == [
        ("SecondTask", "second-worker")
    ]
    assert "FirstTask" not in " ".join(warnings)
    assert "task container declaration not found" in warnings[0]


def test_commented_deployments_and_literal_properties_are_not_evidence() -> None:
    source = """
// new nodejs.NodejsFunction(this, 'DisabledFn', {
//   functionName: 'disabled',
//   entry: 'src/disabled.ts',
// });
new nodejs.NodejsFunction(this, 'DynamicFn', {
  // functionName: 'not-real',
  functionName: configuredName,
  entry: 'src/handler.ts',
});
"""

    declarations, warnings = _deployment_declarations(source, "infra/stack.ts")

    assert declarations == []
    assert len(warnings) == 1
    assert "Lambda functionName is not literal" in warnings[0]


def test_exact_independent_identifiers_create_deployed_by_edges(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(SOURCE)
    write_artifact_fixture(tmp_path)
    targets = (
        target(
            natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
            display_name="ni-sales-agent",
            service="lambda",
            logical_id="AgentFnC1FD126F",
        ),
        target(
            natural_key="arn:aws:ecs:region:account:task-definition/worker:10",
            display_name="worker",
            service="ecs",
            logical_id="ProposalWorkerTask0422E6B9",
            containers=("proposal-worker",),
        ),
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=targets,
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    assert len(batch.relationships) == 2
    assert {item.kind for item in batch.relationships} == {RelationshipKind.DEPLOYED_BY}
    assert {item.assertion_type for item in batch.relationships} == {AssertionType.INFERRED}
    assert all(item.confidence == 1.0 for item in batch.relationships)
    assert all(item.target.natural_key == "github.com/example/anna" for item in batch.relationships)
    assert "control_plane_evidence" in batch.relationships[0].evidence.payload
    by_service = {item.attributes["service"]: item for item in batch.relationships}
    assert by_service["lambda"].attributes["entry"] == "src/handler.ts"
    assert by_service["lambda"].attributes["reachable_source_paths"] == [
        "src/handler.ts",
        "src/shared.ts",
    ]
    assert by_service["ecs"].attributes["entry"] == "src/worker/main.ts"
    assert by_service["ecs"].attributes["build_file"] == "src/worker/Dockerfile"
    assert by_service["ecs"].attributes["artifact_import_chains"]["src/shared.ts"] == [
        "src/worker/main.ts",
        "src/shared.ts",
    ]
    assert by_service["lambda"].attributes["artifact_identity_status"] == "not_evaluated"
    assert by_service["lambda"].attributes["source_revision_status"] == "unattested"


def test_exact_cdk_locator_match_is_separate_from_unattested_revision(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(SOURCE)
    write_artifact_fixture(tmp_path)
    write_cdk_manifest(tmp_path)
    targets = (
        target(
            natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
            display_name="ni-sales-agent",
            service="lambda",
            logical_id="AgentFnC1FD126F",
            deployment_artifact={
                "kind": "s3_object",
                "bucket": "cdk-assets",
                "key": "lambda-asset.zip",
                "code_sha256": "live-code-sha",
            },
        ),
        target(
            natural_key="arn:aws:ecs:region:account:task-definition/worker:10",
            display_name="worker",
            service="ecs",
            logical_id="ProposalWorkerTask0422E6B9",
            containers=("proposal-worker",),
            deployment_artifact={
                "kind": "container_image",
                "container_name": "proposal-worker",
                "image": "123.dkr.ecr/worker:worker-asset",
            },
        ),
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=targets,
    ).collect()

    by_service = {item.attributes["service"]: item for item in batch.relationships}
    for relationship in by_service.values():
        assert relationship.attributes["artifact_identity_status"] == "matched"
        assert relationship.attributes["artifact_identity_method"] == "cdk_asset_manifest"
        assert relationship.attributes["source_revision_status"] == "unattested"
        assert relationship.attributes["repository_revision"] == "working-tree"
    assert by_service["lambda"].attributes["deployment_asset_id"] == "lambda-asset"
    assert by_service["ecs"].attributes["deployment_asset_id"] == "worker-asset"


def test_manifest_without_exact_locator_is_not_reported_as_drift(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(SOURCE.split("const task", 1)[0])
    write_artifact_fixture(tmp_path)
    write_cdk_manifest(tmp_path)
    matching = target(
        natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
        display_name="ni-sales-agent",
        service="lambda",
        logical_id="AgentFnC1FD126F",
        deployment_artifact={
            "kind": "s3_object",
            "bucket": "different-bucket",
            "key": "different-key.zip",
        },
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=(matching,),
    ).collect()

    relationship = batch.relationships[0]
    assert relationship.attributes["artifact_identity_status"] == "not_matched"
    assert relationship.attributes["source_revision_status"] == "unattested"
    assert "drift" not in str(relationship.attributes).lower()


def test_module_graph_includes_literal_dynamic_imports_but_not_type_only_imports() -> None:
    sources = {
        "src/entry.ts": (
            "import type { TypeOnly } from './types.js';\n"
            "// import './commented.js';\n"
            "export async function load() { return import('./runtime.js'); }\n"
        ),
        "src/types.ts": "export interface TypeOnly { value: string }\n",
        "src/commented.ts": "export const ignored = true;\n",
        "src/runtime.ts": "export const runtime = true;\n",
    }

    reachable, chains, warnings = _local_module_graph("src/entry.ts", sources)

    assert warnings == []
    assert reachable == {"src/entry.ts", "src/runtime.ts"}
    assert chains["src/runtime.ts"] == ["src/entry.ts", "src/runtime.ts"]
    assert _local_imports(sources["src/entry.ts"]) == ("./runtime.js",)


def test_unresolved_local_import_is_partial_without_inventing_a_module(tmp_path: Path) -> None:
    source = SOURCE.split("const task", 1)[0]
    (tmp_path / "stack.ts").write_text(source)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "handler.ts").write_text("import './missing.js';\n")
    matching = target(
        natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
        display_name="ni-sales-agent",
        service="lambda",
        logical_id="AgentFnABC123",
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=(matching,),
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert batch.relationships[0].attributes["reachable_source_paths"] == ["src/handler.ts"]
    assert "local import './missing.js' was not found" in (batch.coverage[0].detail or "")


def test_missing_generated_import_is_deliberately_omitted_from_artifact_graph() -> None:
    sources = {
        "src/entry.ts": "import './screenshots.generated.js';\nexport const entry = true;\n",
    }

    reachable, chains, warnings = _local_module_graph("src/entry.ts", sources)

    assert warnings == []
    assert reachable == {"src/entry.ts"}
    assert chains == {"src/entry.ts": ["src/entry.ts"]}


def test_model_or_name_only_match_does_not_create_a_deployment_edge(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(SOURCE)
    wrong_logical_id = target(
        natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
        display_name="ni-sales-agent",
        service="lambda",
        logical_id="DifferentFunctionABC123",
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=(wrong_logical_id,),
    ).collect()

    assert batch.relationships == ()


def test_ambiguous_matches_are_visible_and_not_correlated(tmp_path: Path) -> None:
    (tmp_path / "stack.ts").write_text(SOURCE.split("const task", 1)[0])
    matching = target(
        natural_key="arn:aws:lambda:region:account:function:ni-sales-agent",
        display_name="ni-sales-agent",
        service="lambda",
        logical_id="AgentFnABC123",
    )
    second = target(
        natural_key="arn:aws:lambda:other:account:function:ni-sales-agent",
        display_name="ni-sales-agent",
        service="lambda",
        logical_id="AgentFnXYZ789",
    )

    batch = CodeToCloudConnector(
        tmp_path,
        repository_name="github.com/example/anna",
        targets=(matching, second),
    ).collect()

    assert batch.relationships == ()
    assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert "matched multiple active workloads" in (batch.coverage[0].detail or "")
    summary = batch.assets[0].attributes["correlation_summary"]
    assert summary == {
        "declarations": 1,
        "proven": 0,
        "ambiguous": 1,
        "unmatched": 0,
        "targets_evaluated": 2,
    }
    assert batch.assets[0].attributes["correlation_candidates"] == [
        {
            "status": "ambiguous",
            "provider": "aws",
            "runtime_kind": "serverless_function",
            "deployment_framework": "aws_cdk",
            "service": "lambda",
            "construct_id": "AgentFn",
            "deployment_identifier": "ni-sales-agent",
            "source_path": "stack.ts",
            "source_line": 2,
            "match_basis": [
                "cloudformation_logical_id_prefix",
                "literal_lambda_function_name",
            ],
            "matched_workload_count": 2,
            "matched_workloads": [matching.natural_key, second.natural_key],
        }
    ]
