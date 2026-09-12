"""Short-lived AWS CloudFormation Quick Create launches."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlencode
from uuid import uuid4

from denali.connections.aws import render_cloudformation

AWS_ONBOARDING_TEMPLATE_VERSION = "denali-aws-readonly-role-v2-agent-runtime"
_PRINCIPAL_ARN_PATTERN = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:(role|user)/.+$"
)
_CONSOLE_DOMAINS = {
    "aws": "{region}.console.aws.amazon.com",
    "aws-us-gov": "console.amazonaws-us-gov.com",
    "aws-cn": "console.amazonaws.cn",
}


class S3OnboardingClient(Protocol):
    def put_object(self, **kwargs: Any) -> Any: ...

    def generate_presigned_url(
        self, client_method: str, *, Params: dict[str, str], ExpiresIn: int
    ) -> str: ...


class AwsCloudFormationLauncher:
    """Publish an exact per-connection template and build an AWS Quick Create URL."""

    def __init__(
        self,
        *,
        bucket_name: str,
        principal_arn: str,
        s3_client: S3OnboardingClient | None = None,
        expires_in_seconds: int = 3600,
        object_prefix: str = "denali/onboarding/aws",
        now: Callable[[], datetime] | None = None,
        nonce: Callable[[], str] | None = None,
    ):
        if not bucket_name.strip():
            raise ValueError("AWS onboarding bucket must not be blank")
        principal_match = _PRINCIPAL_ARN_PATTERN.fullmatch(principal_arn)
        if principal_match is None:
            raise ValueError("Denali AWS principal ARN is invalid")
        if not 300 <= expires_in_seconds <= 3600:
            raise ValueError("AWS onboarding URL lifetime must be between 300 and 3600 seconds")
        self._bucket_name = bucket_name
        self._principal_arn = principal_arn
        self._principal_partition = principal_match.group(1)
        self._expires_in_seconds = expires_in_seconds
        self._object_prefix = object_prefix.strip("/")
        self._now = now or (lambda: datetime.now(UTC))
        self._nonce = nonce or (lambda: str(uuid4()))
        self._s3_client = s3_client or _default_s3_client()

    def create_launch(
        self,
        *,
        tenant_id: str,
        connection_id: str,
        connection: dict[str, Any],
    ) -> dict[str, Any]:
        configuration = connection["configuration"]
        partition = configuration.get("partition", "aws")
        if partition not in _CONSOLE_DOMAINS:
            raise ValueError("AWS partition is not supported for Quick Create")
        if partition != self._principal_partition:
            raise ValueError("Denali principal and connection must use the same AWS partition")
        region = configuration.get("deployment_region", "us-east-1")
        template = render_cloudformation(connection)
        template_bytes = template.encode("utf-8")
        template_sha256 = hashlib.sha256(template_bytes).hexdigest()
        published_at = self._now()
        expires_at = published_at + timedelta(seconds=self._expires_in_seconds)
        object_key = (
            f"{self._object_prefix}/{tenant_id}/{connection_id}/{self._nonce()}.yaml"
        )
        self._s3_client.put_object(
            Bucket=self._bucket_name,
            Key=object_key,
            Body=template_bytes,
            ContentType="application/yaml",
            CacheControl="no-store",
            ServerSideEncryption="AES256",
            Metadata={
                "denali-template-version": AWS_ONBOARDING_TEMPLATE_VERSION,
                "denali-template-sha256": template_sha256,
            },
        )
        template_url = self._s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket_name, "Key": object_key},
            ExpiresIn=self._expires_in_seconds,
        )
        stack_name = f"Denali-{connection_id.split('-', 1)[0]}"
        quick_create_parameters = urlencode(
            {
                "templateURL": template_url,
                "stackName": stack_name,
                "param_DenaliPrincipalArn": self._principal_arn,
            }
        )
        console_domain = _CONSOLE_DOMAINS[partition].format(region=region)
        launch_url = (
            f"https://{console_domain}/cloudformation/home?region={region}"
            f"#/stacks/create/review?{quick_create_parameters}"
        )
        return {
            "launch_url": launch_url,
            "stack_name": stack_name,
            "stack_region": region,
            "template_version": AWS_ONBOARDING_TEMPLATE_VERSION,
            "template_sha256": template_sha256,
            "principal_arn": self._principal_arn,
            "published_at": published_at,
            "expires_at": expires_at,
        }


def _default_s3_client() -> S3OnboardingClient:
    try:
        import boto3
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError(
            "install Denali with the aws extra to publish onboarding templates"
        ) from error
    return boto3.client("s3")
