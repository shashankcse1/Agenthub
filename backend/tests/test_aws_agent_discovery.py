from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from app.models import DiscoveryConnection
from app.services.agent_discovery_scope import is_agent_ec2_instance, is_agent_s3_bucket
from app.services.discovery_connectors.cloud import fetch_aws_inventory
from app.services.discovery_connectors.types import ConnectionCredentials, ConnectionRuntime


def test_is_agent_ec2_instance_filters_ml_and_tags():
    assert is_agent_ec2_instance({"InstanceType": "ml.g4dn.xlarge", "Tags": []}) is True
    assert is_agent_ec2_instance(
        {
            "InstanceType": "t3.micro",
            "Tags": [{"Key": "Name", "Value": "langchain-agent-worker"}],
        }
    ) is True
    assert is_agent_ec2_instance(
        {
            "InstanceType": "t3.micro",
            "Tags": [{"Key": "Name", "Value": "web-server"}],
        }
    ) is False


def test_is_agent_s3_bucket_filters_agent_keywords():
    assert is_agent_s3_bucket("corp-llm-models-prod") is True
    assert is_agent_s3_bucket("static-website-assets") is False
    assert is_agent_s3_bucket("data-lake", {"Purpose": "RAG embeddings store"}) is True


@pytest.fixture
def aws_ec2_runtime():
    return ConnectionRuntime(
        connection_id=f"dconn-{uuid4()}",
        tenant_id="tenant-a",
        source_id="aws_ec2",
        base_url="",
        config={"region": "us-east-1"},
        credentials=ConnectionCredentials(provider_type="aws"),
    )


def test_fetch_aws_ec2_only_agent_workloads(aws_ec2_runtime):
    mock_client = MagicMock()
    mock_client.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-agent",
                        "InstanceType": "g5.xlarge",
                        "Tags": [{"Key": "Name", "Value": "inference-host"}],
                    },
                    {
                        "InstanceId": "i-web",
                        "InstanceType": "t3.micro",
                        "Tags": [{"Key": "Name", "Value": "nginx"}],
                    },
                ]
            }
        ]
    }

    with patch("app.services.discovery_connectors.cloud._aws_client", return_value=mock_client):
        records = fetch_aws_inventory(aws_ec2_runtime)

    assert len(records) == 1
    assert records[0].canonical_agent_key == "aws-ec2:i-agent"
    assert records[0].metadata.get("agent_scoped") is True


def test_fetch_aws_s3_only_agent_buckets():
    runtime = ConnectionRuntime(
        connection_id=f"dconn-{uuid4()}",
        tenant_id="tenant-a",
        source_id="aws_s3",
        base_url="",
        config={"region": "us-east-1"},
        credentials=ConnectionCredentials(provider_type="aws"),
    )
    mock_client = MagicMock()
    mock_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "acme-agent-checkpoints"},
            {"Name": "acme-logs"},
        ]
    }
    mock_client.get_bucket_tagging.side_effect = [
        {"TagSet": [{"Key": "Use", "Value": "model training"}]},
        {"TagSet": []},
    ]

    with patch("app.services.discovery_connectors.cloud._aws_client", return_value=mock_client):
        records = fetch_aws_inventory(runtime)

    assert len(records) == 1
    assert records[0].canonical_agent_key == "aws-s3:acme-agent-checkpoints"
