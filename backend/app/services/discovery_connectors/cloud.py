import hashlib
from typing import Any

from app.services.agent_discovery_scope import (
    is_agent_cloud_compute,
    is_agent_cloud_identity,
    is_agent_cloud_storage,
    is_agent_ec2_instance,
    is_agent_related_text,
    is_agent_s3_bucket,
)
from app.services.discovery_connectors.http_utils import bearer_headers, http_get_json
from app.services.discovery_connectors.types import ConnectionRuntime, DiscoveryCandidate


def _fingerprint(*parts: str) -> str:
    payload = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _aws_client(service: str, region: str):
    try:
        import boto3  # type: ignore
    except ImportError as exc:
        raise ValueError("boto3 is required for AWS live discovery") from exc
    return boto3.client(service, region_name=region or None)


def _bucket_tags(client, bucket_name: str) -> dict[str, str]:
    try:
        response = client.get_bucket_tagging(Bucket=bucket_name)
        tags = {}
        for tag in response.get("TagSet") or []:
            key = str(tag.get("Key") or "").strip()
            val = str(tag.get("Value") or "").strip()
            if key:
                tags[key] = val
        return tags
    except Exception:
        return {}


def fetch_aws_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    region = str(runtime.config.get("region") or "us-east-1").strip()
    source_id = runtime.source_id
    records: list[DiscoveryCandidate] = []

    if source_id not in {"aws_ec2", "aws_s3", "aws_bedrock", "aws_sagemaker", "aws_iam"}:
        raise ValueError(f"Unsupported AWS discovery source: {source_id}")

    if source_id == "aws_ec2":
        client = _aws_client("ec2", region)
        response = client.describe_instances()
        reservations = response.get("Reservations") or []
        for reservation in reservations:
            for instance in reservation.get("Instances") or []:
                if not is_agent_ec2_instance(instance):
                    continue
                instance_id = str(instance.get("InstanceId") or "").strip()
                if not instance_id:
                    continue
                records.append(
                    DiscoveryCandidate(
                        canonical_agent_key=f"aws-ec2:{instance_id}",
                        source_fingerprint=_fingerprint(runtime.connection_id, instance_id),
                        confidence=88,
                        metadata={"live": True, "region": region, "agent_scoped": True},
                    )
                )
    elif source_id == "aws_s3":
        client = _aws_client("s3", region)
        response = client.list_buckets()
        for bucket in response.get("Buckets") or []:
            name = str(bucket.get("Name") or "").strip()
            if not name:
                continue
            tags = _bucket_tags(client, name)
            if not is_agent_s3_bucket(name, tags):
                continue
            records.append(
                DiscoveryCandidate(
                    canonical_agent_key=f"aws-s3:{name}",
                    source_fingerprint=_fingerprint(runtime.connection_id, name),
                    confidence=86,
                    metadata={"live": True, "region": region, "agent_scoped": True},
                )
            )
    elif source_id == "aws_bedrock":
        client = _aws_client("bedrock", region)
        response = client.list_foundation_models()
        for model in response.get("modelSummaries") or []:
            model_id = str(model.get("modelId") or "").strip()
            if not model_id:
                continue
            records.append(
                DiscoveryCandidate(
                    canonical_agent_key=f"aws-bedrock:{model_id}",
                    source_fingerprint=_fingerprint(runtime.connection_id, model_id),
                    confidence=91,
                    metadata={"live": True, "region": region},
                )
            )
    elif source_id == "aws_sagemaker":
        client = _aws_client("sagemaker", region)
        response = client.list_endpoints(MaxResults=100)
        for endpoint in response.get("Endpoints") or []:
            name = str(endpoint.get("EndpointName") or "").strip()
            if not name or not is_agent_related_text(name):
                continue
            records.append(
                DiscoveryCandidate(
                    canonical_agent_key=f"aws-sagemaker:{name}",
                    source_fingerprint=_fingerprint(runtime.connection_id, name),
                    confidence=90,
                    metadata={"live": True, "region": region, "agent_scoped": True},
                )
            )
    elif source_id == "aws_iam":
        client = _aws_client("iam", region)
        response = client.list_roles(MaxItems=100)
        for role in response.get("Roles") or []:
            name = str(role.get("RoleName") or "").strip()
            if not name or not is_agent_cloud_identity(name, str(role.get("Description") or "")):
                continue
            records.append(
                DiscoveryCandidate(
                    canonical_agent_key=f"aws-iam:{name}",
                    source_fingerprint=_fingerprint(runtime.connection_id, name),
                    confidence=87,
                    metadata={"live": True, "agent_scoped": True},
                )
            )

    return records


def _azure_resource_type(source_id: str) -> str:
    return {
        "azure_openai": "Microsoft.CognitiveServices/accounts",
        "azure_ml": "Microsoft.MachineLearningServices/workspaces",
        "azure_blob_storage": "Microsoft.Storage/storageAccounts",
        "azure_virtual_machines": "Microsoft.Compute/virtualMachines",
        "azure_managed_identity": "Microsoft.Managed Identity/userAssignedIdentities",
    }.get(source_id, "Microsoft.Resources/resources")


def fetch_azure_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    token = str(runtime.credentials.secret_value or "").strip()
    if not token:
        raise ValueError("Azure connection requires bearer token or stored service principal secret")
    subscription_id = str(runtime.config.get("subscription_id") or "").strip()
    if not subscription_id:
        raise ValueError("Azure connection requires subscription_id in connection_config")

    source_id = runtime.source_id
    base = (runtime.base_url or "https://management.azure.com").rstrip("/")
    api_version = str(runtime.config.get("api_version") or "2023-01-01").strip()
    headers = bearer_headers(token)
    resource_type = _azure_resource_type(source_id)
    url = f"{base}/subscriptions/{subscription_id}/resources"
    payload = http_get_json(
        url,
        headers=headers,
        params={"api-version": api_version, "$filter": f"resourceType eq '{resource_type}'"},
    )
    values = payload.get("value") if isinstance(payload, dict) else []
    records = []
    for item in values or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        tags = item.get("tags") if isinstance(item.get("tags"), dict) else {}
        if source_id == "azure_blob_storage" and not is_agent_cloud_storage(name, tags):
            continue
        if source_id == "azure_virtual_machines" and not is_agent_cloud_compute(name, str(item.get("type") or ""), tags):
            continue
        if source_id == "azure_managed_identity" and not is_agent_cloud_identity(name):
            continue
        if source_id == "azure_ml" and not is_agent_related_text(name):
            continue
        records.append(
            DiscoveryCandidate(
                canonical_agent_key=f"{source_id}:{name}",
                source_fingerprint=_fingerprint(runtime.connection_id, name),
                confidence=90 if source_id == "azure_openai" else 88,
                metadata={"live": True, "resource_type": resource_type},
            )
        )
    return records


def fetch_gcp_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    token = str(runtime.credentials.secret_value or "").strip()
    if not token:
        raise ValueError("GCP connection requires access token or service account key JSON in secret")
    project_id = str(runtime.config.get("project_id") or "").strip()
    if not project_id:
        raise ValueError("GCP connection requires project_id in connection_config")

    source_id = runtime.source_id
    headers = bearer_headers(token)
    records: list[DiscoveryCandidate] = []

    if source_id == "gcp_vertex_ai":
        location = str(runtime.config.get("location") or "us-central1").strip()
        url = f"https://{location}-aiplatform.googleapis.com/v1/projects/{project_id}/locations/{location}/models"
        payload = http_get_json(
            url,
            headers=headers,
        )
        for item in payload.get("models") or []:
            name = str(item.get("name") or item.get("displayName") or "").strip()
            if name:
                records.append(
                    DiscoveryCandidate(
                        canonical_agent_key=f"vertex:{name}",
                        source_fingerprint=_fingerprint(runtime.connection_id, name),
                        confidence=90,
                        metadata={"live": True, "location": location},
                    )
                )
    elif source_id == "gcp_cloud_storage":
        url = "https://storage.googleapis.com/storage/v1/b"
        payload = http_get_json(
            url,
            headers=headers,
            params={"project": project_id},
        )
        for item in payload.get("items") or []:
            name = str(item.get("name") or "").strip()
            if name and is_agent_cloud_storage(name):
                records.append(
                    DiscoveryCandidate(
                        canonical_agent_key=f"gcs:{name}",
                        source_fingerprint=_fingerprint(runtime.connection_id, name),
                        confidence=86,
                        metadata={"live": True, "project_id": project_id, "agent_scoped": True},
                    )
                )
    elif source_id == "gcp_compute_engine":
        zone = str(runtime.config.get("zone") or "us-central1-a").strip()
        url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/zones/{zone}/instances"
        payload = http_get_json(
            url,
            headers=headers,
        )
        for item in payload.get("items") or []:
            name = str(item.get("name") or "").strip()
            machine = str(item.get("machineType") or "").split("/")[-1]
            labels = item.get("labels") if isinstance(item.get("labels"), dict) else {}
            if name and is_agent_cloud_compute(name, machine, labels):
                records.append(
                    DiscoveryCandidate(
                        canonical_agent_key=f"gce:{name}",
                        source_fingerprint=_fingerprint(runtime.connection_id, name),
                        confidence=87,
                        metadata={"live": True, "zone": zone, "agent_scoped": True},
                    )
                )
    elif source_id == "gcp_service_accounts":
        url = f"https://iam.googleapis.com/v1/projects/{project_id}/serviceAccounts"
        payload = http_get_json(
            url,
            headers=headers,
        )
        for item in payload.get("accounts") or []:
            email = str(item.get("email") or "").strip()
            display = str(item.get("displayName") or "")
            if email and is_agent_cloud_identity(email, display):
                records.append(
                    DiscoveryCandidate(
                        canonical_agent_key=email,
                        source_fingerprint=_fingerprint(runtime.connection_id, email),
                        confidence=88,
                        metadata={"live": True, "project_id": project_id, "agent_scoped": True},
                    )
                )

    return records


def fetch_oracle_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    token = str(runtime.credentials.secret_value or "").strip()
    if not token:
        raise ValueError("Oracle OCI connection requires API key or bearer token")
    region = str(runtime.config.get("region") or "us-chicago-1").strip()
    compartment_id = str(runtime.config.get("compartment_id") or "").strip()
    source_id = runtime.source_id
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    records: list[DiscoveryCandidate] = []

    if source_id == "oracle_oci_genai":
        base = (runtime.base_url or f"https://generativeai.{region}.oci.oraclecloud.com").rstrip("/")
        url = f"{base}/20231130/generativeAiModels"
        if compartment_id:
            url = f"{url}?compartmentId={compartment_id}"
        payload = http_get_json(
            url,
            headers=headers,
        )
        items = payload.get("items") if isinstance(payload, dict) else []
        for item in items or []:
            model_id = str(item.get("id") or item.get("displayName") or "").strip()
            if model_id:
                records.append(
                    DiscoveryCandidate(
                        canonical_agent_key=f"oci-genai:{model_id}",
                        source_fingerprint=_fingerprint(runtime.connection_id, model_id),
                        confidence=90,
                        metadata={"live": True, "region": region},
                    )
                )
    elif source_id == "oracle_oci_object_storage":
        namespace = str(runtime.config.get("namespace") or "").strip()
        if not namespace:
            raise ValueError("oracle_oci_object_storage requires namespace in connection_config")
        url = f"https://objectstorage.{region}.oraclecloud.com/n/{namespace}/b/"
        payload = http_get_json(
            url,
            headers=headers,
        )
        for item in payload if isinstance(payload, list) else []:
            name = str(item.get("name") or "").strip()
            if name and is_agent_cloud_storage(name):
                records.append(
                    DiscoveryCandidate(
                        canonical_agent_key=f"oci-os:{name}",
                        source_fingerprint=_fingerprint(runtime.connection_id, name),
                        confidence=86,
                        metadata={"live": True, "namespace": namespace, "agent_scoped": True},
                    )
                )
    elif source_id == "oracle_oci_compute":
        if not compartment_id:
            raise ValueError("oracle_oci_compute requires compartment_id in connection_config")
        url = f"https://iaas.{region}.oraclecloud.com/20160918/instances"
        payload = http_get_json(
            url,
            headers=headers,
            params={"compartmentId": compartment_id},
        )
        for item in payload if isinstance(payload, list) else []:
            name = str(item.get("displayName") or item.get("id") or "").strip()
            shape = str(item.get("shape") or "")
            if name and is_agent_cloud_compute(name, shape):
                records.append(
                    DiscoveryCandidate(
                        canonical_agent_key=f"oci-compute:{name}",
                        source_fingerprint=_fingerprint(runtime.connection_id, name),
                        confidence=87,
                        metadata={"live": True, "region": region, "agent_scoped": True},
                    )
                )

    return records


def fetch_coreweave_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    token = str(runtime.credentials.secret_value or "").strip()
    if not token:
        raise ValueError("coreweave_gpu connection requires API key")
    base = (runtime.base_url or "https://api.coreweave.com").rstrip("/")
    records: list[DiscoveryCandidate] = []
    for path in ("/v1/instances", "/v1/gpu/instances", "/v1/workloads"):
        try:
            payload = http_get_json(
                f"{base}{path}",
                headers=bearer_headers(token),
            )
        except Exception:
            continue
        items = payload.get("data") if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("id") or item.get("name") or "").strip()
            if not name:
                continue
            if not is_agent_cloud_compute(name, str(item.get("type") or item.get("gpu_type") or "")):
                continue
            records.append(
                DiscoveryCandidate(
                    canonical_agent_key=f"coreweave:{name}",
                    source_fingerprint=_fingerprint(runtime.connection_id, path, name),
                    confidence=89,
                    metadata={"live": True, "provider": "coreweave", "agent_scoped": True},
                )
            )
        if records:
            break
    return records
