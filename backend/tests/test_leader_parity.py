"""Unit coverage for Helicone/Portkey/n8n competitive parity slices."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.routers import gateway as gateway_router
from app.services.orchestration_flows import _execute_single_stub_node


def test_serialize_user_properties_sanitizes_and_truncates():
    raw = {
        "user_id": "u-1",
        "plan": "enterprise",
        "nested": {"a": 1},
        "": "skip",
        "long": "x" * 500,
    }
    encoded = gateway_router._serialize_user_properties(raw)
    assert '"user_id":"u-1"' in encoded
    assert '"plan":"enterprise"' in encoded
    assert "nested" in encoded
    assert len(encoded) < 2000


def test_resolve_virtual_key_by_id():
    db = MagicMock()
    key = SimpleNamespace(key_id="vk-1", key_hash="hash-1", status="active")
    db.query.return_value.filter_by.return_value.first.return_value = key
    resolved = gateway_router._resolve_virtual_key_for_inference(
        db,
        virtual_key_id="vk-1",
        authorization_header=None,
        x_virtual_key_id=None,
    )
    assert resolved is key


def test_resolve_virtual_key_by_bearer_hash():
    db = MagicMock()
    key = SimpleNamespace(key_id="vk-2", key_hash="secret-hash", status="active")
    db.query.return_value.filter_by.return_value.first.return_value = key
    resolved = gateway_router._resolve_virtual_key_for_inference(
        db,
        virtual_key_id=None,
        authorization_header="Bearer secret-hash",
        x_virtual_key_id=None,
    )
    assert resolved is key


def test_enforce_virtual_key_guardrails_denies_blocked_key():
    db = MagicMock()
    key = SimpleNamespace(key_id="vk-blocked", status="blocked", guardrail_policy="{}", owner_scope_id="scope-1")
    with pytest.raises(HTTPException) as exc:
        gateway_router._enforce_virtual_key_guardrails_on_inference(
            db,
            key=key,
            environment="dev",
            input_tokens=10,
            owner_scope="actor:a1",
            mfa_verified=False,
            actor_id="a1",
            trace_id="trace-1",
        )
    assert exc.value.status_code == 403


def test_enforce_virtual_key_guardrails_denies_policy_violation():
    db = MagicMock()
    key = SimpleNamespace(
        key_id="vk-policy",
        status="active",
        owner_scope_id="scope-1",
        guardrail_policy='{"max_input_tokens":5,"policy_mode":"block"}',
    )
    with patch.object(gateway_router, "create_audit_event"):
        with pytest.raises(HTTPException) as exc:
            gateway_router._enforce_virtual_key_guardrails_on_inference(
                db,
                key=key,
                environment="dev",
                input_tokens=50,
                owner_scope="actor:a1",
                mfa_verified=False,
                actor_id="a1",
                trace_id="trace-2",
            )
    assert exc.value.status_code == 403
    detail = exc.value.detail
    assert detail["error_code"] == "VIRTUAL_KEY_GUARDRAIL_DENIED"


def test_enforce_virtual_key_allowlists_denies_model():
    db = MagicMock()
    key = SimpleNamespace(
        key_id="vk-allow",
        status="active",
        allowed_models='["gpt-4o-mini"]',
        allowed_endpoint_families="[]",
    )
    with patch.object(gateway_router, "create_audit_event"):
        with pytest.raises(HTTPException) as exc:
            gateway_router._enforce_virtual_key_allowlists(
                db,
                key=key,
                model_name="gpt-4o",
                endpoint_family="chat.completions",
                actor_id="a1",
                trace_id="trace-allow",
            )
    assert exc.value.status_code == 403
    assert exc.value.detail["error_code"] == "VIRTUAL_KEY_ALLOWLIST_DENIED"


def test_enforce_virtual_key_allowlists_allows_empty_and_match():
    db = MagicMock()
    key = SimpleNamespace(
        key_id="vk-ok",
        status="active",
        allowed_models="[]",
        allowed_endpoint_families='["chat.completions"]',
    )
    with patch.object(gateway_router, "create_audit_event"):
        result = gateway_router._enforce_virtual_key_allowlists(
            db,
            key=key,
            model_name="openai/gpt-4o-mini",
            endpoint_family="chat.completions",
            actor_id="a1",
            trace_id="trace-allow-ok",
        )
    assert result["decision"] == "allow"


def test_enforce_virtual_key_output_stage_max_tokens():
    db = MagicMock()
    key = SimpleNamespace(
        key_id="vk-out",
        status="active",
        owner_scope_id="scope-1",
        guardrail_policy='{"max_output_tokens":10,"policy_mode":"block"}',
    )
    with patch.object(gateway_router, "create_audit_event"):
        with pytest.raises(HTTPException) as exc:
            gateway_router._enforce_virtual_key_guardrails_on_inference(
                db,
                key=key,
                environment="dev",
                input_tokens=5,
                owner_scope="actor:a1",
                mfa_verified=False,
                actor_id="a1",
                trace_id="trace-out",
                stage="output",
                output_tokens=50,
            )
    assert exc.value.status_code == 403
    assert exc.value.detail["stage"] == "output"


def test_merge_helicone_request_properties():
    payload = SimpleNamespace(
        user="end-user-9",
        properties={"feature": "assist", "plan": "pro"},
        user_properties={"feature": "override", "team": "ops"},
    )
    merged = gateway_router._merge_helicone_request_properties(payload)
    assert merged["user"] == "end-user-9"
    assert merged["user_id"] == "end-user-9"
    assert merged["feature"] == "override"
    assert merged["plan"] == "pro"
    assert merged["team"] == "ops"


def test_enforce_virtual_key_budget_skips_default():
    db = MagicMock()
    key = SimpleNamespace(key_id="vk-b", budget_policy_id="default")
    with patch.object(gateway_router, "create_audit_event"):
        result = gateway_router._enforce_virtual_key_budget(
            db,
            key=key,
            owner_scope="actor:a1",
            actor_id="a1",
            trace_id="trace-budget-default",
        )
    assert result["decision"] == "allow"
    assert result["applied"] is False


def test_enforce_virtual_key_budget_denies_hard_limit():
    from app.services.cost_limits import CostLimitScopeResult
    from app.policy_constants import COST_POLICY_DECISION_DENY

    db = MagicMock()
    key = SimpleNamespace(key_id="vk-b2", budget_policy_id="bud-1")
    denied = CostLimitScopeResult(
        scope_type="user",
        scope_id="a1",
        policy_id="bud-1",
        spend_cents=200,
        budget_cents=100,
        effective_budget_cents=100,
        utilization_percent=200.0,
        decision=COST_POLICY_DECISION_DENY,
        recommended_action="block",
        soft_limit_alert=False,
    )
    with patch.object(gateway_router, "evaluate_budget_policy_by_id", return_value=denied):
        with patch.object(gateway_router, "create_audit_event"):
            with pytest.raises(HTTPException) as exc:
                gateway_router._enforce_virtual_key_budget(
                    db,
                    key=key,
                    owner_scope="actor:a1",
                    actor_id="a1",
                    trace_id="trace-budget-deny",
                )
    assert exc.value.status_code == 403
    assert exc.value.detail["error_code"] == "VIRTUAL_KEY_BUDGET_DENIED"


def test_resolve_prompt_registry_for_chat_renders_variables():
    from app.services.orchestration_llm_gateway import resolve_prompt_registry_for_chat

    db = MagicMock()
    item = SimpleNamespace(
        prompt_registry_id="p-1",
        name="support",
        prompt_text="Hello {{name}}, ticket {{ticket}}",
    )
    db.query.return_value.filter_by.return_value.first.return_value = item
    text, meta = resolve_prompt_registry_for_chat(
        db,
        prompt_id="p-1",
        variables={"name": "Ada", "ticket": "42"},
    )
    assert text == "Hello Ada, ticket 42"
    assert meta["prompt_registry_id"] == "p-1"


def test_observability_cost_user_properties_parser():
    from app.routers import observability as observability_router

    parsed = observability_router._parse_cost_user_properties('{"user":"u1","plan":"pro"}')
    assert parsed["user"] == "u1"
    assert parsed["plan"] == "pro"
    assert observability_router._parse_cost_user_properties("not-json") is None


def test_enforce_virtual_key_rate_limit_denies_rpm():
    db = MagicMock()
    key = SimpleNamespace(key_id="vk-rl", rate_limit_policy_id="rl-1", budget_policy_id="default")
    budget = SimpleNamespace(
        budget_policy_id="rl-1",
        status="active",
        rate_limit_rpm=2,
        rate_limit_tpm=None,
    )
    db.query.return_value.filter_by.return_value.first.return_value = budget
    with patch.object(gateway_router, "_count_owner_scope_requests_last_minute", return_value=2):
        with patch.object(gateway_router, "_sum_owner_scope_tokens_last_minute", return_value=0):
            with patch.object(gateway_router, "create_audit_event"):
                with pytest.raises(HTTPException) as exc:
                    gateway_router._enforce_virtual_key_rate_limit(
                        db,
                        key=key,
                        owner_scope="actor:a1",
                        actor_id="a1",
                        trace_id="trace-rl",
                        projected_input_tokens=10,
                    )
    assert exc.value.status_code == 429
    assert exc.value.detail["error_code"] == "VIRTUAL_KEY_RATE_LIMIT_DENIED"


def test_merge_helicone_session_path_and_name():
    payload = SimpleNamespace(
        user=None,
        properties=None,
        user_properties=None,
        session_id="sess-9",
        session_path="/support/chat",
        session_name="Support chat",
    )
    merged = gateway_router._merge_helicone_request_properties(payload)
    assert merged["session_id"] == "sess-9"
    assert merged["session_path"] == "/support/chat"
    assert merged["session_name"] == "Support chat"


def test_record_route_traffic_mirrors_samples_and_skips_primary():
    db = MagicMock()
    route = SimpleNamespace(
        route_policy_id="route-1",
        fallback_policy=json.dumps(
            {
                "traffic_mirroring": {
                    "enabled": True,
                    "tenant_id": "t1",
                    "mirror_targets": [
                        {"provider_id": "primary", "sample_percent": 100, "mode": "shadow"},
                        {"provider_id": "shadow-a", "sample_percent": 100, "mode": "shadow"},
                    ],
                }
            }
        ),
    )
    with patch.object(gateway_router, "create_audit_event"):
        recorded = gateway_router._record_route_traffic_mirrors(
            db,
            route=route,
            tenant_id="t1",
            environment="dev",
            request_tag=None,
            request_id="req-1",
            trace_id="trace-1",
            primary_provider_id="primary",
            actor_id="a1",
        )
    assert len(recorded) == 1
    assert recorded[0]["provider_id"] == "shadow-a"
    assert recorded[0]["outcome"] == "mirrored_simulated"
    assert db.add.called


def test_record_route_traffic_mirrors_live_executor_and_error_isolation():
    db = MagicMock()
    route = SimpleNamespace(
        route_policy_id="route-2",
        fallback_policy=json.dumps(
            {
                "traffic_mirroring": {
                    "enabled": True,
                    "tenant_id": "t1",
                    "mirror_targets": [
                        {"provider_id": "shadow-a", "sample_percent": 100, "mode": "shadow"},
                        {"provider_id": "shadow-b", "sample_percent": 100, "mode": "shadow"},
                    ],
                }
            }
        ),
    )

    def _live(provider_id: str) -> str:
        if provider_id == "shadow-a":
            raise RuntimeError("upstream down")
        return "mirrored_live"

    with patch.object(gateway_router, "create_audit_event"):
        recorded = gateway_router._record_route_traffic_mirrors(
            db,
            route=route,
            tenant_id="t1",
            environment="dev",
            request_tag=None,
            request_id="req-2",
            trace_id="trace-2",
            primary_provider_id="primary",
            actor_id="a1",
            live_executor=_live,
            max_live_attempts=1,
        )
    assert recorded[0]["outcome"] == "mirrored_error"
    assert recorded[1]["outcome"] == "mirrored_simulated"
    assert recorded[0].get("deferred_live") is False
    assert recorded[1].get("deferred_live") is False


def test_record_route_traffic_mirrors_defers_extra_live_attempts():
    db = MagicMock()
    route = SimpleNamespace(
        route_policy_id="route-3",
        fallback_policy=json.dumps(
            {
                "traffic_mirroring": {
                    "enabled": True,
                    "tenant_id": "t1",
                    "max_live_attempts": 3,
                    "mirror_targets": [
                        {"provider_id": "shadow-a", "sample_percent": 100, "mode": "shadow"},
                        {"provider_id": "shadow-b", "sample_percent": 100, "mode": "shadow"},
                        {"provider_id": "shadow-c", "sample_percent": 100, "mode": "shadow"},
                    ],
                }
            }
        ),
    )
    calls = []

    def _live(provider_id: str) -> str:
        calls.append(provider_id)
        return "mirrored_live"

    with patch.object(gateway_router, "create_audit_event"):
        recorded = gateway_router._record_route_traffic_mirrors(
            db,
            route=route,
            tenant_id="t1",
            environment="dev",
            request_tag=None,
            request_id="req-3",
            trace_id="trace-3",
            primary_provider_id="primary",
            actor_id="a1",
            live_executor=_live,
            sync_live_cap=1,
        )
    assert calls == ["shadow-a"]
    assert recorded[0]["outcome"] == "mirrored_live"
    assert recorded[0].get("deferred_live") is False
    assert recorded[1].get("deferred_live") is True
    assert recorded[2].get("deferred_live") is True
    assert gateway_router._traffic_mirroring_max_live_attempts({"max_live_attempts": 9}) == 3


def test_merge_helicone_metadata_into_properties():
    payload = SimpleNamespace(
        user=None,
        properties={"plan": "pro"},
        user_properties=None,
        session_id=None,
        session_path=None,
        session_name=None,
        metadata={"feature": "assist", "plan": "should-not-clobber"},
    )
    merged = gateway_router._merge_helicone_request_properties(payload)
    assert merged["plan"] == "pro"
    assert merged["feature"] == "assist"


def test_pin_data_overrides_dry_run_stub_output():
    result = _execute_single_stub_node(
        {
            "id": "llm-1",
            "type": "llm_chat",
            "config": {"pin_data": {"message": "pinned hello", "score": 0.9}},
        },
        dry_run=True,
        trace_id="trace-pin",
    )
    assert result["status"] == "simulated"
    assert result["output"]["pinned"] is True
    assert result["output"]["message"] == "pinned hello"


def test_pin_data_ignored_when_not_dry_run():
    result = _execute_single_stub_node(
        {
            "id": "llm-1",
            "type": "llm_chat",
            "config": {"pin_data": {"message": "should not win"}},
        },
        dry_run=False,
        trace_id="trace-pin-live",
    )
    assert result["output"].get("pinned") is not True


def test_cost_track_spend_schema_accepts_properties():
    from app.schemas import CostTrackSpendRequest

    payload = CostTrackSpendRequest(
        request_id="req-1",
        session_id="sess-1",
        agent_id="agent-1",
        scope_type="agent",
        scope_id="agent-1",
        model_name="gpt-4o-mini",
        endpoint_family="chat.completions",
        cache_hit=True,
        user_properties={"user_id": "u-9", "feature": "assist"},
    )
    assert payload.cache_hit is True
    assert payload.user_properties["feature"] == "assist"


def test_set_fields_and_json_transform_stub_outputs():
    set_result = _execute_single_stub_node(
        {
            "id": "set-1",
            "type": "set_fields",
            "config": {"fields_json": '{"status":"open"}'},
        },
        dry_run=True,
        trace_id="trace-set",
    )
    assert set_result["status"] == "simulated"
    assert "fields" in set_result["output"]

    transform = _execute_single_stub_node(
        {
            "id": "xf-1",
            "type": "json_transform",
            "config": {"source_node_id": "set-1", "mapping_json": '{"title":"x"}'},
        },
        dry_run=True,
        trace_id="trace-xf",
    )
    assert transform["output"]["source_node_id"] == "set-1"

    slack = _execute_single_stub_node(
        {
            "id": "slack-1",
            "type": "slack_webhook",
            "config": {"webhook_url": "https://hooks.slack.com/services/T/B/X", "text_template": "hi"},
        },
        dry_run=True,
        trace_id="trace-slack",
    )
    assert slack["output"]["delivery_status"] == "simulated"


def test_error_branch_routes_instead_of_stopping():
    import json

    from app.services.orchestration_flows import _execute_flow_graph

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "llm-fail",
                    "type": "llm_chat",
                    "config": {
                        "model_id": "gpt-4o-mini",
                        "prompt_template": "x",
                        "error_branch": "recover-1",
                    },
                },
                {"id": "happy-path", "type": "wait_delay", "config": {"delay_seconds": 1}},
                {"id": "recover-1", "type": "set_fields", "config": {"fields_json": '{"recovered":true}'}},
            ],
            "edges": [
                {"source": "llm-fail", "target": "happy-path"},
                {"source": "llm-fail", "target": "recover-1", "kind": "error"},
            ],
        }
    )

    def executor(node, _outputs):
        if node["id"] == "llm-fail":
            return {
                "node_id": "llm-fail",
                "node_type": "llm_chat",
                "status": "failed",
                "output": {"error": "provider down"},
            }
        return {
            "node_id": node["id"],
            "node_type": node["type"],
            "status": "completed",
            "output": {"ok": True, "node": node["id"]},
        }

    status, steps, error = _execute_flow_graph(
        graph_json=graph,
        dry_run=False,
        trace_id="trace-error-branch",
        node_executor=executor,
        fail_on_node_error=True,
    )
    assert status == "completed"
    assert error is None
    failed = next(step for step in steps if step["node_id"] == "llm-fail")
    assert failed["status"] == "completed_with_errors"
    assert failed["output"].get("routed_on_error") is True
    assert any(step.get("node_id") == "recover-1" and step.get("status") == "completed" for step in steps)
    happy = next((step for step in steps if step.get("node_id") == "happy-path"), None)
    assert happy is None or happy.get("status") == "skipped"


def test_new_graph_node_types_are_catalogued():
    from app.services.orchestration_flows import GRAPH_NODE_TYPES, list_node_types

    for node_type in (
        "set_fields",
        "json_transform",
        "slack_webhook",
        "discord_webhook",
        "teams_webhook",
        "switch",
        "filter",
        "merge_data",
        "github_api",
        "gitlab_api",
        "bitbucket_api",
        "jira_api",
        "respond_to_webhook",
        "split_in_batches",
        "limit",
        "aggregate",
        "foreach_map",
        "linear_api",
        "notion_api",
        "sort",
        "dedupe",
        "json_parse",
        "date_time",
        "execute_subflow",
        "string_ops",
        "compare",
        "csv_parse",
        "static_data",
        "hubspot_api",
        "zendesk_api",
        "freshdesk_api",
        "math_ops",
        "wait_until",
        "uuid_gen",
        "salesforce_api",
        "servicenow_api",
        "hash_digest",
        "stop_and_error",
        "noop",
        "json_to_csv",
        "split_out",
        "pick_fields",
        "rename_keys",
        "boolean_logic",
        "airtable_api",
        "telegram_notify",
        "html_strip",
        "url_ops",
        "base64_ops",
        "coalesce",
        "omit_fields",
        "append_items",
        "graphql_request",
        "asana_api",
        "clickup_api",
        "intercom_api",
        "monday_api",
        "pipedrive_api",
        "shopify_api",
        "stripe_api",
        "box_api",
        "dropbox_api",
        "calendly_api",
        "microsoft_graph_api",
        "google_sheets_api",
        "google_drive_api",
        "google_calendar_api",
        "slack_api",
        "zoom_api",
        "twilio_api",
        "sendgrid_api",
        "freshservice_api",
        "okta_api",
        "auth0_api",
        "azure_devops_api",
        "snowflake_api",
        "databricks_api",
        "bigquery_api",
        "splunk_api",
        "elasticsearch_api",
        "redis_api",
        "mongodb_api",
        "postgres_api",
        "mysql_api",
        "s3_api",
        "pinecone_api",
        "weaviate_api",
        "qdrant_api",
        "supabase_api",
        "kafka_api",
        "milvus_api",
        "chroma_api",
        "neo4j_api",
        "rabbitmq_api",
        "opensearch_api",
        "clickhouse_api",
        "dynamodb_api",
        "nats_api",
        "cassandra_api",
        "couchbase_api",
        "influxdb_api",
        "firebase_api",
        "airbyte_api",
        "presto_api",
        "trino_api",
        "redshift_api",
        "athena_api",
        "pulsar_api",
        "scylladb_api",
        "sqs_api",
        "sns_api",
        "kinesis_api",
        "eventbridge_api",
        "lambda_api",
        "stepfunctions_api",
        "cloudwatch_api",
        "xray_api",
        "glue_api",
        "sagemaker_api",
        "bedrock_api",
        "comprehend_api",
        "textract_api",
        "rekognition_api",
        "translate_api",
        "polly_api",
        "transcribe_api",
        "lex_api",
        "ecs_api",
        "eks_api",
        "secretsmanager_api",
        "ssm_api",
        "cognito_api",
        "iam_api",
        "kms_api",
        "sts_api",
        "apigateway_api",
        "cloudformation_api",
        "rds_api",
        "elb_api",
        "cloudfront_api",
        "route53_api",
        "cloudtrail_api",
        "config_api",
        "guardduty_api",
        "securityhub_api",
        "inspector_api",
        "macie_api",
        "waf_api",
        "shield_api",
        "acm_api",
        "networkfirewall_api",
        "ecr_api",
        "efs_api",
        "detective_api",
        "accessanalyzer_api",
        "fargate_api",
        "batch_api",
        "elasticache_api",
        "memorydb_api",
        "emr_api",
        "firehose_api",
        "msk_api",
        "appsync_api",
        "amazon_mq_api",
        "neptune_api",
        "documentdb_api",
        "fsx_api",
        "kendra_api",
        "personalize_api",
        "forecast_api",
        "mediaconvert_api",
        "transfer_api",
        "datasync_api",
        "backup_api",
        "lightsail_api",
        "elasticbeanstalk_api",
        "workspaces_api",
        "appstream_api",
        "mediastore_api",
        "outposts_api",
        "storagegateway_api",
        "directconnect_api",
        "transitgateway_api",
        "ec2_api",
        "autoscaling_api",
        "organizations_api",
        "ram_api",
        "codebuild_api",
        "codepipeline_api",
        "codedeploy_api",
        "codecommit_api",
        "cloud9_api",
        "amplify_api",
        "fis_api",
        "resiliencehub_api",
        "wellarchitected_api",
        "support_api",
        "trustedadvisor_api",
        "controltower_api",
        "servicecatalog_api",
        "lakeformation_api",
        "ses_api",
        "pinpoint_api",
        "connect_api",
        "chime_api",
        "ivs_api",
        "gamelift_api",
        "braket_api",
        "qldb_api",
        "timestream_api",
        "appconfig_api",
        "grafana_api",
        "prometheus_api",
        "location_api",
        "emrserverless_api",
        "iot_api",
        "greengrass_api",
        "iotanalytics_api",
        "freertos_api",
        "datazone_api",
        "cleanrooms_api",
        "entityresolution_api",
        "supplychain_api",
        "amp_api",
        "managedgrafana_api",
        "opensearchserverless_api",
        "mwaa_api",
        "appflow_api",
        "databrew_api",
        "healthlake_api",
        "medicalimaging_api",
        "omics_api",
        "finspace_api",
        "lookoutmetrics_api",
        "lookoutvision_api",
        "evidently_api",
        "rum_api",
        "number_format",
        "regex_extract",
        "text_template",
        "timezone_convert",
        "item_exists",
        "flatten_json",
        "pagerduty_event",
        "opsgenie_alert",
        "datadog_event",
        "sentry_event",
        "statuspage_incident",
        "mattermost_webhook",
        "google_chat_webhook",
        "confluence_api",
        "trello_api",
        "json_stringify",
        "type_of",
        "xml_parse",
        "unflatten_json",
        "chunk_text",
        "form_urlencoded",
        "deep_merge",
        "jwt_decode",
        "html_extract",
        "split_text",
        "json_query",
        "compress",
        "random",
        "hmac_verify",
        "xml_stringify",
        "object_diff",
        "html_to_markdown",
        "markdown_to_html",
        "array_ops",
        "compact_object",
    ):
        assert node_type in GRAPH_NODE_TYPES
        assert any(item["type"] == node_type for item in list_node_types())


def test_switch_routes_matching_case():
    import json

    from app.services.orchestration_flows import _execute_flow_graph

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "sw-1",
                    "type": "switch",
                    "config": {
                        "source_node_id": "upstream",
                        "json_path": "$.status",
                        "cases_json": json.dumps(
                            [
                                {"value": "approved", "branch": "node-ok"},
                                {"value": "denied", "branch": "node-deny"},
                            ]
                        ),
                        "default_branch": "node-other",
                    },
                },
                {"id": "node-ok", "type": "wait_delay", "config": {"delay_seconds": 1}},
                {"id": "node-deny", "type": "wait_delay", "config": {"delay_seconds": 1}},
                {"id": "node-other", "type": "wait_delay", "config": {"delay_seconds": 1}},
            ],
            "edges": [
                {"source": "sw-1", "target": "node-ok", "kind": "case"},
                {"source": "sw-1", "target": "node-deny", "kind": "case"},
                {"source": "sw-1", "target": "node-other", "kind": "default"},
            ],
        }
    )

    def executor(node, outputs):
        if node["id"] == "sw-1":
            from app.services.orchestration_flows import evaluate_switch

            result = evaluate_switch(node["config"], {"upstream": {"status": "approved"}})
            return {
                "node_id": "sw-1",
                "node_type": "switch",
                "status": "completed",
                "output": {"live": True, **result},
            }
        return {
            "node_id": node["id"],
            "node_type": node["type"],
            "status": "completed",
            "output": {"ok": True},
        }

    status, steps, error = _execute_flow_graph(
        graph_json=graph,
        dry_run=False,
        trace_id="trace-switch",
        node_executor=executor,
        fail_on_node_error=True,
    )
    assert status == "completed"
    assert error is None
    assert any(step.get("node_id") == "node-ok" and step.get("status") == "completed" for step in steps)
    deny = next((step for step in steps if step.get("node_id") == "node-deny"), None)
    other = next((step for step in steps if step.get("node_id") == "node-other"), None)
    assert deny is None or deny.get("status") == "skipped"
    assert other is None or other.get("status") == "skipped"


def test_filter_and_merge_helpers():
    from app.services.orchestration_flows import evaluate_filter, merge_step_outputs

    filtered = evaluate_filter(
        {
            "source_node_id": "http-1",
            "items_path": "$.items",
            "item_json_path": "$.status",
            "operator": "==",
            "compare_value": "open",
        },
        {"http-1": {"items": [{"status": "open"}, {"status": "closed"}, {"status": "open"}]}},
    )
    assert filtered["count"] == 2
    assert filtered["input_count"] == 3

    merged = merge_step_outputs(
        {"source_a_node_id": "a", "source_b_node_id": "b", "merge_mode": "shallow"},
        {"a": {"x": 1, "y": 2}, "b": {"y": 9, "z": 3}},
    )
    assert merged["merged"]["x"] == 1
    assert merged["merged"]["y"] == 9
    assert merged["merged"]["z"] == 3


def test_discord_teams_stub_outputs():
    discord = _execute_single_stub_node(
        {
            "id": "d-1",
            "type": "discord_webhook",
            "config": {"webhook_url": "https://discord.com/api/webhooks/1/2", "content_template": "hi"},
        },
        dry_run=True,
        trace_id="trace-discord",
    )
    assert discord["output"]["delivery_status"] == "simulated"

    teams = _execute_single_stub_node(
        {
            "id": "t-1",
            "type": "teams_webhook",
            "config": {"webhook_url": "https://outlook.office.com/webhook/x", "text_template": "hi"},
        },
        dry_run=True,
        trace_id="trace-teams",
    )
    assert teams["output"]["delivery_status"] == "simulated"


def test_split_in_batches_and_webhook_response_helpers():
    from app.services.orchestration_flows import (
        build_preset_api_url,
        evaluate_split_in_batches,
        extract_webhook_response,
        serialize_run,
    )

    split = evaluate_split_in_batches(
        {
            "source_node_id": "src",
            "items_path": "$.items",
            "batch_size": 2,
            "batch_index": 1,
        },
        {"src": {"items": [1, 2, 3, 4, 5]}},
    )
    assert split["items"] == [3, 4]
    assert split["has_more"] is True
    assert split["next_batch_index"] == 2
    assert split["total"] == 5

    url = build_preset_api_url(
        base_url="https://api.github.com",
        path_template="/repos/acme/app/issues",
        query_template="state=open",
    )
    assert url == "https://api.github.com/repos/acme/app/issues?state=open"

    steps = [
        {"node_id": "x", "node_type": "llm_chat", "output": {"message": "hi"}},
        {
            "node_id": "reply",
            "node_type": "respond_to_webhook",
            "output": {
                "webhook_response": True,
                "status_code": 201,
                "content_type": "application/json",
                "body": {"ok": True},
            },
        },
    ]
    response = extract_webhook_response(steps)
    assert response["status_code"] == 201
    assert response["body"] == {"ok": True}

    run = SimpleNamespace(
        run_id="r1",
        flow_id="f1",
        status="completed",
        started_at=None,
        finished_at=None,
        trace_id="t1",
        step_results_json=__import__("json").dumps(steps),
        error_summary=None,
        execution_state_json=None,
    )
    payload = serialize_run(run, flow_name="demo")
    assert payload["webhook_response"]["status_code"] == 201


def test_limit_aggregate_foreach_and_hmac():
    import hashlib
    import hmac as hmac_mod

    from app.services.orchestration_flows import (
        evaluate_aggregate,
        evaluate_foreach_map,
        evaluate_limit,
    )
    from app.services.orchestration_triggers import verify_webhook_hmac

    limited = evaluate_limit(
        {"source_node_id": "src", "items_path": "$.items", "limit": 2, "offset": 1},
        {"src": {"items": ["a", "b", "c", "d"]}},
    )
    assert limited["items"] == ["b", "c"]
    assert limited["total"] == 4

    counted = evaluate_aggregate(
        {"source_node_id": "src", "items_path": "$.items", "aggregate_mode": "count"},
        {"src": {"items": [1, 2, 3]}},
    )
    assert counted["value"] == 3

    mapped = evaluate_foreach_map(
        {
            "source_node_id": "src",
            "items_path": "$.items",
            "mapping_json": '{"label":"{{item.name}}","n":"{{item.n}}"}',
        },
        {"src": {"items": [{"name": "one", "n": 1}, {"name": "two", "n": 2}]}},
    )
    assert mapped["count"] == 2
    assert mapped["items"][0]["label"] == "one"

    secret = "super-secret"
    body = '{"hello":"world"}'
    digest = hmac_mod.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    db = MagicMock()
    binding = SimpleNamespace(binding_id="hmac-1")
    db.query.return_value.filter_by.return_value.first.return_value = binding
    with patch(
        "app.services.orchestration_triggers.resolve_binding_for_runtime",
        return_value=SimpleNamespace(secret_value=secret, api_key=None, access_token=None),
    ):
        verify_webhook_hmac(
            db,
            {"hmac_secret_binding_id": "hmac-1", "hmac_algorithm": "sha256"},
            signature_header=f"sha256={digest}",
            payload_text=body,
        )


def test_sort_dedupe_json_parse_date_time():
    from app.services.orchestration_flows import (
        evaluate_date_time,
        evaluate_dedupe,
        evaluate_json_parse,
        evaluate_sort,
    )

    sorted_items = evaluate_sort(
        {
            "source_node_id": "src",
            "items_path": "$.items",
            "sort_key_path": "$.n",
            "order": "desc",
        },
        {"src": {"items": [{"n": 1}, {"n": 3}, {"n": 2}]}},
    )
    assert [item["n"] for item in sorted_items["items"]] == [3, 2, 1]

    deduped = evaluate_dedupe(
        {"source_node_id": "src", "items_path": "$.items", "item_json_path": "$.id"},
        {"src": {"items": [{"id": "a"}, {"id": "a"}, {"id": "b"}]}},
    )
    assert deduped["count"] == 2
    assert deduped["removed"] == 1

    parsed = evaluate_json_parse(
        {"text_template": '{"ok": true, "n": 2}'},
        {},
    )
    assert parsed["parsed"]["ok"] is True

    now = evaluate_date_time({"operation": "now"}, {})
    assert "T" in now["iso"]
    added = evaluate_date_time(
        {
            "operation": "add",
            "value_template": "2026-07-31T00:00:00Z",
            "input_format": "%Y-%m-%dT%H:%M:%SZ",
            "output_format": "%Y-%m-%d",
            "amount": "1",
            "unit": "days",
        },
        {},
    )
    assert added["formatted"] == "2026-08-01"
    subtracted = evaluate_date_time(
        {
            "operation": "subtract",
            "value_template": "2026-08-01T00:00:00Z",
            "input_format": "%Y-%m-%dT%H:%M:%SZ",
            "output_format": "%Y-%m-%d",
            "amount": "1",
            "unit": "days",
        },
        {},
    )
    assert subtracted["formatted"] == "2026-07-31"
    diffed = evaluate_date_time(
        {
            "operation": "diff",
            "value_template": "2026-07-31T00:00:00Z",
            "compare_value_template": "2026-08-01T12:00:00Z",
            "input_format": "%Y-%m-%dT%H:%M:%SZ",
            "unit": "hours",
        },
        {},
    )
    assert diffed["delta"] == 36.0
    assert diffed["delta_seconds"] == 36 * 3600


def test_string_compare_csv_static_helpers():
    from app.services.orchestration_flows import (
        evaluate_compare,
        evaluate_csv_parse,
        evaluate_static_data,
        evaluate_string_ops,
    )

    trimmed = evaluate_string_ops(
        {"operation": "trim", "value_template": "  hello  "},
        {},
    )
    assert trimmed["result"] == "hello"

    replaced = evaluate_string_ops(
        {
            "operation": "replace",
            "value_template": "foo-bar",
            "search_template": "bar",
            "replace_template": "baz",
        },
        {},
    )
    assert replaced["result"] == "foo-baz"

    compared = evaluate_compare(
        {
            "source_a_node_id": "a",
            "json_path_a": "$.n",
            "operator": "gt",
            "compare_value": "2",
        },
        {"a": {"n": 5}},
    )
    assert compared["matched"] is True

    compared_alias = evaluate_compare(
        {
            "source_a_node_id": "a",
            "json_path_a": "$.n",
            "operator": ">",
            "compare_value": "10",
        },
        {"a": {"n": 5}},
    )
    assert compared_alias["matched"] is False

    csv_out = evaluate_csv_parse(
        {"text_template": "name,role\nAda,eng\nGrace,ops", "has_header": "true"},
        {},
    )
    assert csv_out["count"] == 2
    assert csv_out["items"][0]["name"] == "Ada"

    static = evaluate_static_data(
        {"fields_json": '{"status":"open","ticket":"{{input}}"}'},
        {},
        run_input="T-9",
    )
    assert static["fields"]["status"] == "open"
    assert static["data"]["ticket"] == "T-9"


def test_compare_true_false_branch_routing():
    import json

    from app.services.orchestration_flows import _execute_flow_graph

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "cmp-1",
                    "type": "compare",
                    "config": {
                        "source_a_node_id": "upstream",
                        "json_path_a": "$.score",
                        "operator": "gt",
                        "compare_value": "50",
                        "true_branch": "high-path",
                        "false_branch": "low-path",
                    },
                },
                {"id": "high-path", "type": "wait_delay", "config": {"delay_seconds": 1}},
                {"id": "low-path", "type": "wait_delay", "config": {"delay_seconds": 1}},
            ],
            "edges": [
                {"source": "cmp-1", "target": "high-path", "kind": "true"},
                {"source": "cmp-1", "target": "low-path", "kind": "false"},
            ],
        }
    )

    def executor(node, outputs):
        if node["id"] == "cmp-1":
            from app.services.orchestration_flows import evaluate_compare

            result = evaluate_compare(node["config"], {"upstream": {"score": 80}})
            return {
                "node_id": "cmp-1",
                "node_type": "compare",
                "status": "completed",
                "output": {"live": True, **result},
            }
        return {
            "node_id": node["id"],
            "node_type": node["type"],
            "status": "completed",
            "output": {"ok": True},
        }

    status, steps, error = _execute_flow_graph(
        graph_json=graph,
        dry_run=False,
        trace_id="trace-compare-branch",
        node_executor=executor,
        fail_on_node_error=True,
    )
    assert status == "completed"
    assert error is None
    assert any(step.get("node_id") == "high-path" and step.get("status") == "completed" for step in steps)
    low = next((step for step in steps if step.get("node_id") == "low-path"), None)
    assert low is None or low.get("status") == "skipped"


def test_math_wait_until_uuid_helpers():
    from datetime import datetime, timezone

    from app.services.orchestration_flows import (
        evaluate_math_ops,
        evaluate_uuid_gen,
        evaluate_wait_until,
    )

    added = evaluate_math_ops({"operation": "add", "a_template": "2", "b_template": "3"}, {})
    assert added["result"] == 5

    divided = evaluate_math_ops({"operation": "div", "a_template": "10", "b_template": "0"}, {})
    assert divided.get("error")

    now = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)
    future = evaluate_wait_until(
        {"until_template": "2026-07-31T12:00:10Z"},
        {},
        now=now,
    )
    assert future["wait_seconds"] == 10
    assert future["already_passed"] is False

    past = evaluate_wait_until(
        {"until_template": "2026-07-31T11:00:00Z"},
        {},
        now=now,
    )
    assert past["already_passed"] is True
    assert past["wait_seconds"] == 0

    ids = evaluate_uuid_gen({"count": 2, "prefix": "run-"})
    assert ids["count"] == 2
    assert ids["uuid"].startswith("run-")
    assert len(ids["uuids"]) == 2


def test_hubspot_zendesk_stubs():
    hubspot = _execute_single_stub_node(
        {
            "id": "hs-1",
            "type": "hubspot_api",
            "config": {"path_template": "/crm/v3/objects/contacts", "method": "GET", "auth_binding_id": "b1"},
        },
        dry_run=True,
        trace_id="trace-hs",
    )
    assert hubspot["output"]["provider"] == "hubspot"

    zendesk = _execute_single_stub_node(
        {
            "id": "zd-1",
            "type": "zendesk_api",
            "config": {
                "base_url": "https://example.zendesk.com",
                "path_template": "/api/v2/tickets.json",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-zd",
    )
    assert zendesk["output"]["provider"] == "zendesk"

    freshdesk = _execute_single_stub_node(
        {
            "id": "fd-1",
            "type": "freshdesk_api",
            "config": {
                "base_url": "https://example.freshdesk.com",
                "path_template": "/api/v2/tickets",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-fd",
    )
    assert freshdesk["output"]["provider"] == "freshdesk"


def test_n8n_data_logic_helpers():
    from app.services.orchestration_flows import (
        evaluate_boolean_logic,
        evaluate_hash_digest,
        evaluate_json_to_csv,
        evaluate_noop,
        evaluate_pick_fields,
        evaluate_rename_keys,
        evaluate_split_out,
        evaluate_stop_and_error,
    )

    digest = evaluate_hash_digest(
        {"algorithm": "sha256", "value_template": "hello"},
        {},
    )
    assert digest["digest"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    hmac_digest = evaluate_hash_digest(
        {"algorithm": "hmac-sha256", "value_template": "hello", "key_template": "secret"},
        {},
    )
    assert len(hmac_digest["digest"]) == 64

    stopped = evaluate_stop_and_error({"message_template": "bad {{input}}"}, {}, run_input="payload")
    assert stopped["stopped"] is True
    assert "payload" in stopped["message"]

    passthrough = evaluate_noop({"source_node_id": "a", "note": "x"}, {"a": {"n": 1}})
    assert passthrough["ok"] is True
    assert passthrough["data"]["n"] == 1

    csv_out = evaluate_json_to_csv(
        {"source_node_id": "src", "items_path": "$.items", "include_header": "true"},
        {"src": {"items": [{"name": "Ada"}, {"name": "Grace"}]}},
    )
    assert "Ada" in csv_out["csv"]
    assert csv_out["count"] == 2

    split = evaluate_split_out(
        {"source_node_id": "src", "items_path": "$.rows"},
        {"src": {"rows": [1, 2, 3]}},
    )
    assert split["items"] == [1, 2, 3]

    picked = evaluate_pick_fields(
        {"source_node_id": "src", "fields": "id,status"},
        {"src": {"id": "1", "status": "open", "secret": "x"}},
    )
    assert picked["fields"] == {"id": "1", "status": "open"}
    assert "secret" not in picked["fields"]

    renamed = evaluate_rename_keys(
        {"source_node_id": "src", "mapping_json": '{"id":"ticket_id"}'},
        {"src": {"id": "T-1", "status": "open"}},
    )
    assert renamed["fields"]["ticket_id"] == "T-1"
    assert "id" not in renamed["fields"]

    logic = evaluate_boolean_logic(
        {
            "combine": "and",
            "rules_json": [
                {"source_node_id": "a", "json_path": "$.ok", "operator": "==", "compare_value": "true"},
                {"source_node_id": "a", "json_path": "$.n", "operator": "gt", "compare_value": "1"},
            ],
        },
        {"a": {"ok": "true", "n": 5}},
    )
    assert logic["matched"] is True


def test_boolean_logic_branch_routing():
    import json

    from app.services.orchestration_flows import _execute_flow_graph

    graph = json.dumps(
        {
            "nodes": [
                {
                    "id": "bool-1",
                    "type": "boolean_logic",
                    "config": {
                        "combine": "or",
                        "rules_json": json.dumps(
                            [
                                {
                                    "source_node_id": "upstream",
                                    "json_path": "$.flag",
                                    "operator": "==",
                                    "compare_value": "yes",
                                }
                            ]
                        ),
                        "true_branch": "ok-path",
                        "false_branch": "bad-path",
                    },
                },
                {"id": "ok-path", "type": "noop", "config": {}},
                {"id": "bad-path", "type": "noop", "config": {}},
            ],
            "edges": [
                {"source": "bool-1", "target": "ok-path", "kind": "true"},
                {"source": "bool-1", "target": "bad-path", "kind": "false"},
            ],
        }
    )

    def executor(node, outputs):
        if node["id"] == "bool-1":
            from app.services.orchestration_flows import evaluate_boolean_logic

            result = evaluate_boolean_logic(node["config"], {"upstream": {"flag": "yes"}})
            return {
                "node_id": "bool-1",
                "node_type": "boolean_logic",
                "status": "completed",
                "output": result,
            }
        return {
            "node_id": node["id"],
            "node_type": node["type"],
            "status": "completed",
            "output": {"ok": True},
        }

    status, steps, error = _execute_flow_graph(
        graph_json=graph,
        dry_run=False,
        trace_id="trace-bool",
        node_executor=executor,
        fail_on_node_error=True,
    )
    assert status == "completed"
    assert error is None
    assert any(step.get("node_id") == "ok-path" and step.get("status") == "completed" for step in steps)


def test_html_url_base64_coalesce_append_helpers():
    from app.services.orchestration_flows import (
        evaluate_append_items,
        evaluate_base64_ops,
        evaluate_coalesce,
        evaluate_html_strip,
        evaluate_omit_fields,
        evaluate_url_ops,
    )

    stripped = evaluate_html_strip({"value_template": "<b>Hi&amp;there</b>"}, {})
    assert stripped["text"] == "Hi&there"

    encoded = evaluate_url_ops({"operation": "encode", "value_template": "a b"}, {})
    assert encoded["result"] == "a%20b"
    parsed = evaluate_url_ops({"operation": "parse_query", "value_template": "x=1&y=2"}, {})
    assert parsed["data"]["x"] == "1"

    b64 = evaluate_base64_ops({"operation": "encode", "value_template": "hi"}, {})
    assert b64["result"] == "aGk="
    decoded = evaluate_base64_ops({"operation": "decode", "value_template": "aGk="}, {})
    assert decoded["result"] == "hi"

    chosen = evaluate_coalesce(
        {"candidates_json": '["","{{input}}","fallback"]'},
        {},
        run_input="picked",
    )
    assert chosen["value"] == "picked"
    assert chosen["chosen_index"] == 1

    omitted = evaluate_omit_fields(
        {"source_node_id": "src", "fields": "secret,token"},
        {"src": {"id": "1", "secret": "x", "token": "y", "ok": True}},
    )
    assert omitted["fields"] == {"id": "1", "ok": True}

    appended = evaluate_append_items(
        {
            "source_a_node_id": "a",
            "source_b_node_id": "b",
            "items_path_a": "$.items",
            "items_path_b": "$.items",
        },
        {"a": {"items": [1, 2]}, "b": {"items": [3]}},
    )
    assert appended["items"] == [1, 2, 3]


def test_number_regex_tz_flatten_helpers():
    from app.services.orchestration_flows import (
        evaluate_flatten_json,
        evaluate_item_exists,
        evaluate_number_format,
        evaluate_regex_extract,
        evaluate_text_template,
        evaluate_timezone_convert,
    )

    formatted = evaluate_number_format(
        {"value_template": "12.345", "style": "decimal", "precision": "2"},
        {},
    )
    assert formatted["formatted"] == "12.35"

    extracted = evaluate_regex_extract(
        {"pattern": r"ticket-(\d+)", "value_template": "see ticket-42 please", "group": "1"},
        {},
    )
    assert extracted["first"] == "42"
    assert extracted["count"] == 1

    blocked = evaluate_regex_extract(
        {"pattern": r"(a+)+$", "value_template": "aaaa"},
        {},
    )
    assert blocked.get("error")

    text = evaluate_text_template(
        {"text_template": "Hello {{input}}"},
        {},
        run_input="world",
    )
    assert text["text"] == "Hello world"

    tz = evaluate_timezone_convert(
        {
            "value_template": "2026-07-31T12:00:00Z",
            "from_timezone": "UTC",
            "to_timezone": "UTC",
            "output_format": "%Y-%m-%d",
        },
        {},
    )
    assert tz["formatted"] == "2026-07-31"

    exists = evaluate_item_exists(
        {"source_node_id": "src", "json_path": "$.name"},
        {"src": {"name": "Ada"}},
    )
    assert exists["matched"] is True
    missing = evaluate_item_exists(
        {"source_node_id": "src", "json_path": "$.missing"},
        {"src": {"name": "Ada"}},
    )
    assert missing["matched"] is False

    flat = evaluate_flatten_json(
        {"source_node_id": "src", "json_path": "$"},
        {"src": {"a": {"b": 1}, "c": [2, 3]}},
    )
    assert flat["fields"]["a.b"] == 1
    assert flat["fields"]["c.0"] == 2


def test_json_stringify_and_type_of_helpers():
    from app.services.orchestration_flows import evaluate_json_stringify, evaluate_type_of

    stringified = evaluate_json_stringify(
        {"source_node_id": "src", "json_path": "$.data", "pretty": "false"},
        {"src": {"data": {"ok": True}}},
    )
    assert '"ok": true' in stringified["json"] or '"ok":true' in stringified["json"]

    typed = evaluate_type_of(
        {"source_node_id": "src", "json_path": "$.items"},
        {"src": {"items": [1, 2]}},
    )
    assert typed["type"] == "array"
    assert typed["is_empty"] is False


def test_xml_parse_and_unflatten_helpers():
    from app.services.orchestration_flows import evaluate_unflatten_json, evaluate_xml_parse

    parsed = evaluate_xml_parse(
        {"source_node_id": "src", "json_path": "$.xml"},
        {"src": {"xml": "<root><item id='1'>hi</item></root>"}},
    )
    assert parsed["tag"] == "root"
    assert parsed["data"]["children"]["item"]["text"] == "hi"
    assert "error" not in parsed or parsed.get("error") is None

    rejected = evaluate_xml_parse(
        {"source_node_id": "src", "json_path": "$"},
        {"src": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>"},
    )
    assert rejected.get("error")

    nested = evaluate_unflatten_json(
        {"source_node_id": "src", "json_path": "$.fields", "separator": "."},
        {"src": {"fields": {"a.b": 1, "a.c": 2}}},
    )
    assert nested["data"]["a"]["b"] == 1
    assert nested["data"]["a"]["c"] == 2


def test_chat_completions_schema_accepts_prompt_registry():
    from app.schemas import GatewayOpenAIChatCompletionsRequest

    payload = GatewayOpenAIChatCompletionsRequest(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hi"}],
        prompt_id="prompt-1",
        variables={"name": "Ada"},
        session_path="/support",
        session_name="Support",
    )
    assert payload.prompt_id == "prompt-1"
    assert payload.variables["name"] == "Ada"
    assert payload.session_path == "/support"


def test_resolve_route_policy_id_alias():
    from fastapi import HTTPException

    assert gateway_router._resolve_route_policy_id_alias(route_policy_id="rp-1", config_id=None) == "rp-1"
    assert gateway_router._resolve_route_policy_id_alias(route_policy_id=None, config_id="cfg-1") == "cfg-1"
    assert gateway_router._resolve_route_policy_id_alias(route_policy_id="same", config_id="same") == "same"
    with pytest.raises(HTTPException) as exc:
        gateway_router._resolve_route_policy_id_alias(route_policy_id="a", config_id="b")
    assert exc.value.status_code == 422


def test_resolve_virtual_key_id_alias():
    from fastapi import HTTPException

    assert gateway_router._resolve_virtual_key_id_alias(virtual_key_id="vk-1", guardrail_id=None) == "vk-1"
    assert gateway_router._resolve_virtual_key_id_alias(virtual_key_id=None, guardrail_id="g-1") == "g-1"
    assert gateway_router._resolve_virtual_key_id_alias(virtual_key_id="same", guardrail_id="same") == "same"
    with pytest.raises(HTTPException) as exc:
        gateway_router._resolve_virtual_key_id_alias(virtual_key_id="a", guardrail_id="b")
    assert exc.value.status_code == 422


def test_chat_and_responses_schema_accept_config_id():
    from app.schemas import GatewayOpenAIChatCompletionsRequest, GatewayOpenAIResponsesRequest

    chat = GatewayOpenAIChatCompletionsRequest(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hi"}],
        config_id="cfg-chat-1",
    )
    assert chat.config_id == "cfg-chat-1"
    responses = GatewayOpenAIResponsesRequest(
        model="gpt-4o-mini",
        input="hi",
        config_id="cfg-resp-1",
    )
    assert responses.config_id == "cfg-resp-1"


def test_chat_and_responses_schema_accept_guardrail_id():
    from app.schemas import GatewayOpenAIChatCompletionsRequest, GatewayOpenAIResponsesRequest

    chat = GatewayOpenAIChatCompletionsRequest(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "hi"}],
        guardrail_id="vk-guard-1",
    )
    assert chat.guardrail_id == "vk-guard-1"
    responses = GatewayOpenAIResponsesRequest(
        model="gpt-4o-mini",
        input="hi",
        guardrail_id="vk-guard-2",
    )
    assert responses.guardrail_id == "vk-guard-2"


def test_chunk_text_and_form_urlencoded_helpers():
    from app.services.orchestration_flows import evaluate_chunk_text, evaluate_form_urlencoded

    chunked = evaluate_chunk_text(
        {"source_node_id": "src", "json_path": "$.text", "chunk_size": 5, "overlap": 2},
        {"src": {"text": "abcdefghij"}},
    )
    assert chunked["count"] >= 2
    assert chunked["chunks"][0] == "abcde"

    encoded = evaluate_form_urlencoded(
        {"source_node_id": "src", "json_path": "$", "operation": "encode"},
        {"src": {"a": "1", "b": "two words"}},
    )
    assert "a=1" in encoded["text"]
    assert "b=two" in encoded["text"]

    decoded = evaluate_form_urlencoded(
        {"source_node_id": "src", "json_path": "$", "operation": "decode"},
        {"src": "x=1&y=2"},
    )
    assert decoded["data"]["x"] == "1"
    assert decoded["data"]["y"] == "2"


def test_deep_merge_and_jwt_decode_helpers():
    import base64

    from app.services.orchestration_flows import evaluate_deep_merge, evaluate_jwt_decode

    merged = evaluate_deep_merge(
        {
            "source_node_id": "left",
            "merge_source_node_id": "right",
            "json_path": "$",
            "merge_json_path": "$",
        },
        {"left": {"a": {"b": 1}, "keep": True}, "right": {"a": {"c": 2}, "extra": 3}},
    )
    assert merged["data"]["a"]["b"] == 1
    assert merged["data"]["a"]["c"] == 2
    assert merged["data"]["keep"] is True
    assert merged["data"]["extra"] == 3

    def _seg(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    token = f"{_seg({'alg': 'none', 'typ': 'JWT'})}.{_seg({'sub': 'user-9', 'iss': 'test'})}.sig"
    decoded = evaluate_jwt_decode(
        {"source_node_id": "src", "json_path": "$"},
        {"src": token},
    )
    assert decoded["verified"] is False
    assert decoded["payload"]["sub"] == "user-9"
    assert decoded["issuer"] == "test"


def test_html_extract_and_split_text_helpers():
    from app.services.orchestration_flows import evaluate_html_extract, evaluate_split_text

    extracted = evaluate_html_extract(
        {"source_node_id": "src", "json_path": "$", "mode": "both"},
        {
            "src": (
                "<html><body><script>bad()</script><p>Hello</p>"
                "<a href='https://example.com' title='Ex'>link</a></body></html>"
            )
        },
    )
    assert "Hello" in extracted["text"]
    assert "bad()" not in extracted["text"]
    assert extracted["link_count"] == 1
    assert extracted["links"][0]["href"] == "https://example.com"

    parts = evaluate_split_text(
        {"source_node_id": "src", "json_path": "$", "delimiter": "|", "max_parts": 3},
        {"src": "a|b|c|d"},
    )
    assert parts["parts"] == ["a", "b", "c|d"]
    assert parts["count"] == 3


def test_json_query_compress_and_random_helpers():
    from app.services.orchestration_flows import (
        evaluate_compress,
        evaluate_json_query,
        evaluate_random,
    )

    queried = evaluate_json_query(
        {"source_node_id": "src", "json_path": "$.user.id"},
        {"src": {"user": {"id": "u-9", "name": "Ada"}}},
    )
    assert queried["value"] == "u-9"
    assert queried["found"] is True

    compressed = evaluate_compress(
        {"source_node_id": "src", "json_path": "$", "operation": "compress", "algorithm": "zlib"},
        {"src": "hello-world"},
    )
    assert compressed.get("error") is None
    assert compressed["encoding"] == "base64"
    roundtrip = evaluate_compress(
        {
            "source_node_id": "src",
            "json_path": "$",
            "operation": "decompress",
            "algorithm": "zlib",
        },
        {"src": compressed["data"]},
    )
    assert roundtrip["text"] == "hello-world"

    rand_int = evaluate_random({"mode": "int", "min": 5, "max": 5}, {})
    assert rand_int["value"] == 5
    rand_uuid = evaluate_random({"mode": "uuid"}, {})
    assert isinstance(rand_uuid["value"], str) and len(rand_uuid["value"]) >= 32
    choice = evaluate_random(
        {"mode": "choice", "choices_json": '["alpha","beta"]'},
        {},
    )
    assert choice["value"] in {"alpha", "beta"}


def test_cost_feedback_score_sanitizer():
    from app.routers import cost as cost_router

    cleaned = cost_router._sanitize_feedback_scores(
        {"relevance": 0.91, "bad": float("nan"), "": 1, "x" * 80: 2}
    )
    assert cleaned["relevance"] == 0.91
    assert "bad" not in cleaned
    assert "" not in cleaned
    assert any(len(key) <= 64 for key in cleaned)


def test_feedback_fields_from_properties_and_cache_mode_normalize():
    from app.routers import cost as cost_router

    fields = cost_router._feedback_fields_from_properties(
        json.dumps(
            {
                "rating": 5,
                "scores": {"relevance": 0.8},
                "helicone_feedback": {"comment": "great"},
            }
        )
    )
    assert fields["has_feedback"] is True
    assert fields["rating"] == 5
    assert fields["scores"]["relevance"] == 0.8
    assert fields["comment"] == "great"
    assert cost_router._feedback_fields_from_properties("{}")["has_feedback"] is False


def test_merge_helicone_properties_can_skip_openai_metadata():
    payload = SimpleNamespace(
        properties={"team": "platform"},
        user_properties=None,
        user="u-9",
        session_id="sess-1",
        session_path="/chat/main",
        session_name="Main",
        metadata={"openai_only": "keep-upstream"},
    )
    with_meta = gateway_router._merge_helicone_request_properties(payload)
    assert with_meta["openai_only"] == "keep-upstream"
    assert with_meta["user_id"] == "u-9"
    without_meta = gateway_router._merge_helicone_request_properties(payload, include_metadata=False)
    assert "openai_only" not in without_meta
    assert without_meta["session_path"] == "/chat/main"
    assert without_meta["team"] == "platform"


def test_responses_request_schema_accepts_vk_and_helicone_fields():
    from app.schemas import GatewayOpenAIResponsesRequest

    req = GatewayOpenAIResponsesRequest(
        model="gpt-4o-mini",
        input="hello",
        virtual_key_id="vk-1",
        user="end-user-1",
        properties={"env": "dev"},
        session_path="/responses/demo",
        session_name="demo",
        cache_mode="bypass",
        metadata={"upstream": "ok"},
        prompt_id="prompt-resp-1",
        variables={"name": "Ada"},
    )
    assert req.virtual_key_id == "vk-1"
    assert req.cache_mode == "bypass"
    assert req.user == "end-user-1"
    assert req.metadata["upstream"] == "ok"
    assert req.prompt_id == "prompt-resp-1"
    assert req.variables["name"] == "Ada"


def test_select_route_candidates_accepts_responses_resource():
    db = MagicMock()
    route = SimpleNamespace(
        route_policy_id="rp-1",
        fallback_policy="{}",
        load_balancing_strategy="weighted",
        retry_policy="{}",
    )
    with patch.object(
        gateway_router,
        "_resolve_route_provider_configs",
        return_value=[
            {
                "group_id": "default",
                "priority_order": [
                    {"provider_id": "p1", "model_name": "gpt-4o-mini"},
                    {"provider_id": "p2", "model_name": "gpt-4o"},
                ],
                "max_fallback_hops": 1,
                "health_check_enabled": False,
            }
        ],
    ), patch.object(
        gateway_router,
        "_apply_canary_rollout_to_provider_configs",
        side_effect=lambda configs, **kwargs: (configs, None, None, "canary_control"),
    ), patch.object(gateway_router, "_build_provider_health_map", return_value={}), patch.object(
        gateway_router, "_parse_retry_error_policies", return_value={}
    ), patch.object(gateway_router, "_load_retry_cooldown_registry", return_value={}), patch.object(
        gateway_router, "get_runtime_config_int", return_value=2
    ):
        candidates, meta = gateway_router._select_chat_route_provider_candidates(
            db,
            route=route,
            tenant_id="t1",
            request_tag=None,
            default_model_name="gpt-4o-mini",
            resource="responses",
        )
    assert len(candidates) >= 1
    assert candidates[0]["provider_id"] == "p1"
    assert meta.get("canary_routing_decision") == "canary_control"


def test_session_name_from_properties_helper():
    from app.routers import cost as cost_router

    assert cost_router._session_name_from_properties('{"session_name":"Demo Chat"}') == "Demo Chat"
    assert cost_router._session_name_from_properties("{}") == ""


def test_property_value_from_json_helper():
    from app.routers import cost as cost_router

    assert cost_router._property_value_from_json('{"team":"platform","env":"dev"}', "team") == "platform"
    assert cost_router._property_value_from_json('{"team":"platform"}', "missing") == ""
    assert cost_router._property_value_from_json("not-json", "team") == ""


def test_virtual_key_expiry_enforcement():
    from datetime import datetime, timedelta

    db = MagicMock()
    key = SimpleNamespace(key_id="vk-exp", expires_at=datetime.utcnow() - timedelta(minutes=1))
    with patch.object(gateway_router, "create_audit_event"):
        with pytest.raises(HTTPException) as exc:
            gateway_router._enforce_virtual_key_expiry(
                db,
                key=key,
                actor_id="a1",
                trace_id="trace-exp",
            )
    assert exc.value.status_code == 403
    detail = exc.value.detail
    assert isinstance(detail, dict)
    assert detail.get("error_code") == "VIRTUAL_KEY_EXPIRED"

    key_ok = SimpleNamespace(key_id="vk-ok", expires_at=datetime.utcnow() + timedelta(hours=1))
    with patch.object(gateway_router, "create_audit_event"):
        gateway_router._enforce_virtual_key_expiry(
            db,
            key=key_ok,
            actor_id="a1",
            trace_id="trace-ok",
        )
    key_none = SimpleNamespace(key_id="vk-none", expires_at=None)
    gateway_router._enforce_virtual_key_expiry(db, key=key_none, actor_id="a1", trace_id="trace-none")


def test_user_id_from_properties_helper():
    from app.routers import cost as cost_router

    assert cost_router._user_id_from_properties('{"user":"u-42"}') == "u-42"
    assert cost_router._user_id_from_properties('{"user_id":"uid-9"}') == "uid-9"
    assert cost_router._user_id_from_properties("{}") == ""


def test_hmac_verify_xml_stringify_object_diff_helpers():
    import hashlib
    import hmac as hmac_mod

    from app.services.orchestration_flows import (
        evaluate_hmac_verify,
        evaluate_object_diff,
        evaluate_xml_stringify,
    )

    payload = "body-1"
    key = "secret"
    digest = hmac_mod.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    verified = evaluate_hmac_verify(
        {
            "value_template": payload,
            "key_template": key,
            "expected_template": f"sha256={digest}",
            "algorithm": "sha256",
            "encoding": "hex",
        },
        {},
    )
    assert verified["verified"] is True
    assert verified["matched"] is True

    xml_out = evaluate_xml_stringify(
        {"source_node_id": "src", "json_path": "$", "root_tag": "root"},
        {"src": {"ok": True, "n": 1}},
    )
    assert xml_out.get("error") is None
    assert "<root>" in xml_out["xml"]
    assert "<ok>True</ok>" in xml_out["xml"] or "<ok>true</ok>" in xml_out["xml"].lower()

    diff = evaluate_object_diff(
        {
            "source_node_id": "a",
            "compare_source_node_id": "b",
            "json_path": "$",
            "compare_json_path": "$",
        },
        {"a": {"x": 1, "y": 2}, "b": {"x": 1, "y": 3, "z": 4}},
    )
    assert diff["equal"] is False
    assert diff["changed"] >= 1
    assert diff["added"] >= 1
    ops = {item["op"] for item in diff["changes"]}
    assert "changed" in ops
    assert "added" in ops


def test_html_to_markdown_array_ops_compact_object_helpers():
    from app.services.orchestration_flows import (
        evaluate_array_ops,
        evaluate_compact_object,
        evaluate_html_to_markdown,
        evaluate_markdown_to_html,
    )

    md = evaluate_html_to_markdown(
        {"source_node_id": "src", "json_path": "$"},
        {
            "src": (
                "<html><body><script>bad()</script><h1>Title</h1>"
                "<p>Hello <strong>world</strong></p>"
                "<a href='https://example.com'>link</a></body></html>"
            )
        },
    )
    assert md.get("error") is None
    assert "# Title" in md["markdown"]
    assert "**world**" in md["markdown"]
    assert "[link](https://example.com)" in md["markdown"]
    assert "bad()" not in md["markdown"]

    html_out = evaluate_markdown_to_html(
        {"value_template": "# Hello\n\n- item **one**\n- [link](https://example.com)"},
        {},
    )
    assert "<h1>Hello</h1>" in html_out["html"]
    assert "<strong>one</strong>" in html_out["html"]
    assert 'href="https://example.com"' in html_out["html"]
    assert "<script>" not in html_out["html"]

    sliced = evaluate_array_ops(
        {"source_node_id": "src", "json_path": "$", "operation": "slice", "start": 1, "end": 3},
        {"src": [10, 20, 30, 40]},
    )
    assert sliced["items"] == [20, 30]
    uniq = evaluate_array_ops(
        {"source_node_id": "src", "json_path": "$", "operation": "unique"},
        {"src": [1, 1, 2, 2, 3]},
    )
    assert uniq["items"] == [1, 2, 3]

    compacted = evaluate_compact_object(
        {"source_node_id": "src", "json_path": "$"},
        {"src": {"a": 1, "b": None, "c": "", "d": {"e": None, "f": 2}, "g": []}},
    )
    assert compacted["data"]["a"] == 1
    assert "b" not in compacted["data"]
    assert "c" not in compacted["data"]
    assert compacted["data"]["d"]["f"] == 2
    assert "g" not in compacted["data"]


def test_cost_export_session_path_helper():
    from app.routers import cost as cost_router

    assert cost_router._session_path_from_properties('{"session_path":"/support/chat"}') == "/support/chat"
    assert cost_router._session_path_from_properties("not-json") == ""


def test_cost_session_path_tree_helpers():
    from app.routers import cost as cost_router

    assert cost_router._normalize_session_path("support/chat/") == "/support/chat"
    assert cost_router._session_path_prefixes("/support/chat/thread", 2) == ["/support", "/support/chat"]
    aggregates = {
        "/chat": {"spend_cents": 30, "event_count": 3, "sessions": {"s1", "s2"}},
        "/chat/main": {"spend_cents": 20, "event_count": 2, "sessions": {"s1"}},
        "/chat/other": {"spend_cents": 10, "event_count": 1, "sessions": {"s2"}},
        "/ops": {"spend_cents": 5, "event_count": 1, "sessions": {"s3"}},
    }
    tree = cost_router._build_session_path_tree(aggregates, max_depth=3, limit=10)
    assert [node.path for node in tree] == ["/chat", "/ops"]
    assert tree[0].session_count == 2
    assert [child.path for child in tree[0].children] == ["/chat/main", "/chat/other"]


def test_cost_property_stats_helper():
    from app.routers import cost as cost_router

    assert (
        cost_router._flat_property_value_for_stats('{"team":"platform","scores":{"a":1}}', "team")
        == "platform"
    )
    assert cost_router._flat_property_value_for_stats('{"team":"platform"}', "scores") == ""
    assert cost_router._flat_property_value_for_stats('{"nested":{"a":1}}', "nested") == ""
    assert cost_router._flat_property_value_for_stats('{"flag":true}', "flag") == "true"


def test_cost_property_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "platform", 50),
        (datetime(2026, 8, 1, 10, 45, 0), "platform", 25),
        (datetime(2026, 8, 1, 11, 5, 0), "ops", 10),
        (datetime(2026, 8, 1, 11, 20, 0), "platform", 5),
    ]
    series = cost_router._build_property_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_values=2,
    )
    assert [item.value for item in series] == ["platform", "ops"]
    assert series[0].spend_cents == 80
    assert series[0].points[0].spend_cents == 75
    assert series[0].points[1].spend_cents == 5


def test_cost_model_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "gpt-4o-mini", 50, 100, 20),
        (datetime(2026, 8, 1, 10, 45, 0), "gpt-4o-mini", 25, 50, 10),
        (datetime(2026, 8, 1, 11, 5, 0), "gpt-4o", 10, 40, 10),
        (datetime(2026, 8, 1, 11, 20, 0), "gpt-4o-mini", 5, 10, 5),
    ]
    series = cost_router._build_model_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_models=2,
    )
    assert [item.model_name for item in series] == ["gpt-4o-mini", "gpt-4o"]
    assert series[0].spend_cents == 80
    assert series[0].total_tokens == 195
    assert series[0].points[0].spend_cents == 75
    assert series[0].points[1].spend_cents == 5


def test_cost_tag_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "billing.batch", 50, 120),
        (datetime(2026, 8, 1, 10, 45, 0), "billing.batch", 25, 60),
        (datetime(2026, 8, 1, 11, 5, 0), "ops.alert", 10, 40),
        (datetime(2026, 8, 1, 11, 20, 0), "billing.batch", 5, 15),
    ]
    series = cost_router._build_tag_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_tags=2,
    )
    assert [item.request_tag for item in series] == ["billing.batch", "ops.alert"]
    assert series[0].spend_cents == 80
    assert series[0].total_tokens == 195
    assert series[0].points[0].spend_cents == 75
    assert series[0].points[1].spend_cents == 5


def test_cost_endpoint_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "chat.completions", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "chat.completions", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "responses", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "chat.completions", 5, 20),
    ]
    series = cost_router._build_endpoint_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_endpoints=2,
    )
    assert [item.endpoint_family for item in series] == ["chat.completions", "responses"]
    assert series[0].spend_cents == 65
    assert series[0].total_tokens == 320
    assert series[0].points[0].spend_cents == 60
    assert series[0].points[1].spend_cents == 5


def test_cost_agent_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "agent-a", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "agent-a", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "agent-b", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "agent-a", 5, 20),
    ]
    series = cost_router._build_agent_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_agents=2,
    )
    assert [item.agent_id for item in series] == ["agent-a", "agent-b"]
    assert series[0].spend_cents == 65
    assert series[0].total_tokens == 320
    assert series[0].points[0].spend_cents == 60
    assert series[0].points[1].spend_cents == 5


def test_cost_environment_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "prod", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "prod", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "dev", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "prod", 5, 20),
    ]
    series = cost_router._build_environment_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_environments=2,
    )
    assert [item.environment for item in series] == ["prod", "dev"]
    assert series[0].spend_cents == 65
    assert series[0].total_tokens == 320
    assert series[0].points[0].spend_cents == 60
    assert series[0].points[1].spend_cents == 5


def test_cost_owner_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "team:platform", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "team:platform", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "user:alice", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "team:platform", 5, 20),
    ]
    series = cost_router._build_owner_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_owners=2,
    )
    assert [item.owner_scope for item in series] == ["team:platform", "user:alice"]
    assert series[0].spend_cents == 65
    assert series[0].total_tokens == 320
    assert series[0].points[0].spend_cents == 60
    assert series[0].points[1].spend_cents == 5


def test_cost_currency_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "USD", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "USD", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "EUR", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "USD", 5, 20),
    ]
    series = cost_router._build_currency_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_currencies=2,
    )
    assert [item.currency for item in series] == ["USD", "EUR"]
    assert series[0].spend_cents == 65
    assert series[0].total_tokens == 320
    assert series[0].points[0].spend_cents == 60
    assert series[0].points[1].spend_cents == 5


def test_cost_provider_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "openai", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "openai", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "anthropic", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "openai", 5, 20),
    ]
    series = cost_router._build_provider_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_providers=2,
    )
    assert [item.provider for item in series] == ["openai", "anthropic"]
    assert series[0].spend_cents == 65
    assert series[0].total_tokens == 320
    assert series[0].points[0].spend_cents == 60
    assert series[0].points[1].spend_cents == 5


def test_cost_team_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._team_from_owner_scope("team:platform") == "platform"
    assert cost_router._team_from_owner_scope("team/ops") == "ops"
    assert cost_router._team_from_owner_scope("user:alice") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "platform", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "platform", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "ops", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "platform", 5, 20),
    ]
    series = cost_router._build_team_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_teams=2,
    )
    assert [item.team for item in series] == ["platform", "ops"]
    assert series[0].spend_cents == 65
    assert series[0].total_tokens == 320
    assert series[0].points[0].spend_cents == 60
    assert series[0].points[1].spend_cents == 5


def test_cost_group_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._group_from_owner_scope("group:research") == "research"
    assert cost_router._group_from_owner_scope("group/ml") == "ml"
    assert cost_router._group_from_owner_scope("team:platform") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "research", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "research", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "ml", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "research", 5, 20),
    ]
    series = cost_router._build_group_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_groups=2,
    )
    assert [item.group for item in series] == ["research", "ml"]
    assert series[0].spend_cents == 65
    assert series[0].total_tokens == 320
    assert series[0].points[0].spend_cents == 60
    assert series[0].points[1].spend_cents == 5


def test_cost_project_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._project_from_properties('{"project":"alpha"}') == "alpha"
    assert cost_router._project_from_properties('{"Helicone-Project-Id":"beta"}') == "beta"
    assert cost_router._project_from_properties('{"session_path":"/x"}') == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "alpha", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "alpha", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "beta", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "alpha", 5, 20),
    ]
    series = cost_router._build_project_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_projects=2,
    )
    assert [item.project for item in series] == ["alpha", "beta"]
    assert series[0].spend_cents == 65
    assert series[0].total_tokens == 320
    assert series[0].points[0].spend_cents == 60
    assert series[0].points[1].spend_cents == 5


def test_cost_feedback_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "has_feedback", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "no_feedback", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "has_feedback", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "no_feedback", 5, 20),
    ]
    series = cost_router._build_feedback_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
    )
    assert [item.feedback_state for item in series] == ["has_feedback", "no_feedback"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_session_path_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "/checkout/pay", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "/search", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "/checkout/pay", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "/search", 5, 20),
    ]
    series = cost_router._build_session_path_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_paths=8,
    )
    assert [item.session_path for item in series] == ["/checkout/pay", "/search"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_session_name_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "checkout-flow", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "search-assist", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "checkout-flow", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "search-assist", 5, 20),
    ]
    series = cost_router._build_session_name_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_names=8,
    )
    assert [item.session_name for item in series] == ["checkout-flow", "search-assist"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_prompt_id_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "prm-checkout", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "prm-search", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "prm-checkout", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "prm-search", 5, 20),
    ]
    series = cost_router._build_prompt_id_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_prompts=8,
    )
    assert [item.prompt_id for item in series] == ["prm-checkout", "prm-search"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_application_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "checkout-app", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "search-app", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "checkout-app", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "search-app", 5, 20),
    ]
    series = cost_router._build_application_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_applications=8,
    )
    assert [item.application for item in series] == ["checkout-app", "search-app"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_customer_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "cust-acme", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "cust-globex", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "cust-acme", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "cust-globex", 5, 20),
    ]
    series = cost_router._build_customer_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_customers=8,
    )
    assert [item.customer for item in series] == ["cust-acme", "cust-globex"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_department_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "engineering", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "finance", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "engineering", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "finance", 5, 20),
    ]
    series = cost_router._build_department_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_departments=8,
    )
    assert [item.department for item in series] == ["engineering", "finance"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_feature_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "copilot", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "search", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "copilot", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "search", 5, 20),
    ]
    series = cost_router._build_feature_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_features=8,
    )
    assert [item.feature for item in series] == ["copilot", "search"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_region_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "us-east-1", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "eu-west-1", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "us-east-1", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "eu-west-1", 5, 20),
    ]
    series = cost_router._build_region_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_regions=8,
    )
    assert [item.region for item in series] == ["us-east-1", "eu-west-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_workspace_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "ws-alpha", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "ws-beta", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "ws-alpha", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "ws-beta", 5, 20),
    ]
    series = cost_router._build_workspace_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_workspaces=8,
    )
    assert [item.workspace for item in series] == ["ws-alpha", "ws-beta"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_product_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "sku-chat", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "sku-search", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "sku-chat", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "sku-search", 5, 20),
    ]
    series = cost_router._build_product_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_products=8,
    )
    assert [item.product for item in series] == ["sku-chat", "sku-search"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_service_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "billing-api", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "search-api", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "billing-api", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "search-api", 5, 20),
    ]
    series = cost_router._build_service_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_services=8,
    )
    assert [item.service for item in series] == ["billing-api", "search-api"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_tenant_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "tenant-acme", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "tenant-globex", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "tenant-acme", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "tenant-globex", 5, 20),
    ]
    series = cost_router._build_tenant_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_tenants=8,
    )
    assert [item.tenant for item in series] == ["tenant-acme", "tenant-globex"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_channel_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "web", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "mobile", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "web", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "mobile", 5, 20),
    ]
    series = cost_router._build_channel_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_channels=8,
    )
    assert [item.channel for item in series] == ["web", "mobile"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_campaign_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "spring-launch", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "retarget", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "spring-launch", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "retarget", 5, 20),
    ]
    series = cost_router._build_campaign_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_campaigns=8,
    )
    assert [item.campaign for item in series] == ["spring-launch", "retarget"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_brand_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "acme", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "globex", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "acme", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "globex", 5, 20),
    ]
    series = cost_router._build_brand_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_brands=8,
    )
    assert [item.brand for item in series] == ["acme", "globex"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_market_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "us-east", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "eu-west", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "us-east", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "eu-west", 5, 20),
    ]
    series = cost_router._build_market_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_markets=8,
    )
    assert [item.market for item in series] == ["us-east", "eu-west"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_segment_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "enterprise", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "smb", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "enterprise", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "smb", 5, 20),
    ]
    series = cost_router._build_segment_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_segments=8,
    )
    assert [item.segment for item in series] == ["enterprise", "smb"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_account_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "acct-a", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "acct-b", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "acct-a", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "acct-b", 5, 20),
    ]
    series = cost_router._build_account_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_accounts=8,
    )
    assert [item.account for item in series] == ["acct-a", "acct-b"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_org_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "acme-corp", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "globex", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "acme-corp", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "globex", 5, 20),
    ]
    series = cost_router._build_org_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_orgs=8,
    )
    assert [item.org for item in series] == ["acme-corp", "globex"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_cost_center_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "cc-100", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "cc-200", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "cc-100", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "cc-200", 5, 20),
    ]
    series = cost_router._build_cost_center_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_cost_centers=8,
    )
    assert [item.cost_center for item in series] == ["cc-100", "cc-200"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_business_unit_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "retail", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "platform", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "retail", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "platform", 5, 20),
    ]
    series = cost_router._build_business_unit_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_business_units=8,
    )
    assert [item.business_unit for item in series] == ["retail", "platform"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_site_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._site_from_properties('{"site":"us-east-1a"}') == "us-east-1a"
    assert cost_router._site_from_properties('{"location":"dc-12"}') == "dc-12"
    assert cost_router._site_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "us-east-1a", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "eu-west-1b", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "us-east-1a", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "eu-west-1b", 5, 20),
    ]
    series = cost_router._build_site_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_sites=8,
    )
    assert [item.site for item in series] == ["us-east-1a", "eu-west-1b"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_sku_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._sku_from_properties('{"sku":"sku-pro"}') == "sku-pro"
    assert cost_router._sku_from_properties('{"product_sku":"ent-1"}') == "ent-1"
    assert cost_router._sku_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "sku-pro", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "sku-basic", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "sku-pro", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "sku-basic", 5, 20),
    ]
    series = cost_router._build_sku_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_skus=8,
    )
    assert [item.sku for item in series] == ["sku-pro", "sku-basic"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_line_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._line_from_properties('{"line":"retail"}') == "retail"
    assert cost_router._line_from_properties('{"lob":"platform"}') == "platform"
    assert cost_router._line_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "retail", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "platform", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "retail", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "platform", 5, 20),
    ]
    series = cost_router._build_line_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_lines=8,
    )
    assert [item.line for item in series] == ["retail", "platform"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_tier_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._tier_from_properties('{"tier":"enterprise"}') == "enterprise"
    assert cost_router._tier_from_properties('{"plan_tier":"pro"}') == "pro"
    assert cost_router._tier_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "enterprise", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "pro", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "enterprise", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "pro", 5, 20),
    ]
    series = cost_router._build_tier_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_tiers=8,
    )
    assert [item.tier for item in series] == ["enterprise", "pro"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_stage_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._stage_from_properties('{"stage":"prod"}') == "prod"
    assert cost_router._stage_from_properties('{"pipeline_stage":"canary"}') == "canary"
    assert cost_router._stage_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "prod", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "canary", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "prod", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "canary", 5, 20),
    ]
    series = cost_router._build_stage_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_stages=8,
    )
    assert [item.stage for item in series] == ["prod", "canary"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_platform_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._platform_from_properties('{"platform":"web"}') == "web"
    assert cost_router._platform_from_properties('{"runtime_platform":"ios"}') == "ios"
    assert cost_router._platform_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "web", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "ios", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "web", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "ios", 5, 20),
    ]
    series = cost_router._build_platform_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_platforms=8,
    )
    assert [item.platform for item in series] == ["web", "ios"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_device_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._device_from_properties('{"device":"iphone"}') == "iphone"
    assert cost_router._device_from_properties('{"device_type":"desktop"}') == "desktop"
    assert cost_router._device_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "iphone", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "desktop", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "iphone", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "desktop", 5, 20),
    ]
    series = cost_router._build_device_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_devices=8,
    )
    assert [item.device for item in series] == ["iphone", "desktop"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_client_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._client_from_properties('{"client":"mobile-app"}') == "mobile-app"
    assert cost_router._client_from_properties('{"sdk_client":"python-sdk"}') == "python-sdk"
    assert cost_router._client_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "mobile-app", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "python-sdk", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "mobile-app", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "python-sdk", 5, 20),
    ]
    series = cost_router._build_client_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_clients=8,
    )
    assert [item.client for item in series] == ["mobile-app", "python-sdk"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_browser_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._browser_from_properties('{"browser":"chrome"}') == "chrome"
    assert cost_router._browser_from_properties('{"ua_browser":"safari"}') == "safari"
    assert cost_router._browser_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "chrome", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "safari", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "chrome", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "safari", 5, 20),
    ]
    series = cost_router._build_browser_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_browsers=8,
    )
    assert [item.browser for item in series] == ["chrome", "safari"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_release_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._release_from_properties('{"release":"1.2.3"}') == "1.2.3"
    assert cost_router._release_from_properties('{"version":"2026.08.01"}') == "2026.08.01"
    assert cost_router._release_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "1.2.3", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "1.2.2", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "1.2.3", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "1.2.2", 5, 20),
    ]
    series = cost_router._build_release_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_releases=8,
    )
    assert [item.release for item in series] == ["1.2.3", "1.2.2"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_locale_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._locale_from_properties('{"locale":"en-US"}') == "en-US"
    assert cost_router._locale_from_properties('{"lang":"fr"}') == "fr"
    assert cost_router._locale_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "en-US", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "fr-FR", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "en-US", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "fr-FR", 5, 20),
    ]
    series = cost_router._build_locale_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_locales=8,
    )
    assert [item.locale for item in series] == ["en-US", "fr-FR"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_country_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._country_from_properties('{"country":"US"}') == "US"
    assert cost_router._country_from_properties('{"geo_country":"CA"}') == "CA"
    assert cost_router._country_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "US", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "CA", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "US", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "CA", 5, 20),
    ]
    series = cost_router._build_country_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_countries=8,
    )
    assert [item.country for item in series] == ["US", "CA"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_os_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._os_from_properties('{"os":"ios"}') == "ios"
    assert cost_router._os_from_properties('{"operating_system":"android"}') == "android"
    assert cost_router._os_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "ios", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "android", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "ios", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "android", 5, 20),
    ]
    series = cost_router._build_os_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_os=8,
    )
    assert [item.os for item in series] == ["ios", "android"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_timezone_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._timezone_from_properties('{"timezone":"America/New_York"}') == "America/New_York"
    assert cost_router._timezone_from_properties('{"tz":"UTC"}') == "UTC"
    assert cost_router._timezone_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "America/New_York", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "UTC", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "America/New_York", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "UTC", 5, 20),
    ]
    series = cost_router._build_timezone_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_timezones=8,
    )
    assert [item.timezone for item in series] == ["America/New_York", "UTC"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_language_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._language_from_properties('{"language":"en"}') == "en"
    assert cost_router._language_from_properties('{"content_language":"es"}') == "es"
    assert cost_router._language_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "en", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "es", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "en", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "es", 5, 20),
    ]
    series = cost_router._build_language_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_languages=8,
    )
    assert [item.language for item in series] == ["en", "es"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_city_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._city_from_properties('{"city":"New York"}') == "New York"
    assert cost_router._city_from_properties('{"geo_city":"Toronto"}') == "Toronto"
    assert cost_router._city_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "New York", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "Toronto", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "New York", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "Toronto", 5, 20),
    ]
    series = cost_router._build_city_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_cities=8,
    )
    assert [item.city for item in series] == ["New York", "Toronto"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_continent_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._continent_from_properties('{"continent":"NA"}') == "NA"
    assert cost_router._continent_from_properties('{"geo_continent":"EU"}') == "EU"
    assert cost_router._continent_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "NA", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "EU", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "NA", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "EU", 5, 20),
    ]
    series = cost_router._build_continent_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_continents=8,
    )
    assert [item.continent for item in series] == ["NA", "EU"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_isp_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._isp_from_properties('{"isp":"Comcast"}') == "Comcast"
    assert cost_router._isp_from_properties('{"asn_org":"Cloudflare"}') == "Cloudflare"
    assert cost_router._isp_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "Comcast", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "Cloudflare", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "Comcast", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "Cloudflare", 5, 20),
    ]
    series = cost_router._build_isp_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_isps=8,
    )
    assert [item.isp for item in series] == ["Comcast", "Cloudflare"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_asn_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._asn_from_properties('{"asn":"AS7922"}') == "AS7922"
    assert cost_router._asn_from_properties('{"network_asn":"AS13335"}') == "AS13335"
    assert cost_router._asn_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "AS7922", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "AS13335", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "AS7922", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "AS13335", 5, 20),
    ]
    series = cost_router._build_asn_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_asns=8,
    )
    assert [item.asn for item in series] == ["AS7922", "AS13335"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_sdk_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._sdk_from_properties('{"sdk":"python"}') == "python"
    assert cost_router._sdk_from_properties('{"client_sdk":"javascript"}') == "javascript"
    assert cost_router._sdk_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "python", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "javascript", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "python", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "javascript", 5, 20),
    ]
    series = cost_router._build_sdk_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_sdks=8,
    )
    assert [item.sdk for item in series] == ["python", "javascript"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_framework_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._framework_from_properties('{"framework":"langchain"}') == "langchain"
    assert cost_router._framework_from_properties('{"ml_framework":"llamaindex"}') == "llamaindex"
    assert cost_router._framework_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "langchain", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "llamaindex", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "langchain", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "llamaindex", 5, 20),
    ]
    series = cost_router._build_framework_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_frameworks=8,
    )
    assert [item.framework for item in series] == ["langchain", "llamaindex"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_runtime_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._runtime_from_properties('{"runtime":"nodejs"}') == "nodejs"
    assert cost_router._runtime_from_properties('{"execution_runtime":"python3.11"}') == "python3.11"
    assert cost_router._runtime_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "nodejs", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "python3.11", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "nodejs", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "python3.11", 5, 20),
    ]
    series = cost_router._build_runtime_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_runtimes=8,
    )
    assert [item.runtime for item in series] == ["nodejs", "python3.11"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_library_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._library_from_properties('{"library":"openai"}') == "openai"
    assert cost_router._library_from_properties('{"client_library":"anthropic"}') == "anthropic"
    assert cost_router._library_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "openai", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "anthropic", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "openai", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "anthropic", 5, 20),
    ]
    series = cost_router._build_library_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_libraries=8,
    )
    assert [item.library for item in series] == ["openai", "anthropic"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_host_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._host_from_properties('{"host":"api-1"}') == "api-1"
    assert cost_router._host_from_properties('{"hostname":"edge-2"}') == "edge-2"
    assert cost_router._host_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "api-1", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "edge-2", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "api-1", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "edge-2", 5, 20),
    ]
    series = cost_router._build_host_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_hosts=8,
    )
    assert [item.host for item in series] == ["api-1", "edge-2"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_datacenter_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._datacenter_from_properties('{"datacenter":"iad1"}') == "iad1"
    assert cost_router._datacenter_from_properties('{"dc":"sfo1"}') == "sfo1"
    assert cost_router._datacenter_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "iad1", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "sfo1", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "iad1", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "sfo1", 5, 20),
    ]
    series = cost_router._build_datacenter_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_datacenters=8,
    )
    assert [item.datacenter for item in series] == ["iad1", "sfo1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_az_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._az_from_properties('{"az":"us-east-1a"}') == "us-east-1a"
    assert cost_router._az_from_properties('{"availability_zone":"us-west-2b"}') == "us-west-2b"
    assert cost_router._az_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "us-east-1a", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "us-west-2b", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "us-east-1a", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "us-west-2b", 5, 20),
    ]
    series = cost_router._build_az_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_azs=8,
    )
    assert [item.az for item in series] == ["us-east-1a", "us-west-2b"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_edge_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._edge_from_properties('{"edge":"iad"}') == "iad"
    assert cost_router._edge_from_properties('{"cdn_edge":"sfo"}') == "sfo"
    assert cost_router._edge_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "iad", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "sfo", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "iad", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "sfo", 5, 20),
    ]
    series = cost_router._build_edge_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_edges=8,
    )
    assert [item.edge for item in series] == ["iad", "sfo"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_colo_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._colo_from_properties('{"colo":"DFW"}') == "DFW"
    assert cost_router._colo_from_properties('{"colocation":"ORD"}') == "ORD"
    assert cost_router._colo_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "DFW", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "ORD", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "DFW", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "ORD", 5, 20),
    ]
    series = cost_router._build_colo_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_colos=8,
    )
    assert [item.colo for item in series] == ["DFW", "ORD"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_cluster_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._cluster_from_properties('{"cluster":"prod-a"}') == "prod-a"
    assert cost_router._cluster_from_properties('{"k8s_cluster":"staging"}') == "staging"
    assert cost_router._cluster_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "prod-a", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "staging", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "prod-a", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "staging", 5, 20),
    ]
    series = cost_router._build_cluster_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_clusters=8,
    )
    assert [item.cluster for item in series] == ["prod-a", "staging"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_pod_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._pod_from_properties('{"pod":"api-7"}') == "api-7"
    assert cost_router._pod_from_properties('{"k8s_pod":"worker-1"}') == "worker-1"
    assert cost_router._pod_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "api-7", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "worker-1", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "api-7", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "worker-1", 5, 20),
    ]
    series = cost_router._build_pod_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_pods=8,
    )
    assert [item.pod for item in series] == ["api-7", "worker-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_namespace_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._namespace_from_properties('{"namespace":"payments"}') == "payments"
    assert cost_router._namespace_from_properties('{"k8s_namespace":"default"}') == "default"
    assert cost_router._namespace_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "payments", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "default", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "payments", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "default", 5, 20),
    ]
    series = cost_router._build_namespace_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_namespaces=8,
    )
    assert [item.namespace for item in series] == ["payments", "default"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_node_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._node_from_properties('{"node":"ip-10-0-1-5"}') == "ip-10-0-1-5"
    assert cost_router._node_from_properties('{"k8s_node":"worker-a"}') == "worker-a"
    assert cost_router._node_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "ip-10-0-1-5", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "worker-a", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "ip-10-0-1-5", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "worker-a", 5, 20),
    ]
    series = cost_router._build_node_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_nodes=8,
    )
    assert [item.node for item in series] == ["ip-10-0-1-5", "worker-a"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_tool_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._tool_from_properties('{"tool":"search"}') == "search"
    assert cost_router._tool_from_properties('{"function_name":"lookup"}') == "lookup"
    assert cost_router._tool_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "search", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "lookup", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "search", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "lookup", 5, 20),
    ]
    series = cost_router._build_tool_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_tools=8,
    )
    assert [item.tool for item in series] == ["search", "lookup"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_workflow_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._workflow_from_properties('{"workflow":"intake"}') == "intake"
    assert cost_router._workflow_from_properties('{"flow_id":"flow-9"}') == "flow-9"
    assert cost_router._workflow_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "intake", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "flow-9", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "intake", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "flow-9", 5, 20),
    ]
    series = cost_router._build_workflow_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_workflows=8,
    )
    assert [item.workflow for item in series] == ["intake", "flow-9"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_experiment_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._experiment_from_properties('{"experiment":"pricing-v2"}') == "pricing-v2"
    assert cost_router._experiment_from_properties('{"ab_test":"ab-9"}') == "ab-9"
    assert cost_router._experiment_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "pricing-v2", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "ab-9", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "pricing-v2", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "ab-9", 5, 20),
    ]
    series = cost_router._build_experiment_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_experiments=8,
    )
    assert [item.experiment for item in series] == ["pricing-v2", "ab-9"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_variant_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._variant_from_properties('{"variant":"control"}') == "control"
    assert cost_router._variant_from_properties('{"treatment":"B"}') == "B"
    assert cost_router._variant_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "control", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "B", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "control", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "B", 5, 20),
    ]
    series = cost_router._build_variant_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_variants=8,
    )
    assert [item.variant for item in series] == ["control", "B"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_deployment_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._deployment_from_properties('{"deployment":"chat-west"}') == "chat-west"
    assert cost_router._deployment_from_properties('{"model_deployment":"md-1"}') == "md-1"
    assert cost_router._deployment_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "chat-west", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "md-1", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "chat-west", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "md-1", 5, 20),
    ]
    series = cost_router._build_deployment_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_deployments=8,
    )
    assert [item.deployment for item in series] == ["chat-west", "md-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_version_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._version_from_properties('{"version":"1.2.3"}') == "1.2.3"
    assert cost_router._version_from_properties('{"prompt_version":"v9"}') == "v9"
    assert cost_router._version_from_properties("{}") == ""

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "1.2.3", 40, 200),
        (datetime(2026, 8, 1, 10, 45, 0), "v9", 20, 100),
        (datetime(2026, 8, 1, 11, 5, 0), "1.2.3", 15, 80),
        (datetime(2026, 8, 1, 11, 20, 0), "v9", 5, 20),
    ]
    series = cost_router._build_version_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_versions=8,
    )
    assert [item.version for item in series] == ["1.2.3", "v9"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_canary_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._canary_from_properties('{"canary":"canary-10"}') == "canary-10"
    assert cost_router._canary_from_properties('{"rollout_canary":"rc-a"}') == "rc-a"
    assert cost_router._canary_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "canary-10", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "rc-a", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "canary-10", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "rc-a", 5, 20),
    ]
    series = cost_router._build_canary_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_canaries=8,
    )
    assert [item.canary for item in series] == ["canary-10", "rc-a"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_shadow_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._shadow_from_properties('{"shadow":"shadow-b"}') == "shadow-b"
    assert cost_router._shadow_from_properties('{"traffic_mirror":"mirror-1"}') == "mirror-1"
    assert cost_router._shadow_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "shadow-b", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "mirror-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "shadow-b", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "mirror-1", 5, 20),
    ]
    series = cost_router._build_shadow_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_shadows=8,
    )
    assert [item.shadow for item in series] == ["shadow-b", "mirror-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_rollout_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._rollout_from_properties('{"rollout":"rollout-blue"}') == "rollout-blue"
    assert cost_router._rollout_from_properties('{"rollout_id":"r-42"}') == "r-42"
    assert cost_router._rollout_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "rollout-blue", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "r-42", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "rollout-blue", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "r-42", 5, 20),
    ]
    series = cost_router._build_rollout_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_rollouts=8,
    )
    assert [item.rollout for item in series] == ["rollout-blue", "r-42"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_route_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._route_from_properties('{"route":"route-main"}') == "route-main"
    assert cost_router._route_from_properties('{"route_policy_id":"rp-1"}') == "rp-1"
    assert cost_router._route_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "route-main", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "rp-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "route-main", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "rp-1", 5, 20),
    ]
    series = cost_router._build_route_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_routes=8,
    )
    assert [item.route for item in series] == ["route-main", "rp-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15




def test_cost_batch_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._batch_from_properties('{"batch":"batch-nightly"}') == "batch-nightly"
    assert cost_router._batch_from_properties('{"batch_id":"b-9"}') == "b-9"
    assert cost_router._batch_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "batch-nightly", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "b-9", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "batch-nightly", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "b-9", 5, 20),
    ]
    series = cost_router._build_batch_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_batches=8,
    )
    assert [item.batch for item in series] == ["batch-nightly", "b-9"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_job_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._job_from_properties('{"job":"job-embed"}') == "job-embed"
    assert cost_router._job_from_properties('{"job_id":"j-3"}') == "j-3"
    assert cost_router._job_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "job-embed", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "j-3", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "job-embed", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "j-3", 5, 20),
    ]
    series = cost_router._build_job_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_jobs=8,
    )
    assert [item.job for item in series] == ["job-embed", "j-3"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15




def test_cost_queue_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._queue_from_properties('{"queue":"queue-ingest"}') == "queue-ingest"
    assert cost_router._queue_from_properties('{"sqs_queue":"sqs-a"}') == "sqs-a"
    assert cost_router._queue_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "queue-ingest", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "sqs-a", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "queue-ingest", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "sqs-a", 5, 20),
    ]
    series = cost_router._build_queue_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_queues=8,
    )
    assert [item.queue for item in series] == ["queue-ingest", "sqs-a"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_topic_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._topic_from_properties('{"topic":"topic-events"}') == "topic-events"
    assert cost_router._topic_from_properties('{"kafka_topic":"kt-1"}') == "kt-1"
    assert cost_router._topic_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "topic-events", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "kt-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "topic-events", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "kt-1", 5, 20),
    ]
    series = cost_router._build_topic_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_topics=8,
    )
    assert [item.topic for item in series] == ["topic-events", "kt-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15




def test_cost_pipeline_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._pipeline_from_properties('{"pipeline":"pipeline-etl"}') == "pipeline-etl"
    assert cost_router._pipeline_from_properties('{"data_pipeline":"dp-1"}') == "dp-1"
    assert cost_router._pipeline_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "pipeline-etl", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "dp-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "pipeline-etl", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "dp-1", 5, 20),
    ]
    series = cost_router._build_pipeline_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_pipelines=8,
    )
    assert [item.pipeline for item in series] == ["pipeline-etl", "dp-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_cost_run_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._run_from_properties('{"run":"run-42"}') == "run-42"
    assert cost_router._run_from_properties('{"pipeline_run":"pr-9"}') == "pr-9"
    assert cost_router._run_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "run-42", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "pr-9", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "run-42", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "pr-9", 5, 20),
    ]
    series = cost_router._build_run_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_runs=8,
    )
    assert [item.run for item in series] == ["run-42", "pr-9"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15




def test_cost_worker_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._worker_from_properties('{"worker":"worker-a"}') == "worker-a"
    assert cost_router._worker_from_properties('{"worker_pool":"pool-1"}') == "pool-1"
    assert cost_router._worker_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "worker-a", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "pool-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "worker-a", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "pool-1", 5, 20),
    ]
    series = cost_router._build_worker_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_workers=8,
    )
    assert [item.worker for item in series] == ["worker-a", "pool-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_slot_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._slot_from_properties('{"slot":"slot-7"}') == "slot-7"
    assert cost_router._slot_from_properties('{"capacity_slot":"cap-2"}') == "cap-2"
    assert cost_router._slot_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "slot-7", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "cap-2", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "slot-7", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "cap-2", 5, 20),
    ]
    series = cost_router._build_slot_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_slots=8,
    )
    assert [item.slot for item in series] == ["slot-7", "cap-2"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_task_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._task_from_properties('{"task":"task-embed"}') == "task-embed"
    assert cost_router._task_from_properties('{"workflow_task":"wt-1"}') == "wt-1"
    assert cost_router._task_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "task-embed", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "wt-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "task-embed", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "wt-1", 5, 20),
    ]
    series = cost_router._build_task_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_tasks=8,
    )
    assert [item.task for item in series] == ["task-embed", "wt-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_step_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._step_from_properties('{"step":"step-ingest"}') == "step-ingest"
    assert cost_router._step_from_properties('{"pipeline_step":"ps-3"}') == "ps-3"
    assert cost_router._step_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "step-ingest", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "ps-3", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "step-ingest", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "ps-3", 5, 20),
    ]
    series = cost_router._build_step_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_steps=8,
    )
    assert [item.step for item in series] == ["step-ingest", "ps-3"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_replica_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._replica_from_properties('{"replica":"replica-a"}') == "replica-a"
    assert cost_router._replica_from_properties('{"service_replica":"svc-r1"}') == "svc-r1"
    assert cost_router._replica_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "replica-a", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "svc-r1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "replica-a", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "svc-r1", 5, 20),
    ]
    series = cost_router._build_replica_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_replicas=8,
    )
    assert [item.replica for item in series] == ["replica-a", "svc-r1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_shard_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._shard_from_properties('{"shard":"shard-3"}') == "shard-3"
    assert cost_router._shard_from_properties('{"data_shard":"ds-2"}') == "ds-2"
    assert cost_router._shard_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "shard-3", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "ds-2", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "shard-3", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "ds-2", 5, 20),
    ]
    series = cost_router._build_shard_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_shards=8,
    )
    assert [item.shard for item in series] == ["shard-3", "ds-2"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_partition_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._partition_from_properties('{"partition":"part-0"}') == "part-0"
    assert cost_router._partition_from_properties('{"kafka_partition":"kp-1"}') == "kp-1"
    assert cost_router._partition_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "part-0", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "kp-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "part-0", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "kp-1", 5, 20),
    ]
    series = cost_router._build_partition_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_partitions=8,
    )
    assert [item.partition for item in series] == ["part-0", "kp-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_consumer_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._consumer_from_properties('{"consumer":"consumer-a"}') == "consumer-a"
    assert cost_router._consumer_from_properties('{"consumer_group":"cg-1"}') == "cg-1"
    assert cost_router._consumer_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "consumer-a", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "cg-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "consumer-a", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "cg-1", 5, 20),
    ]
    series = cost_router._build_consumer_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_consumers=8,
    )
    assert [item.consumer for item in series] == ["consumer-a", "cg-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_producer_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._producer_from_properties('{"producer":"producer-a"}') == "producer-a"
    assert cost_router._producer_from_properties('{"kafka_producer":"kp-prod"}') == "kp-prod"
    assert cost_router._producer_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "producer-a", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "kp-prod", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "producer-a", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "kp-prod", 5, 20),
    ]
    series = cost_router._build_producer_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_producers=8,
    )
    assert [item.producer for item in series] == ["producer-a", "kp-prod"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_gpu_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._gpu_from_properties('{"gpu":"gpu-0"}') == "gpu-0"
    assert cost_router._gpu_from_properties('{"accelerator_gpu":"acc-gpu-1"}') == "acc-gpu-1"
    assert cost_router._gpu_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "gpu-0", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "acc-gpu-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "gpu-0", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "acc-gpu-1", 5, 20),
    ]
    series = cost_router._build_gpu_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_gpus=8,
    )
    assert [item.gpu for item in series] == ["gpu-0", "acc-gpu-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_accelerator_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._accelerator_from_properties('{"accelerator":"accel-a"}') == "accel-a"
    assert cost_router._accelerator_from_properties('{"ml_accelerator":"ml-acc-1"}') == "ml-acc-1"
    assert cost_router._accelerator_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "accel-a", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "ml-acc-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "accel-a", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "ml-acc-1", 5, 20),
    ]
    series = cost_router._build_accelerator_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_accelerators=8,
    )
    assert [item.accelerator for item in series] == ["accel-a", "ml-acc-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_cell_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._cell_from_properties('{"cell":"cell-east"}') == "cell-east"
    assert cost_router._cell_from_properties('{"availability_cell":"av-cell-1"}') == "av-cell-1"
    assert cost_router._cell_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "cell-east", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "av-cell-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "cell-east", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "av-cell-1", 5, 20),
    ]
    series = cost_router._build_cell_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_cells=8,
    )
    assert [item.cell for item in series] == ["cell-east", "av-cell-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_zone_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._zone_from_properties('{"zone":"zone-a"}') == "zone-a"
    assert cost_router._zone_from_properties('{"availability_zone":"us-east-1a"}') == "us-east-1a"
    assert cost_router._zone_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "zone-a", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "us-east-1a", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "zone-a", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "us-east-1a", 5, 20),
    ]
    series = cost_router._build_zone_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_zones=8,
    )
    assert [item.zone for item in series] == ["zone-a", "us-east-1a"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_rack_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._rack_from_properties('{"rack":"rack-12"}') == "rack-12"
    assert cost_router._rack_from_properties('{"server_rack":"sr-4"}') == "sr-4"
    assert cost_router._rack_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "rack-12", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "sr-4", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "rack-12", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "sr-4", 5, 20),
    ]
    series = cost_router._build_rack_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_racks=8,
    )
    assert [item.rack for item in series] == ["rack-12", "sr-4"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_pool_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._pool_from_properties('{"pool":"pool-gpu"}') == "pool-gpu"
    assert cost_router._pool_from_properties('{"worker_pool":"wp-1"}') == "wp-1"
    assert cost_router._pool_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "pool-gpu", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "wp-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "pool-gpu", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "wp-1", 5, 20),
    ]
    series = cost_router._build_pool_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_pools=8,
    )
    assert [item.pool for item in series] == ["pool-gpu", "wp-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_fleet_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._fleet_from_properties('{"fleet":"fleet-edge"}') == "fleet-edge"
    assert cost_router._fleet_from_properties('{"compute_fleet":"cf-2"}') == "cf-2"
    assert cost_router._fleet_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "fleet-edge", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "cf-2", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "fleet-edge", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "cf-2", 5, 20),
    ]
    series = cost_router._build_fleet_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_fleets=8,
    )
    assert [item.fleet for item in series] == ["fleet-edge", "cf-2"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_lease_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._lease_from_properties('{"lease":"lease-a"}') == "lease-a"
    assert cost_router._lease_from_properties('{"capacity_lease":"cl-1"}') == "cl-1"
    assert cost_router._lease_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "lease-a", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "cl-1", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "lease-a", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "cl-1", 5, 20),
    ]
    series = cost_router._build_lease_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_leases=8,
    )
    assert [item.lease for item in series] == ["lease-a", "cl-1"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_quota_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._quota_from_properties('{"quota":"quota-rpm"}') == "quota-rpm"
    assert cost_router._quota_from_properties('{"service_quota":"sq-2"}') == "sq-2"
    assert cost_router._quota_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "quota-rpm", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "sq-2", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "quota-rpm", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "sq-2", 5, 20),
    ]
    series = cost_router._build_quota_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_quotas=8,
    )
    assert [item.quota for item in series] == ["quota-rpm", "sq-2"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_capacity_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._capacity_from_properties('{"capacity":"cap-gpu"}') == "cap-gpu"
    assert cost_router._capacity_from_properties('{"reserved_capacity":"rc-3"}') == "rc-3"
    assert cost_router._capacity_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "cap-gpu", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "rc-3", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "cap-gpu", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "rc-3", 5, 20),
    ]
    series = cost_router._build_capacity_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_capacities=8,
    )
    assert [item.capacity for item in series] == ["cap-gpu", "rc-3"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15



def test_cost_reservation_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._reservation_from_properties('{"reservation":"res-1"}') == "res-1"
    assert cost_router._reservation_from_properties('{"capacity_reservation":"cr-4"}') == "cr-4"
    assert cost_router._reservation_from_properties("{}") == ""

    start = datetime(2026, 8, 2, 10, 0, 0)
    end = datetime(2026, 8, 2, 11, 0, 0)
    events = [
        (datetime(2026, 8, 2, 10, 15, 0), "res-1", 40, 200),
        (datetime(2026, 8, 2, 10, 45, 0), "cr-4", 20, 100),
        (datetime(2026, 8, 2, 11, 5, 0), "res-1", 15, 80),
        (datetime(2026, 8, 2, 11, 20, 0), "cr-4", 5, 20),
    ]
    series = cost_router._build_reservation_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_reservations=8,
    )
    assert [item.reservation for item in series] == ["res-1", "cr-4"]
    assert series[0].spend_cents == 55
    assert series[0].total_tokens == 280
    assert series[0].points[0].spend_cents == 40
    assert series[0].points[1].spend_cents == 15


def test_log_export_signed_url_helpers():
    from app.routers import cost as cost_router

    signed_url, exp = cost_router._build_signed_log_export_url(
        export_id="lexp-abc",
        actor_id="actor-1",
        ttl_seconds=900,
    )
    assert signed_url.startswith("/v1/logs/exports/lexp-abc/content?exp=")
    assert "sig=" in signed_url
    assert exp > 0
    sig = signed_url.split("sig=", 1)[1]
    assert cost_router._verify_signed_log_export(
        export_id="lexp-abc",
        actor_id="actor-1",
        exp=exp,
        sig=sig,
    )
    assert not cost_router._verify_signed_log_export(
        export_id="lexp-abc",
        actor_id="actor-other",
        exp=exp,
        sig=sig,
    )
    assert not cost_router._verify_signed_log_export(
        export_id="lexp-abc",
        actor_id="actor-1",
        exp=exp - 10_000,
        sig=sig,
    )


def test_batch_request_stub_helpers_strip_bodies():
    from app.routers import gateway as gw

    stubs = gw._sanitize_batch_request_stubs(
        [
            {
                "custom_id": "a1",
                "model": "gpt-4o-mini",
                "input": "SECRET PROMPT",
                "messages": [{"role": "user", "content": "nope"}],
                "endpoint": "/v1/responses",
            },
            {"model": "gpt-4o", "body": {"x": 1}},
        ]
    )
    assert stubs[0]["custom_id"] == "a1"
    assert stubs[0]["model"] == "gpt-4o-mini"
    assert stubs[0]["endpoint"] == "/v1/responses"
    assert "input" not in stubs[0]
    assert "messages" not in stubs[0]
    assert stubs[1]["custom_id"] == "item-1"
    assert "body" not in stubs[1]

    from types import SimpleNamespace

    record = SimpleNamespace(
        batch_id="batch-1",
        status="queued",
        request_count=2,
        metadata_json='{"_agenthub_request_stubs":[{"custom_id":"a1","model":"gpt-4o-mini"}],"source":"t"}',
    )
    items = gw._build_batch_result_items(record)
    assert len(items) == 1
    assert items[0].custom_id == "a1"
    assert items[0].status == "queued"
    serialized = gw._serialize_openai_batch_record(
        SimpleNamespace(
            batch_id="batch-1",
            status="queued",
            endpoint_family="responses",
            request_count=1,
            completed_count=0,
            failed_count=0,
            request_id="r1",
            trace_id="t1",
            created_at=__import__("datetime").datetime(2026, 8, 1, 12, 0, 0),
            metadata_json=record.metadata_json,
        )
    )
    assert "_agenthub_request_stubs" not in serialized["metadata"]
    assert serialized["metadata"]["source"] == "t"


def test_cost_user_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "user-a", 50, "sess-1"),
        (datetime(2026, 8, 1, 10, 45, 0), "user-a", 25, "sess-2"),
        (datetime(2026, 8, 1, 11, 5, 0), "user-b", 10, "sess-3"),
        (datetime(2026, 8, 1, 11, 20, 0), "user-a", 5, "sess-1"),
    ]
    series = cost_router._build_user_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_users=2,
    )
    assert [item.user_id for item in series] == ["user-a", "user-b"]
    assert series[0].spend_cents == 80
    assert series[0].session_count == 2
    assert series[0].points[0].spend_cents == 75
    assert series[0].points[0].session_count == 2
    assert series[0].points[1].spend_cents == 5


def test_cost_session_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 15, 0), "sess-a", "/chat", "Chat A", 50),
        (datetime(2026, 8, 1, 10, 45, 0), "sess-a", "/chat", "Chat A", 25),
        (datetime(2026, 8, 1, 11, 5, 0), "sess-b", "/ops", "Ops", 10),
        (datetime(2026, 8, 1, 11, 20, 0), "sess-a", "/chat", "Chat A", 5),
    ]
    series = cost_router._build_session_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_sessions=2,
    )
    assert [item.session_id for item in series] == ["sess-a", "sess-b"]
    assert series[0].session_path == "/chat"
    assert series[0].spend_cents == 80
    assert series[0].points[0].spend_cents == 75
    assert series[0].points[1].spend_cents == 5


def test_log_export_helpers_strip_body_fields():
    from app.routers import cost as cost_router
    from app.schemas import CostRequestItem
    from datetime import datetime

    fields = cost_router._normalize_log_export_requested_data(
        ["id", "request", "response", "ai_model", "model", "cost"]
    )
    assert "request" not in fields
    assert "response" not in fields
    assert "ai_model" in fields
    assert "model" not in fields
    assert fields.count("ai_model") == 1

    filters = cost_router._normalize_log_export_filters(
        {"window_hours": 48, "limit": 99999, "cache_hit": "true", "user_id": "u1"}
    )
    assert filters["window_hours"] == 48
    assert filters["limit"] == 5000
    assert filters["cache_hit"] is True
    assert filters["user_id"] == "u1"

    row = cost_router._log_export_row(
        CostRequestItem(
            request_id="req-1",
            model_name="gpt-4o-mini",
            estimated_cost_cents=12,
            cache_hit=True,
            timestamp=datetime(2026, 8, 1, 12, 0, 0),
        ),
        ["id", "ai_model", "cost", "cache_hit"],
    )
    assert row == {"id": "req-1", "ai_model": "gpt-4o-mini", "cost": 12, "cache_hit": True}


def test_cost_score_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 10, 0), "quality", 0.8, 20),
        (datetime(2026, 8, 1, 10, 40, 0), "quality", 1.0, 10),
        (datetime(2026, 8, 1, 11, 5, 0), "latency", 0.5, 5),
        (datetime(2026, 8, 1, 11, 20, 0), "quality", 0.6, 5),
    ]
    series = cost_router._build_score_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_keys=2,
    )
    assert [item.key for item in series] == ["quality", "latency"]
    assert series[0].count == 3
    assert series[0].avg == 0.8
    assert series[0].points[0].avg == 0.9
    assert series[0].points[0].count == 2


def test_cost_rating_timeseries_helper():
    from datetime import datetime

    from app.routers import cost as cost_router

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 10, 0), "rating:5", 5.0, 20),
        (datetime(2026, 8, 1, 10, 40, 0), "rating:5", 5.0, 10),
        (datetime(2026, 8, 1, 11, 5, 0), "rating:3", 3.0, 5),
        (datetime(2026, 8, 1, 11, 20, 0), "rating:5", 5.0, 5),
    ]
    series = cost_router._build_rating_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_labels=2,
    )
    assert [item.rating_label for item in series] == ["rating:5", "rating:3"]
    assert series[0].count == 3
    assert series[0].avg == 5.0
    assert series[0].points[0].count == 2
    assert series[0].points[0].spend_cents == 30


def test_cost_latency_helpers():
    from datetime import datetime

    from app.routers import cost as cost_router
    from app.routers import gateway as gw

    assert cost_router._latency_ms_from_properties('{"latency_ms":120}') == 120
    assert cost_router._latency_ms_from_properties('{"latency_ms":-1}') is None
    assert cost_router._percentile_ms([10, 20, 30, 40, 100], 0.95) == 100.0
    assert gw._elapsed_latency_ms(__import__("time").perf_counter()) >= 0

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 10, 0), "gpt-4o-mini", 100, 20),
        (datetime(2026, 8, 1, 10, 40, 0), "gpt-4o-mini", 200, 10),
        (datetime(2026, 8, 1, 11, 5, 0), "gpt-4o", 50, 5),
        (datetime(2026, 8, 1, 11, 20, 0), "gpt-4o-mini", 300, 5),
    ]
    series = cost_router._build_latency_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_models=2,
    )
    assert [item.model_name for item in series] == ["gpt-4o-mini", "gpt-4o"]
    assert series[0].count == 3
    assert series[0].avg_ms == 200.0
    assert series[0].points[0].count == 2
    assert series[0].points[0].avg_ms == 150.0


def test_cost_cache_timeseries_helpers():
    from datetime import datetime

    from app.routers import cost as cost_router

    assert cost_router._cache_hit_rate(3, 1) == 0.75
    assert cost_router._cache_hit_rate(0, 0) == 0.0

    start = datetime(2026, 8, 1, 10, 0, 0)
    end = datetime(2026, 8, 1, 11, 0, 0)
    events = [
        (datetime(2026, 8, 1, 10, 10, 0), "gpt-4o-mini", True, 20),
        (datetime(2026, 8, 1, 10, 40, 0), "gpt-4o-mini", False, 10),
        (datetime(2026, 8, 1, 11, 5, 0), "gpt-4o", True, 5),
        (datetime(2026, 8, 1, 11, 20, 0), "gpt-4o-mini", True, 5),
    ]
    series = cost_router._build_cache_timeseries_series(
        events,
        start_hour=start,
        end_hour=end,
        top_models=2,
    )
    assert [item.model_name for item in series] == ["gpt-4o-mini", "gpt-4o"]
    assert series[0].hit_count == 2
    assert series[0].miss_count == 1
    assert series[0].hit_rate == 0.6667
    assert series[0].points[0].hit_count == 1
    assert series[0].points[0].miss_count == 1
    assert series[0].points[0].hit_rate == 0.5


def test_sdk_batches_and_logs_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock, patch

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "items": [{"request_id": "req-1", "cache_hit": True}]},
            {"request_id": "req-1", "model_name": "gpt-4o-mini"},
            {"object": "list", "data": [{"id": "batch-1", "status": "queued"}]},
            {"id": "batch-1", "status": "queued", "request_count": 2},
            {
                "id": "batch-1",
                "status": "queued",
                "count": 1,
                "content": '{"custom_id":"a1"}\n',
                "data": [{"custom_id": "a1", "status": "queued"}],
            },
        ]
    )
    client._post = MagicMock(
        side_effect=[
            {"id": "batch-1", "status": "queued", "object": "batch"},
            {"id": "batch-1", "status": "cancelled", "object": "batch"},
            {
                "id": "batch-1",
                "status": "completed",
                "completed_count": 2,
                "failed_count": 0,
                "object": "batch",
            },
            {"id": "batch-2", "status": "expired", "object": "batch"},
        ]
    )
    client._delete = MagicMock(return_value={"id": "batch-1", "deleted": True, "object": "batch.deleted"})

    logs = client.list_logs(window_hours=12, cache_hit=True, limit=10)
    assert logs["count"] == 1
    client._get.assert_any_call("/v1/logs?window_hours=12&limit=10&cache_hit=true")
    got = client.get_log("req-1")
    assert got["request_id"] == "req-1"
    client._get.assert_any_call("/v1/logs/req-1")

    created = client.create_batch(
        requests=[{"model": "gpt-4o-mini", "input": "hi"}],
        endpoint_family="responses",
        metadata={"source": "sdk"},
    )
    assert created["id"] == "batch-1"
    listed = client.list_batches(limit=5, offset=0, status="queued")
    assert listed[0]["id"] == "batch-1"
    client._get.assert_any_call("/v1/batches?limit=5&offset=0&status=queued")
    batch = client.get_batch("batch-1")
    assert batch["request_count"] == 2
    client._get.assert_any_call("/v1/batches/batch-1")
    results = client.get_batch_results("batch-1")
    assert results["count"] == 1
    client._get.assert_any_call("/v1/batches/batch-1/results")
    cancelled = client.cancel_batch("batch-1")
    assert cancelled["status"] == "cancelled"
    client._post.assert_any_call("/v1/batches/batch-1/cancel", {})
    completed = client.complete_batch("batch-1", completed_count=2, failed_count=0, status="completed")
    assert completed["status"] == "completed"
    client._post.assert_any_call(
        "/v1/batches/batch-1/complete",
        {"status": "completed", "completed_count": 2, "failed_count": 0},
    )
    expired = client.expire_batch("batch-2")
    assert expired["status"] == "expired"
    client._post.assert_any_call("/v1/batches/batch-2/expire", {})
    deleted = client.delete_batch("batch-1")
    assert deleted["deleted"] is True
    client._delete.assert_called_once_with("/v1/batches/batch-1")

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"timestamp,request_id\n2026-08-01T00:00:00,req-1\n"

    with patch.object(sdk_mod.request, "urlopen", return_value=_FakeResp()) as urlopen_mock:
        csv_body = client.export_logs(window_hours=6, limit=100, cache_hit=True)
    assert "request_id" in csv_body
    called_req = urlopen_mock.call_args.args[0]
    assert "/v1/logs/export?" in called_req.full_url
    assert "window_hours=6" in called_req.full_url
    assert "cache_hit=true" in called_req.full_url


def test_sdk_files_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._post = MagicMock(return_value={"id": "file-1", "filename": "a.jsonl", "object": "file"})
    client._get = MagicMock(
        side_effect=[
            {"object": "list", "data": [{"id": "file-1", "filename": "a.jsonl"}]},
            {"id": "file-1", "filename": "a.jsonl", "bytes": 12},
            {"id": "file-1", "content_available": False, "object": "file.content"},
        ]
    )
    client._delete = MagicMock(return_value={"id": "file-1", "deleted": True, "object": "file.deleted"})

    created = client.create_file(filename="a.jsonl", purpose="batch", bytes=12, content_type="application/jsonl")
    assert created["id"] == "file-1"
    client._post.assert_called_once_with(
        "/v1/files",
        {
            "filename": "a.jsonl",
            "purpose": "batch",
            "bytes": 12,
            "content_type": "application/jsonl",
            "environment": "dev",
        },
    )
    listed = client.list_files(limit=5, offset=0, purpose="batch")
    assert listed[0]["id"] == "file-1"
    client._get.assert_any_call("/v1/files?limit=5&offset=0&purpose=batch")
    got = client.get_file("file-1")
    assert got["bytes"] == 12
    content = client.get_file_content("file-1")
    assert content["content_available"] is False
    client._get.assert_any_call("/v1/files/file-1/content")
    deleted = client.delete_file("file-1")
    assert deleted["deleted"] is True
    client._delete.assert_called_once_with("/v1/files/file-1")


def test_sdk_assistants_threads_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._post = MagicMock(
        side_effect=[
            {"id": "asst-1", "object": "assistant", "name": "Helper"},
            {"id": "thread-1", "object": "thread"},
            {"id": "msg-1", "object": "thread.message", "role": "user"},
            {"id": "run-1", "object": "thread.run", "status": "queued"},
        ]
    )
    client._get = MagicMock(
        side_effect=[
            {"object": "list", "data": [{"id": "asst-1", "name": "Helper"}]},
            {"id": "asst-1", "name": "Helper", "model": "gpt-4o"},
            {"id": "thread-1", "object": "thread"},
            {"object": "list", "data": [{"id": "msg-1", "role": "user"}]},
            {"id": "run-1", "status": "completed"},
        ]
    )
    client._delete = MagicMock(return_value={"id": "asst-1", "deleted": True, "object": "assistant.deleted"})

    created = client.create_assistant(name="Helper", model="gpt-4o", instructions="Be brief")
    assert created["id"] == "asst-1"
    client._post.assert_any_call(
        "/v1/assistants",
        {
            "name": "Helper",
            "model": "gpt-4o",
            "instructions": "Be brief",
            "environment": "dev",
        },
    )
    listed = client.list_assistants(limit=5, offset=0)
    assert listed[0]["id"] == "asst-1"
    client._get.assert_any_call("/v1/assistants?limit=5&offset=0")
    got = client.get_assistant("asst-1")
    assert got["model"] == "gpt-4o"
    deleted = client.delete_assistant("asst-1")
    assert deleted["deleted"] is True
    client._delete.assert_called_once_with("/v1/assistants/asst-1")

    thread = client.create_thread()
    assert thread["id"] == "thread-1"
    client._post.assert_any_call("/v1/threads", {"environment": "dev"})
    got_thread = client.get_thread("thread-1")
    assert got_thread["id"] == "thread-1"
    msg = client.create_thread_message("thread-1", content="hello")
    assert msg["id"] == "msg-1"
    client._post.assert_any_call(
        "/v1/threads/thread-1/messages",
        {"role": "user", "content": "hello"},
    )
    messages = client.list_thread_messages("thread-1", limit=10, offset=0)
    assert messages[0]["id"] == "msg-1"
    client._get.assert_any_call("/v1/threads/thread-1/messages?limit=10&offset=0")
    run = client.create_thread_run("thread-1", assistant_id="asst-1")
    assert run["id"] == "run-1"
    client._post.assert_any_call(
        "/v1/threads/thread-1/runs",
        {
            "assistant_id": "asst-1",
            "additional_instructions": "",
            "environment": "dev",
            "stream": False,
        },
    )
    got_run = client.get_thread_run("thread-1", "run-1")
    assert got_run["status"] == "completed"
    client._get.assert_any_call("/v1/threads/thread-1/runs/run-1")


def test_sdk_fine_tuning_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._post = MagicMock(
        side_effect=[
            {"id": "ftjob-1", "object": "fine_tuning.job", "status": "queued"},
            {"id": "ftjob-1", "object": "fine_tuning.job", "status": "cancelled"},
        ]
    )
    client._get = MagicMock(
        side_effect=[
            {"object": "list", "data": [{"id": "ftjob-1", "status": "queued"}]},
            {"id": "ftjob-1", "status": "running", "model": "gpt-4o-mini"},
        ]
    )

    created = client.create_fine_tuning_job(model="gpt-4o-mini", training_file_id="file-1")
    assert created["id"] == "ftjob-1"
    client._post.assert_any_call(
        "/v1/fine_tuning/jobs",
        {
            "model": "gpt-4o-mini",
            "training_file_id": "file-1",
            "environment": "dev",
        },
    )
    listed = client.list_fine_tuning_jobs(limit=5, offset=0)
    assert listed[0]["id"] == "ftjob-1"
    client._get.assert_any_call("/v1/fine_tuning/jobs?limit=5&offset=0")
    got = client.get_fine_tuning_job("ftjob-1")
    assert got["status"] == "running"
    client._get.assert_any_call("/v1/fine_tuning/jobs/ftjob-1")
    cancelled = client.cancel_fine_tuning_job("ftjob-1")
    assert cancelled["status"] == "cancelled"
    client._post.assert_any_call("/v1/fine_tuning/jobs/ftjob-1/cancel", {})


def test_sdk_images_audio_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"created": 1, "data": [{"b64_json": "abc", "index": 0}], "model": "gpt-image-1"},
            {"text": "hello world", "model": "whisper-1", "duration_seconds": 1.2},
        ]
    )

    images = client.images({"model": "gpt-image-1", "prompt": "a cat"})
    assert images["data"][0]["b64_json"] == "abc"
    assert images["agenthub"]["request_id"]
    img_call = client._post.call_args_list[0]
    assert img_call.args[0] == "/v1/images"
    assert img_call.args[1]["prompt"] == "a cat"
    assert "X-Request-Id" in (img_call.kwargs.get("extra_headers") or {})

    audio = client.audio_transcriptions({"model": "whisper-1", "input_text": "hello"})
    assert audio["text"] == "hello world"
    aud_call = client._post.call_args_list[1]
    assert aud_call.args[0] == "/v1/audio/transcriptions"
    assert aud_call.args[1]["input_text"] == "hello"
    assert "X-Trace-Id" in (aud_call.kwargs.get("extra_headers") or {})


def test_sdk_rerank_audio_translations_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {
                "object": "list",
                "model": "rerank-english-v3.0",
                "results": [{"index": 0, "relevance_score": 0.9, "document": "a"}],
                "usage": {"prompt_tokens": 12, "total_tokens": 12},
            },
            {"text": "bonjour", "model": "whisper-1", "duration_seconds": 1.0},
        ]
    )

    ranked = client.rerank({"model": "rerank-english-v3.0", "query": "q", "documents": ["a", "b"]})
    assert ranked["results"][0]["relevance_score"] == 0.9
    assert ranked["agenthub"]["request_id"]
    rerank_call = client._post.call_args_list[0]
    assert rerank_call.args[0] == "/v1/rerank"
    assert rerank_call.args[1]["query"] == "q"
    assert "X-Request-Id" in (rerank_call.kwargs.get("extra_headers") or {})

    translated = client.audio_translations(
        {"model": "whisper-1", "input_text": "hello", "target_language": "fr"}
    )
    assert translated["text"] == "bonjour"
    tr_call = client._post.call_args_list[1]
    assert tr_call.args[0] == "/v1/audio/translations"
    assert tr_call.args[1]["target_language"] == "fr"
    assert "X-Trace-Id" in (tr_call.kwargs.get("extra_headers") or {})


def test_sdk_messages_passthrough_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"id": "msg-1", "object": "message", "role": "assistant", "content": "hi", "model": "gpt-4o-mini"},
            {"status_code": 200, "body": {"ok": True}, "provider_id": "openai", "path": "/v1/models", "trace_id": "t1"},
        ]
    )

    msg = client.messages({"model": "gpt-4o-mini", "input": "hello"})
    assert msg["content"] == "hi"
    assert msg["agenthub"]["request_id"]
    msg_call = client._post.call_args_list[0]
    assert msg_call.args[0] == "/v1/messages"
    assert msg_call.args[1]["input"] == "hello"
    assert "X-Request-Id" in (msg_call.kwargs.get("extra_headers") or {})

    passthrough = client.passthrough(provider_id="openai", path="/v1/models", method="GET")
    assert passthrough["status_code"] == 200
    client._post.assert_any_call(
        "/v1/passthrough",
        {
            "provider_id": "openai",
            "path": "/v1/models",
            "method": "GET",
            "environment": "dev",
        },
    )


def test_sdk_realtime_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"id": "rt-1", "object": "realtime.session", "status": "open", "model": "gpt-4o-realtime"},
            {"id": "evt-1", "object": "realtime.event", "event_type": "input.text", "status": "accepted"},
            {"id": "rt-1", "object": "realtime.session", "status": "closed"},
        ]
    )
    client._get = MagicMock(
        side_effect=[
            {"object": "list", "data": [{"id": "rt-1", "status": "open"}]},
            {"id": "rt-1", "status": "open", "model": "gpt-4o-realtime"},
            {"object": "list", "data": [{"id": "evt-1", "event_type": "input.text"}]},
        ]
    )

    created = client.create_realtime_session({"model": "gpt-4o-realtime", "requested_modalities": ["text"]})
    assert created["id"] == "rt-1"
    assert created["agenthub"]["request_id"]
    create_call = client._post.call_args_list[0]
    assert create_call.args[0] == "/v1/realtime"
    assert create_call.args[1]["model"] == "gpt-4o-realtime"

    listed = client.list_realtime_sessions(limit=5, offset=0, status="open")
    assert listed[0]["id"] == "rt-1"
    client._get.assert_any_call("/v1/realtime/sessions?limit=5&offset=0&status=open")
    got = client.get_realtime_session("rt-1")
    assert got["status"] == "open"
    client._get.assert_any_call("/v1/realtime/sessions/rt-1")

    event = client.create_realtime_session_event("rt-1", event_type="input.text", payload={"text": "hi"})
    assert event["id"] == "evt-1"
    client._post.assert_any_call(
        "/v1/realtime/sessions/rt-1/events",
        {
            "event_type": "input.text",
            "binary_mode": "metadata_only",
            "event_bytes": 0,
            "payload": {"text": "hi"},
        },
    )
    events = client.list_realtime_session_events("rt-1")
    assert events[0]["id"] == "evt-1"
    client._get.assert_any_call("/v1/realtime/sessions/rt-1/events")
    closed = client.close_realtime_session("rt-1")
    assert closed["status"] == "closed"
    client._post.assert_any_call("/v1/realtime/sessions/rt-1/close", {})


def test_sdk_a2a_messages_path():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        return_value={"id": "a2a-1", "content": "ack", "from_agent_id": "a1", "to_agent_id": "a2"}
    )
    body = {
        "from_agent_id": "a1",
        "to_agent_id": "a2",
        "message": "hello peer",
        "model": "gpt-4o-mini",
        "session_id": "sess-a2a",
    }
    result = client.a2a_messages(body, request_tag="parity")
    assert result["id"] == "a2a-1"
    assert result["agenthub"]["session_id"] == "sess-a2a"
    assert result["agenthub"]["request_id"]
    client._post.assert_called_once()
    assert client._post.call_args.args[0] == "/v1/a2a/messages"
    assert client._post.call_args.args[1]["from_agent_id"] == "a1"
    assert client._post.call_args.args[1]["message"] == "hello peer"


def test_sdk_vector_store_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"object": "list", "data": [{"id": "vs-1", "name": "docs"}]},
            {"id": "vs-1", "name": "docs", "status": "completed"},
        ]
    )
    listed = client.list_vector_stores()
    assert listed[0]["id"] == "vs-1"
    client._get.assert_any_call("/v1/vector_stores")
    got = client.get_vector_store("vs-1")
    assert got["name"] == "docs"
    client._get.assert_any_call("/v1/vector_stores/vs-1")


def test_sdk_responses_crud_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"object": "list", "data": [{"id": "resp-1", "model": "gpt-4o-mini"}]},
            {"id": "resp-1", "model": "gpt-4o-mini", "output_text": "hi"},
        ]
    )
    client._delete = MagicMock(return_value={"id": "resp-1", "object": "response", "deleted": True})
    listed = client.list_responses(limit=5, offset=0, model_contains="gpt")
    assert listed[0]["id"] == "resp-1"
    client._get.assert_any_call("/v1/responses?limit=5&offset=0&model_contains=gpt")
    got = client.get_response("resp-1")
    assert got["output_text"] == "hi"
    client._get.assert_any_call("/v1/responses/resp-1")
    deleted = client.delete_response("resp-1")
    assert deleted["deleted"] is True
    client._delete.assert_called_once_with("/v1/responses/resp-1")


def test_sdk_rag_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"object": "rag.ingest", "store_id": "vs-1", "ingested": 1, "document_ids": ["d1"]},
            {"object": "rag.query", "store_id": "vs-1", "match_count": 1, "matches": [{"id": "d1"}]},
        ]
    )
    ingested = client.rag_ingest(
        store_id="vs-1",
        documents=[{"id": "d1", "text": "hello"}],
        metadata={"source": "parity"},
    )
    assert ingested["ingested"] == 1
    client._post.assert_any_call(
        "/rag/ingest",
        {
            "store_id": "vs-1",
            "documents": [{"id": "d1", "text": "hello"}],
            "metadata": {"source": "parity"},
        },
    )
    queried = client.rag_query(store_id="vs-1", query="hello", top_k=3)
    assert queried["match_count"] == 1
    client._post.assert_any_call(
        "/rag/query",
        {"store_id": "vs-1", "query": "hello", "top_k": 3},
    )


def test_sdk_memory_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        return_value={"memory_id": "mem-1", "memory_tier": "short_term", "content": "note"}
    )
    client._get = MagicMock(
        side_effect=[
            {"object": "list", "data": [{"memory_id": "mem-1", "label": "note"}]},
            {"memory_id": "mem-1", "content": "note", "status": "active"},
            {"short_term": {"active_count": 1}, "long_term": {"active_count": 0}},
            {"short_term_ttl_seconds": 3600, "pii_classification_enabled": True},
        ]
    )
    client._delete = MagicMock(return_value={"memory_id": "mem-1", "deleted": True})

    created = client.create_memory_record(
        memory_tier="short_term",
        scope_type="session",
        scope_id="sess-1",
        content="note",
        label="note",
        environment="dev",
    )
    assert created["memory_id"] == "mem-1"
    client._post.assert_called_once_with(
        "/gateway/memory/records",
        {
            "memory_tier": "short_term",
            "scope_type": "session",
            "scope_id": "sess-1",
            "content": "note",
            "label": "note",
            "environment": "dev",
        },
    )
    listed = client.list_memory_records(memory_tier="short_term", limit=10, offset=0)
    assert listed[0]["memory_id"] == "mem-1"
    client._get.assert_any_call(
        "/gateway/memory/records?limit=10&offset=0&memory_tier=short_term"
    )
    got = client.get_memory_record("mem-1")
    assert got["status"] == "active"
    client._get.assert_any_call("/gateway/memory/records/mem-1")
    deleted = client.delete_memory_record("mem-1")
    assert deleted["deleted"] is True
    client._delete.assert_called_once_with("/gateway/memory/records/mem-1")
    overview = client.get_memory_overview()
    assert overview["short_term"]["active_count"] == 1
    client._get.assert_any_call("/gateway/memory/overview")
    config = client.get_memory_config()
    assert config["short_term_ttl_seconds"] == 3600
    client._get.assert_any_call("/gateway/memory/config")


def test_sdk_least_privilege_decision_trace_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            [{"recommendation_id": "lpr-1", "status": "pending"}],
            {"trace_id": "t-1", "event_count": 2, "outcomes": {"allow": 2}},
        ]
    )
    recs = client.list_least_privilege_recommendations(status="pending", limit=20, offset=0)
    assert recs[0]["recommendation_id"] == "lpr-1"
    client._get.assert_any_call(
        "/gateway/least-privilege/recommendations?limit=20&offset=0&status=pending"
    )
    trace = client.get_decision_trace("t-1", limit=200)
    assert trace["trace_id"] == "t-1"
    client._get.assert_any_call("/gateway/decision-traces/t-1?limit=200")


def test_sdk_access_review_mcp_tools_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        return_value={"campaign_id": "arc-1", "status": "open", "reviewed_count": 2}
    )
    client._post = MagicMock(
        return_value={"server_id": "mcp-1", "tools": [{"name": "search"}]}
    )
    campaign = client.get_access_review_campaign("arc-1")
    assert campaign["campaign_id"] == "arc-1"
    client._get.assert_called_with("/gateway/access-reviews/campaigns/arc-1")
    tools = client.list_mcp_tools("mcp-1", environment="staging")
    assert tools["tools"][0]["name"] == "search"
    client._post.assert_called_with(
        "/gateway/mcp/servers/mcp-1/tools/list",
        {"environment": "staging"},
    )


def test_sdk_mcp_call_and_routes_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        return_value={
            "server_id": "mcp-1",
            "tool_name": "search",
            "result": {"hits": 1},
            "trace_id": "t-mcp",
        }
    )
    client._get = MagicMock(return_value=[{"route_policy_id": "rp-1", "name": "default"}])
    called = client.call_mcp_tool(
        "mcp-1",
        "search",
        arguments={"q": "docs"},
        environment="dev",
    )
    assert called["tool_name"] == "search"
    client._post.assert_called_with(
        "/gateway/mcp/servers/mcp-1/tools/call",
        {"environment": "dev", "tool_name": "search", "arguments": {"q": "docs"}},
    )
    routes = client.list_routes(limit=20, offset=0)
    assert routes[0]["route_policy_id"] == "rp-1"
    client._get.assert_called_with("/gateway/routes?limit=20&offset=0")


def test_sdk_get_route_and_gateway_analytics_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "name": "default"},
            {"total_events": 12, "total_cost_cents": 340},
        ]
    )
    route = client.get_route("rp-1")
    assert route["route_policy_id"] == "rp-1"
    client._get.assert_any_call("/gateway/routes/rp-1")
    summary = client.get_gateway_analytics_summary(hours=24, environment="prod")
    assert summary["total_events"] == 12
    client._get.assert_any_call("/gateway/analytics/summary?hours=24&environment=prod")


def test_sdk_route_provider_health_priority_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "entries": [{"provider_id": "p1", "status": "healthy"}]},
            {"route_policy_id": "rp-1", "priority_order": ["p1", "p2"]},
        ]
    )
    health = client.get_route_provider_health("rp-1", request_tag="canary")
    assert health["entries"][0]["provider_id"] == "p1"
    client._get.assert_any_call("/gateway/routes/rp-1/providers/health?request_tag=canary")
    priority = client.get_route_provider_priority("rp-1")
    assert priority["priority_order"] == ["p1", "p2"]
    client._get.assert_any_call("/gateway/routes/rp-1/providers/priority")


def test_sdk_priority_timeline_and_mirroring_analytics_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "events": [{"action_type": "gateway.route.provider_priority.update"}]},
            {"route_policy_id": "rp-1", "total_mirror_events": 7},
        ]
    )
    timeline = client.get_route_provider_priority_timeline("rp-1", limit=10, offset=0)
    assert timeline["events"][0]["action_type"] == "gateway.route.provider_priority.update"
    client._get.assert_any_call("/gateway/routes/rp-1/providers/priority/timeline?limit=10&offset=0")
    summary = client.get_route_traffic_mirroring_analytics_summary(
        "rp-1",
        hours=24,
        request_tag="canary",
        environment="prod",
    )
    assert summary["total_mirror_events"] == 7
    client._get.assert_any_call(
        "/gateway/routes/rp-1/traffic-mirroring/analytics-summary?hours=24&request_tag=canary&environment=prod"
    )


def test_sdk_traffic_mirroring_and_canary_rollout_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "enabled": True, "max_live_attempts": 2},
            {"route_policy_id": "rp-1", "baseline_provider_id": "p1", "status": "promoted"},
        ]
    )
    mirroring = client.get_route_traffic_mirroring("rp-1", request_tag="canary")
    assert mirroring["enabled"] is True
    client._get.assert_any_call("/gateway/routes/rp-1/traffic-mirroring?request_tag=canary")
    canary = client.get_route_canary_rollout("rp-1")
    assert canary["baseline_provider_id"] == "p1"
    client._get.assert_any_call("/gateway/routes/rp-1/canary-rollout")


def test_sdk_route_fallbacks_and_pre_call_filters_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "fallbacks": [{"provider_id": "p2"}]},
            {"route_policy_id": "rp-1", "filters": [{"type": "pii"}]},
        ]
    )
    fallbacks = client.get_route_fallbacks("rp-1", request_tag="canary")
    assert fallbacks["fallbacks"][0]["provider_id"] == "p2"
    client._get.assert_any_call("/gateway/routes/rp-1/fallbacks?request_tag=canary")
    filters = client.get_route_pre_call_filters("rp-1")
    assert filters["filters"][0]["type"] == "pii"
    client._get.assert_any_call("/gateway/routes/rp-1/pre-call-filters")


def test_sdk_route_input_data_policy_and_output_guardrails_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "policy_mode": "block", "enforce": True},
            {"route_policy_id": "rp-1", "policy_mode": "warn", "max_output_tokens": 512},
        ]
    )
    input_policy = client.get_route_input_data_policy("rp-1", request_tag="canary")
    assert input_policy["policy_mode"] == "block"
    client._get.assert_any_call("/gateway/routes/rp-1/input-data-policy?request_tag=canary")
    guardrails = client.get_route_output_guardrails("rp-1")
    assert guardrails["max_output_tokens"] == 512
    client._get.assert_any_call("/gateway/routes/rp-1/output-guardrails")


def test_sdk_mirroring_experiment_report_and_simulate_fallback_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        return_value={"route_policy_id": "rp-1", "total_rows": 2, "rows": [{"event_id": "e1"}]}
    )
    client._post = MagicMock(
        return_value={"route_policy_id": "rp-1", "final_outcome": "selected", "fallback_hops_used": 1}
    )
    report = client.get_route_traffic_mirroring_experiment_report(
        "rp-1",
        hours=24,
        request_tag="canary",
        environment="prod",
        limit=10,
        offset=0,
    )
    assert report["total_rows"] == 2
    client._get.assert_any_call(
        "/gateway/routes/rp-1/traffic-mirroring/experiment-report?hours=24&limit=10&offset=0&request_tag=canary&environment=prod"
    )
    simulated = client.simulate_route_fallback(
        "rp-1",
        tenant_id="t1",
        environment="prod",
        request_tag="canary",
        simulate_fail_provider_ids='["p1"]',
    )
    assert simulated["final_outcome"] == "selected"
    client._post.assert_any_call(
        "/gateway/routes/rp-1/simulate-fallback",
        {
            "tenant_id": "t1",
            "environment": "prod",
            "simulate_fail_provider_ids": '["p1"]',
            "request_tag": "canary",
        },
    )


def test_sdk_canary_stop_and_promote_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "status": "stopped"},
            {"route_policy_id": "rp-1", "status": "promoted"},
        ]
    )
    stopped = client.stop_route_canary_rollout("rp-1", request_tag="canary", notes="halt")
    assert stopped["status"] == "stopped"
    client._post.assert_any_call(
        "/gateway/routes/rp-1/canary-rollout/stop?request_tag=canary",
        {"notes": "halt"},
    )
    promoted = client.promote_route_canary_rollout("rp-1", notes="ship it")
    assert promoted["status"] == "promoted"
    client._post.assert_any_call(
        "/gateway/routes/rp-1/canary-rollout/promote",
        {"notes": "ship it"},
    )


def test_sdk_optimize_and_execute_fallback_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "optimize_for": "cost", "updated": True},
            {"route_policy_id": "rp-1", "final_outcome": "selected", "fallback_hops_used": 1},
        ]
    )
    optimized = client.optimize_route("rp-1", optimize_for="cost", environment="dev")
    assert optimized["updated"] is True
    client._post.assert_any_call(
        "/gateway/routes/rp-1/optimize",
        {"optimize_for": "cost", "environment": "dev"},
    )
    executed = client.execute_route_fallback(
        "rp-1",
        tenant_id="t1",
        agent_id="a1",
        environment="dev",
        request_tag="canary",
        simulate_fail_provider_ids='["p1"]',
    )
    assert executed["final_outcome"] == "selected"
    client._post.assert_any_call(
        "/gateway/routes/rp-1/execute-fallback",
        {
            "tenant_id": "t1",
            "agent_id": "a1",
            "environment": "dev",
            "request_priority": "normal",
            "session_id": "gateway-session",
            "endpoint_family": "responses",
            "input_tokens": 100,
            "output_tokens": 50,
            "currency": "USD",
            "simulate_fail_provider_ids": '["p1"]',
            "request_tag": "canary",
        },
    )


def test_sdk_access_review_create_and_jit_request_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"campaign_id": "garc-1", "status": "open", "total_items": 3},
            {"request_id": "gjit-1", "status": "pending", "entitlement_id": "ent-1"},
        ]
    )
    campaign = client.create_access_review_campaign(
        campaign_name="Q3 review",
        tenant_id="t1",
        environment="dev",
        include_disabled=True,
    )
    assert campaign["campaign_id"] == "garc-1"
    client._post.assert_any_call(
        "/gateway/access-reviews/campaigns",
        {
            "campaign_name": "Q3 review",
            "environment": "dev",
            "include_disabled": True,
            "reviewer_role": "Security Approver",
            "tenant_id": "t1",
        },
    )
    jit = client.create_jit_access_request(
        entitlement_id="ent-1",
        justification="Need temporary elevate",
        environment="dev",
        requested_duration_minutes=30,
    )
    assert jit["request_id"] == "gjit-1"
    client._post.assert_any_call(
        "/gateway/jit-requests",
        {
            "entitlement_id": "ent-1",
            "justification": "Need temporary elevate",
            "environment": "dev",
            "requested_duration_minutes": 30,
        },
    )


def test_sdk_jit_approve_and_least_privilege_apply_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"request_id": "gjit-1", "status": "approved"},
            {"recommendation_id": "lpr-1", "status": "applied"},
        ]
    )
    approved = client.approve_jit_access_request(
        "gjit-1",
        decision="approve",
        decision_reason="time-boxed access",
    )
    assert approved["status"] == "approved"
    client._post.assert_any_call(
        "/gateway/jit-requests/gjit-1/approve",
        {"decision": "approve", "decision_reason": "time-boxed access"},
    )
    applied = client.apply_least_privilege_recommendation(
        "lpr-1",
        decision_reason="remove unused role",
        change_ticket_id="CHG-9",
        review_evidence_uri="https://evidence.example/lpr-1",
    )
    assert applied["status"] == "applied"
    client._post.assert_any_call(
        "/gateway/least-privilege/recommendations/lpr-1/apply",
        {
            "decision_reason": "remove unused role",
            "change_ticket_id": "CHG-9",
            "review_evidence_uri": "https://evidence.example/lpr-1",
        },
    )


def test_sdk_system_instructions_and_rules_update_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._put = MagicMock(
        side_effect=[
            {"config_key": "gateway.system_instructions", "instructions": "Be precise."},
            {"config_key": "gateway.system_rules_json", "rules": [{"id": "r1"}]},
        ]
    )
    instructions = client.update_system_instructions(instructions="Be precise.")
    assert instructions["instructions"] == "Be precise."
    client._put.assert_any_call(
        "/gateway/system-instructions",
        {"instructions": "Be precise."},
    )
    rules = client.update_system_rules(rules=[{"id": "r1"}])
    assert rules["rules"][0]["id"] == "r1"
    client._put.assert_any_call(
        "/gateway/system-rules",
        {"rules": [{"id": "r1"}]},
    )


def test_sdk_external_callbacks_cursor_binding_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            [{"callback_id": "cb-1", "enabled": True}],
            {"configured": True, "secret_provider_id": "sp-1", "masked_hint": "***abc"},
        ]
    )
    callbacks = client.list_external_callbacks()
    assert callbacks[0]["callback_id"] == "cb-1"
    client._get.assert_any_call("/gateway/external-callbacks")
    binding = client.get_cursor_secret_binding()
    assert binding["configured"] is True
    assert "masked_hint" in binding
    client._get.assert_any_call("/gateway/cursor-secret-binding")


def test_sdk_system_instructions_rules_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"instructions": "Be helpful.", "config_key": "gateway.system_instructions"},
            {"rules": [{"id": "r1"}], "config_key": "gateway.system_rules_json"},
        ]
    )
    instructions = client.get_system_instructions()
    assert instructions["instructions"] == "Be helpful."
    client._get.assert_any_call("/gateway/system-instructions")
    rules = client.get_system_rules()
    assert rules["rules"][0]["id"] == "r1"
    client._get.assert_any_call("/gateway/system-rules")


def test_sdk_nhi_inventory_tunnel_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            [{"identity_id": "nhi-1", "status": "active"}],
            {"enabled": True, "openai_compatible_base": "/gateway/v1"},
        ]
    )
    inventory = client.list_nhi_inventory(limit=20, offset=0, stale_only=False)
    assert inventory[0]["identity_id"] == "nhi-1"
    client._get.assert_any_call(
        "/gateway/nhi/inventory?limit=20&offset=0&max_credential_age_days=90&stale_only=false"
    )
    tunnel = client.get_tunnel_config()
    assert tunnel["enabled"] is True
    client._get.assert_any_call("/gateway/tunnel/config")


def test_sdk_entitlements_nhi_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            [{"entitlement_id": "ent-1", "enabled": True}],
            {"stale_count": 2, "high_risk_count": 1, "total_count": 10},
        ]
    )
    entitlements = client.list_entitlements(enabled=True, limit=20, offset=0)
    assert entitlements[0]["entitlement_id"] == "ent-1"
    client._get.assert_any_call("/gateway/entitlements?limit=20&offset=0&enabled=true")
    hygiene = client.get_nhi_hygiene(max_credential_age_days=90)
    assert hygiene["stale_count"] == 2
    client._get.assert_any_call("/gateway/nhi/hygiene?max_credential_age_days=90")


def test_sdk_upsert_entitlement_path():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._put = MagicMock(
        return_value={"entitlement_id": "ent-1", "action": "chat.completions", "enabled": True}
    )
    upserted = client.upsert_entitlement(
        "ent-1",
        action="chat.completions",
        tenant_id="t1",
        environment="dev",
        allowed_roles='["admin"]',
        enabled=True,
    )
    assert upserted["entitlement_id"] == "ent-1"
    client._put.assert_called_once_with(
        "/gateway/entitlements/ent-1",
        {
            "action": "chat.completions",
            "environment": "dev",
            "allowed_roles": '["admin"]',
            "enabled": True,
            "tenant_id": "t1",
        },
    )


def test_sdk_upsert_traffic_mirroring_and_canary_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._put = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "enabled": True, "max_live_attempts": 2},
            {"route_policy_id": "rp-1", "status": "active", "enabled": True},
        ]
    )
    mirroring = client.upsert_route_traffic_mirroring(
        "rp-1",
        tenant_id="t1",
        environment="dev",
        mirror_targets='[{"provider_id":"p2"}]',
        enabled=True,
        max_live_attempts=2,
    )
    assert mirroring["enabled"] is True
    client._put.assert_any_call(
        "/gateway/routes/rp-1/traffic-mirroring",
        {
            "tenant_id": "t1",
            "environment": "dev",
            "mirror_targets": '[{"provider_id":"p2"}]',
            "enabled": True,
            "max_live_attempts": 2,
        },
    )
    canary = client.upsert_route_canary_rollout(
        "rp-1",
        tenant_id="t1",
        baseline_provider_id="p1",
        environment="dev",
        canary_targets='[{"provider_id":"p2","traffic_percent":10}]',
        enabled=True,
    )
    assert canary["status"] == "active"
    client._put.assert_any_call(
        "/gateway/routes/rp-1/canary-rollout",
        {
            "tenant_id": "t1",
            "environment": "dev",
            "baseline_provider_id": "p1",
            "canary_targets": '[{"provider_id":"p2","traffic_percent":10}]',
            "cohort_request_tags": "[]",
            "cohort_owner_scopes": "[]",
            "enabled": True,
        },
    )


def test_sdk_upsert_fallbacks_and_pre_call_filters_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._put = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "max_fallback_hops": 3},
            {"route_policy_id": "rp-1", "enforce": True, "allowed_regions": '["us-east-1"]'},
        ]
    )
    fallbacks = client.upsert_route_fallbacks(
        "rp-1",
        tenant_id="t1",
        environment="dev",
        priority_order='["p1","p2"]',
        global_timeout_ms=5000,
        max_fallback_hops=3,
        health_check_enabled=True,
    )
    assert fallbacks["max_fallback_hops"] == 3
    client._put.assert_any_call(
        "/gateway/routes/rp-1/fallbacks",
        {
            "tenant_id": "t1",
            "environment": "dev",
            "priority_order": '["p1","p2"]',
            "global_timeout_ms": 5000,
            "max_fallback_hops": 3,
            "health_check_enabled": True,
        },
    )
    filters = client.upsert_route_pre_call_filters(
        "rp-1",
        tenant_id="t1",
        environment="dev",
        allowed_regions='["us-east-1"]',
        min_context_window_tokens=1000,
        max_context_window_tokens=128000,
        enforce=True,
    )
    assert filters["enforce"] is True
    client._put.assert_any_call(
        "/gateway/routes/rp-1/pre-call-filters",
        {
            "tenant_id": "t1",
            "environment": "dev",
            "allowed_regions": '["us-east-1"]',
            "enforce": True,
            "min_context_window_tokens": 1000,
            "max_context_window_tokens": 128000,
        },
    )


def test_sdk_upsert_input_policy_and_output_guardrails_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._put = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "policy_mode": "block", "enforce": True},
            {"route_policy_id": "rp-1", "policy_mode": "warn", "enforce": True},
        ]
    )
    input_policy = client.upsert_route_input_data_policy(
        "rp-1",
        tenant_id="t1",
        environment="dev",
        policy_mode="block",
        data_classes='["pii"]',
        block_patterns='["ssn"]',
        enforce=True,
    )
    assert input_policy["policy_mode"] == "block"
    client._put.assert_any_call(
        "/gateway/routes/rp-1/input-data-policy",
        {
            "tenant_id": "t1",
            "environment": "dev",
            "policy_mode": "block",
            "data_classes": '["pii"]',
            "block_patterns": '["ssn"]',
            "mask_token": "[REDACTED]",
            "enforce": True,
        },
    )
    output_policy = client.upsert_route_output_guardrails(
        "rp-1",
        tenant_id="t1",
        environment="dev",
        policy_mode="warn",
        blocked_phrases='["secret"]',
        max_output_tokens=2048,
        enforce=True,
    )
    assert output_policy["enforce"] is True
    client._put.assert_any_call(
        "/gateway/routes/rp-1/output-guardrails",
        {
            "tenant_id": "t1",
            "environment": "dev",
            "policy_mode": "warn",
            "blocked_phrases": '["secret"]',
            "redact_phrases": "[]",
            "enforce": True,
            "max_output_tokens": 2048,
        },
    )


def test_sdk_upsert_provider_priority_and_create_cache_policy_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"route_policy_id": "rp-1", "updated": True, "max_fallback_hops": 2},
            {"cache_policy_id": "cp-1", "scope": "tenant:t1", "status": "active"},
        ]
    )
    priority = client.upsert_route_provider_priority(
        "rp-1",
        tenant_id="t1",
        environment="dev",
        priority_order='["p1","p2"]',
        global_timeout_ms=4500,
        max_fallback_hops=2,
        health_check_enabled=True,
    )
    assert priority["updated"] is True
    client._post.assert_any_call(
        "/gateway/routes/rp-1/providers/priority",
        {
            "tenant_id": "t1",
            "environment": "dev",
            "priority_order": '["p1","p2"]',
            "global_timeout_ms": 4500,
            "max_fallback_hops": 2,
            "health_check_enabled": True,
        },
    )
    created = client.create_cache_policy(scope="tenant:t1", ttl_seconds=120, cache_mode="exact")
    assert created["cache_policy_id"] == "cp-1"
    client._post.assert_any_call(
        "/gateway/cache/policies",
        {
            "scope": "tenant:t1",
            "ttl_seconds": 120,
            "key_strategy": "default",
            "invalidation_strategy": "ttl",
            "privacy_mode": "standard",
            "privacy_scope": "tenant",
            "non_cache_data_classes": "[]",
            "cache_mode": "exact",
            "similarity_threshold": 0.9,
        },
    )


def test_sdk_upsert_provider_health_path():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._put = MagicMock(
        return_value={
            "route_policy_id": "rp-1",
            "entries": [{"provider_id": "p1", "status": "healthy"}],
        }
    )
    health = client.upsert_route_provider_health(
        "rp-1",
        entries=[{"provider_id": "p1", "status": "healthy", "latency_ms": 120}],
    )
    assert health["entries"][0]["provider_id"] == "p1"
    client._put.assert_called_once_with(
        "/gateway/routes/rp-1/providers/health",
        {"entries": [{"provider_id": "p1", "status": "healthy", "latency_ms": 120}]},
    )


def test_sdk_invalidate_cache_and_create_budget_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"status": "ok", "purged_cache_entries": 3, "matching_policies": 1},
            {"budget_policy_id": "bp-1", "scope_type": "tenant", "status": "active"},
        ]
    )
    invalidated = client.invalidate_cache(scope="tenant:t1", reason="rotate", active_only=True)
    assert invalidated["purged_cache_entries"] == 3
    client._post.assert_any_call(
        "/gateway/cache/delete",
        {"cache_keys": [], "active_only": True, "scope": "tenant:t1", "reason": "rotate"},
    )
    created = client.create_budget_policy(
        scope_type="tenant",
        scope_id="t1",
        budget_amount_cents=10000,
        window_type="daily",
        rate_limit_rpm=60,
    )
    assert created["budget_policy_id"] == "bp-1"
    client._post.assert_any_call(
        "/cost/budgets",
        {
            "scope_type": "tenant",
            "scope_id": "t1",
            "budget_amount_cents": 10000,
            "window_type": "daily",
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
            "action_on_soft_limit": "warn",
            "action_on_hard_limit": "block",
            "reset_timezone": "UTC",
            "reset_hour_local": 0,
            "temporary_increase_cents": 0,
            "soft_alert_enabled": True,
            "rate_limit_rpm": 60,
        },
    )


def test_sdk_cursor_binding_and_budget_update_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._put = MagicMock(
        side_effect=[
            {"configured": True, "secret_provider_id": "sp-1"},
            {"budget_policy_id": "bp-1", "budget_amount_cents": 20000, "status": "active"},
        ]
    )
    client._delete = MagicMock(return_value={"configured": False})
    client._get = MagicMock(return_value=[{"budget_policy_id": "bp-1", "status": "active"}])

    updated = client.update_cursor_secret_binding(
        secret_provider_id="sp-1",
        secret_ref="vault://cursor/token",
    )
    assert updated["configured"] is True
    client._put.assert_any_call(
        "/gateway/cursor-secret-binding",
        {"secret_provider_id": "sp-1", "secret_ref": "vault://cursor/token"},
    )
    cleared = client.clear_cursor_secret_binding()
    assert cleared["configured"] is False
    client._delete.assert_called_once_with("/gateway/cursor-secret-binding")

    budgets = client.list_budget_policies(status="active", limit=20, offset=0)
    assert budgets[0]["budget_policy_id"] == "bp-1"
    client._get.assert_any_call("/cost/budgets?limit=20&offset=0&status=active")

    budget = client.update_budget_policy(
        "bp-1",
        scope_type="tenant",
        scope_id="t1",
        budget_amount_cents=20000,
        window_type="monthly",
    )
    assert budget["budget_amount_cents"] == 20000
    client._put.assert_any_call(
        "/cost/budgets/bp-1",
        {
            "scope_type": "tenant",
            "scope_id": "t1",
            "budget_amount_cents": 20000,
            "window_type": "monthly",
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
            "action_on_soft_limit": "warn",
            "action_on_hard_limit": "block",
            "reset_timezone": "UTC",
            "reset_hour_local": 0,
            "temporary_increase_cents": 0,
            "soft_alert_enabled": True,
        },
    )


def test_sdk_external_callback_create_and_budget_delete_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        return_value={"callback_id": "cb-1", "callback_url": "https://hooks.example/cb", "enabled": True}
    )
    client._delete = MagicMock(return_value={"budget_policy_id": "bp-1", "status": "deleted"})

    created = client.create_external_callback(
        callback_url="https://hooks.example/cb",
        event_types=["gateway.route.execute_fallback"],
        environment="prod",
        description="ops sink",
    )
    assert created["callback_id"] == "cb-1"
    client._post.assert_called_once_with(
        "/gateway/external-callbacks",
        {
            "callback_url": "https://hooks.example/cb",
            "event_types": ["gateway.route.execute_fallback"],
            "environment": "prod",
            "sink_type": "generic_webhook",
            "correlation_preset": "trace_resource",
            "redact_sensitive": True,
            "enabled": True,
            "description": "ops sink",
        },
    )
    deleted = client.delete_budget_policy("bp-1")
    assert deleted["status"] == "deleted"
    client._delete.assert_called_once_with("/cost/budgets/bp-1")


def test_sdk_external_callback_update_and_budget_evaluate_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._patch = MagicMock(return_value={"callback_id": "cb-1", "enabled": False})
    client._post = MagicMock(
        return_value={
            "scope_type": "tenant",
            "scope_id": "t1",
            "decision": "allow",
            "utilization_percent": 42.0,
        }
    )

    updated = client.update_external_callback("cb-1", enabled=False, environment="prod")
    assert updated["enabled"] is False
    client._patch.assert_called_once_with(
        "/gateway/external-callbacks/cb-1",
        {"environment": "prod", "enabled": False},
    )
    evaluated = client.evaluate_budget_policy(scope_type="tenant", scope_id="t1", window_type="daily")
    assert evaluated["decision"] == "allow"
    client._post.assert_called_once_with(
        "/cost/policies/evaluate",
        {"scope_type": "tenant", "scope_id": "t1", "window_type": "daily"},
    )


def test_sdk_external_callback_test_delivery_and_export_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {
                "callback_id": "cb-1",
                "delivery_status": "delivered_simulated",
                "redaction_applied": True,
            },
            {
                "export_id": "export-1",
                "callback_count": 2,
                "event_count": 5,
                "sink_distribution": {"generic_webhook": 2},
            },
        ]
    )

    tested = client.test_external_callback_delivery(
        "cb-1",
        environment="dev",
        sample_payload={"trace_id": "t-1", "secret": "redact-me"},
    )
    assert tested["delivery_status"] == "delivered_simulated"
    client._post.assert_any_call(
        "/gateway/external-callbacks/cb-1/test-delivery",
        {
            "environment": "dev",
            "sample_payload": {"trace_id": "t-1", "secret": "redact-me"},
        },
    )
    exported = client.export_external_callbacks(environment="dev", limit=25)
    assert exported["export_id"] == "export-1"
    client._post.assert_any_call(
        "/gateway/external-callbacks/export",
        {"limit": 25, "environment": "dev"},
    )


def test_sdk_virtual_key_create_and_governance_export_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"key_id": "vk-1", "status": "active", "owner_scope_type": "tenant"},
            {
                "export_id": "export-gov-1",
                "event_count": 3,
                "data_classification": "confidential",
                "redaction_applied": True,
            },
        ]
    )

    created = client.create_virtual_key(
        owner_scope_type="tenant",
        owner_scope_id="t1",
        allowed_models='["gpt-4o"]',
        authn_method="token",
    )
    assert created["key_id"] == "vk-1"
    client._post.assert_any_call(
        "/keys",
        {
            "owner_scope_type": "tenant",
            "owner_scope_id": "t1",
            "allowed_endpoint_families": "[]",
            "allowed_models": '["gpt-4o"]',
            "guardrail_policy": "{}",
            "budget_policy_id": "default",
            "rate_limit_policy_id": "default",
            "authn_method": "token",
        },
    )
    exported = client.export_gateway_governance_evidence(
        decision_outcome="allow",
        limit_per_action=50,
        redact_actor_login=True,
    )
    assert exported["export_id"] == "export-gov-1"
    client._post.assert_any_call(
        "/gateway/governance/evidence/export",
        {
            "limit_per_action": 50,
            "bundle_label": "gateway-governance-evidence",
            "data_classification": "confidential",
            "retention_days": 90,
            "approved_sharing_channels": ["security-ops", "compliance-review"],
            "redact_actor_login": True,
            "decision_outcome": "allow",
        },
    )


def test_sdk_virtual_key_update_and_guardrail_evaluate_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._patch = MagicMock(return_value={"key_id": "vk-1", "status": "disabled"})
    client._post = MagicMock(
        return_value={"key_id": "vk-1", "decision": "allow", "reasons": [], "applied_guardrails": ["rpm"]}
    )

    updated = client.update_virtual_key("vk-1", status="disabled", authn_method="oidc")
    assert updated["status"] == "disabled"
    client._patch.assert_called_once_with(
        "/keys/vk-1",
        {"status": "disabled", "authn_method": "oidc"},
    )
    evaluated = client.evaluate_key_guardrails(
        "vk-1",
        environment="dev",
        stage="input",
        requests_last_minute=12,
        input_tokens=100,
    )
    assert evaluated["decision"] == "allow"
    client._post.assert_called_once_with(
        "/keys/vk-1/guardrails/evaluate",
        {
            "environment": "dev",
            "stage": "input",
            "policy_mode": "block",
            "requests_last_minute": 12,
            "input_tokens": 100,
            "output_tokens": 0,
            "mfa_verified": False,
        },
    )


def test_sdk_key_rotation_schedule_create_and_list_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        return_value={"key_id": "vk-1", "schedule_id": "sch-1", "interval_hours": 24, "enabled": True}
    )
    client._get = MagicMock(return_value=[{"key_id": "vk-1", "schedule_id": "sch-1", "enabled": True}])

    created = client.create_key_rotation_schedule(
        "vk-1",
        environment="dev",
        interval_hours=24,
        reason="weekly-rotate",
    )
    assert created["schedule_id"] == "sch-1"
    client._post.assert_called_once_with(
        "/keys/vk-1/rotation-schedules",
        {
            "environment": "dev",
            "interval_hours": 24,
            "enabled": True,
            "reason": "weekly-rotate",
        },
    )
    listed = client.list_key_rotation_schedules("vk-1")
    assert listed[0]["schedule_id"] == "sch-1"
    client._get.assert_called_once_with("/keys/vk-1/rotation-schedules")


def test_sdk_key_rotation_schedule_update_and_execute_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._patch = MagicMock(return_value={"key_id": "vk-1", "schedule_id": "sch-1", "enabled": False})
    client._post = MagicMock(
        return_value={
            "key_id": "vk-1",
            "schedule_id": "sch-1",
            "rotation_status": "rotated",
            "environment": "dev",
        }
    )

    updated = client.update_key_rotation_schedule("vk-1", "sch-1", enabled=False, interval_hours=48)
    assert updated["enabled"] is False
    client._patch.assert_called_once_with(
        "/keys/vk-1/rotation-schedules/sch-1",
        {"interval_hours": 48, "enabled": False},
    )
    executed = client.execute_key_rotation_schedule_now("vk-1", "sch-1")
    assert executed["rotation_status"] == "rotated"
    client._post.assert_called_once_with("/keys/vk-1/rotation-schedules/sch-1/execute-now", {})


def test_sdk_key_rotation_schedule_tick_path():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        return_value={"scanned_keys": 2, "due_schedules": 1, "executed": [{"schedule_id": "sch-1"}], "skipped_prod": 0}
    )
    tick = client.tick_key_rotation_schedules(include_prod=False)
    assert tick["due_schedules"] == 1
    client._post.assert_called_once_with("/keys/rotation-schedules/tick?include_prod=false", {})


def test_sdk_packaging_manifests_exist():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    assert (root / "sdk" / "python" / "pyproject.toml").is_file()
    assert (root / "sdk" / "js" / "package.json").is_file()
    pkg = json.loads((root / "sdk" / "js" / "package.json").read_text(encoding="utf-8"))
    assert pkg["publishConfig"]["access"] == "public"
    assert (root / "sdk" / "js" / "src" / "index.d.ts").is_file()
    assert (root / ".github" / "workflows" / "sdk-publish-dry-run.yml").is_file()


def test_sdk_instrumenter_helpers():
    import sys
    from pathlib import Path

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    stamp = sdk_mod.create_gateway_request_instrumenter(
        session_id="s1", user="u1", properties={"plan": "pro"}
    )
    headers = stamp({"Accept": "application/json"})
    assert headers["x-session-id"] == "s1"
    assert headers["x-user"] == "u1"
    assert headers["x-property-plan"] == "pro"

    client = sdk_mod.AgentHubGateway(
        base_url="http://gateway.test",
        api_key="k",
        track_cost=False,
        session_id="s-ctor",
        user="u-ctor",
        properties={"tier": "gold"},
    )
    ctor_headers = client._headers()
    assert ctor_headers["x-session-id"] == "s-ctor"
    assert ctor_headers["x-user"] == "u-ctor"
    assert ctor_headers["x-property-tier"] == "gold"

    js = (Path(__file__).resolve().parents[2] / "sdk" / "js" / "src" / "index.js").read_text(encoding="utf-8")
    assert "export function createGatewayFetchInstrumenter" in js
    assert "wantsInstrument" in js


def test_sdk_virtual_key_block_unblock_and_rotate_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        side_effect=[
            {"key_id": "vk-1", "status": "blocked", "action": "blocked"},
            {"key_id": "vk-1", "status": "active", "action": "unblocked"},
            {"key_id": "vk-1", "rotation_status": "rotated"},
        ]
    )

    blocked = client.block_virtual_key("vk-1")
    assert blocked["action"] == "blocked"
    client._post.assert_any_call("/keys/vk-1/block", {})
    unblocked = client.unblock_virtual_key("vk-1")
    assert unblocked["action"] == "unblocked"
    client._post.assert_any_call("/keys/vk-1/unblock", {})
    rotated = client.rotate_virtual_key("vk-1", environment="staging")
    assert rotated["rotation_status"] == "rotated"
    client._post.assert_any_call("/keys/vk-1/rotate?environment=staging", {})


def test_sdk_key_budget_temporary_increase_path():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._post = MagicMock(
        return_value={
            "key_id": "vk-1",
            "increase_cents": 5000,
            "active": True,
            "environment": "dev",
        }
    )

    increased = client.increase_key_budget_temporary(
        "vk-1",
        increase_cents=5000,
        duration_minutes=120,
        reason="incident-burst",
    )
    assert increased["active"] is True
    client._post.assert_called_once_with(
        "/keys/vk-1/budget/increase-temporary",
        {
            "environment": "dev",
            "increase_cents": 5000,
            "duration_minutes": 120,
            "reason": "incident-burst",
        },
    )


def test_sdk_key_budget_temporary_get_and_create_route_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        return_value={
            "key_id": "vk-1",
            "increase_cents": 5000,
            "active": True,
            "environment": "dev",
        }
    )
    client._post = MagicMock(
        return_value={
            "route_policy_id": "rp-1",
            "route_name": "chat-primary",
            "status": "active",
        }
    )

    budget = client.get_key_budget_increase_temporary("vk-1")
    assert budget["active"] is True
    client._get.assert_called_once_with("/keys/vk-1/budget/increase-temporary")

    created = client.create_route(
        route_name="chat-primary",
        load_balancing_strategy="adaptive",
        candidate_deployments='["d1"]',
    )
    assert created["route_policy_id"] == "rp-1"
    client._post.assert_called_once_with(
        "/gateway/routes",
        {
            "route_name": "chat-primary",
            "candidate_deployments": '["d1"]',
            "load_balancing_strategy": "adaptive",
            "retry_policy": "{}",
            "fallback_policy": "{}",
            "timeout_policy": "{}",
        },
    )



def test_sdk_cost_anomalies_and_limits_evaluate_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        return_value=[
            {
                "anomaly_id": "a1",
                "anomaly_type": "budget_threshold_breach",
                "severity": "high",
                "scope_type": "team",
                "scope_id": "t1",
                "observed_cost_cents": 900,
                "threshold_cents": 800,
            }
        ]
    )
    client._post = MagicMock(
        return_value={
            "actor_id": "actor-1",
            "window_type": "daily",
            "aggregated_decision": "allow",
            "blocking_scopes": [],
            "soft_alert_scopes": [],
            "scopes_evaluated": [],
        }
    )

    anomalies = client.list_cost_anomalies()
    assert anomalies[0]["anomaly_id"] == "a1"
    client._get.assert_called_once_with("/cost/anomalies")

    decision = client.evaluate_cost_limits(
        actor_id="actor-1",
        team_ids=["t1"],
        window_type="daily",
        projected_additional_cost_cents=100,
    )
    assert decision["aggregated_decision"] == "allow"
    client._post.assert_called_once_with(
        "/cost/limits/evaluate",
        {
            "window_type": "daily",
            "projected_additional_cost_cents": 100,
            "team_ids": ["t1"],
            "group_ids": [],
            "agent_ids": [],
            "actor_id": "actor-1",
        },
    )



def test_sdk_cost_live_and_breakdown_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {
                "spend_last_hour_cents": 120,
                "spend_last_day_cents": 2400,
                "burn_rate_cents_per_hour": 100,
                "event_count_last_day": 42,
            },
            {
                "dimension": "user",
                "window_hours": 24,
                "items": [{"label": "alice", "spend_cents": 500}],
            },
        ]
    )

    live = client.get_cost_live()
    assert live["spend_last_hour_cents"] == 120
    breakdown = client.get_cost_breakdown(dimension="user", window_hours=24, limit=8)
    assert breakdown["dimension"] == "user"
    assert client._get.call_args_list[0].args[0] == "/cost/live"
    assert client._get.call_args_list[1].args[0].startswith("/cost/breakdown?")
    assert "dimension=user" in client._get.call_args_list[1].args[0]


def test_sdk_cost_export_path():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get_text = MagicMock(
        return_value="timestamp,cost_event_id,request_id\n2026-08-01T10:00:00,ce-1,req-1\n"
    )

    csv_text = client.export_cost(dimension="user", window_hours=24, limit=100, scope_filter="alice")
    assert csv_text.startswith("timestamp,")
    assert "ce-1" in csv_text
    path = client._get_text.call_args.args[0]
    assert path.startswith("/cost/export?")
    assert "dimension=user" in path
    assert "scope_filter=alice" in path
    assert "window_hours=24" in path



def test_sdk_observability_summary_and_trace_events_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"since_hours": 24, "event_count": 12, "deny_count": 1},
            {"trace_id": "tr-1", "event_count": 2, "events": [{"event_type": "audit"}]},
        ]
    )

    summary = client.get_observability_summary(since_hours=24)
    assert summary["event_count"] == 12
    events = client.get_trace_events("tr-1")
    assert events["trace_id"] == "tr-1"
    assert client._get.call_args_list[0].args[0].startswith("/observability/summary?")
    assert client._get.call_args_list[1].args[0] == "/observability/traces/tr-1/events"



def test_sdk_observability_logs_list_and_export_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        return_value=[{"trace_id": "tr-1", "action_type": "gateway.chat", "decision_outcome": "allow"}]
    )
    client._get_text = MagicMock(return_value="timestamp,actor_id,action_type\n2026-08-01T10:00:00,a1,gateway.chat\n")

    logs = client.list_observability_logs(since_hours=24, limit=10, action_type="gateway.chat")
    assert logs[0]["trace_id"] == "tr-1"
    assert client._get.call_args.args[0].startswith("/observability/logs?")
    assert "action_type=gateway.chat" in client._get.call_args.args[0]

    csv_text = client.export_observability_logs(format="csv", since_hours=24, limit=100, search="gateway")
    assert csv_text.startswith("timestamp,")
    export_path = client._get_text.call_args.args[0]
    assert export_path.startswith("/observability/logs/export?")
    assert "format=csv" in export_path
    assert "search=gateway" in export_path



def test_sdk_siem_rules_list_export_evaluate_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"rule_count": 2, "rules": [{"rule_id": "r1"}]},
            {"evaluated_count": 10, "matched_count": 1, "matches": [{"rule_id": "r1"}]},
        ]
    )
    client._post = MagicMock(
        return_value={"rule_count": 2, "rules": [{"rule_id": "r1"}], "siem_callback_count": 0}
    )

    listed = client.list_siem_rules()
    assert listed["rule_count"] == 2
    client._get.assert_any_call("/observability/siem-rules")

    exported = client.export_siem_rules()
    assert exported["rule_count"] == 2
    client._post.assert_called_once_with("/observability/siem-rules/export", {})

    evaluated = client.evaluate_siem_rules(limit=50, since_hours=24, action_type_prefix="gateway.")
    assert evaluated["matched_count"] == 1
    eval_path = client._get.call_args_list[-1].args[0]
    assert eval_path.startswith("/observability/siem-rules/evaluate?")
    assert "action_type_prefix=gateway." in eval_path



def test_sdk_observability_log_schema_status_path():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        return_value={"sample_size": 200, "field_count": 8, "status": "ok"}
    )

    status = client.get_observability_log_schema_status(sample_size=200)
    assert status["status"] == "ok"
    path = client._get.call_args.args[0]
    assert path.startswith("/observability/logs/schema-status?")
    assert "sample_size=200" in path



def test_sdk_cost_requests_and_session_tree_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "requests": [{"request_id": "req-1", "spend_cents": 12}]},
            {"count": 1, "nodes": [{"path": "/checkout", "spend_cents": 40}]},
        ]
    )

    requests = client.list_cost_requests(window_hours=24, user_id="u1", model="gpt-4o", limit=10)
    assert requests["count"] == 1
    req_path = client._get.call_args_list[0].args[0]
    assert req_path.startswith("/cost/requests?")
    assert "user_id=u1" in req_path
    assert "model=gpt-4o" in req_path

    tree = client.get_cost_session_tree(window_hours=24, path_prefix="/checkout", max_depth=3, limit=20)
    assert tree["count"] == 1
    tree_path = client._get.call_args_list[1].args[0]
    assert tree_path.startswith("/cost/sessions/tree?")
    assert "path_prefix=%2Fcheckout" in tree_path or "path_prefix=/checkout" in tree_path
    assert "max_depth=3" in tree_path




def test_sdk_cost_rollout_and_route_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"rollout": "rollout-blue", "spend_cents": 40}]},
            {"count": 1, "series": [{"route": "route-main", "spend_cents": 20}]},
        ]
    )

    rollouts = client.get_cost_rollout_timeseries(
        window_hours=24, rollout_filter="blue", top_rollouts=5
    )
    assert rollouts["count"] == 1
    r_path = client._get.call_args_list[0].args[0]
    assert r_path.startswith("/cost/rollouts/timeseries?")
    assert "rollout_filter=blue" in r_path
    assert "top_rollouts=5" in r_path

    routes = client.get_cost_route_timeseries(window_hours=12, route_filter="main", top_routes=4)
    assert routes["count"] == 1
    route_path = client._get.call_args_list[1].args[0]
    assert route_path.startswith("/cost/routes/timeseries?")
    assert "route_filter=main" in route_path
    assert "top_routes=4" in route_path




def test_sdk_cost_batch_and_job_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"batch": "batch-nightly", "spend_cents": 40}]},
            {"count": 1, "series": [{"job": "job-embed", "spend_cents": 20}]},
        ]
    )

    batches = client.get_cost_batch_timeseries(
        window_hours=24, batch_filter="nightly", top_batches=5
    )
    assert batches["count"] == 1
    b_path = client._get.call_args_list[0].args[0]
    assert b_path.startswith("/cost/batches/timeseries?")
    assert "batch_filter=nightly" in b_path
    assert "top_batches=5" in b_path

    jobs = client.get_cost_job_timeseries(window_hours=12, job_filter="embed", top_jobs=4)
    assert jobs["count"] == 1
    j_path = client._get.call_args_list[1].args[0]
    assert j_path.startswith("/cost/jobs/timeseries?")
    assert "job_filter=embed" in j_path
    assert "top_jobs=4" in j_path




def test_sdk_cost_queue_and_topic_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"queue": "queue-ingest", "spend_cents": 40}]},
            {"count": 1, "series": [{"topic": "topic-events", "spend_cents": 20}]},
        ]
    )

    queues = client.get_cost_queue_timeseries(
        window_hours=24, queue_filter="ingest", top_queues=5
    )
    assert queues["count"] == 1
    q_path = client._get.call_args_list[0].args[0]
    assert q_path.startswith("/cost/queues/timeseries?")
    assert "queue_filter=ingest" in q_path
    assert "top_queues=5" in q_path

    topics = client.get_cost_topic_timeseries(window_hours=12, topic_filter="events", top_topics=4)
    assert topics["count"] == 1
    t_path = client._get.call_args_list[1].args[0]
    assert t_path.startswith("/cost/topics/timeseries?")
    assert "topic_filter=events" in t_path
    assert "top_topics=4" in t_path




def test_sdk_cost_pipeline_and_run_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"pipeline": "pipeline-etl", "spend_cents": 40}]},
            {"count": 1, "series": [{"run": "run-42", "spend_cents": 20}]},
        ]
    )

    pipelines = client.get_cost_pipeline_timeseries(
        window_hours=24, pipeline_filter="etl", top_pipelines=5
    )
    assert pipelines["count"] == 1
    p_path = client._get.call_args_list[0].args[0]
    assert p_path.startswith("/cost/pipelines/timeseries?")
    assert "pipeline_filter=etl" in p_path
    assert "top_pipelines=5" in p_path

    runs = client.get_cost_run_timeseries(window_hours=12, run_filter="42", top_runs=4)
    assert runs["count"] == 1
    r_path = client._get.call_args_list[1].args[0]
    assert r_path.startswith("/cost/runs/timeseries?")
    assert "run_filter=42" in r_path
    assert "top_runs=4" in r_path


def test_sdk_cost_worker_and_slot_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"worker": "worker-a", "spend_cents": 40}]},
            {"count": 1, "series": [{"slot": "slot-7", "spend_cents": 20}]},
        ]
    )

    workers = client.get_cost_worker_timeseries(
        window_hours=24, worker_filter="worker", top_workers=5
    )
    assert workers["count"] == 1
    w_path = client._get.call_args_list[0].args[0]
    assert w_path.startswith("/cost/workers/timeseries?")
    assert "worker_filter=worker" in w_path
    assert "top_workers=5" in w_path

    slots = client.get_cost_slot_timeseries(window_hours=12, slot_filter="slot", top_slots=4)
    assert slots["count"] == 1
    s_path = client._get.call_args_list[1].args[0]
    assert s_path.startswith("/cost/slots/timeseries?")
    assert "slot_filter=slot" in s_path
    assert "top_slots=4" in s_path




def test_sdk_cost_task_and_step_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"task": "task-embed", "spend_cents": 40}]},
            {"count": 1, "series": [{"step": "step-ingest", "spend_cents": 20}]},
        ]
    )

    tasks = client.get_cost_task_timeseries(
        window_hours=24, task_filter="embed", top_tasks=5
    )
    assert tasks["count"] == 1
    t_path = client._get.call_args_list[0].args[0]
    assert t_path.startswith("/cost/tasks/timeseries?")
    assert "task_filter=embed" in t_path
    assert "top_tasks=5" in t_path

    steps = client.get_cost_step_timeseries(window_hours=12, step_filter="ingest", top_steps=4)
    assert steps["count"] == 1
    s_path = client._get.call_args_list[1].args[0]
    assert s_path.startswith("/cost/steps/timeseries?")
    assert "step_filter=ingest" in s_path
    assert "top_steps=4" in s_path


def test_sdk_cost_replica_and_shard_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"replica": "replica-a", "spend_cents": 40}]},
            {"count": 1, "series": [{"shard": "shard-3", "spend_cents": 20}]},
        ]
    )

    replicas = client.get_cost_replica_timeseries(
        window_hours=24, replica_filter="replica", top_replicas=5
    )
    assert replicas["count"] == 1
    r_path = client._get.call_args_list[0].args[0]
    assert r_path.startswith("/cost/replicas/timeseries?")
    assert "replica_filter=replica" in r_path
    assert "top_replicas=5" in r_path

    shards = client.get_cost_shard_timeseries(window_hours=12, shard_filter="shard", top_shards=4)
    assert shards["count"] == 1
    s_path = client._get.call_args_list[1].args[0]
    assert s_path.startswith("/cost/shards/timeseries?")
    assert "shard_filter=shard" in s_path
    assert "top_shards=4" in s_path




def test_sdk_cost_partition_and_consumer_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"partition": "part-0", "spend_cents": 40}]},
            {"count": 1, "series": [{"consumer": "consumer-a", "spend_cents": 20}]},
        ]
    )

    partitions = client.get_cost_partition_timeseries(
        window_hours=24, partition_filter="part", top_partitions=5
    )
    assert partitions["count"] == 1
    p_path = client._get.call_args_list[0].args[0]
    assert p_path.startswith("/cost/partitions/timeseries?")
    assert "partition_filter=part" in p_path
    assert "top_partitions=5" in p_path

    consumers = client.get_cost_consumer_timeseries(
        window_hours=12, consumer_filter="consumer", top_consumers=4
    )
    assert consumers["count"] == 1
    c_path = client._get.call_args_list[1].args[0]
    assert c_path.startswith("/cost/consumers/timeseries?")
    assert "consumer_filter=consumer" in c_path
    assert "top_consumers=4" in c_path


def test_sdk_cost_producer_and_gpu_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"producer": "producer-a", "spend_cents": 40}]},
            {"count": 1, "series": [{"gpu": "gpu-0", "spend_cents": 20}]},
        ]
    )

    producers = client.get_cost_producer_timeseries(
        window_hours=24, producer_filter="producer", top_producers=5
    )
    assert producers["count"] == 1
    p_path = client._get.call_args_list[0].args[0]
    assert p_path.startswith("/cost/producers/timeseries?")
    assert "producer_filter=producer" in p_path
    assert "top_producers=5" in p_path

    gpus = client.get_cost_gpu_timeseries(window_hours=12, gpu_filter="gpu", top_gpus=4)
    assert gpus["count"] == 1
    g_path = client._get.call_args_list[1].args[0]
    assert g_path.startswith("/cost/gpus/timeseries?")
    assert "gpu_filter=gpu" in g_path
    assert "top_gpus=4" in g_path




def test_sdk_cost_accelerator_and_cell_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"accelerator": "accel-a", "spend_cents": 40}]},
            {"count": 1, "series": [{"cell": "cell-east", "spend_cents": 20}]},
        ]
    )

    accelerators = client.get_cost_accelerator_timeseries(
        window_hours=24, accelerator_filter="accel", top_accelerators=5
    )
    assert accelerators["count"] == 1
    a_path = client._get.call_args_list[0].args[0]
    assert a_path.startswith("/cost/accelerators/timeseries?")
    assert "accelerator_filter=accel" in a_path
    assert "top_accelerators=5" in a_path

    cells = client.get_cost_cell_timeseries(window_hours=12, cell_filter="cell", top_cells=4)
    assert cells["count"] == 1
    c_path = client._get.call_args_list[1].args[0]
    assert c_path.startswith("/cost/cells/timeseries?")
    assert "cell_filter=cell" in c_path
    assert "top_cells=4" in c_path


def test_sdk_cost_zone_and_rack_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"zone": "zone-a", "spend_cents": 40}]},
            {"count": 1, "series": [{"rack": "rack-12", "spend_cents": 20}]},
        ]
    )

    zones = client.get_cost_zone_timeseries(
        window_hours=24, zone_filter="zone", top_zones=5
    )
    assert zones["count"] == 1
    z_path = client._get.call_args_list[0].args[0]
    assert z_path.startswith("/cost/zones/timeseries?")
    assert "zone_filter=zone" in z_path
    assert "top_zones=5" in z_path

    racks = client.get_cost_rack_timeseries(window_hours=12, rack_filter="rack", top_racks=4)
    assert racks["count"] == 1
    r_path = client._get.call_args_list[1].args[0]
    assert r_path.startswith("/cost/racks/timeseries?")
    assert "rack_filter=rack" in r_path
    assert "top_racks=4" in r_path




def test_sdk_cost_pool_and_fleet_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"pool": "pool-gpu", "spend_cents": 40}]},
            {"count": 1, "series": [{"fleet": "fleet-edge", "spend_cents": 20}]},
        ]
    )

    pools = client.get_cost_pool_timeseries(
        window_hours=24, pool_filter="pool", top_pools=5
    )
    assert pools["count"] == 1
    p_path = client._get.call_args_list[0].args[0]
    assert p_path.startswith("/cost/pools/timeseries?")
    assert "pool_filter=pool" in p_path
    assert "top_pools=5" in p_path

    fleets = client.get_cost_fleet_timeseries(window_hours=12, fleet_filter="fleet", top_fleets=4)
    assert fleets["count"] == 1
    f_path = client._get.call_args_list[1].args[0]
    assert f_path.startswith("/cost/fleets/timeseries?")
    assert "fleet_filter=fleet" in f_path
    assert "top_fleets=4" in f_path


def test_sdk_cost_lease_and_quota_timeseries_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"count": 1, "series": [{"lease": "lease-a", "spend_cents": 40}]},
            {"count": 1, "series": [{"quota": "quota-rpm", "spend_cents": 20}]},
        ]
    )

    leases = client.get_cost_lease_timeseries(
        window_hours=24, lease_filter="lease", top_leases=5
    )
    assert leases["count"] == 1
    l_path = client._get.call_args_list[0].args[0]
    assert l_path.startswith("/cost/leases/timeseries?")
    assert "lease_filter=lease" in l_path
    assert "top_leases=5" in l_path

    quotas = client.get_cost_quota_timeseries(window_hours=12, quota_filter="quota", top_quotas=4)
    assert quotas["count"] == 1
    q_path = client._get.call_args_list[1].args[0]
    assert q_path.startswith("/cost/quotas/timeseries?")
    assert "quota_filter=quota" in q_path
    assert "top_quotas=4" in q_path



def test_sdk_notification_vector_registry_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            {"object": "list", "data": [{"channel_id": "ops-email", "enabled": True}]},
            {"object": "list", "data": [{"store_id": "vs-gw-1", "provider": "qdrant"}]},
        ]
    )
    channels = client.list_notification_channels()
    assert channels[0]["channel_id"] == "ops-email"
    client._get.assert_any_call("/gateway/notification-channels")
    stores = client.list_gateway_vector_stores()
    assert stores[0]["store_id"] == "vs-gw-1"
    client._get.assert_any_call("/gateway/vector-stores")


def test_sdk_mcp_compatibility_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            [{"server_id": "mcp-1", "name": "tools"}],
            {"status": "pass", "supported_families": ["chat.completions", "mcp"]},
        ]
    )
    servers = client.list_mcp_servers()
    assert servers[0]["server_id"] == "mcp-1"
    client._get.assert_any_call("/gateway/mcp/servers")
    compat = client.get_endpoints_compatibility()
    assert compat["status"] == "pass"
    client._get.assert_any_call("/gateway/endpoints/compatibility")


def test_sdk_cache_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k", track_cost=False)
    client._get = MagicMock(
        side_effect=[
            [{"cache_policy_id": "cp-1", "status": "active"}],
            {"hit_ratio": 0.5, "hits": 10, "misses": 10},
            {"status": "healthy", "active_policies": 1},
            [{"cache_entry_id": "ce-1", "status": "active"}],
            [{"decision": "miss", "trace_id": "t-1"}],
        ]
    )
    policies = client.list_cache_policies(status="active", limit=20, offset=0)
    assert policies[0]["cache_policy_id"] == "cp-1"
    client._get.assert_any_call("/gateway/cache/policies?limit=20&offset=0&status=active")
    stats = client.get_cache_stats()
    assert stats["hits"] == 10
    client._get.assert_any_call("/gateway/cache/stats")
    health = client.get_cache_health()
    assert health["status"] == "healthy"
    client._get.assert_any_call("/gateway/cache/health")
    entries = client.list_cache_entries(status="active", limit=20, offset=0)
    assert entries[0]["cache_entry_id"] == "ce-1"
    client._get.assert_any_call("/gateway/cache/entries?limit=20&offset=0&status=active")
    decisions = client.list_cache_decisions(decision="miss", limit=20, offset=0)
    assert decisions[0]["decision"] == "miss"
    client._get.assert_any_call("/gateway/cache/decisions?limit=20&offset=0&decision=miss")


def test_sdk_log_export_job_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._post = MagicMock(
        side_effect=[
            {"id": "lexp-1", "status": "pending", "object": "logs.export"},
            {"id": "lexp-1", "status": "completed", "row_count": 2},
            {"id": "lexp-1", "status": "cancelled", "row_count": 0},
        ]
    )
    client._get = MagicMock(
        side_effect=[
            {"object": "list", "data": [{"id": "lexp-1", "status": "pending"}], "count": 1},
            {"id": "lexp-1", "status": "pending"},
            {"id": "lexp-1", "status": "completed", "content": '{"id":"req-1"}\n', "row_count": 1},
        ]
    )
    client._delete = MagicMock(return_value={"id": "lexp-1", "deleted": True, "object": "logs.export.deleted"})

    created = client.create_log_export(
        filters={"window_hours": 24, "limit": 100},
        requested_data=["id", "ai_model", "request"],
        description="parity",
    )
    assert created["id"] == "lexp-1"
    client._post.assert_any_call(
        "/v1/logs/exports",
        {
            "filters": {"window_hours": 24, "limit": 100},
            "requested_data": ["id", "ai_model", "request"],
            "description": "parity",
        },
    )
    listed = client.list_log_exports(limit=10, offset=0, status="pending")
    assert listed[0]["id"] == "lexp-1"
    client._get.assert_any_call("/v1/logs/exports?limit=10&offset=0&status=pending")
    got = client.get_log_export("lexp-1")
    assert got["status"] == "pending"
    started = client.start_log_export("lexp-1")
    assert started["status"] == "completed"
    client._post.assert_any_call("/v1/logs/exports/lexp-1/start", {})
    downloaded = client.download_log_export("lexp-1")
    assert downloaded["row_count"] == 1
    client._get.assert_any_call("/v1/logs/exports/lexp-1/download")
    cancelled = client.cancel_log_export("lexp-1")
    assert cancelled["status"] == "cancelled"
    client._post.assert_any_call("/v1/logs/exports/lexp-1/cancel", {})
    deleted = client.delete_log_export("lexp-1")
    assert deleted["deleted"] is True
    client._delete.assert_called_once_with("/v1/logs/exports/lexp-1")


def test_serialize_guardrail_config_helper():
    from types import SimpleNamespace

    key = SimpleNamespace(
        key_id="vk-g1",
        status="active",
        owner_scope_type="user",
        owner_scope_id="u1",
        guardrail_policy='{"policy_mode":"block","max_requests_per_minute":60,"input_stages":["input"]}',
    )
    item = gateway_router._serialize_guardrail_config(key)
    assert item.guardrail_id == "vk-g1"
    assert item.has_policy is True
    assert item.policy_mode == "block"
    assert item.policy["max_requests_per_minute"] == 60

    empty = gateway_router._serialize_guardrail_config(
        SimpleNamespace(
            key_id="vk-empty",
            status="active",
            owner_scope_type="user",
            owner_scope_id="u1",
            guardrail_policy="{}",
        )
    )
    assert empty.has_policy is False


def test_sdk_list_and_get_prompts_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._get = MagicMock(side_effect=[
        [{"prompt_registry_id": "p-1", "name": "Support"}],
        {"prompt_registry_id": "p-1", "name": "Support", "prompt_text": "Hello {{name}}"},
    ])
    listed = client.list_prompts(limit=10, offset=0)
    assert listed[0]["prompt_registry_id"] == "p-1"
    client._get.assert_any_call("/v1/prompts?limit=10&offset=0")
    got = client.get_prompt("p-1")
    assert got["name"] == "Support"
    client._get.assert_any_call("/v1/prompts/p-1")
    client._get = MagicMock(return_value=[{"prompt_registry_id": "p-2", "name": "Support Ops"}])
    searched = client.list_prompts(limit=5, offset=0, q="support")
    assert searched[0]["name"] == "Support Ops"
    client._get.assert_called_with("/v1/prompts?limit=5&offset=0&q=support")


def test_sdk_list_and_get_virtual_keys_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._get = MagicMock(
        side_effect=[
            [{"key_id": "vk-1", "status": "active"}],
            {"key_id": "vk-1", "status": "active", "authn_method": "token"},
            {"key_id": "vk-1", "requests_last_24h": 12, "status": "active"},
            {
                "hours": 24,
                "total_events": 3,
                "total_estimated_cost_cents": 40,
                "top_models": [{"model_name": "gpt-4o-mini", "events": 2}],
            },
        ]
    )
    listed = client.list_virtual_keys(limit=10, offset=0)
    assert listed[0]["key_id"] == "vk-1"
    client._get.assert_any_call("/v1/virtual-keys?limit=10&offset=0")
    got = client.get_virtual_key("vk-1")
    assert got["status"] == "active"
    client._get.assert_any_call("/v1/virtual-keys/vk-1")
    usage = client.get_virtual_key_usage("vk-1")
    assert usage["requests_last_24h"] == 12
    client._get.assert_any_call("/v1/virtual-keys/vk-1/usage")
    analytics = client.get_analytics(hours=24, environment="prod")
    assert analytics["total_events"] == 3
    client._get.assert_any_call("/v1/analytics?hours=24&environment=prod")


def test_sdk_list_and_get_configs_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._get = MagicMock(
        side_effect=[
            [{"route_policy_id": "cfg-1", "route_name": "default"}],
            {"route_policy_id": "cfg-1", "route_name": "default", "status": "active"},
        ]
    )
    listed = client.list_configs(limit=10, offset=0)
    assert listed[0]["route_policy_id"] == "cfg-1"
    client._get.assert_any_call("/v1/configs?limit=10&offset=0")
    got = client.get_config("cfg-1")
    assert got["status"] == "active"
    client._get.assert_any_call("/v1/configs/cfg-1")


def test_sdk_list_and_get_guardrails_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._get = MagicMock(
        side_effect=[
            [{"guardrail_id": "vk-1", "has_policy": True, "policy_mode": "block"}],
            {"guardrail_id": "vk-1", "has_policy": True, "policy": {"policy_mode": "block"}},
        ]
    )
    listed = client.list_guardrails(limit=10, offset=0, has_policy=True)
    assert listed[0]["guardrail_id"] == "vk-1"
    client._get.assert_any_call("/v1/guardrails?limit=10&offset=0&has_policy=true")
    got = client.get_guardrail("vk-1")
    assert got["has_policy"] is True
    client._get.assert_any_call("/v1/guardrails/vk-1")


def test_sdk_list_and_get_models_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._get = MagicMock(
        side_effect=[
            {"object": "list", "data": [{"id": "gpt-4o-mini", "owned_by": "openai"}], "count": 1},
            {"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"},
        ]
    )
    listed = client.list_models(limit=10, offset=0)
    assert listed[0]["id"] == "gpt-4o-mini"
    client._get.assert_any_call("/v1/models?limit=10&offset=0")
    got = client.get_model("gpt-4o-mini")
    assert got["owned_by"] == "openai"
    client._get.assert_any_call("/v1/models/gpt-4o-mini")


def test_sdk_render_prompt_path():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._post = MagicMock(
        return_value={
            "prompt_registry_id": "p-1",
            "rendered": "Hello Ada",
            "variables_detected": ["name"],
            "missing_variables": [],
        }
    )
    rendered = client.render_prompt("p-1", variables={"name": "Ada"}, require_all_variables=True)
    assert rendered["rendered"] == "Hello Ada"
    client._post.assert_called_once_with(
        "/v1/prompts/p-1/render",
        {"variables": {"name": "Ada"}, "require_all_variables": True},
    )


def test_sdk_promote_prompt_path():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._post = MagicMock(
        return_value={
            "promotion_recorded": True,
            "target_environment": "staging",
            "render_preview": "Hello",
        }
    )
    promoted = client.promote_prompt(
        "p-1",
        target_environment="staging",
        reason="ship",
        render_variables={"name": "Ada"},
        preview_only=False,
    )
    assert promoted["promotion_recorded"] is True
    client._post.assert_called_once_with(
        "/v1/prompts/p-1/promote",
        {
            "target_environment": "staging",
            "reason": "ship",
            "require_render_validation": True,
            "render_variables": {"name": "Ada"},
            "preview_only": False,
        },
    )


def test_sdk_chat_and_responses_config_id_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._post = MagicMock(return_value={"id": "chat-1", "choices": []})
    client.chat_completions(
        {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        config_id="cfg-1",
    )
    chat_call = next(c for c in client._post.call_args_list if c.args and c.args[0] == "/v1/chat/completions")
    chat_body = chat_call.args[1]
    assert chat_body["config_id"] == "cfg-1"
    assert chat_body["route_policy_id"] == "cfg-1"

    client._post = MagicMock(return_value={"id": "resp-1", "output": []})
    client.responses({"model": "gpt-4o-mini", "input": "hi"}, route_policy_id="rp-2")
    resp_call = next(c for c in client._post.call_args_list if c.args and c.args[0] == "/v1/responses")
    resp_body = resp_call.args[1]
    assert resp_body["config_id"] == "rp-2"
    assert resp_body["route_policy_id"] == "rp-2"


def test_sdk_chat_and_responses_guardrail_id_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    import importlib
    import agenthub_gateway as sdk_mod

    importlib.reload(sdk_mod)
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._post = MagicMock(return_value={"id": "chat-1", "choices": []})
    client.chat_completions(
        {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
        guardrail_id="vk-g1",
    )
    chat_call = next(c for c in client._post.call_args_list if c.args and c.args[0] == "/v1/chat/completions")
    chat_body = chat_call.args[1]
    assert chat_body["guardrail_id"] == "vk-g1"
    assert chat_body["virtual_key_id"] == "vk-g1"

    client._post = MagicMock(return_value={"id": "resp-1", "output": []})
    client.responses({"model": "gpt-4o-mini", "input": "hi"}, virtual_key_id="vk-g2")
    resp_call = next(c for c in client._post.call_args_list if c.args and c.args[0] == "/v1/responses")
    resp_body = resp_call.args[1]
    assert resp_body["guardrail_id"] == "vk-g2"
    assert resp_body["virtual_key_id"] == "vk-g2"


def test_cost_request_item_helper_shape():
    from datetime import datetime
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from app.routers import cost as cost_router
    from app.schemas import CostRequestItem

    item = CostRequestItem(
        request_id="req-1",
        model_name="gpt-4o-mini",
        estimated_cost_cents=12,
        timestamp=datetime(2026, 8, 1, 12, 0, 0),
    )
    assert item.request_id == "req-1"
    assert item.estimated_cost_cents == 12

    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [
        SimpleNamespace(
            model_name="gpt-4o-mini",
            properties_json='{"user":"u1","team":"platform"}',
            cache_hit=False,
            estimated_cost_cents=25,
            input_tokens=10,
            output_tokens=5,
            request_id="req-a",
            trace_id="tr-a",
            session_id="sess-a",
            request_tag="tag",
            timestamp=datetime(2026, 8, 1, 12, 0, 0),
        )
    ]
    ctx = SimpleNamespace(actor_role="Platform Admin", actor_id="admin-1")
    items, prop_key = cost_router._collect_cost_request_items(
        db,
        ctx=ctx,
        window_hours=24,
        user_id=None,
        model=None,
        property_key="team",
        property_value=None,
        cache_hit=None,
        has_feedback=None,
        limit=50,
    )
    assert prop_key == "team"
    assert items[0].property_value == "platform"
    assert items[0].user_id == "u1"


def test_sdk_prompt_versions_paths():
    import sys
    from pathlib import Path
    from unittest.mock import MagicMock

    sdk_path = Path(__file__).resolve().parents[2] / "sdk" / "python"
    sys.path.insert(0, str(sdk_path))
    from agenthub_gateway import AgentHubGateway

    client = AgentHubGateway(base_url="http://gateway.test", api_key="k")
    client._get = MagicMock(
        side_effect=[
            [{"version": 2, "prompt_text": "v2"}, {"version": 1, "prompt_text": "v1"}],
            {"version": 2, "prompt_text": "v2"},
        ]
    )
    versions = client.list_prompt_versions("p-1")
    assert versions[0]["version"] == 2
    client._get.assert_any_call("/v1/prompts/p-1/versions")
    got = client.get_prompt_version("p-1", 2)
    assert got["prompt_text"] == "v2"
    client._get.assert_any_call("/v1/prompts/p-1/versions/2")


def test_prompt_render_sanitize_and_missing_vars():
    from app.routers import playground as playground_router
    from fastapi import HTTPException

    sanitized = playground_router._sanitize_prompt_render_variables(
        {" name ": "Ada", "": "skip", "long": "x" * 5000}
    )
    assert sanitized["name"] == "Ada"
    assert len(sanitized["long"]) == 4000

    detected = playground_router._extract_prompt_template_variables("Hi {{name}} from {{team}}")
    assert detected == ["name", "team"]
    rendered = playground_router._render_prompt_template("Hi {{name}}", {"name": "Ada"})
    assert rendered == "Hi Ada"
    with pytest.raises(HTTPException) as exc:
        playground_router._render_prompt_template("Hi {{name", {"name": "Ada"})
    assert exc.value.status_code == 422


def test_variable_and_secret_strategy_consistency():
    """Product-wide I/O variable + secret strategies stay on single canonical paths."""
    from app.services.orchestration_executor import resolve_orchestration_template
    from app.services.orchestration_flows import evaluate_static_data, resolve_safe_template
    from app.services.prompt_template_render import (
        extract_prompt_template_variables,
        render_prompt_template_variables,
        sanitize_prompt_template_variables,
    )
    from app.routers import playground as playground_router
    from app.services import credential_resolution

    step_outputs = {"n1": {"score": 9, "tags": ["a", "b"]}}
    template = "in={{input}} score={{steps['n1'].output.score}} tags={{steps['n1'].output.tags}}"
    via_executor = resolve_orchestration_template(template, step_outputs=step_outputs, run_input="hello")
    via_flows = resolve_safe_template(template, step_outputs=step_outputs, run_input="hello")
    assert via_executor == via_flows == 'in=hello score=9 tags=["a","b"]'

    item_tpl = "item={{item.name}}"
    assert resolve_orchestration_template(
        item_tpl, step_outputs={}, run_input="", item={"name": "Ada"}
    ) == resolve_safe_template(item_tpl, step_outputs={}, run_input="", item={"name": "Ada"})

    static = evaluate_static_data(
        {"fields_json": '{"n":"{{steps[\'n1\'].output.score}}","s":"plain"}'},
        step_outputs=step_outputs,
        run_input="",
    )
    assert static["n"] == 9
    assert static["s"] == "plain"

    shared = render_prompt_template_variables("Hi {{name}}", {"name": "Ada"})
    assert shared == playground_router._render_prompt_template("Hi {{name}}", {"name": "Ada"})
    assert extract_prompt_template_variables("{{a}} {{b}}") == ["a", "b"]
    assert sanitize_prompt_template_variables({" k ": "v" * 5000})["k"] == "v" * 4000
    # Loose `{{ anything }}` tokens are not prompt-registry identifiers.
    assert extract_prompt_template_variables("{{steps['x'].output}} {{good}}") == ["good"]

    db = MagicMock()
    with pytest.raises(HTTPException) as empty_ref:
        gateway_router._read_external_secret_value(db, "prov-1", "")
    assert empty_ref.value.status_code == 422
    assert empty_ref.value.detail == "external_secret_ref is required"

    with patch.object(
        credential_resolution,
        "read_secret_provider_value_at_runtime",
        return_value="secret-value",
    ) as read_secret:
        assert gateway_router._read_external_secret_value(db, "prov-1", "kv/path") == "secret-value"
        read_secret.assert_called_once_with(db, "prov-1", "kv/path")

    with patch.object(
        credential_resolution,
        "read_secret_provider_value_at_runtime",
        side_effect=HTTPException(status_code=400, detail="Secret provider is not active"),
    ):
        with pytest.raises(HTTPException) as inactive:
            gateway_router._read_external_secret_value(db, "prov-1", "kv/path")
        assert inactive.value.detail == "External secret provider is not active"


def test_pagerduty_trello_stubs():
    pd = _execute_single_stub_node(
        {
            "id": "pd-1",
            "type": "pagerduty_event",
            "config": {
                "summary_template": "Alert",
                "severity": "warning",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-pd",
    )
    assert pd["output"]["provider"] == "pagerduty"

    og = _execute_single_stub_node(
        {
            "id": "og-1",
            "type": "opsgenie_alert",
            "config": {
                "summary_template": "Ops alert",
                "priority": "P2",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-og",
    )
    assert og["output"]["provider"] == "opsgenie"
    assert og["output"]["priority"] == "P2"

    dd = _execute_single_stub_node(
        {
            "id": "dd-1",
            "type": "datadog_event",
            "config": {
                "summary_template": "DD event",
                "alert_type": "warning",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-dd",
    )
    assert dd["output"]["provider"] == "datadog"
    assert dd["output"]["alert_type"] == "warning"

    confluence = _execute_single_stub_node(
        {
            "id": "cf-1",
            "type": "confluence_api",
            "config": {
                "base_url": "https://example.atlassian.net",
                "path_template": "/wiki/rest/api/content",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cf",
    )
    assert confluence["output"]["provider"] == "confluence"

    sentry = _execute_single_stub_node(
        {
            "id": "se-1",
            "type": "sentry_event",
            "config": {
                "summary_template": "Boom",
                "organization_slug": "acme",
                "project_slug": "gateway",
                "level": "warning",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-se",
    )
    assert sentry["output"]["provider"] == "sentry"
    assert sentry["output"]["level"] == "warning"

    mattermost = _execute_single_stub_node(
        {
            "id": "mm-1",
            "type": "mattermost_webhook",
            "config": {
                "webhook_url": "https://mm.example.com/hooks/abc",
                "text_template": "Hello",
            },
        },
        dry_run=True,
        trace_id="trace-mm",
    )
    assert mattermost["output"]["provider"] == "mattermost"

    gchat = _execute_single_stub_node(
        {
            "id": "gc-1",
            "type": "google_chat_webhook",
            "config": {
                "webhook_url": "https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&token=t",
                "text_template": "Hello",
            },
        },
        dry_run=True,
        trace_id="trace-gc",
    )
    assert gchat["output"]["provider"] == "google_chat"

    statuspage = _execute_single_stub_node(
        {
            "id": "sp-1",
            "type": "statuspage_incident",
            "config": {
                "name_template": "Outage",
                "page_id": "page1",
                "status": "investigating",
                "impact": "major",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sp",
    )
    assert statuspage["output"]["provider"] == "statuspage"
    assert statuspage["output"]["impact"] == "major"

    trello = _execute_single_stub_node(
        {
            "id": "tr-1",
            "type": "trello_api",
            "config": {
                "path_template": "/1/members/me",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-tr",
    )
    assert trello["output"]["provider"] == "trello"


def test_graphql_asana_stubs():
    graphql = _execute_single_stub_node(
        {
            "id": "gql-1",
            "type": "graphql_request",
            "config": {
                "url": "https://api.example.com/graphql",
                "query_template": "{ viewer { id } }",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-gql",
    )
    assert graphql["output"]["provider"] == "graphql"

    asana = _execute_single_stub_node(
        {
            "id": "as-1",
            "type": "asana_api",
            "config": {
                "path_template": "/api/1.0/users/me",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-as",
    )
    assert asana["output"]["provider"] == "asana"

    clickup = _execute_single_stub_node(
        {
            "id": "cu-1",
            "type": "clickup_api",
            "config": {
                "path_template": "/api/v2/user",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cu",
    )
    assert clickup["output"]["provider"] == "clickup"

    intercom = _execute_single_stub_node(
        {
            "id": "ic-1",
            "type": "intercom_api",
            "config": {
                "path_template": "/me",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ic",
    )
    assert intercom["output"]["provider"] == "intercom"

    monday = _execute_single_stub_node(
        {
            "id": "mo-1",
            "type": "monday_api",
            "config": {
                "path_template": "/v2",
                "method": "POST",
                "body_template": '{"query":"{ me { id } }"}',
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-mo",
    )
    assert monday["output"]["provider"] == "monday"

    gitlab = _execute_single_stub_node(
        {
            "id": "gl-1",
            "type": "gitlab_api",
            "config": {
                "path_template": "/user",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-gl",
    )
    assert gitlab["output"]["provider"] == "gitlab"

    pipedrive = _execute_single_stub_node(
        {
            "id": "pp-1",
            "type": "pipedrive_api",
            "config": {
                "base_url": "https://example.pipedrive.com",
                "path_template": "/api/v1/users/me",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-pp",
    )
    assert pipedrive["output"]["provider"] == "pipedrive"

    bitbucket = _execute_single_stub_node(
        {
            "id": "bb-1",
            "type": "bitbucket_api",
            "config": {
                "path_template": "/user",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-bb",
    )
    assert bitbucket["output"]["provider"] == "bitbucket"

    shopify = _execute_single_stub_node(
        {
            "id": "sh-1",
            "type": "shopify_api",
            "config": {
                "base_url": "https://example.myshopify.com",
                "path_template": "/admin/api/2024-01/shop.json",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sh",
    )
    assert shopify["output"]["provider"] == "shopify"

    stripe = _execute_single_stub_node(
        {
            "id": "st-1",
            "type": "stripe_api",
            "config": {
                "path_template": "/v1/balance",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-st",
    )
    assert stripe["output"]["provider"] == "stripe"

    box = _execute_single_stub_node(
        {
            "id": "bx-1",
            "type": "box_api",
            "config": {
                "path_template": "/users/me",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-bx",
    )
    assert box["output"]["provider"] == "box"

    dropbox = _execute_single_stub_node(
        {
            "id": "db-1",
            "type": "dropbox_api",
            "config": {
                "path_template": "/2/users/get_current_account",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-db",
    )
    assert dropbox["output"]["provider"] == "dropbox"

    calendly = _execute_single_stub_node(
        {
            "id": "cl-1",
            "type": "calendly_api",
            "config": {
                "path_template": "/users/me",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cl",
    )
    assert calendly["output"]["provider"] == "calendly"

    graph = _execute_single_stub_node(
        {
            "id": "mg-1",
            "type": "microsoft_graph_api",
            "config": {
                "path_template": "/me",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-mg",
    )
    assert graph["output"]["provider"] == "microsoft_graph"

    sheets = _execute_single_stub_node(
        {
            "id": "gs-1",
            "type": "google_sheets_api",
            "config": {
                "path_template": "/spreadsheets/sheet-1/values/A1:B2",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-gs",
    )
    assert sheets["output"]["provider"] == "google_sheets"

    drive = _execute_single_stub_node(
        {
            "id": "gd-1",
            "type": "google_drive_api",
            "config": {
                "path_template": "/files",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-gd",
    )
    assert drive["output"]["provider"] == "google_drive"

    calendar = _execute_single_stub_node(
        {
            "id": "gc-1",
            "type": "google_calendar_api",
            "config": {
                "path_template": "/users/me/calendarList",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-gc",
    )
    assert calendar["output"]["provider"] == "google_calendar"

    slack = _execute_single_stub_node(
        {
            "id": "sl-1",
            "type": "slack_api",
            "config": {
                "path_template": "/chat.postMessage",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sl",
    )
    assert slack["output"]["provider"] == "slack"

    zoom = _execute_single_stub_node(
        {
            "id": "zm-1",
            "type": "zoom_api",
            "config": {
                "path_template": "/users/me",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-zm",
    )
    assert zoom["output"]["provider"] == "zoom"

    twilio = _execute_single_stub_node(
        {
            "id": "tw-1",
            "type": "twilio_api",
            "config": {
                "path_template": "/2010-04-01/Accounts.json",
                "method": "GET",
                "auth_binding_id": "b1",
                "auth_type": "basic",
            },
        },
        dry_run=True,
        trace_id="trace-tw",
    )
    assert twilio["output"]["provider"] == "twilio"

    sendgrid = _execute_single_stub_node(
        {
            "id": "sg-1",
            "type": "sendgrid_api",
            "config": {
                "path_template": "/v3/mail/send",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sg",
    )
    assert sendgrid["output"]["provider"] == "sendgrid"

    freshservice = _execute_single_stub_node(
        {
            "id": "fs-1",
            "type": "freshservice_api",
            "config": {
                "base_url": "https://example.freshservice.com",
                "path_template": "/api/v2/tickets",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-fs",
    )
    assert freshservice["output"]["provider"] == "freshservice"

    okta = _execute_single_stub_node(
        {
            "id": "ok-1",
            "type": "okta_api",
            "config": {
                "base_url": "https://example.okta.com",
                "path_template": "/api/v1/users",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ok",
    )
    assert okta["output"]["provider"] == "okta"

    auth0 = _execute_single_stub_node(
        {
            "id": "a0-1",
            "type": "auth0_api",
            "config": {
                "base_url": "https://example.auth0.com",
                "path_template": "/api/v2/users",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-a0",
    )
    assert auth0["output"]["provider"] == "auth0"

    azdo = _execute_single_stub_node(
        {
            "id": "az-1",
            "type": "azure_devops_api",
            "config": {
                "base_url": "https://dev.azure.com/example",
                "path_template": "/_apis/projects",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-az",
    )
    assert azdo["output"]["provider"] == "azure_devops"

    snowflake = _execute_single_stub_node(
        {
            "id": "sf-api-1",
            "type": "snowflake_api",
            "config": {
                "base_url": "https://example.snowflakecomputing.com",
                "path_template": "/api/v2/statements",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-snow",
    )
    assert snowflake["output"]["provider"] == "snowflake"

    databricks = _execute_single_stub_node(
        {
            "id": "dbx-1",
            "type": "databricks_api",
            "config": {
                "base_url": "https://adb-example.azuredatabricks.net",
                "path_template": "/api/2.0/clusters/list",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-dbx",
    )
    assert databricks["output"]["provider"] == "databricks"

    bigquery = _execute_single_stub_node(
        {
            "id": "bq-1",
            "type": "bigquery_api",
            "config": {
                "base_url": "https://bigquery.googleapis.com",
                "path_template": "/bigquery/v2/projects/demo/queries",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-bq",
    )
    assert bigquery["output"]["provider"] == "bigquery"

    splunk = _execute_single_stub_node(
        {
            "id": "spl-1",
            "type": "splunk_api",
            "config": {
                "base_url": "https://splunk.example.com:8089",
                "path_template": "/services/search/jobs",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-spl",
    )
    assert splunk["output"]["provider"] == "splunk"

    elasticsearch = _execute_single_stub_node(
        {
            "id": "es-1",
            "type": "elasticsearch_api",
            "config": {
                "base_url": "https://es.example.com:9200",
                "path_template": "/_search",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-es",
    )
    assert elasticsearch["output"]["provider"] == "elasticsearch"

    redis = _execute_single_stub_node(
        {
            "id": "rd-1",
            "type": "redis_api",
            "config": {
                "base_url": "https://redis.example.com:9443",
                "path_template": "/get/cache-key",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-rd",
    )
    assert redis["output"]["provider"] == "redis"

    mongodb = _execute_single_stub_node(
        {
            "id": "mg-1",
            "type": "mongodb_api",
            "config": {
                "base_url": "https://data.mongodb-api.com",
                "path_template": "/action/find",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-mg",
    )
    assert mongodb["output"]["provider"] == "mongodb"

    postgres = _execute_single_stub_node(
        {
            "id": "pg-1",
            "type": "postgres_api",
            "config": {
                "base_url": "https://db.example.com:3000",
                "path_template": "/users",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-pg",
    )
    assert postgres["output"]["provider"] == "postgres"

    mysql = _execute_single_stub_node(
        {
            "id": "my-1",
            "type": "mysql_api",
            "config": {
                "base_url": "https://mysql-gateway.example.com",
                "path_template": "/query",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-my",
    )
    assert mysql["output"]["provider"] == "mysql"

    s3 = _execute_single_stub_node(
        {
            "id": "s3-1",
            "type": "s3_api",
            "config": {
                "base_url": "https://s3.example.com",
                "path_template": "/bucket/object.json",
                "method": "PUT",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-s3",
    )
    assert s3["output"]["provider"] == "s3"

    pinecone = _execute_single_stub_node(
        {
            "id": "pc-1",
            "type": "pinecone_api",
            "config": {
                "base_url": "https://index.pinecone.io",
                "path_template": "/query",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-pc",
    )
    assert pinecone["output"]["provider"] == "pinecone"

    weaviate = _execute_single_stub_node(
        {
            "id": "wv-1",
            "type": "weaviate_api",
            "config": {
                "base_url": "https://weaviate.example.com",
                "path_template": "/v1/objects",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-wv",
    )
    assert weaviate["output"]["provider"] == "weaviate"

    qdrant = _execute_single_stub_node(
        {
            "id": "qd-1",
            "type": "qdrant_api",
            "config": {
                "base_url": "https://qdrant.example.com",
                "path_template": "/collections",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-qd",
    )
    assert qdrant["output"]["provider"] == "qdrant"

    supabase = _execute_single_stub_node(
        {
            "id": "sb-1",
            "type": "supabase_api",
            "config": {
                "base_url": "https://xyz.supabase.co",
                "path_template": "/rest/v1/items",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sb",
    )
    assert supabase["output"]["provider"] == "supabase"

    kafka = _execute_single_stub_node(
        {
            "id": "kf-1",
            "type": "kafka_api",
            "config": {
                "base_url": "https://kafka-rest.example.com",
                "path_template": "/topics/events",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-kf",
    )
    assert kafka["output"]["provider"] == "kafka"

    milvus = _execute_single_stub_node(
        {
            "id": "mv-1",
            "type": "milvus_api",
            "config": {
                "base_url": "https://milvus.example.com",
                "path_template": "/v1/vector/search",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-mv",
    )
    assert milvus["output"]["provider"] == "milvus"

    chroma = _execute_single_stub_node(
        {
            "id": "ch-1",
            "type": "chroma_api",
            "config": {
                "base_url": "https://chroma.example.com",
                "path_template": "/api/v1/collections",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ch",
    )
    assert chroma["output"]["provider"] == "chroma"

    neo4j = _execute_single_stub_node(
        {
            "id": "n4-1",
            "type": "neo4j_api",
            "config": {
                "base_url": "https://neo4j.example.com:7474",
                "path_template": "/db/neo4j/tx/commit",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-n4",
    )
    assert neo4j["output"]["provider"] == "neo4j"

    rabbitmq = _execute_single_stub_node(
        {
            "id": "rm-1",
            "type": "rabbitmq_api",
            "config": {
                "base_url": "https://rabbitmq.example.com:15672",
                "path_template": "/api/queues",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-rm",
    )
    assert rabbitmq["output"]["provider"] == "rabbitmq"

    opensearch = _execute_single_stub_node(
        {
            "id": "os-1",
            "type": "opensearch_api",
            "config": {
                "base_url": "https://opensearch.example.com",
                "path_template": "/_search",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-os",
    )
    assert opensearch["output"]["provider"] == "opensearch"

    clickhouse = _execute_single_stub_node(
        {
            "id": "ck-1",
            "type": "clickhouse_api",
            "config": {
                "base_url": "https://clickhouse.example.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ck",
    )
    assert clickhouse["output"]["provider"] == "clickhouse"

    dynamodb = _execute_single_stub_node(
        {
            "id": "dd-1",
            "type": "dynamodb_api",
            "config": {
                "base_url": "https://dynamodb.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-dd",
    )
    assert dynamodb["output"]["provider"] == "dynamodb"

    nats = _execute_single_stub_node(
        {
            "id": "nt-1",
            "type": "nats_api",
            "config": {
                "base_url": "https://nats.example.com",
                "path_template": "/varz",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-nt",
    )
    assert nats["output"]["provider"] == "nats"

    cassandra = _execute_single_stub_node(
        {
            "id": "ca-1",
            "type": "cassandra_api",
            "config": {
                "base_url": "https://cassandra.example.com",
                "path_template": "/v2/keyspaces",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ca",
    )
    assert cassandra["output"]["provider"] == "cassandra"

    couchbase = _execute_single_stub_node(
        {
            "id": "cb-1",
            "type": "couchbase_api",
            "config": {
                "base_url": "https://couchbase.example.com",
                "path_template": "/pools/default",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cb",
    )
    assert couchbase["output"]["provider"] == "couchbase"

    influxdb = _execute_single_stub_node(
        {
            "id": "if-1",
            "type": "influxdb_api",
            "config": {
                "base_url": "https://influxdb.example.com",
                "path_template": "/api/v2/query",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-if",
    )
    assert influxdb["output"]["provider"] == "influxdb"

    firebase = _execute_single_stub_node(
        {
            "id": "fb-1",
            "type": "firebase_api",
            "config": {
                "base_url": "https://firestore.googleapis.com",
                "path_template": "/v1/projects",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-fb",
    )
    assert firebase["output"]["provider"] == "firebase"

    airbyte = _execute_single_stub_node(
        {
            "id": "ab-1",
            "type": "airbyte_api",
            "config": {
                "base_url": "https://airbyte.example.com",
                "path_template": "/api/v1/workspaces",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ab",
    )
    assert airbyte["output"]["provider"] == "airbyte"

    presto = _execute_single_stub_node(
        {
            "id": "pr-1",
            "type": "presto_api",
            "config": {
                "base_url": "https://presto.example.com",
                "path_template": "/v1/statement",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-pr",
    )
    assert presto["output"]["provider"] == "presto"

    trino = _execute_single_stub_node(
        {
            "id": "tr-1",
            "type": "trino_api",
            "config": {
                "base_url": "https://trino.example.com",
                "path_template": "/v1/statement",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-tr",
    )
    assert trino["output"]["provider"] == "trino"

    redshift = _execute_single_stub_node(
        {
            "id": "rs-1",
            "type": "redshift_api",
            "config": {
                "base_url": "https://redshift.example.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-rs",
    )
    assert redshift["output"]["provider"] == "redshift"

    athena = _execute_single_stub_node(
        {
            "id": "at-1",
            "type": "athena_api",
            "config": {
                "base_url": "https://athena.example.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-athena",
    )
    assert athena["output"]["provider"] == "athena"

    pulsar = _execute_single_stub_node(
        {
            "id": "pu-1",
            "type": "pulsar_api",
            "config": {
                "base_url": "https://pulsar.example.com",
                "path_template": "/admin/v2/clusters",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-pu",
    )
    assert pulsar["output"]["provider"] == "pulsar"

    scylladb = _execute_single_stub_node(
        {
            "id": "sc-1",
            "type": "scylladb_api",
            "config": {
                "base_url": "https://scylla.example.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sc",
    )
    assert scylladb["output"]["provider"] == "scylladb"

    sqs = _execute_single_stub_node(
        {
            "id": "sq-1",
            "type": "sqs_api",
            "config": {
                "base_url": "https://sqs.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sqs",
    )
    assert sqs["output"]["provider"] == "sqs"

    sns = _execute_single_stub_node(
        {
            "id": "sn-1",
            "type": "sns_api",
            "config": {
                "base_url": "https://sns.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sns",
    )
    assert sns["output"]["provider"] == "sns"

    kinesis = _execute_single_stub_node(
        {
            "id": "ki-1",
            "type": "kinesis_api",
            "config": {
                "base_url": "https://kinesis.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ki",
    )
    assert kinesis["output"]["provider"] == "kinesis"

    eventbridge = _execute_single_stub_node(
        {
            "id": "eb-1",
            "type": "eventbridge_api",
            "config": {
                "base_url": "https://events.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-eb",
    )
    assert eventbridge["output"]["provider"] == "eventbridge"

    lambda_node = _execute_single_stub_node(
        {
            "id": "lm-1",
            "type": "lambda_api",
            "config": {
                "base_url": "https://lambda.us-east-1.amazonaws.com",
                "path_template": "/2015-03-31/functions",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-lm",
    )
    assert lambda_node["output"]["provider"] == "lambda"

    stepfunctions = _execute_single_stub_node(
        {
            "id": "sf-1",
            "type": "stepfunctions_api",
            "config": {
                "base_url": "https://states.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sf",
    )
    assert stepfunctions["output"]["provider"] == "stepfunctions"

    cloudwatch = _execute_single_stub_node(
        {
            "id": "cw-1",
            "type": "cloudwatch_api",
            "config": {
                "base_url": "https://monitoring.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cw",
    )
    assert cloudwatch["output"]["provider"] == "cloudwatch"

    xray = _execute_single_stub_node(
        {
            "id": "xr-1",
            "type": "xray_api",
            "config": {
                "base_url": "https://xray.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-xr",
    )
    assert xray["output"]["provider"] == "xray"

    glue = _execute_single_stub_node(
        {
            "id": "gl-1",
            "type": "glue_api",
            "config": {
                "base_url": "https://glue.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-gl",
    )
    assert glue["output"]["provider"] == "glue"

    sagemaker = _execute_single_stub_node(
        {
            "id": "sm-1",
            "type": "sagemaker_api",
            "config": {
                "base_url": "https://api.sagemaker.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sm",
    )
    assert sagemaker["output"]["provider"] == "sagemaker"

    bedrock = _execute_single_stub_node(
        {
            "id": "br-1",
            "type": "bedrock_api",
            "config": {
                "base_url": "https://bedrock-runtime.us-east-1.amazonaws.com",
                "path_template": "/model",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-br",
    )
    assert bedrock["output"]["provider"] == "bedrock"

    comprehend = _execute_single_stub_node(
        {
            "id": "cp-1",
            "type": "comprehend_api",
            "config": {
                "base_url": "https://comprehend.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cp",
    )
    assert comprehend["output"]["provider"] == "comprehend"

    textract = _execute_single_stub_node(
        {
            "id": "tx-1",
            "type": "textract_api",
            "config": {
                "base_url": "https://textract.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-tx",
    )
    assert textract["output"]["provider"] == "textract"

    rekognition = _execute_single_stub_node(
        {
            "id": "rk-1",
            "type": "rekognition_api",
            "config": {
                "base_url": "https://rekognition.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-rk",
    )
    assert rekognition["output"]["provider"] == "rekognition"

    translate = _execute_single_stub_node(
        {
            "id": "tr-1",
            "type": "translate_api",
            "config": {
                "base_url": "https://translate.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-tr",
    )
    assert translate["output"]["provider"] == "translate"

    polly = _execute_single_stub_node(
        {
            "id": "po-1",
            "type": "polly_api",
            "config": {
                "base_url": "https://polly.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-po",
    )
    assert polly["output"]["provider"] == "polly"

    transcribe = _execute_single_stub_node(
        {
            "id": "tc-1",
            "type": "transcribe_api",
            "config": {
                "base_url": "https://transcribe.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-tc",
    )
    assert transcribe["output"]["provider"] == "transcribe"

    lex = _execute_single_stub_node(
        {
            "id": "lx-1",
            "type": "lex_api",
            "config": {
                "base_url": "https://runtime.lex.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-lx",
    )
    assert lex["output"]["provider"] == "lex"

    ecs = _execute_single_stub_node(
        {
            "id": "ecs-1",
            "type": "ecs_api",
            "config": {
                "base_url": "https://ecs.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ecs",
    )
    assert ecs["output"]["provider"] == "ecs"

    eks = _execute_single_stub_node(
        {
            "id": "eks-1",
            "type": "eks_api",
            "config": {
                "base_url": "https://eks.us-east-1.amazonaws.com",
                "path_template": "/clusters",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-eks",
    )
    assert eks["output"]["provider"] == "eks"

    secretsmanager = _execute_single_stub_node(
        {
            "id": "sm-1",
            "type": "secretsmanager_api",
            "config": {
                "base_url": "https://secretsmanager.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sm",
    )
    assert secretsmanager["output"]["provider"] == "secretsmanager"

    ssm = _execute_single_stub_node(
        {
            "id": "ssm-1",
            "type": "ssm_api",
            "config": {
                "base_url": "https://ssm.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ssm",
    )
    assert ssm["output"]["provider"] == "ssm"

    cognito = _execute_single_stub_node(
        {
            "id": "cg-1",
            "type": "cognito_api",
            "config": {
                "base_url": "https://cognito-idp.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cg",
    )
    assert cognito["output"]["provider"] == "cognito"

    iam = _execute_single_stub_node(
        {
            "id": "iam-1",
            "type": "iam_api",
            "config": {
                "base_url": "https://iam.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-iam",
    )
    assert iam["output"]["provider"] == "iam"

    kms = _execute_single_stub_node(
        {
            "id": "kms-1",
            "type": "kms_api",
            "config": {
                "base_url": "https://kms.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-kms",
    )
    assert kms["output"]["provider"] == "kms"

    sts = _execute_single_stub_node(
        {
            "id": "sts-1",
            "type": "sts_api",
            "config": {
                "base_url": "https://sts.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sts",
    )
    assert sts["output"]["provider"] == "sts"

    apigateway = _execute_single_stub_node(
        {
            "id": "ag-1",
            "type": "apigateway_api",
            "config": {
                "base_url": "https://apigateway.us-east-1.amazonaws.com",
                "path_template": "/restapis",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ag",
    )
    assert apigateway["output"]["provider"] == "apigateway"

    cloudformation = _execute_single_stub_node(
        {
            "id": "cf-1",
            "type": "cloudformation_api",
            "config": {
                "base_url": "https://cloudformation.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cf",
    )
    assert cloudformation["output"]["provider"] == "cloudformation"

    rds = _execute_single_stub_node(
        {
            "id": "rds-1",
            "type": "rds_api",
            "config": {
                "base_url": "https://rds.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-rds",
    )
    assert rds["output"]["provider"] == "rds"

    elb = _execute_single_stub_node(
        {
            "id": "elb-1",
            "type": "elb_api",
            "config": {
                "base_url": "https://elasticloadbalancing.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-elb",
    )
    assert elb["output"]["provider"] == "elb"

    cloudfront = _execute_single_stub_node(
        {
            "id": "cfront-1",
            "type": "cloudfront_api",
            "config": {
                "base_url": "https://cloudfront.amazonaws.com",
                "path_template": "/2020-05-31/distribution",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cfront",
    )
    assert cloudfront["output"]["provider"] == "cloudfront"

    route53 = _execute_single_stub_node(
        {
            "id": "r53-1",
            "type": "route53_api",
            "config": {
                "base_url": "https://route53.amazonaws.com",
                "path_template": "/2013-04-01/hostedzone",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-r53",
    )
    assert route53["output"]["provider"] == "route53"

    cloudtrail = _execute_single_stub_node(
        {
            "id": "ctrail-1",
            "type": "cloudtrail_api",
            "config": {
                "base_url": "https://cloudtrail.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ctrail",
    )
    assert cloudtrail["output"]["provider"] == "cloudtrail"

    config = _execute_single_stub_node(
        {
            "id": "cfg-1",
            "type": "config_api",
            "config": {
                "base_url": "https://config.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cfg",
    )
    assert config["output"]["provider"] == "config"

    guardduty = _execute_single_stub_node(
        {
            "id": "gd-1",
            "type": "guardduty_api",
            "config": {
                "base_url": "https://guardduty.us-east-1.amazonaws.com",
                "path_template": "/detector",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-gd",
    )
    assert guardduty["output"]["provider"] == "guardduty"

    securityhub = _execute_single_stub_node(
        {
            "id": "sh-1",
            "type": "securityhub_api",
            "config": {
                "base_url": "https://securityhub.us-east-1.amazonaws.com",
                "path_template": "/findings",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sh",
    )
    assert securityhub["output"]["provider"] == "securityhub"

    inspector = _execute_single_stub_node(
        {
            "id": "insp-1",
            "type": "inspector_api",
            "config": {
                "base_url": "https://inspector2.us-east-1.amazonaws.com",
                "path_template": "/findings/list",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-insp",
    )
    assert inspector["output"]["provider"] == "inspector"

    macie = _execute_single_stub_node(
        {
            "id": "macie-1",
            "type": "macie_api",
            "config": {
                "base_url": "https://macie2.us-east-1.amazonaws.com",
                "path_template": "/findings",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-macie",
    )
    assert macie["output"]["provider"] == "macie"

    waf = _execute_single_stub_node(
        {
            "id": "waf-1",
            "type": "waf_api",
            "config": {
                "base_url": "https://wafv2.us-east-1.amazonaws.com",
                "path_template": "/webacl",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-waf",
    )
    assert waf["output"]["provider"] == "waf"

    shield = _execute_single_stub_node(
        {
            "id": "shield-1",
            "type": "shield_api",
            "config": {
                "base_url": "https://shield.us-east-1.amazonaws.com",
                "path_template": "/protections",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-shield",
    )
    assert shield["output"]["provider"] == "shield"

    acm = _execute_single_stub_node(
        {
            "id": "acm-1",
            "type": "acm_api",
            "config": {
                "base_url": "https://acm.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-acm",
    )
    assert acm["output"]["provider"] == "acm"

    networkfirewall = _execute_single_stub_node(
        {
            "id": "nfw-1",
            "type": "networkfirewall_api",
            "config": {
                "base_url": "https://network-firewall.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-nfw",
    )
    assert networkfirewall["output"]["provider"] == "networkfirewall"

    ecr = _execute_single_stub_node(
        {
            "id": "ecr-1",
            "type": "ecr_api",
            "config": {
                "base_url": "https://api.ecr.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ecr",
    )
    assert ecr["output"]["provider"] == "ecr"

    efs = _execute_single_stub_node(
        {
            "id": "efs-1",
            "type": "efs_api",
            "config": {
                "base_url": "https://elasticfilesystem.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-efs",
    )
    assert efs["output"]["provider"] == "efs"

    detective = _execute_single_stub_node(
        {
            "id": "det-1",
            "type": "detective_api",
            "config": {
                "base_url": "https://api.detective.us-east-1.amazonaws.com",
                "path_template": "/graph",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-detective",
    )
    assert detective["output"]["provider"] == "detective"

    accessanalyzer = _execute_single_stub_node(
        {
            "id": "aa-1",
            "type": "accessanalyzer_api",
            "config": {
                "base_url": "https://access-analyzer.us-east-1.amazonaws.com",
                "path_template": "/analyzer",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-accessanalyzer",
    )
    assert accessanalyzer["output"]["provider"] == "accessanalyzer"

    fargate = _execute_single_stub_node(
        {
            "id": "fg-1",
            "type": "fargate_api",
            "config": {
                "base_url": "https://ecs.us-east-1.amazonaws.com",
                "path_template": "/tasks",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-fargate",
    )
    assert fargate["output"]["provider"] == "fargate"

    batch = _execute_single_stub_node(
        {
            "id": "bat-1",
            "type": "batch_api",
            "config": {
                "base_url": "https://batch.us-east-1.amazonaws.com",
                "path_template": "/v1/jobs",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-batch",
    )
    assert batch["output"]["provider"] == "batch"

    elasticache = _execute_single_stub_node(
        {
            "id": "ecache-1",
            "type": "elasticache_api",
            "config": {
                "base_url": "https://elasticache.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-elasticache",
    )
    assert elasticache["output"]["provider"] == "elasticache"

    memorydb = _execute_single_stub_node(
        {
            "id": "mdb-1",
            "type": "memorydb_api",
            "config": {
                "base_url": "https://memory-db.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-memorydb",
    )
    assert memorydb["output"]["provider"] == "memorydb"

    emr = _execute_single_stub_node(
        {
            "id": "emr-1",
            "type": "emr_api",
            "config": {
                "base_url": "https://elasticmapreduce.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-emr",
    )
    assert emr["output"]["provider"] == "emr"

    firehose = _execute_single_stub_node(
        {
            "id": "fh-1",
            "type": "firehose_api",
            "config": {
                "base_url": "https://firehose.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-firehose",
    )
    assert firehose["output"]["provider"] == "firehose"

    msk = _execute_single_stub_node(
        {
            "id": "msk-1",
            "type": "msk_api",
            "config": {
                "base_url": "https://kafka.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-msk",
    )
    assert msk["output"]["provider"] == "msk"

    appsync = _execute_single_stub_node(
        {
            "id": "as-1",
            "type": "appsync_api",
            "config": {
                "base_url": "https://xxxxx.appsync-api.us-east-1.amazonaws.com",
                "path_template": "/graphql",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-appsync",
    )
    assert appsync["output"]["provider"] == "appsync"

    amazon_mq = _execute_single_stub_node(
        {
            "id": "amq-1",
            "type": "amazon_mq_api",
            "config": {
                "base_url": "https://mq.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-amazon-mq",
    )
    assert amazon_mq["output"]["provider"] == "amazon_mq"

    neptune = _execute_single_stub_node(
        {
            "id": "nep-1",
            "type": "neptune_api",
            "config": {
                "base_url": "https://neptune-db.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-neptune",
    )
    assert neptune["output"]["provider"] == "neptune"

    documentdb = _execute_single_stub_node(
        {
            "id": "doc-1",
            "type": "documentdb_api",
            "config": {
                "base_url": "https://rds.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-documentdb",
    )
    assert documentdb["output"]["provider"] == "documentdb"

    fsx = _execute_single_stub_node(
        {
            "id": "fsx-1",
            "type": "fsx_api",
            "config": {
                "base_url": "https://fsx.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-fsx",
    )
    assert fsx["output"]["provider"] == "fsx"

    kendra = _execute_single_stub_node(
        {
            "id": "ken-1",
            "type": "kendra_api",
            "config": {
                "base_url": "https://kendra.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-kendra",
    )
    assert kendra["output"]["provider"] == "kendra"

    personalize = _execute_single_stub_node(
        {
            "id": "per-1",
            "type": "personalize_api",
            "config": {
                "base_url": "https://personalize.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-personalize",
    )
    assert personalize["output"]["provider"] == "personalize"

    forecast = _execute_single_stub_node(
        {
            "id": "fc-1",
            "type": "forecast_api",
            "config": {
                "base_url": "https://forecast.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-forecast",
    )
    assert forecast["output"]["provider"] == "forecast"

    mediaconvert = _execute_single_stub_node(
        {
            "id": "mc-1",
            "type": "mediaconvert_api",
            "config": {
                "base_url": "https://mediaconvert.us-east-1.amazonaws.com",
                "path_template": "/2017-08-29/jobs",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-mediaconvert",
    )
    assert mediaconvert["output"]["provider"] == "mediaconvert"

    transfer = _execute_single_stub_node(
        {
            "id": "xfer-1",
            "type": "transfer_api",
            "config": {
                "base_url": "https://transfer.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-transfer",
    )
    assert transfer["output"]["provider"] == "transfer"

    datasync = _execute_single_stub_node(
        {
            "id": "ds-1",
            "type": "datasync_api",
            "config": {
                "base_url": "https://datasync.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-datasync",
    )
    assert datasync["output"]["provider"] == "datasync"

    backup = _execute_single_stub_node(
        {
            "id": "bk-1",
            "type": "backup_api",
            "config": {
                "base_url": "https://backup.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-backup",
    )
    assert backup["output"]["provider"] == "backup"

    lightsail = _execute_single_stub_node(
        {
            "id": "ls-1",
            "type": "lightsail_api",
            "config": {
                "base_url": "https://lightsail.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-lightsail",
    )
    assert lightsail["output"]["provider"] == "lightsail"

    elasticbeanstalk = _execute_single_stub_node(
        {
            "id": "eb-1",
            "type": "elasticbeanstalk_api",
            "config": {
                "base_url": "https://elasticbeanstalk.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-elasticbeanstalk",
    )
    assert elasticbeanstalk["output"]["provider"] == "elasticbeanstalk"

    workspaces = _execute_single_stub_node(
        {
            "id": "ws-1",
            "type": "workspaces_api",
            "config": {
                "base_url": "https://workspaces.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-workspaces",
    )
    assert workspaces["output"]["provider"] == "workspaces"

    appstream = _execute_single_stub_node(
        {
            "id": "as-1",
            "type": "appstream_api",
            "config": {
                "base_url": "https://appstream2.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-appstream",
    )
    assert appstream["output"]["provider"] == "appstream"

    mediastore = _execute_single_stub_node(
        {
            "id": "ms-1",
            "type": "mediastore_api",
            "config": {
                "base_url": "https://mediastore.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-mediastore",
    )
    assert mediastore["output"]["provider"] == "mediastore"

    outposts = _execute_single_stub_node(
        {
            "id": "op-1",
            "type": "outposts_api",
            "config": {
                "base_url": "https://outposts.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-outposts",
    )
    assert outposts["output"]["provider"] == "outposts"

    storagegateway = _execute_single_stub_node(
        {
            "id": "sg-1",
            "type": "storagegateway_api",
            "config": {
                "base_url": "https://storagegateway.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-storagegateway",
    )
    assert storagegateway["output"]["provider"] == "storagegateway"

    directconnect = _execute_single_stub_node(
        {
            "id": "dx-1",
            "type": "directconnect_api",
            "config": {
                "base_url": "https://directconnect.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-directconnect",
    )
    assert directconnect["output"]["provider"] == "directconnect"

    transitgateway = _execute_single_stub_node(
        {
            "id": "tg-1",
            "type": "transitgateway_api",
            "config": {
                "base_url": "https://ec2.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-transitgateway",
    )
    assert transitgateway["output"]["provider"] == "transitgateway"

    ec2 = _execute_single_stub_node(
        {
            "id": "ec2-1",
            "type": "ec2_api",
            "config": {
                "base_url": "https://ec2.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ec2",
    )
    assert ec2["output"]["provider"] == "ec2"

    autoscaling = _execute_single_stub_node(
        {
            "id": "asg-1",
            "type": "autoscaling_api",
            "config": {
                "base_url": "https://autoscaling.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-autoscaling",
    )
    assert autoscaling["output"]["provider"] == "autoscaling"

    organizations = _execute_single_stub_node(
        {
            "id": "org-1",
            "type": "organizations_api",
            "config": {
                "base_url": "https://organizations.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-organizations",
    )
    assert organizations["output"]["provider"] == "organizations"

    ram = _execute_single_stub_node(
        {
            "id": "ram-1",
            "type": "ram_api",
            "config": {
                "base_url": "https://ram.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ram",
    )
    assert ram["output"]["provider"] == "ram"

    codebuild = _execute_single_stub_node(
        {
            "id": "cb-1",
            "type": "codebuild_api",
            "config": {
                "base_url": "https://codebuild.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-codebuild",
    )
    assert codebuild["output"]["provider"] == "codebuild"

    codepipeline = _execute_single_stub_node(
        {
            "id": "cp-1",
            "type": "codepipeline_api",
            "config": {
                "base_url": "https://codepipeline.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-codepipeline",
    )
    assert codepipeline["output"]["provider"] == "codepipeline"

    codedeploy = _execute_single_stub_node(
        {
            "id": "cd-1",
            "type": "codedeploy_api",
            "config": {
                "base_url": "https://codedeploy.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-codedeploy",
    )
    assert codedeploy["output"]["provider"] == "codedeploy"

    codecommit = _execute_single_stub_node(
        {
            "id": "cc-1",
            "type": "codecommit_api",
            "config": {
                "base_url": "https://codecommit.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-codecommit",
    )
    assert codecommit["output"]["provider"] == "codecommit"

    cloud9 = _execute_single_stub_node(
        {
            "id": "c9-1",
            "type": "cloud9_api",
            "config": {
                "base_url": "https://cloud9.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cloud9",
    )
    assert cloud9["output"]["provider"] == "cloud9"

    amplify = _execute_single_stub_node(
        {
            "id": "amp-1",
            "type": "amplify_api",
            "config": {
                "base_url": "https://amplify.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-amplify",
    )
    assert amplify["output"]["provider"] == "amplify"

    fis = _execute_single_stub_node(
        {
            "id": "fis-1",
            "type": "fis_api",
            "config": {
                "base_url": "https://fis.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-fis",
    )
    assert fis["output"]["provider"] == "fis"

    resiliencehub = _execute_single_stub_node(
        {
            "id": "rh-1",
            "type": "resiliencehub_api",
            "config": {
                "base_url": "https://resiliencehub.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-resiliencehub",
    )
    assert resiliencehub["output"]["provider"] == "resiliencehub"

    wellarchitected = _execute_single_stub_node(
        {
            "id": "wa-1",
            "type": "wellarchitected_api",
            "config": {
                "base_url": "https://wellarchitected.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-wellarchitected",
    )
    assert wellarchitected["output"]["provider"] == "wellarchitected"

    support = _execute_single_stub_node(
        {
            "id": "sup-1",
            "type": "support_api",
            "config": {
                "base_url": "https://support.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-support",
    )
    assert support["output"]["provider"] == "support"

    trustedadvisor = _execute_single_stub_node(
        {
            "id": "ta-1",
            "type": "trustedadvisor_api",
            "config": {
                "base_url": "https://trustedadvisor.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-trustedadvisor",
    )
    assert trustedadvisor["output"]["provider"] == "trustedadvisor"

    controltower = _execute_single_stub_node(
        {
            "id": "ct-1",
            "type": "controltower_api",
            "config": {
                "base_url": "https://controltower.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-controltower",
    )
    assert controltower["output"]["provider"] == "controltower"

    servicecatalog = _execute_single_stub_node(
        {
            "id": "sc-1",
            "type": "servicecatalog_api",
            "config": {
                "base_url": "https://servicecatalog.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-servicecatalog",
    )
    assert servicecatalog["output"]["provider"] == "servicecatalog"

    lakeformation = _execute_single_stub_node(
        {
            "id": "lf-1",
            "type": "lakeformation_api",
            "config": {
                "base_url": "https://lakeformation.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-lakeformation",
    )
    assert lakeformation["output"]["provider"] == "lakeformation"

    ses = _execute_single_stub_node(
        {
            "id": "ses-1",
            "type": "ses_api",
            "config": {
                "base_url": "https://email.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ses",
    )
    assert ses["output"]["provider"] == "ses"

    pinpoint = _execute_single_stub_node(
        {
            "id": "pp-1",
            "type": "pinpoint_api",
            "config": {
                "base_url": "https://pinpoint.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-pinpoint",
    )
    assert pinpoint["output"]["provider"] == "pinpoint"



    connect = _execute_single_stub_node(
        {
            "id": "cn-1",
            "type": "connect_api",
            "config": {
                "base_url": "https://connect.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-connect",
    )
    assert connect["output"]["provider"] == "connect"

    chime = _execute_single_stub_node(
        {
            "id": "ch-1",
            "type": "chime_api",
            "config": {
                "base_url": "https://chime.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-chime",
    )
    assert chime["output"]["provider"] == "chime"




    ivs = _execute_single_stub_node(
        {
            "id": "ivs-1",
            "type": "ivs_api",
            "config": {
                "base_url": "https://ivs.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-ivs",
    )
    assert ivs["output"]["provider"] == "ivs"

    gamelift = _execute_single_stub_node(
        {
            "id": "gl-1",
            "type": "gamelift_api",
            "config": {
                "base_url": "https://gamelift.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-gamelift",
    )
    assert gamelift["output"]["provider"] == "gamelift"




    braket = _execute_single_stub_node(
        {
            "id": "bk-1",
            "type": "braket_api",
            "config": {
                "base_url": "https://braket.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-braket",
    )
    assert braket["output"]["provider"] == "braket"

    qldb = _execute_single_stub_node(
        {
            "id": "qldb-1",
            "type": "qldb_api",
            "config": {
                "base_url": "https://qldb.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-qldb",
    )
    assert qldb["output"]["provider"] == "qldb"


    timestream = _execute_single_stub_node(
        {
            "id": "ts-1",
            "type": "timestream_api",
            "config": {
                "base_url": "https://timestream.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-timestream",
    )
    assert timestream["output"]["provider"] == "timestream"

    appconfig = _execute_single_stub_node(
        {
            "id": "ac-1",
            "type": "appconfig_api",
            "config": {
                "base_url": "https://appconfig.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-appconfig",
    )
    assert appconfig["output"]["provider"] == "appconfig"


    grafana = _execute_single_stub_node(
        {
            "id": "gf-1",
            "type": "grafana_api",
            "config": {
                "base_url": "https://grafana.example.com",
                "path_template": "/api/dashboards",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-grafana",
    )
    assert grafana["output"]["provider"] == "grafana"

    prometheus = _execute_single_stub_node(
        {
            "id": "pm-1",
            "type": "prometheus_api",
            "config": {
                "base_url": "https://prometheus.example.com",
                "path_template": "/api/v1/query",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-prometheus",
    )
    assert prometheus["output"]["provider"] == "prometheus"


    location = _execute_single_stub_node(
        {
            "id": "loc-1",
            "type": "location_api",
            "config": {
                "base_url": "https://geo.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-location",
    )
    assert location["output"]["provider"] == "location"

    emrserverless = _execute_single_stub_node(
        {
            "id": "emrs-1",
            "type": "emrserverless_api",
            "config": {
                "base_url": "https://emr-serverless.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-emrserverless",
    )
    assert emrserverless["output"]["provider"] == "emrserverless"


    iot = _execute_single_stub_node(
        {
            "id": "iot-1",
            "type": "iot_api",
            "config": {
                "base_url": "https://iot.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-iot",
    )
    assert iot["output"]["provider"] == "iot"

    greengrass = _execute_single_stub_node(
        {
            "id": "gg-1",
            "type": "greengrass_api",
            "config": {
                "base_url": "https://greengrass.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-greengrass",
    )
    assert greengrass["output"]["provider"] == "greengrass"


    iotanalytics = _execute_single_stub_node(
        {
            "id": "iota-1",
            "type": "iotanalytics_api",
            "config": {
                "base_url": "https://iotanalytics.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-iotanalytics",
    )
    assert iotanalytics["output"]["provider"] == "iotanalytics"

    freertos = _execute_single_stub_node(
        {
            "id": "fr-1",
            "type": "freertos_api",
            "config": {
                "base_url": "https://iot.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-freertos",
    )
    assert freertos["output"]["provider"] == "freertos"

    datazone = _execute_single_stub_node(
        {
            "id": "dz-1",
            "type": "datazone_api",
            "config": {
                "base_url": "https://datazone.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-datazone",
    )
    assert datazone["output"]["provider"] == "datazone"

    cleanrooms = _execute_single_stub_node(
        {
            "id": "cr-1",
            "type": "cleanrooms_api",
            "config": {
                "base_url": "https://cleanrooms.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-cleanrooms",
    )
    assert cleanrooms["output"]["provider"] == "cleanrooms"


    entityresolution = _execute_single_stub_node(
        {
            "id": "er-1",
            "type": "entityresolution_api",
            "config": {
                "base_url": "https://entityresolution.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-entityresolution",
    )
    assert entityresolution["output"]["provider"] == "entityresolution"

    supplychain = _execute_single_stub_node(
        {
            "id": "sc-1",
            "type": "supplychain_api",
            "config": {
                "base_url": "https://scn.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-supplychain",
    )
    assert supplychain["output"]["provider"] == "supplychain"

    amp = _execute_single_stub_node(
        {
            "id": "amp-1",
            "type": "amp_api",
            "config": {
                "base_url": "https://aps-workspaces.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-amp",
    )
    assert amp["output"]["provider"] == "amp"

    managedgrafana = _execute_single_stub_node(
        {
            "id": "mg-1",
            "type": "managedgrafana_api",
            "config": {
                "base_url": "https://grafana.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-managedgrafana",
    )
    assert managedgrafana["output"]["provider"] == "managedgrafana"


    opensearchserverless = _execute_single_stub_node(
        {
            "id": "oss-1",
            "type": "opensearchserverless_api",
            "config": {
                "base_url": "https://aoss.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-opensearchserverless",
    )
    assert opensearchserverless["output"]["provider"] == "opensearchserverless"

    mwaa = _execute_single_stub_node(
        {
            "id": "mwaa-1",
            "type": "mwaa_api",
            "config": {
                "base_url": "https://airflow.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-mwaa",
    )
    assert mwaa["output"]["provider"] == "mwaa"

    appflow = _execute_single_stub_node(
        {
            "id": "af-1",
            "type": "appflow_api",
            "config": {
                "base_url": "https://appflow.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-appflow",
    )
    assert appflow["output"]["provider"] == "appflow"

    databrew = _execute_single_stub_node(
        {
            "id": "db-1",
            "type": "databrew_api",
            "config": {
                "base_url": "https://databrew.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-databrew",
    )
    assert databrew["output"]["provider"] == "databrew"


    healthlake = _execute_single_stub_node(
        {
            "id": "hl-1",
            "type": "healthlake_api",
            "config": {
                "base_url": "https://healthlake.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-healthlake",
    )
    assert healthlake["output"]["provider"] == "healthlake"

    medicalimaging = _execute_single_stub_node(
        {
            "id": "mi-1",
            "type": "medicalimaging_api",
            "config": {
                "base_url": "https://medical-imaging.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-medicalimaging",
    )
    assert medicalimaging["output"]["provider"] == "medicalimaging"

    omics = _execute_single_stub_node(
        {
            "id": "om-1",
            "type": "omics_api",
            "config": {
                "base_url": "https://omics.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-omics",
    )
    assert omics["output"]["provider"] == "omics"

    finspace = _execute_single_stub_node(
        {
            "id": "fs-1",
            "type": "finspace_api",
            "config": {
                "base_url": "https://finspace.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-finspace",
    )
    assert finspace["output"]["provider"] == "finspace"


    lookoutmetrics = _execute_single_stub_node(
        {
            "id": "lm-1",
            "type": "lookoutmetrics_api",
            "config": {
                "base_url": "https://lookoutmetrics.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-lookoutmetrics",
    )
    assert lookoutmetrics["output"]["provider"] == "lookoutmetrics"

    lookoutvision = _execute_single_stub_node(
        {
            "id": "lv-1",
            "type": "lookoutvision_api",
            "config": {
                "base_url": "https://lookoutvision.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-lookoutvision",
    )
    assert lookoutvision["output"]["provider"] == "lookoutvision"

    evidently = _execute_single_stub_node(
        {
            "id": "ev-1",
            "type": "evidently_api",
            "config": {
                "base_url": "https://evidently.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-evidently",
    )
    assert evidently["output"]["provider"] == "evidently"

    rum = _execute_single_stub_node(
        {
            "id": "rum-1",
            "type": "rum_api",
            "config": {
                "base_url": "https://rum.us-east-1.amazonaws.com",
                "path_template": "/",
                "method": "POST",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-rum",
    )
    assert rum["output"]["provider"] == "rum"








































def test_airtable_telegram_stubs():
    airtable = _execute_single_stub_node(
        {
            "id": "at-1",
            "type": "airtable_api",
            "config": {"path_template": "/v0/meta/bases", "method": "GET", "auth_binding_id": "b1"},
        },
        dry_run=True,
        trace_id="trace-at",
    )
    assert airtable["output"]["provider"] == "airtable"

    telegram = _execute_single_stub_node(
        {
            "id": "tg-1",
            "type": "telegram_notify",
            "config": {
                "chat_id_template": "123",
                "text_template": "hi",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-tg",
    )
    assert telegram["output"]["provider"] == "telegram"


def test_salesforce_servicenow_stubs():
    salesforce = _execute_single_stub_node(
        {
            "id": "sf-1",
            "type": "salesforce_api",
            "config": {
                "base_url": "https://example.my.salesforce.com",
                "path_template": "/services/data/v59.0/sobjects",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sf",
    )
    assert salesforce["output"]["provider"] == "salesforce"

    snow = _execute_single_stub_node(
        {
            "id": "sn-1",
            "type": "servicenow_api",
            "config": {
                "base_url": "https://example.service-now.com",
                "path_template": "/api/now/table/incident",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-sn",
    )
    assert snow["output"]["provider"] == "servicenow"


def test_github_jira_respond_stubs():
    github = _execute_single_stub_node(
        {
            "id": "gh-1",
            "type": "github_api",
            "config": {"path_template": "/user", "method": "GET", "auth_binding_id": "b1"},
        },
        dry_run=True,
        trace_id="trace-gh",
    )
    assert github["output"]["provider"] == "github"

    jira = _execute_single_stub_node(
        {
            "id": "ji-1",
            "type": "jira_api",
            "config": {
                "base_url": "https://example.atlassian.net",
                "path_template": "/rest/api/3/myself",
                "method": "GET",
                "auth_binding_id": "b1",
            },
        },
        dry_run=True,
        trace_id="trace-jira",
    )
    assert jira["output"]["provider"] == "jira"

    respond = _execute_single_stub_node(
        {
            "id": "rw-1",
            "type": "respond_to_webhook",
            "config": {"body_template": '{"ok":true}', "status_code": "200"},
        },
        dry_run=True,
        trace_id="trace-rw",
    )
    assert respond["output"]["webhook_response"] is True
