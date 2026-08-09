from __future__ import annotations

import asyncio
import base64
import csv
import gzip
import hashlib
import hmac
import html
import io
import json
import math
import re
import secrets
import time
import zlib
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Any, Callable, Optional
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.orm import Session

from app.api_errors import validation_error
from app.runtime_constants import (
    RUNTIME_CONFIG_ORCHESTRATION_HTTP_ALLOWED_HOSTS_JSON,
    RUNTIME_CONFIG_ORCHESTRATION_MAX_NODES_PER_FLOW,
    RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_APPROVAL,
    RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_ACCESS_CERTIFICATION,
)
from app.services.gateway_vector_stores import list_vector_stores
from app.services.gateway_notification_channels import (
    list_notification_channels,
    validate_recipient_template,
)
from app.services.runtime_config import get_runtime_config, get_runtime_config_int

FLOW_STATUSES = {"draft", "active", "disabled", "deprecated"}
FLOW_ENVIRONMENTS = {"dev", "staging", "prod"}
TRIGGER_TYPES = {"schedule", "webhook", "manual"}
APPROVAL_STATUSES = {"pending", "approved", "rejected"}
HTTP_AUTH_TYPES = {"none", "bearer", "basic", "api_key", "oidc_client_credentials", "workload_identity"}

GRAPH_NODE_TYPES = {
    "llm_chat",
    "mcp_tool",
    "http_request",
    "condition",
    "while_loop",
    "do_while",
    "schedule_trigger",
    "webhook_trigger",
    "memory_read",
    "memory_write",
    "vector_query",
    "vector_ingest",
    "embedding_create",
    "rag_query",
    "wait_delay",
    "guardrail_evaluate",
    "email_send",
    "sms_send",
    "human_approval",
    "parallel_fork",
    "parallel_join",
    "set_fields",
    "json_transform",
    "slack_webhook",
    "discord_webhook",
    "teams_webhook",
    "mattermost_webhook",
    "google_chat_webhook",
    "switch",
    "filter",
    "merge_data",
    "github_api",
    "gitlab_api",
    "bitbucket_api",
    "jira_api",
    "confluence_api",
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
}

MAX_SPLIT_BATCH_SIZE = 100
MAX_SPLIT_BATCH_INDEX = 10_000
MAX_FOREACH_ITEMS = 100
MAX_WHILE_ITERATIONS = 100
DEFAULT_WHILE_ITERATIONS = 25
MAX_WHILE_BODY_NODES = 50
MAX_WHILE_COLLECTED_RESULTS = 100
MAX_WHILE_DELAY_MS = 5_000
MAX_LIMIT_ITEMS = 1000
MAX_SUBFLOW_DEPTH = 3
MAX_CSV_ROWS = 500
MAX_UUID_COUNT = 20
MAX_WAIT_UNTIL_SECONDS = 3600
MAX_BOOLEAN_RULES = 20
MAX_PICK_FIELDS = 50
MAX_RENAME_KEYS = 50
MAX_HASH_INPUT_CHARS = 100_000
MAX_COALESCE_CANDIDATES = 10
MAX_BASE64_CHARS = 100_000
MAX_APPEND_ITEMS = 500
MAX_REGEX_PATTERN_LEN = 128
MAX_REGEX_INPUT_CHARS = 50_000
MAX_REGEX_MATCHES = 50
MAX_FLATTEN_DEPTH = 6
MAX_FLATTEN_KEYS = 200
MAX_XML_BYTES = 100_000
MAX_XML_ELEMENTS = 500
MAX_CHUNK_TEXT_CHARS = 100_000
MAX_CHUNK_COUNT = 200
MAX_CHUNK_SIZE = 8_000
FORM_URLENCODED_OPS = {"encode", "decode"}
MAX_DEEP_MERGE_DEPTH = 6
MAX_DEEP_MERGE_KEYS = 200
MAX_JWT_CHARS = 8_000
MAX_HTML_EXTRACT_BYTES = 100_000
MAX_HTML_LINKS = 100
MAX_SPLIT_PARTS = 200
HTML_EXTRACT_MODES = {"text", "links", "both"}
COMPRESS_OPS = {"compress", "decompress"}
COMPRESS_ALGOS = {"zlib", "gzip"}
MAX_COMPRESS_BYTES = 100_000
RANDOM_MODES = {"int", "uuid", "choice", "bytes"}
MAX_RANDOM_CHOICES = 100
MAX_RANDOM_BYTES = 64
HMAC_VERIFY_ALGOS = {"sha256", "sha1"}
MAX_OBJECT_DIFF_CHANGES = 200
ARRAY_OPS = {"slice", "reverse", "concat", "length", "first", "last", "unique"}
MAX_COMPACT_DEPTH = 6
MAX_COMPACT_KEYS = 200
GITHUB_API_BASE = "https://api.github.com"
GITLAB_API_BASE = "https://gitlab.com/api/v4"
BITBUCKET_API_BASE = "https://api.bitbucket.org/2.0"
STRIPE_API_BASE = "https://api.stripe.com"
# Named operations deepen allowlisted HTTP presets beyond raw path_template (Wave 1 leadership).
GITHUB_API_OPERATION_PRESETS: dict[str, dict[str, str]] = {
    "get_user": {"method": "GET", "path": "/user"},
    "get_repo": {"method": "GET", "path": "/repos/{owner}/{repo}"},
    "list_issues": {"method": "GET", "path": "/repos/{owner}/{repo}/issues"},
    "create_issue": {"method": "POST", "path": "/repos/{owner}/{repo}/issues"},
    "list_pulls": {"method": "GET", "path": "/repos/{owner}/{repo}/pulls"},
    "get_issue": {"method": "GET", "path": "/repos/{owner}/{repo}/issues/{issue_number}"},
}
SLACK_API_OPERATION_PRESETS: dict[str, dict[str, str]] = {
    "auth_test": {"method": "POST", "path": "/auth.test"},
    "chat_post_message": {"method": "POST", "path": "/chat.postMessage"},
    "conversations_list": {"method": "GET", "path": "/conversations.list"},
    "users_info": {"method": "GET", "path": "/users.info"},
}
STRIPE_API_OPERATION_PRESETS: dict[str, dict[str, str]] = {
    "get_balance": {"method": "GET", "path": "/v1/balance"},
    "list_customers": {"method": "GET", "path": "/v1/customers"},
    "list_charges": {"method": "GET", "path": "/v1/charges"},
    "create_customer": {"method": "POST", "path": "/v1/customers"},
}
# Hosts required for leadership-class live connectors (Wave 2 bootstrap).
LEADERSHIP_CONNECTOR_HOSTS: tuple[str, ...] = (
    "api.github.com",
    "slack.com",
    "api.stripe.com",
)


def resolve_connector_operation_preset(
    node_type: str,
    config: dict[str, Any],
    *,
    owner: str = "",
    repo: str = "",
    issue_number: str = "",
) -> tuple[Optional[str], Optional[str]]:
    """Map `operation` to (method, path). Explicit path_template/method in config still win."""
    operation = str(config.get("operation") or "").strip().lower()
    if not operation:
        return None, None
    catalog = {
        "github_api": GITHUB_API_OPERATION_PRESETS,
        "slack_api": SLACK_API_OPERATION_PRESETS,
        "stripe_api": STRIPE_API_OPERATION_PRESETS,
    }.get(node_type)
    if not catalog:
        return None, None
    preset = catalog.get(operation)
    if not preset:
        return None, None
    path = str(preset.get("path") or "")
    if "{owner}" in path or "{repo}" in path or "{issue_number}" in path:
        path = path.replace("{owner}", str(owner or "").strip() or "OWNER")
        path = path.replace("{repo}", str(repo or "").strip() or "REPO")
        path = path.replace("{issue_number}", str(issue_number or "").strip() or "1")
    return str(preset.get("method") or "GET").upper(), path
BOX_API_BASE = "https://api.box.com/2.0"
DROPBOX_API_BASE = "https://api.dropboxapi.com"
CALENDLY_API_BASE = "https://api.calendly.com"
MICROSOFT_GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
GOOGLE_SHEETS_API_BASE = "https://sheets.googleapis.com/v4"
GOOGLE_DRIVE_API_BASE = "https://www.googleapis.com/drive/v3"
GOOGLE_CALENDAR_API_BASE = "https://www.googleapis.com/calendar/v3"
SLACK_API_BASE = "https://slack.com/api"
ZOOM_API_BASE = "https://api.zoom.us/v2"
TWILIO_API_BASE = "https://api.twilio.com"
SENDGRID_API_BASE = "https://api.sendgrid.com"
LINEAR_API_BASE = "https://api.linear.app"
NOTION_API_BASE = "https://api.notion.com"
NOTION_API_VERSION = "2022-06-28"
HUBSPOT_API_BASE = "https://api.hubapi.com"
AIRTABLE_API_BASE = "https://api.airtable.com"
TELEGRAM_API_BASE = "https://api.telegram.org"
ASANA_API_BASE = "https://app.asana.com"
CLICKUP_API_BASE = "https://api.clickup.com"
INTERCOM_API_BASE = "https://api.intercom.io"
INTERCOM_API_VERSION = "2.11"
MONDAY_API_BASE = "https://api.monday.com"
PAGERDUTY_EVENTS_API_BASE = "https://events.pagerduty.com"
OPSGENIE_API_BASE = "https://api.opsgenie.com"
DATADOG_API_BASE = "https://api.datadoghq.com"
DATADOG_ALERT_TYPES = {"error", "warning", "info", "success", "user_update"}
SENTRY_API_BASE = "https://sentry.io"
SENTRY_LEVELS = {"fatal", "error", "warning", "info", "debug"}
STATUSPAGE_API_BASE = "https://api.statuspage.io"
STATUSPAGE_STATUSES = {"investigating", "identified", "monitoring", "resolved"}
STATUSPAGE_IMPACTS = {"none", "minor", "major", "critical"}
TRELLO_API_BASE = "https://api.trello.com"
URL_OPS = {"encode", "decode", "parse_query", "build_query"}
BASE64_OPS = {"encode", "decode"}
NUMBER_FORMAT_STYLES = {"decimal", "integer", "percent", "currency_prefix"}
_HTML_TAG_PATTERN = re.compile(r"<[^>]+>")
_UNSAFE_REGEX_PATTERN = re.compile(
    r"\(\?[^:=!<>]|\{(?:\d+,){2,}|\+\+|\*\*|\([^)]*[+*][^)]*\)[+*{]"
)
DATE_TIME_OPS = {"now", "parse", "format", "add", "subtract", "diff"}
SORT_ORDERS = {"asc", "desc"}
STRING_OPS = {
    "lower",
    "upper",
    "trim",
    "replace",
    "split",
    "join",
    "contains",
    "length",
    "substring",
    "startswith",
    "endswith",
}
COMPARE_OPS = {"==", "!=", "contains", "gt", "lt", ">", "<", "exists"}
MATH_OPS = {"add", "sub", "mul", "div", "mod", "round", "abs", "min", "max", "ceil", "floor"}
HASH_ALGORITHMS = {"sha256", "sha1", "md5", "hmac-sha256"}
BOOLEAN_COMBINE = {"and", "or"}

_STEP_OUTPUT_TEMPLATE_PATTERN = re.compile(
    r"\{\{steps\[['\"]([^'\"]+)['\"]\]\.output(?:\.([a-zA-Z0-9_.\[\]]+))?\}\}"
)
_ITEM_TEMPLATE_PATTERN = re.compile(r"\{\{item(?:\.([a-zA-Z0-9_.\[\]]+))?\}\}")
_LOOP_TEMPLATE_PATTERN = re.compile(r"\{\{loop(?:\.([a-zA-Z0-9_.\[\]]+))?\}\}")
AGGREGATE_MODES = {"count", "pluck", "unique", "sum", "first", "last"}

LLM_CHAT_RESPONSE_FORMATS = {"text", "json_object"}
LLM_CHAT_CACHE_MODES = {"inherit", "bypass", "force"}

MAX_PARALLEL_BRANCHES = 5
MIN_PARALLEL_BRANCHES = 2

INLINE_SECRET_FIELD_PATTERN = re.compile(
    r"(api[_-]?key|secret|password|token|authorization|bearer)",
    re.IGNORECASE,
)

CRON_PATTERN = re.compile(
    r"^(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)$"
)

JSON_PATH_PATTERN = re.compile(r"^\$(?:(?:\.\w+)|(?:\[\d+\]))+$")

NODE_TYPE_CATALOG: list[dict[str, Any]] = [
    {
        "type": "llm_chat",
        "label": "LLM Chat",
        "description": "Gateway chat completion using catalog model, agent config, and prompt template.",
        "required_config_fields": ["prompt_template"],
        "optional_config_fields": [
            "model_id",
            "agent_key",
            "binding_id",
            "temperature",
            "route_id",
            "prompt_registry_id",
            "max_tokens",
            "response_format",
            "cache_mode",
            "continue_on_error",
            "max_retries",
            "retry_delay_seconds",
            "error_branch",
        ],
    },
    {
        "type": "mcp_tool",
        "label": "MCP Tool Call",
        "description": "Invoke a tool from the gateway MCP server registry.",
        "required_config_fields": ["server_id", "tool_name"],
        "optional_config_fields": ["arguments_json", "binding_id", "continue_on_error", "error_branch"],
    },
    {
        "type": "http_request",
        "label": "HTTP Request",
        "description": "Outbound HTTP to allowlisted hosts only; auth via credential binding refs — no inline secrets.",
        "required_config_fields": ["url", "method"],
        "optional_config_fields": [
            "headers_json",
            "body_template",
            "auth_type",
            "auth_binding_id",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "condition",
        "label": "Condition",
        "description": "If/else branch on a safe expression or JSON path from a prior step output.",
        "required_config_fields": ["expression"],
        "optional_config_fields": [
            "source_node_id",
            "json_path",
            "operator",
            "compare_value",
            "true_branch",
            "false_branch",
        ],
    },
    {
        "type": "while_loop",
        "label": "While",
        "description": "Repeat a body branch while a condition is true (hard max iterations — no unbounded loops).",
        "required_config_fields": ["body_branch"],
        "optional_config_fields": [
            "source_node_id",
            "json_path",
            "operator",
            "compare_value",
            "expression",
            "exit_branch",
            "max_iterations",
            "collect_results",
            "delay_between_iterations_ms",
        ],
    },
    {
        "type": "do_while",
        "label": "Do while",
        "description": "Run a body branch once, then repeat while a condition stays true (hard max iterations).",
        "required_config_fields": ["body_branch"],
        "optional_config_fields": [
            "source_node_id",
            "json_path",
            "operator",
            "compare_value",
            "expression",
            "exit_branch",
            "max_iterations",
            "collect_results",
            "delay_between_iterations_ms",
        ],
    },
    {
        "type": "schedule_trigger",
        "label": "Schedule Trigger",
        "description": "Cron schedule stored in flow trigger configuration.",
        "required_config_fields": ["cron_expression"],
        "optional_config_fields": [],
    },
    {
        "type": "webhook_trigger",
        "label": "Webhook Trigger",
        "description": "Incoming webhook path with optional Bearer token and HMAC secret binding refs.",
        "required_config_fields": ["webhook_path_ref"],
        "optional_config_fields": ["token_binding_id", "hmac_secret_binding_id"],
    },
    {
        "type": "memory_read",
        "label": "Memory Read",
        "description": "Read gateway memory for a scope.",
        "required_config_fields": ["scope_type", "scope_id", "memory_tier"],
        "optional_config_fields": ["label_filter"],
    },
    {
        "type": "memory_write",
        "label": "Memory Write",
        "description": "Write gateway memory for a scope.",
        "required_config_fields": ["scope_type", "scope_id", "memory_tier", "content_template"],
        "optional_config_fields": ["label"],
    },
    {
        "type": "vector_query",
        "label": "Vector Search",
        "description": "Semantic search against a configured vector store registry entry.",
        "required_config_fields": ["store_id", "query"],
        "optional_config_fields": ["top_k"],
    },
    {
        "type": "vector_ingest",
        "label": "Vector Ingest",
        "description": "Ingest text into a configured vector store (mcp_bridge and supported backends).",
        "required_config_fields": ["store_id", "content_template"],
        "optional_config_fields": ["document_id"],
    },
    {
        "type": "embedding_create",
        "label": "Create Embedding",
        "description": "Gateway embedding creation using catalog model and input template.",
        "required_config_fields": ["model_id", "input_template"],
        "optional_config_fields": ["binding_id"],
    },
    {
        "type": "rag_query",
        "label": "RAG Query",
        "description": "Retrieval-augmented query against a configured vector store registry entry (credentials come from the store / MCP bridge).",
        "required_config_fields": ["store_id", "query_template"],
        "optional_config_fields": ["top_k"],
    },
    {
        "type": "wait_delay",
        "label": "Wait / Delay",
        "description": "Pause flow execution for a configured number of seconds.",
        "required_config_fields": ["delay_seconds"],
        "optional_config_fields": [],
    },
    {
        "type": "guardrail_evaluate",
        "label": "Guardrail Evaluate",
        "description": "Evaluate gateway guardrail policy against an input template.",
        "required_config_fields": ["key_id", "input_template"],
        "optional_config_fields": ["guardrail_policy_id"],
    },
    {
        "type": "email_send",
        "label": "Send Email",
        "description": "Send email via a gateway notification channel registry entry with live provider delivery.",
        "required_config_fields": ["channel_id", "to_template", "subject_template", "body_template"],
        "optional_config_fields": ["from_override"],
    },
    {
        "type": "sms_send",
        "label": "Send SMS",
        "description": "Send SMS via a gateway notification channel registry entry with live provider delivery.",
        "required_config_fields": ["channel_id", "to_template", "body_template"],
        "optional_config_fields": ["from_override"],
    },
    {
        "type": "human_approval",
        "label": "Human Approval",
        "description": "Creates an approval gate; prod runs require dual approval.",
        "required_config_fields": ["approval_title"],
        "optional_config_fields": [
            "required_role",
            "instructions",
            "approver_source",
            "source_node_id",
            "approver_role_json_path",
            "approver_id_json_path",
        ],
    },
    {
        "type": "parallel_fork",
        "label": "Parallel Fork",
        "description": "Split flow into parallel branches that run concurrently before merging.",
        "required_config_fields": ["group_id"],
        "optional_config_fields": ["branch_count"],
    },
    {
        "type": "parallel_join",
        "label": "Parallel Join",
        "description": "Merge parallel branches and continue serial execution.",
        "required_config_fields": ["group_id", "fork_node_id"],
        "optional_config_fields": [],
    },
    {
        "type": "set_fields",
        "label": "Set Fields",
        "description": "Build a structured object from templates (n8n Set-style) for downstream steps.",
        "required_config_fields": ["fields_json"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "json_transform",
        "label": "JSON Transform",
        "description": "Map fields from a prior step output into a new JSON object using templates.",
        "required_config_fields": ["source_node_id", "mapping_json"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "slack_webhook",
        "label": "Slack Webhook",
        "description": "Post a message to an allowlisted Slack incoming webhook URL (no inline bot tokens).",
        "required_config_fields": ["webhook_url", "text_template"],
        "optional_config_fields": ["blocks_json", "continue_on_error", "error_branch"],
    },
    {
        "type": "discord_webhook",
        "label": "Discord Webhook",
        "description": "Post a message to an allowlisted Discord incoming webhook URL.",
        "required_config_fields": ["webhook_url", "content_template"],
        "optional_config_fields": ["embeds_json", "continue_on_error", "error_branch"],
    },
    {
        "type": "teams_webhook",
        "label": "Teams Webhook",
        "description": "Post a message to an allowlisted Microsoft Teams incoming webhook URL.",
        "required_config_fields": ["webhook_url", "text_template"],
        "optional_config_fields": ["title_template", "continue_on_error", "error_branch"],
    },
    {
        "type": "mattermost_webhook",
        "label": "Mattermost Webhook",
        "description": "Post a message to an allowlisted Mattermost incoming webhook URL.",
        "required_config_fields": ["webhook_url", "text_template"],
        "optional_config_fields": [
            "username_template",
            "channel_template",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "google_chat_webhook",
        "label": "Google Chat Webhook",
        "description": "Post a text message to an allowlisted Google Chat incoming webhook URL.",
        "required_config_fields": ["webhook_url", "text_template"],
        "optional_config_fields": ["thread_key_template", "continue_on_error", "error_branch"],
    },
    {
        "type": "switch",
        "label": "Switch",
        "description": "Multi-case router on a JSON path from a prior step (n8n Switch-style).",
        "required_config_fields": ["source_node_id", "json_path", "cases_json"],
        "optional_config_fields": ["default_branch"],
    },
    {
        "type": "filter",
        "label": "Filter",
        "description": "Keep array items that match a safe JSON-path condition (no code execution).",
        "required_config_fields": ["source_node_id", "items_path", "operator"],
        "optional_config_fields": ["item_json_path", "compare_value", "continue_on_error", "error_branch"],
    },
    {
        "type": "merge_data",
        "label": "Merge Data",
        "description": "Combine two prior step outputs into one object (shallow, prefer-a/b, or nest).",
        "required_config_fields": ["source_a_node_id", "source_b_node_id"],
        "optional_config_fields": ["merge_mode", "continue_on_error", "error_branch"],
    },
    {
        "type": "github_api",
        "label": "GitHub API",
        "description": "Call api.github.com with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "gitlab_api",
        "label": "GitLab API",
        "description": "Call gitlab.com/api/v4 with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "bitbucket_api",
        "label": "Bitbucket API",
        "description": "Call api.bitbucket.org/2.0 with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "jira_api",
        "label": "Jira API",
        "description": "Call a Jira Cloud/Server REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "confluence_api",
        "label": "Confluence API",
        "description": "Call Confluence Cloud/Server wiki REST with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "respond_to_webhook",
        "label": "Respond to Webhook",
        "description": "Shape the synchronous webhook HTTP response body/status for this run.",
        "required_config_fields": ["body_template"],
        "optional_config_fields": ["status_code", "content_type", "source_node_id"],
    },
    {
        "type": "split_in_batches",
        "label": "Split In Batches",
        "description": "Slice an array into a capped batch for downstream steps (no unbounded loops).",
        "required_config_fields": ["source_node_id", "items_path", "batch_size"],
        "optional_config_fields": ["batch_index", "continue_on_error", "error_branch"],
    },
    {
        "type": "limit",
        "label": "Limit",
        "description": "Take a capped slice of an array (offset + limit) for safer downstream processing.",
        "required_config_fields": ["source_node_id", "items_path", "limit"],
        "optional_config_fields": ["offset", "continue_on_error", "error_branch"],
    },
    {
        "type": "aggregate",
        "label": "Aggregate",
        "description": "Count, pluck, unique, sum, first, or last over an array — declarative only.",
        "required_config_fields": ["source_node_id", "items_path", "aggregate_mode"],
        "optional_config_fields": ["item_json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "foreach_map",
        "label": "For Each Map",
        "description": "Map each array item through templates ({{item.field}}) with a hard item cap — no code eval.",
        "required_config_fields": ["source_node_id", "items_path", "mapping_json"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "linear_api",
        "label": "Linear API",
        "description": "Call api.linear.app (GraphQL/REST path) with a credential binding; host must be allowlisted.",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "notion_api",
        "label": "Notion API",
        "description": "Call api.notion.com with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "notion_version",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "sort",
        "label": "Sort",
        "description": "Sort an array by a JSON path key (asc/desc) — declarative only.",
        "required_config_fields": ["source_node_id", "items_path"],
        "optional_config_fields": ["sort_key_path", "order", "continue_on_error", "error_branch"],
    },
    {
        "type": "dedupe",
        "label": "Dedupe",
        "description": "Remove duplicate array items by full value or a JSON path key.",
        "required_config_fields": ["source_node_id", "items_path"],
        "optional_config_fields": ["item_json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "json_parse",
        "label": "JSON Parse",
        "description": "Parse a JSON string from a template or prior step field into an object/array.",
        "required_config_fields": ["text_template"],
        "optional_config_fields": ["source_node_id", "json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "date_time",
        "label": "Date & Time",
        "description": "UTC now, parse/format, add/subtract duration, or diff two timestamps — fixed operations only (no code).",
        "required_config_fields": ["operation"],
        "optional_config_fields": [
            "value_template",
            "compare_value_template",
            "input_format",
            "output_format",
            "amount",
            "unit",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "execute_subflow",
        "label": "Execute Subflow",
        "description": "Run another saved flow by ID (depth-capped; no recursive self-calls).",
        "required_config_fields": ["target_flow_id"],
        "optional_config_fields": ["input_template", "continue_on_error", "error_branch"],
    },
    {
        "type": "string_ops",
        "label": "String Ops",
        "description": "Safe string transforms: lower/upper/trim/replace/split/join/contains/length/substring.",
        "required_config_fields": ["operation", "value_template"],
        "optional_config_fields": [
            "search_template",
            "replace_template",
            "separator",
            "start",
            "end",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "compare",
        "label": "Compare",
        "description": "Compare two prior-step values with safe operators (==, !=, contains, gt, lt, exists).",
        "required_config_fields": ["source_a_node_id", "operator"],
        "optional_config_fields": [
            "json_path_a",
            "source_b_node_id",
            "json_path_b",
            "compare_value",
            "true_branch",
            "false_branch",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "math_ops",
        "label": "Math Ops",
        "description": "Safe numeric ops: add/sub/mul/div/mod/round/abs/min/max/ceil/floor (no eval).",
        "required_config_fields": ["operation", "a_template"],
        "optional_config_fields": ["b_template", "precision", "continue_on_error", "error_branch"],
    },
    {
        "type": "wait_until",
        "label": "Wait Until",
        "description": "Wait until an ISO datetime (capped; complements wait_delay).",
        "required_config_fields": ["until_template"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "uuid_gen",
        "label": "UUID Gen",
        "description": "Generate UUID4 values for idempotency keys (capped count).",
        "required_config_fields": [],
        "optional_config_fields": ["count", "prefix", "continue_on_error", "error_branch"],
    },
    {
        "type": "salesforce_api",
        "label": "Salesforce API",
        "description": "Call a Salesforce instance REST path with a credential binding (host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "servicenow_api",
        "label": "ServiceNow API",
        "description": "Call a ServiceNow instance REST path with a credential binding (host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "csv_parse",
        "label": "CSV Parse",
        "description": "Parse CSV text into an array of row objects (capped rows; no code execution).",
        "required_config_fields": ["text_template"],
        "optional_config_fields": ["has_header", "delimiter", "continue_on_error", "error_branch"],
    },
    {
        "type": "static_data",
        "label": "Static Data",
        "description": "Emit a constant JSON object (templates allowed) for downstream steps.",
        "required_config_fields": ["fields_json"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "hubspot_api",
        "label": "HubSpot API",
        "description": "Call api.hubapi.com with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "zendesk_api",
        "label": "Zendesk API",
        "description": "Call a Zendesk subdomain REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "freshdesk_api",
        "label": "Freshdesk API",
        "description": "Call a Freshdesk subdomain REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "hash_digest",
        "label": "Hash Digest",
        "description": "SHA-256/SHA-1/MD5 or HMAC-SHA256 of a template value (no secrets stored in-graph for HMAC key).",
        "required_config_fields": ["algorithm", "value_template"],
        "optional_config_fields": ["key_template", "continue_on_error", "error_branch"],
    },
    {
        "type": "stop_and_error",
        "label": "Stop and Error",
        "description": "Fail the flow with a templated error message (n8n Stop and Error).",
        "required_config_fields": ["message_template"],
        "optional_config_fields": ["error_branch", "continue_on_error"],
    },
    {
        "type": "noop",
        "label": "No Operation",
        "description": "Pass-through placeholder step (n8n No Operation).",
        "required_config_fields": [],
        "optional_config_fields": ["source_node_id", "note"],
    },
    {
        "type": "json_to_csv",
        "label": "JSON to CSV",
        "description": "Serialize an array of objects to CSV text (capped rows).",
        "required_config_fields": ["source_node_id", "items_path"],
        "optional_config_fields": ["delimiter", "include_header", "continue_on_error", "error_branch"],
    },
    {
        "type": "split_out",
        "label": "Split Out",
        "description": "Promote a nested array into items for downstream batch/filter steps.",
        "required_config_fields": ["source_node_id", "items_path"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "pick_fields",
        "label": "Pick Fields",
        "description": "Keep only selected keys from a prior-step object (declarative allowlist).",
        "required_config_fields": ["source_node_id", "fields"],
        "optional_config_fields": ["json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "rename_keys",
        "label": "Rename Keys",
        "description": "Rename object keys via a JSON mapping (no code eval).",
        "required_config_fields": ["source_node_id", "mapping_json"],
        "optional_config_fields": ["json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "boolean_logic",
        "label": "Boolean Logic",
        "description": "AND/OR combine up to 20 safe compare rules, with optional true/false branches.",
        "required_config_fields": ["rules_json", "combine"],
        "optional_config_fields": ["true_branch", "false_branch", "continue_on_error", "error_branch"],
    },
    {
        "type": "airtable_api",
        "label": "Airtable API",
        "description": "Call api.airtable.com with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "telegram_notify",
        "label": "Telegram Notify",
        "description": "Send a Telegram Bot API message via credential binding (api.telegram.org allowlisted).",
        "required_config_fields": ["chat_id_template", "text_template", "auth_binding_id"],
        "optional_config_fields": ["parse_mode", "continue_on_error", "error_branch"],
    },
    {
        "type": "html_strip",
        "label": "HTML Strip",
        "description": "Strip HTML tags and unescape entities from text (no JS execution).",
        "required_config_fields": ["value_template"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "url_ops",
        "label": "URL Ops",
        "description": "Safe URL encode/decode/parse_query/build_query helpers.",
        "required_config_fields": ["operation", "value_template"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "base64_ops",
        "label": "Base64 Ops",
        "description": "Encode or decode Base64 text (size-capped; no binary file IO).",
        "required_config_fields": ["operation", "value_template"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "coalesce",
        "label": "Coalesce",
        "description": "Return the first non-empty candidate from a JSON list of templates.",
        "required_config_fields": ["candidates_json"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "omit_fields",
        "label": "Omit Fields",
        "description": "Drop selected keys from a prior-step object (declarative denylist).",
        "required_config_fields": ["source_node_id", "fields"],
        "optional_config_fields": ["json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "append_items",
        "label": "Append Items",
        "description": "Concatenate two arrays from prior steps into one items list (capped).",
        "required_config_fields": ["source_a_node_id", "source_b_node_id"],
        "optional_config_fields": [
            "items_path_a",
            "items_path_b",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "graphql_request",
        "label": "GraphQL Request",
        "description": "POST a GraphQL query to an allowlisted URL with a credential binding.",
        "required_config_fields": ["url", "query_template", "auth_binding_id"],
        "optional_config_fields": [
            "variables_json",
            "operation_name",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "asana_api",
        "label": "Asana API",
        "description": "Call app.asana.com API paths with a credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "clickup_api",
        "label": "ClickUp API",
        "description": "Call api.clickup.com paths with a credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "intercom_api",
        "label": "Intercom API",
        "description": "Call api.intercom.io paths with a credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "intercom_version",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "monday_api",
        "label": "Monday.com API",
        "description": "Call api.monday.com GraphQL/REST paths with a credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "pipedrive_api",
        "label": "Pipedrive API",
        "description": "Call a Pipedrive company REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "shopify_api",
        "label": "Shopify API",
        "description": "Call a Shopify Admin REST path with a credential binding (shop base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "stripe_api",
        "label": "Stripe API",
        "description": "Call api.stripe.com with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "box_api",
        "label": "Box API",
        "description": "Call api.box.com/2.0 with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "dropbox_api",
        "label": "Dropbox API",
        "description": "Call api.dropboxapi.com with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "calendly_api",
        "label": "Calendly API",
        "description": "Call api.calendly.com with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "microsoft_graph_api",
        "label": "Microsoft Graph API",
        "description": "Call graph.microsoft.com/v1.0 with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "google_sheets_api",
        "label": "Google Sheets API",
        "description": "Call sheets.googleapis.com/v4 with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "google_drive_api",
        "label": "Google Drive API",
        "description": "Call www.googleapis.com/drive/v3 with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "google_calendar_api",
        "label": "Google Calendar API",
        "description": "Call www.googleapis.com/calendar/v3 with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "slack_api",
        "label": "Slack API",
        "description": "Call slack.com/api with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "zoom_api",
        "label": "Zoom API",
        "description": "Call api.zoom.us/v2 with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "twilio_api",
        "label": "Twilio API",
        "description": "Call api.twilio.com with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "sendgrid_api",
        "label": "SendGrid API",
        "description": "Call api.sendgrid.com with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "freshservice_api",
        "label": "Freshservice API",
        "description": "Call a Freshservice subdomain REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "okta_api",
        "label": "Okta API",
        "description": "Call an Okta org REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "auth0_api",
        "label": "Auth0 API",
        "description": "Call an Auth0 tenant Management API path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "azure_devops_api",
        "label": "Azure DevOps API",
        "description": "Call an Azure DevOps org REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "snowflake_api",
        "label": "Snowflake API",
        "description": "Call a Snowflake account SQL API path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "databricks_api",
        "label": "Databricks API",
        "description": "Call a Databricks workspace REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "bigquery_api",
        "label": "BigQuery API",
        "description": "Call a Google BigQuery REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "splunk_api",
        "label": "Splunk API",
        "description": "Call a Splunk management/search REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "elasticsearch_api",
        "label": "Elasticsearch API",
        "description": "Call an Elasticsearch/_search REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "redis_api",
        "label": "Redis REST API",
        "description": "Call a Redis REST/JSON API path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "mongodb_api",
        "label": "MongoDB Data API",
        "description": "Call a MongoDB Data/Atlas API path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "postgres_api",
        "label": "Postgres REST API",
        "description": "Call a PostgREST/Postgres HTTP API path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "mysql_api",
        "label": "MySQL REST API",
        "description": "Call a MySQL HTTP/REST gateway path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "s3_api",
        "label": "S3 REST API",
        "description": "Call an S3-compatible REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "pinecone_api",
        "label": "Pinecone API",
        "description": "Call a Pinecone index/control REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "weaviate_api",
        "label": "Weaviate API",
        "description": "Call a Weaviate REST/GraphQL path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "qdrant_api",
        "label": "Qdrant API",
        "description": "Call a Qdrant REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "supabase_api",
        "label": "Supabase API",
        "description": "Call a Supabase REST/RPC path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "kafka_api",
        "label": "Kafka REST API",
        "description": "Call a Kafka REST Proxy path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "milvus_api",
        "label": "Milvus API",
        "description": "Call a Milvus REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "chroma_api",
        "label": "Chroma API",
        "description": "Call a Chroma REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "neo4j_api",
        "label": "Neo4j API",
        "description": "Call a Neo4j HTTP/Cypher REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "rabbitmq_api",
        "label": "RabbitMQ API",
        "description": "Call a RabbitMQ Management/HTTP API path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "opensearch_api",
        "label": "OpenSearch API",
        "description": "Call an OpenSearch REST path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "clickhouse_api",
        "label": "ClickHouse API",
        "description": "Call a ClickHouse HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "dynamodb_api",
        "label": "DynamoDB API",
        "description": "Call a DynamoDB HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "nats_api",
        "label": "NATS API",
        "description": "Call a NATS HTTP monitoring/API path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "cassandra_api",
        "label": "Cassandra API",
        "description": "Call a Cassandra/Stargate HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "couchbase_api",
        "label": "Couchbase API",
        "description": "Call a Couchbase HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "influxdb_api",
        "label": "InfluxDB API",
        "description": "Call an InfluxDB HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "firebase_api",
        "label": "Firebase API",
        "description": "Call a Firebase/Firestore HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "airbyte_api",
        "label": "Airbyte API",
        "description": "Call an Airbyte HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "presto_api",
        "label": "Presto API",
        "description": "Call a Presto/PrestoDB HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "trino_api",
        "label": "Trino API",
        "description": "Call a Trino HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "redshift_api",
        "label": "Redshift API",
        "description": "Call an Amazon Redshift Data API HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "athena_api",
        "label": "Athena API",
        "description": "Call an Amazon Athena HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "pulsar_api",
        "label": "Pulsar API",
        "description": "Call an Apache Pulsar HTTP/admin path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "scylladb_api",
        "label": "ScyllaDB API",
        "description": "Call a ScyllaDB/Alternator HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "sqs_api",
        "label": "SQS API",
        "description": "Call an Amazon SQS HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "sns_api",
        "label": "SNS API",
        "description": "Call an Amazon SNS HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "kinesis_api",
        "label": "Kinesis API",
        "description": "Call an Amazon Kinesis HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "eventbridge_api",
        "label": "EventBridge API",
        "description": "Call an Amazon EventBridge HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "lambda_api",
        "label": "Lambda API",
        "description": "Call an Amazon Lambda HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "stepfunctions_api",
        "label": "Step Functions API",
        "description": "Call an Amazon Step Functions HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "cloudwatch_api",
        "label": "CloudWatch API",
        "description": "Call an Amazon CloudWatch HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "xray_api",
        "label": "X-Ray API",
        "description": "Call an Amazon X-Ray HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "glue_api",
        "label": "Glue API",
        "description": "Call an Amazon Glue HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "sagemaker_api",
        "label": "SageMaker API",
        "description": "Call an Amazon SageMaker HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "bedrock_api",
        "label": "Bedrock API",
        "description": "Call an Amazon Bedrock HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "comprehend_api",
        "label": "Comprehend API",
        "description": "Call an Amazon Comprehend HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "textract_api",
        "label": "Textract API",
        "description": "Call an Amazon Textract HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "rekognition_api",
        "label": "Rekognition API",
        "description": "Call an Amazon Rekognition HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "translate_api",
        "label": "Translate API",
        "description": "Call an Amazon Translate HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "polly_api",
        "label": "Polly API",
        "description": "Call an Amazon Polly HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "transcribe_api",
        "label": "Transcribe API",
        "description": "Call an Amazon Transcribe HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "lex_api",
        "label": "Lex API",
        "description": "Call an Amazon Lex HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "ecs_api",
        "label": "ECS API",
        "description": "Call an Amazon ECS HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "eks_api",
        "label": "EKS API",
        "description": "Call an Amazon EKS HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "secretsmanager_api",
        "label": "Secrets Manager API",
        "description": "Call an AWS Secrets Manager HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "ssm_api",
        "label": "SSM API",
        "description": "Call an AWS Systems Manager HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "cognito_api",
        "label": "Cognito API",
        "description": "Call an Amazon Cognito HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "iam_api",
        "label": "IAM API",
        "description": "Call an AWS IAM HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "kms_api",
        "label": "KMS API",
        "description": "Call an AWS KMS HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "sts_api",
        "label": "STS API",
        "description": "Call an AWS STS HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "apigateway_api",
        "label": "API Gateway API",
        "description": "Call an Amazon API Gateway HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "cloudformation_api",
        "label": "CloudFormation API",
        "description": "Call an AWS CloudFormation HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "rds_api",
        "label": "RDS API",
        "description": "Call an Amazon RDS HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "elb_api",
        "label": "ELB API",
        "description": "Call an AWS Elastic Load Balancing HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "cloudfront_api",
        "label": "CloudFront API",
        "description": "Call an Amazon CloudFront HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "route53_api",
        "label": "Route 53 API",
        "description": "Call an Amazon Route 53 HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "cloudtrail_api",
        "label": "CloudTrail API",
        "description": "Call an AWS CloudTrail HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "config_api",
        "label": "AWS Config API",
        "description": "Call an AWS Config HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "guardduty_api",
        "label": "GuardDuty API",
        "description": "Call an Amazon GuardDuty HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "securityhub_api",
        "label": "Security Hub API",
        "description": "Call an AWS Security Hub HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "inspector_api",
        "label": "Inspector API",
        "description": "Call an Amazon Inspector HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "macie_api",
        "label": "Macie API",
        "description": "Call an Amazon Macie HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "waf_api",
        "label": "WAF API",
        "description": "Call an AWS WAF HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "shield_api",
        "label": "Shield API",
        "description": "Call an AWS Shield HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "acm_api",
        "label": "ACM API",
        "description": "Call an AWS Certificate Manager HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "networkfirewall_api",
        "label": "Network Firewall API",
        "description": "Call an AWS Network Firewall HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "ecr_api",
        "label": "ECR API",
        "description": "Call an Amazon ECR HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "efs_api",
        "label": "EFS API",
        "description": "Call an Amazon EFS HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "detective_api",
        "label": "Detective API",
        "description": "Call an Amazon Detective HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "accessanalyzer_api",
        "label": "Access Analyzer API",
        "description": "Call an AWS IAM Access Analyzer HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "fargate_api",
        "label": "Fargate API",
        "description": "Call an Amazon ECS/Fargate HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "batch_api",
        "label": "Batch API",
        "description": "Call an AWS Batch HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "elasticache_api",
        "label": "ElastiCache API",
        "description": "Call an Amazon ElastiCache HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "memorydb_api",
        "label": "MemoryDB API",
        "description": "Call an Amazon MemoryDB HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "emr_api",
        "label": "EMR API",
        "description": "Call an Amazon EMR HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "firehose_api",
        "label": "Firehose API",
        "description": "Call an Amazon Kinesis Data Firehose HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "msk_api",
        "label": "MSK API",
        "description": "Call an Amazon MSK HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "appsync_api",
        "label": "AppSync API",
        "description": "Call an AWS AppSync HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "amazon_mq_api",
        "label": "Amazon MQ API",
        "description": "Call an Amazon MQ HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "neptune_api",
        "label": "Neptune API",
        "description": "Call an Amazon Neptune HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "documentdb_api",
        "label": "DocumentDB API",
        "description": "Call an Amazon DocumentDB HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "fsx_api",
        "label": "FSx API",
        "description": "Call an Amazon FSx HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "kendra_api",
        "label": "Kendra API",
        "description": "Call an Amazon Kendra HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "personalize_api",
        "label": "Personalize API",
        "description": "Call an Amazon Personalize HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "forecast_api",
        "label": "Forecast API",
        "description": "Call an Amazon Forecast HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "mediaconvert_api",
        "label": "MediaConvert API",
        "description": "Call an AWS Elemental MediaConvert HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "transfer_api",
        "label": "Transfer API",
        "description": "Call an AWS Transfer Family HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "datasync_api",
        "label": "DataSync API",
        "description": "Call an AWS DataSync HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "backup_api",
        "label": "Backup API",
        "description": "Call an AWS Backup HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "lightsail_api",
        "label": "Lightsail API",
        "description": "Call an Amazon Lightsail HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "elasticbeanstalk_api",
        "label": "Elastic Beanstalk API",
        "description": "Call an AWS Elastic Beanstalk HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "workspaces_api",
        "label": "WorkSpaces API",
        "description": "Call an Amazon WorkSpaces HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "appstream_api",
        "label": "AppStream API",
        "description": "Call an Amazon AppStream 2.0 HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "mediastore_api",
        "label": "MediaStore API",
        "description": "Call an AWS Elemental MediaStore HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "outposts_api",
        "label": "Outposts API",
        "description": "Call an AWS Outposts HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "storagegateway_api",
        "label": "Storage Gateway API",
        "description": "Call an AWS Storage Gateway HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "directconnect_api",
        "label": "Direct Connect API",
        "description": "Call an AWS Direct Connect HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "transitgateway_api",
        "label": "Transit Gateway API",
        "description": "Call an AWS Transit Gateway HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "ec2_api",
        "label": "EC2 API",
        "description": "Call an Amazon EC2 HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "autoscaling_api",
        "label": "Auto Scaling API",
        "description": "Call an Amazon EC2 Auto Scaling HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "organizations_api",
        "label": "Organizations API",
        "description": "Call an AWS Organizations HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "ram_api",
        "label": "RAM API",
        "description": "Call an AWS Resource Access Manager HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "codebuild_api",
        "label": "CodeBuild API",
        "description": "Call an AWS CodeBuild HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "codepipeline_api",
        "label": "CodePipeline API",
        "description": "Call an AWS CodePipeline HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "codedeploy_api",
        "label": "CodeDeploy API",
        "description": "Call an AWS CodeDeploy HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "codecommit_api",
        "label": "CodeCommit API",
        "description": "Call an AWS CodeCommit HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "cloud9_api",
        "label": "Cloud9 API",
        "description": "Call an AWS Cloud9 HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "amplify_api",
        "label": "Amplify API",
        "description": "Call an AWS Amplify HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "fis_api",
        "label": "FIS API",
        "description": "Call an AWS Fault Injection Service HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "resiliencehub_api",
        "label": "Resilience Hub API",
        "description": "Call an AWS Resilience Hub HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "wellarchitected_api",
        "label": "Well-Architected API",
        "description": "Call an AWS Well-Architected Tool HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "support_api",
        "label": "Support API",
        "description": "Call an AWS Support HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "trustedadvisor_api",
        "label": "Trusted Advisor API",
        "description": "Call an AWS Trusted Advisor HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "controltower_api",
        "label": "Control Tower API",
        "description": "Call an AWS Control Tower HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "servicecatalog_api",
        "label": "Service Catalog API",
        "description": "Call an AWS Service Catalog HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "lakeformation_api",
        "label": "Lake Formation API",
        "description": "Call an AWS Lake Formation HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "ses_api",
        "label": "SES API",
        "description": "Call an Amazon SES HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "pinpoint_api",
        "label": "Pinpoint API",
        "description": "Call an Amazon Pinpoint HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "connect_api",
        "label": "Connect API",
        "description": "Call an Amazon Connect HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "chime_api",
        "label": "Chime API",
        "description": "Call an Amazon Chime SDK HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "ivs_api",
        "label": "IVS API",
        "description": "Call an Amazon Interactive Video Service HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "gamelift_api",
        "label": "GameLift API",
        "description": "Call an Amazon GameLift HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "braket_api",
        "label": "Braket API",
        "description": "Call an Amazon Braket HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "qldb_api",
        "label": "QLDB API",
        "description": "Call an Amazon QLDB HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "timestream_api",
        "label": "Timestream API",
        "description": "Call an Amazon Timestream HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "appconfig_api",
        "label": "AppConfig API",
        "description": "Call an AWS AppConfig HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "grafana_api",
        "label": "Grafana API",
        "description": "Call a Grafana HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "prometheus_api",
        "label": "Prometheus API",
        "description": "Call a Prometheus HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "location_api",
        "label": "Location API",
        "description": "Call an Amazon Location Service HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "emrserverless_api",
        "label": "EMR Serverless API",
        "description": "Call an Amazon EMR Serverless HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "iot_api",
        "label": "IoT API",
        "description": "Call an AWS IoT Core HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "greengrass_api",
        "label": "Greengrass API",
        "description": "Call an AWS IoT Greengrass HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "iotanalytics_api",
        "label": "IoT Analytics API",
        "description": "Call an AWS IoT Analytics HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "freertos_api",
        "label": "FreeRTOS API",
        "description": "Call an AWS FreeRTOS / IoT Device HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "datazone_api",
        "label": "DataZone API",
        "description": "Call an Amazon DataZone HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "cleanrooms_api",
        "label": "Clean Rooms API",
        "description": "Call an AWS Clean Rooms HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "entityresolution_api",
        "label": "Entity Resolution API",
        "description": "Call an AWS Entity Resolution HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "supplychain_api",
        "label": "Supply Chain API",
        "description": "Call an AWS Supply Chain HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "amp_api",
        "label": "AMP API",
        "description": "Call an Amazon Managed Prometheus HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "managedgrafana_api",
        "label": "Managed Grafana API",
        "description": "Call an Amazon Managed Grafana HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "opensearchserverless_api",
        "label": "OpenSearch Serverless API",
        "description": "Call an Amazon OpenSearch Serverless HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "mwaa_api",
        "label": "MWAA API",
        "description": "Call an Amazon MWAA (Managed Airflow) HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "appflow_api",
        "label": "AppFlow API",
        "description": "Call an Amazon AppFlow HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "databrew_api",
        "label": "DataBrew API",
        "description": "Call an AWS Glue DataBrew HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "healthlake_api",
        "label": "HealthLake API",
        "description": "Call an AWS HealthLake HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "medicalimaging_api",
        "label": "Medical Imaging API",
        "description": "Call an AWS HealthImaging HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "omics_api",
        "label": "Omics API",
        "description": "Call an AWS HealthOmics HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "finspace_api",
        "label": "FinSpace API",
        "description": "Call an Amazon FinSpace HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "lookoutmetrics_api",
        "label": "Lookout for Metrics API",
        "description": "Call an Amazon Lookout for Metrics HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "lookoutvision_api",
        "label": "Lookout for Vision API",
        "description": "Call an Amazon Lookout for Vision HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "evidently_api",
        "label": "Evidently API",
        "description": "Call an Amazon CloudWatch Evidently HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "rum_api",
        "label": "RUM API",
        "description": "Call an Amazon CloudWatch RUM HTTP path with a credential binding (base host must be allowlisted).",
        "required_config_fields": ["base_url", "path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "auth_header_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "number_format",
        "label": "Number Format",
        "description": "Format a numeric template value (decimal/integer/percent/currency_prefix).",
        "required_config_fields": ["value_template"],
        "optional_config_fields": [
            "style",
            "precision",
            "prefix",
            "suffix",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "regex_extract",
        "label": "Regex Extract",
        "description": "Extract matches with a size-capped safe regex (no code eval; ReDoS guards).",
        "required_config_fields": ["pattern", "value_template"],
        "optional_config_fields": ["flags", "group", "continue_on_error", "error_branch"],
    },
    {
        "type": "text_template",
        "label": "Text Template",
        "description": "Render a multi-line text template from prior steps / run input.",
        "required_config_fields": ["text_template"],
        "optional_config_fields": ["continue_on_error", "error_branch"],
    },
    {
        "type": "timezone_convert",
        "label": "Timezone Convert",
        "description": "Convert an ISO datetime between IANA timezones (zoneinfo).",
        "required_config_fields": ["value_template", "to_timezone"],
        "optional_config_fields": ["from_timezone", "output_format", "continue_on_error", "error_branch"],
    },
    {
        "type": "item_exists",
        "label": "Item Exists",
        "description": "Check whether a JSON path exists / is non-empty, with optional true/false branches.",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": [
            "json_path",
            "true_branch",
            "false_branch",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "flatten_json",
        "label": "Flatten JSON",
        "description": "Flatten a nested object into dotted keys (depth and key capped).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": ["json_path", "separator", "continue_on_error", "error_branch"],
    },
    {
        "type": "pagerduty_event",
        "label": "PagerDuty Event",
        "description": "Send an Events API v2 enqueue payload (routing key from credential binding).",
        "required_config_fields": ["summary_template", "auth_binding_id"],
        "optional_config_fields": [
            "severity",
            "source_template",
            "component_template",
            "custom_details_json",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "opsgenie_alert",
        "label": "Opsgenie Alert",
        "description": "Create an Opsgenie alert (GenieKey from credential binding; allowlisted HTTP).",
        "required_config_fields": ["summary_template", "auth_binding_id"],
        "optional_config_fields": [
            "priority",
            "source_template",
            "alias_template",
            "description_template",
            "tags_template",
            "custom_details_json",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "datadog_event",
        "label": "Datadog Event",
        "description": "Post an Events API v1 event (DD-API-KEY from credential binding; allowlisted HTTP).",
        "required_config_fields": ["summary_template", "auth_binding_id"],
        "optional_config_fields": [
            "description_template",
            "alert_type",
            "tags_template",
            "source_type_name",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "sentry_event",
        "label": "Sentry Event",
        "description": "Submit a store event to sentry.io (auth token from credential binding; allowlisted HTTP).",
        "required_config_fields": [
            "summary_template",
            "organization_slug",
            "project_slug",
            "auth_binding_id",
        ],
        "optional_config_fields": [
            "level",
            "tags_template",
            "fingerprint_template",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "statuspage_incident",
        "label": "Statuspage Incident",
        "description": "Create a Statuspage incident (API key from credential binding; allowlisted HTTP).",
        "required_config_fields": ["name_template", "page_id", "auth_binding_id"],
        "optional_config_fields": [
            "status",
            "impact",
            "body_template",
            "component_ids_csv",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "trello_api",
        "label": "Trello API",
        "description": "Call api.trello.com with a path template and credential binding (allowlisted HTTP).",
        "required_config_fields": ["path_template", "method", "auth_binding_id"],
        "optional_config_fields": [
            "query_template",
            "body_template",
            "auth_type",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "json_stringify",
        "label": "JSON Stringify",
        "description": "Serialize a prior-step object/array to a JSON string (no code eval).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": ["json_path", "pretty", "continue_on_error", "error_branch"],
    },
    {
        "type": "type_of",
        "label": "Type Of",
        "description": "Report the JSON type of a prior-step path (string/number/object/array/null/boolean).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": ["json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "xml_parse",
        "label": "XML Parse",
        "description": "Parse XML text from a prior step into a JSON object (stdlib, no DTD/XXE).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": ["json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "unflatten_json",
        "label": "Unflatten JSON",
        "description": "Rebuild nested objects from a flattened key map (inverse of flatten_json).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": ["json_path", "separator", "continue_on_error", "error_branch"],
    },
    {
        "type": "chunk_text",
        "label": "Chunk Text",
        "description": "Split prior-step text into capped overlapping chunks (RAG-friendly, no eval).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": [
            "json_path",
            "chunk_size",
            "overlap",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "form_urlencoded",
        "label": "Form URL-Encoded",
        "description": "Encode an object to application/x-www-form-urlencoded or decode a form string.",
        "required_config_fields": ["source_node_id", "operation"],
        "optional_config_fields": ["json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "deep_merge",
        "label": "Deep Merge",
        "description": "Deep-merge two prior-step objects (depth/key capped, no code eval).",
        "required_config_fields": ["source_node_id", "merge_source_node_id"],
        "optional_config_fields": [
            "json_path",
            "merge_json_path",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "jwt_decode",
        "label": "JWT Decode",
        "description": "Inspect JWT header/payload claims without signature verification (not for auth trust).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": ["json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "html_extract",
        "label": "HTML Extract",
        "description": "Extract visible text and/or anchor hrefs from HTML (stdlib parser, no JS eval).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": ["json_path", "mode", "continue_on_error", "error_branch"],
    },
    {
        "type": "split_text",
        "label": "Split Text",
        "description": "Split prior-step text by a delimiter into a capped parts array.",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": [
            "json_path",
            "delimiter",
            "max_parts",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "json_query",
        "label": "JSON Query",
        "description": "Read a JSONPath value from a prior step (safe path walk only, no JMESPath/eval).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": ["json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "compress",
        "label": "Compress / Decompress",
        "description": "zlib/gzip compress or decompress with size caps (stdlib only).",
        "required_config_fields": ["source_node_id", "operation"],
        "optional_config_fields": [
            "json_path",
            "algorithm",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "random",
        "label": "Random",
        "description": "Cryptographically secure random int/uuid/bytes/choice (secrets module).",
        "required_config_fields": ["mode"],
        "optional_config_fields": [
            "min",
            "max",
            "length",
            "source_node_id",
            "json_path",
            "choices_json",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "hmac_verify",
        "label": "HMAC Verify",
        "description": "Verify an HMAC digest with compare_digest (key from template; not for storing secrets).",
        "required_config_fields": ["value_template", "key_template", "expected_template"],
        "optional_config_fields": ["algorithm", "encoding", "continue_on_error", "error_branch"],
    },
    {
        "type": "xml_stringify",
        "label": "XML Stringify",
        "description": "Serialize a prior-step object to XML text (element/depth capped, no DTD).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": ["json_path", "root_tag", "continue_on_error", "error_branch"],
    },
    {
        "type": "object_diff",
        "label": "Object Diff",
        "description": "Depth-capped deep diff of two prior-step objects (added/removed/changed).",
        "required_config_fields": ["source_node_id", "compare_source_node_id"],
        "optional_config_fields": [
            "json_path",
            "compare_json_path",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "html_to_markdown",
        "label": "HTML to Markdown",
        "description": "Convert HTML to a constrained markdown subset (no JS eval; script/style skipped).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": ["json_path", "continue_on_error", "error_branch"],
    },
    {
        "type": "markdown_to_html",
        "label": "Markdown to HTML",
        "description": "Convert a constrained markdown subset to escaped HTML (no JS eval).",
        "required_config_fields": [],
        "optional_config_fields": [
            "source_node_id",
            "json_path",
            "value_template",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "array_ops",
        "label": "Array Ops",
        "description": "Declarative list ops: slice/reverse/concat/length/first/last/unique (capped).",
        "required_config_fields": ["source_node_id", "operation"],
        "optional_config_fields": [
            "json_path",
            "start",
            "end",
            "merge_source_node_id",
            "merge_json_path",
            "continue_on_error",
            "error_branch",
        ],
    },
    {
        "type": "compact_object",
        "label": "Compact Object",
        "description": "Drop null/empty-string keys from a prior-step object (depth/key capped).",
        "required_config_fields": ["source_node_id"],
        "optional_config_fields": [
            "json_path",
            "drop_empty_arrays",
            "drop_empty_objects",
            "continue_on_error",
            "error_branch",
        ],
    },
]

NODE_REQUIRED_FIELDS: dict[str, set[str]] = {
    item["type"]: set(item["required_config_fields"]) for item in NODE_TYPE_CATALOG
}


def list_node_types() -> list[dict[str, Any]]:
    return [dict(item) for item in NODE_TYPE_CATALOG]


def _parse_json_object(raw: str, *, field_name: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise validation_error(
            message=f"{field_name} must be valid JSON",
            decision_trace_id="orchestration-json-invalid",
            field=field_name,
        ) from exc
    if not isinstance(parsed, dict):
        raise validation_error(
            message=f"{field_name} must be a JSON object",
            decision_trace_id="orchestration-json-shape",
            field=field_name,
        )
    return parsed


def _parse_graph(raw: str) -> dict[str, Any]:
    graph = _parse_json_object(raw, field_name="graph_json")
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise validation_error(
            message="graph_json must include nodes and edges arrays",
            decision_trace_id="orchestration-graph-shape",
        )
    return {"nodes": nodes, "edges": edges}


def _json_path_value(data: Any, json_path: str) -> Any:
    path = str(json_path or "").strip()
    if not path or path == "$":
        return data
    if not path.startswith("$"):
        return None
    current: Any = data
    remainder = path[1:]
    if remainder.startswith("."):
        remainder = remainder[1:]
    if not remainder:
        return current
    tokens = re.split(r"\.(?![^\[]*\])", remainder)
    for token in tokens:
        if not token:
            continue
        key = token
        index: Optional[int] = None
        bracket = re.match(r"^([^\[]+)\[(\d+)\]$", token)
        if bracket:
            key = bracket.group(1)
            index = int(bracket.group(2))
        if key and isinstance(current, dict):
            current = current.get(key)
        elif key:
            return None
        if index is not None:
            if isinstance(current, list) and 0 <= index < len(current):
                current = current[index]
            else:
                return None
    return current


def evaluate_condition(config: dict[str, Any], step_outputs: dict[str, Any]) -> bool:
    source_node_id = str(config.get("source_node_id") or "").strip()
    json_path = str(config.get("json_path") or "").strip()
    operator = str(config.get("operator") or "==").strip()
    compare_value = config.get("compare_value")

    if source_node_id and json_path:
        left = _json_path_value(step_outputs.get(source_node_id), json_path)
    else:
        left = config.get("expression")

    if operator == "exists":
        return left is not None and left != ""
    if operator == "contains":
        return str(compare_value or "") in str(left or "")
    if operator == "==":
        return str(left) == str(compare_value)
    if operator == "!=":
        return str(left) != str(compare_value)
    if operator == ">":
        try:
            return float(left) > float(compare_value)
        except (TypeError, ValueError):
            return False
    if operator == "<":
        try:
            return float(left) < float(compare_value)
        except (TypeError, ValueError):
            return False
    return True


def clamp_while_max_iterations(raw: Any) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = DEFAULT_WHILE_ITERATIONS
    return max(1, min(MAX_WHILE_ITERATIONS, value))


def _truthy_config_flag(raw: Any) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _while_loop_context(
    *,
    node_id: str,
    node_type: str,
    iteration_count: int,
    max_iterations: int,
    previous: Any = None,
) -> dict[str, Any]:
    """Live loop state readable as {{loop.*}} or steps[while].output.index."""
    return {
        "index": iteration_count,
        "iteration": iteration_count + 1,
        "max_iterations": max_iterations,
        "mode": node_type,
        "node_id": node_id,
        "previous": previous,
        "is_first": iteration_count == 0,
    }


def _publish_while_loop_context(
    outputs: dict[str, Any],
    *,
    node_id: str,
    node_type: str,
    iteration_count: int,
    max_iterations: int,
    previous: Any = None,
) -> dict[str, Any]:
    loop_ctx = _while_loop_context(
        node_id=node_id,
        node_type=node_type,
        iteration_count=iteration_count,
        max_iterations=max_iterations,
        previous=previous,
    )
    previous_out = outputs.get(node_id)
    merged = {**previous_out, **loop_ctx} if isinstance(previous_out, dict) else dict(loop_ctx)
    outputs[node_id] = merged
    outputs["__loop__"] = loop_ctx
    return loop_ctx


def _body_flag_truthy(output: Any, *keys: str) -> bool:
    if not isinstance(output, dict):
        return False
    for key in keys:
        value = output.get(key)
        if value is True:
            return True
        if str(value or "").strip().lower() in {"1", "true", "yes", "on"}:
            return True
    return False


def _body_requests_loop_break(output: Any) -> bool:
    """Body step can early-exit the while/do-while by setting loop_break/_loop_break."""
    return _body_flag_truthy(output, "loop_break", "_loop_break")


def _body_requests_loop_continue(output: Any) -> bool:
    """Skip remaining body steps and advance to the next iteration."""
    return _body_flag_truthy(output, "loop_continue", "_loop_continue")


def _clamp_while_delay_ms(raw: Any) -> int:
    if raw in (None, ""):
        return 0
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 0
    return max(0, min(MAX_WHILE_DELAY_MS, value))


def _while_condition_is_configured(config: dict[str, Any]) -> bool:
    expression = str(config.get("expression") or "").strip()
    if expression:
        return True
    json_path = str(config.get("json_path") or "").strip()
    source_node_id = str(config.get("source_node_id") or "").strip()
    if not source_node_id:
        return False
    return bool(json_path) and json_path not in {"$", "$."}


def _collect_loop_body_node_ids(
    body_head: str,
    exit_id: str,
    while_id: str,
    outgoing: dict[str, list[str]],
    *,
    max_nodes: int = MAX_WHILE_BODY_NODES,
) -> list[str]:
    """Collect body chain nodes without following exit/while back-edges."""
    head = str(body_head or "").strip()
    exit_node = str(exit_id or "").strip()
    loop_id = str(while_id or "").strip()
    if not head or head in {exit_node, loop_id}:
        return []
    ordered: list[str] = []
    visited: set[str] = set()
    queue = [head]
    while queue and len(ordered) < max_nodes:
        current = queue.pop(0)
        if current in visited or current == exit_node or current == loop_id:
            continue
        visited.add(current)
        ordered.append(current)
        for successor in outgoing.get(current, []):
            if successor in visited or successor == exit_node or successor == loop_id:
                continue
            queue.append(successor)
    return ordered


def _parse_cases_json(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if raw in (None, ""):
        return []
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def evaluate_switch(config: dict[str, Any], step_outputs: dict[str, Any]) -> dict[str, Any]:
    """Pick a branch from declarative cases — no code execution."""
    source_node_id = str(config.get("source_node_id") or "").strip()
    json_path = str(config.get("json_path") or "$").strip() or "$"
    if source_node_id:
        left = _json_path_value(step_outputs.get(source_node_id), json_path)
    else:
        left = config.get("expression")
    cases = _parse_cases_json(config.get("cases_json"))
    default_branch = str(config.get("default_branch") or "").strip() or None
    chosen = default_branch
    matched_case: Optional[int] = None
    for index, case in enumerate(cases):
        branch = str(case.get("branch") or "").strip()
        if not branch:
            continue
        if str(left) == str(case.get("value")):
            chosen = branch
            matched_case = index
            break
    return {
        "value": left,
        "chosen_branch": chosen,
        "matched_case": matched_case,
        "default_branch": default_branch,
        "case_count": len(cases),
    }


def evaluate_filter(config: dict[str, Any], step_outputs: dict[str, Any]) -> dict[str, Any]:
    """Filter list items with the same safe operators as condition nodes."""
    source_node_id = str(config.get("source_node_id") or "").strip()
    items_path = str(config.get("items_path") or "$").strip() or "$"
    source = step_outputs.get(source_node_id) if source_node_id else {}
    items = _json_path_value(source, items_path)
    if isinstance(items, dict):
        items_list: list[Any] = [items]
    elif isinstance(items, list):
        items_list = items
    elif items is None:
        items_list = []
    else:
        items_list = [items]

    item_json_path = str(config.get("item_json_path") or "$").strip() or "$"
    kept: list[Any] = []
    for item in items_list:
        item_config = {
            "source_node_id": "_item",
            "json_path": item_json_path,
            "operator": config.get("operator") or "==",
            "compare_value": config.get("compare_value"),
        }
        if evaluate_condition(item_config, {"_item": item}):
            kept.append(item)
    return {
        "items": kept,
        "count": len(kept),
        "input_count": len(items_list),
        "source_node_id": source_node_id or None,
        "items_path": items_path,
    }


def merge_step_outputs(config: dict[str, Any], step_outputs: dict[str, Any]) -> dict[str, Any]:
    source_a = str(config.get("source_a_node_id") or "").strip()
    source_b = str(config.get("source_b_node_id") or "").strip()
    a = step_outputs.get(source_a) if source_a else {}
    b = step_outputs.get(source_b) if source_b else {}
    if not isinstance(a, dict):
        a = {"value": a}
    if not isinstance(b, dict):
        b = {"value": b}
    mode = str(config.get("merge_mode") or "shallow").strip().lower()
    if mode == "prefer_a":
        merged = {**b, **a}
    elif mode == "prefer_b":
        merged = {**a, **b}
    elif mode == "nest":
        merged = {"a": a, "b": b}
    else:
        mode = "shallow"
        merged = {**a, **b}
    return {
        "merged": merged,
        "merge_mode": mode,
        "source_a_node_id": source_a or None,
        "source_b_node_id": source_b or None,
        **merged,
    }


def _load_items_list(config: dict[str, Any], step_outputs: dict[str, Any]) -> tuple[list[Any], str, str]:
    source_node_id = str(config.get("source_node_id") or "").strip()
    items_path = str(config.get("items_path") or "$").strip() or "$"
    source = step_outputs.get(source_node_id) if source_node_id else {}
    items = _json_path_value(source, items_path)
    if isinstance(items, dict):
        items_list: list[Any] = [items]
    elif isinstance(items, list):
        items_list = items
    elif items is None:
        items_list = []
    else:
        items_list = [items]
    return items_list, source_node_id, items_path


def evaluate_split_in_batches(config: dict[str, Any], step_outputs: dict[str, Any]) -> dict[str, Any]:
    items_list, source_node_id, items_path = _load_items_list(config, step_outputs)

    try:
        batch_size = int(config.get("batch_size") or 10)
    except (TypeError, ValueError):
        batch_size = 10
    batch_size = max(1, min(MAX_SPLIT_BATCH_SIZE, batch_size))

    try:
        batch_index = int(config.get("batch_index") or 0)
    except (TypeError, ValueError):
        batch_index = 0
    batch_index = max(0, min(MAX_SPLIT_BATCH_INDEX, batch_index))

    start = batch_index * batch_size
    end = start + batch_size
    batch = items_list[start:end]
    has_more = end < len(items_list)
    return {
        "items": batch,
        "batch": batch,
        "count": len(batch),
        "batch_size": batch_size,
        "batch_index": batch_index,
        "next_batch_index": batch_index + 1 if has_more else batch_index,
        "has_more": has_more,
        "total": len(items_list),
        "source_node_id": source_node_id or None,
        "items_path": items_path,
    }


def resolve_safe_template(
    template: str,
    *,
    step_outputs: dict[str, Any],
    run_input: str = "",
    item: Any = None,
    loop: Any = None,
) -> str:
    """Template resolver for orchestration nodes — no eval/exec."""
    text = str(template or "")

    def _replace_path_root(root: Any, subpath: Optional[str]) -> str:
        if not subpath:
            if isinstance(root, (dict, list)):
                return json.dumps(root, separators=(",", ":"))
            return "" if root is None else str(root)
        root_obj = root if isinstance(root, dict) else {"value": root}
        resolved = _json_path_value(root_obj, f"$.{subpath}")
        if resolved is None:
            return ""
        if isinstance(resolved, (dict, list)):
            return json.dumps(resolved, separators=(",", ":"))
        return str(resolved)

    if item is not None:
        item_obj = item if isinstance(item, dict) else {"value": item}

        def _item_replace(match: re.Match[str]) -> str:
            return _replace_path_root(item_obj if match.group(1) else item, match.group(1))

        text = _ITEM_TEMPLATE_PATTERN.sub(_item_replace, text)

    loop_ctx = loop
    if loop_ctx is None and isinstance(step_outputs, dict):
        loop_ctx = step_outputs.get("__loop__")
    if loop_ctx is not None or "{{loop" in text:

        def _loop_replace(match: re.Match[str]) -> str:
            return _replace_path_root(loop_ctx, match.group(1))

        text = _LOOP_TEMPLATE_PATTERN.sub(_loop_replace, text)

    def _step_replace(match: re.Match[str]) -> str:
        node_id = match.group(1)
        subpath = match.group(2)
        value = step_outputs.get(node_id)
        if subpath:
            resolved = _json_path_value(value, f"$.{subpath}")
            if resolved is None:
                return ""
            if isinstance(resolved, (dict, list)):
                return json.dumps(resolved, separators=(",", ":"))
            return str(resolved)
        if isinstance(value, (dict, list)):
            return json.dumps(value, separators=(",", ":"))
        return "" if value is None else str(value)

    text = _STEP_OUTPUT_TEMPLATE_PATTERN.sub(_step_replace, text)
    return text.replace("{{input}}", str(run_input or ""))


def evaluate_limit(config: dict[str, Any], step_outputs: dict[str, Any]) -> dict[str, Any]:
    items_list, source_node_id, items_path = _load_items_list(config, step_outputs)
    try:
        limit_n = int(config.get("limit") or 10)
    except (TypeError, ValueError):
        limit_n = 10
    limit_n = max(1, min(MAX_LIMIT_ITEMS, limit_n))
    try:
        offset = int(config.get("offset") or 0)
    except (TypeError, ValueError):
        offset = 0
    offset = max(0, offset)
    sliced = items_list[offset : offset + limit_n]
    return {
        "items": sliced,
        "count": len(sliced),
        "total": len(items_list),
        "limit": limit_n,
        "offset": offset,
        "source_node_id": source_node_id or None,
        "items_path": items_path,
    }


def evaluate_aggregate(config: dict[str, Any], step_outputs: dict[str, Any]) -> dict[str, Any]:
    items_list, source_node_id, items_path = _load_items_list(config, step_outputs)
    mode = str(config.get("aggregate_mode") or "count").strip().lower()
    if mode not in AGGREGATE_MODES:
        mode = "count"
    item_path = str(config.get("item_json_path") or "$").strip() or "$"
    plucked: list[Any] = []
    for item in items_list:
        if item_path == "$":
            plucked.append(item)
            continue
        item_obj = item if isinstance(item, (dict, list)) else {"value": item}
        plucked.append(_json_path_value(item_obj, item_path))

    result: dict[str, Any] = {
        "aggregate_mode": mode,
        "input_count": len(items_list),
        "source_node_id": source_node_id or None,
        "items_path": items_path,
    }
    if mode == "count":
        result.update({"value": len(items_list), "count": len(items_list)})
    elif mode == "pluck":
        result.update({"values": plucked, "count": len(plucked)})
    elif mode == "unique":
        unique_vals: list[Any] = []
        seen: set[str] = set()
        for value in plucked:
            key = json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list)) else str(value)
            if key in seen:
                continue
            seen.add(key)
            unique_vals.append(value)
        result.update({"values": unique_vals, "count": len(unique_vals)})
    elif mode == "sum":
        total = 0.0
        for value in plucked:
            try:
                total += float(value)
            except (TypeError, ValueError):
                continue
        result.update({"value": total, "count": len(plucked)})
    elif mode == "first":
        result.update({"value": items_list[0] if items_list else None, "count": min(1, len(items_list))})
    elif mode == "last":
        result.update({"value": items_list[-1] if items_list else None, "count": min(1, len(items_list))})
    return result


def evaluate_foreach_map(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    items_list, source_node_id, items_path = _load_items_list(config, step_outputs)
    if len(items_list) > MAX_FOREACH_ITEMS:
        items_list = items_list[:MAX_FOREACH_ITEMS]
        truncated = True
    else:
        truncated = False

    mapping_raw = config.get("mapping_json") or "{}"
    try:
        mapping = json.loads(mapping_raw) if isinstance(mapping_raw, str) else mapping_raw
    except json.JSONDecodeError:
        mapping = {}
    if not isinstance(mapping, dict):
        mapping = {}

    mapped_items: list[Any] = []
    for item in items_list:
        if not mapping:
            mapped_items.append(item)
            continue
        mapped: dict[str, Any] = {}
        for key, template in mapping.items():
            field_key = str(key or "").strip()
            if not field_key:
                continue
            if isinstance(template, str):
                resolved = resolve_safe_template(
                    template,
                    step_outputs=step_outputs,
                    run_input=run_input,
                    item=item,
                )
                try:
                    mapped[field_key] = json.loads(resolved)
                except json.JSONDecodeError:
                    mapped[field_key] = resolved
            else:
                mapped[field_key] = template
        mapped_items.append(mapped)

    return {
        "items": mapped_items,
        "count": len(mapped_items),
        "input_count": len(items_list),
        "truncated": truncated,
        "max_items": MAX_FOREACH_ITEMS,
        "source_node_id": source_node_id or None,
        "items_path": items_path,
    }


def _item_sort_key(item: Any, sort_key_path: str) -> Any:
    if not sort_key_path or sort_key_path == "$":
        value = item
    else:
        item_obj = item if isinstance(item, (dict, list)) else {"value": item}
        value = _json_path_value(item_obj, sort_key_path)
    if value is None:
        return (1, "")
    if isinstance(value, (int, float)):
        return (0, value)
    if isinstance(value, bool):
        return (0, int(value))
    return (0, str(value))


def evaluate_sort(config: dict[str, Any], step_outputs: dict[str, Any]) -> dict[str, Any]:
    items_list, source_node_id, items_path = _load_items_list(config, step_outputs)
    sort_key_path = str(config.get("sort_key_path") or "$").strip() or "$"
    order = str(config.get("order") or "asc").strip().lower()
    if order not in SORT_ORDERS:
        order = "asc"
    sorted_items = sorted(items_list, key=lambda item: _item_sort_key(item, sort_key_path), reverse=order == "desc")
    return {
        "items": sorted_items,
        "count": len(sorted_items),
        "order": order,
        "sort_key_path": sort_key_path,
        "source_node_id": source_node_id or None,
        "items_path": items_path,
    }


def evaluate_dedupe(config: dict[str, Any], step_outputs: dict[str, Any]) -> dict[str, Any]:
    items_list, source_node_id, items_path = _load_items_list(config, step_outputs)
    key_path = str(config.get("item_json_path") or "$").strip() or "$"
    unique_items: list[Any] = []
    seen: set[str] = set()
    for item in items_list:
        if key_path == "$":
            key_value = item
        else:
            item_obj = item if isinstance(item, (dict, list)) else {"value": item}
            key_value = _json_path_value(item_obj, key_path)
        key = json.dumps(key_value, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        unique_items.append(item)
    return {
        "items": unique_items,
        "count": len(unique_items),
        "input_count": len(items_list),
        "removed": len(items_list) - len(unique_items),
        "source_node_id": source_node_id or None,
        "items_path": items_path,
    }


def evaluate_json_parse(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    source_node_id = str(config.get("source_node_id") or "").strip()
    json_path = str(config.get("json_path") or "").strip()
    raw: Any
    if source_node_id and json_path:
        raw = _json_path_value(step_outputs.get(source_node_id), json_path)
    else:
        raw = resolve_safe_template(
            str(config.get("text_template") or ""),
            step_outputs=step_outputs,
            run_input=run_input,
        )
    if isinstance(raw, (dict, list)):
        parsed = raw
    else:
        parsed = json.loads(str(raw or ""))
    return {
        "parsed": parsed,
        "data": parsed if isinstance(parsed, dict) else {"value": parsed},
        "type": "array" if isinstance(parsed, list) else "object" if isinstance(parsed, dict) else type(parsed).__name__,
        "source_node_id": source_node_id or None,
    }


def evaluate_date_time(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    operation = str(config.get("operation") or "now").strip().lower()
    if operation not in DATE_TIME_OPS:
        operation = "now"
    output_format = str(config.get("output_format") or "%Y-%m-%dT%H:%M:%SZ").strip() or "%Y-%m-%dT%H:%M:%SZ"
    input_format = str(config.get("input_format") or "%Y-%m-%dT%H:%M:%SZ").strip() or "%Y-%m-%dT%H:%M:%SZ"
    value_text = resolve_safe_template(
        str(config.get("value_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    ).strip()
    unit = str(config.get("unit") or "days").strip().lower()

    def _shift(base: datetime, amount: int, shift_unit: str) -> datetime:
        if shift_unit in {"seconds", "second"}:
            return base + timedelta(seconds=amount)
        if shift_unit in {"minutes", "minute"}:
            return base + timedelta(minutes=amount)
        if shift_unit in {"hours", "hour"}:
            return base + timedelta(hours=amount)
        if shift_unit in {"weeks", "week"}:
            return base + timedelta(weeks=amount)
        return base + timedelta(days=amount)

    def _delta_in_unit(total_seconds: float, shift_unit: str) -> float:
        if shift_unit in {"seconds", "second"}:
            return float(total_seconds)
        if shift_unit in {"minutes", "minute"}:
            return float(total_seconds) / 60.0
        if shift_unit in {"hours", "hour"}:
            return float(total_seconds) / 3600.0
        if shift_unit in {"weeks", "week"}:
            return float(total_seconds) / (7.0 * 86400.0)
        return float(total_seconds) / 86400.0

    if operation == "diff":
        compare_text = resolve_safe_template(
            str(config.get("compare_value_template") or ""),
            step_outputs=step_outputs,
            run_input=run_input,
        ).strip()
        left = (
            datetime.strptime(value_text, input_format)
            if value_text
            else datetime.now(timezone.utc).replace(tzinfo=None)
        )
        right = (
            datetime.strptime(compare_text, input_format)
            if compare_text
            else datetime.now(timezone.utc).replace(tzinfo=None)
        )
        total_seconds = (right - left).total_seconds()
        delta_value = _delta_in_unit(total_seconds, unit)
        return {
            "operation": operation,
            "iso": right.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "formatted": str(delta_value),
            "value": delta_value,
            "delta": delta_value,
            "delta_seconds": total_seconds,
            "unit": unit if unit in {"seconds", "minutes", "hours", "days", "weeks", "second", "minute", "hour", "day", "week"} else "days",
            "left_iso": left.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "right_iso": right.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "epoch_seconds": int(right.replace(tzinfo=timezone.utc).timestamp()),
        }

    if operation == "now":
        moment = datetime.now(timezone.utc).replace(tzinfo=None)
    elif operation == "parse":
        moment = datetime.strptime(value_text, input_format)
    elif operation == "format":
        moment = datetime.strptime(value_text, input_format) if value_text else datetime.now(timezone.utc).replace(tzinfo=None)
    else:  # add / subtract
        base = datetime.strptime(value_text, input_format) if value_text else datetime.now(timezone.utc).replace(tzinfo=None)
        try:
            amount = int(config.get("amount") or 0)
        except (TypeError, ValueError):
            amount = 0
        if operation == "subtract":
            amount = -amount
        moment = _shift(base, amount, unit)

    formatted = moment.strftime(output_format)
    return {
        "operation": operation,
        "iso": moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "formatted": formatted,
        "value": formatted,
        "epoch_seconds": int(moment.replace(tzinfo=timezone.utc).timestamp()),
    }


def evaluate_string_ops(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    operation = str(config.get("operation") or "trim").strip().lower()
    if operation not in STRING_OPS:
        operation = "trim"
    value = resolve_safe_template(
        str(config.get("value_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    search = resolve_safe_template(
        str(config.get("search_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    replacement = resolve_safe_template(
        str(config.get("replace_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    separator = str(config.get("separator") or ",")
    result: Any
    matched = None
    if operation == "lower":
        result = value.lower()
    elif operation == "upper":
        result = value.upper()
    elif operation == "trim":
        result = value.strip()
    elif operation == "replace":
        result = value.replace(search, replacement)
    elif operation == "split":
        result = value.split(separator) if separator else list(value)
    elif operation == "join":
        try:
            parsed = json.loads(value)
            items = parsed if isinstance(parsed, list) else [value]
        except json.JSONDecodeError:
            items = [part.strip() for part in value.split("\n") if part.strip()]
        result = separator.join(str(item) for item in items)
    elif operation == "contains":
        matched = search in value
        result = matched
    elif operation == "startswith":
        matched = value.startswith(search)
        result = matched
    elif operation == "endswith":
        matched = value.endswith(search)
        result = matched
    elif operation == "length":
        result = len(value)
    else:  # substring
        try:
            start = int(config.get("start") or 0)
        except (TypeError, ValueError):
            start = 0
        end_raw = config.get("end")
        try:
            end = int(end_raw) if end_raw not in (None, "") else None
        except (TypeError, ValueError):
            end = None
        result = value[start:end] if end is not None else value[start:]
    output = {
        "operation": operation,
        "value": result,
        "input": value,
        "result": result,
    }
    if matched is not None:
        output["matched"] = matched
    if isinstance(result, list):
        output["items"] = result
        output["count"] = len(result)
    return output


def evaluate_compare(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    source_a = str(config.get("source_a_node_id") or "").strip()
    source_b = str(config.get("source_b_node_id") or "").strip()
    path_a = str(config.get("json_path_a") or "$").strip() or "$"
    path_b = str(config.get("json_path_b") or "$").strip() or "$"
    left = _json_path_value(step_outputs.get(source_a), path_a) if source_a else None
    if source_b:
        right = _json_path_value(step_outputs.get(source_b), path_b)
    else:
        right = resolve_safe_template(
            str(config.get("compare_value") or ""),
            step_outputs=step_outputs,
            run_input=run_input,
        )
    operator = str(config.get("operator") or "==").strip()
    if operator not in COMPARE_OPS:
        operator = "=="
    if operator == "exists":
        matched = left is not None and left != ""
    elif operator == "contains":
        matched = str(right or "") in str(left or "")
    elif operator == "==":
        matched = str(left) == str(right)
    elif operator == "!=":
        matched = str(left) != str(right)
    elif operator in {"gt", ">"}:
        try:
            matched = float(left) > float(right)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            matched = False
    else:  # lt or <
        try:
            matched = float(left) < float(right)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            matched = False
    return {
        "matched": matched,
        "operator": operator,
        "left": left,
        "right": right,
        "source_a_node_id": source_a or None,
        "source_b_node_id": source_b or None,
    }


def evaluate_csv_parse(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    text = resolve_safe_template(
        str(config.get("text_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    delimiter = str(config.get("delimiter") or ",")[:1] or ","
    has_header = str(config.get("has_header") or "true").strip().lower() in {"1", "true", "yes", "on"}
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    rows_raw = list(reader)
    truncated = len(rows_raw) > MAX_CSV_ROWS + (1 if has_header else 0)
    items: list[dict[str, Any]] = []
    if has_header and rows_raw:
        headers = [str(h or f"col_{i}").strip() or f"col_{i}" for i, h in enumerate(rows_raw[0])]
        data_rows = rows_raw[1 : MAX_CSV_ROWS + 1]
        for row in data_rows:
            item: dict[str, Any] = {}
            for i, cell in enumerate(row):
                key = headers[i] if i < len(headers) else f"col_{i}"
                item[key] = cell
            items.append(item)
    else:
        for row in rows_raw[:MAX_CSV_ROWS]:
            item = {"columns": row}
            for i, cell in enumerate(row):
                item[f"c{i}"] = cell
            items.append(item)
    return {
        "items": items,
        "count": len(items),
        "has_header": has_header,
        "delimiter": delimiter,
        "truncated": truncated,
        "max_rows": MAX_CSV_ROWS,
    }


def evaluate_static_data(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    fields_raw = config.get("fields_json") or "{}"
    try:
        fields = json.loads(fields_raw) if isinstance(fields_raw, str) else fields_raw
    except json.JSONDecodeError:
        fields = {}
    if not isinstance(fields, dict):
        fields = {}
    resolved: dict[str, Any] = {}
    for key, value in fields.items():
        field_key = str(key or "").strip()
        if not field_key:
            continue
        if isinstance(value, str):
            text = resolve_safe_template(value, step_outputs=step_outputs, run_input=run_input)
            try:
                resolved[field_key] = json.loads(text)
            except json.JSONDecodeError:
                resolved[field_key] = text
        else:
            resolved[field_key] = value
    return {"fields": resolved, "data": resolved, **resolved}


def _parse_math_number(raw: Any) -> float:
    if isinstance(raw, bool):
        return float(int(raw))
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw or "").strip()
    if not text:
        return 0.0
    return float(text)


def evaluate_math_ops(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    operation = str(config.get("operation") or "add").strip().lower()
    if operation not in MATH_OPS:
        operation = "add"
    a_raw = resolve_safe_template(
        str(config.get("a_template") or "0"),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    b_raw = resolve_safe_template(
        str(config.get("b_template") or "0"),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    try:
        a = _parse_math_number(a_raw)
        b = _parse_math_number(b_raw)
    except (TypeError, ValueError):
        return {
            "operation": operation,
            "a": a_raw,
            "b": b_raw,
            "result": None,
            "error": "math_ops operands must be numeric",
        }
    error = None
    result: Any
    if operation == "add":
        result = a + b
    elif operation == "sub":
        result = a - b
    elif operation == "mul":
        result = a * b
    elif operation == "div":
        if b == 0:
            error = "division by zero"
            result = None
        else:
            result = a / b
    elif operation == "mod":
        if b == 0:
            error = "modulo by zero"
            result = None
        else:
            result = a % b
    elif operation == "round":
        try:
            precision = int(config.get("precision") or 0)
        except (TypeError, ValueError):
            precision = 0
        precision = max(0, min(10, precision))
        result = round(a, precision)
    elif operation == "abs":
        result = abs(a)
    elif operation == "min":
        result = min(a, b)
    elif operation == "max":
        result = max(a, b)
    elif operation == "ceil":
        result = math.ceil(a)
    else:  # floor
        result = math.floor(a)
    if error is None and result is not None and operation not in {"ceil", "floor"} and isinstance(result, float):
        try:
            precision = int(config.get("precision") or 6)
        except (TypeError, ValueError):
            precision = 6
        precision = max(0, min(10, precision))
        result = round(result, precision)
        if precision == 0 or result == int(result):
            result = int(result) if float(result).is_integer() else result
    output: dict[str, Any] = {
        "operation": operation,
        "a": a,
        "b": b,
        "result": result,
        "value": result,
    }
    if error:
        output["error"] = error
    return output


def evaluate_wait_until(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    until_raw = resolve_safe_template(
        str(config.get("until_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    ).strip()
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    target: Optional[datetime] = None
    parse_error = None
    candidates = [until_raw]
    if until_raw.endswith("Z"):
        candidates.append(until_raw[:-1] + "+00:00")
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            target = parsed.astimezone(timezone.utc)
            break
        except ValueError:
            continue
    if target is None:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(until_raw, fmt).replace(tzinfo=timezone.utc)
                target = parsed
                break
            except ValueError:
                continue
    if target is None:
        parse_error = "until_template must be an ISO datetime"
        return {
            "until": until_raw or None,
            "wait_seconds": 0,
            "waited_seconds": 0,
            "already_passed": False,
            "error": parse_error,
        }
    delta = (target - current).total_seconds()
    already_passed = delta <= 0
    wait_seconds = 0 if already_passed else min(int(math.ceil(delta)), MAX_WAIT_UNTIL_SECONDS)
    capped = (not already_passed) and delta > MAX_WAIT_UNTIL_SECONDS
    return {
        "until": target.isoformat().replace("+00:00", "Z"),
        "now": current.isoformat().replace("+00:00", "Z"),
        "wait_seconds": wait_seconds,
        "waited_seconds": wait_seconds,
        "already_passed": already_passed,
        "capped": capped,
        "max_wait_seconds": MAX_WAIT_UNTIL_SECONDS,
    }


def evaluate_uuid_gen(config: dict[str, Any]) -> dict[str, Any]:
    try:
        count = int(config.get("count") or 1)
    except (TypeError, ValueError):
        count = 1
    count = max(1, min(MAX_UUID_COUNT, count))
    prefix = str(config.get("prefix") or "").strip()
    if len(prefix) > 64:
        prefix = prefix[:64]
    uuids = [f"{prefix}{uuid4()}" if prefix else str(uuid4()) for _ in range(count)]
    return {
        "uuid": uuids[0],
        "uuids": uuids,
        "count": count,
        "prefix": prefix or None,
    }


def evaluate_hash_digest(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    algorithm = str(config.get("algorithm") or "sha256").strip().lower()
    if algorithm not in HASH_ALGORITHMS:
        algorithm = "sha256"
    value = resolve_safe_template(
        str(config.get("value_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    if len(value) > MAX_HASH_INPUT_CHARS:
        return {
            "algorithm": algorithm,
            "digest": None,
            "error": f"hash input exceeds {MAX_HASH_INPUT_CHARS} characters",
        }
    data = value.encode("utf-8")
    if algorithm == "hmac-sha256":
        key = resolve_safe_template(
            str(config.get("key_template") or ""),
            step_outputs=step_outputs,
            run_input=run_input,
        )
        if not key:
            return {"algorithm": algorithm, "digest": None, "error": "hmac-sha256 requires key_template"}
        digest = hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()
    elif algorithm == "sha1":
        digest = hashlib.sha1(data).hexdigest()
    elif algorithm == "md5":
        digest = hashlib.md5(data).hexdigest()
    else:
        digest = hashlib.sha256(data).hexdigest()
    return {
        "algorithm": algorithm,
        "digest": digest,
        "hex": digest,
        "length": len(digest),
    }


def evaluate_stop_and_error(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    message = resolve_safe_template(
        str(config.get("message_template") or "Stopped by stop_and_error"),
        step_outputs=step_outputs,
        run_input=run_input,
    ).strip() or "Stopped by stop_and_error"
    return {
        "stopped": True,
        "error": message,
        "message": message,
    }


def evaluate_noop(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    note = str(config.get("note") or "").strip() or None
    payload = step_outputs.get(source) if source else None
    return {
        "ok": True,
        "passthrough": True,
        "source_node_id": source or None,
        "note": note,
        "data": payload if isinstance(payload, dict) else {"value": payload},
    }


def evaluate_json_to_csv(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    items_list, source_node_id, items_path = _load_items_list(config, step_outputs)
    delimiter = str(config.get("delimiter") or ",")[:1] or ","
    include_header = str(config.get("include_header") or "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    rows = items_list[:MAX_CSV_ROWS]
    truncated = len(items_list) > MAX_CSV_ROWS
    fieldnames: list[str] = []
    dict_rows: list[dict[str, Any]] = []
    for item in rows:
        if isinstance(item, dict):
            dict_rows.append(item)
            for key in item.keys():
                key_str = str(key)
                if key_str not in fieldnames:
                    fieldnames.append(key_str)
        else:
            dict_rows.append({"value": item})
            if "value" not in fieldnames:
                fieldnames.append("value")
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=fieldnames or ["value"],
        delimiter=delimiter,
        extrasaction="ignore",
        lineterminator="\n",
    )
    if include_header and fieldnames:
        writer.writeheader()
    for row in dict_rows:
        writer.writerow({k: row.get(k, "") for k in fieldnames})
    csv_text = buffer.getvalue()
    return {
        "csv": csv_text,
        "text": csv_text,
        "count": len(dict_rows),
        "truncated": truncated,
        "delimiter": delimiter,
        "include_header": include_header,
        "source_node_id": source_node_id,
        "items_path": items_path,
        "columns": fieldnames,
    }


def evaluate_split_out(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    items_list, source_node_id, items_path = _load_items_list(config, step_outputs)
    capped = items_list[:MAX_FOREACH_ITEMS]
    return {
        "items": capped,
        "count": len(capped),
        "total": len(items_list),
        "truncated": len(items_list) > MAX_FOREACH_ITEMS,
        "source_node_id": source_node_id,
        "items_path": items_path,
    }


def _parse_field_list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    text = str(raw or "").strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass
    return [part.strip() for part in text.split(",") if part.strip()]


def evaluate_pick_fields(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    fields = _parse_field_list(config.get("fields"))[:MAX_PICK_FIELDS]
    base = _json_path_value(step_outputs.get(source), path) if source else None
    if not isinstance(base, dict):
        base = {}
    picked = {key: base[key] for key in fields if key in base}
    return {
        "fields": picked,
        "data": picked,
        **picked,
        "picked_keys": list(picked.keys()),
        "source_node_id": source or None,
        "json_path": path,
    }


def evaluate_rename_keys(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    mapping_raw = config.get("mapping_json") or "{}"
    try:
        mapping = json.loads(mapping_raw) if isinstance(mapping_raw, str) else mapping_raw
    except json.JSONDecodeError:
        mapping = {}
    if not isinstance(mapping, dict):
        mapping = {}
    pairs = [(str(k), str(v)) for k, v in list(mapping.items())[:MAX_RENAME_KEYS] if str(k) and str(v)]
    base = _json_path_value(step_outputs.get(source), path) if source else None
    if not isinstance(base, dict):
        base = {}
    renamed = dict(base)
    for old_key, new_key in pairs:
        if old_key in renamed:
            renamed[new_key] = renamed.pop(old_key)
    return {
        "fields": renamed,
        "data": renamed,
        **renamed,
        "renamed": [{"from": old, "to": new} for old, new in pairs],
        "source_node_id": source or None,
        "json_path": path,
    }


def _evaluate_boolean_rule(rule: dict[str, Any], step_outputs: dict[str, Any]) -> bool:
    cfg = {
        "source_node_id": rule.get("source_node_id") or rule.get("source_a_node_id"),
        "json_path": rule.get("json_path") or rule.get("json_path_a") or "$",
        "operator": rule.get("operator") or "==",
        "compare_value": rule.get("compare_value"),
    }
    operator = str(cfg["operator"]).strip()
    if operator in COMPARE_OPS and operator not in {"==", "!=", ">", "<", "contains", "exists"}:
        # reuse compare semantics for gt/lt aliases
        result = evaluate_compare(
            {
                "source_a_node_id": cfg["source_node_id"],
                "json_path_a": cfg["json_path"],
                "operator": operator,
                "compare_value": cfg.get("compare_value"),
            },
            step_outputs,
        )
        return bool(result.get("matched"))
    return evaluate_condition(cfg, step_outputs)


def evaluate_boolean_logic(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    combine = str(config.get("combine") or "and").strip().lower()
    if combine not in BOOLEAN_COMBINE:
        combine = "and"
    raw = config.get("rules_json") or "[]"
    try:
        rules = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        rules = []
    if not isinstance(rules, list):
        rules = []
    rules = [rule for rule in rules if isinstance(rule, dict)][:MAX_BOOLEAN_RULES]
    results = [_evaluate_boolean_rule(rule, step_outputs) for rule in rules]
    if not results:
        matched = False
    elif combine == "or":
        matched = any(results)
    else:
        matched = all(results)
    return {
        "matched": matched,
        "combine": combine,
        "rule_count": len(results),
        "rule_results": results,
    }


def evaluate_html_strip(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    value = resolve_safe_template(
        str(config.get("value_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    stripped = _HTML_TAG_PATTERN.sub("", value)
    text = html.unescape(stripped).strip()
    return {
        "text": text,
        "value": text,
        "result": text,
        "input_length": len(value),
        "output_length": len(text),
    }


def evaluate_url_ops(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    operation = str(config.get("operation") or "encode").strip().lower()
    if operation not in URL_OPS:
        operation = "encode"
    value = resolve_safe_template(
        str(config.get("value_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    if operation == "encode":
        result = quote(value, safe="")
        return {"operation": operation, "result": result, "value": result, "input": value}
    if operation == "decode":
        result = unquote(value)
        return {"operation": operation, "result": result, "value": result, "input": value}
    if operation == "parse_query":
        query = value
        if "?" in query:
            query = query.split("?", 1)[1]
        pairs = parse_qsl(query, keep_blank_values=True)
        data = {str(k): str(v) for k, v in pairs}
        return {
            "operation": operation,
            "result": data,
            "data": data,
            "fields": data,
            "count": len(data),
            "input": value,
        }
    # build_query — value may be JSON object
    try:
        parsed = json.loads(value) if value.strip().startswith("{") else None
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        result = urlencode({str(k): str(v) for k, v in parsed.items()}, doseq=True)
    else:
        result = urlencode(parse_qsl(value, keep_blank_values=True), doseq=True)
    return {"operation": operation, "result": result, "value": result, "input": value}


def evaluate_base64_ops(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    operation = str(config.get("operation") or "encode").strip().lower()
    if operation not in BASE64_OPS:
        operation = "encode"
    value = resolve_safe_template(
        str(config.get("value_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    if len(value) > MAX_BASE64_CHARS:
        return {
            "operation": operation,
            "result": None,
            "error": f"base64 input exceeds {MAX_BASE64_CHARS} characters",
        }
    if operation == "encode":
        result = base64.b64encode(value.encode("utf-8")).decode("ascii")
        return {"operation": operation, "result": result, "value": result, "input": value}
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=False)
        result = decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        return {"operation": operation, "result": None, "error": f"base64 decode failed: {exc}"}
    return {"operation": operation, "result": result, "value": result, "input": value}


def evaluate_coalesce(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    raw = config.get("candidates_json") or "[]"
    try:
        candidates = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        candidates = []
    if not isinstance(candidates, list):
        candidates = []
    candidates = candidates[:MAX_COALESCE_CANDIDATES]
    resolved: list[Any] = []
    chosen = None
    chosen_index = None
    for index, item in enumerate(candidates):
        if isinstance(item, str):
            value = resolve_safe_template(item, step_outputs=step_outputs, run_input=run_input)
        else:
            value = item
        resolved.append(value)
        if chosen is None and value not in (None, "", [], {}):
            chosen = value
            chosen_index = index
    return {
        "value": chosen,
        "result": chosen,
        "chosen_index": chosen_index,
        "candidate_count": len(candidates),
        "found": chosen is not None,
    }


def evaluate_omit_fields(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    omit = set(_parse_field_list(config.get("fields"))[:MAX_PICK_FIELDS])
    base = _json_path_value(step_outputs.get(source), path) if source else None
    if not isinstance(base, dict):
        base = {}
    kept = {key: value for key, value in base.items() if str(key) not in omit}
    return {
        "fields": kept,
        "data": kept,
        **kept,
        "omitted_keys": sorted(omit),
        "kept_keys": list(kept.keys()),
        "source_node_id": source or None,
        "json_path": path,
    }


def evaluate_append_items(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source_a = str(config.get("source_a_node_id") or "").strip()
    source_b = str(config.get("source_b_node_id") or "").strip()
    path_a = str(config.get("items_path_a") or config.get("items_path") or "$").strip() or "$"
    path_b = str(config.get("items_path_b") or config.get("items_path") or "$").strip() or "$"
    a = _json_path_value(step_outputs.get(source_a), path_a) if source_a else []
    b = _json_path_value(step_outputs.get(source_b), path_b) if source_b else []
    list_a = list(a) if isinstance(a, list) else ([] if a in (None, "") else [a])
    list_b = list(b) if isinstance(b, list) else ([] if b in (None, "") else [b])
    merged = list_a + list_b
    truncated = len(merged) > MAX_APPEND_ITEMS
    items = merged[:MAX_APPEND_ITEMS]
    return {
        "items": items,
        "count": len(items),
        "total": len(merged),
        "truncated": truncated,
        "source_a_node_id": source_a or None,
        "source_b_node_id": source_b or None,
        "count_a": len(list_a),
        "count_b": len(list_b),
    }


def evaluate_number_format(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    raw = resolve_safe_template(
        str(config.get("value_template") or "0"),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    style = str(config.get("style") or "decimal").strip().lower()
    if style not in NUMBER_FORMAT_STYLES:
        style = "decimal"
    try:
        precision = int(config.get("precision") or 2)
    except (TypeError, ValueError):
        precision = 2
    precision = max(0, min(10, precision))
    prefix = str(config.get("prefix") or "")
    suffix = str(config.get("suffix") or "")
    try:
        number = float(raw)
    except (TypeError, ValueError):
        return {
            "style": style,
            "formatted": None,
            "value": None,
            "error": "number_format value must be numeric",
        }
    if style == "integer":
        formatted = str(int(round(number)))
    elif style == "percent":
        formatted = f"{number * 100:.{precision}f}%"
    elif style == "currency_prefix":
        currency = prefix or "$"
        formatted = f"{currency}{number:,.{precision}f}"
        prefix = ""
    else:
        formatted = f"{number:.{precision}f}"
    formatted = f"{prefix}{formatted}{suffix}"
    return {
        "style": style,
        "number": number,
        "formatted": formatted,
        "value": formatted,
        "result": formatted,
        "precision": precision,
    }


def evaluate_regex_extract(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    pattern = str(config.get("pattern") or "").strip()
    if not pattern:
        return {"matches": [], "count": 0, "first": None, "error": "regex_extract requires pattern"}
    if len(pattern) > MAX_REGEX_PATTERN_LEN:
        return {
            "matches": [],
            "count": 0,
            "first": None,
            "error": f"pattern exceeds {MAX_REGEX_PATTERN_LEN} characters",
        }
    if _UNSAFE_REGEX_PATTERN.search(pattern):
        return {
            "matches": [],
            "count": 0,
            "first": None,
            "error": "pattern uses disallowed constructs (nested lookaround / explosive quantifiers)",
        }
    value = resolve_safe_template(
        str(config.get("value_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    if len(value) > MAX_REGEX_INPUT_CHARS:
        return {
            "matches": [],
            "count": 0,
            "first": None,
            "error": f"input exceeds {MAX_REGEX_INPUT_CHARS} characters",
        }
    flags_raw = str(config.get("flags") or "").lower()
    flags = 0
    if "i" in flags_raw:
        flags |= re.IGNORECASE
    if "m" in flags_raw:
        flags |= re.MULTILINE
    if "s" in flags_raw:
        flags |= re.DOTALL
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        return {"matches": [], "count": 0, "first": None, "error": f"invalid regex: {exc}"}
    try:
        group = int(config.get("group") or 0)
    except (TypeError, ValueError):
        group = 0
    group = max(0, min(20, group))
    matches: list[str] = []
    truncated = False
    for match in compiled.finditer(value):
        if group == 0:
            matches.append(match.group(0))
        else:
            try:
                matches.append(match.group(group))
            except IndexError:
                matches.append(match.group(0))
        if len(matches) >= MAX_REGEX_MATCHES:
            truncated = True
            break
    return {
        "matches": matches,
        "items": matches,
        "count": len(matches),
        "first": matches[0] if matches else None,
        "value": matches[0] if matches else None,
        "pattern": pattern,
        "truncated": truncated,
    }


def evaluate_text_template(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    text = resolve_safe_template(
        str(config.get("text_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    return {
        "text": text,
        "message": text,
        "value": text,
        "result": text,
        "length": len(text),
    }


def evaluate_timezone_convert(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    value = resolve_safe_template(
        str(config.get("value_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    ).strip()
    to_tz_name = str(config.get("to_timezone") or "UTC").strip() or "UTC"
    from_tz_name = str(config.get("from_timezone") or "UTC").strip() or "UTC"
    output_format = str(config.get("output_format") or "%Y-%m-%dT%H:%M:%S%z").strip()
    try:
        to_tz = ZoneInfo(to_tz_name)
        from_tz = ZoneInfo(from_tz_name)
    except ZoneInfoNotFoundError:
        return {
            "error": "unknown timezone — use IANA names like UTC or America/New_York",
            "iso": None,
            "formatted": None,
        }
    parsed: Optional[datetime] = None
    candidates = [value]
    if value.endswith("Z"):
        candidates.append(value[:-1] + "+00:00")
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            break
        except ValueError:
            continue
    if parsed is None:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return {"error": "value_template must be an ISO datetime", "iso": None, "formatted": None}
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=from_tz)
    converted = parsed.astimezone(to_tz)
    iso = converted.isoformat()
    try:
        formatted = converted.strftime(output_format)
    except ValueError:
        formatted = iso
    return {
        "iso": iso,
        "formatted": formatted,
        "value": formatted,
        "epoch_seconds": int(converted.timestamp()),
        "from_timezone": from_tz_name,
        "to_timezone": to_tz_name,
    }


def evaluate_item_exists(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    value = _json_path_value(step_outputs.get(source), path) if source else None
    exists = value is not None and value != "" and value != [] and value != {}
    return {
        "matched": exists,
        "exists": exists,
        "value": value,
        "source_node_id": source or None,
        "json_path": path,
    }


def _flatten_json_object(
    data: Any,
    *,
    prefix: str = "",
    separator: str = ".",
    depth: int = 0,
    out: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    result = out if out is not None else {}
    if len(result) >= MAX_FLATTEN_KEYS or depth > MAX_FLATTEN_DEPTH:
        if prefix and prefix not in result and len(result) < MAX_FLATTEN_KEYS:
            result[prefix] = data
        return result
    if isinstance(data, dict):
        if not data and prefix:
            result[prefix] = {}
            return result
        for key, value in data.items():
            key_str = str(key)
            next_prefix = f"{prefix}{separator}{key_str}" if prefix else key_str
            _flatten_json_object(
                value,
                prefix=next_prefix,
                separator=separator,
                depth=depth + 1,
                out=result,
            )
            if len(result) >= MAX_FLATTEN_KEYS:
                break
        return result
    if isinstance(data, list):
        if not data and prefix:
            result[prefix] = []
            return result
        for index, value in enumerate(data):
            next_prefix = f"{prefix}{separator}{index}" if prefix else str(index)
            _flatten_json_object(
                value,
                prefix=next_prefix,
                separator=separator,
                depth=depth + 1,
                out=result,
            )
            if len(result) >= MAX_FLATTEN_KEYS:
                break
        return result
    if prefix:
        result[prefix] = data
    return result


def evaluate_flatten_json(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    separator = str(config.get("separator") or ".").strip()[:3] or "."
    base = _json_path_value(step_outputs.get(source), path) if source else None
    flat = _flatten_json_object(base if base is not None else {}, separator=separator)
    truncated = len(flat) >= MAX_FLATTEN_KEYS
    return {
        "fields": flat,
        "data": flat,
        **flat,
        "count": len(flat),
        "truncated": truncated,
        "separator": separator,
        "source_node_id": source or None,
        "json_path": path,
    }


def evaluate_json_stringify(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    pretty = str(config.get("pretty") or "false").strip().lower() in {"1", "true", "yes", "on"}
    value = _json_path_value(step_outputs.get(source), path) if source else None
    indent = 2 if pretty else None
    try:
        text = json.dumps(value, indent=indent, ensure_ascii=True, default=str)
    except (TypeError, ValueError) as exc:
        return {"json": None, "text": None, "error": f"json_stringify failed: {exc}"}
    return {
        "json": text,
        "text": text,
        "value": text,
        "result": text,
        "length": len(text),
        "pretty": pretty,
        "source_node_id": source or None,
        "json_path": path,
    }


def evaluate_type_of(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    value = _json_path_value(step_outputs.get(source), path) if source else None
    if value is None:
        type_name = "null"
    elif isinstance(value, bool):
        type_name = "boolean"
    elif isinstance(value, int) and not isinstance(value, bool):
        type_name = "number"
    elif isinstance(value, float):
        type_name = "number"
    elif isinstance(value, str):
        type_name = "string"
    elif isinstance(value, list):
        type_name = "array"
    elif isinstance(value, dict):
        type_name = "object"
    else:
        type_name = type(value).__name__
    return {
        "type": type_name,
        "value": value,
        "is_null": value is None,
        "is_empty": value in ("", [], {}),
        "source_node_id": source or None,
        "json_path": path,
    }


def _xml_element_to_obj(element: ET.Element, *, counter: list[int]) -> dict[str, Any]:
    counter[0] += 1
    if counter[0] > MAX_XML_ELEMENTS:
        raise ValueError(f"XML exceeds max element count ({MAX_XML_ELEMENTS})")
    children = list(element)
    node: dict[str, Any] = {"tag": element.tag}
    if element.attrib:
        node["attributes"] = {str(k)[:64]: str(v)[:512] for k, v in list(element.attrib.items())[:32]}
    text = (element.text or "").strip()
    if text:
        node["text"] = text[:4000]
    if children:
        grouped: dict[str, Any] = {}
        for child in children:
            child_obj = _xml_element_to_obj(child, counter=counter)
            tag = str(child.tag)
            if tag in grouped:
                existing = grouped[tag]
                if isinstance(existing, list):
                    existing.append(child_obj)
                else:
                    grouped[tag] = [existing, child_obj]
            else:
                grouped[tag] = child_obj
        node["children"] = grouped
    return node


def evaluate_xml_parse(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    raw = _json_path_value(step_outputs.get(source), path) if source else None
    if raw is None:
        return {"data": None, "error": "xml_parse source value is empty", "source_node_id": source or None}
    text = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=True, default=str)
    if len(text) > MAX_XML_BYTES:
        return {
            "data": None,
            "error": f"xml_parse input exceeds {MAX_XML_BYTES} bytes",
            "source_node_id": source or None,
        }
    lowered = text.lstrip().lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        return {
            "data": None,
            "error": "xml_parse rejects DOCTYPE/ENTITY (XXE prevention)",
            "source_node_id": source or None,
        }
    try:
        root = ET.fromstring(text)
        data = _xml_element_to_obj(root, counter=[0])
    except (ET.ParseError, ValueError) as exc:
        return {"data": None, "error": f"xml_parse failed: {exc}", "source_node_id": source or None}
    return {
        "data": data,
        "tag": data.get("tag"),
        "source_node_id": source or None,
        "json_path": path,
    }


def _unflatten_json_object(flat: dict[str, Any], *, separator: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    for raw_key, value in list(flat.items())[:MAX_FLATTEN_KEYS]:
        key = str(raw_key or "").strip()
        if not key:
            continue
        parts = [part for part in key.split(separator) if part != ""][:MAX_FLATTEN_DEPTH]
        if not parts:
            continue
        cursor: Any = root
        for index, part in enumerate(parts):
            is_last = index == len(parts) - 1
            next_part = parts[index + 1] if not is_last else None
            next_is_index = next_part is not None and next_part.isdigit()
            if part.isdigit():
                idx = int(part)
                if not isinstance(cursor, list):
                    break
                while len(cursor) <= idx:
                    cursor.append({} if (next_is_index is False and not is_last) else ([] if next_is_index else None))
                if is_last:
                    cursor[idx] = value
                else:
                    if cursor[idx] is None or isinstance(cursor[idx], (str, int, float, bool)):
                        cursor[idx] = [] if next_is_index else {}
                    cursor = cursor[idx]
                continue
            if not isinstance(cursor, dict):
                break
            if is_last:
                cursor[part] = value
            else:
                if part not in cursor or not isinstance(cursor[part], (dict, list)):
                    cursor[part] = [] if next_is_index else {}
                cursor = cursor[part]
    return root


def evaluate_unflatten_json(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    separator = str(config.get("separator") or ".").strip()[:3] or "."
    base = _json_path_value(step_outputs.get(source), path) if source else None
    if isinstance(base, dict) and "fields" in base and isinstance(base.get("fields"), dict):
        flat = base["fields"]
    elif isinstance(base, dict):
        flat = base
    else:
        flat = {}
    nested = _unflatten_json_object(flat if isinstance(flat, dict) else {}, separator=separator)
    return {
        "data": nested,
        "fields": nested,
        "separator": separator,
        "count": len(flat) if isinstance(flat, dict) else 0,
        "source_node_id": source or None,
        "json_path": path,
    }


def evaluate_chunk_text(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    raw = _json_path_value(step_outputs.get(source), path) if source else None
    text = raw if isinstance(raw, str) else (json.dumps(raw, ensure_ascii=True, default=str) if raw is not None else "")
    text = text[:MAX_CHUNK_TEXT_CHARS]
    try:
        chunk_size = int(config.get("chunk_size") or 500)
    except (TypeError, ValueError):
        chunk_size = 500
    try:
        overlap = int(config.get("overlap") or 0)
    except (TypeError, ValueError):
        overlap = 0
    chunk_size = max(1, min(chunk_size, MAX_CHUNK_SIZE))
    overlap = max(0, min(overlap, chunk_size - 1 if chunk_size > 1 else 0))
    step = max(1, chunk_size - overlap)
    chunks: list[str] = []
    if text:
        for start in range(0, len(text), step):
            chunks.append(text[start : start + chunk_size])
            if len(chunks) >= MAX_CHUNK_COUNT:
                break
            if start + chunk_size >= len(text):
                break
    return {
        "chunks": chunks,
        "items": chunks,
        "count": len(chunks),
        "chunk_size": chunk_size,
        "overlap": overlap,
        "truncated": len(text) >= MAX_CHUNK_TEXT_CHARS or len(chunks) >= MAX_CHUNK_COUNT,
        "source_node_id": source or None,
        "json_path": path,
    }


def evaluate_form_urlencoded(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    operation = str(config.get("operation") or "encode").strip().lower()
    raw = _json_path_value(step_outputs.get(source), path) if source else None
    if operation not in FORM_URLENCODED_OPS:
        return {"error": f"form_urlencoded operation must be one of: {', '.join(sorted(FORM_URLENCODED_OPS))}"}
    if operation == "encode":
        if isinstance(raw, dict):
            pairs = [(str(k)[:64], str(v)[:2000]) for k, v in list(raw.items())[:64]]
        elif isinstance(raw, list):
            pairs = []
            for item in raw[:64]:
                if isinstance(item, dict) and "key" in item:
                    pairs.append((str(item.get("key"))[:64], str(item.get("value", ""))[:2000]))
                else:
                    pairs.append((str(len(pairs)), str(item)[:2000]))
        else:
            pairs = [("value", str(raw or "")[:2000])]
        encoded = urlencode(pairs, doseq=True)
        return {
            "operation": "encode",
            "text": encoded,
            "value": encoded,
            "data": encoded,
            "pair_count": len(pairs),
            "source_node_id": source or None,
            "json_path": path,
        }
    text = raw if isinstance(raw, str) else str(raw or "")
    parsed = parse_qsl(text[:MAX_CHUNK_TEXT_CHARS], keep_blank_values=True)[:64]
    data = {str(k)[:64]: str(v)[:2000] for k, v in parsed}
    return {
        "operation": "decode",
        "data": data,
        "fields": data,
        "pair_count": len(parsed),
        "source_node_id": source or None,
        "json_path": path,
    }


def _deep_merge_dicts(
    left: Any,
    right: Any,
    *,
    depth: int = 0,
    key_counter: list[int],
) -> Any:
    if depth > MAX_DEEP_MERGE_DEPTH:
        return right if right is not None else left
    if not isinstance(left, dict) or not isinstance(right, dict):
        return right if right is not None else left
    merged: dict[str, Any] = dict(left)
    for key, value in right.items():
        if key_counter[0] >= MAX_DEEP_MERGE_KEYS:
            break
        key_str = str(key)[:64]
        key_counter[0] += 1
        if key_str in merged and isinstance(merged[key_str], dict) and isinstance(value, dict):
            merged[key_str] = _deep_merge_dicts(
                merged[key_str],
                value,
                depth=depth + 1,
                key_counter=key_counter,
            )
        else:
            merged[key_str] = value
    return merged


def evaluate_deep_merge(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    merge_source = str(config.get("merge_source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    merge_path = str(config.get("merge_json_path") or "$").strip() or "$"
    left = _json_path_value(step_outputs.get(source), path) if source else {}
    right = _json_path_value(step_outputs.get(merge_source), merge_path) if merge_source else {}
    if not isinstance(left, dict):
        left = {}
    if not isinstance(right, dict):
        right = {}
    counter = [0]
    merged = _deep_merge_dicts(left, right, key_counter=counter)
    return {
        "data": merged,
        "fields": merged,
        "key_count": counter[0],
        "truncated": counter[0] >= MAX_DEEP_MERGE_KEYS,
        "source_node_id": source or None,
        "merge_source_node_id": merge_source or None,
        "json_path": path,
        "merge_json_path": merge_path,
    }


def _b64url_json_segment(segment: str) -> Optional[dict[str, Any]]:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def evaluate_jwt_decode(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    raw = _json_path_value(step_outputs.get(source), path) if source else None
    token = str(raw or "").strip()
    if len(token) > MAX_JWT_CHARS:
        return {"error": f"jwt_decode token exceeds {MAX_JWT_CHARS} characters", "verified": False}
    parts = token.split(".")
    if len(parts) < 2:
        return {"error": "jwt_decode expects a compact JWT with at least header.payload", "verified": False}
    header = _b64url_json_segment(parts[0][:2048])
    payload = _b64url_json_segment(parts[1][:MAX_JWT_CHARS])
    if header is None or payload is None:
        return {"error": "jwt_decode failed to parse header/payload JSON", "verified": False}
    # Never treat decode-as-inspect as cryptographic verification.
    return {
        "header": header,
        "payload": payload,
        "claims": payload,
        "data": payload,
        "verified": False,
        "algorithm": header.get("alg"),
        "subject": payload.get("sub"),
        "issuer": payload.get("iss"),
        "audience": payload.get("aud"),
        "expires_at": payload.get("exp"),
        "source_node_id": source or None,
        "json_path": path,
        "note": "Claims are decoded only; signature is not verified.",
    }


class _SafeHtmlExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self.links: list[dict[str, str]] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        lowered = str(tag or "").lower()
        if lowered in {"script", "style"}:
            self._skip_depth += 1
            return
        if lowered == "a" and self._skip_depth == 0 and len(self.links) < MAX_HTML_LINKS:
            href = ""
            text_hint = ""
            for key, value in attrs:
                if str(key).lower() == "href":
                    href = str(value or "").strip()[:2048]
                if str(key).lower() == "title":
                    text_hint = str(value or "").strip()[:256]
            if href:
                self.links.append({"href": href, "title": text_hint})

    def handle_endtag(self, tag: str) -> None:
        lowered = str(tag or "").lower()
        if lowered in {"script", "style"} and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        text = str(data or "").strip()
        if text:
            self._chunks.append(text)

    @property
    def text(self) -> str:
        return " ".join(self._chunks)[:MAX_HTML_EXTRACT_BYTES]


def evaluate_html_extract(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    mode = str(config.get("mode") or "both").strip().lower() or "both"
    if mode not in HTML_EXTRACT_MODES:
        mode = "both"
    raw = _json_path_value(step_outputs.get(source), path) if source else None
    html_text = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
    html_text = html_text[:MAX_HTML_EXTRACT_BYTES]
    parser = _SafeHtmlExtractor()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception as exc:  # noqa: BLE001 — malformed HTML should not crash flows
        return {"error": f"html_extract failed: {exc}", "text": "", "links": [], "mode": mode}
    text = parser.text
    links = parser.links if mode in {"links", "both"} else []
    if mode == "links":
        text = ""
    return {
        "text": text,
        "value": text,
        "links": links,
        "link_count": len(links),
        "mode": mode,
        "truncated": len(str(raw or "")) > MAX_HTML_EXTRACT_BYTES,
        "source_node_id": source or None,
        "json_path": path,
    }


def evaluate_split_text(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    delimiter = str(config.get("delimiter") if config.get("delimiter") is not None else ",")
    if delimiter == "":
        delimiter = ","
    try:
        max_parts = int(config.get("max_parts") or 50)
    except (TypeError, ValueError):
        max_parts = 50
    max_parts = max(1, min(max_parts, MAX_SPLIT_PARTS))
    raw = _json_path_value(step_outputs.get(source), path) if source else None
    text = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
    text = text[:MAX_CHUNK_TEXT_CHARS]
    parts = text.split(delimiter, max_parts - 1) if delimiter else [text]
    parts = [part.strip() for part in parts][:max_parts]
    return {
        "parts": parts,
        "items": parts,
        "count": len(parts),
        "delimiter": delimiter[:32],
        "max_parts": max_parts,
        "source_node_id": source or None,
        "json_path": path,
    }


def evaluate_json_query(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    value = _json_path_value(step_outputs.get(source), path) if source else None
    return {
        "value": value,
        "data": value,
        "result": value,
        "found": value is not None,
        "source_node_id": source or None,
        "json_path": path,
    }


def evaluate_compress(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    operation = str(config.get("operation") or "compress").strip().lower() or "compress"
    if operation not in COMPRESS_OPS:
        return {"error": f"compress operation must be one of: {', '.join(sorted(COMPRESS_OPS))}"}
    algorithm = str(config.get("algorithm") or "zlib").strip().lower() or "zlib"
    if algorithm not in COMPRESS_ALGOS:
        return {"error": f"compress algorithm must be one of: {', '.join(sorted(COMPRESS_ALGOS))}"}
    raw = _json_path_value(step_outputs.get(source), path) if source else None
    if raw is None:
        return {"error": "compress source value is empty", "operation": operation, "algorithm": algorithm}

    try:
        if operation == "compress":
            if isinstance(raw, (bytes, bytearray)):
                payload = bytes(raw)[:MAX_COMPRESS_BYTES]
            elif isinstance(raw, str):
                payload = raw.encode("utf-8")[:MAX_COMPRESS_BYTES]
            else:
                payload = json.dumps(raw, ensure_ascii=True, default=str).encode("utf-8")[:MAX_COMPRESS_BYTES]
            compressed = gzip.compress(payload) if algorithm == "gzip" else zlib.compress(payload)
            encoded = base64.b64encode(compressed).decode("ascii")
            return {
                "operation": operation,
                "algorithm": algorithm,
                "encoding": "base64",
                "data": encoded,
                "value": encoded,
                "text": encoded,
                "input_bytes": len(payload),
                "output_bytes": len(compressed),
                "source_node_id": source or None,
                "json_path": path,
            }

        if isinstance(raw, (bytes, bytearray)):
            blob = bytes(raw)[:MAX_COMPRESS_BYTES]
        else:
            text = str(raw).strip()
            if len(text) > MAX_COMPRESS_BYTES * 2:
                return {"error": f"compress input exceeds {MAX_COMPRESS_BYTES} bytes", "operation": operation}
            try:
                blob = base64.b64decode(text)
            except Exception:  # noqa: BLE001
                blob = text.encode("utf-8")
            blob = blob[:MAX_COMPRESS_BYTES]
        expanded = gzip.decompress(blob) if algorithm == "gzip" else zlib.decompress(blob)
        if len(expanded) > MAX_COMPRESS_BYTES:
            return {
                "error": f"decompress output exceeds {MAX_COMPRESS_BYTES} bytes",
                "operation": operation,
                "algorithm": algorithm,
            }
        try:
            text_out = expanded.decode("utf-8")
            data_out: Any = text_out
            try:
                data_out = json.loads(text_out)
            except json.JSONDecodeError:
                pass
        except UnicodeDecodeError:
            text_out = base64.b64encode(expanded).decode("ascii")
            data_out = text_out
        return {
            "operation": operation,
            "algorithm": algorithm,
            "data": data_out,
            "value": data_out,
            "text": text_out if isinstance(text_out, str) else None,
            "input_bytes": len(blob),
            "output_bytes": len(expanded),
            "source_node_id": source or None,
            "json_path": path,
        }
    except Exception as exc:  # noqa: BLE001 — malformed input should not crash flows
        return {"error": f"compress failed: {exc}", "operation": operation, "algorithm": algorithm}


def evaluate_hmac_verify(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    algorithm = str(config.get("algorithm") or "sha256").strip().lower() or "sha256"
    if algorithm not in HMAC_VERIFY_ALGOS:
        return {"error": f"hmac_verify algorithm must be one of: {', '.join(sorted(HMAC_VERIFY_ALGOS))}"}
    encoding = str(config.get("encoding") or "hex").strip().lower() or "hex"
    if encoding not in {"hex", "base64"}:
        encoding = "hex"
    value = resolve_safe_template(
        str(config.get("value_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    key = resolve_safe_template(
        str(config.get("key_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    )
    expected_raw = resolve_safe_template(
        str(config.get("expected_template") or ""),
        step_outputs=step_outputs,
        run_input=run_input,
    ).strip()
    if not key:
        return {"verified": False, "matched": False, "error": "hmac_verify requires key_template"}
    if not expected_raw:
        return {"verified": False, "matched": False, "error": "hmac_verify requires expected_template"}
    if len(value) > MAX_HASH_INPUT_CHARS or len(key) > MAX_HASH_INPUT_CHARS:
        return {"verified": False, "matched": False, "error": "hmac_verify input exceeds size cap"}

    digest_mod = hashlib.sha256 if algorithm == "sha256" else hashlib.sha1
    digest_bytes = hmac.new(key.encode("utf-8"), value.encode("utf-8"), digest_mod).digest()
    computed = digest_bytes.hex() if encoding == "hex" else base64.b64encode(digest_bytes).decode("ascii")
    expected = expected_raw
    for prefix in ("sha256=", "sha1=", "sha-256=", "sha-1="):
        if expected.lower().startswith(prefix):
            expected = expected[len(prefix) :]
            break
    expected = expected.strip()
    try:
        matched = hmac.compare_digest(computed, expected)
    except (TypeError, ValueError):
        matched = False
    return {
        "verified": matched,
        "matched": matched,
        "algorithm": algorithm,
        "encoding": encoding,
        "digest": computed,
        "expected_present": True,
    }


def _xml_escape(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _obj_to_xml(data: Any, tag: str, *, counter: list[int], depth: int = 0) -> str:
    counter[0] += 1
    if counter[0] > MAX_XML_ELEMENTS or depth > MAX_DEEP_MERGE_DEPTH:
        return f"<{_xml_escape(tag)} truncated=\"true\"/>"
    safe_tag = re.sub(r"[^A-Za-z0-9_.-]", "_", str(tag or "item")) or "item"
    if safe_tag[0].isdigit():
        safe_tag = f"n_{safe_tag}"
    if isinstance(data, dict):
        # Prefer xml_parse-shaped objects.
        if "tag" in data and any(key in data for key in ("text", "children", "attributes")):
            element_tag = re.sub(r"[^A-Za-z0-9_.-]", "_", str(data.get("tag") or safe_tag)) or safe_tag
            attrs = data.get("attributes") if isinstance(data.get("attributes"), dict) else {}
            attr_parts = []
            for key, value in list(attrs.items())[:32]:
                attr_parts.append(f'{_xml_escape(str(key)[:64])}="{_xml_escape(str(value)[:512])}"')
            attr_str = (" " + " ".join(attr_parts)) if attr_parts else ""
            children = data.get("children")
            text = str(data.get("text") or "")[:4000]
            if isinstance(children, dict) and children:
                inner = "".join(
                    _obj_to_xml(child, child_tag, counter=counter, depth=depth + 1)
                    for child_tag, child in list(children.items())[:MAX_DEEP_MERGE_KEYS]
                )
                return f"<{element_tag}{attr_str}>{_xml_escape(text)}{inner}</{element_tag}>"
            if text:
                return f"<{element_tag}{attr_str}>{_xml_escape(text)}</{element_tag}>"
            return f"<{element_tag}{attr_str}/>"
        inner = "".join(
            _obj_to_xml(value, str(key), counter=counter, depth=depth + 1)
            for key, value in list(data.items())[:MAX_DEEP_MERGE_KEYS]
        )
        return f"<{safe_tag}>{inner}</{safe_tag}>"
    if isinstance(data, list):
        inner = "".join(
            _obj_to_xml(item, "item", counter=counter, depth=depth + 1) for item in data[:MAX_DEEP_MERGE_KEYS]
        )
        return f"<{safe_tag}>{inner}</{safe_tag}>"
    if data is None:
        return f"<{safe_tag}/>"
    return f"<{safe_tag}>{_xml_escape(str(data)[:4000])}</{safe_tag}>"


def evaluate_xml_stringify(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    root_tag = str(config.get("root_tag") or "root").strip() or "root"
    raw = _json_path_value(step_outputs.get(source), path) if source else None
    if raw is None:
        return {"xml": None, "text": None, "error": "xml_stringify source value is empty"}
    try:
        xml_text = _obj_to_xml(raw, root_tag, counter=[0])
    except Exception as exc:  # noqa: BLE001
        return {"xml": None, "text": None, "error": f"xml_stringify failed: {exc}"}
    if len(xml_text) > MAX_XML_BYTES:
        return {"xml": None, "text": None, "error": f"xml_stringify output exceeds {MAX_XML_BYTES} bytes"}
    return {
        "xml": xml_text,
        "text": xml_text,
        "value": xml_text,
        "length": len(xml_text),
        "root_tag": root_tag[:64],
        "source_node_id": source or None,
        "json_path": path,
    }


def _object_diff_walk(
    left: Any,
    right: Any,
    *,
    path: str,
    depth: int,
    changes: list[dict[str, Any]],
    key_counter: list[int],
) -> None:
    if len(changes) >= MAX_OBJECT_DIFF_CHANGES or key_counter[0] >= MAX_DEEP_MERGE_KEYS:
        return
    if depth > MAX_DEEP_MERGE_DEPTH:
        if left != right:
            changes.append({"path": path or "$", "op": "changed", "left": left, "right": right})
        return
    if isinstance(left, dict) and isinstance(right, dict):
        left_map = {str(k): v for k, v in list(left.items())[:MAX_DEEP_MERGE_KEYS]}
        right_map = {str(k): v for k, v in list(right.items())[:MAX_DEEP_MERGE_KEYS]}
        keys = sorted(set(left_map) | set(right_map))
        for key in keys:
            if len(changes) >= MAX_OBJECT_DIFF_CHANGES:
                break
            key_counter[0] += 1
            child_path = f"{path}.{key}" if path else f"$.{key}"
            if key not in left_map:
                changes.append({"path": child_path, "op": "added", "right": right_map.get(key)})
            elif key not in right_map:
                changes.append({"path": child_path, "op": "removed", "left": left_map.get(key)})
            else:
                _object_diff_walk(
                    left_map.get(key),
                    right_map.get(key),
                    path=child_path,
                    depth=depth + 1,
                    changes=changes,
                    key_counter=key_counter,
                )
        return
    if isinstance(left, list) and isinstance(right, list):
        max_len = min(max(len(left), len(right)), MAX_DEEP_MERGE_KEYS)
        for index in range(max_len):
            if len(changes) >= MAX_OBJECT_DIFF_CHANGES:
                break
            key_counter[0] += 1
            child_path = f"{path}[{index}]"
            if index >= len(left):
                changes.append({"path": child_path, "op": "added", "right": right[index]})
            elif index >= len(right):
                changes.append({"path": child_path, "op": "removed", "left": left[index]})
            else:
                _object_diff_walk(
                    left[index],
                    right[index],
                    path=child_path,
                    depth=depth + 1,
                    changes=changes,
                    key_counter=key_counter,
                )
        return
    if left != right:
        changes.append({"path": path or "$", "op": "changed", "left": left, "right": right})


def evaluate_object_diff(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    compare_source = str(config.get("compare_source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    compare_path = str(config.get("compare_json_path") or "$").strip() or "$"
    left = _json_path_value(step_outputs.get(source), path) if source else None
    right = _json_path_value(step_outputs.get(compare_source), compare_path) if compare_source else None
    changes: list[dict[str, Any]] = []
    _object_diff_walk(left, right, path="$", depth=0, changes=changes, key_counter=[0])
    added = sum(1 for item in changes if item.get("op") == "added")
    removed = sum(1 for item in changes if item.get("op") == "removed")
    changed = sum(1 for item in changes if item.get("op") == "changed")
    return {
        "changes": changes,
        "count": len(changes),
        "added": added,
        "removed": removed,
        "changed": changed,
        "equal": len(changes) == 0,
        "truncated": len(changes) >= MAX_OBJECT_DIFF_CHANGES,
        "source_node_id": source or None,
        "compare_source_node_id": compare_source or None,
        "json_path": path,
        "compare_json_path": compare_path,
    }


class _SafeHtmlToMarkdown(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0
        self._list_depth = 0
        self._pending_link: Optional[str] = None
        self._link_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        lowered = str(tag or "").lower()
        if lowered in {"script", "style"}:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if lowered in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            level = int(lowered[1])
            self._parts.append("\n" + ("#" * level) + " ")
        elif lowered == "p":
            self._parts.append("\n\n")
        elif lowered == "br":
            self._parts.append("\n")
        elif lowered in {"strong", "b"}:
            self._parts.append("**")
        elif lowered in {"em", "i"}:
            self._parts.append("*")
        elif lowered == "code":
            self._parts.append("`")
        elif lowered in {"ul", "ol"}:
            self._list_depth += 1
            self._parts.append("\n")
        elif lowered == "li":
            self._parts.append("\n- ")
        elif lowered == "a":
            href = ""
            for key, value in attrs:
                if str(key).lower() == "href":
                    href = str(value or "").strip()[:2048]
                    break
            self._pending_link = href
            self._link_text = []

    def handle_endtag(self, tag: str) -> None:
        lowered = str(tag or "").lower()
        if lowered in {"script", "style"} and self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if lowered in {"strong", "b"}:
            self._parts.append("**")
        elif lowered in {"em", "i"}:
            self._parts.append("*")
        elif lowered == "code":
            self._parts.append("`")
        elif lowered in {"ul", "ol"} and self._list_depth > 0:
            self._list_depth -= 1
            self._parts.append("\n")
        elif lowered == "a":
            text = "".join(self._link_text).strip() or self._pending_link or ""
            href = self._pending_link or ""
            if href:
                self._parts.append(f"[{text}]({href})")
            else:
                self._parts.append(text)
            self._pending_link = None
            self._link_text = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = str(data or "")
        if not text:
            return
        if self._pending_link is not None:
            self._link_text.append(text)
        else:
            self._parts.append(text)

    @property
    def markdown(self) -> str:
        raw = "".join(self._parts)
        # Collapse excessive blank lines while preserving structure.
        lines = [line.rstrip() for line in raw.splitlines()]
        cleaned: list[str] = []
        blank_run = 0
        for line in lines:
            if not line.strip():
                blank_run += 1
                if blank_run <= 2:
                    cleaned.append("")
                continue
            blank_run = 0
            cleaned.append(line)
        return "\n".join(cleaned).strip()[:MAX_HTML_EXTRACT_BYTES]


def evaluate_html_to_markdown(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    raw = _json_path_value(step_outputs.get(source), path) if source else None
    html_text = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
    html_text = html_text[:MAX_HTML_EXTRACT_BYTES]
    parser = _SafeHtmlToMarkdown()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"html_to_markdown failed: {exc}", "markdown": "", "text": ""}
    markdown = parser.markdown
    return {
        "markdown": markdown,
        "text": markdown,
        "value": markdown,
        "length": len(markdown),
        "truncated": len(str(raw or "")) > MAX_HTML_EXTRACT_BYTES,
        "source_node_id": source or None,
        "json_path": path,
    }


def _markdown_inline_to_html(text: str) -> str:
    escaped = html.escape(text, quote=False)

    def _code(match: re.Match[str]) -> str:
        return f"<code>{match.group(1)}</code>"

    def _link(match: re.Match[str]) -> str:
        label = match.group(1)
        href = match.group(2)
        if not re.match(r"^(https?:|mailto:|/)", href, flags=re.IGNORECASE):
            return match.group(0)
        return f'<a href="{html.escape(href, quote=True)}">{label}</a>'

    escaped = re.sub(r"`([^`\n]+)`", _code, escaped)
    escaped = re.sub(r"\*\*([^*\n]+)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", escaped)
    escaped = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", _link, escaped)
    return escaped


def evaluate_markdown_to_html(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
    *,
    run_input: str = "",
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    raw: Any = None
    if source:
        raw = _json_path_value(step_outputs.get(source), path)
        markdown_text = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
    else:
        markdown_text = resolve_safe_template(
            str(config.get("value_template") or ""),
            step_outputs=step_outputs,
            run_input=run_input,
        )
    original_len = len(markdown_text)
    markdown_text = markdown_text[:MAX_HTML_EXTRACT_BYTES]
    blocks: list[str] = []
    list_items: list[str] = []

    def _flush_list() -> None:
        nonlocal list_items
        if list_items:
            blocks.append("<ul>" + "".join(f"<li>{item}</li>" for item in list_items) + "</ul>")
            list_items = []

    for line in markdown_text.splitlines():
        stripped = line.strip()
        if not stripped:
            _flush_list()
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)$", stripped)
        if heading:
            _flush_list()
            level = len(heading.group(1))
            blocks.append(f"<h{level}>{_markdown_inline_to_html(heading.group(2))}</h{level}>")
            continue
        bullet = re.match(r"^[-*+]\s+(.+)$", stripped)
        if bullet:
            list_items.append(_markdown_inline_to_html(bullet.group(1)))
            continue
        _flush_list()
        blocks.append(f"<p>{_markdown_inline_to_html(stripped)}</p>")
    _flush_list()
    html_out = "\n".join(blocks)
    return {
        "html": html_out,
        "text": html_out,
        "value": html_out,
        "length": len(html_out),
        "truncated": original_len > MAX_HTML_EXTRACT_BYTES,
        "source_node_id": source or None,
        "json_path": path if source else None,
    }


def evaluate_array_ops(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    operation = str(config.get("operation") or "length").strip().lower() or "length"
    if operation not in ARRAY_OPS:
        return {"error": f"array_ops operation must be one of: {', '.join(sorted(ARRAY_OPS))}"}
    items_list, source_node_id, items_path = _load_items_list(config, step_outputs)
    # Prefer json_path alias when items_path default unused.
    path = str(config.get("json_path") or items_path or "$").strip() or "$"
    if str(config.get("json_path") or "").strip():
        source = str(config.get("source_node_id") or "").strip()
        raw = _json_path_value(step_outputs.get(source), path) if source else None
        if isinstance(raw, list):
            items_list = raw
        elif raw is None:
            items_list = []
        else:
            items_list = [raw]
    items_list = items_list[:MAX_APPEND_ITEMS]

    if operation == "length":
        return {
            "operation": operation,
            "count": len(items_list),
            "length": len(items_list),
            "value": len(items_list),
            "items": items_list,
            "source_node_id": source_node_id or None,
            "json_path": path,
        }
    if operation == "reverse":
        reversed_items = list(reversed(items_list))
        return {
            "operation": operation,
            "items": reversed_items,
            "count": len(reversed_items),
            "value": reversed_items,
            "source_node_id": source_node_id or None,
            "json_path": path,
        }
    if operation == "first":
        value = items_list[0] if items_list else None
        return {
            "operation": operation,
            "value": value,
            "item": value,
            "count": len(items_list),
            "source_node_id": source_node_id or None,
            "json_path": path,
        }
    if operation == "last":
        value = items_list[-1] if items_list else None
        return {
            "operation": operation,
            "value": value,
            "item": value,
            "count": len(items_list),
            "source_node_id": source_node_id or None,
            "json_path": path,
        }
    if operation == "unique":
        seen: list[Any] = []
        for item in items_list:
            if item not in seen:
                seen.append(item)
            if len(seen) >= MAX_APPEND_ITEMS:
                break
        return {
            "operation": operation,
            "items": seen,
            "count": len(seen),
            "value": seen,
            "source_node_id": source_node_id or None,
            "json_path": path,
        }
    if operation == "concat":
        merge_source = str(config.get("merge_source_node_id") or "").strip()
        merge_path = str(config.get("merge_json_path") or "$").strip() or "$"
        right_raw = _json_path_value(step_outputs.get(merge_source), merge_path) if merge_source else []
        if isinstance(right_raw, list):
            right = right_raw[:MAX_APPEND_ITEMS]
        elif right_raw is None:
            right = []
        else:
            right = [right_raw]
        combined = (items_list + right)[:MAX_APPEND_ITEMS]
        return {
            "operation": operation,
            "items": combined,
            "count": len(combined),
            "value": combined,
            "source_node_id": source_node_id or None,
            "merge_source_node_id": merge_source or None,
            "json_path": path,
            "merge_json_path": merge_path,
        }

    # slice
    try:
        start = int(config.get("start") if config.get("start") is not None else 0)
    except (TypeError, ValueError):
        start = 0
    try:
        end_raw = config.get("end")
        end = int(end_raw) if end_raw not in (None, "") else None
    except (TypeError, ValueError):
        end = None
    sliced = items_list[start:end] if end is not None else items_list[start:]
    sliced = sliced[:MAX_APPEND_ITEMS]
    return {
        "operation": operation,
        "items": sliced,
        "count": len(sliced),
        "value": sliced,
        "start": start,
        "end": end,
        "source_node_id": source_node_id or None,
        "json_path": path,
    }


def _compact_value(
    value: Any,
    *,
    depth: int,
    key_counter: list[int],
    drop_empty_arrays: bool,
    drop_empty_objects: bool,
) -> Any:
    if depth > MAX_COMPACT_DEPTH or key_counter[0] >= MAX_COMPACT_KEYS:
        return value
    if isinstance(value, dict):
        compacted: dict[str, Any] = {}
        for key, child in list(value.items())[:MAX_COMPACT_KEYS]:
            key_counter[0] += 1
            if child is None or child == "":
                continue
            nested = _compact_value(
                child,
                depth=depth + 1,
                key_counter=key_counter,
                drop_empty_arrays=drop_empty_arrays,
                drop_empty_objects=drop_empty_objects,
            )
            if drop_empty_arrays and nested == []:
                continue
            if drop_empty_objects and nested == {}:
                continue
            if nested is None or nested == "":
                continue
            compacted[str(key)[:64]] = nested
        return compacted
    if isinstance(value, list):
        compacted_list = []
        for child in value[:MAX_APPEND_ITEMS]:
            key_counter[0] += 1
            if child is None or child == "":
                continue
            nested = _compact_value(
                child,
                depth=depth + 1,
                key_counter=key_counter,
                drop_empty_arrays=drop_empty_arrays,
                drop_empty_objects=drop_empty_objects,
            )
            if drop_empty_arrays and nested == []:
                continue
            if drop_empty_objects and nested == {}:
                continue
            if nested is None or nested == "":
                continue
            compacted_list.append(nested)
        return compacted_list
    return value


def evaluate_compact_object(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    source = str(config.get("source_node_id") or "").strip()
    path = str(config.get("json_path") or "$").strip() or "$"
    drop_empty_arrays = str(config.get("drop_empty_arrays") or "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    drop_empty_objects = str(config.get("drop_empty_objects") or "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    raw = _json_path_value(step_outputs.get(source), path) if source else None
    if not isinstance(raw, (dict, list)):
        return {
            "data": {},
            "fields": {},
            "error": "compact_object source must be an object or array",
            "source_node_id": source or None,
        }
    counter = [0]
    compacted = _compact_value(
        raw,
        depth=0,
        key_counter=counter,
        drop_empty_arrays=drop_empty_arrays,
        drop_empty_objects=drop_empty_objects,
    )
    key_count = counter[0]
    return {
        "data": compacted,
        "fields": compacted if isinstance(compacted, dict) else {"items": compacted},
        "value": compacted,
        "key_count": key_count,
        "drop_empty_arrays": drop_empty_arrays,
        "drop_empty_objects": drop_empty_objects,
        "truncated": key_count >= MAX_COMPACT_KEYS,
        "source_node_id": source or None,
        "json_path": path,
    }


def evaluate_random(
    config: dict[str, Any],
    step_outputs: dict[str, Any],
) -> dict[str, Any]:
    mode = str(config.get("mode") or "int").strip().lower() or "int"
    if mode not in RANDOM_MODES:
        return {"error": f"random mode must be one of: {', '.join(sorted(RANDOM_MODES))}"}

    if mode == "uuid":
        value = str(uuid4())
        return {"mode": mode, "value": value, "uuid": value, "result": value}

    if mode == "bytes":
        try:
            length = int(config.get("length") or 16)
        except (TypeError, ValueError):
            length = 16
        length = max(1, min(length, MAX_RANDOM_BYTES))
        raw = secrets.token_bytes(length)
        hex_value = raw.hex()
        b64_value = base64.b64encode(raw).decode("ascii")
        return {
            "mode": mode,
            "length": length,
            "hex": hex_value,
            "base64": b64_value,
            "value": hex_value,
            "result": hex_value,
        }

    if mode == "choice":
        choices: list[Any] = []
        source = str(config.get("source_node_id") or "").strip()
        path = str(config.get("json_path") or "$").strip() or "$"
        if source:
            raw = _json_path_value(step_outputs.get(source), path)
            if isinstance(raw, list):
                choices = raw[:MAX_RANDOM_CHOICES]
            elif isinstance(raw, str) and raw.strip():
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        choices = parsed[:MAX_RANDOM_CHOICES]
                except json.JSONDecodeError:
                    choices = [part.strip() for part in raw.split(",") if part.strip()][:MAX_RANDOM_CHOICES]
        if not choices:
            raw_choices = config.get("choices_json")
            if isinstance(raw_choices, list):
                choices = raw_choices[:MAX_RANDOM_CHOICES]
            elif isinstance(raw_choices, str) and raw_choices.strip():
                try:
                    parsed = json.loads(raw_choices)
                    if isinstance(parsed, list):
                        choices = parsed[:MAX_RANDOM_CHOICES]
                except json.JSONDecodeError:
                    choices = [part.strip() for part in raw_choices.split(",") if part.strip()][:MAX_RANDOM_CHOICES]
        if not choices:
            return {"error": "random choice requires a non-empty choices list", "mode": mode}
        index = secrets.randbelow(len(choices))
        value = choices[index]
        return {
            "mode": mode,
            "value": value,
            "result": value,
            "index": index,
            "choice_count": len(choices),
            "source_node_id": source or None,
            "json_path": path,
        }

    try:
        minimum = int(config.get("min") if config.get("min") is not None else 0)
    except (TypeError, ValueError):
        minimum = 0
    try:
        maximum = int(config.get("max") if config.get("max") is not None else 100)
    except (TypeError, ValueError):
        maximum = 100
    if maximum < minimum:
        minimum, maximum = maximum, minimum
    span = maximum - minimum + 1
    if span <= 0 or span > 1_000_000_000:
        return {"error": "random int range must be between 1 and 1e9 inclusive values", "mode": mode}
    value = minimum + secrets.randbelow(span)
    return {
        "mode": mode,
        "value": value,
        "result": value,
        "number": value,
        "min": minimum,
        "max": maximum,
    }


def extract_webhook_response(step_results: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Return the last respond_to_webhook step output for sync webhook HTTP replies."""
    for step in reversed(step_results or []):
        if str(step.get("node_type") or "") != "respond_to_webhook":
            continue
        output = step.get("output") if isinstance(step.get("output"), dict) else {}
        if not output.get("webhook_response"):
            continue
        body = output.get("body")
        return {
            "status_code": int(output.get("status_code") or 200),
            "content_type": str(output.get("content_type") or "application/json"),
            "body": body,
            "node_id": step.get("node_id"),
        }
    return None


def build_preset_api_url(*, base_url: str, path_template: str, query_template: str = "") -> str:
    base = str(base_url or "").rstrip("/")
    path = str(path_template or "").strip() or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    url = f"{base}{path}"
    query = str(query_template or "").strip()
    if query:
        if query.startswith("?"):
            url = f"{url}{query}"
        else:
            url = f"{url}?{query}"
    return url


def _scan_inline_secrets(value: Any, path: str = "") -> list[str]:
    violations: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            if INLINE_SECRET_FIELD_PATTERN.search(str(key)):
                allowed_ref_keys = {
                    "binding_id",
                    "auth_binding_id",
                    "auth_type",
                    "secret_provider_id",
                    "cp_ref",
                    "token_binding_id",
                    "webhook_path_ref",
                    "max_tokens",
                }
                if str(key) not in allowed_ref_keys and nested not in (None, "", []):
                    if not (str(key).endswith("_ref") or str(key).endswith("_binding_id")):
                        violations.append(key_path)
            violations.extend(_scan_inline_secrets(nested, key_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            violations.extend(_scan_inline_secrets(item, f"{path}[{index}]"))
    elif isinstance(value, str) and value.strip():
        key_name = path.rsplit(".", 1)[-1] if path else ""
        if key_name in {"auth_type", "method", "operator"}:
            return violations
        lowered = value.lower()
        if lowered.startswith("sk-") or lowered.startswith("bearer "):
            violations.append(path or "value")
    return violations


def _load_http_allowlist(db: Session) -> list[str]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_ORCHESTRATION_HTTP_ALLOWED_HOSTS_JSON, "[]")
    try:
        parsed = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item).strip().lower() for item in parsed if str(item).strip()]


def _validate_http_url(db: Session, url: str) -> Optional[str]:
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        return "HTTP node URL must use http or https scheme"
    host = (parsed.hostname or "").lower()
    if not host:
        return "HTTP node URL must include a host"
    allowlist = _load_http_allowlist(db)
    if not allowlist:
        return "HTTP outbound hosts are denied by default; configure orchestration.http_allowed_hosts_json"
    if host not in allowlist and not any(host.endswith(f".{allowed}") for allowed in allowlist):
        return f"HTTP host '{host}' is not in orchestration.http_allowed_hosts_json allowlist"
    return None


def merge_http_allowed_hosts(db: Session, hosts: list[str] | tuple[str, ...]) -> list[str]:
    """Merge hosts into orchestration.http_allowed_hosts_json (deduped, lowercased)."""
    from app.services.runtime_config import upsert_runtime_config_value

    current = _load_http_allowlist(db)
    merged: list[str] = list(current)
    for host in hosts:
        normalized = str(host or "").strip().lower()
        if not normalized or normalized in merged:
            continue
        merged.append(normalized)
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_ORCHESTRATION_HTTP_ALLOWED_HOSTS_JSON,
        json.dumps(merged, separators=(",", ":")),
        description="HTTP outbound host allowlist for Flow Studio live connectors",
    )
    return merged


def ensure_leadership_connector_hosts(db: Session) -> list[str]:
    """Seed GitHub / Slack / Stripe hosts required for leadership-class live connectors."""
    return merge_http_allowed_hosts(db, LEADERSHIP_CONNECTOR_HOSTS)


def leadership_connector_host_coverage(db: Session) -> dict[str, Any]:
    allowlist = set(_load_http_allowlist(db))
    missing = [host for host in LEADERSHIP_CONNECTOR_HOSTS if host not in allowlist]
    return {
        "required_hosts": list(LEADERSHIP_CONNECTOR_HOSTS),
        "allowed_hosts": sorted(allowlist),
        "missing_hosts": missing,
        "ready": not missing,
    }


def live_readiness_snapshot(db: Session) -> dict[str, Any]:
    from app.services.orchestration_executor import live_executor_policy_snapshot

    host_coverage = leadership_connector_host_coverage(db)
    live_policy = live_executor_policy_snapshot(db)
    live_enabled = str(live_policy.get("live_executor_enabled") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    prod_enabled = str(live_policy.get("live_executor_prod_enabled") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    recommendations: list[str] = []
    if not host_coverage["ready"]:
        recommendations.append(
            "Seed connector hosts via POST /orchestration/live-readiness/bootstrap "
            f"(missing: {', '.join(host_coverage['missing_hosts'])})."
        )
    if not live_enabled:
        recommendations.append(
            "Enable non-prod live executor (`orchestration.live_executor_enabled=true`); keep prod flag false."
        )
    if prod_enabled:
        recommendations.append(
            "Prod live executor is enabled — confirm dual-approval + allowlist posture before traffic."
        )
    return {
        "connector_hosts": host_coverage,
        "live_executor": live_policy,
        "non_prod_live_ready": bool(live_enabled and host_coverage["ready"]),
        "prod_live_enabled": prod_enabled,
        "recommendations": recommendations,
    }


def _vector_store_exists(db: Session, store_id: str) -> bool:
    normalized = str(store_id or "").strip()
    if not normalized:
        return False
    return any(str(store.get("store_id") or "").strip() == normalized for store in list_vector_stores(db))


def _notification_channel_valid(db: Session, channel_id: str) -> bool:
    normalized = str(channel_id or "").strip()
    if not normalized:
        return False
    for channel in list_notification_channels(db):
        if str(channel.get("channel_id") or "").strip() != normalized:
            continue
        if not channel.get("enabled"):
            return False
        return bool(str(channel.get("credential_binding_id") or "").strip())
    return False


def _validate_trigger(trigger_type: str, trigger_config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    normalized = str(trigger_type or "manual").strip().lower()
    if normalized not in TRIGGER_TYPES:
        errors.append(f"trigger_type must be one of: {', '.join(sorted(TRIGGER_TYPES))}")
        return errors

    if normalized == "schedule":
        cron = str(trigger_config.get("cron_expression") or "").strip()
        if not cron:
            errors.append("schedule trigger requires cron_expression in trigger_config_json")
        elif not CRON_PATTERN.match(cron):
            errors.append("cron_expression must be a valid 5-field cron expression")

    if normalized == "webhook":
        path_ref = str(trigger_config.get("webhook_path_ref") or trigger_config.get("path_ref") or "").strip()
        if not path_ref:
            errors.append("webhook trigger requires webhook_path_ref in trigger_config_json")
        token_ref = trigger_config.get("token_binding_id")
        if token_ref is not None and str(token_ref).strip():
            errors.extend(_scan_inline_secrets({"token_binding_id": token_ref}, "trigger_config_json"))
        hmac_ref = trigger_config.get("hmac_secret_binding_id")
        if hmac_ref is not None and str(hmac_ref).strip():
            errors.extend(_scan_inline_secrets({"hmac_secret_binding_id": hmac_ref}, "trigger_config_json"))
            algo = str(trigger_config.get("hmac_algorithm") or "sha256").strip().lower()
            if algo and algo not in {"sha256", "sha1"}:
                errors.append("webhook hmac_algorithm must be sha256 or sha1")

    return errors


def _validate_node_config(db: Session, node_type: str, config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if node_type not in GRAPH_NODE_TYPES:
        errors.append(f"unsupported node type: {node_type}")
        return errors

    required = NODE_REQUIRED_FIELDS.get(node_type, set())
    for field in sorted(required):
        value = config.get(field)
        if value is None or str(value).strip() == "":
            errors.append(f"node type '{node_type}' requires config.{field}")

    errors.extend(_scan_inline_secrets(config, "config"))

    if node_type == "llm_chat":
        model_id = str(config.get("model_id") or "").strip()
        agent_key = str(config.get("agent_key") or "").strip()
        if not model_id and not agent_key:
            errors.append("llm_chat requires config.model_id or config.agent_key")
        max_retries_raw = config.get("max_retries")
        if max_retries_raw not in (None, ""):
            try:
                max_retries = int(max_retries_raw)
            except (TypeError, ValueError):
                errors.append("llm_chat max_retries must be an integer between 0 and 3")
            else:
                if max_retries < 0 or max_retries > 3:
                    errors.append("llm_chat max_retries must be an integer between 0 and 3")

    if node_type == "http_request":
        url_error = _validate_http_url(db, str(config.get("url") or ""))
        if url_error:
            errors.append(url_error)
        auth_type = str(config.get("auth_type") or "none").strip().lower()
        if auth_type and auth_type not in HTTP_AUTH_TYPES:
            errors.append(
                f"http_request auth_type must be one of: {', '.join(sorted(HTTP_AUTH_TYPES))}"
            )
        if auth_type not in {"", "none"}:
            binding_id = str(config.get("auth_binding_id") or "").strip()
            if not binding_id:
                errors.append("http_request requires config.auth_binding_id when auth_type is set")
            if auth_type == "api_key":
                header_name = str(config.get("auth_header_name") or "").strip()
                if not header_name:
                    errors.append("http_request api_key auth requires config.auth_header_name")
            headers_raw = config.get("headers_json")
            if headers_raw not in (None, "", {}):
                try:
                    headers = json.loads(headers_raw) if isinstance(headers_raw, str) else headers_raw
                except json.JSONDecodeError:
                    headers = None
                if isinstance(headers, dict):
                    for key in headers:
                        if INLINE_SECRET_FIELD_PATTERN.search(str(key)):
                            errors.append(
                                "http_request must not embed credentials in headers_json; use auth_binding_id"
                            )
                            break

    if node_type == "schedule_trigger":
        cron = str(config.get("cron_expression") or "").strip()
        if cron and not CRON_PATTERN.match(cron):
            errors.append("schedule_trigger cron_expression must be a valid 5-field cron expression")

    if node_type == "condition":
        json_path = str(config.get("json_path") or "").strip()
        if json_path and not JSON_PATH_PATTERN.match(json_path):
            errors.append("condition json_path must start with $ and use dot or bracket notation (e.g. $.status or $.items[0].id)")
        operator = str(config.get("operator") or "").strip()
        if operator and operator not in {"==", "!=", ">", "<", "contains", "exists"}:
            errors.append("condition operator must be one of: ==, !=, >, <, contains, exists")
        source_node_id = str(config.get("source_node_id") or "").strip()
        if json_path and not source_node_id:
            errors.append("condition requires config.source_node_id when json_path is set")

    if node_type in {"while_loop", "do_while"}:
        json_path = str(config.get("json_path") or "").strip()
        if json_path and not JSON_PATH_PATTERN.match(json_path):
            errors.append(f"{node_type} json_path must start with $ and use dot or bracket notation")
        operator = str(config.get("operator") or "").strip()
        if operator and operator not in {"==", "!=", ">", "<", "contains", "exists"}:
            errors.append(f"{node_type} operator must be one of: ==, !=, >, <, contains, exists")
        source_node_id = str(config.get("source_node_id") or "").strip()
        if json_path and not source_node_id:
            errors.append(f"{node_type} requires config.source_node_id when json_path is set")
        body_branch = str(config.get("body_branch") or "").strip()
        if not body_branch:
            errors.append(f"{node_type} requires config.body_branch (first step of the loop body)")
        exit_branch = str(config.get("exit_branch") or "").strip()
        if body_branch and exit_branch and body_branch == exit_branch:
            errors.append(f"{node_type} body_branch and exit_branch must be different nodes")
        if config.get("max_iterations") not in (None, ""):
            try:
                max_iterations = int(config.get("max_iterations"))
            except (TypeError, ValueError):
                errors.append(f"{node_type} max_iterations must be an integer")
            else:
                if max_iterations < 1 or max_iterations > MAX_WHILE_ITERATIONS:
                    errors.append(
                        f"{node_type} max_iterations must be between 1 and {MAX_WHILE_ITERATIONS}"
                    )
        if config.get("collect_results") not in (None, ""):
            flag = str(config.get("collect_results") or "").strip().lower()
            if flag not in {"0", "1", "true", "false", "yes", "no", "on", "off"}:
                errors.append(f"{node_type} collect_results must be a boolean-like value")
        if config.get("delay_between_iterations_ms") not in (None, ""):
            try:
                delay_ms = int(config.get("delay_between_iterations_ms"))
            except (TypeError, ValueError):
                errors.append(f"{node_type} delay_between_iterations_ms must be an integer")
            else:
                if delay_ms < 0 or delay_ms > MAX_WHILE_DELAY_MS:
                    errors.append(
                        f"{node_type} delay_between_iterations_ms must be between 0 and {MAX_WHILE_DELAY_MS}"
                    )

    if node_type == "switch":
        json_path = str(config.get("json_path") or "").strip()
        if json_path and not JSON_PATH_PATTERN.match(json_path):
            errors.append("switch json_path must start with $ and use dot or bracket notation")
        cases = _parse_cases_json(config.get("cases_json"))
        if not cases:
            # Still allow empty when JSON string is invalid — surface parse issues.
            raw = config.get("cases_json")
            if isinstance(raw, str) and raw.strip():
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    errors.append("switch cases_json must be valid JSON array")
                else:
                    if not isinstance(parsed, list) or not parsed:
                        errors.append("switch cases_json must be a non-empty JSON array of {value, branch}")
            else:
                errors.append("switch requires a non-empty cases_json array of {value, branch}")
        else:
            for index, case in enumerate(cases):
                if not str(case.get("branch") or "").strip():
                    errors.append(f"switch cases_json[{index}] requires branch")

    if node_type == "filter":
        items_path = str(config.get("items_path") or "").strip()
        if items_path and not JSON_PATH_PATTERN.match(items_path):
            errors.append("filter items_path must start with $ and use dot or bracket notation")
        item_path = str(config.get("item_json_path") or "").strip()
        if item_path and not JSON_PATH_PATTERN.match(item_path):
            errors.append("filter item_json_path must start with $ and use dot or bracket notation")
        operator = str(config.get("operator") or "").strip()
        if operator and operator not in {"==", "!=", ">", "<", "contains", "exists"}:
            errors.append("filter operator must be one of: ==, !=, >, <, contains, exists")

    if node_type == "merge_data":
        mode = str(config.get("merge_mode") or "shallow").strip().lower()
        if mode and mode not in {"shallow", "prefer_a", "prefer_b", "nest"}:
            errors.append("merge_data merge_mode must be one of: shallow, prefer_a, prefer_b, nest")

    if node_type in {
        "github_api",
        "gitlab_api",
        "bitbucket_api",
        "jira_api",
        "confluence_api",
        "linear_api",
        "notion_api",
        "hubspot_api",
        "zendesk_api",
        "freshdesk_api",
        "salesforce_api",
        "servicenow_api",
        "airtable_api",
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
        "trello_api",
    }:
        method = str(config.get("method") or "GET").strip().upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            errors.append(f"{node_type} method must be one of: GET, POST, PUT, PATCH, DELETE")
        path = str(config.get("path_template") or "").strip()
        if path and "://" in path:
            errors.append(f"{node_type} path_template must be a path (not a full URL)")
        auth_type = str(config.get("auth_type") or "bearer").strip().lower()
        if auth_type and auth_type not in HTTP_AUTH_TYPES:
            errors.append(f"{node_type} auth_type must be one of: {', '.join(sorted(HTTP_AUTH_TYPES))}")
        if node_type in {
            "jira_api",
            "confluence_api",
            "zendesk_api",
            "freshdesk_api",
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
            "pipedrive_api",
            "shopify_api",
            "salesforce_api",
            "servicenow_api",
        }:
            base_url = str(config.get("base_url") or "").strip()
            if base_url:
                normalized_base = base_url if "://" in base_url else f"https://{base_url}"
                host_error = _validate_http_url(db, normalized_base)
                if host_error:
                    errors.append(host_error)
            elif node_type in {
                "freshdesk_api",
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
                "pipedrive_api",
                "shopify_api",
            }:
                errors.append(f"{node_type} requires config.base_url")
        if node_type == "github_api":
            host_error = _validate_http_url(db, GITHUB_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "gitlab_api":
            host_error = _validate_http_url(db, GITLAB_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "bitbucket_api":
            host_error = _validate_http_url(db, BITBUCKET_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "stripe_api":
            host_error = _validate_http_url(db, STRIPE_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "box_api":
            host_error = _validate_http_url(db, BOX_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "dropbox_api":
            host_error = _validate_http_url(db, DROPBOX_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "calendly_api":
            host_error = _validate_http_url(db, CALENDLY_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "microsoft_graph_api":
            host_error = _validate_http_url(db, MICROSOFT_GRAPH_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "google_sheets_api":
            host_error = _validate_http_url(db, GOOGLE_SHEETS_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "google_drive_api":
            host_error = _validate_http_url(db, GOOGLE_DRIVE_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "google_calendar_api":
            host_error = _validate_http_url(db, GOOGLE_CALENDAR_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "slack_api":
            host_error = _validate_http_url(db, SLACK_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "zoom_api":
            host_error = _validate_http_url(db, ZOOM_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "twilio_api":
            host_error = _validate_http_url(db, TWILIO_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "sendgrid_api":
            host_error = _validate_http_url(db, SENDGRID_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "linear_api":
            host_error = _validate_http_url(db, LINEAR_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "notion_api":
            host_error = _validate_http_url(db, NOTION_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "hubspot_api":
            host_error = _validate_http_url(db, HUBSPOT_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "airtable_api":
            host_error = _validate_http_url(db, AIRTABLE_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "asana_api":
            host_error = _validate_http_url(db, ASANA_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "clickup_api":
            host_error = _validate_http_url(db, CLICKUP_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "intercom_api":
            host_error = _validate_http_url(db, INTERCOM_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "monday_api":
            host_error = _validate_http_url(db, MONDAY_API_BASE)
            if host_error:
                errors.append(host_error)
        if node_type == "trello_api":
            host_error = _validate_http_url(db, TRELLO_API_BASE)
            if host_error:
                errors.append(host_error)

    if node_type == "pagerduty_event":
        host_error = _validate_http_url(db, PAGERDUTY_EVENTS_API_BASE)
        if host_error:
            errors.append(host_error)
        severity = str(config.get("severity") or "").strip().lower()
        if severity and severity not in {"critical", "error", "warning", "info"}:
            errors.append("pagerduty_event severity must be critical, error, warning, or info")
        details_raw = config.get("custom_details_json")
        if details_raw not in (None, ""):
            try:
                details = json.loads(details_raw) if isinstance(details_raw, str) else details_raw
            except json.JSONDecodeError:
                errors.append("pagerduty_event custom_details_json must be valid JSON")
            else:
                if not isinstance(details, dict):
                    errors.append("pagerduty_event custom_details_json must be a JSON object")

    if node_type == "opsgenie_alert":
        host_error = _validate_http_url(db, OPSGENIE_API_BASE)
        if host_error:
            errors.append(host_error)
        priority = str(config.get("priority") or "").strip().upper()
        if priority and priority not in {"P1", "P2", "P3", "P4", "P5"}:
            errors.append("opsgenie_alert priority must be P1, P2, P3, P4, or P5")
        details_raw = config.get("custom_details_json")
        if details_raw not in (None, ""):
            try:
                details = json.loads(details_raw) if isinstance(details_raw, str) else details_raw
            except json.JSONDecodeError:
                errors.append("opsgenie_alert custom_details_json must be valid JSON")
            else:
                if not isinstance(details, dict):
                    errors.append("opsgenie_alert custom_details_json must be a JSON object")

    if node_type == "datadog_event":
        host_error = _validate_http_url(db, DATADOG_API_BASE)
        if host_error:
            errors.append(host_error)
        alert_type = str(config.get("alert_type") or "").strip().lower()
        if alert_type and alert_type not in DATADOG_ALERT_TYPES:
            errors.append(
                "datadog_event alert_type must be one of: " + ", ".join(sorted(DATADOG_ALERT_TYPES))
            )

    if node_type == "sentry_event":
        host_error = _validate_http_url(db, SENTRY_API_BASE)
        if host_error:
            errors.append(host_error)
        level = str(config.get("level") or "").strip().lower()
        if level and level not in SENTRY_LEVELS:
            errors.append("sentry_event level must be one of: " + ", ".join(sorted(SENTRY_LEVELS)))
        org = str(config.get("organization_slug") or "").strip()
        project = str(config.get("project_slug") or "").strip()
        if org and ("/" in org or "://" in org):
            errors.append("sentry_event organization_slug must be a slug (not a path/URL)")
        if project and ("/" in project or "://" in project):
            errors.append("sentry_event project_slug must be a slug (not a path/URL)")

    if node_type == "mattermost_webhook":
        webhook_url = str(config.get("webhook_url") or "").strip()
        if webhook_url and "{{" not in webhook_url:
            host_error = _validate_http_url(db, webhook_url)
            if host_error:
                errors.append(host_error)

    if node_type == "google_chat_webhook":
        webhook_url = str(config.get("webhook_url") or "").strip()
        if webhook_url and "{{" not in webhook_url:
            host_error = _validate_http_url(db, webhook_url)
            if host_error:
                errors.append(host_error)

    if node_type == "statuspage_incident":
        host_error = _validate_http_url(db, STATUSPAGE_API_BASE)
        if host_error:
            errors.append(host_error)
        status = str(config.get("status") or "").strip().lower()
        if status and status not in STATUSPAGE_STATUSES:
            errors.append(
                "statuspage_incident status must be one of: " + ", ".join(sorted(STATUSPAGE_STATUSES))
            )
        impact = str(config.get("impact") or "").strip().lower()
        if impact and impact not in STATUSPAGE_IMPACTS:
            errors.append(
                "statuspage_incident impact must be one of: " + ", ".join(sorted(STATUSPAGE_IMPACTS))
            )
        page_id = str(config.get("page_id") or "").strip()
        if page_id and ("/" in page_id or "://" in page_id):
            errors.append("statuspage_incident page_id must be an id (not a path/URL)")

    if node_type == "telegram_notify":
        host_error = _validate_http_url(db, TELEGRAM_API_BASE)
        if host_error:
            errors.append(host_error)

    if node_type == "graphql_request":
        url = str(config.get("url") or "").strip()
        if url and "{{" not in url:
            host_error = _validate_http_url(db, url)
            if host_error:
                errors.append(host_error)
        auth_type = str(config.get("auth_type") or "bearer").strip().lower()
        if auth_type and auth_type not in HTTP_AUTH_TYPES:
            errors.append(f"graphql_request auth_type must be one of: {', '.join(sorted(HTTP_AUTH_TYPES))}")
        variables_raw = config.get("variables_json")
        if variables_raw not in (None, ""):
            try:
                variables = json.loads(variables_raw) if isinstance(variables_raw, str) else variables_raw
            except json.JSONDecodeError:
                errors.append("graphql_request variables_json must be valid JSON")
            else:
                if not isinstance(variables, dict):
                    errors.append("graphql_request variables_json must be a JSON object")

    if node_type == "limit":
        items_path = str(config.get("items_path") or "").strip()
        if items_path and not JSON_PATH_PATTERN.match(items_path):
            errors.append("limit items_path must start with $ and use dot or bracket notation")
        try:
            limit_n = int(config.get("limit") or 10)
        except (TypeError, ValueError):
            errors.append("limit must be an integer")
        else:
            if limit_n < 1 or limit_n > MAX_LIMIT_ITEMS:
                errors.append(f"limit must be between 1 and {MAX_LIMIT_ITEMS}")

    if node_type == "aggregate":
        items_path = str(config.get("items_path") or "").strip()
        if items_path and not JSON_PATH_PATTERN.match(items_path):
            errors.append("aggregate items_path must start with $ and use dot or bracket notation")
        mode = str(config.get("aggregate_mode") or "").strip().lower()
        if mode and mode not in AGGREGATE_MODES:
            errors.append(f"aggregate_mode must be one of: {', '.join(sorted(AGGREGATE_MODES))}")

    if node_type == "foreach_map":
        items_path = str(config.get("items_path") or "").strip()
        if items_path and not JSON_PATH_PATTERN.match(items_path):
            errors.append("foreach_map items_path must start with $ and use dot or bracket notation")
        mapping_raw = config.get("mapping_json")
        if mapping_raw not in (None, ""):
            try:
                mapping = json.loads(mapping_raw) if isinstance(mapping_raw, str) else mapping_raw
            except json.JSONDecodeError:
                errors.append("foreach_map mapping_json must be valid JSON")
            else:
                if not isinstance(mapping, dict):
                    errors.append("foreach_map mapping_json must be a JSON object")

    if node_type in {"sort", "dedupe"}:
        items_path = str(config.get("items_path") or "").strip()
        if items_path and not JSON_PATH_PATTERN.match(items_path):
            errors.append(f"{node_type} items_path must start with $ and use dot or bracket notation")
        if node_type == "sort":
            order = str(config.get("order") or "asc").strip().lower()
            if order and order not in SORT_ORDERS:
                errors.append("sort order must be asc or desc")
            sort_key = str(config.get("sort_key_path") or "").strip()
            if sort_key and not JSON_PATH_PATTERN.match(sort_key):
                errors.append("sort sort_key_path must start with $ and use dot or bracket notation")

    if node_type == "json_parse":
        json_path = str(config.get("json_path") or "").strip()
        if json_path and not JSON_PATH_PATTERN.match(json_path):
            errors.append("json_parse json_path must start with $ and use dot or bracket notation")

    if node_type == "date_time":
        operation = str(config.get("operation") or "").strip().lower()
        if operation and operation not in DATE_TIME_OPS:
            errors.append(f"date_time operation must be one of: {', '.join(sorted(DATE_TIME_OPS))}")
        unit = str(config.get("unit") or "").strip().lower()
        if unit and unit not in {"seconds", "second", "minutes", "minute", "hours", "hour", "days", "day", "weeks", "week"}:
            errors.append("date_time unit must be seconds, minutes, hours, days, or weeks")

    if node_type == "execute_subflow":
        target = str(config.get("target_flow_id") or "").strip()
        if target and ("{{" in target or "}}" in target):
            pass  # templates resolved at runtime
        elif target and len(target) > 128:
            errors.append("execute_subflow target_flow_id is too long")

    if node_type == "string_ops":
        operation = str(config.get("operation") or "").strip().lower()
        if operation and operation not in STRING_OPS:
            errors.append(f"string_ops operation must be one of: {', '.join(sorted(STRING_OPS))}")

    if node_type == "compare":
        operator = str(config.get("operator") or "").strip()
        if operator and operator not in COMPARE_OPS:
            errors.append(f"compare operator must be one of: {', '.join(sorted(COMPARE_OPS))}")
        for field in ("json_path_a", "json_path_b"):
            path = str(config.get(field) or "").strip()
            if path and not JSON_PATH_PATTERN.match(path):
                errors.append(f"compare {field} must start with $ and use dot or bracket notation")

    if node_type == "csv_parse":
        delimiter = str(config.get("delimiter") or ",")
        if delimiter and len(delimiter) > 1:
            errors.append("csv_parse delimiter must be a single character")

    if node_type == "static_data":
        fields_raw = config.get("fields_json")
        if fields_raw not in (None, ""):
            try:
                fields = json.loads(fields_raw) if isinstance(fields_raw, str) else fields_raw
            except json.JSONDecodeError:
                errors.append("static_data fields_json must be valid JSON")
            else:
                if not isinstance(fields, dict):
                    errors.append("static_data fields_json must be a JSON object")

    if node_type == "math_ops":
        operation = str(config.get("operation") or "").strip().lower()
        if operation and operation not in MATH_OPS:
            errors.append(f"math_ops operation must be one of: {', '.join(sorted(MATH_OPS))}")
        precision = config.get("precision")
        if precision not in (None, ""):
            try:
                p = int(precision)
            except (TypeError, ValueError):
                errors.append("math_ops precision must be an integer")
            else:
                if p < 0 or p > 10:
                    errors.append("math_ops precision must be between 0 and 10")

    if node_type == "wait_until":
        until = str(config.get("until_template") or "").strip()
        if until and "{{" not in until:
            probe = evaluate_wait_until({"until_template": until}, {})
            if probe.get("error"):
                errors.append(str(probe["error"]))

    if node_type == "uuid_gen":
        count = config.get("count")
        if count not in (None, ""):
            try:
                n = int(count)
            except (TypeError, ValueError):
                errors.append("uuid_gen count must be an integer")
            else:
                if n < 1 or n > MAX_UUID_COUNT:
                    errors.append(f"uuid_gen count must be between 1 and {MAX_UUID_COUNT}")

    if node_type == "hash_digest":
        algorithm = str(config.get("algorithm") or "").strip().lower()
        if algorithm and algorithm not in HASH_ALGORITHMS:
            errors.append(f"hash_digest algorithm must be one of: {', '.join(sorted(HASH_ALGORITHMS))}")

    if node_type == "json_to_csv":
        items_path = str(config.get("items_path") or "").strip()
        if items_path and not JSON_PATH_PATTERN.match(items_path):
            errors.append("json_to_csv items_path must start with $ and use dot or bracket notation")
        delimiter = str(config.get("delimiter") or ",")
        if delimiter and len(delimiter) > 1:
            errors.append("json_to_csv delimiter must be a single character")

    if node_type == "split_out":
        items_path = str(config.get("items_path") or "").strip()
        if items_path and not JSON_PATH_PATTERN.match(items_path):
            errors.append("split_out items_path must start with $ and use dot or bracket notation")

    if node_type == "pick_fields":
        path = str(config.get("json_path") or "").strip()
        if path and not JSON_PATH_PATTERN.match(path):
            errors.append("pick_fields json_path must start with $ and use dot or bracket notation")
        fields = _parse_field_list(config.get("fields"))
        if config.get("fields") not in (None, "") and not fields:
            errors.append("pick_fields fields must list at least one key")
        if len(fields) > MAX_PICK_FIELDS:
            errors.append(f"pick_fields supports at most {MAX_PICK_FIELDS} keys")

    if node_type == "rename_keys":
        path = str(config.get("json_path") or "").strip()
        if path and not JSON_PATH_PATTERN.match(path):
            errors.append("rename_keys json_path must start with $ and use dot or bracket notation")
        mapping_raw = config.get("mapping_json")
        if mapping_raw not in (None, ""):
            try:
                mapping = json.loads(mapping_raw) if isinstance(mapping_raw, str) else mapping_raw
            except json.JSONDecodeError:
                errors.append("rename_keys mapping_json must be valid JSON")
            else:
                if not isinstance(mapping, dict):
                    errors.append("rename_keys mapping_json must be a JSON object")
                elif len(mapping) > MAX_RENAME_KEYS:
                    errors.append(f"rename_keys supports at most {MAX_RENAME_KEYS} renames")

    if node_type == "boolean_logic":
        combine = str(config.get("combine") or "").strip().lower()
        if combine and combine not in BOOLEAN_COMBINE:
            errors.append("boolean_logic combine must be and or or")
        raw = config.get("rules_json")
        if raw not in (None, ""):
            try:
                rules = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                errors.append("boolean_logic rules_json must be valid JSON array")
            else:
                if not isinstance(rules, list):
                    errors.append("boolean_logic rules_json must be a JSON array")
                elif len(rules) > MAX_BOOLEAN_RULES:
                    errors.append(f"boolean_logic supports at most {MAX_BOOLEAN_RULES} rules")
                else:
                    for index, rule in enumerate(rules):
                        if not isinstance(rule, dict):
                            errors.append(f"boolean_logic rules_json[{index}] must be an object")
                            continue
                        op = str(rule.get("operator") or "").strip()
                        if op and op not in COMPARE_OPS and op not in {"==", "!=", ">", "<", "contains", "exists"}:
                            errors.append(f"boolean_logic rules_json[{index}] has invalid operator")

    if node_type == "url_ops":
        operation = str(config.get("operation") or "").strip().lower()
        if operation and operation not in URL_OPS:
            errors.append(f"url_ops operation must be one of: {', '.join(sorted(URL_OPS))}")

    if node_type == "base64_ops":
        operation = str(config.get("operation") or "").strip().lower()
        if operation and operation not in BASE64_OPS:
            errors.append(f"base64_ops operation must be one of: {', '.join(sorted(BASE64_OPS))}")

    if node_type == "coalesce":
        raw = config.get("candidates_json")
        if raw not in (None, ""):
            try:
                candidates = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                errors.append("coalesce candidates_json must be valid JSON array")
            else:
                if not isinstance(candidates, list):
                    errors.append("coalesce candidates_json must be a JSON array")
                elif len(candidates) > MAX_COALESCE_CANDIDATES:
                    errors.append(f"coalesce supports at most {MAX_COALESCE_CANDIDATES} candidates")

    if node_type == "omit_fields":
        path = str(config.get("json_path") or "").strip()
        if path and not JSON_PATH_PATTERN.match(path):
            errors.append("omit_fields json_path must start with $ and use dot or bracket notation")
        fields = _parse_field_list(config.get("fields"))
        if config.get("fields") not in (None, "") and not fields:
            errors.append("omit_fields fields must list at least one key")

    if node_type == "append_items":
        for field in ("items_path_a", "items_path_b", "items_path"):
            path = str(config.get(field) or "").strip()
            if path and not JSON_PATH_PATTERN.match(path):
                errors.append(f"append_items {field} must start with $ and use dot or bracket notation")

    if node_type == "number_format":
        style = str(config.get("style") or "").strip().lower()
        if style and style not in NUMBER_FORMAT_STYLES:
            errors.append(f"number_format style must be one of: {', '.join(sorted(NUMBER_FORMAT_STYLES))}")

    if node_type == "regex_extract":
        pattern = str(config.get("pattern") or "")
        if pattern and len(pattern) > MAX_REGEX_PATTERN_LEN:
            errors.append(f"regex_extract pattern must be <= {MAX_REGEX_PATTERN_LEN} characters")
        if pattern and _UNSAFE_REGEX_PATTERN.search(pattern):
            errors.append("regex_extract pattern uses disallowed constructs")
        if pattern:
            try:
                re.compile(pattern)
            except re.error:
                errors.append("regex_extract pattern is not a valid regular expression")

    if node_type == "timezone_convert":
        for field in ("to_timezone", "from_timezone"):
            name = str(config.get(field) or "").strip()
            if not name:
                continue
            try:
                ZoneInfo(name)
            except ZoneInfoNotFoundError:
                errors.append(f"timezone_convert {field} must be a valid IANA timezone")

    if node_type == "item_exists":
        path = str(config.get("json_path") or "").strip()
        if path and not JSON_PATH_PATTERN.match(path):
            errors.append("item_exists json_path must start with $ and use dot or bracket notation")

    if node_type == "flatten_json":
        path = str(config.get("json_path") or "").strip()
        if path and not JSON_PATH_PATTERN.match(path):
            errors.append("flatten_json json_path must start with $ and use dot or bracket notation")

    if node_type in {
        "xml_parse",
        "unflatten_json",
        "json_stringify",
        "type_of",
        "chunk_text",
        "form_urlencoded",
        "deep_merge",
        "jwt_decode",
        "html_extract",
        "split_text",
        "json_query",
        "compress",
        "random",
        "xml_stringify",
        "object_diff",
        "html_to_markdown",
        "markdown_to_html",
        "array_ops",
        "compact_object",
    }:
        path = str(config.get("json_path") or "").strip()
        if path and not JSON_PATH_PATTERN.match(path):
            errors.append(f"{node_type} json_path must start with $ and use dot or bracket notation")

    if node_type == "deep_merge":
        merge_path = str(config.get("merge_json_path") or "").strip()
        if merge_path and not JSON_PATH_PATTERN.match(merge_path):
            errors.append("deep_merge merge_json_path must start with $ and use dot or bracket notation")

    if node_type == "object_diff":
        compare_path = str(config.get("compare_json_path") or "").strip()
        if compare_path and not JSON_PATH_PATTERN.match(compare_path):
            errors.append("object_diff compare_json_path must start with $ and use dot or bracket notation")

    if node_type == "hmac_verify":
        algorithm = str(config.get("algorithm") or "").strip().lower()
        if algorithm and algorithm not in HMAC_VERIFY_ALGOS:
            errors.append(f"hmac_verify algorithm must be one of: {', '.join(sorted(HMAC_VERIFY_ALGOS))}")
        encoding = str(config.get("encoding") or "").strip().lower()
        if encoding and encoding not in {"hex", "base64"}:
            errors.append("hmac_verify encoding must be hex or base64")

    if node_type == "array_ops":
        operation = str(config.get("operation") or "").strip().lower()
        if operation and operation not in ARRAY_OPS:
            errors.append(f"array_ops operation must be one of: {', '.join(sorted(ARRAY_OPS))}")
        merge_path = str(config.get("merge_json_path") or "").strip()
        if merge_path and not JSON_PATH_PATTERN.match(merge_path):
            errors.append("array_ops merge_json_path must start with $ and use dot or bracket notation")

    if node_type == "html_extract":
        mode = str(config.get("mode") or "").strip().lower()
        if mode and mode not in HTML_EXTRACT_MODES:
            errors.append(f"html_extract mode must be one of: {', '.join(sorted(HTML_EXTRACT_MODES))}")

    if node_type == "split_text":
        raw_max = config.get("max_parts")
        if raw_max not in (None, ""):
            try:
                int(raw_max)
            except (TypeError, ValueError):
                errors.append("split_text max_parts must be an integer")

    if node_type == "compress":
        operation = str(config.get("operation") or "").strip().lower()
        if operation and operation not in COMPRESS_OPS:
            errors.append(f"compress operation must be one of: {', '.join(sorted(COMPRESS_OPS))}")
        algorithm = str(config.get("algorithm") or "").strip().lower()
        if algorithm and algorithm not in COMPRESS_ALGOS:
            errors.append(f"compress algorithm must be one of: {', '.join(sorted(COMPRESS_ALGOS))}")

    if node_type == "random":
        mode = str(config.get("mode") or "").strip().lower()
        if mode and mode not in RANDOM_MODES:
            errors.append(f"random mode must be one of: {', '.join(sorted(RANDOM_MODES))}")

    if node_type == "chunk_text":
        for field_name in ("chunk_size", "overlap"):
            raw_val = config.get(field_name)
            if raw_val in (None, ""):
                continue
            try:
                int(raw_val)
            except (TypeError, ValueError):
                errors.append(f"chunk_text {field_name} must be an integer")

    if node_type == "form_urlencoded":
        operation = str(config.get("operation") or "").strip().lower()
        if operation and operation not in FORM_URLENCODED_OPS:
            errors.append(f"form_urlencoded operation must be one of: {', '.join(sorted(FORM_URLENCODED_OPS))}")

    if node_type == "respond_to_webhook":
        status_raw = config.get("status_code")
        if status_raw not in (None, ""):
            try:
                status_code = int(status_raw)
            except (TypeError, ValueError):
                errors.append("respond_to_webhook status_code must be an integer")
            else:
                if status_code < 100 or status_code > 599:
                    errors.append("respond_to_webhook status_code must be between 100 and 599")

    if node_type == "split_in_batches":
        items_path = str(config.get("items_path") or "").strip()
        if items_path and not JSON_PATH_PATTERN.match(items_path):
            errors.append("split_in_batches items_path must start with $ and use dot or bracket notation")
        try:
            batch_size = int(config.get("batch_size") or 10)
        except (TypeError, ValueError):
            errors.append("split_in_batches batch_size must be an integer")
        else:
            if batch_size < 1 or batch_size > MAX_SPLIT_BATCH_SIZE:
                errors.append(f"split_in_batches batch_size must be between 1 and {MAX_SPLIT_BATCH_SIZE}")

    if node_type == "parallel_fork":
        group_id = str(config.get("group_id") or "").strip()
        if not group_id:
            errors.append("parallel_fork requires config.group_id")
        branch_count = config.get("branch_count")
        if branch_count is not None:
            try:
                count = int(branch_count)
            except (TypeError, ValueError):
                errors.append("parallel_fork branch_count must be an integer")
            else:
                if count < MIN_PARALLEL_BRANCHES or count > MAX_PARALLEL_BRANCHES:
                    errors.append(
                        f"parallel_fork branch_count must be between {MIN_PARALLEL_BRANCHES} and {MAX_PARALLEL_BRANCHES}"
                    )

    if node_type == "parallel_join":
        group_id = str(config.get("group_id") or "").strip()
        fork_node_id = str(config.get("fork_node_id") or "").strip()
        if not group_id:
            errors.append("parallel_join requires config.group_id")
        if not fork_node_id:
            errors.append("parallel_join requires config.fork_node_id")

    if node_type == "llm_chat":
        route_id = config.get("route_id")
        if route_id is not None and not str(route_id).strip():
            errors.append("llm_chat route_id must be a non-empty string when set")
        prompt_registry_id = config.get("prompt_registry_id")
        if prompt_registry_id is not None and not str(prompt_registry_id).strip():
            errors.append("llm_chat prompt_registry_id must be a non-empty string when set")
        max_tokens = config.get("max_tokens")
        if max_tokens is not None and str(max_tokens).strip():
            try:
                parsed = int(max_tokens)
            except (TypeError, ValueError):
                errors.append("llm_chat max_tokens must be an integer")
            else:
                if parsed < 1:
                    errors.append("llm_chat max_tokens must be at least 1")
        response_format = str(config.get("response_format") or "").strip().lower()
        if response_format and response_format not in LLM_CHAT_RESPONSE_FORMATS:
            errors.append(
                f"llm_chat response_format must be one of: {', '.join(sorted(LLM_CHAT_RESPONSE_FORMATS))}"
            )
        cache_mode = str(config.get("cache_mode") or "inherit").strip().lower()
        if cache_mode and cache_mode not in LLM_CHAT_CACHE_MODES:
            errors.append(
                f"llm_chat cache_mode must be one of: {', '.join(sorted(LLM_CHAT_CACHE_MODES))}"
            )

    if node_type in {"vector_query", "vector_ingest", "rag_query"}:
        store_id = str(config.get("store_id") or "").strip()
        if store_id and not _vector_store_exists(db, store_id):
            errors.append(
                f"{node_type} store_id '{store_id}' is not in gateway.vector_stores_json — configure in Routing & Gateway"
            )
        if node_type in {"vector_query", "rag_query"}:
            top_k = config.get("top_k")
            if top_k is not None and str(top_k).strip():
                try:
                    parsed = int(top_k)
                except (TypeError, ValueError):
                    errors.append(f"{node_type} top_k must be an integer")
                else:
                    if parsed < 1 or parsed > 100:
                        errors.append(f"{node_type} top_k must be between 1 and 100")

    if node_type == "wait_delay":
        delay_seconds = config.get("delay_seconds")
        if delay_seconds is not None and str(delay_seconds).strip():
            try:
                parsed = int(delay_seconds)
            except (TypeError, ValueError):
                errors.append("wait_delay delay_seconds must be an integer")
            else:
                if parsed < 1 or parsed > 3600:
                    errors.append("wait_delay delay_seconds must be between 1 and 3600")

    if node_type in {"email_send", "sms_send"}:
        channel_id = str(config.get("channel_id") or "").strip()
        if channel_id and not _notification_channel_valid(db, channel_id):
            errors.append(
                f"{node_type} channel_id '{channel_id}' is not an enabled entry in "
                "gateway.notification_channels_json with credential_binding_id — configure in Routing & Gateway"
            )
        to_template = str(config.get("to_template") or "")
        to_error = validate_recipient_template(to_template, field_name="to_template")
        if to_error:
            errors.append(to_error)
        body_template = str(config.get("body_template") or "")
        body_error = validate_recipient_template(body_template, field_name="body_template")
        if body_error:
            errors.append(body_error)
        if node_type == "email_send":
            subject_template = str(config.get("subject_template") or "")
            subject_error = validate_recipient_template(subject_template, field_name="subject_template")
            if subject_error:
                errors.append(subject_error)

    return errors


def _build_graph_indexes(
    nodes: list[Any], edges: list[Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]], dict[str, list[str]]]:
    nodes_by_id: dict[str, dict[str, Any]] = {}
    outgoing: dict[str, list[str]] = defaultdict(list)
    incoming: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        if isinstance(node, dict):
            node_id = str(node.get("id") or "").strip()
            if node_id:
                nodes_by_id[node_id] = node
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        if source and target:
            outgoing[source].append(target)
            incoming[target].append(source)
    return nodes_by_id, outgoing, incoming


def _validate_parallel_topology(
    nodes: list[Any], edges: list[Any], node_ids: set[str]
) -> list[str]:
    errors: list[str] = []
    nodes_by_id, outgoing, incoming = _build_graph_indexes(nodes, edges)

    fork_nodes = [
        node for node in nodes if isinstance(node, dict) and str(node.get("type") or "") == "parallel_fork"
    ]
    join_nodes = [
        node for node in nodes if isinstance(node, dict) and str(node.get("type") or "") == "parallel_join"
    ]

    join_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for join in join_nodes:
        config = join.get("config") if isinstance(join.get("config"), dict) else {}
        group_id = str(config.get("group_id") or "").strip()
        if group_id:
            join_by_group[group_id].append(join)

    for fork in fork_nodes:
        fork_id = str(fork.get("id") or "").strip()
        config = fork.get("config") if isinstance(fork.get("config"), dict) else {}
        group_id = str(config.get("group_id") or "").strip()
        if not group_id:
            continue

        matching_joins = join_by_group.get(group_id, [])
        if not matching_joins:
            errors.append(f"parallel_fork '{fork_id}' requires a matching parallel_join with group_id '{group_id}'")
            continue
        if len(matching_joins) > 1:
            errors.append(f"parallel_fork '{fork_id}' has multiple parallel_join nodes for group_id '{group_id}'")
            continue

        join = matching_joins[0]
        join_id = str(join.get("id") or "").strip()
        join_config = join.get("config") if isinstance(join.get("config"), dict) else {}
        fork_ref = str(join_config.get("fork_node_id") or "").strip()
        if fork_ref and fork_ref != fork_id:
            errors.append(
                f"parallel_join '{join_id}' fork_node_id must reference parallel_fork '{fork_id}'"
            )

        branch_heads = [target for target in outgoing.get(fork_id, []) if target != join_id]
        if len(branch_heads) < MIN_PARALLEL_BRANCHES:
            errors.append(
                f"parallel_fork '{fork_id}' must fan out to at least {MIN_PARALLEL_BRANCHES} branches"
            )
        if len(branch_heads) > MAX_PARALLEL_BRANCHES:
            errors.append(
                f"parallel_fork '{fork_id}' exceeds max parallel branches ({MAX_PARALLEL_BRANCHES})"
            )

        configured_branch_count = config.get("branch_count")
        if configured_branch_count is not None:
            try:
                expected = int(configured_branch_count)
            except (TypeError, ValueError):
                pass
            else:
                if expected != len(branch_heads):
                    errors.append(
                        f"parallel_fork '{fork_id}' branch_count ({expected}) does not match "
                        f"actual outgoing branches ({len(branch_heads)})"
                    )

        for branch_head in branch_heads:
            branch_nodes = _collect_branch_node_ids(branch_head, join_id, outgoing)
            if not branch_nodes and branch_head != join_id:
                errors.append(
                    f"parallel_fork '{fork_id}' branch starting at '{branch_head}' is empty — add at least one step"
                )

        for branch_head in branch_heads:
            if branch_head not in node_ids:
                errors.append(f"parallel_fork '{fork_id}' branch references unknown node '{branch_head}'")
            elif branch_head == join_id:
                errors.append(f"parallel_fork '{fork_id}' cannot connect directly to its parallel_join")

        # Each branch head must have a path to the join node.
        for branch_head in branch_heads:
            visited: set[str] = set()
            queue = [branch_head]
            reached_join = False
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                if current == join_id:
                    reached_join = True
                    break
                if current == fork_id:
                    errors.append(f"parallel branch from '{fork_id}' contains a cycle through '{current}'")
                    break
                for successor in outgoing.get(current, []):
                    if successor not in visited:
                        queue.append(successor)
            if not reached_join:
                errors.append(
                    f"parallel branch starting at '{branch_head}' from fork '{fork_id}' must reach join '{join_id}'"
                )

        # Join should only be reached from branch tails (no stray incoming from outside the group).
        for source in incoming.get(join_id, []):
            if source == fork_id:
                errors.append(f"parallel_join '{join_id}' must not connect directly from its fork")

    orphan_joins = [
        join
        for join in join_nodes
        if str((join.get("config") or {}).get("group_id") or "").strip()
        not in {
            str((fork.get("config") or {}).get("group_id") or "").strip()
            for fork in fork_nodes
            if isinstance(fork.get("config"), dict)
        }
    ]
    for join in orphan_joins:
        join_id = str(join.get("id") or "").strip()
        group_id = str((join.get("config") or {}).get("group_id") or "").strip()
        if group_id:
            errors.append(f"parallel_join '{join_id}' has no matching parallel_fork for group_id '{group_id}'")

    return errors


def _validate_graph_cycles(
    nodes: list[Any], edges: list[Any], node_ids: set[str]
) -> list[str]:
    """Detect cycles in the overall DAG (parallel fork→join segments are acyclic by branch rules)."""
    if not node_ids:
        return []
    _, outgoing, incoming = _build_graph_indexes(nodes, edges)
    in_degree = {node_id: len(incoming.get(node_id, [])) for node_id in node_ids}
    queue = [node_id for node_id, degree in in_degree.items() if degree == 0]
    visited = 0
    while queue:
        current = queue.pop(0)
        visited += 1
        for successor in outgoing.get(current, []):
            if successor not in in_degree:
                continue
            in_degree[successor] -= 1
            if in_degree[successor] == 0:
                queue.append(successor)
    if visited == len(node_ids):
        return []
    cyclic = sorted(node_id for node_id, degree in in_degree.items() if degree > 0)
    if not cyclic:
        return ["graph contains a cycle — remove circular edges between steps"]
    preview = ", ".join(cyclic[:5])
    suffix = "…" if len(cyclic) > 5 else ""
    return [f"graph contains a cycle involving node(s): {preview}{suffix}"]


def validate_flow_definition(
    db: Session,
    *,
    trigger_type: str,
    trigger_config_json: str,
    graph_json: str,
    environment: str,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    env = str(environment or "dev").strip().lower()
    if env not in FLOW_ENVIRONMENTS:
        errors.append(f"environment must be one of: {', '.join(sorted(FLOW_ENVIRONMENTS))}")

    trigger_config = _parse_json_object(trigger_config_json, field_name="trigger_config_json")
    errors.extend(_validate_trigger(trigger_type, trigger_config))

    graph = _parse_graph(graph_json)
    nodes = graph["nodes"]
    edges = graph["edges"]

    max_nodes = get_runtime_config_int(db, RUNTIME_CONFIG_ORCHESTRATION_MAX_NODES_PER_FLOW, 50)
    if len(nodes) > max_nodes:
        errors.append(f"graph exceeds orchestration.max_nodes_per_flow ({max_nodes})")

    node_ids: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            errors.append(f"nodes[{index}] must be an object")
            continue
        node_id = str(node.get("id") or "").strip()
        node_type = str(node.get("type") or "").strip()
        if not node_id:
            errors.append(f"nodes[{index}] requires id")
        elif node_id in node_ids:
            errors.append(f"duplicate node id: {node_id}")
        else:
            node_ids.add(node_id)
        config = node.get("config") if isinstance(node.get("config"), dict) else {}
        errors.extend(_scan_inline_secrets(node, f"nodes[{index}]"))
        errors.extend(_validate_node_config(db, node_type, config))
        if node_type in {"while_loop", "do_while"} and not _while_condition_is_configured(config):
            warnings.append(
                f"{node_id or f'nodes[{index}]'}: {node_type} has no usable condition — "
                "loop will run until max_iterations (use This loop · $.index or a prior-step flag)"
            )

    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{index}] must be an object")
            continue
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        if not source or not target:
            errors.append(f"edges[{index}] requires source and target")
        elif node_ids and (source not in node_ids or target not in node_ids):
            errors.append(f"edges[{index}] references unknown node id")

    errors.extend(_validate_parallel_topology(nodes, edges, node_ids))
    errors.extend(_validate_graph_cycles(nodes, edges, node_ids))

    if env == "prod" and not nodes:
        warnings.append("prod flows should include at least one node before promotion")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "max_nodes_per_flow": max_nodes,
        "http_allowlist_configured": bool(_load_http_allowlist(db)),
    }


def prod_run_requires_approval(db: Session) -> bool:
    raw = get_runtime_config(db, RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_APPROVAL, "true").strip().lower()
    return raw not in {"0", "false", "no"}


def flow_has_human_approval_nodes(graph_json: str) -> bool:
    try:
        graph = _parse_graph(graph_json)
    except Exception:
        return False
    return any(
        isinstance(node, dict) and str(node.get("type") or "") == "human_approval"
        for node in graph.get("nodes", [])
    )


def serialize_flow(row: Any) -> dict[str, Any]:
    return {
        "flow_id": row.flow_id,
        "flow_name": row.flow_name,
        "description": row.description,
        "status": row.status,
        "environment": row.environment,
        "tenant_id": row.tenant_id,
        "trigger_type": row.trigger_type,
        "trigger_config_json": row.trigger_config_json,
        "graph_json": row.graph_json,
        "access_policy_json": getattr(row, "access_policy_json", None) or "{}",
        "approval_stage_state_json": getattr(row, "approval_stage_state_json", None) or "{}",
        "approval_status": row.approval_status,
        "metadata_version": row.metadata_version,
        "created_by": row.created_by,
        "updated_by": row.updated_by,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def serialize_run(row: Any, *, flow_name: Optional[str] = None) -> dict[str, Any]:
    payload = {
        "run_id": row.run_id,
        "flow_id": row.flow_id,
        "status": row.status,
        "started_at": row.started_at,
        "finished_at": row.finished_at,
        "trace_id": row.trace_id,
        "step_results_json": row.step_results_json,
        "error_summary": row.error_summary,
        "execution_state_json": getattr(row, "execution_state_json", None),
    }
    if flow_name is not None:
        payload["flow_name"] = flow_name
    try:
        steps = json.loads(row.step_results_json or "[]")
    except json.JSONDecodeError:
        steps = []
    if isinstance(steps, list):
        webhook_response = extract_webhook_response(steps)
        if webhook_response is not None:
            payload["webhook_response"] = webhook_response
    return payload


def _stub_node_output(node_type: str, config: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    if node_type == "llm_chat":
        stub_message = "Stub LLM response for orchestration Phase 1"
        return {
            "simulated": True,
            "model_id": config.get("model_id"),
            "route_id": config.get("route_id"),
            "prompt_registry_id": config.get("prompt_registry_id"),
            "max_tokens": config.get("max_tokens"),
            "response_format": config.get("response_format") or "text",
            "cache_mode": config.get("cache_mode") or "inherit",
            "message": stub_message,
            "content": stub_message,
            "choices": [
                {
                    "message": {"role": "assistant", "content": stub_message},
                    "finish_reason": "stop",
                }
            ],
        }
    if node_type == "mcp_tool":
        return {
            "simulated": True,
            "server_id": config.get("server_id"),
            "tool_name": config.get("tool_name"),
        }
    if node_type == "http_request":
        return {
            "simulated": True,
            "url": config.get("url"),
            "method": config.get("method"),
            "status_code": 200,
            "status": 200,
            "data": {"approved": True, "email": "stub@example.com"},
            "body_preview": '{"approved":true}',
            "dry_run": dry_run,
        }
    if node_type == "condition":
        return {"simulated": True, "expression": config.get("expression"), "matched": True}
    if node_type in {"while_loop", "do_while"}:
        return {
            "simulated": True,
            "mode": node_type,
            "matched": True,
            "iterations": 1,
            "index": 0,
            "iteration": 1,
            "max_iterations": clamp_while_max_iterations(config.get("max_iterations")),
            "capped": False,
            "exit_reason": "simulated",
            "body_branch": config.get("body_branch"),
            "exit_branch": config.get("exit_branch"),
            "collect_results": _truthy_config_flag(config.get("collect_results")),
            "delay_between_iterations_ms": _clamp_while_delay_ms(
                config.get("delay_between_iterations_ms")
            ),
            "results": [],
            "expression": config.get("expression"),
        }
    if node_type in {"memory_read", "memory_write"}:
        return {
            "simulated": True,
            "scope_type": config.get("scope_type"),
            "scope_id": config.get("scope_id"),
            "memory_tier": config.get("memory_tier"),
        }
    if node_type == "vector_query":
        return {
            "simulated": True,
            "store_id": config.get("store_id"),
            "query": config.get("query"),
            "top_k": config.get("top_k"),
            "matches": [],
            "match_count": 0,
        }
    if node_type == "vector_ingest":
        return {
            "simulated": True,
            "store_id": config.get("store_id"),
            "document_id": config.get("document_id"),
            "ingested": 1,
        }
    if node_type == "embedding_create":
        return {
            "simulated": True,
            "embedding_dims": 1536,
            "model_id": config.get("model_id"),
        }
    if node_type == "rag_query":
        return {
            "simulated": True,
            "source": "rag_query",
            "store_id": config.get("store_id"),
            "query_template": config.get("query_template"),
            "top_k": config.get("top_k"),
            "matches": [],
            "chunks": [],
            "match_count": 0,
        }
    if node_type == "wait_delay":
        return {
            "simulated": True,
            "delay_seconds": config.get("delay_seconds"),
            "waited": True,
        }
    if node_type == "guardrail_evaluate":
        return {
            "simulated": True,
            "passed": True,
            "violations": [],
        }
    if node_type == "email_send":
        return {
            "simulated": True,
            "channel_id": config.get("channel_id"),
            "to": config.get("to_template"),
            "subject": config.get("subject_template"),
            "body": config.get("body_template"),
            "from_override": config.get("from_override"),
            "delivery_status": "simulated",
        }
    if node_type == "sms_send":
        return {
            "simulated": True,
            "channel_id": config.get("channel_id"),
            "to": config.get("to_template"),
            "body": config.get("body_template"),
            "from_override": config.get("from_override"),
            "delivery_status": "simulated",
        }
    if node_type == "human_approval":
        return {
            "simulated": True,
            "approval_gate_id": f"gate-{uuid4().hex[:12]}",
            "approval_title": config.get("approval_title"),
            "status": "pending" if dry_run else "approved_stub",
        }
    if node_type == "parallel_fork":
        return {
            "simulated": True,
            "execution_mode": "parallel",
            "group_id": config.get("group_id"),
        }
    if node_type == "parallel_join":
        return {
            "simulated": True,
            "execution_mode": "merge",
            "group_id": config.get("group_id"),
            "fork_node_id": config.get("fork_node_id"),
            "merged": True,
        }
    if node_type == "set_fields":
        return {
            "simulated": True,
            "fields": config.get("fields_json") or {},
            "note": "Set fields (template map)",
        }
    if node_type == "json_transform":
        return {
            "simulated": True,
            "source_node_id": config.get("source_node_id"),
            "mapping": config.get("mapping_json") or {},
            "transformed": {},
        }
    if node_type == "slack_webhook":
        return {
            "simulated": True,
            "webhook_url": config.get("webhook_url"),
            "text": config.get("text_template"),
            "delivery_status": "simulated",
        }
    if node_type == "discord_webhook":
        return {
            "simulated": True,
            "webhook_url": config.get("webhook_url"),
            "content": config.get("content_template"),
            "delivery_status": "simulated",
        }
    if node_type == "teams_webhook":
        return {
            "simulated": True,
            "webhook_url": config.get("webhook_url"),
            "text": config.get("text_template"),
            "title": config.get("title_template"),
            "delivery_status": "simulated",
        }
    if node_type == "mattermost_webhook":
        return {
            "simulated": True,
            "provider": "mattermost",
            "webhook_url": config.get("webhook_url"),
            "text": config.get("text_template"),
            "delivery_status": "simulated",
        }
    if node_type == "google_chat_webhook":
        return {
            "simulated": True,
            "provider": "google_chat",
            "webhook_url": config.get("webhook_url"),
            "text": config.get("text_template"),
            "delivery_status": "simulated",
        }
    if node_type == "switch":
        return {
            "simulated": True,
            "chosen_branch": config.get("default_branch"),
            "case_count": len(_parse_cases_json(config.get("cases_json"))),
            "note": "Switch router",
        }
    if node_type == "filter":
        return {
            "simulated": True,
            "items": [],
            "count": 0,
            "input_count": 0,
            "source_node_id": config.get("source_node_id"),
            "items_path": config.get("items_path"),
        }
    if node_type == "merge_data":
        return {
            "simulated": True,
            "merged": {},
            "merge_mode": config.get("merge_mode") or "shallow",
            "source_a_node_id": config.get("source_a_node_id"),
            "source_b_node_id": config.get("source_b_node_id"),
        }
    if node_type == "github_api":
        return {
            "simulated": True,
            "provider": "github",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "gitlab_api":
        return {
            "simulated": True,
            "provider": "gitlab",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "bitbucket_api":
        return {
            "simulated": True,
            "provider": "bitbucket",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "jira_api":
        return {
            "simulated": True,
            "provider": "jira",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "confluence_api":
        return {
            "simulated": True,
            "provider": "confluence",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "respond_to_webhook":
        return {
            "simulated": True,
            "webhook_response": True,
            "status_code": int(config.get("status_code") or 200),
            "content_type": config.get("content_type") or "application/json",
            "body": config.get("body_template"),
        }
    if node_type == "split_in_batches":
        return {
            "simulated": True,
            "items": [],
            "batch": [],
            "count": 0,
            "batch_size": config.get("batch_size") or 10,
            "batch_index": config.get("batch_index") or 0,
            "has_more": False,
            "total": 0,
        }
    if node_type == "limit":
        return {
            "simulated": True,
            "items": [],
            "count": 0,
            "total": 0,
            "limit": config.get("limit") or 10,
            "offset": config.get("offset") or 0,
        }
    if node_type == "aggregate":
        return {
            "simulated": True,
            "aggregate_mode": config.get("aggregate_mode") or "count",
            "value": 0,
            "count": 0,
            "input_count": 0,
        }
    if node_type == "foreach_map":
        return {
            "simulated": True,
            "items": [],
            "count": 0,
            "input_count": 0,
            "truncated": False,
            "max_items": MAX_FOREACH_ITEMS,
        }
    if node_type == "linear_api":
        return {
            "simulated": True,
            "provider": "linear",
            "method": config.get("method") or "POST",
            "path": config.get("path_template") or "/graphql",
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "notion_api":
        return {
            "simulated": True,
            "provider": "notion",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "sort":
        return {"simulated": True, "items": [], "count": 0, "order": config.get("order") or "asc"}
    if node_type == "dedupe":
        return {"simulated": True, "items": [], "count": 0, "input_count": 0, "removed": 0}
    if node_type == "json_parse":
        return {"simulated": True, "parsed": {}, "data": {}, "type": "object"}
    if node_type == "date_time":
        return {
            "simulated": True,
            "operation": config.get("operation") or "now",
            "iso": "2026-07-31T00:00:00Z",
            "formatted": "2026-07-31T00:00:00Z",
            "value": "2026-07-31T00:00:00Z",
            "epoch_seconds": 0,
        }
    if node_type == "execute_subflow":
        return {
            "simulated": True,
            "target_flow_id": config.get("target_flow_id"),
            "status": "simulated",
            "step_count": 0,
            "nested": True,
        }
    if node_type == "string_ops":
        return {
            "simulated": True,
            "operation": config.get("operation") or "trim",
            "value": "",
            "result": "",
        }
    if node_type == "compare":
        return {
            "simulated": True,
            "matched": True,
            "operator": config.get("operator") or "==",
            "left": None,
            "right": None,
        }
    if node_type == "csv_parse":
        return {
            "simulated": True,
            "items": [],
            "count": 0,
            "has_header": True,
            "truncated": False,
            "max_rows": MAX_CSV_ROWS,
        }
    if node_type == "static_data":
        return {
            "simulated": True,
            "fields": config.get("fields_json") or {},
            "data": {},
        }
    if node_type == "hubspot_api":
        return {
            "simulated": True,
            "provider": "hubspot",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "zendesk_api":
        return {
            "simulated": True,
            "provider": "zendesk",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "freshdesk_api":
        return {
            "simulated": True,
            "provider": "freshdesk",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "math_ops":
        return {
            "simulated": True,
            "operation": config.get("operation") or "add",
            "a": 0,
            "b": 0,
            "result": 0,
            "value": 0,
        }
    if node_type == "wait_until":
        return {
            "simulated": True,
            "until": config.get("until_template"),
            "wait_seconds": 0,
            "waited_seconds": 0,
            "already_passed": True,
            "capped": False,
        }
    if node_type == "uuid_gen":
        return {
            "simulated": True,
            "uuid": "00000000-0000-4000-8000-000000000000",
            "uuids": ["00000000-0000-4000-8000-000000000000"],
            "count": 1,
        }
    if node_type == "salesforce_api":
        return {
            "simulated": True,
            "provider": "salesforce",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "servicenow_api":
        return {
            "simulated": True,
            "provider": "servicenow",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "hash_digest":
        return {
            "simulated": True,
            "algorithm": config.get("algorithm") or "sha256",
            "digest": "0" * 64,
            "hex": "0" * 64,
        }
    if node_type == "stop_and_error":
        return {
            "simulated": True,
            "stopped": True,
            "error": config.get("message_template") or "Stopped by stop_and_error",
            "message": config.get("message_template") or "Stopped by stop_and_error",
        }
    if node_type == "noop":
        return {"simulated": True, "ok": True, "passthrough": True, "note": config.get("note")}
    if node_type == "json_to_csv":
        return {
            "simulated": True,
            "csv": "col\n",
            "text": "col\n",
            "count": 0,
            "truncated": False,
            "columns": ["col"],
        }
    if node_type == "split_out":
        return {"simulated": True, "items": [], "count": 0, "total": 0, "truncated": False}
    if node_type == "pick_fields":
        return {"simulated": True, "fields": {}, "data": {}, "picked_keys": []}
    if node_type == "rename_keys":
        return {"simulated": True, "fields": {}, "data": {}, "renamed": []}
    if node_type == "boolean_logic":
        return {
            "simulated": True,
            "matched": True,
            "combine": config.get("combine") or "and",
            "rule_count": 0,
            "rule_results": [],
        }
    if node_type == "airtable_api":
        return {
            "simulated": True,
            "provider": "airtable",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "telegram_notify":
        return {
            "simulated": True,
            "provider": "telegram",
            "delivery_status": "simulated",
            "chat_id": config.get("chat_id_template"),
        }
    if node_type == "html_strip":
        return {"simulated": True, "text": "", "value": "", "result": ""}
    if node_type == "url_ops":
        return {
            "simulated": True,
            "operation": config.get("operation") or "encode",
            "result": "",
            "value": "",
        }
    if node_type == "base64_ops":
        return {
            "simulated": True,
            "operation": config.get("operation") or "encode",
            "result": "",
            "value": "",
        }
    if node_type == "coalesce":
        return {"simulated": True, "value": None, "result": None, "found": False, "candidate_count": 0}
    if node_type == "omit_fields":
        return {"simulated": True, "fields": {}, "data": {}, "omitted_keys": [], "kept_keys": []}
    if node_type == "append_items":
        return {"simulated": True, "items": [], "count": 0, "total": 0, "truncated": False}
    if node_type == "graphql_request":
        return {
            "simulated": True,
            "provider": "graphql",
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "asana_api":
        return {
            "simulated": True,
            "provider": "asana",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "clickup_api":
        return {
            "simulated": True,
            "provider": "clickup",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "intercom_api":
        return {
            "simulated": True,
            "provider": "intercom",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "monday_api":
        return {
            "simulated": True,
            "provider": "monday",
            "method": config.get("method") or "POST",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "pipedrive_api":
        return {
            "simulated": True,
            "provider": "pipedrive",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "shopify_api":
        return {
            "simulated": True,
            "provider": "shopify",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "stripe_api":
        return {
            "simulated": True,
            "provider": "stripe",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "box_api":
        return {
            "simulated": True,
            "provider": "box",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "dropbox_api":
        return {
            "simulated": True,
            "provider": "dropbox",
            "method": config.get("method") or "POST",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "calendly_api":
        return {
            "simulated": True,
            "provider": "calendly",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "microsoft_graph_api":
        return {
            "simulated": True,
            "provider": "microsoft_graph",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "google_sheets_api":
        return {
            "simulated": True,
            "provider": "google_sheets",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "google_drive_api":
        return {
            "simulated": True,
            "provider": "google_drive",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "google_calendar_api":
        return {
            "simulated": True,
            "provider": "google_calendar",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "slack_api":
        return {
            "simulated": True,
            "provider": "slack",
            "method": config.get("method") or "POST",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "zoom_api":
        return {
            "simulated": True,
            "provider": "zoom",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "twilio_api":
        return {
            "simulated": True,
            "provider": "twilio",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "sendgrid_api":
        return {
            "simulated": True,
            "provider": "sendgrid",
            "method": config.get("method") or "POST",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "freshservice_api":
        return {
            "simulated": True,
            "provider": "freshservice",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "okta_api":
        return {
            "simulated": True,
            "provider": "okta",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "auth0_api":
        return {
            "simulated": True,
            "provider": "auth0",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "azure_devops_api":
        return {
            "simulated": True,
            "provider": "azure_devops",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "snowflake_api":
        return {
            "simulated": True,
            "provider": "snowflake",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "databricks_api":
        return {
            "simulated": True,
            "provider": "databricks",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "bigquery_api":
        return {
            "simulated": True,
            "provider": "bigquery",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "splunk_api":
        return {
            "simulated": True,
            "provider": "splunk",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "elasticsearch_api":
        return {
            "simulated": True,
            "provider": "elasticsearch",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "redis_api":
        return {
            "simulated": True,
            "provider": "redis",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "mongodb_api":
        return {
            "simulated": True,
            "provider": "mongodb",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "postgres_api":
        return {
            "simulated": True,
            "provider": "postgres",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "mysql_api":
        return {
            "simulated": True,
            "provider": "mysql",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "s3_api":
        return {
            "simulated": True,
            "provider": "s3",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "pinecone_api":
        return {
            "simulated": True,
            "provider": "pinecone",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "weaviate_api":
        return {
            "simulated": True,
            "provider": "weaviate",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "qdrant_api":
        return {
            "simulated": True,
            "provider": "qdrant",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "supabase_api":
        return {
            "simulated": True,
            "provider": "supabase",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "kafka_api":
        return {
            "simulated": True,
            "provider": "kafka",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "milvus_api":
        return {
            "simulated": True,
            "provider": "milvus",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "chroma_api":
        return {
            "simulated": True,
            "provider": "chroma",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "neo4j_api":
        return {
            "simulated": True,
            "provider": "neo4j",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "rabbitmq_api":
        return {
            "simulated": True,
            "provider": "rabbitmq",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "opensearch_api":
        return {
            "simulated": True,
            "provider": "opensearch",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "clickhouse_api":
        return {
            "simulated": True,
            "provider": "clickhouse",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "dynamodb_api":
        return {
            "simulated": True,
            "provider": "dynamodb",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "nats_api":
        return {
            "simulated": True,
            "provider": "nats",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "cassandra_api":
        return {
            "simulated": True,
            "provider": "cassandra",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "couchbase_api":
        return {
            "simulated": True,
            "provider": "couchbase",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "influxdb_api":
        return {
            "simulated": True,
            "provider": "influxdb",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "firebase_api":
        return {
            "simulated": True,
            "provider": "firebase",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "airbyte_api":
        return {
            "simulated": True,
            "provider": "airbyte",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "presto_api":
        return {
            "simulated": True,
            "provider": "presto",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "trino_api":
        return {
            "simulated": True,
            "provider": "trino",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "redshift_api":
        return {
            "simulated": True,
            "provider": "redshift",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "athena_api":
        return {
            "simulated": True,
            "provider": "athena",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "pulsar_api":
        return {
            "simulated": True,
            "provider": "pulsar",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "scylladb_api":
        return {
            "simulated": True,
            "provider": "scylladb",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "sqs_api":
        return {
            "simulated": True,
            "provider": "sqs",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "sns_api":
        return {
            "simulated": True,
            "provider": "sns",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "kinesis_api":
        return {
            "simulated": True,
            "provider": "kinesis",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "eventbridge_api":
        return {
            "simulated": True,
            "provider": "eventbridge",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "lambda_api":
        return {
            "simulated": True,
            "provider": "lambda",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "stepfunctions_api":
        return {
            "simulated": True,
            "provider": "stepfunctions",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "cloudwatch_api":
        return {
            "simulated": True,
            "provider": "cloudwatch",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "xray_api":
        return {
            "simulated": True,
            "provider": "xray",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "glue_api":
        return {
            "simulated": True,
            "provider": "glue",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "sagemaker_api":
        return {
            "simulated": True,
            "provider": "sagemaker",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "bedrock_api":
        return {
            "simulated": True,
            "provider": "bedrock",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "comprehend_api":
        return {
            "simulated": True,
            "provider": "comprehend",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "textract_api":
        return {
            "simulated": True,
            "provider": "textract",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "rekognition_api":
        return {
            "simulated": True,
            "provider": "rekognition",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "translate_api":
        return {
            "simulated": True,
            "provider": "translate",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "polly_api":
        return {
            "simulated": True,
            "provider": "polly",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "transcribe_api":
        return {
            "simulated": True,
            "provider": "transcribe",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "lex_api":
        return {
            "simulated": True,
            "provider": "lex",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "ecs_api":
        return {
            "simulated": True,
            "provider": "ecs",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "eks_api":
        return {
            "simulated": True,
            "provider": "eks",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "secretsmanager_api":
        return {
            "simulated": True,
            "provider": "secretsmanager",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "ssm_api":
        return {
            "simulated": True,
            "provider": "ssm",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "cognito_api":
        return {
            "simulated": True,
            "provider": "cognito",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "iam_api":
        return {
            "simulated": True,
            "provider": "iam",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "kms_api":
        return {
            "simulated": True,
            "provider": "kms",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "sts_api":
        return {
            "simulated": True,
            "provider": "sts",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "apigateway_api":
        return {
            "simulated": True,
            "provider": "apigateway",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "cloudformation_api":
        return {
            "simulated": True,
            "provider": "cloudformation",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "rds_api":
        return {
            "simulated": True,
            "provider": "rds",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "elb_api":
        return {
            "simulated": True,
            "provider": "elb",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "cloudfront_api":
        return {
            "simulated": True,
            "provider": "cloudfront",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "route53_api":
        return {
            "simulated": True,
            "provider": "route53",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "cloudtrail_api":
        return {
            "simulated": True,
            "provider": "cloudtrail",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "config_api":
        return {
            "simulated": True,
            "provider": "config",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "guardduty_api":
        return {
            "simulated": True,
            "provider": "guardduty",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "securityhub_api":
        return {
            "simulated": True,
            "provider": "securityhub",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "inspector_api":
        return {
            "simulated": True,
            "provider": "inspector",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "macie_api":
        return {
            "simulated": True,
            "provider": "macie",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "waf_api":
        return {
            "simulated": True,
            "provider": "waf",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "shield_api":
        return {
            "simulated": True,
            "provider": "shield",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "acm_api":
        return {
            "simulated": True,
            "provider": "acm",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "networkfirewall_api":
        return {
            "simulated": True,
            "provider": "networkfirewall",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "ecr_api":
        return {
            "simulated": True,
            "provider": "ecr",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "efs_api":
        return {
            "simulated": True,
            "provider": "efs",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "detective_api":
        return {
            "simulated": True,
            "provider": "detective",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "accessanalyzer_api":
        return {
            "simulated": True,
            "provider": "accessanalyzer",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "fargate_api":
        return {
            "simulated": True,
            "provider": "fargate",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "batch_api":
        return {
            "simulated": True,
            "provider": "batch",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "elasticache_api":
        return {
            "simulated": True,
            "provider": "elasticache",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "memorydb_api":
        return {
            "simulated": True,
            "provider": "memorydb",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "emr_api":
        return {
            "simulated": True,
            "provider": "emr",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "firehose_api":
        return {
            "simulated": True,
            "provider": "firehose",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "msk_api":
        return {
            "simulated": True,
            "provider": "msk",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "appsync_api":
        return {
            "simulated": True,
            "provider": "appsync",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "amazon_mq_api":
        return {
            "simulated": True,
            "provider": "amazon_mq",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "neptune_api":
        return {
            "simulated": True,
            "provider": "neptune",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "documentdb_api":
        return {
            "simulated": True,
            "provider": "documentdb",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "fsx_api":
        return {
            "simulated": True,
            "provider": "fsx",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "kendra_api":
        return {
            "simulated": True,
            "provider": "kendra",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "personalize_api":
        return {
            "simulated": True,
            "provider": "personalize",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "forecast_api":
        return {
            "simulated": True,
            "provider": "forecast",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "mediaconvert_api":
        return {
            "simulated": True,
            "provider": "mediaconvert",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "transfer_api":
        return {
            "simulated": True,
            "provider": "transfer",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "datasync_api":
        return {
            "simulated": True,
            "provider": "datasync",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "backup_api":
        return {
            "simulated": True,
            "provider": "backup",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "lightsail_api":
        return {
            "simulated": True,
            "provider": "lightsail",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "elasticbeanstalk_api":
        return {
            "simulated": True,
            "provider": "elasticbeanstalk",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "workspaces_api":
        return {
            "simulated": True,
            "provider": "workspaces",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "appstream_api":
        return {
            "simulated": True,
            "provider": "appstream",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "mediastore_api":
        return {
            "simulated": True,
            "provider": "mediastore",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "outposts_api":
        return {
            "simulated": True,
            "provider": "outposts",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "storagegateway_api":
        return {
            "simulated": True,
            "provider": "storagegateway",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "directconnect_api":
        return {
            "simulated": True,
            "provider": "directconnect",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "transitgateway_api":
        return {
            "simulated": True,
            "provider": "transitgateway",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "ec2_api":
        return {
            "simulated": True,
            "provider": "ec2",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "autoscaling_api":
        return {
            "simulated": True,
            "provider": "autoscaling",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "organizations_api":
        return {
            "simulated": True,
            "provider": "organizations",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "ram_api":
        return {
            "simulated": True,
            "provider": "ram",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "codebuild_api":
        return {
            "simulated": True,
            "provider": "codebuild",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "codepipeline_api":
        return {
            "simulated": True,
            "provider": "codepipeline",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "codedeploy_api":
        return {
            "simulated": True,
            "provider": "codedeploy",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "codecommit_api":
        return {
            "simulated": True,
            "provider": "codecommit",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "cloud9_api":
        return {
            "simulated": True,
            "provider": "cloud9",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "amplify_api":
        return {
            "simulated": True,
            "provider": "amplify",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "fis_api":
        return {
            "simulated": True,
            "provider": "fis",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "resiliencehub_api":
        return {
            "simulated": True,
            "provider": "resiliencehub",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "wellarchitected_api":
        return {
            "simulated": True,
            "provider": "wellarchitected",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "support_api":
        return {
            "simulated": True,
            "provider": "support",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "trustedadvisor_api":
        return {
            "simulated": True,
            "provider": "trustedadvisor",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "controltower_api":
        return {
            "simulated": True,
            "provider": "controltower",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "servicecatalog_api":
        return {
            "simulated": True,
            "provider": "servicecatalog",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "lakeformation_api":
        return {
            "simulated": True,
            "provider": "lakeformation",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "ses_api":
        return {
            "simulated": True,
            "provider": "ses",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "pinpoint_api":
        return {
            "simulated": True,
            "provider": "pinpoint",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "connect_api":
        return {
            "simulated": True,
            "provider": "connect",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "chime_api":
        return {
            "simulated": True,
            "provider": "chime",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "ivs_api":
        return {
            "simulated": True,
            "provider": "ivs",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "gamelift_api":
        return {
            "simulated": True,
            "provider": "gamelift",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "braket_api":
        return {
            "simulated": True,
            "provider": "braket",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "qldb_api":
        return {
            "simulated": True,
            "provider": "qldb",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "timestream_api":
        return {
            "simulated": True,
            "provider": "timestream",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "appconfig_api":
        return {
            "simulated": True,
            "provider": "appconfig",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "grafana_api":
        return {
            "simulated": True,
            "provider": "grafana",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "prometheus_api":
        return {
            "simulated": True,
            "provider": "prometheus",
            "method": config.get("method") or "GET",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "location_api":
        return {
            "simulated": True,
            "provider": "location",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "emrserverless_api":
        return {
            "simulated": True,
            "provider": "emrserverless",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "iot_api":
        return {
            "simulated": True,
            "provider": "iot",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "greengrass_api":
        return {
            "simulated": True,
            "provider": "greengrass",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "iotanalytics_api":
        return {
            "simulated": True,
            "provider": "iotanalytics",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "freertos_api":
        return {
            "simulated": True,
            "provider": "freertos",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "datazone_api":
        return {
            "simulated": True,
            "provider": "datazone",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "cleanrooms_api":
        return {
            "simulated": True,
            "provider": "cleanrooms",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "entityresolution_api":
        return {
            "simulated": True,
            "provider": "entityresolution",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "supplychain_api":
        return {
            "simulated": True,
            "provider": "supplychain",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "amp_api":
        return {
            "simulated": True,
            "provider": "amp",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "managedgrafana_api":
        return {
            "simulated": True,
            "provider": "managedgrafana",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "opensearchserverless_api":
        return {
            "simulated": True,
            "provider": "opensearchserverless",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "mwaa_api":
        return {
            "simulated": True,
            "provider": "mwaa",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "appflow_api":
        return {
            "simulated": True,
            "provider": "appflow",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "databrew_api":
        return {
            "simulated": True,
            "provider": "databrew",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "healthlake_api":
        return {
            "simulated": True,
            "provider": "healthlake",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "medicalimaging_api":
        return {
            "simulated": True,
            "provider": "medicalimaging",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "omics_api":
        return {
            "simulated": True,
            "provider": "omics",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "finspace_api":
        return {
            "simulated": True,
            "provider": "finspace",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "lookoutmetrics_api":
        return {
            "simulated": True,
            "provider": "lookoutmetrics",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "lookoutvision_api":
        return {
            "simulated": True,
            "provider": "lookoutvision",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "evidently_api":
        return {
            "simulated": True,
            "provider": "evidently",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "rum_api":
        return {
            "simulated": True,
            "provider": "rum",
            "method": config.get("method") or "POST",
            "base_url": config.get("base_url"),
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "number_format":
        return {
            "simulated": True,
            "style": config.get("style") or "decimal",
            "formatted": "0.00",
            "value": "0.00",
            "number": 0,
        }
    if node_type == "regex_extract":
        return {"simulated": True, "matches": [], "items": [], "count": 0, "first": None}
    if node_type == "text_template":
        return {"simulated": True, "text": config.get("text_template") or "", "message": "", "value": ""}
    if node_type == "timezone_convert":
        return {
            "simulated": True,
            "iso": "2026-07-31T12:00:00+00:00",
            "formatted": "2026-07-31T12:00:00+0000",
            "to_timezone": config.get("to_timezone") or "UTC",
        }
    if node_type == "item_exists":
        return {"simulated": True, "matched": True, "exists": True, "value": None}
    if node_type == "flatten_json":
        return {"simulated": True, "fields": {}, "data": {}, "count": 0, "truncated": False}
    if node_type == "pagerduty_event":
        return {
            "simulated": True,
            "provider": "pagerduty",
            "delivery_status": "simulated",
            "severity": config.get("severity") or "info",
        }
    if node_type == "opsgenie_alert":
        return {
            "simulated": True,
            "provider": "opsgenie",
            "delivery_status": "simulated",
            "priority": str(config.get("priority") or "P3").strip().upper() or "P3",
        }
    if node_type == "datadog_event":
        return {
            "simulated": True,
            "provider": "datadog",
            "delivery_status": "simulated",
            "alert_type": str(config.get("alert_type") or "info").strip().lower() or "info",
        }
    if node_type == "sentry_event":
        return {
            "simulated": True,
            "provider": "sentry",
            "delivery_status": "simulated",
            "level": str(config.get("level") or "error").strip().lower() or "error",
            "organization_slug": config.get("organization_slug"),
            "project_slug": config.get("project_slug"),
        }
    if node_type == "statuspage_incident":
        return {
            "simulated": True,
            "provider": "statuspage",
            "delivery_status": "simulated",
            "status": str(config.get("status") or "investigating").strip().lower() or "investigating",
            "impact": str(config.get("impact") or "minor").strip().lower() or "minor",
            "page_id": config.get("page_id"),
        }
    if node_type == "trello_api":
        return {
            "simulated": True,
            "provider": "trello",
            "method": config.get("method") or "GET",
            "path": config.get("path_template"),
            "status_code": 200,
            "status": 200,
            "data": {"ok": True},
        }
    if node_type == "json_stringify":
        return {"simulated": True, "json": "{}", "text": "{}", "value": "{}", "length": 2}
    if node_type == "type_of":
        return {"simulated": True, "type": "null", "value": None, "is_null": True, "is_empty": True}
    if node_type == "xml_parse":
        return {
            "simulated": True,
            "data": {"tag": "root", "text": "ok"},
            "tag": "root",
        }
    if node_type == "unflatten_json":
        return {"simulated": True, "data": {"a": {"b": 1}}, "fields": {"a": {"b": 1}}, "count": 1}
    if node_type == "chunk_text":
        return {"simulated": True, "chunks": ["hello"], "items": ["hello"], "count": 1, "chunk_size": 500, "overlap": 0}
    if node_type == "form_urlencoded":
        return {"simulated": True, "operation": "encode", "text": "a=1", "value": "a=1", "pair_count": 1}
    if node_type == "deep_merge":
        return {"simulated": True, "data": {"a": 1, "b": 2}, "fields": {"a": 1, "b": 2}, "key_count": 2}
    if node_type == "jwt_decode":
        return {
            "simulated": True,
            "header": {"alg": "none", "typ": "JWT"},
            "payload": {"sub": "user-1"},
            "claims": {"sub": "user-1"},
            "verified": False,
        }
    if node_type == "html_extract":
        return {
            "simulated": True,
            "text": "Hello",
            "value": "Hello",
            "links": [{"href": "https://example.com", "title": ""}],
            "link_count": 1,
            "mode": "both",
        }
    if node_type == "split_text":
        return {"simulated": True, "parts": ["a", "b"], "items": ["a", "b"], "count": 2, "delimiter": ","}
    if node_type == "json_query":
        return {"simulated": True, "value": {"ok": True}, "data": {"ok": True}, "found": True}
    if node_type == "compress":
        return {
            "simulated": True,
            "operation": "compress",
            "algorithm": "zlib",
            "encoding": "base64",
            "data": "eJyrBQQAAP//AwA=",
            "value": "eJyrBQQAAP//AwA=",
        }
    if node_type == "random":
        return {"simulated": True, "mode": "int", "value": 42, "result": 42, "min": 0, "max": 100}
    if node_type == "hmac_verify":
        return {"simulated": True, "verified": True, "matched": True, "algorithm": "sha256", "encoding": "hex"}
    if node_type == "xml_stringify":
        return {"simulated": True, "xml": "<root><ok>true</ok></root>", "text": "<root><ok>true</ok></root>", "length": 24}
    if node_type == "object_diff":
        return {
            "simulated": True,
            "changes": [{"path": "$.a", "op": "changed", "left": 1, "right": 2}],
            "count": 1,
            "added": 0,
            "removed": 0,
            "changed": 1,
            "equal": False,
        }
    if node_type == "html_to_markdown":
        return {"simulated": True, "markdown": "# Hello", "text": "# Hello", "length": 7}
    if node_type == "markdown_to_html":
        return {"simulated": True, "html": "<h1>Hello</h1>", "text": "<h1>Hello</h1>", "length": 14}
    if node_type == "array_ops":
        return {"simulated": True, "operation": "length", "count": 2, "length": 2, "items": [1, 2]}
    if node_type == "compact_object":
        return {"simulated": True, "data": {"a": 1}, "fields": {"a": 1}, "key_count": 1}
    return {"simulated": True, "note": "trigger or passthrough node"}


def _execute_single_stub_node(
    node: dict[str, Any],
    *,
    dry_run: bool,
    trace_id: str,
    step_outputs: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    node_id = str(node.get("id") or "")
    node_type = str(node.get("type") or "")
    config = node.get("config") if isinstance(node.get("config"), dict) else {}
    # n8n-style pin data: dry-run / design-time override from prior live run output.
    pinned = config.get("pin_data")
    if dry_run and pinned is not None:
        if isinstance(pinned, str):
            try:
                pinned = json.loads(pinned)
            except json.JSONDecodeError:
                pinned = {"pinned_raw": pinned}
        if isinstance(pinned, dict):
            output = {**pinned, "pinned": True, "simulated": True, "dry_run": True}
            return {
                "node_id": node_id,
                "node_type": node_type,
                "status": "simulated",
                "trace_id": trace_id,
                "output": output,
            }
    output = _stub_node_output(node_type, config, dry_run=dry_run)
    if node_type == "condition" and step_outputs is not None:
        output["matched"] = evaluate_condition(config, step_outputs)
    if node_type == "switch" and step_outputs is not None:
        output.update(evaluate_switch(config, step_outputs))
    if node_type == "filter" and step_outputs is not None:
        output.update(evaluate_filter(config, step_outputs))
    if node_type == "merge_data" and step_outputs is not None:
        output.update(merge_step_outputs(config, step_outputs))
    if node_type == "split_in_batches" and step_outputs is not None:
        output.update(evaluate_split_in_batches(config, step_outputs))
    if node_type == "limit" and step_outputs is not None:
        output.update(evaluate_limit(config, step_outputs))
    if node_type == "aggregate" and step_outputs is not None:
        output.update(evaluate_aggregate(config, step_outputs))
    if node_type == "foreach_map" and step_outputs is not None:
        output.update(evaluate_foreach_map(config, step_outputs))
    if node_type == "sort" and step_outputs is not None:
        output.update(evaluate_sort(config, step_outputs))
    if node_type == "dedupe" and step_outputs is not None:
        output.update(evaluate_dedupe(config, step_outputs))
    if node_type == "json_parse" and step_outputs is not None:
        try:
            output.update(evaluate_json_parse(config, step_outputs))
        except json.JSONDecodeError as exc:
            output = {**output, "error": f"JSON parse failed: {exc}", "parsed": None}
    if node_type == "date_time" and step_outputs is not None:
        try:
            output.update(evaluate_date_time(config, step_outputs))
        except ValueError as exc:
            output = {**output, "error": f"date_time failed: {exc}"}
    if node_type == "string_ops" and step_outputs is not None:
        output.update(evaluate_string_ops(config, step_outputs))
    if node_type == "compare" and step_outputs is not None:
        output.update(evaluate_compare(config, step_outputs))
    if node_type == "csv_parse" and step_outputs is not None:
        output.update(evaluate_csv_parse(config, step_outputs))
    if node_type == "static_data" and step_outputs is not None:
        output.update(evaluate_static_data(config, step_outputs))
    if node_type == "math_ops" and step_outputs is not None:
        output.update(evaluate_math_ops(config, step_outputs))
    if node_type == "wait_until" and step_outputs is not None:
        output.update(evaluate_wait_until(config, step_outputs))
    if node_type == "uuid_gen":
        output.update(evaluate_uuid_gen(config))
    if node_type == "hash_digest" and step_outputs is not None:
        output.update(evaluate_hash_digest(config, step_outputs))
    if node_type == "stop_and_error" and step_outputs is not None:
        output.update(evaluate_stop_and_error(config, step_outputs))
    if node_type == "noop" and step_outputs is not None:
        output.update(evaluate_noop(config, step_outputs))
    if node_type == "json_to_csv" and step_outputs is not None:
        output.update(evaluate_json_to_csv(config, step_outputs))
    if node_type == "split_out" and step_outputs is not None:
        output.update(evaluate_split_out(config, step_outputs))
    if node_type == "pick_fields" and step_outputs is not None:
        output.update(evaluate_pick_fields(config, step_outputs))
    if node_type == "rename_keys" and step_outputs is not None:
        output.update(evaluate_rename_keys(config, step_outputs))
    if node_type == "boolean_logic" and step_outputs is not None:
        output.update(evaluate_boolean_logic(config, step_outputs))
    if node_type == "html_strip" and step_outputs is not None:
        output.update(evaluate_html_strip(config, step_outputs))
    if node_type == "url_ops" and step_outputs is not None:
        output.update(evaluate_url_ops(config, step_outputs))
    if node_type == "base64_ops" and step_outputs is not None:
        output.update(evaluate_base64_ops(config, step_outputs))
    if node_type == "coalesce" and step_outputs is not None:
        output.update(evaluate_coalesce(config, step_outputs))
    if node_type == "omit_fields" and step_outputs is not None:
        output.update(evaluate_omit_fields(config, step_outputs))
    if node_type == "append_items" and step_outputs is not None:
        output.update(evaluate_append_items(config, step_outputs))
    if node_type == "number_format" and step_outputs is not None:
        output.update(evaluate_number_format(config, step_outputs))
    if node_type == "regex_extract" and step_outputs is not None:
        output.update(evaluate_regex_extract(config, step_outputs))
    if node_type == "text_template" and step_outputs is not None:
        output.update(evaluate_text_template(config, step_outputs))
    if node_type == "timezone_convert" and step_outputs is not None:
        output.update(evaluate_timezone_convert(config, step_outputs))
    if node_type == "item_exists" and step_outputs is not None:
        output.update(evaluate_item_exists(config, step_outputs))
    if node_type == "flatten_json" and step_outputs is not None:
        output.update(evaluate_flatten_json(config, step_outputs))
    if node_type == "json_stringify" and step_outputs is not None:
        output.update(evaluate_json_stringify(config, step_outputs))
    if node_type == "type_of" and step_outputs is not None:
        output.update(evaluate_type_of(config, step_outputs))
    if node_type == "xml_parse" and step_outputs is not None:
        output.update(evaluate_xml_parse(config, step_outputs))
    if node_type == "unflatten_json" and step_outputs is not None:
        output.update(evaluate_unflatten_json(config, step_outputs))
    if node_type == "chunk_text" and step_outputs is not None:
        output.update(evaluate_chunk_text(config, step_outputs))
    if node_type == "form_urlencoded" and step_outputs is not None:
        output.update(evaluate_form_urlencoded(config, step_outputs))
    if node_type == "deep_merge" and step_outputs is not None:
        output.update(evaluate_deep_merge(config, step_outputs))
    if node_type == "jwt_decode" and step_outputs is not None:
        output.update(evaluate_jwt_decode(config, step_outputs))
    if node_type == "html_extract" and step_outputs is not None:
        output.update(evaluate_html_extract(config, step_outputs))
    if node_type == "split_text" and step_outputs is not None:
        output.update(evaluate_split_text(config, step_outputs))
    if node_type == "json_query" and step_outputs is not None:
        output.update(evaluate_json_query(config, step_outputs))
    if node_type == "compress" and step_outputs is not None:
        output.update(evaluate_compress(config, step_outputs))
    if node_type == "random":
        output.update(evaluate_random(config, step_outputs or {}))
    if node_type == "hmac_verify" and step_outputs is not None:
        output.update(evaluate_hmac_verify(config, step_outputs))
    if node_type == "xml_stringify" and step_outputs is not None:
        output.update(evaluate_xml_stringify(config, step_outputs))
    if node_type == "object_diff" and step_outputs is not None:
        output.update(evaluate_object_diff(config, step_outputs))
    if node_type == "html_to_markdown" and step_outputs is not None:
        output.update(evaluate_html_to_markdown(config, step_outputs))
    if node_type == "markdown_to_html" and step_outputs is not None:
        output.update(evaluate_markdown_to_html(config, step_outputs))
    if node_type == "array_ops" and step_outputs is not None:
        output.update(evaluate_array_ops(config, step_outputs))
    if node_type == "compact_object" and step_outputs is not None:
        output.update(evaluate_compact_object(config, step_outputs))
    status = "simulated" if dry_run else "completed"
    if node_type == "stop_and_error" and not dry_run:
        status = "failed"
    return {
        "node_id": node_id,
        "node_type": node_type,
        "status": status,
        "trace_id": trace_id,
        "output": output,
    }


def _collect_branch_node_ids(
    branch_head: str,
    join_id: str,
    outgoing: dict[str, list[str]],
) -> list[str]:
    ordered: list[str] = []
    visited: set[str] = set()
    queue = [branch_head]
    while queue:
        current = queue.pop(0)
        if current in visited or current == join_id:
            continue
        visited.add(current)
        ordered.append(current)
        for successor in outgoing.get(current, []):
            if successor != join_id and successor not in visited:
                queue.append(successor)
    return ordered


def _mark_branch_skipped(
    branch_head: str,
    condition_node_id: str,
    outgoing: dict[str, list[str]],
    incoming: dict[str, list[str]],
    completed: set[str],
) -> None:
    head = str(branch_head or "").strip()
    if not head:
        return
    to_skip: set[str] = set()
    queue = [head]
    while queue:
        node_id = queue.pop(0)
        if node_id in to_skip:
            continue
        preds = incoming.get(node_id, [])
        external = [pred for pred in preds if pred != condition_node_id and pred not in to_skip]
        if external:
            continue
        to_skip.add(node_id)
        for successor in outgoing.get(node_id, []):
            queue.append(successor)
    completed.update(to_skip)


def _execute_parallel_branches(
    fork_id: str,
    join_id: str,
    nodes_by_id: dict[str, dict[str, Any]],
    outgoing: dict[str, list[str]],
    *,
    trace_id: str,
    node_executor: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    step_outputs: dict[str, Any],
) -> list[list[dict[str, Any]]]:
    branch_heads = [target for target in outgoing.get(fork_id, []) if target != join_id]
    results: list[list[dict[str, Any]]] = []
    for branch_head in branch_heads:
        branch_ids = _collect_branch_node_ids(branch_head, join_id, outgoing)
        branch_outputs = dict(step_outputs)
        branch_steps: list[dict[str, Any]] = []
        for node_id in branch_ids:
            node = nodes_by_id.get(node_id)
            if not node:
                continue
            step = node_executor(node, branch_outputs)
            branch_steps.append(step)
        for step in branch_steps:
            node_id = str(step.get("node_id") or "")
            if node_id:
                step_outputs[node_id] = step.get("output")
        results.append(branch_steps)
    return results


def _execute_flow_graph(
    *,
    graph_json: str,
    dry_run: bool,
    trace_id: str,
    node_executor: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
    step_outputs: Optional[dict[str, Any]] = None,
    fail_on_node_error: bool = False,
    initial_completed: Optional[set[str]] = None,
    initial_step_results: Optional[list[dict[str, Any]]] = None,
    resume_from_node_id: Optional[str] = None,
) -> tuple[str, list[dict[str, Any]], Optional[str]]:
    graph = _parse_graph(graph_json)
    nodes = [node for node in graph["nodes"] if isinstance(node, dict)]
    edges = [edge for edge in graph["edges"] if isinstance(edge, dict)]
    nodes_by_id, outgoing, incoming = _build_graph_indexes(nodes, edges)

    outputs = step_outputs if step_outputs is not None else {}
    step_results: list[dict[str, Any]] = list(initial_step_results or [])
    error_summary: Optional[str] = None
    completed: set[str] = set(initial_completed or set())
    skipped_joins: set[str] = set()
    awaiting_approval = False

    entry_nodes = [node_id for node_id in nodes_by_id if not incoming.get(node_id)]
    if not entry_nodes and nodes_by_id:
        entry_nodes = [next(iter(nodes_by_id))]

    if resume_from_node_id:
        resume_id = str(resume_from_node_id).strip()
        ready = [successor for successor in outgoing.get(resume_id, []) if successor not in completed]
    else:
        ready = [node_id for node_id in entry_nodes if node_id not in completed]
    while ready:
        node_id = ready.pop(0)
        if node_id in completed or node_id in skipped_joins:
            continue
        node = nodes_by_id.get(node_id)
        if not node:
            completed.add(node_id)
            continue

        node_type = str(node.get("type") or "")
        config = node.get("config") if isinstance(node.get("config"), dict) else {}

        if node_type == "parallel_fork":
            join_candidates = [
                target
                for target in nodes_by_id
                if str(nodes_by_id[target].get("type") or "") == "parallel_join"
                and str((nodes_by_id[target].get("config") or {}).get("group_id") or "").strip()
                == str(config.get("group_id") or "").strip()
            ]
            join_id = join_candidates[0] if join_candidates else ""
            branch_results = (
                _execute_parallel_branches(
                    node_id,
                    join_id,
                    nodes_by_id,
                    outgoing,
                    trace_id=trace_id,
                    node_executor=node_executor,
                    step_outputs=outputs,
                )
                if join_id
                else []
            )
            fork_result = node_executor(node, outputs)
            fork_result["output"] = {
                **fork_result.get("output", {}),
                "branch_count": len(branch_results),
                "branches": branch_results,
            }
            step_results.append(fork_result)
            completed.add(node_id)

            for branch in branch_results:
                for branch_step in branch:
                    completed.add(branch_step["node_id"])
                    step_results.append(branch_step)
                    if fail_on_node_error and branch_step.get("status") == "failed":
                        branch_node = nodes_by_id.get(str(branch_step.get("node_id") or ""))
                        branch_cfg = (
                            branch_node.get("config")
                            if isinstance(branch_node, dict) and isinstance(branch_node.get("config"), dict)
                            else {}
                        )
                        continue_on_error = str(branch_cfg.get("continue_on_error") or "").strip().lower() in {
                            "1",
                            "true",
                            "yes",
                            "on",
                        }
                        if continue_on_error:
                            output = (
                                branch_step.get("output")
                                if isinstance(branch_step.get("output"), dict)
                                else {}
                            )
                            branch_step["output"] = {
                                **output,
                                "continued_on_error": True,
                                "error": output.get("error")
                                or f"Node {branch_step.get('node_id')} failed during parallel execution",
                            }
                            branch_step["status"] = "completed_with_errors"
                            outputs[str(branch_step.get("node_id") or "")] = branch_step["output"]
                        else:
                            error_summary = f"Node {branch_step.get('node_id')} failed during parallel execution"
                            ready.clear()
                            break
                if error_summary:
                    break

            if error_summary:
                break

            if join_id and join_id in nodes_by_id:
                join_node = nodes_by_id[join_id]
                join_result = node_executor(join_node, outputs)
                join_result["output"] = {
                    **join_result.get("output", {}),
                    "branch_count": len(branch_results),
                }
                step_results.append(join_result)
                completed.add(join_id)
                skipped_joins.add(join_id)
                for successor in outgoing.get(join_id, []):
                    if successor not in completed:
                        ready.append(successor)
            continue

        if node_type == "parallel_join":
            completed.add(node_id)
            continue

        if node_type in {"while_loop", "do_while"}:
            body_start = str(config.get("body_branch") or "").strip()
            exit_id = str(config.get("exit_branch") or config.get("false_branch") or "").strip()
            max_iterations = clamp_while_max_iterations(config.get("max_iterations"))
            collect_results = _truthy_config_flag(config.get("collect_results"))
            delay_ms = _clamp_while_delay_ms(config.get("delay_between_iterations_ms"))
            body_ids = _collect_loop_body_node_ids(
                body_start,
                exit_id,
                node_id,
                outgoing,
            )
            do_mode = node_type == "do_while"
            iteration_count = 0
            capped = False
            exit_reason = "condition_false"
            loop_failed = False
            iteration_summaries: list[dict[str, Any]] = []
            collected_results: list[Any] = []
            previous_body_output: Any = None
            continued_count = 0

            while True:
                if iteration_count >= max_iterations:
                    capped = True
                    exit_reason = "max_iterations"
                    break

                _publish_while_loop_context(
                    outputs,
                    node_id=node_id,
                    node_type=node_type,
                    iteration_count=iteration_count,
                    max_iterations=max_iterations,
                    previous=previous_body_output,
                )

                if not do_mode or iteration_count > 0:
                    if not evaluate_condition(config, outputs):
                        exit_reason = "condition_false"
                        break

                iter_steps: list[dict[str, Any]] = []
                continued = False
                for body_node_id in body_ids:
                    body_node = nodes_by_id.get(body_node_id)
                    if not body_node:
                        continue
                    body_step = node_executor(body_node, outputs)
                    body_output = body_step.get("output")
                    if isinstance(body_output, dict):
                        body_step["output"] = {
                            **body_output,
                            "_loop": {
                                "node_id": node_id,
                                "mode": node_type,
                                "index": iteration_count,
                                "iteration": iteration_count + 1,
                            },
                        }
                        body_output = body_step["output"]
                    iter_steps.append(body_step)
                    step_results.append(body_step)
                    outputs[body_node_id] = body_output
                    if _body_requests_loop_break(body_output):
                        exit_reason = "break"
                        break
                    if _body_requests_loop_continue(body_output):
                        continued = True
                        continued_count += 1
                        break
                    if fail_on_node_error and body_step.get("status") == "failed":
                        body_cfg = (
                            body_node.get("config")
                            if isinstance(body_node.get("config"), dict)
                            else {}
                        )
                        continue_on_error = str(body_cfg.get("continue_on_error") or "").strip().lower() in {
                            "1",
                            "true",
                            "yes",
                            "on",
                        }
                        if continue_on_error:
                            output = body_output if isinstance(body_output, dict) else {}
                            body_step["output"] = {
                                **output,
                                "continued_on_error": True,
                                "error": output.get("error")
                                or f"Node {body_step.get('node_id')} failed during {node_type}",
                            }
                            body_step["status"] = "completed_with_errors"
                            outputs[body_node_id] = body_step["output"]
                        else:
                            loop_failed = True
                            exit_reason = "body_failed"
                            break
                if body_ids:
                    previous_body_output = outputs.get(body_ids[-1])
                iteration_summaries.append(
                    {
                        "index": iteration_count,
                        "node_ids": [str(step.get("node_id") or "") for step in iter_steps],
                        "broke": exit_reason == "break",
                        "continued": continued,
                    }
                )
                if collect_results and body_ids:
                    last_body_id = body_ids[-1]
                    collected_results.append(outputs.get(last_body_id))
                    if len(collected_results) > MAX_WHILE_COLLECTED_RESULTS:
                        collected_results = collected_results[-MAX_WHILE_COLLECTED_RESULTS:]
                iteration_count += 1
                if loop_failed or exit_reason == "break":
                    break
                if do_mode:
                    _publish_while_loop_context(
                        outputs,
                        node_id=node_id,
                        node_type=node_type,
                        iteration_count=iteration_count,
                        max_iterations=max_iterations,
                        previous=previous_body_output,
                    )
                    if not evaluate_condition(config, outputs):
                        exit_reason = "condition_false"
                        break
                if delay_ms > 0 and not dry_run and iteration_count < max_iterations:
                    should_delay = do_mode
                    if not do_mode:
                        _publish_while_loop_context(
                            outputs,
                            node_id=node_id,
                            node_type=node_type,
                            iteration_count=iteration_count,
                            max_iterations=max_iterations,
                            previous=previous_body_output,
                        )
                        should_delay = evaluate_condition(config, outputs)
                    if should_delay:
                        time.sleep(delay_ms / 1000.0)

            outputs.pop("__loop__", None)
            loop_output = {
                "mode": node_type,
                "iterations": iteration_count,
                "index": max(0, iteration_count - 1) if iteration_count else 0,
                "iteration": iteration_count,
                "max_iterations": max_iterations,
                "capped": capped,
                "exit_reason": exit_reason,
                "body_node_ids": body_ids,
                "body_branch": body_start or None,
                "exit_branch": exit_id or None,
                "iteration_summaries": iteration_summaries,
                "collect_results": collect_results,
                "results": collected_results if collect_results else [],
                "delay_between_iterations_ms": delay_ms,
                "continued_count": continued_count,
                "expression": config.get("expression"),
                "matched": exit_reason not in {"condition_false"},
            }
            loop_result = {
                "node_id": node_id,
                "node_type": node_type,
                "status": "failed" if loop_failed else ("simulated" if dry_run else "completed"),
                "trace_id": trace_id,
                "output": loop_output,
            }
            step_results.append(loop_result)
            outputs[node_id] = loop_output
            completed.add(node_id)
            for body_node_id in body_ids:
                completed.add(body_node_id)
            if loop_failed:
                break
            # Prefer explicit exit; otherwise continue to non-body successors.
            if exit_id and exit_id in nodes_by_id:
                ready.append(exit_id)
            else:
                for successor in outgoing.get(node_id, []):
                    if successor in completed or successor in skipped_joins:
                        continue
                    if successor == body_start or successor in body_ids:
                        continue
                    preds = incoming.get(successor, [])
                    if all(pred in completed or pred in skipped_joins for pred in preds):
                        ready.append(successor)
            continue

        step_result = node_executor(node, outputs)
        step_results.append(step_result)
        if step_result.get("status") == "awaiting_approval":
            awaiting_approval = True
            break
        completed.add(node_id)
        if fail_on_node_error and step_result.get("status") == "failed":
            continue_on_error = str(config.get("continue_on_error") or "").strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }
            error_branch = str(config.get("error_branch") or config.get("on_error") or "").strip()
            if error_branch and error_branch in nodes_by_id:
                output = step_result.get("output") if isinstance(step_result.get("output"), dict) else {}
                step_result["output"] = {
                    **output,
                    "routed_on_error": True,
                    "error_branch": error_branch,
                    "error": output.get("error") or f"Node {step_result.get('node_id')} failed",
                }
                step_result["status"] = "completed_with_errors"
                outputs[str(step_result.get("node_id") or node_id)] = step_result["output"]
                for successor in list(outgoing.get(node_id, [])):
                    if successor != error_branch:
                        _mark_branch_skipped(successor, node_id, outgoing, incoming, completed)
                ready.append(error_branch)
                continue
            if continue_on_error:
                output = step_result.get("output") if isinstance(step_result.get("output"), dict) else {}
                step_result["output"] = {
                    **output,
                    "continued_on_error": True,
                    "error": output.get("error") or f"Node {step_result.get('node_id')} failed",
                }
                step_result["status"] = "completed_with_errors"
                outputs[str(step_result.get("node_id") or node_id)] = step_result["output"]
            else:
                error_summary = f"Node {step_result.get('node_id')} failed"
                break

        if node_type in {"condition", "compare", "boolean_logic", "item_exists"}:
            matched = bool((step_result.get("output") or {}).get("matched"))
            true_branch = str(config.get("true_branch") or "").strip()
            false_branch = str(config.get("false_branch") or "").strip()
            if true_branch or false_branch:
                chosen = true_branch if matched else false_branch
                skipped = false_branch if matched else true_branch
                if skipped:
                    _mark_branch_skipped(skipped, node_id, outgoing, incoming, completed)
                if chosen and chosen in nodes_by_id:
                    ready.append(chosen)
                else:
                    for successor in outgoing.get(node_id, []):
                        if successor in completed or successor in skipped_joins:
                            continue
                        preds = incoming.get(successor, [])
                        if all(pred in completed or pred in skipped_joins for pred in preds):
                            ready.append(successor)
                continue

        if node_type == "switch":
            chosen = str((step_result.get("output") or {}).get("chosen_branch") or "").strip()
            branch_targets = {
                str(case.get("branch") or "").strip()
                for case in _parse_cases_json(config.get("cases_json"))
                if str(case.get("branch") or "").strip()
            }
            default_branch = str(config.get("default_branch") or "").strip()
            if default_branch:
                branch_targets.add(default_branch)
            if branch_targets:
                for target in branch_targets:
                    if target != chosen:
                        _mark_branch_skipped(target, node_id, outgoing, incoming, completed)
                if chosen and chosen in nodes_by_id:
                    ready.append(chosen)
                else:
                    for successor in outgoing.get(node_id, []):
                        if successor in completed or successor in skipped_joins or successor in branch_targets:
                            continue
                        preds = incoming.get(successor, [])
                        if all(pred in completed or pred in skipped_joins for pred in preds):
                            ready.append(successor)
                continue

        for successor in outgoing.get(node_id, []):
            if successor in completed or successor in skipped_joins:
                continue
            preds = incoming.get(successor, [])
            if all(pred in completed or pred in skipped_joins for pred in preds):
                ready.append(successor)

    if awaiting_approval:
        return "awaiting_approval", step_results, error_summary
    status = "failed" if error_summary else "completed"
    if dry_run and not error_summary:
        status = "dry_run_completed"
    return status, step_results, error_summary


def execute_flow_stub(
    *,
    flow_id: str,
    graph_json: str,
    dry_run: bool,
    trace_id: str,
) -> tuple[str, list[dict[str, Any]], Optional[str]]:
    def stub_executor(node: dict[str, Any], outputs: dict[str, Any]) -> dict[str, Any]:
        return _execute_single_stub_node(
            node,
            dry_run=dry_run,
            trace_id=trace_id,
            step_outputs=outputs,
        )

    status, step_results, error_summary = _execute_flow_graph(
        graph_json=graph_json,
        dry_run=dry_run,
        trace_id=trace_id,
        node_executor=stub_executor,
    )
    return status, step_results, error_summary


def prod_run_requires_access_certification(db: Session) -> bool:
    raw = get_runtime_config(
        db,
        RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_ACCESS_CERTIFICATION,
        "true",
    ).strip().lower()
    return raw not in {"0", "false", "no"}


def security_policy_snapshot(db: Session) -> dict[str, Any]:
    return {
        "http_allowed_hosts": _load_http_allowlist(db),
        "leadership_connector_hosts": leadership_connector_host_coverage(db),
        "max_nodes_per_flow": get_runtime_config_int(db, RUNTIME_CONFIG_ORCHESTRATION_MAX_NODES_PER_FLOW, 50),
        "prod_run_requires_approval": prod_run_requires_approval(db),
        "prod_run_requires_access_certification": prod_run_requires_access_certification(db),
        "max_parallel_branches": MAX_PARALLEL_BRANCHES,
    }
