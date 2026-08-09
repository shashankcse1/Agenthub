from unittest.mock import patch

from app.services.inference_readiness import build_inference_readiness


def test_build_inference_readiness_reports_live_and_catalog(db_session=None):
    # Lightweight unit path using a fake Session-like object is awkward; exercise via helpers.
    class _Query:
        def filter(self, *_args, **_kwargs):
            return self

        def group_by(self, *_args, **_kwargs):
            return self

        def all(self):
            return [("openai", 3), ("aws", 5), ("azure-openai", 2), ("google", 4)]

    class _Db:
        def query(self, *_args, **_kwargs):
            return _Query()

    with patch("app.services.inference_readiness.inference_simulation_enabled", return_value=True), patch(
        "app.services.inference_readiness.provider_env_credential_configured",
        side_effect=lambda provider: provider in {"openai", "aws"},
    ), patch("app.services.inference_readiness._azure_endpoint_configured", return_value=False), patch(
        "app.services.inference_readiness._vertex_endpoint_configured", return_value=False
    ), patch(
        "app.services.inference_readiness._binding_ready_provider_types",
        return_value=set(),
    ):
        payload = build_inference_readiness(_Db())

    assert payload["simulation_enabled"] is True
    assert payload["catalog_models_total"] == 14
    by_provider = {row["provider_type"]: row for row in payload["providers"]}
    assert by_provider["openai"]["catalog_models"] == 3
    assert by_provider["openai"]["live_ready"] is True
    assert by_provider["aws"]["live_ready"] is True
    assert by_provider["azure-openai"]["live_ready"] is False
    assert by_provider["azure-openai"]["endpoint_configured"] is False


def test_build_inference_readiness_counts_binding_credentials():
    class _Query:
        def filter(self, *_args, **_kwargs):
            return self

        def group_by(self, *_args, **_kwargs):
            return self

        def all(self):
            return [("openai", 2), ("anthropic", 2)]

    class _Db:
        def query(self, *_args, **_kwargs):
            return _Query()

    with patch("app.services.inference_readiness.inference_simulation_enabled", return_value=False), patch(
        "app.services.inference_readiness.provider_env_credential_configured",
        return_value=False,
    ), patch(
        "app.services.inference_readiness._binding_ready_provider_types",
        return_value={"openai", "anthropic"},
    ), patch("app.services.inference_readiness._azure_endpoint_configured", return_value=True), patch(
        "app.services.inference_readiness._vertex_endpoint_configured", return_value=True
    ):
        payload = build_inference_readiness(_Db())

    by_provider = {row["provider_type"]: row for row in payload["providers"]}
    assert by_provider["openai"]["binding_credential_configured"] is True
    assert by_provider["openai"]["live_ready"] is True
    assert by_provider["anthropic"]["live_ready"] is True
    assert payload["ready_providers"] >= 2
