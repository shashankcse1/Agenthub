"""Abuse-case controls for leadership-bootstrap / CPLI enhance."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.routers.gateway import (
    _leadership_bootstrap_requires_dual_approval,
    _resolve_leadership_bootstrap_probe_peer,
    _runtime_is_production,
)


def test_dual_approval_required_when_app_env_production(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    assert _runtime_is_production() is True
    assert _leadership_bootstrap_requires_dual_approval(request_environment="dev") is True
    monkeypatch.setenv("APP_ENV", "dev")
    assert _leadership_bootstrap_requires_dual_approval(request_environment="dev") is False
    assert _leadership_bootstrap_requires_dual_approval(request_environment="prod") is True


def test_probe_peer_auto_on_production_and_split(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    assert _resolve_leadership_bootstrap_probe_peer(None, enhance_cpli=True) is True
    monkeypatch.setenv("APP_ENV", "dev")
    with patch("app.plane_mode.resolve_app_plane", return_value="data"):
        assert _resolve_leadership_bootstrap_probe_peer(None, enhance_cpli=True) is True
    with patch("app.plane_mode.resolve_app_plane", return_value="all"):
        assert _resolve_leadership_bootstrap_probe_peer(None, enhance_cpli=True) is False
    assert _resolve_leadership_bootstrap_probe_peer(False, enhance_cpli=True) is False
    assert _resolve_leadership_bootstrap_probe_peer(True, enhance_cpli=True) is True


def test_raise_engineering_blocks_when_control_readonly():
    from app.services.gateway_best_practices import raise_engineering_leadership_scores

    db = MagicMock()
    with patch(
        "app.services.control_plane_contract.resolve_control_readonly",
        return_value=True,
    ):
        with pytest.raises(HTTPException) as exc:
            raise_engineering_leadership_scores(
                db,
                actor_id="admin-freeze",
                enhance_cpli=True,
            )
    assert exc.value.status_code == 403
    detail = exc.value.detail
    assert isinstance(detail, dict)
    assert detail.get("error_code") == "PLANE_CONTROL_READONLY"
