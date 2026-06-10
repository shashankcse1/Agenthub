import os
from pathlib import Path
import subprocess
import sys


def _subprocess_env_with_pythonpath() -> dict:
    env = os.environ.copy()
    src_path = str(Path(__file__).resolve().parents[2] / "src")
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = f"{src_path}{os.pathsep}{existing}" if existing else src_path
    return env


def test_startup_fails_on_invalid_evidence_storage_mode(tmp_path) -> None:
    env = _subprocess_env_with_pythonpath()
    env["EVIDENCE_STORAGE_MODE"] = "invalid-mode"
    env["EVIDENCE_STORE_PATH"] = str(tmp_path / "evidence.jsonl")

    result = subprocess.run(
        [sys.executable, "-c", "import agent_platform.api.dependencies"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode != 0
    assert "Unsupported EVIDENCE_STORAGE_MODE" in (result.stderr + result.stdout)


def test_startup_succeeds_on_worm_evidence_storage_mode(tmp_path) -> None:
    env = _subprocess_env_with_pythonpath()
    env["EVIDENCE_STORAGE_MODE"] = "worm_json"
    env["EVIDENCE_STORE_PATH"] = str(tmp_path / "worm-events")

    result = subprocess.run(
        [sys.executable, "-c", "import agent_platform.api.dependencies"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0


def test_startup_fails_when_basic_auth_enabled_outside_local_modes(tmp_path) -> None:
    env = _subprocess_env_with_pythonpath()
    env["APP_ENV"] = "prod"
    env["ALLOW_BASIC_AUTH"] = "true"
    env["EVIDENCE_STORAGE_MODE"] = "append_jsonl"
    env["EVIDENCE_STORE_PATH"] = str(tmp_path / "evidence.jsonl")

    result = subprocess.run(
        [sys.executable, "-c", "import agent_platform.api.dependencies"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode != 0
    assert "ALLOW_BASIC_AUTH must remain disabled" in (result.stderr + result.stdout)