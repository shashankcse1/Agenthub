from pathlib import Path


ROOT = Path(__file__).resolve().parents[2] / "src" / "platform"


def _read_py_files(path: Path):
    return [p.read_text() for p in path.rglob("*.py") if p.is_file()]


def test_domain_does_not_depend_on_fastapi_or_pydantic() -> None:
    domain_text = "\n".join(_read_py_files(ROOT / "domain"))
    assert "fastapi" not in domain_text
    assert "pydantic" not in domain_text


def test_application_does_not_depend_on_api_layer() -> None:
    app_text = "\n".join(_read_py_files(ROOT / "application"))
    assert "agent_platform.api" not in app_text
