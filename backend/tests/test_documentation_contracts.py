import ast
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

from backend.app.core.notifier import DiscordNotifier
from backend.app.main import app, health


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _dotenv_items(path):
    items = {}
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        items[key.strip()] = value.strip()
    return items


def _config_getenv_keys():
    tree = ast.parse((PROJECT_ROOT / "backend/app/config.py").read_text())
    keys = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        is_os_getenv = (
            isinstance(func, ast.Attribute)
            and func.attr == "getenv"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        )
        if not is_os_getenv or not node.args:
            continue

        first_arg = node.args[0]
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            keys.add(first_arg.value)

    return keys


def test_health_endpoint_handler_returns_documented_status():
    assert asyncio.run(health()) == {"status": "ok"}


def test_health_endpoint_is_registered_for_get_requests():
    matching_routes = [
        route
        for route in app.routes
        if getattr(route, "path", None) == "/health" and "GET" in route.methods
    ]

    assert matching_routes, "Expected GET /health to be registered on the FastAPI app"


def test_discord_alert_card_supports_readme_field_contract():
    notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
    fields = [
        {"name": "Feed source", "value": "AbuseIPDB", "inline": True},
        {"name": "Threat indicator", "value": "203.0.113.42", "inline": True},
        {"name": "Indicator type", "value": "ip", "inline": True},
        {"name": "Country context", "value": "ZA", "inline": True},
        {"name": "Total threats available from the feed", "value": "128", "inline": True},
    ]

    card = notifier.format_card(
        title="Threat Detected",
        description="Threat intelligence indicator collected from a public feed.",
        severity="high",
        fields=fields,
    )

    assert [field["name"] for field in card["fields"]] == [
        "Feed source",
        "Threat indicator",
        "Indicator type",
        "Country context",
        "Total threats available from the feed",
    ]


@patch("backend.app.core.notifier.requests.post")
def test_discord_alert_payload_wraps_documented_card_as_embed(mock_post):
    mock_post.return_value = MagicMock(status_code=204)
    notifier = DiscordNotifier(webhook_url="https://hooks.example.com")
    card = notifier.format_card(
        title="Threat Detected",
        description="Public threat feed update.",
        severity="critical",
        fields=[{"name": "Feed source", "value": "AlienVault OTX", "inline": True}],
    )

    assert notifier.send_alert(card) is True

    mock_post.assert_called_once_with(
        "https://hooks.example.com",
        json={"embeds": [card]},
    )


def test_env_example_covers_environment_variables_used_by_config():
    env_example_keys = set(_dotenv_items(PROJECT_ROOT / ".env.example"))

    assert _config_getenv_keys() <= env_example_keys


def test_env_example_keeps_sensitive_values_blank():
    env_items = _dotenv_items(PROJECT_ROOT / ".env.example")
    sensitive_keys = {
        key
        for key in env_items
        if key.endswith("API_KEY") or key.endswith("WEBHOOK_URL") or key.endswith("PASSWORD")
    }

    assert sensitive_keys
    assert all(env_items[key] == "" for key in sensitive_keys)


def test_gitignore_excludes_local_env_file():
    ignored_patterns = {
        line.strip()
        for line in (PROJECT_ROOT / ".gitignore").read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    }

    assert ".env" in ignored_patterns


def test_docker_compose_defines_postgres_database_service():
    compose_text = (PROJECT_ROOT / "docker-compose.yml").read_text()

    assert "postgres:16" in compose_text
    assert "POSTGRES_DB" in compose_text
    assert "5432:5432" in compose_text
