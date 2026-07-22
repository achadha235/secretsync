from __future__ import annotations

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_path(name: str) -> Path:
    return FIXTURES / name


FULL_ENV = {
    "YB_DATABASE_URL": "postgres://prod",
    "YB_STAGING_DATABASE_URL": "postgres://staging",
    "STRIPE_SECRET_KEY": "sk_test",
    "SENTRY_DSN": "https://sentry.example",
    "GITHUB_TOKEN": "ghp_test",
    "VERCEL_TOKEN": "vercel_test",
}
