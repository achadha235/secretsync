# Connector auth (inject via `op run --env-file=.env.secretsync` or your vault)
GITHUB_TOKEN="op://secretsync/GitHub/personal access token"

# App secrets referenced by secretsync.yaml
UV_PUBLISH_TOKEN="op://secretsync/PyPI/api token"