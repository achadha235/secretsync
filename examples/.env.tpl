# Connector auth (inject via `op run --env-file=.env.secretsync` or your vault)
GITHUB_TOKEN="op://secretsync-example/GitHub/personal access token"
VERCEL_TOKEN="op://secretsync-example/Vercel/token"
# Prefer a named profile for SST/AWS:
AWS_PROFILE="secretsync-example"
AWS_REGION="us-east-1"

# App secrets referenced by secretsync.yaml
SECRET_ONE_PROD="op://secretsync-example/production/secret one"
SECRET_ONE_STAGING="op://secretsync-example/staging/secret one"
SECRET_TWO_COMMON="op://secretsync-example/common/secret two"
