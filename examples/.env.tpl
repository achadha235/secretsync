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

SECRET_THREE_ORG_PROD="op://secretsync-example/org/api key production"
SECRET_THREE_ORG_STAGING="op://secretsync-example/org/api key staging"


PUBLIC_APP_URL_PROD="public-app-url-prod.com"
PUBLIC_APP_URL_STAGING="public-app-url-staging.com"

ORG_NAME="achadha-team"

LOG_LEVEL_PROD="info"
LOG_LEVEL_STAGING="debug"