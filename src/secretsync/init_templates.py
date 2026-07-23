"""Static string templates for `secretsync init`."""

from __future__ import annotations

SECRETSYNC_YAML = """\
version: 1
changeDetection: always-write

secrets:
  secretOneProd:
    env: SECRET_ONE_PROD
  secretOneStaging:
    env: SECRET_ONE_STAGING
  secretTwoCommon:
    env: SECRET_TWO_COMMON

sets:
  common:
    include: [secretTwoCommon]
  production:
    extends: common
    include: [secretOneProd]
  staging:
    extends: common
    include: [secretOneStaging]

destinations:
  github:
    connector: github-actions
    repository: owner/repo
    auth:
      tokenEnv: GITHUB_TOKEN
  vercel:
    connector: vercel
    project: my-project
    auth:
      tokenEnv: VERCEL_TOKEN
  sst:
    connector: sst
    workingDirectory: .
    executable: sst

deployments:
  - name: github-production
    set: production
    destination: github
    scope:
      kind: environment
      environment: production
    secrets:
      secretOneProd: SECRET_ONE
      secretTwoCommon: SECRET_TWO
  - name: github-staging
    set: staging
    destination: github
    scope:
      kind: environment
      environment: staging
    secrets:
      secretOneStaging: SECRET_ONE
      secretTwoCommon: SECRET_TWO
  - name: vercel-production
    set: production
    destination: vercel
    scope:
      targets: [production]
      sensitive: true
    secrets:
      secretOneProd: SECRET_ONE
      secretTwoCommon: SECRET_TWO
  - name: sst-staging
    set: staging
    destination: sst
    scope:
      stage: staging
      fallback: false
    secrets:
      secretOneStaging: SecretOne
      secretTwoCommon: SecretTwo
"""

ENV_SECRETSYNC_TPL = """\
# Connector auth (inject via `op run --env-file=.env.secretsync` or your vault)
GITHUB_TOKEN=op://vault/github/token
VERCEL_TOKEN=op://vault/vercel/token
# Prefer a named profile for SST/AWS:
AWS_PROFILE=default
AWS_REGION=us-east-1
# Or explicit keys instead of AWS_PROFILE:
# AWS_ACCESS_KEY_ID=op://vault/aws/access-key-id
# AWS_SECRET_ACCESS_KEY=op://vault/aws/secret-access-key

# App secrets referenced by secretsync.yaml
SECRET_ONE_PROD=op://vault/app/secret-one-prod
SECRET_ONE_STAGING=op://vault/app/secret-one-staging
SECRET_TWO_COMMON=op://vault/app/secret-two-common
"""
