from __future__ import annotations

from secretsync.destinations.github_actions import GitHubActionsFactory
from secretsync.destinations.vercel import VercelFactory


def test_github_capabilities_individual() -> None:
    manifest = GitHubActionsFactory().manifest
    assert manifest.id == "github-actions"
    assert manifest.capabilities.put_batch.supported is False
    assert manifest.capabilities.read_values is False


def test_vercel_capabilities_batch() -> None:
    manifest = VercelFactory().manifest
    assert manifest.id == "vercel"
    assert manifest.capabilities.put_batch.supported is True
    assert manifest.capabilities.put_batch.max_items == 100
    assert manifest.capabilities.multiple_scopes_per_mutation is True


def test_sst_capabilities_env_file_pipe() -> None:
    from secretsync.destinations.sst import SstFactory

    manifest = SstFactory().manifest
    assert manifest.id == "sst"
    assert manifest.capabilities.put_batch.supported is True
    assert manifest.capabilities.put_batch.transport == "env-file-pipe"
    assert manifest.capabilities.multiple_scopes_per_mutation is False
