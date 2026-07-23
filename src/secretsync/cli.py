"""Click CLI entrypoint."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

import anyio
import click
from loguru import logger

from secretsync.application.apply import run_apply
from secretsync.application.health import HealthReport, health_token_envs_from_config, run_health
from secretsync.application.plan import plan_from_path
from secretsync.application.selection import selection_extra
from secretsync.application.services import AppServices, create_services
from secretsync.application.validate import validate_config
from secretsync.domain.errors import EXIT_CONFIG, EXIT_OK
from secretsync.infrastructure.audit import record_audit
from secretsync.presentation.human import (
    render_apply_human,
    render_plan_human,
    render_validation_human,
)
from secretsync.presentation.json import (
    render_apply_json,
    render_plan_json,
    render_validation_json,
)


@dataclass(slots=True)
class AppContext:
    config_path: Path
    output_format: str
    services: AppServices
    deployments: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()


def _configure_logging(*, verbose: bool, quiet: bool) -> None:
    logger.remove()
    if quiet:
        level = "WARNING"
    elif verbose:
        level = "DEBUG"
    else:
        level = "INFO"
    logger.add(sys.stderr, level=level, format="{time:HH:mm:ss} | {level:<7} | {message}")


def _dep_set(ctx: AppContext) -> set[str] | None:
    return set(ctx.deployments) if ctx.deployments else None


def _dest_set(ctx: AppContext) -> set[str] | None:
    return set(ctx.destinations) if ctx.destinations else None


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config",
    type=click.Path(path_type=Path, exists=False),
    default="secretsync.yaml",
    show_default=True,
    help="Path to secretsync.yaml",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
)
@click.option("--verbose", "verbose", is_flag=True, help="Debug logging to stderr.")
@click.option("--quiet", "quiet", is_flag=True, help="Only warnings and errors.")
@click.option(
    "--deployment",
    "deployments",
    multiple=True,
    help="Limit to deployment name(s). Repeatable.",
)
@click.option(
    "--destination",
    "destinations",
    multiple=True,
    help="Limit to destination id(s). Repeatable.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    config: Path,
    output_format: str,
    verbose: bool,
    quiet: bool,
    deployments: tuple[str, ...],
    destinations: tuple[str, ...],
) -> None:
    """Declarative secret delivery across deployment platforms."""
    if verbose and quiet:
        raise click.UsageError("Use only one of --verbose / --quiet")
    _configure_logging(verbose=verbose, quiet=quiet)
    services = create_services(os.environ)
    ctx.obj = AppContext(
        config_path=config,
        output_format=output_format,
        services=services,
        deployments=deployments,
        destinations=destinations,
    )


@cli.command("init")
@click.pass_obj
def init_cmd(ctx: AppContext) -> None:
    """Create secretsync.yaml and .env.secretsync.tpl in the current directory."""
    from secretsync.init_templates import ENV_SECRETSYNC_TPL, SECRETSYNC_YAML

    cwd = Path.cwd()
    yaml_path = cwd / "secretsync.yaml"
    tpl_path = cwd / ".env.secretsync.tpl"
    if yaml_path.exists():
        click.echo(
            f"Refusing to overwrite existing {yaml_path.name}. "
            "Remove it or run init in an empty directory.",
            err=True,
        )
        record_audit(command="init", config_path=yaml_path, exit_code=EXIT_CONFIG, cwd=cwd)
        raise SystemExit(EXIT_CONFIG)

    yaml_path.write_text(SECRETSYNC_YAML, encoding="utf-8")
    logger.info("Wrote {}", yaml_path)
    click.echo(f"Created {yaml_path.name}")
    if tpl_path.exists():
        click.echo(f"Left existing {tpl_path.name} unchanged")
    else:
        tpl_path.write_text(ENV_SECRETSYNC_TPL, encoding="utf-8")
        logger.info("Wrote {}", tpl_path)
        click.echo(f"Created {tpl_path.name}")
    record_audit(command="init", config_path=yaml_path, exit_code=EXIT_OK, cwd=cwd)
    raise SystemExit(EXIT_OK)


@cli.command("validate")
@click.pass_obj
def validate_cmd(ctx: AppContext) -> None:
    """Parse, compose, and check environment presence without remote writes."""
    result = validate_config(
        ctx.services,
        ctx.config_path,
        deployments=_dep_set(ctx),
        destinations=_dest_set(ctx),
    )
    if ctx.output_format == "json":
        click.echo(render_validation_json(result))
    else:
        click.echo(render_validation_human(result))
    record_audit(
        command="validate",
        config_path=ctx.config_path if ctx.config_path.exists() else None,
        exit_code=result.exit_code,
        extra=selection_extra(ctx.deployments, ctx.destinations),
    )
    raise SystemExit(result.exit_code)


@cli.command("plan")
@click.pass_obj
def plan_cmd(ctx: AppContext) -> None:
    """Produce a value-free always-write plan."""
    plan, result = plan_from_path(
        ctx.services,
        ctx.config_path,
        deployments=_dep_set(ctx),
        destinations=_dest_set(ctx),
    )
    if plan is None:
        if ctx.output_format == "json":
            click.echo(render_validation_json(result))
        else:
            click.echo(render_validation_human(result))
        record_audit(
            command="plan",
            config_path=ctx.config_path if ctx.config_path.exists() else None,
            exit_code=result.exit_code,
            extra=selection_extra(ctx.deployments, ctx.destinations),
        )
        raise SystemExit(result.exit_code)
    if ctx.output_format == "json":
        click.echo(render_plan_json(plan))
    else:
        click.echo(render_plan_human(plan))
    record_audit(
        command="plan",
        config_path=ctx.config_path,
        exit_code=EXIT_OK,
        extra=selection_extra(ctx.deployments, ctx.destinations) + f" puts={len(plan.puts)}",
    )
    raise SystemExit(EXIT_OK)


@cli.command("apply")
@click.option("--yes", is_flag=True, help="Skip interactive confirmation.")
@click.option("--max-concurrency", type=click.IntRange(1, 32), default=4, show_default=True)
@click.pass_obj
def apply_cmd(ctx: AppContext, yes: bool, max_concurrency: int) -> None:
    """Rebuild plan, resolve values, and apply destination mutations."""
    report = run_apply(
        ctx.services,
        config_path=ctx.config_path,
        confirm=not yes,
        max_concurrency=max_concurrency,
        deployments=_dep_set(ctx),
        destinations=_dest_set(ctx),
    )
    if ctx.output_format == "json":
        click.echo(render_apply_json(report))
    else:
        click.echo(render_apply_human(report))
    record_audit(
        command="apply",
        config_path=ctx.config_path if ctx.config_path.exists() else None,
        exit_code=report.exit_code,
        extra=(
            selection_extra(ctx.deployments, ctx.destinations)
            + f" applied={report.summary.applied} failed={report.summary.failed}"
        ),
    )
    raise SystemExit(report.exit_code)


@cli.command("health")
@click.pass_obj
def health_cmd(ctx: AppContext) -> None:
    """Check connector auth / reachability for env vars that are set."""
    github_env, vercel_env = health_token_envs_from_config(ctx.config_path, ctx.services.environ)

    async def _run() -> HealthReport:
        return await run_health(
            ctx.services.environ,
            github_token_env=github_env,
            vercel_token_env=vercel_env,
        )

    report: HealthReport = anyio.run(_run)
    for item in report.results:
        click.echo(item.message)
    record_audit(
        command="health",
        config_path=ctx.config_path if ctx.config_path.exists() else None,
        exit_code=report.exit_code,
    )
    raise SystemExit(report.exit_code)


@cli.command("ui")
@click.pass_obj
def ui_cmd(ctx: AppContext) -> None:
    """Open Textual review/apply interface."""
    if ctx.output_format == "json":
        click.echo(
            "JSON mode bypasses Textual; use: secretsync apply --yes --format json",
            err=True,
        )
        raise SystemExit(EXIT_CONFIG)
    from secretsync.tui.app import SecretSyncApp

    app = SecretSyncApp(services=ctx.services, config_path=ctx.config_path)
    report = app.run()
    code = report.exit_code if report is not None else EXIT_OK
    record_audit(
        command="ui",
        config_path=ctx.config_path if ctx.config_path.exists() else None,
        exit_code=code,
    )
    raise SystemExit(code)


@cli.command("connectors")
@click.pass_obj
def connectors_cmd(ctx: AppContext) -> None:
    """List built-in connector IDs, versions, and capabilities."""
    manifests = ctx.services.connectors.list_manifests()
    if ctx.output_format == "json":
        import json

        click.echo(json.dumps({"schemaVersion": 1, "connectors": manifests}, indent=2))
    else:
        click.echo("Built-in connectors:")
        for item in manifests:
            click.echo(f"  - {item['id']} ({item['version']}) [{item['status']}]")
    raise SystemExit(EXIT_OK)


def main() -> None:
    cli(prog_name="secretsync")


if __name__ == "__main__":
    main()
    sys.exit(0)
