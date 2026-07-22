"""Click CLI entrypoint."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

import click

from secretsync.application.apply import run_apply
from secretsync.application.plan import plan_from_path
from secretsync.application.services import AppServices, create_services
from secretsync.application.validate import validate_config
from secretsync.domain.errors import EXIT_CONFIG, EXIT_OK
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
@click.pass_context
def cli(ctx: click.Context, config: Path, output_format: str) -> None:
    """Declarative secret delivery across deployment platforms."""
    services = create_services(os.environ)
    ctx.obj = AppContext(config_path=config, output_format=output_format, services=services)


@cli.command("validate")
@click.pass_obj
def validate_cmd(ctx: AppContext) -> None:
    """Parse, compose, and check environment presence without remote writes."""
    result = validate_config(ctx.services, ctx.config_path)
    if ctx.output_format == "json":
        click.echo(render_validation_json(result))
    else:
        click.echo(render_validation_human(result))
    raise SystemExit(result.exit_code)


@cli.command("plan")
@click.pass_obj
def plan_cmd(ctx: AppContext) -> None:
    """Produce a value-free always-write plan."""
    plan, result = plan_from_path(ctx.services, ctx.config_path)
    if plan is None:
        if ctx.output_format == "json":
            click.echo(render_validation_json(result))
        else:
            click.echo(render_validation_human(result))
        raise SystemExit(result.exit_code)
    if ctx.output_format == "json":
        click.echo(render_plan_json(plan))
    else:
        click.echo(render_plan_human(plan))
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
    )
    if ctx.output_format == "json":
        click.echo(render_apply_json(report))
    else:
        click.echo(render_apply_human(report))
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
    raise SystemExit(report.exit_code if report is not None else EXIT_OK)


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
