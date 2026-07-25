"""SecretSync Textual application shell."""

from __future__ import annotations

from pathlib import Path

from textual.app import App
from textual.binding import Binding

from secretsync import __version__
from secretsync.application.apply import ApplyReport
from secretsync.application.services import AppServices
from secretsync.domain.models import Plan
from secretsync.tui.screens import ConfigScreen


class SecretSyncApp(App[ApplyReport | None]):
    """Review/apply UI over the same AppServices as Click."""

    CSS_PATH = "secretsync.tcss"
    TITLE = "SecretSync"
    SUB_TITLE = f"v{__version__}"
    BINDINGS = [
        Binding("q", "quit_app", "Quit", show=True),
        Binding("r", "reload", "Reload", show=True),
    ]

    def __init__(
        self,
        services: AppServices,
        config_path: Path,
        *,
        max_concurrency: int = 4,
        prune: bool = False,
        run_id: str | None = None,
    ) -> None:
        from secretsync.infrastructure.audit import new_run_id

        super().__init__()
        self.services = services
        self.config_path = config_path.resolve()
        self.max_concurrency = max_concurrency
        self.prune = prune
        self.run_id = run_id or new_run_id()
        self.plan: Plan | None = None
        self.report: ApplyReport | None = None
        self.retry_mutation_ids: frozenset[str] | None = None

    def on_mount(self) -> None:
        self.push_screen(ConfigScreen())

    def action_quit_app(self) -> None:
        self.exit(self.report)

    def action_reload(self) -> None:
        screen = self.screen
        reload = getattr(screen, "action_reload", None)
        if callable(reload):
            reload()
