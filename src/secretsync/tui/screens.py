"""Textual screens for validate → plan → confirm → execute → results."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
    Tree,
)
from textual.widgets.tree import TreeNode

from secretsync.application.apply import (
    ApplyReport,
    DestinationProgress,
    run_apply_async,
)
from secretsync.application.plan import plan_from_path_async
from secretsync.application.validate import ValidationResult, validate_config
from secretsync.domain.models import Plan, PlannedDelete, PlannedPut
from secretsync.presentation.json import render_apply_json

if TYPE_CHECKING:
    from secretsync.tui.app import SecretSyncApp


def _app(screen: Screen[Any]) -> SecretSyncApp:
    return screen.app  # type: ignore[return-value]


class ConfigScreen(Screen[None]):
    """Config path, validation issues, connector readiness."""

    BINDINGS = [("escape", "quit_app", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="body"):
            yield Label("Configuration", classes="title")
            yield Label("Config path")
            yield Input(value=str(_app(self).config_path), id="config-path")
            yield Label("Status: CHECK", id="status", classes="status-run")
            yield Static("Issues", classes="title")
            yield RichLog(id="issues", markup=False, highlight=False)
            with Horizontal(classes="button-row"):
                yield Button("Reload", id="reload", variant="default")
                yield Button("Continue", id="continue", variant="primary", disabled=True)
                yield Button("Quit", id="quit", variant="default")
        yield Footer()

    def on_mount(self) -> None:
        self.run_validation()

    def action_reload(self) -> None:
        self.run_validation()

    def action_quit_app(self) -> None:
        _app(self).action_quit_app()

    @on(Button.Pressed, "#reload")
    def on_reload_pressed(self) -> None:
        self.run_validation()

    @on(Button.Pressed, "#quit")
    def on_quit_pressed(self) -> None:
        _app(self).action_quit_app()

    @on(Button.Pressed, "#continue")
    def on_continue_pressed(self) -> None:
        self.app.push_screen(PlanScreen())

    def run_validation(self) -> None:
        path_input = self.query_one("#config-path", Input)
        path = Path(path_input.value.strip() or str(_app(self).config_path))
        _app(self).config_path = path.resolve()
        status = self.query_one("#status", Label)
        status.update("Status: CHECK — validating…")
        status.set_classes("status-run")
        self.query_one("#continue", Button).disabled = True
        self.query_one("#issues", RichLog).clear()
        self._validate_worker(path)

    @work(exclusive=True, group="validate")
    async def _validate_worker(self, path: Path) -> None:
        result = validate_config(_app(self).services, path)
        self._apply_validation_result(result)

    def _apply_validation_result(self, result: ValidationResult) -> None:
        log = self.query_one("#issues", RichLog)
        log.clear()
        status = self.query_one("#status", Label)
        cont = self.query_one("#continue", Button)
        if result.ok:
            status.update("Status: OK — config and env ready")
            status.set_classes("status-ok")
            cont.disabled = False
            log.write("No issues. Continue to review the always-write plan.")
        else:
            status.update(f"Status: FAIL — {len(result.issues)} issue(s)")
            status.set_classes("status-fail")
            cont.disabled = True
            for issue in result.issues:
                line = f"[{issue.code}] {issue.message}"
                if issue.hint:
                    line += f" ({issue.hint})"
                log.write(line)


class PlanScreen(Screen[None]):
    """Value-free plan tree (names and scopes only)."""

    BINDINGS = [("escape", "go_back", "Back")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="body"):
            yield Label("Plan (always-write)", classes="title")
            yield Checkbox(
                "Prune: delete remote secrets not listed in YAML",
                id="prune-toggle",
            )
            yield Label("Filter (destination / name / env)")
            yield Input(placeholder="filter…", id="filter-input")
            yield Tree("destinations", id="plan-tree")
            yield Label("", id="plan-summary")
            with Horizontal(classes="button-row"):
                yield Button("Back", id="back", variant="default")
                yield Button("Continue", id="continue", variant="primary", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#prune-toggle", Checkbox).value = _app(self).prune
        self._load_plan()

    def action_reload(self) -> None:
        self._load_plan()

    def action_go_back(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#back")
    def on_back(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#continue")
    def on_continue(self) -> None:
        self.app.push_screen(ConfirmScreen())

    @on(Checkbox.Changed, "#prune-toggle")
    def on_prune_changed(self, event: Checkbox.Changed) -> None:
        _app(self).prune = event.value
        self._load_plan()

    @on(Input.Changed, "#filter-input")
    def on_filter_changed(self, event: Input.Changed) -> None:
        plan = _app(self).plan
        if plan is not None:
            self._populate_tree(plan, event.value.strip().lower())

    @work(exclusive=True, group="plan")
    async def _load_plan(self) -> None:
        app = _app(self)
        plan, validation = await plan_from_path_async(
            app.services, app.config_path, prune=app.prune
        )
        if plan is None:
            self.query_one("#plan-summary", Label).update(
                f"Status: FAIL — cannot build plan ({validation.exit_code})"
            )
            self.query_one("#continue", Button).disabled = True
            return
        app.plan = plan
        app.retry_mutation_ids = None
        self._populate_tree(plan, self.query_one("#filter-input", Input).value.strip().lower())
        self.query_one("#plan-summary", Label).update(
            f"Status: OK — {len(plan.puts)} put(s), {len(plan.deletes)} delete(s), "
            f"strategy={plan.strategy}"
        )
        self.query_one("#continue", Button).disabled = False

    def _populate_tree(self, plan: Plan, needle: str) -> None:
        tree = self.query_one("#plan-tree", Tree)
        tree.clear()
        tree.root.expand()
        by_dest: dict[str, list[PlannedPut]] = defaultdict(list)
        deletes_by_dest: dict[str, list[PlannedDelete]] = defaultdict(list)
        for put in plan.puts:
            by_dest[put.target.destination_id].append(put)
        for deletion in plan.deletes:
            deletes_by_dest[deletion.target.destination_id].append(deletion)

        for dest_id in sorted(set(by_dest) | set(deletes_by_dest)):
            puts = by_dest.get(dest_id, [])
            dels = deletes_by_dest.get(dest_id, [])
            connector = (puts or dels)[0].target.connector_id
            visible_puts = [p for p in puts if self._matches_put(p, needle)]
            visible_dels = [d for d in dels if self._matches_delete(d, needle)]
            if needle and not visible_puts and not visible_dels:
                continue
            dest_node: TreeNode[None] = tree.root.add(
                f"{dest_id} [{connector}] — {len(visible_puts)} put(s), "
                f"{len(visible_dels)} delete(s)",
                expand=True,
            )
            by_deploy: dict[str, list[PlannedPut]] = defaultdict(list)
            for put in visible_puts:
                by_deploy[put.deployment_id].append(put)
            for deploy_id, deploy_puts in sorted(by_deploy.items()):
                deploy_node = dest_node.add(f"deployment: {deploy_id}", expand=True)
                for put in deploy_puts:
                    scope = dict(put.target.scope)
                    deploy_node.add_leaf(
                        f"put {put.target.name} ← {put.source.env_name} scope={scope}"
                    )
            if visible_dels:
                del_node = dest_node.add("deletes", expand=True)
                for deletion in visible_dels:
                    scope = dict(deletion.target.scope)
                    del_node.add_leaf(f"delete {deletion.target.name} scope={scope}")

    @staticmethod
    def _matches_put(put: PlannedPut, needle: str) -> bool:
        if not needle:
            return True
        hay = " ".join(
            [
                put.target.destination_id,
                put.target.connector_id,
                put.deployment_id,
                put.target.name,
                put.source.env_name,
                put.source.logical_id,
                str(dict(put.target.scope)),
            ]
        ).lower()
        return needle in hay

    @staticmethod
    def _matches_delete(deletion: PlannedDelete, needle: str) -> bool:
        if not needle:
            return True
        hay = " ".join(
            [
                deletion.target.destination_id,
                deletion.target.connector_id,
                deletion.deployment_id,
                deletion.target.name,
                str(dict(deletion.target.scope)),
                "delete",
            ]
        ).lower()
        return needle in hay


class ConfirmScreen(Screen[None]):
    """Counts, destinations, always-write warning."""

    BINDINGS = [("escape", "go_back", "Back")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="body"):
            yield Label("Confirm apply", classes="title")
            yield Label("", id="confirm-summary")
            yield Static(
                "WARNING: always-write — every listed secret will be written. "
                "Completed writes are not rolled back if later destinations fail.",
                classes="warning",
                id="always-write-warning",
            )
            yield Static(
                "WARNING: prune — remote secrets not listed in YAML for each "
                "destination scope will be deleted.",
                classes="warning",
                id="prune-warning",
            )
            yield RichLog(id="confirm-destinations", markup=False, highlight=False)
            with Horizontal(classes="button-row"):
                yield Button("Cancel", id="cancel", variant="default")
                yield Button("Apply", id="apply", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        app = _app(self)
        plan = app.plan
        if plan is None:
            self.query_one("#confirm-summary", Label).update("Status: FAIL — no plan loaded")
            self.query_one("#apply", Button).disabled = True
            return
        puts = plan.puts
        deletes = plan.deletes
        if app.retry_mutation_ids is not None:
            puts = tuple(p for p in puts if p.mutation_id in app.retry_mutation_ids)
            deletes = tuple(d for d in deletes if d.mutation_id in app.retry_mutation_ids)
        dests = sorted(
            {p.target.destination_id for p in puts} | {d.target.destination_id for d in deletes}
        )
        mode = "retry-failures" if app.retry_mutation_ids is not None else "full"
        self.query_one("#confirm-summary", Label).update(
            f"Status: READY — {len(puts)} put(s), {len(deletes)} delete(s) "
            f"across {len(dests)} destination(s) [{mode}]"
        )
        self.query_one("#prune-warning", Static).display = bool(deletes)
        log = self.query_one("#confirm-destinations", RichLog)
        log.clear()
        for dest in dests:
            put_count = sum(1 for p in puts if p.target.destination_id == dest)
            del_count = sum(1 for d in deletes if d.target.destination_id == dest)
            connector = next(
                (p.target.connector_id for p in puts if p.target.destination_id == dest),
                None,
            )
            if connector is None:
                connector = next(
                    d.target.connector_id for d in deletes if d.target.destination_id == dest
                )
            log.write(f"{dest} ({connector}): {put_count} put(s), {del_count} delete(s)")

    def action_go_back(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#cancel")
    def on_cancel(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#apply")
    def on_apply(self) -> None:
        self.app.push_screen(ExecutionScreen())


class ExecutionScreen(Screen[None]):
    """Per-destination progress via worker; cancel pending only."""

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="body"):
            yield Label("Execution", classes="title")
            yield Label("Status: RUN — applying…", id="exec-status", classes="status-run")
            yield Label("Applied: 0  Failed: 0  Skipped: 0", id="exec-counters")
            yield RichLog(id="progress-log", markup=False, highlight=False)
            with Horizontal(classes="button-row"):
                yield Button("Cancel pending", id="cancel", variant="error")
        yield Footer()

    @on(Button.Pressed, "#cancel")
    def on_cancel(self) -> None:
        for worker in list(self.workers):
            if getattr(worker, "group", "") == "apply" and worker.is_running:
                worker.cancel()
                self.query_one("#progress-log", RichLog).write(
                    "Cancel requested — in-flight destination writes may still complete; "
                    "completed writes are not rolled back."
                )
                break

    def on_mount(self) -> None:
        self._sum_applied = 0
        self._sum_failed = 0
        self._sum_skipped = 0
        self._apply_worker()

    @work(exclusive=True, group="apply")
    async def _apply_worker(self) -> None:
        app = _app(self)
        log = self.query_one("#progress-log", RichLog)

        def on_progress(event: DestinationProgress) -> None:
            self.call_later(self._handle_progress, event)

        try:
            report = await run_apply_async(
                app.services,
                app.config_path,
                confirm=False,
                max_concurrency=app.max_concurrency,
                on_destination_progress=on_progress,
                mutation_ids=app.retry_mutation_ids,
                prune=app.prune,
                run_id=app.run_id,
            )
        except Exception:  # noqa: BLE001 — map unexpected cancel/errors to interrupted report
            report = ApplyReport(
                exit_code=130,
                cancelled=True,
            )
            log.write("Apply interrupted.")

        app.report = report
        self._finish(report)

    def _handle_progress(self, event: DestinationProgress) -> None:
        log = self.query_one("#progress-log", RichLog)
        if event.phase == "started":
            log.write(f"RUN  {event.destination_id} ({event.connector})")
            return
        mark = "OK" if event.failed == 0 else "FAIL"
        log.write(
            f"{mark}  {event.destination_id}: "
            f"applied={event.applied} failed={event.failed} skipped={event.skipped}"
        )
        self._sum_applied = int(getattr(self, "_sum_applied", 0)) + event.applied
        self._sum_failed = int(getattr(self, "_sum_failed", 0)) + event.failed
        self._sum_skipped = int(getattr(self, "_sum_skipped", 0)) + event.skipped
        self.query_one("#exec-counters", Label).update(
            f"Applied: {self._sum_applied}  "
            f"Failed: {self._sum_failed}  "
            f"Skipped: {self._sum_skipped}"
        )

    def _finish(self, report: ApplyReport) -> None:
        status = self.query_one("#exec-status", Label)
        if report.cancelled:
            status.update("Status: INTERRUPTED — completed writes not rolled back")
            status.set_classes("status-fail")
        elif report.summary.failed:
            status.update(
                f"Status: FAIL — applied={report.summary.applied} "
                f"failed={report.summary.failed} exit={report.exit_code}"
            )
            status.set_classes("status-fail")
        else:
            status.update(f"Status: OK — applied={report.summary.applied} exit={report.exit_code}")
            status.set_classes("status-ok")
        self.query_one("#cancel", Button).disabled = True
        self.query_one("#exec-counters", Label).update(
            f"Applied: {report.summary.applied}  "
            f"Failed: {report.summary.failed}  "
            f"Skipped: {report.summary.skipped}"
        )
        self.app.push_screen(ResultsScreen())


class ResultsScreen(Screen[None]):
    """Per-mutation outcomes, retry failures, export JSON, quit."""

    BINDINGS = [("escape", "quit_app", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="body"):
            yield Label("Results", classes="title")
            yield Label("", id="results-summary")
            yield DataTable(id="results-table", zebra_stripes=True)
            yield Label("", id="export-status")
            with Horizontal(classes="button-row"):
                yield Button("Retry failures", id="retry", variant="warning", disabled=True)
                yield Button("Export JSON", id="export", variant="default")
                yield Button("Quit", id="quit", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        report = _app(self).report
        table = self.query_one("#results-table", DataTable)
        table.clear(columns=True)
        table.add_columns("Status", "Destination", "Mutation", "Effect", "Error", "Retryable")
        failed_ids: list[str] = []
        if report is None:
            self.query_one("#results-summary", Label).update("Status: FAIL — no report")
            return
        self.query_one("#results-summary", Label).update(
            f"Status: {'OK' if report.summary.failed == 0 and not report.cancelled else 'FAIL'} "
            f"— applied={report.summary.applied} failed={report.summary.failed} "
            f"skipped={report.summary.skipped} exit={report.exit_code}"
        )
        for block in report.destinations:
            for result in block.results:
                err = ""
                retryable = ""
                if result.error is not None:
                    err = f"{result.error.code}: {result.error.message}"
                    retryable = "yes" if result.error.retryable else "no"
                status_label = {
                    "applied": "OK",
                    "failed": "FAIL",
                    "skipped": "SKIP",
                }.get(result.status, result.status.upper())
                table.add_row(
                    status_label,
                    block.id,
                    result.mutation_id,
                    result.effect or "-",
                    err or "-",
                    retryable or "-",
                )
                if result.status == "failed":
                    failed_ids.append(result.mutation_id)
        self._failed_ids = frozenset(failed_ids)
        self.query_one("#retry", Button).disabled = not bool(failed_ids)

    def action_quit_app(self) -> None:
        _app(self).action_quit_app()

    @on(Button.Pressed, "#quit")
    def on_quit(self) -> None:
        _app(self).action_quit_app()

    @on(Button.Pressed, "#retry")
    def on_retry(self) -> None:
        failed: frozenset[str] = frozenset(getattr(self, "_failed_ids", frozenset()))
        if not failed:
            return
        app = _app(self)
        app.retry_mutation_ids = failed
        # Leave Results + Execution, then confirm filtered retry.
        self.app.pop_screen()
        if isinstance(self.app.screen, ExecutionScreen):
            self.app.pop_screen()
        self.app.push_screen(ConfirmScreen())

    @on(Button.Pressed, "#export")
    def on_export(self) -> None:
        report = _app(self).report
        status = self.query_one("#export-status", Label)
        if report is None:
            status.update("Status: FAIL — nothing to export")
            return
        out = Path.cwd() / "secretsync-apply-report.json"
        out.write_text(render_apply_json(report) + "\n")
        status.update(f"Status: OK — wrote {out.name} (value-free)")
