"""Plan/apply screen: shows a Tree of pending push steps and applies them
in a thread worker so the UI never blocks while ssh/local writes happen."""
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static, Tree

from ..executor import Executor


def step_label(step) -> str:
    if step.kind == "write-file":
        label = f"write {step.detail['path']} (stale: {', '.join(step.detail['stale'])})"
        if step.detail["missing"]:
            label += f" [no value yet: {', '.join(step.detail['missing'])}]"
        return label
    if step.kind == "command":
        return f"run {' '.join(step.detail['argv'])} <- {step.detail['stdin_secret']}"
    return f"exec {step.detail['cmd']}"


class PlanScreen(ModalScreen):
    def __init__(self, plan, scope: str | None = None) -> None:
        super().__init__()
        self.plan = plan
        self.scope = scope
        self._step_nodes = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            title = f"push plan — {self.scope}" if self.scope else "push plan"
            tree: Tree = Tree(title, id="plan-tree")
            tree.root.expand()
            for host, steps in self.plan.by_host().items():
                host_node = tree.root.add(host, expand=True)
                for step in steps:
                    self._step_nodes[id(step)] = host_node.add_leaf(step_label(step))
            yield tree
            yield Static("", id="plan-summary")
            yield Button("Apply", variant="primary", id="apply",
                         disabled=self.plan.is_empty())
            yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        event.button.disabled = True
        self.run_worker(self._apply, thread=True)

    def _apply(self) -> None:
        app = self.app
        values = {name: e["value"] for name, e in app.entries.items()}
        ex = Executor(values.__getitem__, ssh_options=app.settings.ssh_options)
        results = ex.execute(self.plan)
        ok_count = 0
        for r in results:
            node = self._step_nodes[id(r.step)]
            mark = "✓" if r.ok else "✗"
            app.call_from_thread(node.set_label, f"{mark} {step_label(r.step)} — {r.message}")
            if r.ok:
                ok_count += 1
                if r.step.kind == "write-file":
                    for logical in r.step.detail["env_keys"]:
                        app.state.record_push(logical, r.step.target)
                elif r.step.kind == "command":
                    app.state.record_push(r.step.detail["stdin_secret"], r.step.target)
        app.call_from_thread(
            self.query_one("#plan-summary", Static).update,
            f"{ok_count}/{len(results)} steps succeeded")
        app.call_from_thread(app.refresh_table)
