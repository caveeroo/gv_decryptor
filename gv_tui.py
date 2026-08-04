import asyncio
import os
import threading
import time
from collections import Counter
from collections.abc import Callable

from prompt_toolkit import Application
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import HSplit, VSplit, Window, WindowAlign
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.styles import Style
from prompt_toolkit.widgets import Box, Button, Checkbox, Frame, Label, TextArea

from gv_decryptor import (
    GalleryVaultDecryptor,
    default_output_dir,
    discover_files,
    output_base_for,
)


class GalleryVaultTUI:
    def __init__(self) -> None:
        self.decryptor = GalleryVaultDecryptor()
        self.running = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event = threading.Event()
        self._last_default_output = ""

        path_completer = PathCompleter(expanduser=True)
        self.path_input = TextArea(
            multiline=False,
            completer=path_completer,
            complete_while_typing=True,
            text=os.getcwd(),
            style="class:input-field",
            focusable=True,
            accept_handler=self.handle_path_accept,
        )
        self.output_input = TextArea(
            multiline=False,
            completer=path_completer,
            complete_while_typing=True,
            style="class:input-field",
            focusable=True,
            accept_handler=self.handle_output_accept,
        )

        self.path_status = Label(text="Checking path...", style="class:status-valid")
        self.path_input.buffer.on_text_changed += self.validate_path

        self.smart_cb = Checkbox(text="Smart Vault Discovery", checked=True)
        self.recursive_cb = Checkbox(text="Recursive Search", checked=True)
        self.overwrite_cb = Checkbox(text="Overwrite Existing", checked=False)

        self.log_area = TextArea(
            read_only=True,
            scrollbar=True,
            wrap_lines=True,
            style="class:log-area",
        )
        self.progress_label = Label(
            text="Ready for recovery operations.", style="class:progress-idle"
        )

        self.start_btn = Button("RECOVER", handler=self.start_task, width=14)
        self.clear_btn = Button("Clear Logs", handler=self.clear_logs, width=14)
        self.exit_btn = Button("Exit", handler=self.request_exit, width=12)

        body = HSplit(
            [
                Box(
                    Label(text=" GALLERY VAULT DECRYPTOR ", style="class:header-text"),
                    style="class:header",
                    height=1,
                    padding=0,
                ),
                Frame(
                    HSplit(
                        [
                            VSplit(
                                [Label(text="Dump Root:   ", width=13), self.path_input]
                            ),
                            VSplit([Window(width=13), self.path_status]),
                            Window(height=1),
                            VSplit(
                                [
                                    Label(text="Output Dir:  ", width=13),
                                    self.output_input,
                                ]
                            ),
                            Window(height=1),
                            VSplit(
                                [
                                    self.smart_cb,
                                    Window(width=3),
                                    self.recursive_cb,
                                ]
                            ),
                            VSplit([self.overwrite_cb]),
                            Window(height=1),
                            VSplit(
                                [
                                    self.start_btn,
                                    Window(width=2),
                                    self.clear_btn,
                                    Window(width=2),
                                    self.exit_btn,
                                ]
                            ),
                        ]
                    ),
                    title="Parameters",
                    style="class:frame",
                    height=D(min=11, max=13),
                ),
                Frame(self.log_area, title="Activity Stream", style="class:frame"),
                Box(self.progress_label, style="class:progress-bar", height=1),
                VSplit(
                    [
                        Label(
                            text=" [Tab] Navigate | [F5] Recover | [F10] Stop/Exit ",
                            style="class:footer-text",
                        ),
                        Label(
                            text=" [V2 RECOVERY] ",
                            style="class:mode-text",
                            align=WindowAlign.RIGHT,
                        ),
                    ],
                    style="class:footer",
                    height=1,
                ),
            ]
        )

        self.kb = KeyBindings()

        @self.kb.add("f10")
        def _exit_or_stop(event) -> None:
            self.request_exit()

        @self.kb.add("f5")
        def _start(event) -> None:
            self.start_task()

        @self.kb.add("tab")
        def _next(event) -> None:
            event.app.layout.focus_next()

        @self.kb.add("s-tab")
        def _previous(event) -> None:
            event.app.layout.focus_previous()

        self.style = Style.from_dict(
            {
                "header": "bg:#002266 #ffffff bold",
                "footer": "bg:#111111 #888888",
                "footer-text": "fg:#00ff00 italic",
                "mode-text": "fg:#888888",
                "input-field": "bg:#111111 #ffffff",
                "input-field.focused": "bg:#333333 #ffffff bold",
                "button.focused": "bg:#00aa00 #000000 bold",
                "checkbox.focused": "bg:#00aa00 #000000",
                "frame.label": "#ffffff bold",
                "frame.border": "#444444",
                "status-valid": "fg:#00ff00",
                "status-invalid": "fg:#ff0000 bold",
                "progress-active": "fg:#ffff00 bold",
                "progress-idle": "fg:#aaaaaa",
                "progress-bar": "bg:#111111",
                "log-area": "bg:#000000 #00ff00",
            }
        )

        self.app = Application(
            layout=Layout(body, focused_element=self.path_input),
            key_bindings=self.kb,
            style=self.style,
            full_screen=True,
            mouse_support=True,
        )
        self.validate_path(None)

    def handle_path_accept(self, buffer) -> bool:
        self.app.layout.focus(self.output_input)
        return True

    def handle_output_accept(self, buffer) -> bool:
        self.app.layout.focus(self.start_btn)
        return True

    def validate_path(self, _) -> None:
        raw_path = self.path_input.text.strip()
        path = os.path.abspath(os.path.expanduser(raw_path)) if raw_path else ""
        new_default = default_output_dir(path) if path else ""
        if (
            not self.output_input.text
            or self.output_input.text == self._last_default_output
        ):
            self.output_input.text = new_default
        self._last_default_output = new_default

        if os.path.isfile(path):
            self.path_status.text = "[Encrypted file selected]"
            self.path_status.style = "class:status-valid"
        elif os.path.isdir(path):
            self.path_status.text = "[Directory verified]"
            self.path_status.style = "class:status-valid"
        else:
            self.path_status.text = "[Path not found]"
            self.path_status.style = "class:status-invalid"

    def _call_in_ui(self, callback: Callable[[], None]) -> None:
        if self._loop and self._loop.is_running():
            try:
                self._loop.call_soon_threadsafe(callback)
                return
            except RuntimeError:
                pass
        callback()

    def log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}\n"

        def update() -> None:
            self.log_area.text += entry
            self.log_area.buffer.cursor_position = len(self.log_area.text)
            self.app.invalidate()

        self._call_in_ui(update)

    def clear_logs(self) -> None:
        self.log_area.text = ""

    def _set_progress(self, text: str, active: bool = True) -> None:
        def update() -> None:
            self.progress_label.text = text
            self.progress_label.style = (
                "class:progress-active" if active else "class:progress-idle"
            )
            self.app.invalidate()

        self._call_in_ui(update)

    def start_task(self) -> None:
        if self.running:
            self.log("Recovery is already running.")
            return

        raw_target = self.path_input.text.strip()
        if not raw_target:
            self.log("Select an input file or directory first.")
            return
        target = os.path.abspath(os.path.expanduser(raw_target))
        output_dir = os.path.abspath(
            os.path.expanduser(
                self.output_input.text.strip() or default_output_dir(target)
            )
        )
        if not os.path.exists(target):
            self.log(f"Input path does not exist: {target}")
            return
        if os.path.exists(output_dir) and not os.path.isdir(output_dir):
            self.log(f"Output path is not a directory: {output_dir}")
            return
        if os.path.isdir(target) and os.path.realpath(target) == os.path.realpath(
            output_dir
        ):
            self.log("Output directory must be different from the input directory.")
            return

        self._loop = asyncio.get_running_loop()
        self._stop_event.clear()
        self.running = True
        self.start_btn.text = "RUNNING"
        self.exit_btn.text = "Stop"
        self.progress_label.style = "class:progress-active"
        self.path_input.read_only = True
        self.output_input.read_only = True

        options = (
            target,
            output_dir,
            self.smart_cb.checked,
            self.recursive_cb.checked,
            self.overwrite_cb.checked,
        )
        threading.Thread(
            target=self.run_decryption,
            args=options,
            daemon=False,
            name="gallery-vault-recovery",
        ).start()

    def request_exit(self) -> None:
        if self.running:
            self._stop_event.set()
            self.exit_btn.text = "Stopping"
            self.log("Stop requested; cleaning up the current output file.")
            return
        self.app.exit()

    def run_decryption(
        self,
        target: str,
        output_dir: str,
        smart: bool,
        recursive: bool,
        overwrite: bool,
    ) -> None:
        cancelled = False
        counts: Counter[str] = Counter()
        try:
            mode = "smart discovery" if smart else "all-file scan"
            self.log(f"Starting {mode}: {target}")
            discovery = discover_files(
                target,
                smart=smart,
                recursive=recursive,
                output_dir=output_dir,
            )
            for vault in discovery.vaults:
                self.log(f"Found repository: {vault}")

            total = len(discovery.files)
            if total == 0:
                self.log("No candidate assets found.")
                return

            self.log(f"Processing {total} candidate assets into: {output_dir}")
            for index, input_path in enumerate(discovery.files, 1):
                if self._stop_event.is_set():
                    cancelled = True
                    break

                percent = int(index * 100 / total)
                self._set_progress(
                    f"Recovery progress: {index}/{total} ({percent}%) | "
                    f"recovered={counts['RECOVERED']} processed={sum(counts.values())}"
                )
                output_base = output_base_for(input_path, target, output_dir)
                result = self.decryptor.decrypt_file(
                    input_path,
                    output_base,
                    overwrite=overwrite,
                    should_cancel=self._stop_event.is_set,
                )
                counts[result.status] += 1

                if result.ok:
                    self.log(
                        f"RECOVERED: {os.path.basename(input_path)} -> {result.output_path}"
                    )
                elif result.status == "CANCELLED":
                    cancelled = True
                    break
                elif result.status not in {"NOT_GV", "TOO_SMALL"}:
                    self.log(
                        f"{result.status}: {os.path.basename(input_path)}"
                        + (f" ({result.error})" if result.error else "")
                    )

            skipped = counts["NOT_GV"] + counts["TOO_SMALL"]
            failed = sum(counts.values()) - counts["RECOVERED"] - skipped
            if cancelled:
                self.log("Recovery stopped by user.")
            self.log(
                f"Completed: recovered={counts['RECOVERED']} "
                f"skipped={skipped} failed={failed}"
            )
        # Surface unexpected worker failures in the TUI instead of losing the thread.
        except Exception as error:  # noqa: BLE001
            self.log(f"Critical error: {error}")
        finally:

            def finish() -> None:
                self.running = False
                self.start_btn.text = "RECOVER"
                self.exit_btn.text = "Exit"
                self.path_input.read_only = False
                self.output_input.read_only = False
                self.progress_label.style = "class:progress-idle"
                self.progress_label.text = (
                    "Recovery stopped." if cancelled else "Recovery session finished."
                )
                self.app.invalidate()

            self._call_in_ui(finish)


if __name__ == "__main__":
    GalleryVaultTUI().app.run()
