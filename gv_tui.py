import os
import threading
import time
import re
from prompt_toolkit import Application
from prompt_toolkit.layout.containers import VSplit, HSplit, Window, WindowAlign
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.widgets import Button, TextArea, Label, Checkbox, Frame, Box
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.styles import Style
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.layout.dimension import D
from gv_decryptor import GalleryVaultDecryptor

class GalleryVaultTUI:
    def __init__(self):
        self.decryptor = GalleryVaultDecryptor(logger=self.log)
        self.running = False
        
        path_completer = PathCompleter(expanduser=True)
        self.path_input = TextArea(
            multiline=False, completer=path_completer,
            complete_while_typing=True, text=os.getcwd(), 
            style="class:input-field", focusable=True,
            accept_handler=self.handle_path_accept
        )
        
        self.output_input = TextArea(
            multiline=False, style="class:input-field",
            focusable=True, accept_handler=self.handle_output_accept
        )
        
        self.path_status = Label(text="System Ready.", style="class:status-valid")
        self.path_input.buffer.on_text_changed += self.validate_path
        
        self.smart_cb = Checkbox(text="Smart Vault Discovery", checked=True)
        self.recursive_cb = Checkbox(text="Recursive Search", checked=True)
        
        self.log_area = TextArea(
            read_only=True, scrollbar=True, wrap_lines=True, style="class:log-area"
        )
        
        self.progress_label = Label(text="Ready for recovery operations.", style="class:progress-idle")
        
        self.start_btn = Button("START RECOVERY", handler=self.start_task)
        self.clear_btn = Button("Clear Logs", handler=self.clear_logs)
        self.exit_btn = Button("Exit", handler=lambda: self.app.exit())
        
        body = HSplit([
            Box(Label(text=" GALLERY VAULT DECRYPTOR v4.6 ", style="class:header-text"), 
                style="class:header", height=1, padding=0),
            
            Frame(HSplit([
                VSplit([Label(text="Dump Root:   ", width=13), self.path_input]),
                VSplit([Window(width=13), self.path_status]),
                Window(height=1),
                VSplit([Label(text="Output Dir:  ", width=13), self.output_input]),
                Window(height=1),
                VSplit([self.smart_cb, Window(width=4), self.recursive_cb]),
                Window(height=1),
                VSplit([self.start_btn, Window(width=2), self.clear_btn, Window(width=2), self.exit_btn]),
            ]), title="Parameters", style="class:frame", height=D(min=10, max=12)),
            
            Frame(self.log_area, title="Activity Stream", style="class:frame"),
            Box(self.progress_label, style="class:progress-bar", height=1),
            
            VSplit([
                Label(text=" [Tab] Navigate | [F5] Start | [F10] Exit ", style="class:footer-text"),
                Label(text=" [STABLE VERSION] ", style="class:mode-text", align=WindowAlign.RIGHT),
            ], style="class:footer", height=1),
        ])

        self.kb = KeyBindings()
        @self.kb.add("f10")
        def _(event): event.app.exit()
        @self.kb.add("f5")
        def _(event): self.start_task()
        @self.kb.add("tab")
        def _(event): event.app.layout.focus_next()
        @self.kb.add("s-tab")
        def _(event): event.app.layout.focus_previous()

        self.style = Style.from_dict({
            "header": "bg:#002266 #ffffff bold",
            "footer": "bg:#111111 #888888",
            "footer-text": "fg:#00ff00 italic",
            "input-field": "bg:#111111 #ffffff",
            "input-field.focused": "bg:#333333 #ffffff bold",
            "button.focused": "bg:#00aa00 #000000 bold",
            "checkbox.focused": "bg:#00aa00 #000000",
            "frame.label": "#ffffff bold",
            "frame.border": "#444444",
            "status-valid": "fg:#00ff00",
            "status-invalid": "fg:#ff0000 bold",
            "progress-active": "fg:#ffff00 bold",
            "log-area": "bg:#000000 #00ff00",
        })

        self.app = Application(
            layout=Layout(body, focused_element=self.path_input),
            key_bindings=self.kb, style=self.style, full_screen=True, mouse_support=True
        )
        self.validate_path(None)

    def handle_path_accept(self, buffer):
        self.app.layout.focus(self.output_input)
        return True

    def handle_output_accept(self, buffer):
        self.app.layout.focus(self.start_btn)
        return True

    def validate_path(self, _):
        path = self.path_input.text.strip()
        if os.path.exists(path):
            self.path_status.text = "[Path Verified]"
            self.path_status.style = "class:status-valid"
        else:
            self.path_status.text = "[Path Not Found]"
            self.path_status.style = "class:status-invalid"

    def log(self, message):
        ts = time.strftime('%H:%M:%S')
        new_entry = f"[{ts}] {message}\n"
        def _update():
            self.log_area.text += new_entry
            self.log_area.buffer.cursor_position = len(self.log_area.text)
        if hasattr(self, 'app') and self.app.is_running:
            self.app.call_from_executor(_update)
        else:
            self.log_area.text += new_entry

    def clear_logs(self):
        self.log_area.text = ""

    def start_task(self):
        if self.running: return
        target = self.path_input.text.strip()
        if not os.path.exists(target): return
        self.running = True
        self.start_btn.text = "RUNNING"
        self.progress_label.style = "class:progress-active"
        threading.Thread(target=self.run_decryption, args=(target,), daemon=True).start()

    def run_decryption(self, target):
        try:
            files_to_process = []
            if self.smart_cb.checked:
                self.log(f"Hunting for repositories in: {target}")
                vault_pattern = re.compile(r"\.galleryvault_DoNotDelete_\d+")
                found_vaults = []
                for root, dirs, _ in os.walk(target):
                    for d in dirs:
                        if vault_pattern.match(d):
                            found_vaults.append(os.path.join(root, d))
                            self.log(f"Found repository: {d}")
                    if not self.recursive_cb.checked: break
                
                for v_path in found_vaults:
                    assets_root = os.path.join(v_path, "files")
                    if os.path.exists(assets_root):
                        for r, _, fns in os.walk(assets_root):
                            for f in fns:
                                if len(f) > 30: files_to_process.append(os.path.join(r, f))
            else:
                if os.path.isfile(target): files_to_process.append(target)
                else:
                    for r, _, fns in os.walk(target):
                        for f in fns:
                            if not f.endswith((".txt", ".dat", ".db", ".backup")):
                                files_to_process.append(os.path.join(r, f))
                        if not self.recursive_cb.checked: break

            total = len(files_to_process)
            if total == 0:
                self.log("No encrypted assets identified.")
                return

            self.log(f"Extracting {total} assets...")
            success = 0
            for i, f_path in enumerate(files_to_process, 1):
                self.progress_label.text = f"Recovery Progress: {i}/{total}"
                out_dir = self.output_input.text.strip()
                rel = os.path.relpath(f_path, target)
                f_out = os.path.join(out_dir or (target.rstrip("/") + "_recovered"), rel)
                
                ok, err = self.decryptor.decrypt_file(f_path, f_out)
                if ok:
                    self.log(f"RECOVERED: {os.path.basename(f_path)}")
                    success += 1
                else:
                    if err != "NOT_GV" and err != "SKIPPED":
                        self.log(f"FAIL ({os.path.basename(f_path)}): {err}")
                
            self.log(f"Completed. Assets recovered: {success}/{total}")
        except Exception as e:
            self.log(f"Critical Error: {str(e)}")
        finally:
            self.running = False
            self.start_btn.text = "START RECOVERY"
            self.progress_label.style = "class:progress-idle"
            self.progress_label.text = "Recovery session finished."
            if hasattr(self, 'app'): self.app.invalidate()

if __name__ == "__main__":
    tui = GalleryVaultTUI()
    tui.app.run()