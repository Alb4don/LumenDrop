from __future__ import annotations

import dataclasses
import logging
import os
import queue
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Callable

import qrcode

from lumendrop import APP_VERSION
from lumendrop.config import Settings
from lumendrop.i18n import FOLDER_REJECTION_REASONS, GUI_STRINGS
from lumendrop.netinfo import LocalAddress, discover_addresses
from lumendrop.paths import FolderRejected
from lumendrop.server import ServerController, is_elevated_privileges

MAX_LOG_LINES = 2000
MAX_LOG_LINES_PER_TICK = 300


def generate_qr_image(data: str, size: int = 200):
    qr = qrcode.QRCode(border=2, box_size=8, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB").resize((size, size))


def open_in_file_manager(path: Path) -> None:
    target = str(path)
    if sys.platform == "win32":
        os.startfile(target)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.Popen(["xdg-open", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_gui(settings: Settings, logger: logging.Logger, log_queue: "queue.Queue[str]") -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    from tkinter.scrolledtext import ScrolledText

    import ttkbootstrap as ttk
    from PIL import ImageTk
    from ttkbootstrap.constants import BOTH, LEFT, RIGHT, W, X, YES

    class LumenDropGUI:
        def __init__(self) -> None:
            self.lang = "en"
            self.settings = settings
            self.controller: ServerController | None = None
            self.event_queue = None
            self.ui_queue: "queue.Queue[Callable[[], None]]" = queue.Queue()
            self.qr_photo = None
            self.addresses: list[LocalAddress] = []
            self.busy = False
            self.pin_visible = False
            self.elevated = is_elevated_privileges() and not settings.allow_root

            self.root = ttk.Window(themename="darkly")
            self.root.title(self.t("window_title_ver").format(version=APP_VERSION))
            self.root.geometry("860x780")
            self.root.minsize(720, 640)
            self.root.protocol("WM_DELETE_WINDOW", self.on_close)

            self.folder_var = tk.StringVar(value=str(settings.share_folder))
            self.port_var = tk.StringVar(value=str(settings.port))
            self.interface_var = tk.StringVar(value="")
            self.host_var = tk.StringVar(value="")
            self.pin_var = tk.StringVar(value="•" * settings.policy.pin_length)
            self.fingerprint_var = tk.StringVar(value="")
            self.status_var = tk.StringVar(value=self.t("status_stopped"))
            self.stats_var = tk.StringVar(value="")
            self.lang_var = tk.StringVar(value="English")
            self.real_pin = ""

            self._build_layout()
            if self.elevated:
                self.root_warning_label.configure(text=self.t("root_warning"))
            self.refresh_interfaces()
            self.root.after(150, self.poll_queues)
            self.root.after(2000, self.refresh_stats)

        def t(self, key: str) -> str:
            return GUI_STRINGS[self.lang][key]

        def run_background(self, work: Callable[[], object], done: Callable[[object, BaseException | None], None]) -> None:
            def runner() -> None:
                try:
                    result = work()
                    error = None
                except BaseException as exc:
                    result, error = None, exc
                self.ui_queue.put(lambda: done(result, error))

            threading.Thread(target=runner, daemon=True).start()

        def _build_layout(self) -> None:
            top = ttk.Frame(self.root, padding=10)
            top.pack(fill=X)
            self.title_label = ttk.Label(top, text=self.t("window_title"), font=("TkDefaultFont", 14, "bold"))
            self.title_label.pack(side=LEFT)
            self.lang_combo = ttk.Combobox(
                top, textvariable=self.lang_var, values=["English", "Português (BR)"], state="readonly", width=16,
            )
            self.lang_combo.pack(side=RIGHT)
            self.lang_combo.bind("<<ComboboxSelected>>", self.on_lang_change)
            self.lang_label = ttk.Label(top, text=self.t("language_label"))
            self.lang_label.pack(side=RIGHT, padx=(0, 6))

            self.notebook = ttk.Notebook(self.root)
            self.notebook.pack(fill=BOTH, expand=YES, padx=10, pady=(0, 10))
            self.tab_server = ttk.Frame(self.notebook, padding=14)
            self.tab_security = ttk.Frame(self.notebook, padding=14)
            self.tab_logs = ttk.Frame(self.notebook, padding=14)
            self.notebook.add(self.tab_server, text=self.t("tab_server"))
            self.notebook.add(self.tab_security, text=self.t("tab_security"))
            self.notebook.add(self.tab_logs, text=self.t("tab_logs"))
            self._build_server_tab()
            self._build_security_tab()
            self._build_logs_tab()

        def _build_server_tab(self) -> None:
            f = self.tab_server
            f.columnconfigure(1, weight=1)

            self.folder_label = ttk.Label(f, text=self.t("folder_label"))
            self.folder_label.grid(row=0, column=0, sticky=W, pady=6)
            self.folder_entry = ttk.Entry(f, textvariable=self.folder_var)
            self.folder_entry.grid(row=0, column=1, sticky="ew", padx=6)
            folder_buttons = ttk.Frame(f)
            folder_buttons.grid(row=0, column=2, sticky=W)
            self.browse_button = ttk.Button(folder_buttons, text=self.t("browse"), command=self.on_browse)
            self.browse_button.pack(side=LEFT, padx=(0, 4))
            self.open_folder_button = ttk.Button(folder_buttons, text=self.t("open_folder"), command=self.on_open_folder,
                                                 bootstyle="secondary")
            self.open_folder_button.pack(side=LEFT)

            self.port_label = ttk.Label(f, text=self.t("port_label"))
            self.port_label.grid(row=1, column=0, sticky=W, pady=6)
            self.port_spin = ttk.Spinbox(f, from_=1024, to=65535, textvariable=self.port_var, width=10)
            self.port_spin.grid(row=1, column=1, sticky=W, padx=6)

            self.interface_label = ttk.Label(f, text=self.t("interface_label"))
            self.interface_label.grid(row=2, column=0, sticky=W, pady=6)
            self.interface_combo = ttk.Combobox(f, textvariable=self.interface_var, state="readonly")
            self.interface_combo.grid(row=2, column=1, sticky="ew", padx=6)
            self.refresh_button = ttk.Button(f, text=self.t("refresh"), command=self.refresh_interfaces,
                                             bootstyle="secondary")
            self.refresh_button.grid(row=2, column=2, sticky=W)

            self.host_label = ttk.Label(f, text=self.t("host_label"))
            self.host_label.grid(row=3, column=0, sticky=W, pady=6)
            ttk.Entry(f, textvariable=self.host_var, state="readonly").grid(row=3, column=1, sticky="ew", padx=6)
            url_buttons = ttk.Frame(f)
            url_buttons.grid(row=3, column=2, sticky=W)
            self.open_browser_button = ttk.Button(url_buttons, text=self.t("open_browser"), command=self.on_open_browser)
            self.open_browser_button.pack(side=LEFT, padx=(0, 4))
            self.copy_url_button = ttk.Button(url_buttons, text=self.t("copy_url"), command=self.on_copy_url,
                                              bootstyle="secondary")
            self.copy_url_button.pack(side=LEFT)

            self.pin_label = ttk.Label(f, text=self.t("pin_label"))
            self.pin_label.grid(row=4, column=0, sticky=W, pady=6)
            ttk.Label(f, textvariable=self.pin_var, font=("Courier", 22, "bold")).grid(row=4, column=1, sticky=W, padx=6)
            pin_buttons = ttk.Frame(f)
            pin_buttons.grid(row=4, column=2, sticky=W)
            self.show_pin_button = ttk.Button(pin_buttons, text=self.t("show_pin"), command=self.on_toggle_pin,
                                              bootstyle="secondary")
            self.show_pin_button.pack(side=LEFT, padx=(0, 4))
            self.copy_pin_button = ttk.Button(pin_buttons, text=self.t("copy_pin"), command=self.on_copy_pin)
            self.copy_pin_button.pack(side=LEFT, padx=(0, 4))
            self.new_pin_button = ttk.Button(pin_buttons, text=self.t("new_pin"), command=self.on_new_pin,
                                             bootstyle="warning-outline", state="disabled")
            self.new_pin_button.pack(side=LEFT)

            self.qr_label = ttk.Label(f)
            self.qr_label.grid(row=5, column=0, columnspan=2, pady=12, sticky=W)
            self.qr_hint_label = ttk.Label(f, text=self.t("qr_hint"), wraplength=720)
            self.qr_hint_label.grid(row=6, column=0, columnspan=3, sticky=W)

            self.fingerprint_label = ttk.Label(f, text=self.t("fingerprint_label"))
            self.fingerprint_label.grid(row=7, column=0, sticky=W, pady=6)
            ttk.Label(f, textvariable=self.fingerprint_var, font=("Courier", 8), wraplength=600).grid(
                row=7, column=1, columnspan=2, sticky=W, padx=6,
            )

            button_row = ttk.Frame(f)
            button_row.grid(row=8, column=0, columnspan=3, pady=14, sticky=W)
            self.start_button = ttk.Button(button_row, text=self.t("start"), command=self.on_start, bootstyle="success")
            self.start_button.pack(side=LEFT, padx=(0, 8))
            self.stop_button = ttk.Button(button_row, text=self.t("stop"), command=self.on_stop, bootstyle="danger",
                                          state="disabled")
            self.stop_button.pack(side=LEFT)

            ttk.Label(f, textvariable=self.status_var, font=("TkDefaultFont", 10, "italic")).grid(
                row=9, column=0, columnspan=2, sticky=W,
            )
            ttk.Label(f, textvariable=self.stats_var, bootstyle="info").grid(row=9, column=2, sticky=W)
            self.root_warning_label = ttk.Label(f, text="", bootstyle="danger", wraplength=720)
            self.root_warning_label.grid(row=10, column=0, columnspan=3, sticky=W, pady=(10, 0))
            self.notice_label = ttk.Label(f, text="", bootstyle="warning", wraplength=720)
            self.notice_label.grid(row=11, column=0, columnspan=3, sticky=W, pady=(4, 0))

        def _build_security_tab(self) -> None:
            f = self.tab_security
            self.security_events_heading = ttk.Label(f, text=self.t("security_events_heading"),
                                                     font=("TkDefaultFont", 11, "bold"))
            self.security_events_heading.pack(anchor=W)
            columns = ("time", "ip", "reason", "score")
            self.events_tree = ttk.Treeview(f, columns=columns, show="headings", height=10)
            widths = {"time": 90, "ip": 170, "reason": 380, "score": 70}
            for col in columns:
                self.events_tree.heading(col, text=self.t(f"col_{col}"))
                self.events_tree.column(col, width=widths[col], stretch=col == "reason")
            self.events_tree.pack(fill=X, pady=(4, 14))

            self.banned_heading = ttk.Label(f, text=self.t("banned_ips_heading"), font=("TkDefaultFont", 11, "bold"))
            self.banned_heading.pack(anchor=W)
            ban_columns = ("ip", "until")
            self.banned_tree = ttk.Treeview(f, columns=ban_columns, show="headings", height=6)
            for col in ban_columns:
                self.banned_tree.heading(col, text=self.t(f"col_{col}"))
                self.banned_tree.column(col, width=240)
            self.banned_tree.pack(fill=X, pady=4)
            actions = ttk.Frame(f)
            actions.pack(fill=X, pady=(8, 0))
            self.unban_button = ttk.Button(actions, text=self.t("unban"), command=self.on_unban, bootstyle="secondary")
            self.unban_button.pack(side=LEFT, padx=(0, 8))
            self.revoke_button = ttk.Button(actions, text=self.t("revoke_sessions"), command=self.on_revoke,
                                            bootstyle="danger-outline")
            self.revoke_button.pack(side=LEFT)

        def _build_logs_tab(self) -> None:
            f = self.tab_logs
            self.logs_heading = ttk.Label(f, text=self.t("logs_heading"), font=("TkDefaultFont", 11, "bold"))
            self.logs_heading.pack(anchor=W)
            self.log_text = ScrolledText(
                f, height=24, wrap="word", background="#0c141c", foreground="#e7edf3", insertbackground="#e7edf3",
                borderwidth=0, highlightthickness=0,
            )
            self.log_text.pack(fill=BOTH, expand=YES, pady=(4, 8))
            self.log_text.configure(state="disabled")
            self.clear_logs_button = ttk.Button(f, text=self.t("clear_logs"), command=self.on_clear_logs)
            self.clear_logs_button.pack(anchor=W)

        def refresh_texts(self) -> None:
            g = GUI_STRINGS[self.lang]
            self.root.title(g["window_title_ver"].format(version=APP_VERSION))
            self.title_label.configure(text=g["window_title"])
            self.lang_label.configure(text=g["language_label"])
            self.notebook.tab(self.tab_server, text=g["tab_server"])
            self.notebook.tab(self.tab_security, text=g["tab_security"])
            self.notebook.tab(self.tab_logs, text=g["tab_logs"])
            for widget, key in (
                (self.folder_label, "folder_label"), (self.browse_button, "browse"),
                (self.open_folder_button, "open_folder"), (self.port_label, "port_label"),
                (self.interface_label, "interface_label"), (self.refresh_button, "refresh"),
                (self.host_label, "host_label"), (self.open_browser_button, "open_browser"),
                (self.copy_url_button, "copy_url"), (self.pin_label, "pin_label"), (self.copy_pin_button, "copy_pin"),
                (self.new_pin_button, "new_pin"), (self.qr_hint_label, "qr_hint"),
                (self.fingerprint_label, "fingerprint_label"), (self.start_button, "start"),
                (self.stop_button, "stop"), (self.security_events_heading, "security_events_heading"),
                (self.banned_heading, "banned_ips_heading"), (self.unban_button, "unban"),
                (self.revoke_button, "revoke_sessions"), (self.logs_heading, "logs_heading"),
                (self.clear_logs_button, "clear_logs"),
            ):
                widget.configure(text=g[key])
            self.show_pin_button.configure(text=g["hide_pin"] if self.pin_visible else g["show_pin"])
            running = self.controller is not None and self.controller.running
            if not self.busy:
                self.status_var.set(g["status_running"] if running else g["status_stopped"])
            if self.elevated:
                self.root_warning_label.configure(text=g["root_warning"])
            for col in ("time", "ip", "reason", "score"):
                self.events_tree.heading(col, text=g[f"col_{col}"])
            for col in ("ip", "until"):
                self.banned_tree.heading(col, text=g[f"col_{col}"])
            self.refresh_stats(reschedule=False)

        def on_lang_change(self, _event=None) -> None:
            self.lang = "en" if self.lang_var.get().startswith("English") else "pt"
            self.refresh_texts()

        def refresh_interfaces(self) -> None:
            def done(result, error) -> None:
                self.addresses = list(result or [])
                labels = [item.label for item in self.addresses]
                self.interface_combo.configure(values=labels)
                preferred = self.settings.advertise_address
                choice = next((item.label for item in self.addresses if item.ip == preferred), labels[0] if labels else "")
                current = self.interface_var.get()
                self.interface_var.set(current if current in labels else choice)
                self.notice_label.configure(text="" if labels else self.t("no_network"))

            self.run_background(discover_addresses, done)

        def selected_ip(self) -> str | None:
            label = self.interface_var.get()
            for item in self.addresses:
                if item.label == label:
                    return item.ip
            return None

        def on_browse(self) -> None:
            chosen = filedialog.askdirectory(initialdir=self.folder_var.get(), mustexist=False)
            if chosen:
                self.folder_var.set(chosen)

        def on_open_folder(self) -> None:
            folder = self.controller.share_folder if self.controller else Path(self.folder_var.get()).expanduser()
            if folder.is_dir():
                try:
                    open_in_file_manager(folder)
                except OSError:
                    pass

        def on_open_browser(self) -> None:
            url = self.host_var.get()
            if url.startswith(("http://", "https://")):
                webbrowser.open(url)

        def _copy(self, text: str) -> None:
            if text:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)

        def on_copy_url(self) -> None:
            self._copy(self.host_var.get())

        def on_copy_pin(self) -> None:
            self._copy(self.real_pin)
            self.root.after(60_000, self._clear_clipboard_if_pin)

        def _clear_clipboard_if_pin(self) -> None:
            try:
                if self.real_pin and self.root.clipboard_get() == self.real_pin:
                    self.root.clipboard_clear()
            except tk.TclError:
                pass

        def on_toggle_pin(self) -> None:
            self.pin_visible = not self.pin_visible
            self._render_pin()

        def _render_pin(self) -> None:
            if self.real_pin and self.pin_visible:
                self.pin_var.set(self.real_pin)
            else:
                self.pin_var.set("•" * self.settings.policy.pin_length)
            self.show_pin_button.configure(text=self.t("hide_pin") if self.pin_visible else self.t("show_pin"))

        def on_new_pin(self) -> None:
            if self.controller is not None and self.controller.running:
                self.real_pin = self.controller.ctx.pins.rotate("operator")
                self._render_pin()

        def on_clear_logs(self) -> None:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")

        def _set_controls(self, running: bool) -> None:
            editable = "disabled" if running or self.busy else "normal"
            self.start_button.configure(state="disabled" if running or self.busy else "normal")
            self.stop_button.configure(state="normal" if running and not self.busy else "disabled")
            self.new_pin_button.configure(state="normal" if running else "disabled")
            for widget in (self.folder_entry, self.browse_button, self.port_spin, self.refresh_button):
                widget.configure(state=editable)
            self.interface_combo.configure(state="disabled" if running or self.busy else "readonly")

        def on_start(self) -> None:
            if self.busy:
                return
            try:
                port = int(self.port_var.get())
                if not 1024 <= port <= 65535:
                    raise ValueError
            except ValueError:
                messagebox.showerror(self.t("window_title"), self.t("start_failed"))
                return
            settings_for_run = dataclasses.replace(
                self.settings,
                share_folder=Path(self.folder_var.get()).expanduser(),
                port=port,
                advertise_address=self.selected_ip(),
            )
            self.busy = True
            self.status_var.set(self.t("status_starting"))
            self._set_controls(False)

            def work():
                controller = ServerController(settings_for_run, logger)
                if not controller.start():
                    controller.stop()
                    return None
                return controller

            def done(controller, error) -> None:
                self.busy = False
                if isinstance(error, FolderRejected):
                    reason = FOLDER_REJECTION_REASONS[self.lang].get(error.code, error.code)
                    self.status_var.set(self.t("status_stopped"))
                    self._set_controls(False)
                    messagebox.showerror(self.t("window_title"), self.t("folder_rejected").format(reason=reason))
                    return
                if error is not None or controller is None:
                    if error is not None:
                        logger.error("Server preparation failed; see log file for details")
                        logger.debug("Server preparation failure", exc_info=error)
                    self.status_var.set(self.t("status_stopped"))
                    self._set_controls(False)
                    messagebox.showerror(self.t("window_title"), self.t("start_failed"))
                    return
                self._attach(controller)

            self.run_background(work, done)

        def _attach(self, controller: ServerController) -> None:
            self.controller = controller
            self.event_queue = controller.ctx.bus.subscribe()
            controller.ctx.pins.on_rotate(lambda pin, reason: self.ui_queue.put(lambda: self._on_pin_rotated(pin, reason)))
            info = controller.info
            self.real_pin = controller.ctx.pins.pin
            self._render_pin()
            self.host_var.set(info.url)
            self.fingerprint_var.set(info.fingerprint or "-")
            self.notice_label.configure(text=self.t("https_unavailable") if info.https_requested and not info.https_active else "")
            self.qr_photo = ImageTk.PhotoImage(generate_qr_image(info.url))
            self.qr_label.configure(image=self.qr_photo)
            self.status_var.set(self.t("status_running"))
            self._set_controls(True)
            self.refresh_security_tables()

        def _on_pin_rotated(self, pin: str, reason: str) -> None:
            self.real_pin = pin
            self._render_pin()
            if reason != "operator":
                self.notice_label.configure(text=self.t("pin_rotated"))
                self.root.bell()

        def on_stop(self, then: Callable[[], None] | None = None) -> None:
            if self.controller is None or self.busy:
                return
            controller = self.controller
            self.busy = True
            self.status_var.set(self.t("status_stopping"))
            self._set_controls(True)

            def done(_result, _error) -> None:
                self.busy = False
                if self.event_queue is not None:
                    controller.ctx.bus.unsubscribe(self.event_queue)
                self.controller = None
                self.event_queue = None
                self.real_pin = ""
                self._render_pin()
                self.host_var.set("")
                self.qr_label.configure(image="")
                self.qr_photo = None
                self.status_var.set(self.t("status_stopped"))
                self._set_controls(False)
                if then is not None:
                    then()

            self.run_background(controller.stop, done)

        def on_unban(self) -> None:
            if self.controller is None:
                return
            for item in self.banned_tree.selection():
                values = self.banned_tree.item(item, "values")
                if values:
                    self.controller.ctx.bans.unban(str(values[0]))
            self.refresh_security_tables()

        def on_revoke(self) -> None:
            if self.controller is None:
                return
            self.controller.ctx.sessions.revoke_all()
            messagebox.showinfo(self.t("window_title"), self.t("sessions_revoked"))
            self.refresh_stats(reschedule=False)

        def refresh_security_tables(self) -> None:
            if self.controller is None:
                return
            self.events_tree.delete(*self.events_tree.get_children())
            for event in self.controller.ctx.bus.recent()[-100:][::-1]:
                when = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
                self.events_tree.insert("", "end", values=(when, event.client, event.reason, event.weight))
            self.banned_tree.delete(*self.banned_tree.get_children())
            for client, until in sorted(self.controller.ctx.bans.snapshot().items(), key=lambda kv: kv[1]):
                when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(until))
                self.banned_tree.insert("", "end", values=(client, when))

        def refresh_stats(self, reschedule: bool = True) -> None:
            controller = self.controller
            if controller is not None and controller.running:
                try:
                    uploads = controller.ctx.uploads.active_count()
                except Exception:
                    uploads = 0
                self.stats_var.set(self.t("stats").format(sessions=controller.ctx.sessions.count(), uploads=uploads))
            else:
                self.stats_var.set("")
            if reschedule:
                self.root.after(3000, self.refresh_stats)

        def poll_queues(self) -> None:
            for _ in range(100):
                try:
                    callback = self.ui_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    callback()
                except Exception:
                    logger.exception("UI callback failed")
            lines = []
            for _ in range(MAX_LOG_LINES_PER_TICK):
                try:
                    lines.append(log_queue.get_nowait())
                except queue.Empty:
                    break
            if lines:
                self.log_text.configure(state="normal")
                self.log_text.insert("end", "\n".join(lines) + "\n")
                excess = int(self.log_text.index("end-1c").split(".")[0]) - MAX_LOG_LINES
                if excess > 0:
                    self.log_text.delete("1.0", f"{excess + 1}.0")
                self.log_text.configure(state="disabled")
                self.log_text.see("end")
            if self.event_queue is not None:
                changed = False
                for _ in range(500):
                    try:
                        self.event_queue.get_nowait()
                    except queue.Empty:
                        break
                    changed = True
                if changed:
                    self.refresh_security_tables()
            self.root.after(200, self.poll_queues)

        def on_close(self) -> None:
            if self.busy:
                return
            if self.controller is not None and self.controller.running:
                if not messagebox.askyesno(self.t("confirm_quit_title"), self.t("confirm_quit_body")):
                    return
                self.on_stop(then=self.root.destroy)
                return
            if self.controller is not None:
                self.controller.stop()
            self.root.destroy()

        def run(self) -> None:
            self.root.mainloop()

    LumenDropGUI().run()
