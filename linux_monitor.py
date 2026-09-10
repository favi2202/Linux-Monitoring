#!/usr/bin/env python3
"""Linux Monitoring - lightweight, read-only Linux desktop inspector."""

from __future__ import annotations

import hashlib
import html
import json
import os
import platform
import shutil
import socket
import subprocess
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import psutil

APP_NAME = "Linux Monitoring"
APP_VERSION = "0.2.0"
DEFAULT_REFRESH_MS = 2500


def run_cmd(args: list[str], timeout: int = 4) -> str:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return ""


def human_bytes(value: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    value = float(value)
    for unit in units:
        if abs(value) < 1024.0:
            return f"{value:,.1f} {unit}"
        value /= 1024.0
    return f"{value:,.1f} EB"


def human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, _ = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def fmt_addr(addr) -> str:
    if not addr:
        return ""
    try:
        return f"{addr.ip}:{addr.port}"
    except AttributeError:
        try:
            return f"{addr[0]}:{addr[1]}"
        except (IndexError, TypeError):
            return str(addr)


def tree(parent, columns, widths=None):
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True)

    widget = ttk.Treeview(frame, columns=columns, show="headings")
    widths = widths or {}
    for col in columns:
        widget.heading(col, text=col)
        widget.column(col, width=widths.get(col, 130), anchor="w")

    yscroll = ttk.Scrollbar(frame, orient="vertical", command=widget.yview)
    xscroll = ttk.Scrollbar(frame, orient="horizontal", command=widget.xview)
    widget.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

    widget.grid(row=0, column=0, sticky="nsew")
    yscroll.grid(row=0, column=1, sticky="ns")
    xscroll.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    return widget


def systemd_unit_for_pid(pid: int) -> str:
    """Best-effort mapping of a process to a systemd service via /proc/<pid>/cgroup."""
    try:
        text = Path(f"/proc/{pid}/cgroup").read_text(errors="ignore")
    except (OSError, PermissionError):
        return ""

    for line in text.splitlines():
        cgroup_path = line.rsplit(":", 1)[-1]
        for part in reversed(cgroup_path.split("/")):
            if part.endswith(".service"):
                return part
    return ""


def executable_link(pid: int) -> str:
    """Read /proc/<pid>/exe so '(deleted)' state is preserved when present."""
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (OSError, PermissionError):
        return ""


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class LinuxMonitor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1280x820")
        self.minsize(980, 650)

        self.refresh_ms = DEFAULT_REFRESH_MS
        self._last_net = psutil.net_io_counters()
        self._last_net_time = time.time()
        self.current_investigation: dict | None = None

        self._build_menu()
        self._build_ui()
        self.after(300, self.refresh_all)

    def _build_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Export system JSON", command=lambda: self.export_report("json"))
        file_menu.add_command(label="Export system HTML", command=lambda: self.export_report("html"))
        file_menu.add_separator()
        file_menu.add_command(label="Export investigation JSON", command=self.export_investigation)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=False)
        view_menu.add_command(label="Refresh now", command=self.refresh_all)
        view_menu.add_command(label="Refresh investigation", command=self.refresh_investigation)
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(
            label="About",
            command=lambda: messagebox.showinfo(
                "About",
                f"{APP_NAME} {APP_VERSION}\n\n"
                "Read-only Linux inspection and incident-response helper.\n"
                "Some visibility requires elevated permissions."
            ),
        )
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

    def _build_ui(self):
        top = ttk.Frame(self, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text=APP_NAME, font=("TkDefaultFont", 16, "bold")).pack(side="left")
        ttk.Label(top, text="read-only inspector", foreground="#666").pack(side="left", padx=(10, 0))
        self.status = ttk.Label(top, text="Starting…")
        self.status.pack(side="right")

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.overview_tab = ttk.Frame(self.tabs, padding=10)
        self.process_tab = ttk.Frame(self.tabs, padding=10)
        self.investigate_tab = ttk.Frame(self.tabs, padding=10)
        self.network_tab = ttk.Frame(self.tabs, padding=10)
        self.disk_tab = ttk.Frame(self.tabs, padding=10)
        self.service_tab = ttk.Frame(self.tabs, padding=10)
        self.logs_tab = ttk.Frame(self.tabs, padding=10)
        self.security_tab = ttk.Frame(self.tabs, padding=10)

        for tab, name in [
            (self.overview_tab, "Overview"),
            (self.process_tab, "Processes"),
            (self.investigate_tab, "Investigate"),
            (self.network_tab, "Network"),
            (self.disk_tab, "Disks"),
            (self.service_tab, "Services"),
            (self.logs_tab, "Logs"),
            (self.security_tab, "Security"),
        ]:
            self.tabs.add(tab, text=name)

        self._build_overview()
        self._build_processes()
        self._build_investigator()
        self._build_network()
        self._build_disks()
        self._build_services()
        self._build_logs()
        self._build_security()

    def _build_overview(self):
        self.cards = {}
        grid = ttk.Frame(self.overview_tab)
        grid.pack(fill="x")
        names = ["Host", "Uptime", "CPU", "Memory", "Swap", "Disk /", "Network", "Load"]
        for i, name in enumerate(names):
            frame = ttk.LabelFrame(grid, text=name, padding=10)
            frame.grid(row=i // 4, column=i % 4, sticky="nsew", padx=5, pady=5)
            label = ttk.Label(frame, text="—", font=("TkDefaultFont", 12, "bold"), wraplength=240)
            label.pack(anchor="w")
            self.cards[name] = label
        for i in range(4):
            grid.columnconfigure(i, weight=1)

        info = ttk.LabelFrame(self.overview_tab, text="System", padding=10)
        info.pack(fill="x", padx=5, pady=8)
        self.system_text = ttk.Label(info, text="", justify="left")
        self.system_text.pack(anchor="w")

        cores_frame = ttk.LabelFrame(self.overview_tab, text="Per-core CPU", padding=10)
        cores_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.core_tree = tree(cores_frame, ("Core", "Usage"), {"Core": 100, "Usage": 180})

    def _build_processes(self):
        bar = ttk.Frame(self.process_tab)
        bar.pack(fill="x", pady=(0, 8))

        ttk.Label(bar, text="Filter:").pack(side="left")
        self.proc_filter = tk.StringVar()
        proc_entry = ttk.Entry(bar, textvariable=self.proc_filter, width=35)
        proc_entry.pack(side="left", padx=6)
        proc_entry.bind("<Return>", lambda _e: self.refresh_processes())

        ttk.Button(bar, text="Refresh", command=self.refresh_processes).pack(side="left")
        ttk.Button(bar, text="Investigate selected", command=self.investigate_selected_process).pack(side="left", padx=6)
        ttk.Label(bar, text="Double-click a process to pivot into Investigate.", foreground="#666").pack(side="left", padx=10)

        holder = ttk.Frame(self.process_tab)
        holder.pack(fill="both", expand=True)
        self.proc_tree = tree(
            holder,
            ("PID", "PPID", "User", "CPU%", "RAM%", "State", "Name", "Command"),
            {
                "PID": 80, "PPID": 80, "User": 120, "CPU%": 75, "RAM%": 75,
                "State": 90, "Name": 160, "Command": 460
            },
        )
        self.proc_tree.bind("<Double-1>", self.investigate_selected_process)

    def _build_investigator(self):
        controls = ttk.Frame(self.investigate_tab)
        controls.pack(fill="x", pady=(0, 8))

        ttk.Label(controls, text="PID:").pack(side="left")
        self.investigate_pid = tk.StringVar()
        pid_entry = ttk.Entry(controls, textvariable=self.investigate_pid, width=12)
        pid_entry.pack(side="left", padx=6)
        pid_entry.bind("<Return>", lambda _e: self.load_investigation())

        ttk.Button(controls, text="Load", command=self.load_investigation).pack(side="left")
        ttk.Button(controls, text="Refresh", command=self.refresh_investigation).pack(side="left", padx=6)
        ttk.Button(controls, text="SHA-256 executable", command=self.hash_investigated_executable).pack(side="left", padx=6)
        ttk.Button(controls, text="Export snapshot", command=self.export_investigation).pack(side="left", padx=6)

        self.investigate_status = ttk.Label(controls, text="Select a process from Processes or Network.")
        self.investigate_status.pack(side="right")

        summary_frame = ttk.LabelFrame(self.investigate_tab, text="Process identity & pivots", padding=6)
        summary_frame.pack(fill="x", pady=(0, 8))
        self.investigate_summary = tk.Text(summary_frame, height=11, wrap="word", font=("TkFixedFont", 10))
        self.investigate_summary.pack(fill="x")
        self.investigate_summary.config(state="disabled")

        self.investigate_notebook = ttk.Notebook(self.investigate_tab)
        self.investigate_notebook.pack(fill="both", expand=True)

        rel_tab = ttk.Frame(self.investigate_notebook, padding=6)
        sock_tab = ttk.Frame(self.investigate_notebook, padding=6)
        file_tab = ttk.Frame(self.investigate_notebook, padding=6)
        log_tab = ttk.Frame(self.investigate_notebook, padding=6)
        svc_tab = ttk.Frame(self.investigate_notebook, padding=6)

        self.investigate_notebook.add(rel_tab, text="Relationships")
        self.investigate_notebook.add(sock_tab, text="Sockets")
        self.investigate_notebook.add(file_tab, text="Open Files")
        self.investigate_notebook.add(log_tab, text="Related Logs")
        self.investigate_notebook.add(svc_tab, text="systemd")

        self.relation_tree = tree(
            rel_tab,
            ("Relation", "PID", "User", "State", "Name", "Command"),
            {"Relation": 100, "PID": 80, "User": 120, "State": 90, "Name": 170, "Command": 520},
        )
        self.relation_tree.bind("<Double-1>", self.investigate_selected_relation)

        self.invest_socket_tree = tree(
            sock_tab,
            ("Proto", "Local", "Remote", "State", "Direction"),
            {"Proto": 70, "Local": 250, "Remote": 250, "State": 100, "Direction": 130},
        )

        self.invest_file_tree = tree(
            file_tab,
            ("FD", "Position", "Mode", "Path"),
            {"FD": 80, "Position": 100, "Mode": 100, "Path": 780},
        )

        log_controls = ttk.Frame(log_tab)
        log_controls.pack(fill="x", pady=(0, 6))
        ttk.Label(
            log_controls,
            text="journalctl correlation uses _PID and the detected systemd unit. Not every application log is in journald.",
            foreground="#666",
        ).pack(side="left")
        self.invest_log_text = tk.Text(log_tab, wrap="none", font=("TkFixedFont", 10))
        self.invest_log_text.pack(fill="both", expand=True)

        self.invest_service_text = tk.Text(svc_tab, wrap="none", font=("TkFixedFont", 10))
        self.invest_service_text.pack(fill="both", expand=True)

    def _build_network(self):
        self.net_summary = ttk.Label(self.network_tab, text="")
        self.net_summary.pack(anchor="w", pady=(0, 8))

        upper = ttk.LabelFrame(self.network_tab, text="Interfaces", padding=6)
        upper.pack(fill="x", pady=(0, 8))
        self.iface_tree = tree(
            upper,
            ("Interface", "Sent", "Received", "Packets sent", "Packets recv"),
            {"Interface": 170},
        )

        lower = ttk.LabelFrame(self.network_tab, text="Sockets — double-click to investigate owning PID", padding=6)
        lower.pack(fill="both", expand=True)
        self.socket_tree = tree(
            lower,
            ("Proto", "Local", "Remote", "State", "PID", "Process"),
            {"Proto": 70, "Local": 240, "Remote": 240, "State": 100, "PID": 80, "Process": 190},
        )
        self.socket_tree.bind("<Double-1>", self.investigate_selected_socket)

    def _build_disks(self):
        upper = ttk.LabelFrame(self.disk_tab, text="Filesystems", padding=6)
        upper.pack(fill="both", expand=True, pady=(0, 8))
        self.fs_tree = tree(upper, ("Device", "Mount", "Type", "Size", "Used", "Free", "Use%"))

        lower = ttk.LabelFrame(self.disk_tab, text="Disk I/O", padding=6)
        lower.pack(fill="both", expand=True)
        self.io_tree = tree(lower, ("Device", "Read", "Written", "Read ops", "Write ops"))

    def _build_services(self):
        bar = ttk.Frame(self.service_tab)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Button(bar, text="Refresh services", command=self.refresh_services).pack(side="left")
        ttk.Label(bar, text="Double-click a service to pivot to its MainPID.", foreground="#666").pack(side="left", padx=10)

        holder = ttk.Frame(self.service_tab)
        holder.pack(fill="both", expand=True)
        self.service_tree = tree(
            holder,
            ("Unit", "Load", "Active", "Sub", "Description"),
            {"Unit": 270, "Description": 480},
        )
        self.service_tree.bind("<Double-1>", self.investigate_selected_service)

    def _build_logs(self):
        bar = ttk.Frame(self.logs_tab)
        bar.pack(fill="x", pady=(0, 8))

        ttk.Label(bar, text="Contains:").pack(side="left")
        self.log_filter = tk.StringVar()
        ttk.Entry(bar, textvariable=self.log_filter, width=30).pack(side="left", padx=6)

        ttk.Label(bar, text="Priority:").pack(side="left", padx=(12, 0))
        self.log_priority = tk.StringVar(value="info")
        ttk.Combobox(
            bar,
            textvariable=self.log_priority,
            values=["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
            width=10,
            state="readonly",
        ).pack(side="left", padx=6)

        ttk.Button(bar, text="Load logs", command=self.refresh_logs).pack(side="left")

        self.log_text = tk.Text(self.logs_tab, wrap="none", font=("TkFixedFont", 10))
        self.log_text.pack(fill="both", expand=True)

    def _build_security(self):
        ttk.Button(self.security_tab, text="Run checks", command=self.refresh_security).pack(anchor="w", pady=(0, 8))
        self.security_text = tk.Text(self.security_tab, wrap="word", font=("TkFixedFont", 10))
        self.security_text.pack(fill="both", expand=True)

    def refresh_all(self):
        self.refresh_overview()
        self.refresh_processes()
        self.refresh_network()
        self.refresh_disks()

        selected_index = self.tabs.index(self.tabs.select())
        if selected_index == 5:
            self.refresh_services()

        self.status.config(text=f"Updated {datetime.now().strftime('%H:%M:%S')}")
        self.after(self.refresh_ms, self.refresh_all)

    def refresh_overview(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        root = psutil.disk_usage("/")

        now = time.time()
        net = psutil.net_io_counters()
        elapsed = max(0.1, now - self._last_net_time)
        tx = max(0, net.bytes_sent - self._last_net.bytes_sent) / elapsed
        rx = max(0, net.bytes_recv - self._last_net.bytes_recv) / elapsed
        self._last_net, self._last_net_time = net, now

        load = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
        values = {
            "Host": socket.gethostname(),
            "Uptime": human_duration(time.time() - psutil.boot_time()),
            "CPU": f"{cpu:.1f}%",
            "Memory": f"{mem.percent:.1f}%  {human_bytes(mem.used)} / {human_bytes(mem.total)}",
            "Swap": f"{swap.percent:.1f}%  {human_bytes(swap.used)} / {human_bytes(swap.total)}",
            "Disk /": f"{root.percent:.1f}%  {human_bytes(root.used)} / {human_bytes(root.total)}",
            "Network": f"↓ {human_bytes(rx)}/s   ↑ {human_bytes(tx)}/s",
            "Load": f"{load[0]:.2f}  {load[1]:.2f}  {load[2]:.2f}",
        }
        for key, value in values.items():
            self.cards[key].config(text=value)

        self.system_text.config(
            text=(
                f"OS: {platform.platform()}\n"
                f"Kernel: {platform.release()}    Architecture: {platform.machine()}    "
                f"Python: {platform.python_version()}\n"
                f"Logical CPUs: {psutil.cpu_count()}    "
                f"Physical CPUs: {psutil.cpu_count(logical=False) or 'unknown'}"
            )
        )

        self.core_tree.delete(*self.core_tree.get_children())
        for i, val in enumerate(psutil.cpu_percent(interval=None, percpu=True)):
            self.core_tree.insert("", "end", values=(i, f"{val:.1f}%"))

    def refresh_processes(self):
        needle = self.proc_filter.get().lower().strip()
        rows = []

        for p in psutil.process_iter(
            ["pid", "ppid", "username", "cpu_percent", "memory_percent", "status", "name", "cmdline"]
        ):
            try:
                info = p.info
                cmd = " ".join(info.get("cmdline") or [])
                haystack = (
                    f"{info.get('pid')} {info.get('ppid')} {info.get('username')} "
                    f"{info.get('name')} {cmd}"
                ).lower()
                if needle and needle not in haystack:
                    continue
                rows.append(
                    (
                        info.get("pid", ""),
                        info.get("ppid", ""),
                        info.get("username") or "",
                        f"{info.get('cpu_percent') or 0:.1f}",
                        f"{info.get('memory_percent') or 0:.1f}",
                        info.get("status") or "",
                        info.get("name") or "",
                        cmd,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        rows.sort(key=lambda x: float(x[3]), reverse=True)
        self.proc_tree.delete(*self.proc_tree.get_children())
        for row in rows[:1500]:
            self.proc_tree.insert("", "end", values=row)

    def investigate_selected_process(self, _event=None):
        selected = self.proc_tree.selection()
        if not selected:
            return
        try:
            pid = int(self.proc_tree.item(selected[0], "values")[0])
        except (ValueError, IndexError):
            return
        self.open_investigator(pid)

    def investigate_selected_socket(self, _event=None):
        selected = self.socket_tree.selection()
        if not selected:
            return
        values = self.socket_tree.item(selected[0], "values")
        try:
            pid = int(values[4])
        except (ValueError, TypeError, IndexError):
            messagebox.showinfo("Socket owner", "No visible owning PID for this socket. Try elevated privileges.")
            return
        self.open_investigator(pid)

    def investigate_selected_relation(self, _event=None):
        selected = self.relation_tree.selection()
        if not selected:
            return
        values = self.relation_tree.item(selected[0], "values")
        try:
            pid = int(values[1])
        except (ValueError, TypeError, IndexError):
            return
        self.open_investigator(pid)

    def investigate_selected_service(self, _event=None):
        selected = self.service_tree.selection()
        if not selected:
            return
        values = self.service_tree.item(selected[0], "values")
        if not values:
            return

        unit = str(values[0])
        pid_text = run_cmd(["systemctl", "show", unit, "--property=MainPID", "--value"], timeout=5)
        try:
            pid = int(pid_text)
        except ValueError:
            pid = 0

        if pid > 0 and psutil.pid_exists(pid):
            self.open_investigator(pid)
            return

        messagebox.showinfo(
            "No running MainPID",
            f"{unit} does not currently expose a running MainPID.\n"
            "The service may be inactive, failed, transient, or permission-restricted."
        )

    def open_investigator(self, pid: int):
        self.investigate_pid.set(str(pid))
        self.tabs.select(self.investigate_tab)
        self.load_investigation(pid)

    def load_investigation(self, pid: int | None = None):
        if pid is None:
            try:
                pid = int(self.investigate_pid.get().strip())
            except ValueError:
                messagebox.showerror("Investigate", "Enter a numeric PID.")
                return

        if pid <= 0:
            messagebox.showerror("Investigate", "PID must be greater than zero.")
            return

        self.investigate_status.config(text=f"Collecting PID {pid}…")
        self.update_idletasks()

        try:
            p = psutil.Process(pid)
            with p.oneshot():
                name = p.name()
                username = p.username()
                status = p.status()
                ppid = p.ppid()
                cmdline = " ".join(p.cmdline())
                create_time = p.create_time()
                memory = p.memory_info()
                cwd = p.cwd()
                nice = p.nice()
                threads = p.num_threads()
                cpu = p.cpu_percent(interval=0.05)
        except psutil.NoSuchProcess:
            self.investigate_status.config(text=f"PID {pid} exited.")
            messagebox.showerror("Investigate", f"PID {pid} no longer exists.")
            return
        except psutil.AccessDenied:
            try:
                p = psutil.Process(pid)
                name = p.name()
                username = "permission denied"
                status = p.status()
                ppid = p.ppid()
                cmdline = ""
                create_time = p.create_time()
                memory = p.memory_info()
                cwd = "permission denied"
                nice = "?"
                threads = "?"
                cpu = 0.0
            except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                messagebox.showerror("Investigate", str(exc))
                return

        exe = executable_link(pid)
        if not exe:
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = ""

        unit = systemd_unit_for_pid(pid)

        try:
            conns = p.net_connections(kind="inet")
        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
            conns = []

        try:
            open_files = p.open_files()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            open_files = []

        parent = None
        try:
            parent = p.parent()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            children = p.children(recursive=False)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            children = []

        relationships = []
        if parent:
            relationships.append(self._process_relationship_row("parent", parent))
        relationships.append(self._process_relationship_row("selected", p))
        for child in children[:200]:
            relationships.append(self._process_relationship_row("child", child))

        socket_rows = []
        remote_count = 0
        listen_count = 0
        for c in conns:
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            local = fmt_addr(c.laddr)
            remote = fmt_addr(c.raddr)
            if remote:
                direction = "connected"
                remote_count += 1
            elif c.status == psutil.CONN_LISTEN:
                direction = "listening"
                listen_count += 1
            else:
                direction = "local/unconnected"
            socket_rows.append(
                {
                    "proto": proto,
                    "local": local,
                    "remote": remote,
                    "state": c.status,
                    "direction": direction,
                }
            )

        file_rows = []
        for f in open_files[:2000]:
            file_rows.append(
                {
                    "fd": getattr(f, "fd", ""),
                    "position": getattr(f, "position", ""),
                    "mode": getattr(f, "mode", ""),
                    "path": f.path,
                }
            )

        hints = self._investigation_hints(
            pid=pid,
            username=username,
            exe=exe,
            cmdline=cmdline,
            remote_count=remote_count,
            listen_count=listen_count,
            unit=unit,
        )

        pid_logs = self._journal_for_pid(pid)
        unit_logs = self._journal_for_unit(unit) if unit else ""
        related_logs = self._merge_log_text(pid_logs, unit_logs)

        service_info = self._service_details(unit) if unit else (
            "No .service unit was detected in this process's cgroup.\n"
            "That is normal for interactive shells, desktop apps, containers, and manually launched processes."
        )

        snapshot = {
            "captured_at": datetime.now().astimezone().isoformat(),
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "username": username,
            "status": status,
            "command": cmdline,
            "executable": exe,
            "cwd": cwd,
            "started": datetime.fromtimestamp(create_time).astimezone().isoformat(),
            "cpu_percent_sample": cpu,
            "rss": memory.rss,
            "vms": memory.vms,
            "nice": nice,
            "threads": threads,
            "systemd_unit": unit,
            "remote_connection_count": remote_count,
            "listening_socket_count": listen_count,
            "hints": hints,
            "relationships": relationships,
            "sockets": socket_rows,
            "open_files": file_rows,
            "related_logs": related_logs,
            "service_info": service_info,
        }
        self.current_investigation = snapshot
        self._render_investigation(snapshot)
        self.investigate_status.config(
            text=f"PID {pid}: {len(socket_rows)} sockets • {len(file_rows)} files • unit {unit or 'none'}"
        )

    def refresh_investigation(self):
        if self.current_investigation:
            self.load_investigation(int(self.current_investigation["pid"]))
        elif self.investigate_pid.get().strip():
            self.load_investigation()

    def _process_relationship_row(self, relation: str, proc: psutil.Process) -> dict:
        try:
            with proc.oneshot():
                pid = proc.pid
                username = proc.username()
                state = proc.status()
                name = proc.name()
                cmd = " ".join(proc.cmdline())
        except psutil.NoSuchProcess:
            return {
                "relation": relation,
                "pid": "",
                "user": "",
                "state": "exited",
                "name": "",
                "command": "",
            }
        except psutil.AccessDenied:
            return {
                "relation": relation,
                "pid": proc.pid,
                "user": "?",
                "state": "?",
                "name": "?",
                "command": "permission denied",
            }
        return {
            "relation": relation,
            "pid": pid,
            "user": username,
            "state": state,
            "name": name,
            "command": cmd,
        }

    def _investigation_hints(
        self,
        pid: int,
        username: str,
        exe: str,
        cmdline: str,
        remote_count: int,
        listen_count: int,
        unit: str,
    ) -> list[str]:
        """Return contextual cues, not malicious/benign verdicts."""
        hints = []
        lowered_exe = exe.lower()
        lowered_cmd = cmdline.lower()

        if "(deleted)" in lowered_exe:
            hints.append("Executable backing file appears deleted while the process is still running.")
        if lowered_exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
            hints.append("Executable is running from a temporary or shared-memory directory.")
        if remote_count:
            hints.append(f"Process currently has {remote_count} remote network connection(s).")
        if listen_count:
            hints.append(f"Process currently owns {listen_count} listening socket(s).")
        if username == "root":
            hints.append("Process is running as root; treat its activity as high-impact context, not automatic suspicion.")
        if not unit:
            hints.append("No systemd service unit detected; it may be interactive, manually launched, containerized, or desktop-managed.")
        if any(token in lowered_cmd for token in ("curl ", "wget ", "nc ", "ncat ", "socat ")):
            hints.append("Command line contains a network utility; review destination and purpose in context.")
        if not hints:
            hints.append("No high-signal contextual cues were identified by the lightweight checks.")

        return hints

    def _journal_for_pid(self, pid: int) -> str:
        if not shutil.which("journalctl"):
            return "journalctl is not installed."
        out = run_cmd(
            ["journalctl", "--no-pager", "-n", "250", "--output=short-iso", f"_PID={pid}"],
            timeout=8,
        )
        return out or "No journald entries visible for this PID (or access was denied)."

    def _journal_for_unit(self, unit: str) -> str:
        if not unit or not shutil.which("journalctl"):
            return ""
        return run_cmd(
            ["journalctl", "--no-pager", "-n", "250", "--output=short-iso", "-u", unit],
            timeout=8,
        )

    @staticmethod
    def _merge_log_text(pid_logs: str, unit_logs: str) -> str:
        if not unit_logs:
            return pid_logs
        seen = set()
        lines = []
        for line in (pid_logs + "\n" + unit_logs).splitlines():
            if line not in seen:
                seen.add(line)
                lines.append(line)
        return "\n".join(lines)

    def _service_details(self, unit: str) -> str:
        if not unit or not shutil.which("systemctl"):
            return "systemctl is unavailable."
        props = [
            "Id", "Description", "LoadState", "ActiveState", "SubState", "MainPID",
            "User", "Group", "ExecStart", "FragmentPath", "UnitFileState",
            "Restart", "MemoryCurrent", "TasksCurrent"
        ]
        return run_cmd(
            ["systemctl", "show", unit, "--no-pager", "--property=" + ",".join(props)],
            timeout=6,
        ) or "systemctl returned no visible details."

    def _render_investigation(self, snap: dict):
        hints = "\n".join(f"  • {item}" for item in snap["hints"])
        summary = (
            f"PID / PPID : {snap['pid']} / {snap['ppid']}\n"
            f"Name       : {snap['name']}\n"
            f"User       : {snap['username']}\n"
            f"Status     : {snap['status']}\n"
            f"Executable : {snap['executable'] or 'unknown'}\n"
            f"CWD        : {snap['cwd']}\n"
            f"Command    : {snap['command'] or '(not visible)'}\n"
            f"Started    : {snap['started']}\n"
            f"CPU/RSS    : {snap['cpu_percent_sample']:.1f}% / {human_bytes(snap['rss'])}\n"
            f"systemd    : {snap['systemd_unit'] or 'not detected'}\n"
            f"Context cues:\n{hints}"
        )

        self.investigate_summary.config(state="normal")
        self.investigate_summary.delete("1.0", "end")
        self.investigate_summary.insert("1.0", summary)
        self.investigate_summary.config(state="disabled")

        self.relation_tree.delete(*self.relation_tree.get_children())
        for row in snap["relationships"]:
            self.relation_tree.insert(
                "", "end",
                values=(
                    row["relation"], row["pid"], row["user"], row["state"],
                    row["name"], row["command"]
                ),
            )

        self.invest_socket_tree.delete(*self.invest_socket_tree.get_children())
        for row in snap["sockets"]:
            self.invest_socket_tree.insert(
                "", "end",
                values=(row["proto"], row["local"], row["remote"], row["state"], row["direction"]),
            )

        self.invest_file_tree.delete(*self.invest_file_tree.get_children())
        for row in snap["open_files"]:
            self.invest_file_tree.insert(
                "", "end",
                values=(row["fd"], row["position"], row["mode"], row["path"]),
            )

        self.invest_log_text.delete("1.0", "end")
        self.invest_log_text.insert("1.0", snap["related_logs"])

        self.invest_service_text.delete("1.0", "end")
        self.invest_service_text.insert("1.0", snap["service_info"])

    def hash_investigated_executable(self):
        if not self.current_investigation:
            messagebox.showinfo("SHA-256", "Load a process first.")
            return

        raw_path = self.current_investigation.get("executable") or ""
        path = raw_path.removesuffix(" (deleted)")
        if not path or not Path(path).is_file():
            messagebox.showerror("SHA-256", f"Executable is not readable as a regular file:\n{raw_path or 'unknown'}")
            return

        self.investigate_status.config(text=f"Hashing {path}…")
        self.update_idletasks()
        try:
            digest = sha256_file(path)
        except (OSError, PermissionError) as exc:
            messagebox.showerror("SHA-256", str(exc))
            return

        self.current_investigation["executable_sha256"] = digest
        self.investigate_status.config(text=f"SHA-256: {digest}")
        messagebox.showinfo("Executable SHA-256", f"{path}\n\n{digest}")

    def export_investigation(self):
        if not self.current_investigation:
            messagebox.showinfo("Export investigation", "Load a process investigation first.")
            return

        pid = self.current_investigation["pid"]
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=f"linux-investigation-pid{pid}-{stamp}.json",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return

        Path(path).write_text(
            json.dumps(self.current_investigation, indent=2, default=str),
            encoding="utf-8",
        )
        messagebox.showinfo("Export complete", f"Saved investigation snapshot to:\n{path}")

    def refresh_network(self):
        self.iface_tree.delete(*self.iface_tree.get_children())
        for name, c in psutil.net_io_counters(pernic=True).items():
            self.iface_tree.insert(
                "",
                "end",
                values=(
                    name,
                    human_bytes(c.bytes_sent),
                    human_bytes(c.bytes_recv),
                    c.packets_sent,
                    c.packets_recv,
                ),
            )

        self.socket_tree.delete(*self.socket_tree.get_children())
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            conns = []

        for c in conns[:3000]:
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            local = fmt_addr(c.laddr)
            remote = fmt_addr(c.raddr)
            pname = ""
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            self.socket_tree.insert(
                "",
                "end",
                values=(proto, local, remote, c.status, c.pid or "", pname),
            )

        self.net_summary.config(
            text=f"Hostname: {socket.gethostname()}    Interfaces: {len(psutil.net_if_addrs())}"
        )

    def refresh_disks(self):
        self.fs_tree.delete(*self.fs_tree.get_children())
        for p in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(p.mountpoint)
            except (PermissionError, OSError):
                continue
            self.fs_tree.insert(
                "",
                "end",
                values=(
                    p.device, p.mountpoint, p.fstype, human_bytes(u.total),
                    human_bytes(u.used), human_bytes(u.free), f"{u.percent:.1f}%"
                ),
            )

        self.io_tree.delete(*self.io_tree.get_children())
        for dev, c in (psutil.disk_io_counters(perdisk=True) or {}).items():
            self.io_tree.insert(
                "",
                "end",
                values=(dev, human_bytes(c.read_bytes), human_bytes(c.write_bytes), c.read_count, c.write_count),
            )

    def refresh_services(self):
        self.service_tree.delete(*self.service_tree.get_children())
        if not shutil.which("systemctl"):
            self.service_tree.insert("", "end", values=("systemctl unavailable", "", "", "", ""))
            return

        out = run_cmd(
            [
                "systemctl", "list-units", "--type=service", "--all",
                "--no-pager", "--no-legend", "--plain"
            ],
            timeout=8,
        )
        for line in out.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4:
                self.service_tree.insert(
                    "",
                    "end",
                    values=(*parts[:4], parts[4] if len(parts) > 4 else ""),
                )

    def refresh_logs(self):
        self.log_text.delete("1.0", "end")
        if not shutil.which("journalctl"):
            self.log_text.insert("end", "journalctl is not available on this system.\n")
            return

        priority = self.log_priority.get() or "info"
        out = run_cmd(
            [
                "journalctl", "-n", "500", "-p", f"0..{priority}",
                "--no-pager", "--output=short-iso"
            ],
            timeout=8,
        )

        needle = self.log_filter.get().lower().strip()
        if needle:
            out = "\n".join(line for line in out.splitlines() if needle in line.lower())

        self.log_text.insert("end", out or "No matching log entries, or access was denied.\n")

    def refresh_security(self):
        lines = ["[Listening ports]"]
        if shutil.which("ss"):
            listeners = run_cmd(["ss", "-lntup"], timeout=6)
            lines.append(listeners or "No output / permission denied")
        else:
            lines.append("ss not installed")

        lines.append("\n[Firewall tooling]")
        found = [cmd for cmd in ("ufw", "firewall-cmd", "nft", "iptables") if shutil.which(cmd)]
        lines.append(", ".join(found) if found else "No common firewall command found in PATH")

        lines.append("\n[Mandatory access control]")
        if shutil.which("getenforce"):
            lines.append(f"SELinux: {run_cmd(['getenforce']) or 'unknown'}")
        elif Path("/sys/module/apparmor/parameters/enabled").exists():
            try:
                val = Path("/sys/module/apparmor/parameters/enabled").read_text().strip()
            except OSError:
                val = "unknown"
            lines.append(f"AppArmor kernel module: {val}")
        else:
            lines.append("SELinux/AppArmor status not detected with available interfaces")

        lines.append("\n[SSH]")
        sshd = "/etc/ssh/sshd_config"
        if Path(sshd).exists():
            lines.append(f"Configuration present: {sshd}")
            try:
                interesting = []
                for raw in Path(sshd).read_text(errors="ignore").splitlines():
                    line = raw.strip()
                    if (
                        line
                        and not line.startswith("#")
                        and line.lower().startswith(
                            (
                                "permitrootlogin", "passwordauthentication",
                                "pubkeyauthentication", "allowusers", "allowgroups"
                            )
                        )
                    ):
                        interesting.append(line)
                lines.extend(interesting or ["No active high-signal options found in main config"])
            except PermissionError:
                lines.append("Cannot read sshd_config with current permissions")
        else:
            lines.append("No /etc/ssh/sshd_config")

        lines.append("\n[Sudo]")
        for path in ("/etc/sudoers", "/etc/sudoers.d"):
            lines.append(f"{path}: {'present' if Path(path).exists() else 'not present'}")

        self.security_text.delete("1.0", "end")
        self.security_text.insert("end", "\n".join(lines))

    def collect_report(self) -> dict:
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        net = psutil.net_io_counters()
        report = {
            "generated_at": datetime.now().astimezone().isoformat(),
            "host": socket.gethostname(),
            "os": platform.platform(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "uptime_seconds": int(time.time() - psutil.boot_time()),
            "cpu": {
                "logical_count": psutil.cpu_count(),
                "physical_count": psutil.cpu_count(logical=False),
                "usage_percent": psutil.cpu_percent(interval=0.15),
                "per_core_percent": psutil.cpu_percent(interval=0.15, percpu=True),
            },
            "memory": {
                "total": mem.total,
                "used": mem.used,
                "available": mem.available,
                "percent": mem.percent,
            },
            "swap": {
                "total": swap.total,
                "used": swap.used,
                "percent": swap.percent,
            },
            "network": {
                "bytes_sent": net.bytes_sent,
                "bytes_recv": net.bytes_recv,
                "packets_sent": net.packets_sent,
                "packets_recv": net.packets_recv,
            },
            "filesystems": [],
            "top_processes": [],
        }

        for p in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(p.mountpoint)
                report["filesystems"].append(
                    {
                        "device": p.device,
                        "mount": p.mountpoint,
                        "fstype": p.fstype,
                        "total": u.total,
                        "used": u.used,
                        "free": u.free,
                        "percent": u.percent,
                    }
                )
            except (PermissionError, OSError):
                pass

        procs = []
        for p in psutil.process_iter(
            ["pid", "ppid", "username", "name", "cpu_percent", "memory_percent", "cmdline"]
        ):
            try:
                info = p.info
                info["cmdline"] = " ".join(info.get("cmdline") or [])
                procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        report["top_processes"] = sorted(
            procs,
            key=lambda x: (x.get("cpu_percent") or 0, x.get("memory_percent") or 0),
            reverse=True,
        )[:50]
        return report

    def export_report(self, kind: str):
        report = self.collect_report()
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        if kind == "json":
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                initialfile=f"linux-monitor-{stamp}.json",
                filetypes=[("JSON", "*.json")],
            )
            if not path:
                return
            Path(path).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        else:
            path = filedialog.asksaveasfilename(
                defaultextension=".html",
                initialfile=f"linux-monitor-{stamp}.html",
                filetypes=[("HTML", "*.html")],
            )
            if not path:
                return

            pretty = html.escape(json.dumps(report, indent=2, default=str))
            doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Linux Monitoring Report</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px}}
pre{{white-space:pre-wrap;background:#f4f4f4;padding:18px;border-radius:10px}}
</style>
</head>
<body>
<h1>Linux Monitoring Report</h1>
<p>Host: <strong>{html.escape(report['host'])}</strong></p>
<p>Generated: {html.escape(report['generated_at'])}</p>
<pre>{pretty}</pre>
</body>
</html>"""
            Path(path).write_text(doc, encoding="utf-8")

        messagebox.showinfo("Export complete", f"Saved report to:\n{path}")


if __name__ == "__main__":
    try:
        app = LinuxMonitor()
        app.mainloop()
    except tk.TclError as exc:
        raise SystemExit(
            f"Unable to start the GUI: {exc}. "
            "Is a graphical desktop available and is tkinter installed?"
        )
