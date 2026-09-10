#!/usr/bin/env python3
"""Linux Monitoring - lightweight read-only Linux desktop inspector."""

from __future__ import annotations

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
DEFAULT_REFRESH_MS = 2500


def run_cmd(args: list[str], timeout: int = 4) -> str:
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        ).stdout.strip()
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


def tree(parent, columns, widths=None):
    widget = ttk.Treeview(parent, columns=columns, show="headings")
    widths = widths or {}
    for col in columns:
        widget.heading(col, text=col)
        widget.column(col, width=widths.get(col, 130), anchor="w")
    scroll = ttk.Scrollbar(parent, orient="vertical", command=widget.yview)
    widget.configure(yscrollcommand=scroll.set)
    widget.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")
    return widget


class LinuxMonitor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1180x760")
        self.minsize(900, 600)
        self.refresh_ms = DEFAULT_REFRESH_MS
        self._last_net = psutil.net_io_counters()
        self._last_net_time = time.time()
        self._build_menu()
        self._build_ui()
        self.after(300, self.refresh_all)

    def _build_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Export JSON", command=lambda: self.export_report("json"))
        file_menu.add_command(label="Export HTML", command=lambda: self.export_report("html"))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=False)
        view_menu.add_command(label="Refresh now", command=self.refresh_all)
        menubar.add_cascade(label="View", menu=view_menu)
        self.config(menu=menubar)

    def _build_ui(self):
        top = ttk.Frame(self, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text=APP_NAME, font=("TkDefaultFont", 16, "bold")).pack(side="left")
        self.status = ttk.Label(top, text="Starting…")
        self.status.pack(side="right")

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.overview_tab = ttk.Frame(self.tabs, padding=10)
        self.process_tab = ttk.Frame(self.tabs, padding=10)
        self.network_tab = ttk.Frame(self.tabs, padding=10)
        self.disk_tab = ttk.Frame(self.tabs, padding=10)
        self.service_tab = ttk.Frame(self.tabs, padding=10)
        self.logs_tab = ttk.Frame(self.tabs, padding=10)
        self.security_tab = ttk.Frame(self.tabs, padding=10)

        for tab, name in [
            (self.overview_tab, "Overview"),
            (self.process_tab, "Processes"),
            (self.network_tab, "Network"),
            (self.disk_tab, "Disks"),
            (self.service_tab, "Services"),
            (self.logs_tab, "Logs"),
            (self.security_tab, "Security"),
        ]:
            self.tabs.add(tab, text=name)

        self._build_overview()
        self._build_processes()
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
            label = ttk.Label(frame, text="—", font=("TkDefaultFont", 12, "bold"), wraplength=220)
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
        ttk.Entry(bar, textvariable=self.proc_filter, width=35).pack(side="left", padx=6)
        ttk.Button(bar, text="Refresh", command=self.refresh_processes).pack(side="left")
        holder = ttk.Frame(self.process_tab)
        holder.pack(fill="both", expand=True)
        self.proc_tree = tree(
            holder,
            ("PID", "User", "CPU%", "RAM%", "State", "Name", "Command"),
            {"PID": 80, "User": 110, "CPU%": 80, "RAM%": 80, "State": 90, "Name": 150, "Command": 420},
        )
        self.proc_tree.bind("<Double-1>", self.show_process_details)

    def _build_network(self):
        self.net_summary = ttk.Label(self.network_tab, text="")
        self.net_summary.pack(anchor="w", pady=(0, 8))
        upper = ttk.LabelFrame(self.network_tab, text="Interfaces", padding=6)
        upper.pack(fill="x", pady=(0, 8))
        self.iface_tree = tree(upper, ("Interface", "Sent", "Received", "Packets sent", "Packets recv"))
        lower = ttk.LabelFrame(self.network_tab, text="Sockets", padding=6)
        lower.pack(fill="both", expand=True)
        self.socket_tree = tree(
            lower,
            ("Proto", "Local", "Remote", "State", "PID", "Process"),
            {"Proto": 70, "Local": 210, "Remote": 210, "State": 100, "PID": 80, "Process": 180},
        )

    def _build_disks(self):
        upper = ttk.LabelFrame(self.disk_tab, text="Filesystems", padding=6)
        upper.pack(fill="both", expand=True, pady=(0, 8))
        self.fs_tree = tree(upper, ("Device", "Mount", "Type", "Size", "Used", "Free", "Use%"))
        lower = ttk.LabelFrame(self.disk_tab, text="Disk I/O", padding=6)
        lower.pack(fill="both", expand=True)
        self.io_tree = tree(lower, ("Device", "Read", "Written", "Read ops", "Write ops"))

    def _build_services(self):
        ttk.Button(self.service_tab, text="Refresh services", command=self.refresh_services).pack(anchor="w", pady=(0, 8))
        holder = ttk.Frame(self.service_tab)
        holder.pack(fill="both", expand=True)
        self.service_tree = tree(holder, ("Unit", "Load", "Active", "Sub", "Description"), {"Unit": 260, "Description": 420})

    def _build_logs(self):
        bar = ttk.Frame(self.logs_tab)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="Contains:").pack(side="left")
        self.log_filter = tk.StringVar()
        ttk.Entry(bar, textvariable=self.log_filter, width=30).pack(side="left", padx=6)
        ttk.Label(bar, text="Priority:").pack(side="left", padx=(12, 0))
        self.log_priority = tk.StringVar(value="info")
        ttk.Combobox(bar, textvariable=self.log_priority, values=["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"], width=10, state="readonly").pack(side="left", padx=6)
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
        if self.tabs.index(self.tabs.select()) == 4:
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
        tx = (net.bytes_sent - self._last_net.bytes_sent) / elapsed
        rx = (net.bytes_recv - self._last_net.bytes_recv) / elapsed
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
                f"Logical CPUs: {psutil.cpu_count()}    Physical CPUs: {psutil.cpu_count(logical=False) or 'unknown'}"
            )
        )
        self.core_tree.delete(*self.core_tree.get_children())
        for i, val in enumerate(psutil.cpu_percent(interval=None, percpu=True)):
            self.core_tree.insert("", "end", values=(i, f"{val:.1f}%"))

    def refresh_processes(self):
        needle = self.proc_filter.get().lower().strip()
        rows = []
        for p in psutil.process_iter(["pid", "username", "cpu_percent", "memory_percent", "status", "name", "cmdline"]):
            try:
                info = p.info
                cmd = " ".join(info.get("cmdline") or [])
                haystack = f"{info.get('pid')} {info.get('username')} {info.get('name')} {cmd}".lower()
                if needle and needle not in haystack:
                    continue
                rows.append((
                    info.get("pid", ""),
                    info.get("username") or "",
                    f"{info.get('cpu_percent') or 0:.1f}",
                    f"{info.get('memory_percent') or 0:.1f}",
                    info.get("status") or "",
                    info.get("name") or "",
                    cmd,
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        rows.sort(key=lambda x: float(x[2]), reverse=True)
        self.proc_tree.delete(*self.proc_tree.get_children())
        for row in rows[:1200]:
            self.proc_tree.insert("", "end", values=row)

    def show_process_details(self, _event=None):
        selected = self.proc_tree.selection()
        if not selected:
            return
        pid = int(self.proc_tree.item(selected[0], "values")[0])
        try:
            p = psutil.Process(pid)
            lines = [
                f"PID: {pid}",
                f"Name: {p.name()}",
                f"User: {p.username()}",
                f"Status: {p.status()}",
                f"Executable: {p.exe() if p.exe() else 'unknown'}",
                f"Command: {' '.join(p.cmdline())}",
                f"Started: {datetime.fromtimestamp(p.create_time())}",
                f"Threads: {p.num_threads()}",
                f"RSS: {human_bytes(p.memory_info().rss)}",
            ]
            try:
                conns = p.net_connections(kind="inet")
                lines.append("\nConnections:")
                for c in conns[:40]:
                    lines.append(f"  {c.laddr} -> {c.raddr or '-'}  {c.status}")
            except (psutil.AccessDenied, AttributeError):
                lines.append("\nConnections: permission denied")
            try:
                files = p.open_files()
                lines.append("\nOpen files:")
                for f in files[:40]:
                    lines.append(f"  {f.path}")
            except psutil.AccessDenied:
                lines.append("\nOpen files: permission denied")
            messagebox.showinfo(f"Process {pid}", "\n".join(lines))
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            messagebox.showerror("Process details", str(exc))

    def refresh_network(self):
        self.iface_tree.delete(*self.iface_tree.get_children())
        for name, c in psutil.net_io_counters(pernic=True).items():
            self.iface_tree.insert("", "end", values=(name, human_bytes(c.bytes_sent), human_bytes(c.bytes_recv), c.packets_sent, c.packets_recv))

        self.socket_tree.delete(*self.socket_tree.get_children())
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            conns = []
        for c in conns[:2500]:
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            pname = ""
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            self.socket_tree.insert("", "end", values=(proto, local, remote, c.status, c.pid or "", pname))
        self.net_summary.config(text=f"Hostname: {socket.gethostname()}    Interfaces: {len(psutil.net_if_addrs())}")

    def refresh_disks(self):
        self.fs_tree.delete(*self.fs_tree.get_children())
        for p in psutil.disk_partitions(all=False):
            try:
                u = psutil.disk_usage(p.mountpoint)
            except (PermissionError, OSError):
                continue
            self.fs_tree.insert("", "end", values=(p.device, p.mountpoint, p.fstype, human_bytes(u.total), human_bytes(u.used), human_bytes(u.free), f"{u.percent:.1f}%"))

        self.io_tree.delete(*self.io_tree.get_children())
        for dev, c in (psutil.disk_io_counters(perdisk=True) or {}).items():
            self.io_tree.insert("", "end", values=(dev, human_bytes(c.read_bytes), human_bytes(c.write_bytes), c.read_count, c.write_count))

    def refresh_services(self):
        self.service_tree.delete(*self.service_tree.get_children())
        if not shutil.which("systemctl"):
            self.service_tree.insert("", "end", values=("systemctl unavailable", "", "", "", ""))
            return
        out = run_cmd(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"], timeout=8)
        for line in out.splitlines():
            parts = line.split(None, 4)
            if len(parts) >= 4:
                self.service_tree.insert("", "end", values=(*parts[:4], parts[4] if len(parts) > 4 else ""))

    def refresh_logs(self):
        self.log_text.delete("1.0", "end")
        if not shutil.which("journalctl"):
            self.log_text.insert("end", "journalctl is not available on this system.\n")
            return
        priority = self.log_priority.get() or "info"
        out = run_cmd(["journalctl", "-n", "500", "-p", f"0..{priority}", "--no-pager", "--output=short-iso"], timeout=8)
        needle = self.log_filter.get().lower().strip()
        if needle:
            out = "\n".join(line for line in out.splitlines() if needle in line.lower())
        self.log_text.insert("end", out or "No matching log entries, or access was denied.\n")

    def refresh_security(self):
        lines = []
        lines.append("[Listening ports]")
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
                    if line and not line.startswith("#") and line.lower().startswith(("permitrootlogin", "passwordauthentication", "pubkeyauthentication", "allowusers", "allowgroups")):
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
            "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
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
                report["filesystems"].append({"device": p.device, "mount": p.mountpoint, "fstype": p.fstype, "total": u.total, "used": u.used, "free": u.free, "percent": u.percent})
            except (PermissionError, OSError):
                pass
        procs = []
        for p in psutil.process_iter(["pid", "username", "name", "cpu_percent", "memory_percent", "cmdline"]):
            try:
                info = p.info
                info["cmdline"] = " ".join(info.get("cmdline") or [])
                procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        report["top_processes"] = sorted(procs, key=lambda x: (x.get("cpu_percent") or 0, x.get("memory_percent") or 0), reverse=True)[:50]
        return report

    def export_report(self, kind: str):
        report = self.collect_report()
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        if kind == "json":
            path = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"linux-monitor-{stamp}.json", filetypes=[("JSON", "*.json")])
            if not path:
                return
            Path(path).write_text(json.dumps(report, indent=2, default=str))
        else:
            path = filedialog.asksaveasfilename(defaultextension=".html", initialfile=f"linux-monitor-{stamp}.html", filetypes=[("HTML", "*.html")])
            if not path:
                return
            pretty = html.escape(json.dumps(report, indent=2, default=str))
            doc = f"""<!doctype html><html><head><meta charset='utf-8'><title>Linux Monitoring Report</title><style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px}}pre{{white-space:pre-wrap;background:#f4f4f4;padding:18px;border-radius:10px}}</style></head><body><h1>Linux Monitoring Report</h1><p>Host: <strong>{html.escape(report['host'])}</strong></p><p>Generated: {html.escape(report['generated_at'])}</p><pre>{pretty}</pre></body></html>"""
            Path(path).write_text(doc)
        messagebox.showinfo("Export complete", f"Saved report to:\n{path}")


if __name__ == "__main__":
    try:
        app = LinuxMonitor()
        app.mainloop()
    except tk.TclError as exc:
        raise SystemExit(f"Unable to start the GUI: {exc}. Is a graphical desktop available and is tkinter installed?")
