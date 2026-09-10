# Linux Monitoring

A lightweight Linux desktop inspector for quickly understanding what a system is doing: CPU, memory, disks, network, processes, sockets, services, logs, and basic security posture.

The project is local-first and read-only by default. It reads standard Linux interfaces such as `/proc`, uses `psutil`, and calls common system tools such as `systemctl`, `journalctl`, `ss`, and `sensors` when available.

## Current MVP

- Overview dashboard with CPU, memory, swap, disk, network, uptime, OS, kernel, and load averages
- Per-core CPU usage
- Process table with PID, user, CPU, RAM, state, command and a detailed process view
- Network interface counters and active socket view
- Disk usage and disk I/O statistics
- systemd service overview
- journalctl viewer with severity and text filters
- Basic security checks for listening ports, SSH configuration, SELinux/AppArmor, sudo configuration, and firewall tooling
- Export a point-in-time system report to JSON or HTML
- Automatic refresh with a configurable interval
- No agent, database, or cloud account required

## Planned

- Deeper process → sockets → files → logs investigation links
- Historical graphs and short-term local sampling
- systemd timer inspection
- Better temperature and hardware sensor support
- PDF report export
- AppImage, `.deb`, and `.rpm` packaging
- Alert thresholds and saved investigation snapshots

## Requirements

Recommended: Python 3.10+ on a Linux desktop.

Required Python package:

```bash
psutil
```

Optional system tools improve coverage:

```bash
systemctl
journalctl
ss
sensors
ip
```

On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-tk lm-sensors iproute2
```

On Fedora:

```bash
sudo dnf install -y python3 python3-tkinter lm_sensors iproute
```

## Quick start

```bash
git clone https://github.com/favi2202/Linux-Monitoring.git
cd Linux-Monitoring

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 linux_monitor.py
```

Or use the helper scripts:

```bash
chmod +x install.sh run.sh
./install.sh
./run.sh
```

## Permissions

The app is designed to work without root. Some process details, sockets, logs, and security settings may be hidden by normal Linux permissions.

Run it as your normal user first. Only use elevated privileges when you specifically need data your account cannot read:

```bash
sudo .venv/bin/python3 linux_monitor.py
```

Do not make running the whole GUI as root your default workflow.

## Tabs

### Overview

Shows live system health: CPU, RAM, swap, filesystem usage, network throughput, load, uptime, host information, and per-core utilization.

### Processes

Filter running processes and double-click a row for a detailed view of the selected PID, including command line, executable path, open files, and connections where permissions allow.

### Network

Shows interface counters and active TCP/UDP sockets. Useful for answering questions such as “which process owns this connection?”

### Disks

Shows mounted filesystems plus read/write counters and I/O activity.

### Services

Reads `systemctl` and lists service state. Failed services are easy to spot.

### Logs

Reads recent `journalctl` entries and supports text/priority filtering.

### Security

Performs non-destructive checks for listening ports, firewall tooling, SSH configuration, SELinux/AppArmor, and sudo policy locations.

## Exporting reports

Use **File → Export JSON** or **File → Export HTML**. Reports are snapshots; they do not contain a continuous history of everything the machine has done.

Be careful before sharing exported reports. Hostnames, usernames, IP addresses, process command lines, and other environment information can be sensitive.

## Design goals

- Low idle overhead
- Read-only by default
- Clear explanations instead of unexplained numbers
- Useful on a workstation, server VM, or incident-response lab
- Graceful fallback when an optional Linux command is unavailable

The long-term performance target is below roughly 2% CPU while idle and below roughly 100 MB RAM for the packaged application. The Python/Tkinter MVP is a development baseline; measure on your target distro rather than assuming those numbers are guaranteed.

## Project structure

```text
Linux-Monitoring/
├── linux_monitor.py     # Desktop application
├── requirements.txt     # Python dependencies
├── install.sh           # Creates venv and installs dependencies
├── run.sh               # Starts the application
├── .gitignore
├── LICENSE
└── README.md
```

## Security model

This tool does not execute remediation actions, kill processes, edit configuration files, or modify firewall rules. The current MVP is an inspection tool. Any future action-oriented feature should require explicit confirmation and clearly show the command/change before execution.

## License

MIT License. See [LICENSE](LICENSE).
