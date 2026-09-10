# Linux Monitoring

A lightweight, local-first Linux desktop inspector for quickly understanding what a system is doing: CPU, memory, disks, network, processes, sockets, services, logs, and basic security posture.

The project is read-only by default. It reads standard Linux interfaces such as `/proc`, uses `psutil`, and calls common system tools such as `systemctl`, `journalctl`, `ss`, and `sensors` when available.

## Current version: 0.2.0

The main addition in 0.2.0 is the **cross-linked Investigation workspace**. Instead of checking processes, sockets, files, services, and logs separately, you can pivot from one process and inspect the related evidence together.

### What it can do

- Overview dashboard with CPU, memory, swap, disk, network, uptime, OS, kernel, and load averages
- Per-core CPU usage
- Process table with PID, PPID, user, CPU, RAM, state, command line
- **Process investigation workspace**
  - process identity, executable, CWD, start time and resource use
  - parent and child process relationships
  - active/listening sockets owned by the process
  - open files
  - best-effort mapping to its systemd service
  - related `journalctl` entries by PID and systemd unit
  - SHA-256 hashing of the executable
  - lightweight investigation cues such as deleted executables, execution from `/tmp`/`/dev/shm`, active remote connections, root context, and network utilities in command lines
  - JSON investigation snapshot export
- Network interface counters and system-wide socket view
- Double-click a socket to investigate its owning PID
- Double-click a service to pivot to its `MainPID`
- Disk usage and disk I/O statistics
- systemd service overview
- journalctl viewer with severity and text filters
- Basic security checks for listening ports, SSH configuration, SELinux/AppArmor, sudo configuration, and firewall tooling
- Export point-in-time system reports to JSON or HTML
- Automatic refresh
- No agent, database, or cloud account required

The investigation cues are **context, not verdicts**. For example, a root process or a process using `curl` is not automatically malicious.

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

On Debian/Ubuntu/Kali:

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

## Investigation workflow

A practical workflow is:

```text
Processes / Network / Services
          ↓
      choose a PID
          ↓
       Investigate
          ↓
 identity + parent/children
          ↓
 sockets ↔ files ↔ systemd ↔ journal
          ↓
 hash executable / export snapshot
```

### From Processes

Open **Processes**, select a row, and click **Investigate selected** or double-click the process.

### From Network

Open **Network** and double-click a socket. If the owning PID is visible, the app pivots directly into that process investigation.

### From Services

Open **Services** and double-click a service. The app asks systemd for its `MainPID` and pivots to that process when it is running.

### Inside Investigate

The Investigation tab contains:

- **Process identity & pivots** — PID/PPID, user, command, executable, CWD, start time, memory, systemd unit, and context cues
- **Relationships** — parent, selected process, and direct children; double-click another PID to pivot again
- **Sockets** — local/remote endpoints and connection state
- **Open Files** — files currently held by the process where permissions allow
- **Related Logs** — recent journald entries correlated using `_PID=<pid>` and the detected service unit
- **systemd** — service state, `ExecStart`, unit file, user/group, restart policy, memory/tasks and other useful properties

Use **SHA-256 executable** to hash the executable on disk without running or modifying it. Use **Export snapshot** to save the gathered investigation data as JSON.

More details are in [`docs/INVESTIGATION.md`](docs/INVESTIGATION.md).

## Permissions

The app is designed to work as your normal user. Linux intentionally restricts visibility into some other users' processes, file descriptors, sockets, and logs.

Start normally:

```bash
./run.sh
```

Only when a lab or investigation genuinely requires broader visibility, you can run:

```bash
sudo .venv/bin/python3 linux_monitor.py
```

Do not make running the whole GUI as root your default workflow.

If a socket has no visible PID or a process shows fewer files/logs than expected, that may simply be a permissions boundary rather than missing data.

## Tabs

### Overview

Live CPU, RAM, swap, filesystem usage, network throughput, load, uptime, host information, and per-core utilization.

### Processes

Filter running processes by PID, PPID, user, name, or command. Double-click a process to pivot into Investigate.

### Investigate

Cross-links one selected PID to process relationships, sockets, open files, systemd context, journald events, executable hashing, and an exportable investigation snapshot.

### Network

Shows interface counters and active TCP/UDP sockets. Double-click a socket to investigate the owning process.

### Disks

Mounted filesystems plus read/write counters and I/O activity.

### Services

Reads `systemctl` and lists service state. Double-click a service to investigate its current `MainPID`.

### Logs

Reads recent `journalctl` entries and supports text/priority filtering.

### Security

Non-destructive checks for listening ports, firewall tooling, SSH configuration, SELinux/AppArmor, and sudo policy locations.

## Exporting reports

Use **File → Export system JSON** or **File → Export system HTML** for a system snapshot.

For a focused process investigation, use **Investigate → Export snapshot** or **File → Export investigation JSON**.

Exports can contain hostnames, usernames, IP addresses, file paths, command lines, and logs. Review them before sharing.

## Security model

This tool does not kill processes, modify services, edit files, change firewall rules, or execute remediation commands. The current application is an inspection tool.

The program may read command lines, open-file paths, network endpoints, service metadata, and logs that are already visible to the account running it. Treat exported data as potentially sensitive.

## Planned

- Historical graphs and short-term local sampling
- Full process ancestry tree and descendant graph
- Better `/proc/<pid>/fd` inspection and deleted-file visibility
- systemd timer inspection
- Better temperature and hardware sensor support
- Saved investigation history and diffing
- Alert thresholds
- PDF report export
- AppImage, `.deb`, and `.rpm` packaging

## Design goals

- Low idle overhead
- Read-only by default
- Analyst-friendly pivots instead of disconnected metrics
- Clear explanations instead of unexplained numbers
- Useful on a workstation, server VM, or incident-response lab
- Graceful fallback when an optional Linux command is unavailable

The long-term performance target is below roughly 2% CPU while idle and below roughly 100 MB RAM for the packaged application. The Python/Tkinter version is a development baseline; measure on the target distro rather than assuming those figures are guaranteed.

## Project structure

```text
Linux-Monitoring/
├── linux_monitor.py          # Desktop application
├── requirements.txt          # Python dependencies
├── install.sh                # Creates venv and installs dependencies
├── run.sh                    # Starts the application
├── docs/
│   └── INVESTIGATION.md      # Investigation workflow and field guide
├── .gitignore
├── LICENSE
└── README.md
```

## License

MIT License. See [LICENSE](LICENSE).
