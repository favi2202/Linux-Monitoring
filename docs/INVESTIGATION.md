# Investigation Workspace

Linux Monitoring 0.2 adds a process-centric investigation workspace intended for troubleshooting, incident response, and learning how Linux activity connects together.

The key idea is simple: a PID should not be viewed in isolation.

```text
parent process
     ↓
selected PID ──→ executable / hash
     ├─────────→ child processes
     ├─────────→ network sockets
     ├─────────→ open files
     ├─────────→ systemd service
     └─────────→ journald events
```

The tool gathers these relationships without killing a process or changing the host.

## Starting an investigation

There are four entry points.

### Enter a PID directly

Open **Investigate**, enter a numeric PID, and press **Load**.

### Pivot from Processes

Open **Processes**, select a row, then click **Investigate selected**. Double-clicking the row performs the same pivot.

### Pivot from a socket

Open **Network** and double-click a socket. When Linux exposes the socket owner, the application opens the corresponding PID.

### Pivot from a service

Open **Services** and double-click a systemd service. The application obtains `MainPID` using `systemctl show` and opens that process if it is running.

## Process identity

The top panel records useful identity and execution context:

- PID and PPID
- process name
- user
- process state
- executable path
- current working directory
- full command line where visible
- creation time
- sampled CPU use
- RSS memory
- detected systemd service

The executable path is read from `/proc/<pid>/exe` first. This preserves the useful `(deleted)` marker Linux may expose when a process continues running after its original executable was removed.

## Relationships

The **Relationships** view shows the direct parent, the selected process, and its direct children.

Double-click a related process to pivot again. This makes it possible to walk a process chain without returning to the global process table each time.

Example investigation:

```text
systemd (PID 1)
  ↓
sshd
  ↓
sshd session
  ↓
bash
  ↓
python3
```

The relationship itself is evidence; it is not a verdict. A strange-looking parent/child pair needs context before being classified as suspicious.

## Sockets

The **Sockets** view is scoped to the selected process and displays:

- protocol
- local endpoint
- remote endpoint
- connection state
- basic direction/context

This helps answer questions such as:

- Does this process have an outbound connection?
- Is it listening on a port?
- Which endpoint is it communicating with?
- Does the network activity fit the purpose of the process?

Some socket ownership data is restricted to privileged users on Linux.

## Open files

The **Open Files** view uses `psutil` to list regular files currently opened by the selected process where the kernel and permissions expose them.

Useful things to inspect include:

- unusual files in `/tmp`, `/var/tmp`, or user download directories
- configuration files the process is reading
- logs the process is writing
- database files
- staged payloads or scripts in a lab

An empty list does not prove the process has no file descriptors. `psutil.open_files()` focuses on regular files and visibility is permission-dependent.

## Related logs

The **Related Logs** view queries journald in two ways:

```bash
journalctl _PID=<pid>
```

and, when a systemd service is detected:

```bash
journalctl -u <unit.service>
```

The app merges duplicate lines and shows recent events.

There are important limitations:

- PID reuse means old logs should always be interpreted with timestamps.
- not every application writes to journald
- containers may have separate logging paths
- current permissions may hide system logs
- a process that has already exited cannot be inspected live even though its logs may remain

## systemd correlation

The application reads `/proc/<pid>/cgroup` and looks for a `.service` component. When found, it queries systemd for properties including:

```text
Id
Description
LoadState
ActiveState
SubState
MainPID
User
Group
ExecStart
FragmentPath
UnitFileState
Restart
MemoryCurrent
TasksCurrent
```

This is useful for distinguishing a manually launched process from one managed by a service and for finding the unit file or configured command responsible for it.

Not every Linux process belongs directly to a `.service` unit. Desktop applications, shell commands, containers, scopes, and user sessions may be managed differently.

## Context cues

The app generates a few lightweight cues to focus attention. Current checks include:

- executable marked `(deleted)`
- executable launched from `/tmp`, `/var/tmp`, or `/dev/shm`
- active remote connections
- listening sockets
- root execution context
- no detected systemd service
- command line containing tools such as `curl`, `wget`, `nc`, `ncat`, or `socat`

These are **not detection rules and not malicious/benign labels**. They are investigation prompts.

For example, this is normal on many systems:

```bash
root ... /usr/sbin/sshd
```

and this may be perfectly legitimate:

```bash
curl https://example.org/update.json
```

Use the cues to decide what to inspect next, not as automated conclusions.

## SHA-256 executable hashing

Press **SHA-256 executable** to hash the selected process's executable file.

The file is opened read-only and processed in chunks. The application does not execute it.

The hash can be useful for:

- comparing a binary with a known baseline
- searching an approved threat-intelligence source manually
- documenting an investigation
- checking whether two hosts have the same binary

If the executable was deleted or cannot be read with the current account, hashing may not be possible.

## Investigation snapshots

Press **Export snapshot** to save the current investigation as JSON.

The snapshot can include:

- process identity
- command line and executable path
- relationships
- sockets
- open files
- journal excerpts
- systemd metadata
- executable hash, if calculated
- context cues

This is a point-in-time snapshot, not a forensic acquisition. Processes, sockets, and files can change immediately after collection.

## Permissions

Run the application as your normal account first.

```bash
./run.sh
```

If an authorized lab or troubleshooting task requires broader visibility:

```bash
sudo .venv/bin/python3 linux_monitor.py
```

Elevating the entire GUI increases the impact of any software bug and may cause root-owned files to be created in places you did not expect, so it should not be the default.

## What this is not

Linux Monitoring is not currently:

- an EDR agent
- a packet-capture engine
- a forensic disk-imaging tool
- a malware sandbox
- a kernel event recorder
- a remediation tool

It is a fast inspection and correlation interface built on live Linux state plus standard system tools.

## Good next investigations

Try the workspace against harmless processes first:

```bash
sleep 300
python3 -m http.server 8000
ssh localhost
```

Observe how process ancestry, sockets, files, services, and logs differ. Learning the normal relationships makes abnormal ones much easier to recognize later.
