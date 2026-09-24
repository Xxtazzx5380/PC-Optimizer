# PC-Optimizer

Python-first, conservative Windows 10/11 audit and optimization toolkit.

## Safety model

PC-Optimizer is deliberately **not** a generic tweak pack.

- Default mode is read-only.
- Experimental optimizations are blocked by policy.
- Mutations require Administrator privileges.
- Every mutation creates a JSON manifest before changing the system.
- Manifests contain the original state plus SHA-256 integrity hashes.
- Rollback restores the state captured by the manifest.
- Post-change verification is performed where a reliable verification API exists.
- Windows Defender, security services, and Windows Firewall are never targeted.
- Windows Update is never disabled. A safety optimization can restore a disabled
  Windows Update service instead.
- No external Python dependencies are required.

## Current modules

### Safe

- expanded system audit: RAM, top memory/CPU processes, running services,
  startup items, scheduled tasks, active power plan;
- Windows visual effects;
- Windows-managed page file;
- TRIM state;
- Windows Update availability.

### Caution

- High Performance power plan;
- AC processor performance minimum/maximum and core parking;
- selected non-security services (SysMain, WSearch, DiagTrack);
- background Windows apps;
- Game Mode;
- Game DVR capture;
- minimum diagnostic-data policy;
- explicitly selected startup registry entries;
- explicitly selected scheduled tasks;
- explicitly selected DNS servers;
- TikTok LIVE Studio process priority;
- per-application GPU preference.

### Experimental (disabled by default)

- HAGS registry setting;
- multimedia NetworkThrottlingIndex;
- TCP TcpAckFrequency / TCPNoDelay / TcpDelAckTicks.

The experimental category is intentionally blocked by OptimizationPolicy.allow_experimental = False.

## Important design decisions

Some popular Internet tweaks are intentionally **not** applied automatically.

### Windows Search / SysMain

Disabling these services can reduce background activity on some machines, but it is not
universally beneficial. Microsoft documents Windows Search as a normal Windows component
and warns that optimization utilities disabling it can affect Search. These modules are
therefore Caution rather than Safe.

### Windows Update

The optimizer does not disable wuauserv, BITS, Update Orchestrator, or Windows Update
policies. Windows servicing and security updates are part of system stability.

### Networking

DNS selection is environment-dependent. Nagle, TCP throttling and QoS changes can be
workload-dependent and are therefore not part of the Safe profile.

### Streaming encoding

There is no reliable Windows-wide registry switch that magically makes TikTok LIVE Studio
encode better on a weak CPU. The project audits encoder pressure rather than inventing
application-specific settings. Encoder choice/quality should be measured in the target
application.

## Running

```powershell
python optimizer.py
python optimizer.py list
python optimizer.py check
python optimizer.py apply visual-effects
python optimizer.py rollback backups\\manifest_YYYYMMDD_HHMMSS_xxxxxx.json
```

The default command performs a read-only audit. Mutations are never automatic.

- `list` shows every optimization and its **Safe/Caution/Experimental** risk level.
- `check` runs each configured `check()`; target-specific optimizations report when explicit parameters are required.
- `apply <id>` shows the risk and reason, then requires typing `APPLY` before mutation.
- `rollback <manifest>` reconstructs the optimization from the manifest and requires typing `ROLLBACK`.
- `--allow-experimental` explicitly unlocks Experimental mutations for that invocation. **Dangerous: this is intentionally not enabled by default.**
- Parameterized targets require explicit values, for example `--task`, `--dns-interface` + `--dns`, `--nagle-guid`, or `--tiktok-exe`.
- A non-administrator process is refused before any mutation/rollback.

The default command performs a read-only audit and writes:

- reports/ — JSON audit reports
- logs/ — optimizer log
- backups/ — mutation manifests

Run from an elevated terminal when you intend to use system-level optimizations.

## Testing

```powershell
python -m unittest discover -s tests -v
```

Tests mock native Windows calls and do not intentionally mutate the host configuration.

## Native Windows interfaces used

The project remains Python-first. It calls Windows native tools only when those tools
are the appropriate interface:

- PowerShell for CIM/Windows management APIs;
- powercfg.exe for processor/power-plan configuration;
- sc.exe for service configuration;
- schtasks.exe for scheduled tasks;
- fsutil.exe for NTFS/TRIM state.

No command is executed through shell=True.

## References

The implementation follows Microsoft documentation for processor power management,
core parking, Windows services, scheduled tasks, TRIM, diagnostic-data policy, and
Windows Update behavior.
