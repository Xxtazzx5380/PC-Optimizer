# PC-Optimizer

A Python-first Windows PC auditing and optimization toolkit.

## Goals

PC-Optimizer is designed to:

- audit the current Windows installation;
- detect hardware and configuration;
- identify useful optimizations instead of applying generic tweak packs;
- create backups before system changes;
- apply reversible optimizations;
- verify changes;
- provide a complete rollback path;
- measure before/after results.

## Design

The main application is written in **Python**.

When Windows exposes a feature more reliably through a native interface, Python may invoke tools such as PowerShell, Registry APIs/commands, or other Windows utilities. These are implementation details; the project itself remains Python-first.

## Safety principles

1. Audit before changing anything.
2. Never apply an optimization blindly.
3. Back up every setting that will be changed.
4. Prefer documented/reversible settings.
5. Separate safe, advanced, and experimental tweaks.
6. Do not promise FPS or latency gains without measurement.
7. Keep a rollback mechanism.

## Current status

V1 contains the Python entry point and a non-destructive system audit.

Run:

```powershell
python optimizer.py
```

Run it as Administrator when system-level functionality is introduced.

## Planned modules

- hardware detection
- Windows configuration audit
- registry backup/restore
- registry optimization
- services and startup analysis
- power-plan management
- GPU configuration
- network analysis
- gaming profile
- streaming profile
- before/after benchmarking
- rollback
- structured JSON reports

## License

To be decided.
