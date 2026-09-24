#!/usr/bin/env python3
"""PC-Optimizer command-line interface."""
from __future__ import annotations
import argparse, json, os
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from core.backup import load_manifest
from core.logging_utils import configure
from core.policy import OptimizationPolicy, PolicyViolation, Risk
from core.system import is_admin, snapshot
from optimizations.base import Optimization
from optimizations.optional import (
    DnsOptimization, NagleOptimization, NetworkQosAudit,
    ScheduledTaskOptimization, StartupRegistryOptimization,
    StreamingEncodingAudit, WindowsUpdateSafetyOptimization,
)
from optimizations.windows import (
    BackgroundAppsOptimization, GameDvrOptimization, GameModeOptimization,
    HagsOptimization, MultimediaNetworkOptimization, PagefileOptimization,
    PowerPlanOptimization, ProcessorPerformanceOptimization, ServiceOptimization,
    TelemetryOptimization, TikTokGpuPreferenceOptimization,
    TikTokProcessOptimization, TrimOptimization, VisualEffectsOptimization,
)

APP_NAME="PC-Optimizer"
ROOT=Path(__file__).resolve().parent
REPORTS=ROOT/"reports"
LOGS=ROOT/"logs"

def save_report(data: dict)->Path:
    REPORTS.mkdir(parents=True, exist_ok=True)
    path=REPORTS/f"audit_{datetime.now():%Y%m%d_%H%M%S}.json"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path

def build_optimizations(args: argparse.Namespace)->list[Optimization]:
    items: list[Optimization]=[
        VisualEffectsOptimization(), TrimOptimization(), PagefileOptimization(),
        PowerPlanOptimization(), ProcessorPerformanceOptimization(),
        ServiceOptimization("SysMain"), ServiceOptimization("WSearch"),
        ServiceOptimization("DiagTrack"), BackgroundAppsOptimization(),
        GameModeOptimization(), GameDvrOptimization(), TelemetryOptimization(),
        MultimediaNetworkOptimization(), HagsOptimization(),
        TikTokProcessOptimization(), WindowsUpdateSafetyOptimization(),
        NetworkQosAudit(), StreamingEncodingAudit(),
    ]
    if args.startup_hive and args.startup_name:
        items.append(StartupRegistryOptimization(args.startup_hive,args.startup_name,args.run_once))
    if args.task:
        items.append(ScheduledTaskOptimization(args.task))
    if args.dns_interface and args.dns:
        items.append(DnsOptimization(args.dns_interface,tuple(args.dns)))
    if args.nagle_guid:
        items.append(NagleOptimization(args.nagle_guid))
    if args.tiktok_exe:
        items.append(TikTokGpuPreferenceOptimization(args.tiktok_exe))
    return items

PARAMS={
    "startup-registry-entry":"--startup-hive HKCU|HKLM --startup-name NAME [--run-once]",
    "scheduled-task":"--task TASK_PATH",
    "dns-servers":"--dns-interface ALIAS --dns SERVER [SERVER ...]",
    "tcp-nagle":"--nagle-guid GUID",
    "tiktok-gpu-preference":"--tiktok-exe PATH",
}
PARAM_IDS=set(PARAMS)

def command_audit(logger)->int:
    try:
        system=snapshot()
        print("="*64); print(f" {APP_NAME}"); print("="*64)
        print(f"Administrator : {'YES' if system.administrator else 'NO'}")
        print(f"Windows       : {system.os}")
        print(f"Architecture  : {system.architecture}")
        print(f"CPU           : {system.processor}")
        print(f"RAM           : {system.ram_used_mb} / {system.ram_total_mb} MB")
        print(f"GPUs          : {len(system.gpus)}")
        print(f"Running svcs  : {len(system.services)}")
        print(f"Startup items : {len(system.startup)}")
        print(f"Power plan    : {system.power_plan}")
        report=save_report(asdict(system))
        print(f"\nAudit saved to: {report}")
        if not system.administrator:
            print("\nWARNING: system-level mutations require Administrator privileges.")
        print("No optimization has been applied.")
        return 0
    except Exception as exc:
        logger.exception("System audit failed")
        print(f"Audit failed: {exc}"); return 1

def command_list(args)->int:
    print("ID                              RISK         STATUS       NAME")
    for o in build_optimizations(args):
        configured="unconfigured" if o.id in PARAM_IDS and o.id not in {
            "startup-registry-entry" if args.startup_hive and args.startup_name else "",
            "scheduled-task" if args.task else "",
            "dns-servers" if args.dns_interface and args.dns else "",
            "tcp-nagle" if args.nagle_guid else "",
            "tiktok-gpu-preference" if args.tiktok_exe else "",
        } else "configured"
        print(f"{o.id:<31} {o.risk.value.upper():<12} {configured:<12} {o.name}")
        if configured=="unconfigured": print(f"  -> {PARAMS[o.id]}")
    print("\nExperimental optimizations are blocked unless --allow-experimental is supplied.")
    return 0

def command_check(args)->int:
    errors=0
    for o in build_optimizations(args):
        try:
            r=o.check()
            print(f"{o.id:<31} risk={o.risk.value:<12} applicable={str(r.applicable):<5} reason={r.reason}")
        except Exception as exc:
            errors+=1
            print(f"{o.id:<31} risk={o.risk.value:<12} CHECK ERROR: {exc}")
    return 1 if errors else 0

def _confirm(o: Optimization, reason: str)->bool:
    print("\nMutation requested:")
    print(f"  ID     : {o.id}\n  Name   : {o.name}\n  Risk   : {o.risk.value.upper()}\n  Reason : {reason}")
    if o.risk==Risk.CAUTION:
        print("  WARNING: this can change system behavior, power use or background activity.")
    if o.risk==Risk.EXPERIMENTAL:
        print("  WARNING: EXPERIMENTAL. Results are workload-dependent and may require rollback/reboot.")
    return input("Type APPLY to confirm this exact mutation: ").strip()=="APPLY"

def command_apply(args)->int:
    if not is_admin():
        print("Mutation refused: Administrator privileges are required.")
        print("Run this command from an elevated PowerShell/Command Prompt.")
        return 2
    try:
        o=next(x for x in build_optimizations(args) if x.id==args.optimization)
        r=o.check()
        if not r.applicable:
            print(f"Not applicable: {r.reason}"); return 0
        if not _confirm(o,r.reason):
            print("Cancelled. No mutation was performed."); return 0
        o.apply()
        print(f"Applied: {o.id}\nManifest: {o.last_manifest}")
        return 0
    except StopIteration:
        print(f"Unknown or unconfigured optimization: {args.optimization}")
        return 1
    except (PolicyViolation,PermissionError) as exc:
        print(f"Mutation refused by safety policy: {exc}"); return 2
    except Exception as exc:
        print(f"Mutation failed: {exc}"); return 1

def _from_manifest(data:dict)->Optimization:
    oid=data["items"]["optimization"]["value"]
    if oid=="optional-windows-services":
        return ServiceOptimization(data["items"]["service"]["value"]["Name"])
    if oid=="startup-registry-entry":
        s=data["items"]["registry_state"]["value"]
        return StartupRegistryOptimization(s["hive"],s["name"],"RunOnce" in s["path"])
    if oid=="scheduled-task":
        return ScheduledTaskOptimization(data["items"]["task_path"]["value"])
    if oid=="dns-servers":
        d=data["items"]
        return DnsOptimization(d["interface_alias"]["value"],tuple(d["dns"]["value"]))
    if oid=="tcp-nagle":
        s=data["items"]["registry_states"]["value"][0]
        guid=s["path"].rsplit("\\",1)[-1]
        return NagleOptimization(guid)
    if oid=="tiktok-gpu-preference":
        return TikTokGpuPreferenceOptimization(data["items"]["registry_state"]["value"]["name"])
    classes={
        "visual-effects":VisualEffectsOptimization,"trim":TrimOptimization,
        "pagefile-system-managed":PagefileOptimization,
        "power-plan-high-performance":PowerPlanOptimization,
        "processor-ac-performance":ProcessorPerformanceOptimization,
        "background-apps":BackgroundAppsOptimization,"game-mode":GameModeOptimization,
        "game-dvr-off":GameDvrOptimization,"diagnostic-data-minimum":TelemetryOptimization,
        "multimedia-network":MultimediaNetworkOptimization,"hags":HagsOptimization,
        "tiktok-process":TikTokProcessOptimization,"windows-update-safety":WindowsUpdateSafetyOptimization,
        "network-qos-audit":NetworkQosAudit,"streaming-encoding-audit":StreamingEncodingAudit,
    }
    if oid in classes: return classes[oid]()
    raise ValueError(f"Unsupported manifest optimization: {oid}")

def command_rollback(args)->int:
    if not is_admin():
        print("Rollback refused: Administrator privileges are required."); return 2
    path=Path(args.manifest)
    if not path.is_file():
        print(f"Manifest not found: {path}"); return 1
    try:
        data=load_manifest(path); o=_from_manifest(data); o.last_manifest=path
        print(f"Rollback: {o.id} ({o.name})\nRisk: {o.risk.value.upper()}")
        if input("Type ROLLBACK to confirm restoration from this manifest: ").strip()!="ROLLBACK":
            print("Cancelled. No mutation was performed."); return 0
        o.rollback(); print("Rollback completed."); return 0
    except (PolicyViolation,PermissionError) as exc:
        print(f"Rollback refused by safety policy: {exc}"); return 2
    except Exception as exc:
        print(f"Rollback failed: {exc}"); return 1

def build_parser()->argparse.ArgumentParser:
    p=argparse.ArgumentParser(description="Conservative Windows audit and optimization CLI.")
    p.add_argument("--allow-experimental",action="store_true",
                   help="DANGEROUS: allow Experimental optimizations for this invocation.")
    p.add_argument("--startup-hive",choices=("HKCU","HKLM")); p.add_argument("--startup-name")
    p.add_argument("--run-once",action="store_true"); p.add_argument("--task")
    p.add_argument("--dns-interface"); p.add_argument("--dns",nargs="+")
    p.add_argument("--nagle-guid"); p.add_argument("--tiktok-exe")
    sub=p.add_subparsers(dest="command")
    sub.add_parser("audit",help="Read-only system audit.")
    sub.add_parser("list",help="List optimizations and risk levels.")
    sub.add_parser("check",help="Run check() for available optimizations.")
    a=sub.add_parser("apply",help="Interactively apply one optimization.")
    a.add_argument("optimization",help="Optimization ID from 'list'.")
    r=sub.add_parser("rollback",help="Rollback from a manifest.")
    r.add_argument("manifest",help="Path to a JSON manifest in backups/.")
    return p

def main(argv:list[str]|None=None)->int:
    if os.name!="nt":
        print("PC-Optimizer is designed for Windows."); return 1
    logger=configure(LOGS); args=build_parser().parse_args(argv)
    OptimizationPolicy.allow_experimental=bool(args.allow_experimental)
    if args.command in (None,"audit"): return command_audit(logger)
    if args.command=="list": return command_list(args)
    if args.command=="check": return command_check(args)
    if args.command=="apply": return command_apply(args)
    if args.command=="rollback": return command_rollback(args)
    return 2

if __name__=="__main__":
    raise SystemExit(main())
