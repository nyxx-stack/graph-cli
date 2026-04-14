"""First-run diagnostics for GraphConnect."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass

from graphconnect.auth import CONFIG_FILE, _powershell_executable, _run_powershell, status
from graphconnect.output import console, print_json, print_table


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str
    fix: str = ""


def run_doctor(output_format: str = "table") -> int:
    """Run environment checks and print actionable results."""
    checks = [
        _check_python(),
        _check_powershell(),
        _check_sdk(),
        _check_graph_module(),
        _check_auth(),
    ]

    if output_format == "json":
        print_json([check.__dict__ for check in checks])
    else:
        print_table(
            [
                {
                    "check": check.name,
                    "status": check.status,
                    "detail": check.detail,
                    "fix": check.fix,
                }
                for check in checks
            ],
            title="GraphConnect doctor",
        )

    failed = [check for check in checks if check.status == "fail"]
    if failed and output_format != "json":
        console.print("\n[bold]Next steps[/bold]")
        for check in failed:
            console.print(f"- {check.fix}")
    return 0 if not failed else 1


def _check_python() -> CheckResult:
    version = sys.version_info
    if version >= (3, 12):
        return CheckResult("Python", "ok", f"{version.major}.{version.minor}.{version.micro}")
    return CheckResult(
        "Python",
        "fail",
        f"{version.major}.{version.minor}.{version.micro} detected; GraphConnect requires Python 3.12+.",
        "Install Python 3.12+ and recreate your virtual environment.",
    )


def _check_powershell() -> CheckResult:
    powershell = _powershell_executable()
    if powershell:
        return CheckResult("PowerShell", "ok", powershell)
    return CheckResult(
        "PowerShell",
        "fail",
        "Windows PowerShell was not found on PATH.",
        "Add `powershell.exe` to PATH or run GraphConnect on a Windows machine with PowerShell installed.",
    )


def _check_sdk() -> CheckResult:
    if importlib.util.find_spec("msgraph") is not None:
        return CheckResult("msgraph-sdk", "ok", "Python package import succeeded.")
    return CheckResult(
        "msgraph-sdk",
        "fail",
        "The Python `msgraph-sdk` package is not importable.",
        "Run `python -m pip install -e .` from the repo root.",
    )


def _check_graph_module() -> CheckResult:
    if not _powershell_executable():
        return CheckResult(
            "Microsoft.Graph module",
            "skip",
            "Skipped because PowerShell is unavailable.",
            "Install Windows PowerShell first, then run `Install-Module Microsoft.Graph -Scope CurrentUser`.",
        )

    result = _run_powershell(
        "if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) { 'installed' }",
        timeout=15,
    )
    if result.returncode == 0 and "installed" in (result.stdout or ""):
        return CheckResult("Microsoft.Graph module", "ok", "Microsoft.Graph.Authentication is installed.")
    return CheckResult(
        "Microsoft.Graph module",
        "fail",
        "Microsoft.Graph.Authentication is not installed for the current user.",
        "Run `Install-Module Microsoft.Graph -Scope CurrentUser` in PowerShell.",
    )


def _check_auth() -> CheckResult:
    auth = status()
    if auth.authenticated:
        detail = auth.user_principal or (auth.auth_method.value if auth.auth_method else "authenticated")
        return CheckResult("Auth", "ok", detail)
    return CheckResult(
        "Auth",
        "fail",
        f"No active Microsoft Graph session was detected. Config file path: {CONFIG_FILE}",
        "Run `graphconnect auth login` or `Connect-MgGraph -UseDeviceCode` first.",
    )
