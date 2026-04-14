# GraphConnect

GraphConnect is a Windows-first operator CLI for Intune and Entra workflows. It wraps a curated Microsoft Graph catalog with safer defaults: easy catalog discovery, read-only queries, write previews, and explicit confirmation tokens before changes execute.

It is built on Microsoft Graph and uses `Connect-MgGraph`-style authentication flows, but it is not an official Microsoft tool.

## What You Get

- A searchable catalog of bundled Intune, Entra, audit, compliance, and policy operations
- `read` commands for common tenant inspection tasks
- `write` commands that preview first and require a confirmation token to execute
- PowerShell-first auth support with Graph PowerShell, plus Azure CLI, Azure PowerShell, and app-registration fallback paths
- Local audit logs and pending-token state in `~/.graphconnect`

## Prerequisites

- Windows with PowerShell available on `PATH`
- Python 3.12 or newer
- Microsoft Graph PowerShell module installed for the current user:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## 60-Second Quickstart

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
graphconnect doctor
graphconnect auth login
graphconnect catalog search device compliance
graphconnect read devices.list_managed --top 5
```

If the script path is not on `PATH`, use the module form instead:

```powershell
python -m graphconnect --help
python -m graphconnect doctor
```

## First Useful Commands

Browse what ships in the catalog:

```powershell
graphconnect catalog list
graphconnect catalog detail devices.list_managed
```

Run a read-only query:

```powershell
graphconnect read devices.list_stale --param days_inactive=30 --top 10
```

Preview a write without applying it:

```powershell
graphconnect write devices.sync_device --param device_id=<managed-device-id>
```

That command returns a short-lived token. To actually apply the change, rerun it with `--execute --token <token>`.

## How Auth Works

GraphConnect checks auth in this order:

1. Existing Microsoft Graph PowerShell context from `Connect-MgGraph`
2. Device-code auth using `MSGRAPH_TENANT_ID` and `MSGRAPH_CLIENT_ID`, or `~/.graphconnect/config.yaml`
3. Existing Azure CLI login
4. Existing Azure PowerShell login

The recommended path is still Graph PowerShell:

```powershell
Connect-MgGraph -UseDeviceCode
graphconnect auth status
```

## Architecture

GraphConnect does not expose arbitrary Microsoft Graph access. It executes only the curated operations defined in the local YAML catalog under `catalog/`.

- `catalog` helps users discover supported operations
- `read` builds Graph GET requests from catalog metadata
- `write` always previews first and requires a confirmation token before execution
- `doctor` validates local prerequisites and points to the next command to run

## Troubleshooting

- Start with `graphconnect doctor`
- If you see auth failures, run `Connect-MgGraph -UseDeviceCode` or `graphconnect auth login`
- If `graphconnect` is not recognized, use `python -m graphconnect ...`
- If the Graph PowerShell module is missing, run `Install-Module Microsoft.Graph -Scope CurrentUser`

More detail is in [docs/quickstart.md](docs/quickstart.md) and [docs/troubleshooting.md](docs/troubleshooting.md).
