# Quickstart

## Install

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

## Verify the Environment

```powershell
graphconnect doctor
```

Expected first-run checks:

- Python 3.12+
- PowerShell found
- `msgraph-sdk` import succeeds
- `Microsoft.Graph.Authentication` module is installed
- Auth is either active or the command tells you what to run next

If `graphconnect` is not on `PATH`, use:

```powershell
python -m graphconnect doctor
```

## Authenticate

Recommended:

```powershell
Connect-MgGraph -UseDeviceCode
graphconnect auth status
```

CLI-driven fallback:

```powershell
graphconnect auth login
```

App-registration fallback:

```powershell
$env:MSGRAPH_TENANT_ID = "<tenant-id>"
$env:MSGRAPH_CLIENT_ID = "<client-id>"
graphconnect auth status
```

## Discover Operations

```powershell
graphconnect catalog search stale devices
graphconnect catalog list --domain devices
graphconnect catalog detail devices.list_stale
```

## Run a Read Query

```powershell
graphconnect read devices.list_stale --param days_inactive=30 --top 10
```

## Preview a Write

```powershell
graphconnect write devices.sync_device --param device_id=<managed-device-id>
```

Preview is the default. GraphConnect prints the exact execute command only after it has shown the preview.
