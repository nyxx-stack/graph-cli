# Troubleshooting

## `graphconnect` is not recognized

Use the module entrypoint instead:

```powershell
python -m graphconnect --help
```

If that works, your Python script directory is not on `PATH`.

## `doctor` says PowerShell is missing

GraphConnect is Windows-first and expects PowerShell to be installed and available on `PATH`.

## `doctor` says Microsoft.Graph.Authentication is missing

Install the Graph PowerShell module for the current user:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Auth is not detected

Recommended:

```powershell
Connect-MgGraph -UseDeviceCode
graphconnect auth status
```

Fallback:

```powershell
graphconnect auth login
```

## Device-code fallback is still not working

Set these environment variables or create `~/.graphconnect/config.yaml`:

```powershell
$env:MSGRAPH_TENANT_ID = "<tenant-id>"
$env:MSGRAPH_CLIENT_ID = "<client-id>"
```

## A write command failed

- Re-run the command without `--execute` to get a fresh preview token
- Make sure the parameters match the preview exactly
- Check `~/.graphconnect/audit.jsonl` for the recorded operation result
