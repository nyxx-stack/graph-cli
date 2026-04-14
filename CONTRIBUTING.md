# Contributing

## Local Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
python -m pytest -q
```

## Contribution Rules

- Keep the CLI Windows-first unless the change explicitly broadens platform support
- Preserve the catalog-driven model and preview-before-execute safety behavior
- Add or update tests when you change command behavior, auth logic, or request execution
- Keep README and quickstart examples aligned with real command output

## Pull Requests

- Explain the operator problem being solved
- Call out any changes to the public CLI surface
- Mention any new Microsoft Graph scopes or catalog entries
- Include the test commands you ran
