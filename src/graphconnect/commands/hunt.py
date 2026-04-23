"""`hunt` verb: run Microsoft Graph Security advanced hunting (KQL) queries."""

from __future__ import annotations

import asyncio
import re
import uuid
from pathlib import Path
from typing import Any

import typer

from graphconnect.auth import list_profiles
from graphconnect.output import emit
from graphconnect.transport import graph_request
from graphconnect.transport.client import GraphTransportError
from graphconnect.types import Envelope, ErrorCode, ErrorPayload


SNIPPETS_DIR = Path(__file__).resolve().parents[3] / "catalog" / "_hunts"
HUNT_ENDPOINT = "/security/runHuntingQuery"
DEFAULT_TIMESPAN = "P7D"
_ISO_TIMESPAN_RE = re.compile(r"^P(?:\d+D|T\d+H|\d+DT\d+H|\d+W)$", re.IGNORECASE)


def _snippets_dir() -> Path:
    return SNIPPETS_DIR


def _parse_snippet_header(text: str) -> tuple[str, str]:
    title = ""
    description = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("//"):
            if line:
                break
            continue
        stripped = line.lstrip("/").strip()
        low = stripped.lower()
        if low.startswith("title:"):
            title = stripped.split(":", 1)[1].strip()
        elif low.startswith("description:"):
            description = stripped.split(":", 1)[1].strip()
    return title, description


def _list_snippet_files(directory: Path | None = None) -> list[Path]:
    root = directory or _snippets_dir()
    if not root.exists():
        return []
    return sorted(p for p in root.iterdir() if p.is_file() and p.suffix.lower() == ".kql")


def _load_snippet(name: str, directory: Path | None = None) -> tuple[str, Path]:
    root = directory or _snippets_dir()
    candidate = root / (name if name.endswith(".kql") else f"{name}.kql")
    if not candidate.exists():
        raise FileNotFoundError(f"snippet '{name}' not found at {candidate}")
    return candidate.read_text(encoding="utf-8"), candidate


def _default_profile_name() -> tuple[str, list[str]]:
    """Pick first app-only profile; otherwise default-profile + warning."""
    warnings: list[str] = []
    try:
        profiles = list(list_profiles())
    except Exception:
        return "default", warnings

    for p in profiles:
        mode = getattr(p, "mode", "")
        if mode in ("app-secret", "app-cert"):
            return getattr(p, "name", "default"), warnings

    for p in profiles:
        if getattr(p, "default", False):
            warnings.append(
                f"No app-only profile configured; falling back to delegated profile "
                f"'{getattr(p, 'name', 'default')}'. Advanced hunting is best run with "
                f"an app-only profile (ThreatHunting.Read.All)."
            )
            return getattr(p, "name", "default"), warnings

    return "default", warnings


def _profile_mode(name: str) -> str | None:
    try:
        profiles = list(list_profiles())
    except Exception:
        return None
    for p in profiles:
        if getattr(p, "name", None) == name:
            return getattr(p, "mode", None)
    return None


def _validate_timespan(value: str) -> None:
    if not _ISO_TIMESPAN_RE.match(value):
        raise typer.BadParameter(
            f"invalid ISO 8601 duration: '{value}'. Examples: P1D, P7D, P30D, PT1H."
        )


def _read_kql_file(path: Path) -> str:
    if not path.exists():
        raise typer.BadParameter(f"file not found: {path}")
    return path.read_text(encoding="utf-8")


def _extract_body(body: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]] | None]:
    """Return (results, schema) from the Graph hunting response."""
    if not isinstance(body, dict):
        return [], None
    results = body.get("results") or body.get("Results") or []
    schema = body.get("schema") or body.get("Schema")
    if not isinstance(results, list):
        results = []
    return results, schema


def _format_error(exc: GraphTransportError) -> tuple[str, str | None]:
    body = getattr(exc, "body", None)
    msg = str(exc)
    hint: str | None = None
    if isinstance(body, dict):
        err = body.get("error") if "error" in body else None
        if isinstance(err, dict):
            inner = err.get("message") or err.get("code")
            if inner:
                msg = f"{msg}: {inner}"
        else:
            inner = body.get("message")
            if inner:
                msg = f"{msg}: {inner}"
    status = getattr(exc, "status_code", None)
    if status == 400:
        hint = "Check KQL syntax and that the query returns a bounded result set."
    elif status == 403:
        hint = "Ensure the profile has ThreatHunting.Read.All (app-only preferred)."
    elif status == 404:
        hint = "Advanced hunting endpoint is /security/runHuntingQuery on v1.0."
    return msg, hint


async def _run_hunt(
    *,
    kql: str,
    timespan: str,
    profile: str,
) -> Envelope:
    trace_id = uuid.uuid4().hex
    warnings: list[str] = []

    mode = _profile_mode(profile)
    if mode == "delegated" or mode == "delegated-ps":
        warnings.append(
            f"Profile '{profile}' is delegated; advanced hunting is best run with an "
            f"app-only profile (ThreatHunting.Read.All) for a stable permission model."
        )

    try:
        response = await graph_request(
            "POST",
            HUNT_ENDPOINT,
            profile=profile,
            body={"Query": kql, "Timespan": timespan},
            api_version="v1.0",
        )
    except GraphTransportError as exc:
        message, hint = _format_error(exc)
        return Envelope.err(
            summary="advanced hunting query failed",
            error=ErrorPayload(code=ErrorCode.UPSTREAM_ERROR, message=message, hint=hint),
            trace_id=trace_id,
            warnings=warnings,
        )

    results, _schema = _extract_body(getattr(response, "body", None))

    # Graph caps hunting results at 100k rows per query; callers should re-window
    # long time spans. We surface that as a warning rather than an error.
    if isinstance(getattr(response, "body", None), dict):
        body = response.body
        if body.get("@odata.nextLink") or body.get("truncated") is True:
            warnings.append(
                f"advanced hunting results were truncated ({len(results)} rows returned); "
                f"consider narrowing the timespan or adding filters."
            )

    return Envelope.ok_read(
        summary=f"advanced hunting returned {len(results)} row(s) over {timespan}",
        data=results,
        trace_id=trace_id,
        warnings=warnings,
    )


def _run_sync(coro: Any) -> Envelope:
    return asyncio.run(coro)


def _do_list_snippets(directory: Path | None = None) -> Envelope:
    trace_id = uuid.uuid4().hex
    rows: list[dict[str, Any]] = []
    for path in _list_snippet_files(directory):
        title, description = _parse_snippet_header(path.read_text(encoding="utf-8"))
        rows.append(
            {
                "name": path.stem,
                "title": title,
                "description": description,
                "path": str(path),
            }
        )
    return Envelope.ok_read(
        summary=f"{len(rows)} hunt snippet(s) available",
        data=rows,
        trace_id=trace_id,
    )


def _usage_error(message: str, *, hint: str | None = None) -> Envelope:
    return Envelope.err(
        summary="usage error",
        error=ErrorPayload(code=ErrorCode.USAGE_ERROR, message=message, hint=hint),
        trace_id=uuid.uuid4().hex,
    )


def hunt_command(
    kql: str | None = None,
    *,
    file: Path | None = None,
    snippet: str | None = None,
    timespan: str = DEFAULT_TIMESPAN,
    profile: str | None = None,
    list_snippets: bool = False,
) -> Envelope:
    """Programmatic entry point; returns an Envelope (used by tests and wrappers)."""
    if list_snippets:
        return _do_list_snippets()

    sources = sum(1 for v in (kql, file, snippet) if v)
    if sources == 0:
        return _usage_error(
            "hunt requires a KQL string, --file, or --snippet.",
            hint="Try `hunt --list-snippets` to see bundled hunts.",
        )
    if sources > 1:
        return _usage_error(
            "hunt accepts exactly one of: KQL string, --file, --snippet.",
        )

    _validate_timespan(timespan)

    if file is not None:
        try:
            kql_text = _read_kql_file(file)
        except typer.BadParameter as exc:
            return _usage_error(str(exc))
    elif snippet is not None:
        try:
            kql_text, _path = _load_snippet(snippet)
        except FileNotFoundError as exc:
            return _usage_error(
                str(exc),
                hint="Run `hunt --list-snippets` to see bundled snippets.",
            )
    else:
        kql_text = kql or ""

    kql_text = kql_text.strip()
    if not kql_text:
        return _usage_error("KQL query is empty.")

    resolved_profile = profile
    fallback_warnings: list[str] = []
    if resolved_profile is None:
        resolved_profile, fallback_warnings = _default_profile_name()

    env = _run_sync(
        _run_hunt(kql=kql_text, timespan=timespan, profile=resolved_profile)
    )
    if fallback_warnings:
        env.warnings = list(fallback_warnings) + list(env.warnings)
    return env


def register(app: typer.Typer) -> None:
    """Register the `hunt` verb on the given Typer app."""

    @app.command("hunt", help="Run a Microsoft Graph Security advanced hunting (KQL) query.")
    def _hunt(  # noqa: D401
        kql: str = typer.Argument(
            None, help="KQL query string. Mutually exclusive with --file and --snippet."
        ),
        file: Path | None = typer.Option(
            None, "--file", "-f", help="Load KQL from a file on disk."
        ),
        snippet: str | None = typer.Option(
            None, "--snippet", "-s", help="Load a bundled snippet from catalog/_hunts/."
        ),
        timespan: str = typer.Option(
            DEFAULT_TIMESPAN,
            "--timespan",
            "-t",
            help="ISO 8601 duration (e.g. P1D, P7D, P30D). Default P7D.",
        ),
        profile: str | None = typer.Option(
            None, "--profile", help="Auth profile to use; defaults to first app-only profile."
        ),
        list_snippets: bool = typer.Option(
            False, "--list-snippets", help="List bundled KQL snippets and exit."
        ),
    ) -> None:
        env = hunt_command(
            kql=kql,
            file=file,
            snippet=snippet,
            timespan=timespan,
            profile=profile,
            list_snippets=list_snippets,
        )
        emit(env)


__all__ = ["hunt_command", "register"]
