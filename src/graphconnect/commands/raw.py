"""`raw` verb — generic Graph passthrough (dead-end escape for untyped calls)."""

from __future__ import annotations

import asyncio
import json
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import typer

from graphconnect.output import emit
from graphconnect.transport import graph_request
from graphconnect.types import Envelope, ErrorCode, ErrorPayload


# --- scope whitelist --------------------------------------------------------

_ALLOWED_PREFIXES = (
    "/users",
    "/groups",
    "/devices",
    "/deviceManagement",
    "/identity",
    "/policies",
    "/security",
    "/auditLogs",
    "/directoryObjects",
    "/applications",
    "/servicePrincipals",
    "/me",
    "/organization",
    "/reports",
    "/directory",
)


def _normalize_path(path: str) -> str:
    """Strip query + fragment and leading api-version segment; keep a leading slash."""
    p = path.split("?", 1)[0].split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    for ver in ("/v1.0", "/beta"):
        if p == ver or p.startswith(ver + "/"):
            p = p[len(ver):] or "/"
            break
    return p


def _path_in_scope(path: str) -> bool:
    normalized = _normalize_path(path)
    return any(
        normalized == prefix or normalized.startswith(prefix + "/") or normalized.startswith(prefix + "(")
        for prefix in _ALLOWED_PREFIXES
    )


# --- plan-token store (file-backed, simple TTL) -----------------------------

_TOKEN_DIR = Path.home() / ".graphconnect"
_TOKEN_FILE = _TOKEN_DIR / "raw_plan_tokens.json"
_TOKEN_TTL_S = 120


def _load_tokens() -> dict[str, dict[str, Any]]:
    try:
        with open(_TOKEN_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def _save_tokens(tokens: dict[str, dict[str, Any]]) -> None:
    _TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    with open(_TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(tokens, f)


def _mint_plan_token(plan: dict[str, Any]) -> tuple[str, int]:
    token = "raw_" + secrets.token_hex(16)
    expires_at = time.time() + _TOKEN_TTL_S
    tokens = _load_tokens()
    now = time.time()
    tokens = {k: v for k, v in tokens.items() if v.get("expires_at", 0) > now}
    tokens[token] = {"plan": plan, "expires_at": expires_at}
    _save_tokens(tokens)
    return token, _TOKEN_TTL_S


def _validate_plan_token(token: str, plan: dict[str, Any]) -> bool:
    tokens = _load_tokens()
    entry = tokens.get(token)
    if not entry:
        return False
    if entry.get("expires_at", 0) <= time.time():
        tokens.pop(token, None)
        _save_tokens(tokens)
        return False
    stored_plan = entry.get("plan") or {}
    if (
        stored_plan.get("method") != plan.get("method")
        or stored_plan.get("path") != plan.get("path")
        or stored_plan.get("body") != plan.get("body")
    ):
        return False
    tokens.pop(token, None)
    _save_tokens(tokens)
    return True


# --- audit ------------------------------------------------------------------

_AUDIT_DIR = Path.home() / ".graphconnect" / "audit"


def _audit_record(
    *,
    trace_id: str,
    verb: str,
    mode: str,
    profile: str,
    method: str,
    path: str,
    ok: bool,
    http_status: int | None = None,
    error: str | None = None,
    body_redacted: bool = False,
) -> None:
    status = "success" if ok else "error"
    if mode == "plan" and ok:
        status = "planned"
    record = {
        "trace_id": trace_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation_id": "raw",
        "verb": verb,
        "mode": mode,
        "profile": profile,
        "method": method,
        "graph_url": path,
        "status": status,
        "http_status": http_status,
        "args_redacted": {
            "method": method,
            "path": path,
            "has_body": body_redacted,
        },
        "http_requests": (
            [{"method": method, "path": path, "status": http_status}]
            if http_status is not None
            else []
        ),
        "ok": ok,
        "error": error,
    }
    try:
        _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with open(_AUDIT_DIR / f"{today}.ndjson", "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass  # audit is best-effort; never block the call


# --- body loading -----------------------------------------------------------


def _load_body(body: str | None, body_file: Path | None) -> dict | None:
    if body is not None and body_file is not None:
        raise typer.BadParameter("use --body OR --body-file, not both")
    if body is not None:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise typer.BadParameter(f"--body is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise typer.BadParameter("--body must decode to a JSON object")
        return parsed
    if body_file is not None:
        try:
            raw = Path(body_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise typer.BadParameter(f"--body-file unreadable: {exc}") from exc
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise typer.BadParameter(f"--body-file is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise typer.BadParameter("--body-file must decode to a JSON object")
        return parsed
    return None


def _append_query_params(path: str, query_params: str | None) -> str:
    if not query_params:
        return path
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}{query_params.lstrip('?&')}"


def _rows_from_response(body: Any) -> list[dict[str, Any]]:
    if body is None:
        return []
    if isinstance(body, dict):
        value = body.get("value")
        if isinstance(value, list):
            return [row if isinstance(row, dict) else {"value": row} for row in value]
        return [body]
    if isinstance(body, list):
        return [row if isinstance(row, dict) else {"value": row} for row in body]
    return [{"value": body}]


def _refuse_out_of_scope(trace_id: str, path: str) -> Envelope:
    return Envelope.err(
        summary=f"path '{path}' is outside the allowed raw scope",
        error=ErrorPayload(
            code=ErrorCode.USAGE_ERROR,
            message="raw verb is restricted to a whitelisted set of Graph path prefixes",
            hint="Allowed prefixes: " + ", ".join(_ALLOWED_PREFIXES),
        ),
        trace_id=trace_id,
    )


# --- core async impl --------------------------------------------------------


_READ_METHODS = {"GET"}
_WRITE_METHODS = {"POST", "PATCH", "PUT", "DELETE"}


async def _run(
    *,
    method: str,
    path: str,
    body: str | None,
    body_file: Path | None,
    plan_flag: bool,
    apply_flag: bool,
    token: str | None,
    profile: str,
    api_version: str,
    query_params: str | None,
    force_allow_delete: bool,
) -> Envelope:
    trace_id = uuid.uuid4().hex
    method = method.upper()

    if method not in _READ_METHODS and method not in _WRITE_METHODS:
        return Envelope.err(
            summary=f"unsupported method {method}",
            error=ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message=f"raw supports GET, POST, PATCH, PUT, DELETE (got {method})",
            ),
            trace_id=trace_id,
        )

    if not _path_in_scope(path):
        _audit_record(
            trace_id=trace_id, verb="raw", mode="read", profile=profile,
            method=method, path=path, ok=False, error="out_of_scope",
        )
        return _refuse_out_of_scope(trace_id, path)

    try:
        parsed_body = _load_body(body, body_file)
    except typer.BadParameter as exc:
        return Envelope.err(
            summary="invalid body argument",
            error=ErrorPayload(code=ErrorCode.BAD_REQUEST, message=str(exc)),
            trace_id=trace_id,
        )

    full_path = _append_query_params(path, query_params)

    # --- GET path -----------------------------------------------------------
    if method == "GET":
        try:
            resp = await graph_request(
                "GET", full_path, profile=profile, api_version=api_version
            )
        except Exception as exc:
            _audit_record(
                trace_id=trace_id, verb="raw", mode="read", profile=profile,
                method=method, path=full_path, ok=False, error=str(exc),
            )
            return Envelope.err(
                summary=f"GET {path} failed",
                error=ErrorPayload(code=ErrorCode.UPSTREAM_ERROR, message=str(exc)),
                trace_id=trace_id,
            )

        _audit_record(
            trace_id=trace_id, verb="raw", mode="read", profile=profile,
            method=method, path=full_path, ok=True,
            http_status=getattr(resp, "status_code", None),
        )
        rows = _rows_from_response(getattr(resp, "body", None))
        return Envelope.ok_read(
            summary=f"GET {path} -> {len(rows)} row(s)",
            data=rows,
            trace_id=trace_id,
        )

    # --- write methods ------------------------------------------------------
    if plan_flag and apply_flag:
        return Envelope.err(
            summary="cannot combine --plan and --apply",
            error=ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message="choose either --plan (preview) or --apply --token <t> (execute)",
            ),
            trace_id=trace_id,
        )

    if not plan_flag and not apply_flag:
        return Envelope.err(
            summary=f"{method} {path} requires a mode",
            error=ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message=f"non-GET requests must be run with --plan (preview) or --apply --token <t>",
                hint=f"Try: raw {method} {path} --plan",
            ),
            trace_id=trace_id,
            next_actions=[
                f"raw {method} {path} --plan",
                f"raw {method} {path} --apply --token <token>",
            ],
        )

    plan_payload = {
        "method": method,
        "path": full_path,
        "body": parsed_body,
        "api_version": api_version,
        "profile": profile,
    }

    warnings: list[str] = []
    if method == "DELETE":
        warnings.append(
            "DELETE requests permanently remove the target resource; confirm the path before --apply."
        )

    if plan_flag:
        if method == "DELETE" and not force_allow_delete:
            # Still mint a plan; the warning is the safety.
            warnings.append(
                "DELETE plan minted. Re-run with --apply --token <t> AND --force-allow-delete to execute."
            )
        plan_token, ttl = _mint_plan_token(plan_payload)
        plan_out = {**plan_payload, "token": plan_token, "ttl_s": ttl}
        _audit_record(
            trace_id=trace_id, verb="raw", mode="plan", profile=profile,
            method=method, path=full_path, ok=True,
            body_redacted=parsed_body is not None,
        )
        return Envelope.ok_plan(
            summary=f"plan: {method} {path}",
            plan=plan_out,
            trace_id=trace_id,
            warnings=warnings,
            next_actions=[f"raw {method} {path} --apply --token {plan_token}"],
        )

    # --apply
    if not token:
        return Envelope.err(
            summary="--apply requires --token",
            error=ErrorPayload(
                code=ErrorCode.TOKEN_INVALID,
                message="--apply must be paired with a --token <t> from a prior --plan run",
            ),
            trace_id=trace_id,
        )

    if method == "DELETE" and not force_allow_delete:
        return Envelope.err(
            summary="DELETE requires --force-allow-delete",
            error=ErrorPayload(
                code=ErrorCode.USAGE_ERROR,
                message="DELETE --apply must also pass --force-allow-delete to acknowledge destruction",
            ),
            trace_id=trace_id,
            warnings=warnings,
        )

    if not _validate_plan_token(token, plan_payload):
        _audit_record(
            trace_id=trace_id, verb="raw", mode="apply", profile=profile,
            method=method, path=full_path, ok=False, error="token_invalid",
        )
        return Envelope.err(
            summary="token invalid or expired",
            error=ErrorPayload(
                code=ErrorCode.TOKEN_INVALID,
                message="plan token is unknown, expired, used, or does not match this request",
                hint="Re-run with --plan to mint a fresh token.",
            ),
            trace_id=trace_id,
        )

    try:
        resp = await graph_request(
            method, full_path, profile=profile, body=parsed_body, api_version=api_version
        )
    except Exception as exc:
        _audit_record(
            trace_id=trace_id, verb="raw", mode="apply", profile=profile,
            method=method, path=full_path, ok=False, error=str(exc),
            body_redacted=parsed_body is not None,
        )
        return Envelope.err(
            summary=f"{method} {path} failed",
            error=ErrorPayload(code=ErrorCode.UPSTREAM_ERROR, message=str(exc)),
            trace_id=trace_id,
            warnings=warnings,
        )

    _audit_record(
        trace_id=trace_id, verb="raw", mode="apply", profile=profile,
        method=method, path=full_path, ok=True,
        http_status=getattr(resp, "status_code", None),
        body_redacted=parsed_body is not None,
    )
    rows = _rows_from_response(getattr(resp, "body", None))
    return Envelope.ok_apply(
        summary=f"{method} {path} applied",
        trace_id=trace_id,
        data=rows,
        warnings=warnings,
    )


# --- Typer surface ----------------------------------------------------------


app = typer.Typer(
    name="raw",
    help="Generic Graph passthrough (escape hatch for calls not covered by typed verbs).",
    no_args_is_help=True,
)


def _dispatch(envelope: Envelope) -> Envelope:
    """Emit the envelope for CLI users and return it for unit tests."""
    emit(envelope)
    return envelope


_METHOD_CHOICES = ("GET", "POST", "PATCH", "PUT", "DELETE")


def _method_callback(method: str) -> str:
    upper = method.upper()
    if upper not in _METHOD_CHOICES:
        raise typer.BadParameter(
            f"method must be one of {', '.join(_METHOD_CHOICES)} (got {method})"
        )
    return upper


def raw_cmd(
    method: str = typer.Argument(..., callback=_method_callback, help="HTTP method: GET|POST|PATCH|PUT|DELETE"),
    path: str = typer.Argument(..., help="Graph path, e.g. /users/{id}"),
    body: str | None = typer.Option(None, "--body", help="Inline JSON body."),
    body_file: Path | None = typer.Option(None, "--body-file", help="Path to a JSON body file."),
    plan: bool = typer.Option(False, "--plan", help="Mint a plan token (no live call)."),
    apply: bool = typer.Option(False, "--apply", help="Execute a previously planned call."),
    token: str | None = typer.Option(None, "--token", help="Plan token from --plan (required with --apply)."),
    profile: str = typer.Option("default", "--profile", help="Auth profile name."),
    query_params: str | None = typer.Option(
        None, "--query-params", help="Extra query params, e.g. '$top=5&$select=id'."
    ),
    api_version: str = typer.Option("v1.0", "--api-version", help="Graph API version: v1.0 | beta."),
    force_allow_delete: bool = typer.Option(
        False, "--force-allow-delete",
        help="Required in addition to --apply --token for DELETE requests.",
    ),
) -> Envelope:
    if api_version not in ("v1.0", "beta"):
        raise typer.BadParameter("--api-version must be 'v1.0' or 'beta'")
    envelope = asyncio.run(
        _run(
            method=method,
            path=path,
            body=body,
            body_file=body_file,
            plan_flag=plan,
            apply_flag=apply,
            token=token,
            profile=profile,
            api_version=api_version,
            query_params=query_params,
            force_allow_delete=force_allow_delete,
        )
    )
    return _dispatch(envelope)


def register(parent: typer.Typer) -> None:
    """Attach the `raw` verb to a parent Typer app as a single command."""
    parent.command(
        "raw",
        help="Generic Graph passthrough (escape hatch for calls not covered by typed verbs).",
    )(raw_cmd)
