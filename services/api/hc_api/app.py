"""FastAPI application (spec Section 6.1). Handlers are thin: the logic lives in the service classes."""
import hmac
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from hc_common.config import Settings, get_settings, require_api_key
from hc_common.logging import get_logger

from . import __version__
from .errors import ApiError, error_body
from .models import ApproveBody, HuntCreate, ProposalCreate, RejectBody
from .ratelimit import RateLimiter
from .services import Services, build_services

log = get_logger("api")
MAX_BODY_BYTES = 65536
HUNT_CALLS_PER_MINUTE = 60


def _guard(what: str, fn, *args, **kwargs) -> Any:
    """Run a read against an external store; turn failures into a clean 503 (no traceback)."""
    try:
        return fn(*args, **kwargs)
    except ApiError:
        raise
    except Exception as exc:
        log.error("dependency error", extra={"what": what, "error": type(exc).__name__})
        raise ApiError("internal", f"{what} is unavailable", status=503)


def _dependency_states(svc: Services) -> dict:
    """Per-dependency state for /health. Each check has a short time limit."""
    def redis_state() -> str:
        if svc.mock_hunt:
            return "mock"
        from hc_common.clients import get_redis
        return "ok" if get_redis().ping() else "down"

    checks = {
        "redis": redis_state,
        "opensearch": lambda: "mock" if getattr(svc.backend, "mock", False) else ("ok" if svc.backend.ping() else "down"),
        "ml": svc.ml.health,
    }
    out = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {k: pool.submit(fn) for k, fn in checks.items()}
        for name, fut in futures.items():
            try:
                out[name] = fut.result(timeout=3)
            except Exception:
                out[name] = "down"
    out["llm"] = "configured" if svc.llm.enabled else "disabled"
    return out


def create_app(settings: Optional[Settings] = None, services: Optional[Services] = None) -> FastAPI:
    """Build the app. Fails fast when HC_API_KEY is not set."""
    settings = settings or get_settings()
    api_key = require_api_key(settings)
    svc = services or build_services(settings)
    app = FastAPI(title="HuntCopilot API", version=__version__)
    app.state.services = svc
    limiter = RateLimiter(HUNT_CALLS_PER_MINUTE)

    def auth(x_api_key: Optional[str] = Header(default=None)) -> None:
        if x_api_key is None or not hmac.compare_digest(x_api_key.encode("utf-8"), api_key.encode("utf-8")):
            raise ApiError("invalid_request", "missing or invalid API key", status=401)

    def small_body(request: Request) -> None:
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            raise ApiError("invalid_request", "request body too large", status=413)

    def hunt_limit(request: Request) -> None:
        limiter.check(request.client.host if request.client else "unknown")

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError):
        return JSONResponse(exc.body(), status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def _invalid(request: Request, exc: RequestValidationError):
        details = [{"loc": [str(p) for p in e.get("loc", [])], "msg": str(e.get("msg", ""))} for e in exc.errors()]
        return JSONResponse(error_body("invalid_request", "request validation failed", details), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        code = "not_found" if exc.status_code == 404 else "invalid_request"
        return JSONResponse(error_body(code, str(exc.detail), None), status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):
        log.error("unhandled error", extra={"path": request.url.path, "error": type(exc).__name__})
        return JSONResponse(error_body("internal", "internal error", None), status_code=500)

    @app.get("/health")
    def health() -> dict:
        deps = _dependency_states(svc)
        ok = all(deps[k] in ("ok", "mock") for k in ("redis", "opensearch", "ml"))
        return {"status": "ok" if ok else "degraded", "version": __version__, "dependencies": deps,
                "hunt_lib": svc.lib.source, "mocks": {"hunt": svc.mock_hunt, "ml": svc.mock_ml}}

    r = APIRouter(prefix="/v1", dependencies=[Depends(auth), Depends(small_body)])

    @r.post("/hunts", dependencies=[Depends(hunt_limit)])
    def create_hunt(body: HuntCreate):
        return svc.hunts.create_plan(body.intent, body.time_range)

    @r.post("/hunts/{plan_id}/run", dependencies=[Depends(hunt_limit)])
    def run_hunt(plan_id: str):
        return svc.hunts.run(plan_id)

    @r.get("/hunts/{run_id}")
    def get_run(run_id: str):
        return svc.hunts.get_run(run_id)

    @r.get("/alerts")
    def list_alerts(status: Optional[Literal["new", "triaged", "closed"]] = None, rule_id: str = "",
                    host: str = "", limit: int = Query(100, ge=1, le=500)):
        items, total = _guard("alert store", svc.backend.search_alerts, status or "", rule_id, host, limit)
        return {"items": items, "total": total}

    @r.get("/findings")
    def list_findings(min_confidence: float = Query(0.0, ge=0, le=100), host: str = "",
                      limit: int = Query(100, ge=1, le=500)):
        items, total = svc.store.list_findings(min_confidence, host, limit)
        return {"items": items, "total": total}

    @r.get("/findings/{finding_id}")
    def get_finding(finding_id: str):
        f = svc.store.get_finding(finding_id)
        if not f:
            raise ApiError("not_found", f"finding {finding_id} not found")
        return f

    @r.post("/proposals")
    def create_proposal(body: ProposalCreate):
        if not svc.store.get_finding(body.finding_id):
            raise ApiError("not_found", f"finding {body.finding_id} not found")
        return svc.proposals.create(body.finding_id, body.action, body.target, body.justification, "analyst")

    @r.get("/proposals")
    def list_proposals(status: Optional[Literal["pending", "approved", "rejected", "executed", "failed"]] = None,
                       limit: int = Query(100, ge=1, le=500)):
        items, total = svc.store.list_proposals(status or "", "", limit)
        return {"items": items, "total": total}

    @r.post("/proposals/{proposal_id}/approve")
    def approve(proposal_id: str, body: ApproveBody):
        return svc.proposals.approve(proposal_id, body.approver, body.confirm)

    @r.post("/proposals/{proposal_id}/reject")
    def reject(proposal_id: str, body: RejectBody):
        return svc.proposals.reject(proposal_id, body.approver, body.reason)

    @r.get("/audit")
    def audit_list(limit: int = Query(100, ge=1, le=500)):
        items, total = svc.audit.read(limit)
        return {"items": items, "total": total}

    @r.get("/audit/verify")
    def audit_verify():
        ok, first_bad = svc.audit.verify()
        return {"ok": ok, "first_bad_seq": first_bad}

    @r.get("/cases/{finding_id}/export")
    def export_case(finding_id: str, format: Literal["json", "md"] = "json", analyst: str = Query("", max_length=100)):
        case = svc.exporter.case(finding_id, analyst)
        if format == "json":
            return case
        name = f"case_{finding_id[:12]}.md"
        return PlainTextResponse(svc.exporter.markdown(case), media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @r.get("/state")
    def state():
        return svc.store.state_snapshot()

    @r.get("/stats")
    def stats():
        def safe(fn):
            try:
                return fn()
            except Exception:
                return None

        by_status = svc.store.proposal_counts()
        return {"events": safe(svc.backend.count_events), "alerts": safe(svc.backend.count_alerts),
                "findings": svc.store.count("findings"), "proposals": svc.store.count("proposals"),
                "proposals_by_status": by_status, "plans": svc.store.count("plans"), "runs": svc.store.count("runs")}

    app.include_router(r)
    return app
