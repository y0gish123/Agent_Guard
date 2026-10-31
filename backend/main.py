"""Main FastAPI application for AgentGuard AI SOC Backend."""

from contextlib import asynccontextmanager
import uuid
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.api import audit, demo, incidents, ingest, meta, phishing, responses, stream
from backend.config import get_settings
from backend.db.session import get_db, init_db
from shared.contracts import ErrorBody


class BodyLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int = 1_048_576):
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_bytes:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={
                    "code": "PAYLOAD_TOO_LARGE",
                    "plain_message": "Request body exceeds maximum allowed size of 1 MB.",
                    "detail_id": f"err-{uuid.uuid4().hex[:8]}",
                },
            )
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Enforce HMAC_SECRET check on startup
    settings = get_settings()
    init_db(settings.DB_URL)
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentGuard AI SOC",
        description="Verified Policy Gateway and AI SOC Backend",
        version="1.0.0",
        lifespan=lifespan,
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check endpoint for frontend / proxy monitoring
    @app.get("/api/health", tags=["health"])
    def health_check():
        return {"status": "ok"}

    # Request body size limiter (1 MB)
    app.add_middleware(BodyLimitMiddleware, max_bytes=1_048_576)

    # Global Exception Handlers returning ErrorBody
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and "code" in detail and "plain_message" in detail:
            return JSONResponse(status_code=exc.status_code, content=detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "code": "HTTP_ERROR",
                "plain_message": str(detail),
                "detail_id": f"err-{uuid.uuid4().hex[:8]}",
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "code": "VALIDATION_ERROR",
                "plain_message": "Request body or parameter validation failed.",
                "detail_id": f"err-{uuid.uuid4().hex[:8]}",
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        # Never log or leak internal secret details or trace to client
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "code": "INTERNAL_ERROR",
                "plain_message": "An internal server error occurred.",
                "detail_id": f"err-{uuid.uuid4().hex[:8]}",
            },
        )

    # Register Routers
    app.include_router(ingest.router)
    app.include_router(incidents.router)
    # Expose POST /api/identity/confirm as specified in Phase C
    @app.post("/api/identity/confirm", tags=["identity"])
    def global_confirm_identity(
        req: incidents.ConfirmIdentityRequest,
        x_user: str = Header(default="analyst-lead"),
        x_role: str = Header(default="approver"),
        db = Depends(get_db),
    ):
        return incidents.confirm_identity(req, x_user, x_role, db)

    app.include_router(phishing.router)
    app.include_router(responses.router)
    app.include_router(audit.router)
    app.include_router(meta.router)
    app.include_router(demo.router)
    app.include_router(stream.router)

    return app


app = create_app()

