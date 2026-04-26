from contextlib import asynccontextmanager
from redis.asyncio import Redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine
from app.routers import remediation, demo, setup


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = Redis.from_url(settings.redis_url, decode_responses=False)
    yield
    await app.state.redis.aclose()
    await engine.dispose()


app = FastAPI(
    title="Firewatch EDR",
    description="AI-powered Endpoint Detection & Response platform",
    version="0.4.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(setup.router, prefix="/api")
app.include_router(remediation.router, prefix="/api")
app.include_router(demo.router, prefix="/api")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "firewatch-edr",
        "anthropic_configured": bool(settings.anthropic_api_key),
    }
