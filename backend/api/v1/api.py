from fastapi import APIRouter

from backend.api.v1.routes import auth, intelligence, analysis, users

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(intelligence.router)
api_router.include_router(analysis.router)
api_router.include_router(users.router)
