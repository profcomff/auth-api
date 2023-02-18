from fastapi import FastAPI
from fastapi_sqlalchemy import DBSessionMiddleware
from starlette.middleware.cors import CORSMiddleware

from auth_backend.auth_plugins.auth_method import AUTH_METHODS
from auth_backend.settings import get_settings
from .user_session import logout_router
from .user_groups import user_groups
from .groups import groups

settings = get_settings()

app = FastAPI()


app.add_middleware(DBSessionMiddleware, db_url=settings.DB_DSN, engine_args={"pool_pre_ping": True})

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

app.include_router(logout_router)
app.include_router(user_groups)
app.include_router(groups)

for method in AUTH_METHODS.values():
    if settings.ENABLED_AUTH_METHODS is None or method.get_name() in settings.ENABLED_AUTH_METHODS:
        app.include_router(router=method().router, prefix=method.prefix, tags=[method.get_name()])
