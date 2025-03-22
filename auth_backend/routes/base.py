from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi_sqlalchemy import DBSessionMiddleware
from starlette.middleware.cors import CORSMiddleware

from auth_backend import __version__
from auth_backend.auth_method import AuthPluginMeta
from auth_backend.kafka.kafka import get_kafka_producer
from auth_backend.settings import get_settings

from .groups import groups as groups_router
from .oidc import router as openid_router
from .scopes import scopes as scopes_router
from .user import user as user_router
from .user_session import user_session as user_session_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    get_kafka_producer().close()


settings = get_settings()
app = FastAPI(
    title='Сервис аутентификации и авторизации',
    description=(
        'Серверная часть сервиса проверки подлинности пользователя '
        'и предоставления лицу или группе лиц прав на выполнение определённых действий'
    ),
    version=__version__,
    # Настраиваем интернет документацию
    root_path=settings.ROOT_PATH if __version__ != 'dev' else '',
    docs_url=None if __version__ != 'dev' else '/docs',
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    DBSessionMiddleware,
    db_url=str(settings.DB_DSN),
    engine_args={"pool_pre_ping": True},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

app.include_router(groups_router)
app.include_router(scopes_router)
app.include_router(user_router)
app.include_router(user_session_router)
app.include_router(openid_router)

for method in AuthPluginMeta.active_auth_methods():
    app.include_router(router=method().router, prefix=method.prefix, tags=[method.get_name()])
