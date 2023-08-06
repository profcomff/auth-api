from fastapi import FastAPI
from fastapi_sqlalchemy import DBSessionMiddleware
from starlette.middleware.cors import CORSMiddleware

from auth_backend import __version__
from auth_backend.auth_plugins.auth_method import AUTH_METHODS
from auth_backend.settings import get_settings

from .groups import groups
from .scopes import scopes
from .user import user
from .user_session import user_session


settings = get_settings()
app = FastAPI(
    title='Сервис аутентификации и авторизации',
    description=(
        'Серверная часть сервиса проверки подлинности пользователя '
        'и предоставления лицу или группе лиц прав на выполнение определённых действий'
    ),
    version=__version__,
    # Настраиваем интернет документацию
    root_path=settings.ROOT_PATH if __version__ != 'dev' else '/',
    docs_url=None if __version__ != 'dev' else '/docs',
    redoc_url=None,
)

app.add_middleware(
    DBSessionMiddleware,
    db_url=str(settings.DB_DSN),
    engine_args={"pool_pre_ping": True, "isolation_level": "AUTOCOMMIT"},
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)


app.include_router(user_session)
app.include_router(groups)
app.include_router(scopes)
app.include_router(user)

for method in AUTH_METHODS.values():
    if settings.ENABLED_AUTH_METHODS is None or method.get_name() in settings.ENABLED_AUTH_METHODS:
        app.include_router(router=method().router, prefix=method.prefix, tags=[method.get_name()])
