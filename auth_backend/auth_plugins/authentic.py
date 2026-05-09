import logging
from typing import Any
from urllib.parse import quote

import aiohttp
import jwt
from aiocache import cached
from event_schema.auth import UserLogin
from fastapi import Depends
from fastapi.background import BackgroundTasks
from fastapi_sqlalchemy import db
from pydantic import AnyHttpUrl, BaseModel, Field

from auth_backend.auth_method import AuthPluginMeta, OauthMeta, Session
from auth_backend.auth_method.outer import ConnectionIssue
from auth_backend.exceptions import AlreadyExists, OauthAuthFailed
from auth_backend.kafka.kafka import get_kafka_producer
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.schemas.types.scopes import Scope
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth


AUTH_METHOD_ID_PARAM_NAME = 'user_id'
logger = logging.getLogger(__name__)


class AuthenticSettings(Settings):
    AUTHENTIC_ROOT_URL: AnyHttpUrl | None = None
    AUTHENTIC_OIDC_CONFIGURATION_URL: AnyHttpUrl | None = None
    AUTHENTIC_REDIRECT_URL: AnyHttpUrl | None = 'https://app.test.profcomff.com/auth/oauth-authorized/authentic'
    AUTHENTIC_CLIENT_ID: str | None = None
    AUTHENTIC_CLIENT_SECRET: str | None = None
    AUTHENTIC_TOKEN: str | None = None


class AuthenticAuth(OauthMeta):
    """Вход в приложение по аккаунту Authentic"""

    prefix = '/authentic'
    tags = ['authentic']
    settings = AuthenticSettings()

    class OauthResponseSchema(BaseModel):
        code: str | None = None
        id_token: str | None = Field(default=None, help="Authentic JWT token identifier")
        scopes: list[Scope] | None = None
        session_name: str | None = None

    @classmethod
    @cached()
    async def __get_configuration(cls):
        if not cls.settings.AUTHENTIC_OIDC_CONFIGURATION_URL:
            raise OauthAuthFailed(
                'Error in OIDC configuration',
                'Ошибка конфигурации OIDC',
                500,
            )
        async with aiohttp.ClientSession() as session:
            async with session.get(
                str(cls.settings.AUTHENTIC_OIDC_CONFIGURATION_URL),
            ) as response:
                res = await response.json()
        logger.debug(res)
        return res

    @classmethod
    @cached()
    async def __get_jwks_options(cls) -> dict[str, list[dict[str]]]:
        config = await cls.__get_configuration()
        if 'jwks_uri' not in config:
            logger.error('No OIDC JWKS config: %s', str(config))
            raise OauthAuthFailed(
                'Error in OIDC configuration',
                'Ошибка конфигурации OIDC',
                500,
            )
        jwks_uri = config['jwks_uri']
        async with aiohttp.ClientSession() as session:
            async with session.get(jwks_uri) as response:
                res = await response.json()
        logger.debug(res)
        return res

    @classmethod
    async def __get_token(cls, code: str) -> dict[str]:
        token_url = (await cls.__get_configuration())['token_endpoint']
        async with aiohttp.ClientSession() as session:
            async with session.post(
                token_url,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": cls.settings.AUTHENTIC_CLIENT_ID,
                    "client_secret": cls.settings.AUTHENTIC_CLIENT_SECRET,
                    "redirect_uri": str(cls.settings.AUTHENTIC_REDIRECT_URL),
                },
                headers={"Accept": "application/x-www-form-urlencoded"},
            ) as response:
                token_result = await response.json()
                logger.debug(token_result)
        return token_result

    @classmethod
    async def __decode_token(cls, token: str):
        jwks = jwt.PyJWKSet.from_dict(await cls.__get_jwks_options())
        algorithms = (await cls.__get_configuration()).get('id_token_signing_alg_values_supported', [])
        id_token_info = jwt.decode(
            token, jwks.keys[0], algorithms, {'verify_signature': True}, audience=cls.settings.AUTHENTIC_CLIENT_ID
        )
        logger.debug(id_token_info)
        return id_token_info

    @classmethod
    def __check_response(cls, token_result: dict[str]):
        if 'access_token' not in token_result:
            raise OauthAuthFailed(
                'Invalid credentials for authentic account',
                'Неверные данные для входа в аккаунт authentic',
            )
        if 'id_token' not in token_result:
            raise OauthAuthFailed(
                'No oauth scope granted from authentic',
                'Не получены данные о пользователе authentic',
            )

    @classmethod
    def __get_old_user(cls, user_session: UserSession | None):
        if user_session is None:
            return None
        return {'user_id': user_session.user_id}

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        background_tasks: BackgroundTasks,
        user_session: UserSession | None = Depends(UnionAuth(auto_error=True, scopes=[], allow_none=True)),
    ) -> Session:
        """Создает аккаунт или привязывает существующий"""
        id_token = user_inp.id_token

        # Получаем параметры токена пользователя
        if id_token is None:
            # Если id_token не передали в register запросе – надо запросить его по коду
            if user_inp.code is None:
                raise OauthAuthFailed(
                    'Nor code or id_token provided',
                    'Не передано ни кода авторизации, ни токена идентификации',
                )
            token_result = await cls.__get_token(user_inp.code)
            cls.__check_response(token_result)
            id_token_info = await cls.__decode_token(token_result['id_token'])
        else:
            # id_token может быть передан непосредственно из ручки входа
            # Это происходит, если пользователь пытался залогиниться, но аккаунта не существовало
            id_token_info = await cls.__decode_token(id_token)

        # Субъект передается как id пользователя
        # Это настройка делается в Authentic, по умолчанию хэш
        authentic_id = id_token_info['sub']

        # Получаем пользователей, у которых уже есть такой authentic_id
        user = await cls._get_user(AUTH_METHOD_ID_PARAM_NAME, authentic_id, db_session=db.session)

        if user is not None:
            # Существует пользователь, уже имеющий привязку к этому методу аутентификации
            raise AlreadyExists(User, user.id)

        # Создаем нового пользователя или берем существующего, в зависимости от авторизации
        if user_session is None:
            user = await cls._create_user(db_session=db.session)
        else:
            user = user_session.user
        # Добавляем пользователю метод входа
        authentic_id = cls.create_auth_method_param(
            AUTH_METHOD_ID_PARAM_NAME, authentic_id, user.id, db_session=db.session
        )

        # Отправляем обновления пользовательских данных в userdata api
        background_tasks.add_task(
            get_kafka_producer().produce,
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            AuthenticAuth.generate_kafka_key(user.id),
            await AuthenticAuth._convert_data_to_userdata_format(id_token_info),
        )

        # Формируем diff пользователя для обработки другими методами входа
        new_user = {
            'user_id': user.id,
            cls.get_name(): {AUTH_METHOD_ID_PARAM_NAME: authentic_id.value},
        }
        old_user = cls.__get_old_user(user_session)
        await AuthPluginMeta.user_updated(new_user, old_user)

        # Возвразаем сессию пользрвателя
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema, background_tasks: BackgroundTasks) -> Session:
        """Вход в пользователя с помощью аккаунта Authentic"""
        id_token = user_inp.id_token

        # Получаем параметры токена пользователя
        if id_token is None:
            # Если id_token не передали в register запросе – надо запросить его по коду
            if user_inp.code is None:
                raise OauthAuthFailed(
                    'Nor code or id_token provided',
                    'Не передано ни кода авторизации, ни токена идентификации',
                )
            token_result = await cls.__get_token(user_inp.code)
            cls.__check_response(token_result)
            id_token = token_result['id_token']
            id_token_info = await cls.__decode_token(id_token)
        else:
            # id_token может быть передан непосредственно из ручки входа
            # Это происходит, если пользователь пытался залогиниться, но аккаунта не существовало
            id_token_info = await cls.__decode_token(id_token)

        # Субъект передается как id пользователя
        # Это настройка делается в Authentic, по умолчанию хэш
        authentic_id = id_token_info['sub']

        # Получаем пользователей, у которых уже есть такой authentic_id
        # Получаем для этого пользователя сессию или, если не существует, направляем на регистрацию
        user = await cls._get_user(AUTH_METHOD_ID_PARAM_NAME, authentic_id, db_session=db.session)
        if not user:
            raise OauthAuthFailed(
                'No users found for authentic account',
                'Пользователь с данным аккаунтом Authentic не найден',
                id_token,
            )
        user_session = await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

        # Отправляем обновления пользовательских данных в userdata api
        background_tasks.add_task(
            get_kafka_producer().produce,
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            AuthenticAuth.generate_kafka_key(user.id),
            await AuthenticAuth._convert_data_to_userdata_format(id_token_info),
        )

        # Формируем diff пользователя для обработки другими методами входа
        new_user = {'user_id': user.id}
        old_user = cls.__get_old_user(user_session)
        await AuthPluginMeta.user_updated(new_user, old_user)

        # Возвразаем сессию пользрвателя
        return user_session

    @classmethod
    async def _redirect_url(cls):
        """URL на который происходит редирект после завершения входа на стороне провайдера"""
        return OauthMeta.UrlSchema(url=str(cls.settings.AUTHENTIC_REDIRECT_URL))

    @classmethod
    async def _auth_url(cls):
        """URL на который происходит редирект из приложения для авторизации на стороне провайдера"""
        authorize_url = (await cls.__get_configuration())['authorization_endpoint']
        return OauthMeta.UrlSchema(
            url=f'{authorize_url}'
            f'?client_id={cls.settings.AUTHENTIC_CLIENT_ID}'
            f'&redirect_uri={quote(str(cls.settings.AUTHENTIC_REDIRECT_URL))}'
            f'&scope=openid,tvoyff-manage-password'
            f'&response_type=code'
        )

    @classmethod
    async def _convert_data_to_userdata_format(cls, data: dict[str, Any]) -> UserLogin:
        result = {
            "items": [
                {"category": "Личная информация", "param": "Полное имя", "value": data.get("name", "").strip()},
                {"category": "Контакты", "param": "Электронная почта", "value": data.get("email")},
            ],
            "source": cls.get_name(),
        }
        return cls.userdata_process_empty_strings(UserLogin.model_validate(result))

    # Обновление пароля пользователя Authentic при обновлении пароля Auth API
    @classmethod
    async def on_user_update(cls, new_user: dict[str, Any], old_user: dict[str, Any] | None = None):
        """Произвести действия на обновление пользователя, в т.ч. обновление в других провайдерах

        Описания входных параметров соответствует параметрам `AuthMethodMeta.user_updated`.
        """
        logger.debug("on_user_update class=%s started, new_user=%s, old_user=%s", cls.get_name(), new_user, old_user)
        if not new_user or not old_user:
            # Пользователь был только что создан или удален
            # Тут не будет дополнительных методов
            logger.debug("%s not new_user or not old_user, closing", cls.get_name())
            return

        user_id = new_user.get("user_id")
        password = new_user.get("email", {}).get("password")
        if not password:
            # В этом событии пароль не обновлялся, ничего не делаем
            logger.debug("%s not password, closing", cls.get_name())
            return

        username = await cls._get_username(user_id)
        if not username:
            # У пользователя нет имени во внешнем сервисе
            logger.debug("%s not username, closing", cls.get_name())
            return

        if await cls._is_outer_user_exists(username.value):
            logger.debug("%s user exists, changing password", cls.get_name())
            await cls._update_outer_user_password(username.value, password)
        else:
            # Мы не нашли этого пользователя во внешнем сервисе
            logger.error("Attention! Authentic user not exists")
        logger.debug("on_user_update class=%s finished", cls.get_name())

    @classmethod
    async def _get_username(cls, user_id: int) -> AuthMethod:
        auth_params = cls.get_auth_method_params(user_id, session=db.session)
        authentic_user_id = auth_params.get(AUTH_METHOD_ID_PARAM_NAME)
        if not authentic_user_id:
            logger.debug("User user_id=%d have no authentic_user_id in outer service %s", user_id, cls.get_name())
            return
        return authentic_user_id

    @classmethod
    async def _is_outer_user_exists(cls, id: str) -> bool:
        """Проверяет наличие пользователя в Authentic"""
        logger.debug("_is_outer_user_exists class=%s started", cls.get_name())
        async with aiohttp.ClientSession() as session:
            async with session.get(
                str(cls.settings.AUTHENTIC_ROOT_URL).removesuffix('/') + f'/api/v3/core/users/{id}/',
                headers={'authorization': "Bearer " + cls.settings.AUTHENTIC_TOKEN, 'Accept': 'application/json'},
            ) as response:
                if not response.ok:
                    raise ConnectionIssue(response.text)
                res: dict[str] = await response.json()
                logger.debug(res)
                return str(res.get('pk')) == id

    @classmethod
    async def _update_outer_user_password(cls, id: str, password: str):
        """Устанавливает пользователю новый пароль в Authentic"""
        logger.debug("_update_outer_user_password class=%s started", cls.get_name())
        res = False
        async with aiohttp.ClientSession() as session:
            async with session.post(
                str(cls.settings.AUTHENTIC_ROOT_URL).removesuffix('/') + f'/api/v3/core/users/{id}/set_password/',
                headers={'authorization': "Bearer " + cls.settings.AUTHENTIC_TOKEN, 'Accept': 'application/json'},
                json={'password': password},
            ) as response:
                res = response.ok
                logger.debug("_update_outer_user_password class=%s response %s", cls.get_name(), str(response.status))
        if res:
            logger.info("User %s updated in %s", id, cls.get_name())
        else:
            logger.error("User %s can't be updated in %s. Error: %s", id, cls.get_name(), res)
