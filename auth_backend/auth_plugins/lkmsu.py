import logging
from typing import Any
from urllib.parse import quote

import aiohttp
import jwt
from event_schema.auth import UserLogin
from fastapi import Depends
from fastapi_sqlalchemy import db
from pydantic import BaseModel, Field
from starlette.background import BackgroundTasks

from auth_backend.exceptions import AlreadyExists, OauthAuthFailed
from auth_backend.kafka.kafka import get_kafka_producer
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.schemas.types.scopes import Scope
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth
from auth_backend.utils.string import concantenate_strings

from .auth_method import OauthMeta, Session


logger = logging.getLogger(__name__)


class LkmsuSettings(Settings):
    LKMSU_REDIRECT_URL: str = 'https://app.test.profcomff.com/auth/oauth-authorized/lk-msu'
    LKMSU_CLIENT_ID: str | None = None
    LKMSU_CLIENT_SECRET: str | None = None
    LKMSU_FACULTY_NAME: str = 'Физический факультет'


class LkmsuAuth(OauthMeta):
    """Вход в приложение по аккаунту гугл"""

    prefix = '/lk-msu'
    tags = ['lk_msu']
    settings = LkmsuSettings()

    class OauthResponseSchema(BaseModel):
        code: str | None = None
        id_token: str | None = Field(default=None, help="LK MSU JWT token identifier")
        scopes: list[Scope] | None = None
        session_name: str | None = None

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(auto_error=True, scopes=[], allow_none=True)),
    ) -> Session:
        """Создает аккаунт или привязывает существующий

        Если передана активная сессия пользователя, то привязывает аккаунт https://lk.msu.ru к
        аккаунту в активной сессии. Иначе, создает новый пользователь и делает https://lk.msu.ru
        первым методом входа.
        """
        payload = {
            "grant_type": "authorization_code",
            "code": user_inp.code,
            "client_id": cls.settings.LKMSU_CLIENT_ID,
            "client_secret": cls.settings.LKMSU_CLIENT_SECRET,
            "redirect_uri": cls.settings.LKMSU_REDIRECT_URL,
        }
        lk_user_id = None
        userinfo = None

        if user_inp.id_token is None:
            async with aiohttp.ClientSession() as session:
                async with session.post('https://lk.msu.ru/oauth/token', json=payload) as response:
                    token_result = await response.json()
                    logger.debug(token_result)
                if 'access_token' not in token_result:
                    raise OauthAuthFailed('Invalid credentials for lk msu account', 'Неправильные учетные данные')
                token = token_result['access_token']

                async with session.get(
                    'https://lk.msu.ru/oauth/userinfo', headers={"Authorization": f"Bearer {token}"}
                ) as response:
                    userinfo = await response.json()
                    logger.debug(userinfo)
                    lk_user_id = userinfo['user_id']
        else:
            userinfo = jwt.decode(user_inp.id_token, cls.settings.ENCRYPTION_KEY, algorithms=["HS256"])
            lk_user_id = userinfo['user_id']
            logger.debug(userinfo)

        user = await cls._get_user('user_id', lk_user_id, db_session=db.session)

        if user is not None:
            raise AlreadyExists(User, user.id)
        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
        await cls._register_auth_method('user_id', lk_user_id, user, db_session=db.session)
        userdata = await LkmsuAuth._convert_data_to_userdata_format(userinfo)
        await get_kafka_producer().produce(
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            LkmsuAuth.generate_kafka_key(user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _login(
        cls,
        user_inp: OauthResponseSchema,
        background_tasks: BackgroundTasks,
    ) -> Session:
        """Вход в пользователя с помощью аккаунта https://lk.msu.ru

        Производит вход, если находит пользователя по уникальному идендификатору. Если аккаунт не
        найден, возвращает ошибка.
        """
        payload = {
            "grant_type": "authorization_code",
            "code": user_inp.code,
            "client_id": cls.settings.LKMSU_CLIENT_ID,
            "client_secret": cls.settings.LKMSU_CLIENT_SECRET,
            "redirect_uri": cls.settings.LKMSU_REDIRECT_URL,
        }
        lk_user_id = None
        userinfo = None
        async with aiohttp.ClientSession() as session:
            async with session.post('https://lk.msu.ru/oauth/token', json=payload) as response:
                token_result = await response.json()
                logger.debug(token_result)
            if 'access_token' not in token_result:
                raise OauthAuthFailed('Invalid credentials for lk msu account', 'Неправильные учетные данные')
            token = token_result['access_token']

            async with session.get(
                'https://lk.msu.ru/oauth/userinfo', headers={"Authorization": f"Bearer {token}"}
            ) as response:
                userinfo = await response.json()
                logger.error(userinfo)
                lk_user_id = userinfo['user_id']

        user = await cls._get_user('user_id', lk_user_id, db_session=db.session)
        if not user:
            id_token = jwt.encode(userinfo, cls.settings.ENCRYPTION_KEY, algorithm="HS256")
            raise OauthAuthFailed(
                'No users found for lk msu account', 'Не найдено пользователей с таким аккаунтом LK MSU', id_token
            )
        userdata = await LkmsuAuth._convert_data_to_userdata_format(userinfo)
        await get_kafka_producer().produce(
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            LkmsuAuth.generate_kafka_key(user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _redirect_url(cls):
        """URL на который происходит редирект после завершения входа на стороне провайдера"""
        return OauthMeta.UrlSchema(url=cls.settings.LKMSU_REDIRECT_URL)

    @classmethod
    async def _auth_url(cls):
        """URL на который происходит редирект из приложения для авторизации на стороне провайдера"""
        return OauthMeta.UrlSchema(
            url=f'https://lk.msu.ru/oauth/authorize?response_type=code&client_id={cls.settings.LKMSU_CLIENT_ID}&redirect_uri={quote(cls.settings.LKMSU_REDIRECT_URL)}&scope=scope.profile.view'
        )

    @classmethod
    def get_student(cls, data: dict[str, Any]) -> list[dict[str | Any]]:
        student: dict[str, Any] = data.get("student", {})
        first_name, last_name, middle_name = '', '', ''
        if 'first_name' in data.keys() and data['first_name'] is not None:
            first_name = data['first_name']
        if 'last_name' in data.keys() and data['last_name'] is not None:
            last_name = data['last_name']
        if 'middle_name' in data.keys() and data['middle_name'] is not None:
            middle_name = data['middle_name']
        full_name = concantenate_strings([first_name, last_name, middle_name])
        if not full_name:
            full_name = None
        items = [
            {"category": "Личная информация", "param": "Полное имя", "value": full_name},
        ]
        return items

    @classmethod
    def get_entrants(cls, data: dict[str, Any]) -> list[dict[str, Any]]:
        student: dict[str, Any] = data.get("student", {})
        faculties_names = []
        for entrant in student.get('entrants'):
            faculties_names.append(entrant.get('faculty', {}).get("name"))
        for entrant in student.get('entrants'):
            if (
                cls.settings.LKMSU_FACULTY_NAME in faculties_names
                and entrant.get('faculty', {}).get("name") != cls.settings.LKMSU_FACULTY_NAME
            ):
                continue
            if not (group := entrant.get("groups")):
                group = [{}]
            items = [
                {
                    "category": "Учёба",
                    "param": "Номер студенческого билета",
                    "value": entrant.get("record_book"),
                },
                {"category": "Учёба", "param": "Факультет", "value": entrant.get('faculty', {}).get("name")},
                {
                    "category": "Учёба",
                    "param": "Ступень обучения",
                    "value": entrant.get('educationType', {}).get("name"),
                },
                {
                    "category": "Учёба",
                    "param": "Форма обучения",
                    "value": entrant.get("educationForm", {}).get("name"),
                },
                {
                    "category": "Учёба",
                    "param": "Академическая группа",
                    "value": group[0].get("name"),
                },
            ]
            if cls.settings.LKMSU_FACULTY_NAME not in faculties_names:
                break
            return items

    @classmethod
    async def _convert_data_to_userdata_format(cls, data: dict[str, Any]) -> UserLogin:
        items = [
            {"category": "Контакты", "param": "Электронная почта", "value": data.get("email")},
            {"category": "Учёба", "param": "Должность", "value": data.get("userType", {}).get('name')},
        ]
        student_items = cls.get_student(data)
        entrants_items = cls.get_entrants(data)
        items.extend(student_items)
        items.extend(entrants_items)
        result = {"items": items, "source": cls.get_name()}
        return cls.userdata_process_empty_strings(UserLogin.model_validate(result))
