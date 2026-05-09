from datetime import datetime, timedelta

import jwt

from auth_backend.settings import get_settings
from auth_backend.utils.jwt import create_jwks, decode_jwt, generate_jwt


settings = get_settings()


def test_decode():
    uid = 123
    iat = datetime.now()
    exp = iat + timedelta(days=5)
    token = generate_jwt(uid, iat, exp)
    dct = decode_jwt(token)
    assert dct["sub"] == f"{uid}"
    assert dct["iat"] == int(iat.timestamp())
    assert dct["exp"] == int(exp.timestamp())
    assert dct["iss"] == settings.APPLICATION_HOST


def test_decode_jwks():
    uid = 123
    iat = datetime.now()
    exp = iat + timedelta(days=5)
    token = generate_jwt(uid, iat, exp)
    dct = jwt.decode(
        token,
        jwt.PyJWK(create_jwks()),
        algorithms=["RS256"],
    )
    assert dct["sub"] == f"{uid}"
    assert dct["iat"] == int(iat.timestamp())
    assert dct["exp"] == int(exp.timestamp())
    assert dct["iss"] == settings.APPLICATION_HOST
