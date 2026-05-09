import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Any

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from auth_backend.settings import get_settings


settings = get_settings()


@dataclass
class JwtSettings:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    pem_private_key: bytes
    pem_public_key: bytes
    n: str
    e: str
    kid: str


@lru_cache(1)
def get_private_key() -> rsa.RSAPrivateKey:
    # Если использование отключено – используем отсебятину
    if not settings.JWT_ENABLED:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    if settings.JWT_PRIVATE_KEY:
        key_bytes = settings.JWT_PRIVATE_KEY
    elif settings.JWT_PRIVATE_KEY_FILE:
        with open(settings.JWT_PRIVATE_KEY_FILE, "rb") as key_file:
            key_bytes = key_file.read()
    else:
        raise Exception("JWT private key not provided")
    return serialization.load_pem_private_key(key_bytes, password=None)


def to_base64url(value: int) -> str:
    """Функция для преобразования числа в Base64URL"""
    # Преобразуем число в байты
    byte_length = (value.bit_length() + 7) // 8
    byte_data = value.to_bytes(byte_length, byteorder='big')
    # Кодируем в Base64 и удаляем padding (=)
    return base64.urlsafe_b64encode(byte_data).rstrip(b'=').decode('utf-8')


@lru_cache(1)
def ensure_jwt_settings() -> JwtSettings:
    private_key = get_private_key()
    public_key = private_key.public_key()
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_numbers = public_key.public_numbers()
    n = to_base64url(public_numbers.n)
    e = to_base64url(public_numbers.e)
    kid = hashlib.sha256(pem_public_key).hexdigest()[:16]
    return JwtSettings(
        private_key=private_key,
        public_key=public_key,
        pem_private_key=pem_private_key,
        pem_public_key=pem_public_key,
        n=n,
        e=e,
        kid=kid,
    )


@lru_cache(1)
def create_jwks() -> dict[str, str]:
    jwt_settings = ensure_jwt_settings()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": jwt_settings.kid,
        "alg": "RS256",
        "n": jwt_settings.n,
        "e": jwt_settings.e,
    }


def generate_jwt(user_id: int, create_ts: datetime, expire_ts: datetime) -> str:
    jwt_settings = ensure_jwt_settings()
    return jwt.encode(
        {
            "sub": f"{user_id}",
            "iss": f"{settings.APPLICATION_HOST}",
            "iat": int(create_ts.timestamp()),
            "exp": int(expire_ts.timestamp()),
        },
        jwt_settings.pem_private_key,
        algorithm="RS256",
    )


def decode_jwt(token: str) -> dict[str, Any]:
    jwt_settings = ensure_jwt_settings()
    return jwt.decode(
        token,
        jwt_settings.pem_public_key,
        algorithms=["RS256"],
    )
