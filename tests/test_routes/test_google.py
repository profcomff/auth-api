from unittest.mock import patch

import google.auth.exceptions
import oauthlib.oauth2.rfc6749.errors
import pytest
from fastapi.testclient import TestClient


@pytest.mark.skip('Google should be properly mocked')
def test_login_ok(client_auth: TestClient):
    """Пользователь существует, просто логинимся в него"""

    patch_check_google_creds = patch("google_auth_oauthlib.flow.Flow.fetch_token")
    patch_check_google_creds.return_value = {"id_token": "abc.123.efg"}
    patch_check_google_creds.start()

    patch_check_google_token = patch("google.oauth2.id_token.verify_oauth2_token")
    patch_check_google_token.return_value = {"sub": "12345"}
    patch_check_google_token.start()

    resp = client_auth.post(
        '/google/login',
        json={
            "state": "a81RJAxRnewtdjWwwAhVJpBIQopz6U",
            "code": "4/0AWtgzh7aIxp1d-Spxd-....-.....",
            "scope": "profile https://www.googleapis.com/auth/userinfo.profile openid",
            "authuser": "0",
            "prompt": "none",
        },
    )
    assert resp.status_code == 200, resp.json()
    assert resp.json().get('token') is not None, resp.json()

    patch_check_google_creds.stop()
    patch_check_google_token.stop()


@pytest.mark.skip('Google should be properly mocked')
def test_login_fail(client_auth: TestClient):
    """Пользователь существует, просто логинимся в него, но с неверными данными гугла"""

    patch_check_google_creds = patch("google_auth_oauthlib.flow.Flow.fetch_token")
    patch_check_google_creds.side_effect = oauthlib.oauth2.rfc6749.errors.InvalidGrantError()
    patch_check_google_creds.start()

    patch_check_google_token = patch("google.oauth2.id_token.verify_oauth2_token")
    patch_check_google_token.return_value = {"sub": "12345"}
    patch_check_google_token.start()

    resp = client_auth.post(
        '/google/login',
        json={
            "state": "a81RJAxRnewtdjWwwAhVJpBIQopz6U",
            "code": "4/0AWtgzh7aIxp1d-Spxd-....-.....",
            "scope": "profile https://www.googleapis.com/auth/userinfo.profile openid",
            "authuser": "0",
            "prompt": "none",
        },
    )
    assert resp.status_code == 406, resp.json()
    patch_check_google_creds.stop()
    patch_check_google_token.stop()


@pytest.mark.skip('Google should be properly mocked')
def test_register_ok(client_auth: TestClient):
    """Пользователь не сущесвует, пробуем логиниться, а потом регистрируемся"""

    patch_check_google_creds = patch("google_auth_oauthlib.flow.Flow.fetch_token")
    patch_check_google_creds.return_value = {"id_token": "abc.123.efg"}
    patch_check_google_creds.start()

    patch_check_google_token = patch("google.oauth2.id_token.verify_oauth2_token")
    patch_check_google_token.return_value = {"sub": "12345"}
    patch_check_google_token.start()

    resp = client_auth.post(
        '/google/login',
        json={
            "state": "a81RJAxRnewtdjWwwAhVJpBIQopz6U",
            "code": "4/0AWtgzh7aIxp1d-Spxd-....-.....",
            "scope": "profile https://www.googleapis.com/auth/userinfo.profile openid",
            "authuser": "0",
            "prompt": "none",
        },
    )
    assert resp.status_code == 403, resp.json()
    assert resp.json().get('id_token') is not None

    resp = client_auth.post(
        '/google/register',
        json={"id_token": resp.json().get('id_token')},
    )
    assert resp.status_code == 200, resp.json()
    assert resp.json().get('token') is not None

    patch_check_google_creds.stop()
    patch_check_google_token.stop()


@pytest.mark.skip('Google should be properly mocked')
def test_register_fail(client_auth: TestClient):
    """Пользователь не сущесвует, пробуем логиниться, а потом регистрируемся с неверным id_token"""

    patch_check_google_creds = patch("google_auth_oauthlib.flow.Flow.fetch_token")
    patch_check_google_creds.return_value = {"id_token": "abc.123.efg"}
    patch_check_google_creds.start()

    patch_check_google_token = patch("google.oauth2.id_token.verify_oauth2_token")
    patch_check_google_token.return_value = {"sub": "12345"}
    patch_check_google_token.start()

    resp = client_auth.post(
        '/google/login',
        json={
            "state": "a81RJAxRnewtdjWwwAhVJpBIQopz6U",
            "code": "4/0AWtgzh7aIxp1d-Spxd-....-.....",
            "scope": "profile https://www.googleapis.com/auth/userinfo.profile openid",
            "authuser": "0",
            "prompt": "none",
        },
    )
    assert resp.status_code == 403, resp.json()
    assert resp.json().get('id_token') is not None

    patch_check_google_token.stop()
    patch_check_google_token.side_effect = google.auth.exceptions.DefaultCredentialsError()
    patch_check_google_token.start()

    resp = client_auth.post(
        '/google/register',
        json={"id_token": '213.abc.123'},  # Просто другой токен
    )
    assert resp.status_code == 406, resp.json()

    patch_check_google_creds.stop()
    patch_check_google_token.stop()


@pytest.mark.skip('Google should be properly mocked')
def test_add_method_ok(client: TestClient):
    """Пользователь залогинен, передаем ему верные данные гугла"""

    patch_check_google_creds = patch("google_auth_oauthlib.flow.Flow.fetch_token")
    patch_check_google_creds.return_value = {"id_token": "abc.123.efg"}
    patch_check_google_creds.start()

    patch_check_google_token = patch("google.oauth2.id_token.verify_oauth2_token")
    patch_check_google_token.return_value = {"sub": "12345"}
    patch_check_google_token.start()

    resp = client.post(
        '/google/register',
        json={"id_token": resp.json().get('id_token')},
    )
    assert resp.status_code == 200, resp.json()
    assert resp.json().get('token') is not None
    assert resp.json().get('user_id') == client.user_id  # Скорее всего неправильная конструкция

    patch_check_google_creds.stop()
    patch_check_google_token.stop()


@pytest.mark.skip('Google should be properly mocked')
def test_add_method(client: TestClient):
    """Пользователь залогинен, передаем ему неверные данные гугла"""

    patch_check_google_creds = patch("google_auth_oauthlib.flow.Flow.fetch_token")
    patch_check_google_creds.side_effect = oauthlib.oauth2.rfc6749.errors.InvalidGrantError()
    patch_check_google_creds.start()

    patch_check_google_token = patch("google.oauth2.id_token.verify_oauth2_token")
    patch_check_google_token.return_value = {"sub": "12345"}
    patch_check_google_token.start()

    resp = client.post(
        '/google/register',
        json={"id_token": resp.json().get('id_token')},
    )
    assert resp.status_code == 406, resp.json()

    patch_check_google_creds.stop()
    patch_check_google_token.stop()
