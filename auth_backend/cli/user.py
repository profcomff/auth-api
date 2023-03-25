import errno

from sqlalchemy.orm import Session

from auth_backend.auth_plugins import Email
from auth_backend.auth_plugins.auth_method import random_string
from auth_backend.models import AuthMethod, User


def create_user(email: str, password: str, session: Session) -> None:
    if (
        AuthMethod.query(session=session)
        .filter(AuthMethod.value == email, AuthMethod.auth_method == "email")
        .one_or_none()
    ):
        print("User already exists")
        exit(errno.EIO)
    user = User.create(session=session)
    session.flush()
    email = AuthMethod.create(
        user_id=user.id, param="email", value=email, auth_method=Email.get_name(), session=session
    )
    _salt = random_string()
    password = AuthMethod.create(
        user_id=user.id,
        param="hashed_password",
        value=Email._hash_password(password, _salt),
        auth_method=Email.get_name(),
        session=session,
    )
    salt = AuthMethod.create(user_id=user.id, param="salt", value=_salt, auth_method=Email.get_name(), session=session)
    confirmed = AuthMethod.create(
        user_id=user.id, param="confirmed", value="true", auth_method=Email.get_name(), session=session
    )
    confirmation_token = AuthMethod.create(
        user_id=user.id, param="confirmation_token", value="admin", auth_method=Email.get_name(), session=session
    )
    session.add_all([email, password, salt, confirmed, confirmation_token])
    session.commit()
    print(f"Created user: {user.id=}, {email.value=}")
