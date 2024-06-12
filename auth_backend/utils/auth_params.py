from sqlalchemy.orm import Session

from auth_backend.models.db import AuthMethod


def get_auth_params(user_id: int, auth_method: str, session: Session) -> dict[str, AuthMethod]:
    retval: dict[str, AuthMethod] = {}
    methods: list[AuthMethod] = (
        AuthMethod.query(session=session)
        .filter(AuthMethod.user_id == user_id, AuthMethod.auth_method == auth_method)
        .all()
    )
    for method in methods:
        retval[method.param] = method
    return retval


def get_users_auth_params(auth_method: str, session: Session) -> dict[int, dict[str, AuthMethod]]:
    retval = {}
    methods: list[AuthMethod] = AuthMethod.query(session=session).filter(AuthMethod.auth_method == auth_method).all()
    for method in methods:
        if method.user_id not in retval:
            retval[method.user_id] = {}
        retval[method.user_id][method.param] = method
    return retval
