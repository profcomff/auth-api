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
