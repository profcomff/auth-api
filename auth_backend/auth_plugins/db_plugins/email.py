from auth_backend.auth_plugins.db_plugins.db_aggregators_meta import MethodMeta
from auth_backend.models import AuthMethod


class Email(MethodMeta):
    email: AuthMethod
    hashed_password: AuthMethod
    salt: AuthMethod
    confirmed: AuthMethod
    confirmation_token: AuthMethod
    tmp_email: AuthMethod
    reset_token: AuthMethod
    tmp_email_confirmation_token: AuthMethod
