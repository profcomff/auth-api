from auth_backend.models.db import AuthMethod
from .db_aggregators_meta import MethodMeta




class Email(MethodMeta):
    email: AuthMethod
    hashed_password: AuthMethod
    salt: AuthMethod
    confirmed: AuthMethod
    confirmation_token: AuthMethod
    tmp_email: AuthMethod
    reset_token: AuthMethod
    tmp_email_confirmation_token: AuthMethod



class GoogleAuth(MethodMeta):
    unique_google_id: AuthMethod


class PhysicsAuth(MethodMeta):
    unique_google_id: AuthMethod


class LkmsuAuth(MethodMeta):
    user_id: AuthMethod
