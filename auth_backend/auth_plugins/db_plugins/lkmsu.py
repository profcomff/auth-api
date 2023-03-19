from auth_backend.auth_plugins.db_plugins.db_aggregators_meta import MethodMeta
from auth_backend.models import AuthMethod


class LkmsuAuth(MethodMeta):
    user_id: AuthMethod
