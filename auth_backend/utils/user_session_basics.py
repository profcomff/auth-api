from datetime import datetime, timedelta

from auth_backend.settings import get_settings


settings = get_settings()


def session_expires_date():
    return datetime.utcnow() + timedelta(days=settings.SESSION_TIME_IN_DAYS)
