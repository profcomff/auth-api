from auth_backend.base import Base


class PostTokenResponse(Base):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
