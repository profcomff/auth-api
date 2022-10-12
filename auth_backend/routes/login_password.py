from fastapi import APIRouter


login_password = APIRouter(prefix="/email", tags=["Email"])


@login_password.post("/forgot", response_model=None)
async def forgot_password() -> ...:
    ...


@login_password.post("/approve", response_model=bool)
async def approve_email(token: str):
    pass
