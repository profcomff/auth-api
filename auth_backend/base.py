from pydantic import BaseModel


class Base(BaseModel):
    def __repr__(self) -> str:
        attrs = []
        for k, v in self.__class__.schema().items():
            attrs.append(f"{k}={v}")
        return "{}({})".format(self.__class__.__name__, ', '.join(attrs))

    class Config:
        orm_mode = True


class ResponseModel(Base):
    status: str
    message: str


class Token(Base):
    token: str
