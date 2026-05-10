from sqladmin import ModelView
from sqlalchemy import func, select
from sqlalchemy.sql.expression import Select
from starlette.requests import Request

from auth_backend.admin.filter import FilteredModelConverter
from auth_backend.models.db import Group, Scope, User
from auth_backend.routes.groups import create_group_logic, delete_group_id, patch_group_logic
from auth_backend.routes.user import patch_user_groups
from auth_backend.schemas.models import GroupPatch, GroupPost


class ScopeAdmin(ModelView, model=Scope):
    name = "Scope"
    name_plural = "Scopes"
    column_list = ["id", "name", "comment"]
    column_details_list = [
        "id",
        "name",
        "comment",
        "creator_id",
        "is_deleted",
    ]
    column_searchable_list = ["id", "name"]
    column_sortable_list = ["id", "name"]
    column_default_sort = [("id", False)]
    form_excluded_columns = ["create_ts", "update_ts", "groups", "user_sessions", "is_deleted"]
    can_create = False  # I don't know how to use UnionAuth there to get user_id that is required
    form_converter = FilteredModelConverter

    def list_query(self, request: Request) -> Select:
        return select(Scope).where(Scope.is_deleted == False)

    def count_query(self, request: Request) -> Select:
        return select(func.count(Scope.id)).where(Scope.is_deleted == False)

    async def update_model(self, request, pk, data):
        with self.session_maker(expire_on_commit=False) as session:
            scope_data = {k: v for k, v in data.items() if v is not None}
            obj = Scope.update(int(pk), **scope_data, session=session)
            session.commit()
            return obj

    async def delete_model(self, request, pk):
        with self.session_maker(expire_on_commit=False) as session:
            Scope.delete(session=session, id=int(pk))
            session.commit()


class GroupAdmin(ModelView, model=Group):
    name = "Group"
    name_plural = "Groups"
    column_list = ["id", "name", "scopes", "users", "parent_id"]
    column_details_list = [
        "id",
        "name",
        "parent_id",
        "scopes",
        "users",
        "create_ts",
        "update_ts",
        "is_deleted",
    ]
    column_searchable_list = ["name"]
    column_sortable_list = ["id", "name", "parent_id", "is_deleted"]
    column_default_sort = [("id", False)]
    form_excluded_columns = ["child", "users", "create_ts", "update_ts", "is_deleted"]
    form_converter = FilteredModelConverter

    def list_query(self, request: Request) -> Select:
        return select(Group).where(Group.is_deleted == False)

    def count_query(self, request: Request) -> Select:
        return select(func.count(Group.id)).where(Group.is_deleted == False)

    async def insert_model(self, request, data):
        scope_ids = [int(s) for s in (data.pop("scopes", None) or [])]
        parent_id = int(data["parent_id"]) if data.get("parent_id") else None
        group_inp = GroupPost(name=data["name"], parent_id=parent_id, scopes=scope_ids)
        with self.session_maker(expire_on_commit=False) as session:
            result = create_group_logic(group_inp, session)
            return Group.get(result["id"], session=session)

    async def update_model(self, request, pk, data):
        scope_ids = [int(s) for s in (data.pop("scopes", None) or [])]
        parent_id = int(data["parent_id"]) if data.get("parent_id") else None
        group_inp = GroupPatch(
            name=data.get("name"),
            parent_id=parent_id,
            scopes=scope_ids,
        )
        with self.session_maker(expire_on_commit=False) as session:
            return patch_group_logic(int(pk), group_inp, session)

    async def delete_model(self, request, pk):
        with self.session_maker(expire_on_commit=False) as session:
            delete_group_id(int(pk), session)


class UserAdmin(ModelView, model=User):
    name = "User"
    name_plural = "Users"
    column_list = ["id", "scopes", "groups"]
    column_details_list = ["id", "groups", "scopes", "is_deleted"]
    column_searchable_list = ["id"]
    column_sortable_list = ["id", "is_deleted"]
    form_include_pk = False
    form_columns = ["groups"]
    can_create = False
    can_delete = False
    column_formatters = {
        "scopes": lambda m, a: ", ".join(s.name for s in m.scopes),
    }
    column_formatters_detail = {
        "scopes": lambda m, a: ", ".join(s.name for s in (m.scopes or set())),
    }
    form_converter = FilteredModelConverter

    def list_query(self, request: Request) -> Select:
        return select(User).where(User.is_deleted == False)

    def count_query(self, request: Request) -> Select:
        return select(func.count(User.id)).where(User.is_deleted == False)

    async def update_model(self, request, pk, data):
        group_ids = [int(group) for group in (data.pop("groups") or [])]
        with self.session_maker(expire_on_commit=False) as session:
            patch_user_groups(int(pk), group_ids, session)
            return User.get(int(pk), session=session)
