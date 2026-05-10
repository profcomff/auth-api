from sqladmin import ModelView

from auth_backend.models.db import Group, Scope, User
from auth_backend.routes.user import patch_user_groups


class ScopeAdmin(ModelView, model=Scope):
    name = "Scope"
    name_plural = "Scopes"
    column_list = ["id", "name", "comment", "is_deleted"]
    column_details_list = [
        "id",
        "name",
        "comment",
        "group",
        "create_ts",
        "update_ts",
        "is_deleted",
    ]
    column_searchable_list = ["id", "name"]
    column_sortable_list = ["id", "name", "is_deleted"]
    column_default_sort = [("id", False)]
    form_excluded_columns = ["create_ts", "update_ts", "groups", "user_sessions", "is_deleted"]
    can_create = False  # I don't know how to use UnionAuth there to get user_id that is required


class GroupAdmin(ModelView, model=Group):
    name = "Group"
    name_plural = "Groups"
    column_list = ["id", "name", "scopes", "users", "parent_id", "is_deleted"]
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
    form_excluded_columns = ["create_ts", "update_ts", "is_deleted"]


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

    async def on_model_change(self, data: dict, model: User, is_created: bool, request) -> None:
        group_ids = [int(group) for group in (data.pop("groups") or [])]
        with self.session_maker(expire_on_commit=False) as session:
            patch_user_groups(model.id, group_ids, session)
