from sqladmin import ModelView

from auth_backend.models.db import Scope, Group, User


class ScopeAdmin(ModelView, model=Scope):
    name = "Scope"
    name_plural = "Scopes"
    column_list = ["id", "name", "comment", "is_deleted", "create_ts"]
    column_searchable_list = ["name", "comment"]


class GroupAdmin(ModelView, model=Group):
    name = "Group"
    name_plural = "Groups"
    column_list = ["id", "name", "parent_id", "is_deleted", "create_ts"]
    column_searchable_list = ["name"]


class UserAdmin(ModelView, model=User):
    name = "User"
    name_plural = "Users"
    column_list = ["id", "is_deleted", "create_ts"]