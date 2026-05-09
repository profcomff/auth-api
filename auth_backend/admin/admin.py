from sqladmin import ModelView

from auth_backend.models.db import Group, Scope, User


class ScopeAdmin(ModelView, model=Scope):
    name = "Scope"
    name_plural = "Scopes"
    column_list = ["id", "name", "comment", "is_deleted"]
    column_searchable_list = ["name", "comment"]


class GroupAdmin(ModelView, model=Group):
    name = "Group"
    name_plural = "Groups"
    column_list = ["id", "name", "scopes", "users", "parent_id", "is_deleted"]
    column_searchable_list = ["name"]


class UserAdmin(ModelView, model=User):
    name = "User"
    name_plural = "Users"
    column_list = ["id", "scopes", "groups"]
