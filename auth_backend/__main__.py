import argparse

from auth_backend.auth_plugins import Email
from auth_backend.auth_plugins.auth_method import random_string
from auth_backend.models.db import User, Group, AuthMethod, UserGroup, GroupScope, Scope
from fastapi_sqlalchemy import db

import uvicorn


def get_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser("start")

    user = subparsers.add_parser("user")
    user_subparsers = user.add_subparsers(dest='subcommand')
    user_create = user_subparsers.add_parser("create")
    user_create.add_argument('--email', type=str, required=True)
    user_create.add_argument('--password', type=str, required=True)
    user_create.add_argument('--groups', type=str, nargs='*')

    group = subparsers.add_parser("group")
    group_subparsers = group.add_subparsers(dest='subcommand')
    group_create = group_subparsers.add_parser("create")
    group_create.add_argument('--name', type=str, required=True)
    group_create.add_argument('--parent', type=str, required=True)
    group_create.add_argument('--scopes', type=str, nargs='*')

    scope = subparsers.add_parser("scope")
    scope_subparsers = scope.add_subparsers(dest='subcommand')
    scope_create = scope_subparsers.add_parser("create")
    scope_create.add_argument('--name', type=str, required=True)
    scope_create.add_argument('--creator', type=str, required=True)

    return parser.parse_args()


if __name__ == '__main__':
    args = get_args()
    if args.command == 'start':
        print('Just start')
    if args.command == 'user' and args.subcommand == 'create':
        print(f'Creating user with params {args}')
        user = User.create(session=db.session)
        db.session.flush()
        email = AuthMethod.create(
            user_id=user.id, param="email", value=args.email, auth_method=Email.get_name(), session=db.session
        )
        _salt = random_string()
        password = AuthMethod.create(
            user_id=user.id,
            param="hashed_password",
            value=Email._hash_password(args.password, _salt),
            auth_method=Email.get_name(),
            session=db.session,
        )
        salt = AuthMethod.create(
            user_id=user.id, param="salt", value=_salt, auth_method=Email.get_name(), session=db.session
        )
        confirmed = AuthMethod.create(
            user_id=user.id, param="confirmed", value="true", auth_method=Email.get_name(), session=db.session
        )
        confirmation_token = AuthMethod.create(
            user_id=user.id, param="confirmation_token", value="admin", auth_method=Email.get_name(), session=db.session
        )
        db.session.add_all([email, password, salt, confirmed, confirmation_token])
        db.session.flush()
        for id in args.groups:
            db.session.add(UserGroup(user_id=user.id, group_id=id))
        db.session.commit()
    elif args.command == 'group' and args.subcommand == 'create':
        print(f'Creating group with params {args}')
        group = Group.create(name=args.name, parent_id=args.parent_id)
        db.session.flush()
        for id in args.scopes:
            db.session.add(GroupScope(group_id=group.id, scope_id=id))
        db.session.commit()
    elif args.command == 'scope' and args.subcommand == 'create':
        print(f'Creating scope with params {args}')
        scope = Scope(name=args.name, creator_id=args.creator_id)
        db.session.add(scope)
        db.session.commit()
