import argparse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from auth_backend.settings import get_settings
from .group import create_group
from .scope import create_scope
from .user import create_user

settings = get_settings()
engine = create_engine(settings.DB_DSN)
Session = sessionmaker(bind=engine)


def get_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

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


def process() -> None:
    args = get_args()
    session = Session()
    if args.command == 'user' and args.subcommand == 'create':
        print(f'Creating user with params {args}')
        create_user(args.email, args.password, args.group, session)
    elif args.command == 'group' and args.subcommand == 'create':
        print(f'Creating group with params {args}')
        create_group(args.namee, args.scopes, args.parent_id, session)
    elif args.command == 'scope' and args.subcommand == 'create':
        print(f'Creating scope with params {args}')
        create_scope(args.name, args.creator_id, args.comment, session)
