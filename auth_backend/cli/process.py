import argparse

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from auth_backend.settings import get_settings

from ..routes import app
from .group import create_group
from .scope import create_scope
from .user import create_user
from .user_group import create_user_group


settings = get_settings()
engine = create_engine(str(settings.DB_DSN))
Session = sessionmaker(bind=engine)


def get_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    start = subparsers.add_parser("start")

    user = subparsers.add_parser("user")
    user_subparsers = user.add_subparsers(dest='subcommand')
    user_create = user_subparsers.add_parser("create")
    user_create.add_argument('--email', type=str, required=True)
    user_create.add_argument('--password', type=str, required=True)

    group = subparsers.add_parser("group")
    group_subparsers = group.add_subparsers(dest='subcommand')
    group_create = group_subparsers.add_parser("create")
    group_create.add_argument('--name', type=str, required=True)
    group_create.add_argument('--parent', type=str, required=False, default=None)
    group_create.add_argument('--scopes', type=str, nargs='*')

    scope = subparsers.add_parser("scope")
    scope_subparsers = scope.add_subparsers(dest='subcommand')
    scope_create = scope_subparsers.add_parser("create")
    scope_create.add_argument('--name', type=str, required=True)
    scope_create.add_argument('--creator_email', type=str, required=True)
    scope_create.add_argument('--comment', type=str, required=True)

    user_group = subparsers.add_parser("user_group")
    user_group_subparsers = user_group.add_subparsers(dest='subcommand')
    user_group_create = user_group_subparsers.add_parser("create")
    user_group_create.add_argument('--email', type=str, required=True)

    return parser.parse_args()


def process() -> None:
    args = get_args()
    session = Session()
    if args.command == "start":
        import uvicorn

        uvicorn.run(app)
    elif args.command == 'user' and args.subcommand == 'create':
        print(f'Creating user with params {args}')
        create_user(args.email, args.password, session)
    elif args.command == 'group' and args.subcommand == 'create':
        print(f'Creating group with params {args}')
        create_group(args.name, args.scopes, args.parent, session)
    elif args.command == 'scope' and args.subcommand == 'create':
        print(f'Creating scope with params {args}')
        create_scope(args.name, args.creator_email, args.comment, session)
    elif args.command == 'user_group' and args.subcommand == 'create':
        print(f'Creating user_group with params {args}')
        create_user_group(args.email, session)
