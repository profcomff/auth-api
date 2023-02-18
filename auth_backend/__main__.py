import argparse


def get_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser("start")

    user = subparsers.add_parser("user")
    user_subparsers = user.add_subparsers(dest='subcommand')
    user_create = user_subparsers.add_parser("create")
    user_create.add_argument('--name', type=str, required=True)
    user_create.add_argument('--password', type=str, required=True)
    user_create.add_argument('--groups', type=str, nargs='*')

    group = subparsers.add_parser("group")
    group_subparsers = group.add_subparsers(dest='subcommand')
    group_create = group_subparsers.add_parser("create")
    group_create.add_argument('--name', type=str, required=True)
    group_create.add_argument('--parent', type=str, required=True)
    group_create.add_argument('--scopes', type=str, nargs='*')

    return parser.parse_args()


if __name__ == '__main__':
    args = get_args()
    if args.command == 'start':
        print('Just start')
    if args.command == 'user' and args.subcommand == 'create':
        print(f'Creating user with params {args}')
    elif args.command == 'group' and args.subcommand == 'create':
        print(f'Creating user with params {args}')