from os import path as os_path
from pathlib import Path
from types import SimpleNamespace
from typing import Union

from alembic.config import Config
from alembic import command
from auth_backend.settings import get_settings


PROJECT_PATH = Path(__file__).parent.parent.resolve()


def make_alembic_config(cmd_opts: Union[SimpleNamespace], base_path: Path = PROJECT_PATH) -> Config:
    """
    Создает объект конфигурации alembic на основе аргументов командной строки,
    подменяет относительные пути на абсолютные.
    """
    database_uri = get_settings().DB_DSN

    path_to_folder = cmd_opts.config
    if not os_path.isabs(cmd_opts.config):
        cmd_opts.config = os_path.join(base_path, cmd_opts.config + "alembic.ini")

    config = Config(file_=cmd_opts.config, ini_section=cmd_opts.name, cmd_opts=cmd_opts)

    alembic_location = config.get_main_option("script_location")
    if not os_path.isabs(alembic_location):
        config.set_main_option("script_location", os_path.join(base_path, path_to_folder + alembic_location))
    if cmd_opts.pg_url:
        config.set_main_option("sqlalchemy.url", database_uri)

    return config


def run_upgrade():
    cmd_options = SimpleNamespace(config="",
                                  name="alembic",
                                  pg_url=get_settings().DB_DSN)
    config = make_alembic_config(cmd_options)
    command.upgrade(config, "head")


def run_downgrade():
    cmd_options = SimpleNamespace(config="",
                                  name="alembic",
                                  pg_url=get_settings().DB_DSN)
    config = make_alembic_config(cmd_options)
    command.downgrade(config, "base")
