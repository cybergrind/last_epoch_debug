from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class Config(BaseSettings):
    # you should set this path
    GAME_FOLDER: str = Field(default='')
    BASE_DIR: Path = Field(default=Path(__file__).resolve().parent.parent.parent)
    # set after load from BASE_DIR
    EXTERNAL_DIR: Path = Field(default=Path(__file__).resolve().parent.parent.parent / 'external')


config = Config()


def update_config(overrides: dict):
    global config
    config = config.copy(update=overrides)
