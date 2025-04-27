from pydantic_settings import BaseSettings, Field


class Config(BaseSettings):
    # you should set this path
    GAME_FOLDER: str = Field(default='')


config = Config()


def update_config(overrides: dict):
    global config
    config = config.copy(update=overrides)
