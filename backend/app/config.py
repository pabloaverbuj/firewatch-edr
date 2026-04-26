from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://firewatch:firewatch123@localhost:5432/firewatch"
    redis_url: str = "redis://localhost:6379"
    secret_key: str = "change-me"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480
    anthropic_api_key: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
