import secrets

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator


class Settings(BaseSettings):
    database_url: str = "sqlite:///./meal_manager.db"
    secret_key: str = secrets.token_urlsafe(32)
    access_token_expire_minutes: int = 60
    cors_origins: str = "http://localhost:3000"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @field_validator("access_token_expire_minutes")
    @classmethod
    def valid_expiry(cls, v):
        if v < 5 or v > 1440:
            raise ValueError("ACCESS_TOKEN_EXPIRE_MINUTES must be between 5 and 1440")
        return v

    @field_validator("secret_key")
    @classmethod
    def valid_secret_key(cls, v):
        if v == "change-me-in-production":
            raise ValueError("SECRET_KEY must be replaced with a secure random value")
        if len(v) < 24:
            raise ValueError("SECRET_KEY must be at least 24 characters")
        return v


settings = Settings()
