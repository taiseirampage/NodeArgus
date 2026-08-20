from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env."""

    POSTGRES_URL: str = (
        "postgresql://nodeargus:nodeargus_password@localhost:5432/nodeargus"
    )
    POSTGRES_ASYNC_URL: str = (
        "postgresql+asyncpg://nodeargus:nodeargus_password@localhost:5432/nodeargus"
    )
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    GEOIP_DB_PATH: str = "data/GeoLite2-City.mmdb"
    GEOIP_LICENSE_KEY: str | None = None
    GEOIP_MIRROR_URL: str | None = None
    GEOIP_AUTO_UPDATE: bool = False

    model_config = SettingsConfigDict(env_file=PROJECT_ROOT / ".env", extra="ignore")


settings = Settings()
