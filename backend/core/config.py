import os
import secrets
from typing import Any, List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator, ValidationInfo


def _load_or_generate_secret() -> str:
    """Load SECRET_KEY from env; if missing, generate once and cache to file."""
    env_key = os.getenv("SECRET_KEY")
    if env_key:
        return env_key
    secret_file = os.path.join(os.path.dirname(__file__), "..", "..", ".secret_key")
    secret_path = os.path.abspath(secret_file)
    if os.path.exists(secret_path):
        with open(secret_path, "r") as f:
            return f.read().strip()
    new_secret = secrets.token_urlsafe(32)
    os.makedirs(os.path.dirname(secret_path), exist_ok=True)
    with open(secret_path, "w") as f:
        f.write(new_secret)
    return new_secret


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- Project Meta ---
    PROJECT_NAME: str = "CTI Platform"
    PROJECT_DESCRIPTION: str = "Cyber Threat Intelligence analysis and orchestration platform"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False

    # --- Security ---
    SECRET_KEY: str = Field(default_factory=lambda: _load_or_generate_secret())
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 10080  # 7 days
    ALGORITHM: str = "HS256"

    # --- CORS ---
    BACKEND_CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # --- Database ---
    DATABASE_URL: Optional[str] = "sqlite:///./data/cti.db"

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: Optional[str], info: ValidationInfo) -> Any:
        if isinstance(v, str):
            return v
        return None

    # --- Redis / Celery (Optional) ---
    REDIS_URL: Optional[str] = None
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None

    # --- External Integrations ---
    VIRUSTOTAL_API_KEY: Optional[str] = None
    MALWAREBAZAAR_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    # --- Logging ---
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json or text

    # --- Host Security ---
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1", "*.localhost"]

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def assemble_allowed_hosts(cls, v: Any) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # --- File Upload ---
    UPLOAD_DIR: str = "./data/uploads"
    MAX_UPLOAD_SIZE_MB: int = 50

    # --- Pagination defaults ---
    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100


settings = Settings()
