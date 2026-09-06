"""Configuration, validated at import time so misconfiguration fails loudly."""

from __future__ import annotations

import secrets
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SKYRECON_", env_file=".env", extra="ignore"
    )

    env: str = "development"
    database_url: str = "sqlite:///./skyrecon.db"

    master_key: str = ""
    jwt_secret: str = ""

    cors_origins: str = "http://localhost:8000"
    access_ttl_min: int = 15
    refresh_ttl_days: int = 7

    rate_limit: int = 120
    rate_window: int = 60

    bootstrap_email: str = "admin@skyrecon.local"
    bootstrap_password: str = ""
    require_admin_mfa: bool = True

    # Confidence half-life, in days, used when ageing indicators.
    ioc_half_life_days: int = 30

    @property
    def is_production(self) -> bool:
        return self.env.lower() in {"production", "prod"}

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @field_validator("master_key", "jwt_secret", mode="after")
    @classmethod
    def _no_blank_secrets_in_prod(cls, v: str, info) -> str:
        return v

    def validated(self) -> Settings:
        """
        Production refuses to start without real secrets; development mints
        ephemeral ones so `uvicorn app.main:app` just works on a clean clone.
        """
        if self.is_production:
            missing = [
                name
                for name, val in (
                    ("SKYRECON_MASTER_KEY", self.master_key),
                    ("SKYRECON_JWT_SECRET", self.jwt_secret),
                )
                if not val
            ]
            if missing:
                raise RuntimeError(
                    "refusing to start in production without: " + ", ".join(missing)
                )
            if len(self.jwt_secret) < 32:
                raise RuntimeError("SKYRECON_JWT_SECRET must be at least 32 characters")
        else:
            if not self.master_key:
                from app.security.crypto import generate_master_key

                object.__setattr__(self, "master_key", generate_master_key())
            if not self.jwt_secret:
                object.__setattr__(self, "jwt_secret", secrets.token_urlsafe(48))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings().validated()


def reset_settings() -> None:
    get_settings.cache_clear()
