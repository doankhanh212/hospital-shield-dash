"""Configuration loader — reads settings from .env file and environment variables."""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Config:
    """Immutable application configuration."""

    db_host: str
    db_port: int
    db_name: str
    db_user: str
    db_password: str
    db_pool_min: int
    db_pool_max: int
    batch_size: int
    log_level: str
    zeek_log_dir: str
    scan_mode: str = "file"       # 'file' | 'live'
    zeek_interface: str = ""      # e.g. 'eth0' — informational only (Zeek runs on host)
    local_subnets: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    # Authentication
    jwt_secret_key: str = ""     # Must be set in .env; min 32 chars
    # Disk / retention
    log_retention_days: int = 7  # delete log files older than N days
    # Backpressure
    max_ingest_queue_size: int = 1000  # max rows buffered between parse and write
    api_cors_origins: str = "http://localhost:8080,http://127.0.0.1:8080,http://localhost:5173,http://127.0.0.1:5173"

    @property
    def local_subnets_list(self) -> list[str]:
        """Return LOCAL_SUBNETS as a list of CIDR strings."""
        return [s.strip() for s in self.local_subnets.split(",") if s.strip()]

    @property
    def dsn(self) -> str:
        """Build a PostgreSQL DSN string."""
        return (
            f"postgresql://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def api_cors_origins_list(self) -> list[str]:
        """Return API_CORS_ORIGINS as a list of origin strings."""
        return [s.strip() for s in self.api_cors_origins.split(",") if s.strip()]


def load_config(env_path: str | None = None) -> Config:
    """Load configuration from .env file and environment variables.

    Args:
        env_path: Optional path to a .env file. If None, searches for .env
                  in the package directory and current working directory.

    Returns:
        A frozen Config dataclass with all settings.
    """
    if env_path:
        load_dotenv(env_path)
    else:
        pkg_dir = Path(__file__).resolve().parent.parent
        load_dotenv(pkg_dir / ".env")
        load_dotenv()  # also check cwd

    return Config(
        db_host=os.getenv("DB_HOST", "localhost"),
        db_port=int(os.getenv("DB_PORT", "5432")),
        db_name=os.getenv("DB_NAME", "passive_asset_intel"),
        db_user=os.getenv("DB_USER", "postgres"),
        db_password=os.getenv("DB_PASSWORD", ""),
        db_pool_min=int(os.getenv("DB_POOL_MIN", "2")),
        db_pool_max=int(os.getenv("DB_POOL_MAX", "10")),
        batch_size=int(os.getenv("BATCH_SIZE", "500")),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        zeek_log_dir=os.getenv("ZEEK_LOG_DIR", "/logs"),
        scan_mode=os.getenv("SCAN_MODE", "file").lower(),
        zeek_interface=os.getenv("ZEEK_INTERFACE", ""),
        local_subnets=os.getenv(
            "LOCAL_SUBNETS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
        ),
        jwt_secret_key=os.getenv("JWT_SECRET_KEY", ""),
        log_retention_days=int(os.getenv("LOG_RETENTION_DAYS", "7")),
        max_ingest_queue_size=int(os.getenv("MAX_INGEST_QUEUE_SIZE", "1000")),
        api_cors_origins=os.getenv(
            "API_CORS_ORIGINS",
            "http://localhost:8080,http://127.0.0.1:8080,http://localhost:5173,http://127.0.0.1:5173",
        ),
    )
