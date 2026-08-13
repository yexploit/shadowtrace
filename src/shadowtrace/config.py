"""Application paths and tunable thresholds."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _find_project_root() -> Path:
    """Resolve project root whether package lives in ./shadowtrace or ./src/shadowtrace."""
    here = Path(__file__).resolve().parent
    for candidate in (here, *here.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    # Fallback: src/shadowtrace -> parents[1] == project root
    return here.parents[1]


ROOT = _find_project_root()
DATA_DIR = ROOT / "data"
SAMPLES_DIR = DATA_DIR / "samples"
DEFAULT_DB = DATA_DIR / "shadowtrace.db"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SHADOWTRACE_", extra="ignore")

    db_path: Path = DEFAULT_DB
    # Similarity thresholds (0–1)
    same_actor_threshold: float = 0.85
    probable_actor_threshold: float = 0.62
    # Clustering
    dbscan_eps: float = 0.18
    dbscan_min_samples: int = 2
    # Feature weights for composite similarity
    weight_temporal: float = 0.18
    weight_enumeration: float = 0.18
    weight_protocol: float = 0.16
    weight_username: float = 0.16
    weight_burst: float = 0.12
    weight_http_seq: float = 0.12
    weight_dns: float = 0.08
    api_host: str = "127.0.0.1"
    api_port: int = 8787
    # Real-time engine
    attr_interval_sec: float = 5.0
    flush_batch: int = 25
    default_bpf: str = "tcp or udp"
    udp_listen_host: str = "0.0.0.0"
    udp_listen_port: int = 9514


def get_settings() -> Settings:
    return Settings()


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
