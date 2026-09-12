"""Settings, one source of truth, driven by the environment.

Everything an operator might need to change at deploy time lives here and nowhere
else. Defaults are the ones you would actually want in production, not the ones
that make a demo look good: detect mode rather than block, fail open rather than
closed.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="WAF_", env_file=".env", extra="ignore")

    # --- what we protect and where we listen ---------------------------------
    upstream: str = Field(
        default="http://localhost:3000",
        description="Origin the proxy forwards to.",
    )
    host: str = "0.0.0.0"
    port: int = 8080

    # --- enforcement ---------------------------------------------------------
    # detect is the default on purpose. A WAF is deployed by watching first and
    # enforcing later, and shipping something that blocks on first run is how you
    # get switched off permanently after one false positive.
    mode: str = Field(default="detect", pattern="^(detect|block)$")
    threshold: float | None = Field(
        default=None,
        description="Score at or above which a request is refused. "
        "Defaults to the value chosen against the FPR budget during training.",
    )

    # --- failure behaviour ---------------------------------------------------
    # A broken model must not become a site outage, so the default is to let the
    # request through and shout about it. Flip to "closed" if you would rather
    # drop traffic than serve it unscored.
    fail_mode: str = Field(default="open", pattern="^(open|closed)$")
    scoring_budget_ms: float = Field(
        default=180.0,
        description="Deadline for scoring. Past it the request is allowed and "
        "counted, so a slow model costs protection rather than availability. "
        "A request-level model scores in a few milliseconds; a unit-decomposition "
        "model scores every parameter value separately (~1.5ms each, capped at "
        "MAX_UNITS in units.py), so this has to cover that worst case rather than "
        "the typical one, or ordinary multi-field requests fail open silently.",
    )

    # --- limits --------------------------------------------------------------
    max_body_bytes: int = Field(
        default=1_048_576,
        description="Bodies larger than this are forwarded unscored. Buffering "
        "unbounded uploads is how a proxy becomes the outage it was meant to stop.",
    )
    upstream_timeout_s: float = 30.0
    cache_size: int = Field(default=4096, description="LRU entries for repeat requests.")

    # --- storage -------------------------------------------------------------
    db_path: str = "data/waf.db"
    retention_rows: int = Field(
        default=200_000,
        description="Oldest decisions are trimmed beyond this so the log cannot "
        "fill the disk on a long run.",
    )
    feedback_path: str = "data/feedback.jsonl"

    # --- model ---------------------------------------------------------------
    model_path: str = "models/model.joblib"

    # --- control plane access ------------------------------------------------
    # The console and its API share a port with the proxy, so anything that can
    # reach the protected site can also reach /_waf. Without a token, switching
    # the firewall off is a single unauthenticated POST, which is a much cheaper
    # attack than evading the model. Left unset, a token is generated at startup
    # and written to the log so a local demo still works.
    admin_token: str | None = None
    metrics_public: bool = Field(
        default=False,
        description="Serve /_waf/metrics without a token. Set this only when the "
        "port is reachable solely by your Prometheus scraper.",
    )

    @property
    def blocking(self) -> bool:
        return self.mode == "block"

    @property
    def fail_open(self) -> bool:
        return self.fail_mode == "open"


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Drop the cached settings. Tests use this after changing the environment."""
    global _settings
    _settings = None
