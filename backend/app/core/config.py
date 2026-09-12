"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application settings.

    All values are sourced from environment variables (or a local .env file
    in development). Nothing sensitive is hardcoded here.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = Field(default="amnix")
    environment: str = Field(default="development")
    debug: bool = Field(default=False)

    # PostgreSQL
    postgres_user: str = Field(default="postgres")
    postgres_password: str = Field(default="")
    postgres_host: str = Field(default="localhost")
    postgres_port: int = Field(default=5432)
    postgres_db: str = Field(default="amnix")

    # Redis
    redis_host: str = Field(default="localhost")
    redis_port: int = Field(default=6379)
    redis_password: str = Field(default="")
    redis_db: int = Field(default=0)

    # Detection engine
    brute_force_threshold: int = Field(default=5)
    brute_force_window_seconds: int = Field(default=300)

    # AI Copilot. "mock" requires no credentials and makes no network
    # calls — see app.ai.factory. Real provider credentials, when a real
    # provider is added, belong here as env-var-only fields, never as
    # literal values in code or in a committed .env file.
    ai_provider: str = Field(default="mock")

    # Anthropic provider (only read when AI_PROVIDER=anthropic — see
    # app.ai.factory and app.ai.providers.anthropic). Left empty by
    # default so the "mock" default provider never requires this to be
    # set; app.ai.factory fails fast with a clear error if AI_PROVIDER is
    # "anthropic" and this is empty, rather than silently falling back
    # to mock.
    anthropic_api_key: str = Field(default="")
    anthropic_model: str = Field(default="claude-sonnet-5")
    anthropic_max_tokens: int = Field(default=1024)
    anthropic_timeout_seconds: float = Field(default=30.0)

    # Authentication (Step 11D). Left empty by default so an
    # unconfigured environment fails fast and loudly the first time a
    # token is issued/validated (see app.core.tokens) rather than
    # signing with an empty or predictable key — the same "fail fast on
    # missing config" discipline app.ai.factory already applies to
    # ANTHROPIC_API_KEY.
    jwt_secret_key: str = Field(default="")
    jwt_access_token_expire_minutes: int = Field(default=15)
    jwt_issuer: str = Field(default="amnix")
    jwt_audience: str = Field(default="amnix-api")
    refresh_token_expire_days: int = Field(default=7)

    # Login rate limiting (Step 11H). Redis-backed, fixed-window, applied
    # only to POST /auth/login — see app.api.dependencies.
    # enforce_login_rate_limit for why this endpoint specifically. A
    # generous default (10 attempts/60s per client IP): blunt enough to
    # stop scripted credential stuffing/brute force without punishing a
    # real analyst who mistypes a password a few times.
    login_rate_limit_max_attempts: int = Field(default=10)
    login_rate_limit_window_seconds: int = Field(default=60)

    # Request body size protection (Step 11I). Applies globally, at the
    # ASGI layer, before Pydantic ever sees a request body — see
    # app.middleware.request_size_limit. 1 MiB was chosen from measured
    # worst-case legitimate payloads: the largest bounded-by-schema
    # request AMNIX accepts (POST /alerts, with every optional field at
    # its schema maximum) is ~370 KB; 1 MiB leaves roughly 2.8x headroom
    # above that without being large enough to make the memory/CPU-
    # exhaustion risk this control exists for meaningful again. See the
    # Step 11I final report for the full measurement.
    max_request_body_bytes: int = Field(default=1_048_576)

    # HTTP security boundary (Step 11L). Both are comma-separated lists,
    # matching this Settings class's existing style for scalar
    # env-var-sourced config (no list-typed field exists elsewhere in
    # this project to mirror; a comma-separated string parsed by a
    # small property is the simplest representation that fits pydantic-
    # settings' plain-env-var loading without introducing a new parsing
    # convention). Both reject a literal "*" outright (see the
    # validators below) — an operator who copies the common CORS "allow
    # everything" habit into either setting gets a loud startup failure,
    # never a silently permissive app. See app.main for how each is
    # actually wired into CORSMiddleware / TrustedHostMiddleware, and
    # the Step 11L final report for the full design rationale.
    #
    # cors_allowed_origins: empty by default. AMNIX has no frontend
    # implementation anywhere in this repository (verified during Step
    # 11L discovery — grepped for any concrete frontend dev-server
    # origin; none exists, only an aspirational one-line mention in a
    # pre-implementation planning doc) — inventing one here would be
    # exactly the guessed production origin the brief prohibits. A real
    # deployment (or a future frontend's local dev setup) must set this
    # explicitly once a real origin exists; until then, no cross-origin
    # browser request is permitted at all, which is the safe default.
    cors_allowed_origins: str = Field(default="")

    # trusted_hosts: defaults to exactly the three Host values verified
    # to be genuinely necessary for this repository to keep working —
    # "localhost"/"127.0.0.1" for interactive local development, and
    # "testserver" because Starlette's own TestClient sends that exact
    # Host header by default (empirically verified, not guessed — see
    # the Step 11L final report) and this project's ~1100-test suite
    # exercises the real app.main:app instance directly. This default is
    # still safe for a real deployment that forgets to override it: none
    # of these three values matches a real production Host header, so
    # TrustedHostMiddleware would correctly reject real traffic by
    # default until an operator explicitly configures their actual
    # domain(s) — fail-closed, not fail-open, for anything other than
    # local dev/test.
    trusted_hosts: str = Field(default="localhost,127.0.0.1,testserver")

    @field_validator("cors_allowed_origins")
    @classmethod
    def _reject_wildcard_cors_origin(cls, v: str) -> str:
        if "*" in v:
            raise ValueError(
                "CORS_ALLOWED_ORIGINS must not contain '*' -- list explicit origins, comma-separated."
            )
        return v

    @field_validator("trusted_hosts")
    @classmethod
    def _reject_wildcard_trusted_host(cls, v: str) -> str:
        if "*" in v:
            raise ValueError("TRUSTED_HOSTS must not contain '*' -- list explicit hostnames, comma-separated.")
        return v

    @property
    def cors_allowed_origins_list(self) -> list[str]:
        """Parsed, whitespace-trimmed, empty-entry-free list. Never
        contains "*" — enforced at field-validation time above, not
        re-checked here, so this property can never silently produce a
        wildcard even if the raw string were somehow malformed.
        """
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

    @property
    def trusted_hosts_list(self) -> list[str]:
        """Parsed, whitespace-trimmed, empty-entry-free list. Same
        wildcard guarantee as cors_allowed_origins_list above.
        """
        return [host.strip() for host in self.trusted_hosts.split(",") if host.strip()]

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
