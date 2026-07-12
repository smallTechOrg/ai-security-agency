from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
ROOT = Path(__file__).resolve().parents[2]
class Settings(BaseSettings):
    environment: str = "local"
    database_url: str = "sqlite:///./data/app.db"
    app_secret_key: str = "change-me"
    agent_openai_api_key: str = ""
    openai_api_key: str = ""
    agent_gemini_api_key: str = ""
    gemini_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4.1-mini"
    gemini_model: str = "gemini-2.5-flash-lite"
    upi_id: str = ""  # UPI handle for QR payments, e.g. yourname@bank
    cors_origins: str = "http://127.0.0.1:5173,http://localhost:5173"
    default_budget_usd: float = 2.0
    browser_recon_enabled: bool = True
    browser_headless: bool = True
    browser_timeout_ms: int = 15000
    browser_max_network_events: int = 100
    browser_artifacts_dir: str = "data/artifacts"
    model_config = SettingsConfigDict(env_file=(ROOT/'.env', ROOT/'backend/.env', '.env'), extra='ignore')
    @property
    def openai_key_present(self) -> bool: return bool((self.agent_openai_api_key or self.openai_api_key).strip())
    @property
    def gemini_key_present(self) -> bool: return bool((self.agent_gemini_api_key or self.gemini_api_key).strip())
settings = Settings()
