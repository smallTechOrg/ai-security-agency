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
    openai_model: str = "gpt-4.1-mini"
    gemini_model: str = "gemini-2.5-flash"
    cors_origins: str = "http://127.0.0.1:5173,http://localhost:5173"
    default_budget_usd: float = 2.0
    model_config = SettingsConfigDict(env_file=(ROOT/'.env', ROOT/'backend/.env', '.env'), extra='ignore')
    @property
    def openai_key_present(self) -> bool: return bool((self.agent_openai_api_key or self.openai_api_key).strip())
    @property
    def gemini_key_present(self) -> bool: return bool((self.agent_gemini_api_key or self.gemini_api_key).strip())
settings = Settings()
