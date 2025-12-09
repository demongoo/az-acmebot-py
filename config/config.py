from pydantic import Field
from pydantic_settings import BaseSettings

# Configuration settings for the application
class Settings(BaseSettings):
    username: str
    password: str

    azure_credential: str = Field(default='default')

    azure_keyvault_url: str

    renewal_days_before_expiry: int = Field(default=10)

    cert_pfx_password: str | None = Field(default=None)

    process_interval: int = Field(default=12*60)  # interval in minutes for processing
    process_first_run_delay: int = Field(default=0)  # delay in minutes before first run

    log_level: str = Field(default="INFO")

    class Config:
        env_file = None  # Disable .env file loading
        case_sensitive = False


settings = Settings()
