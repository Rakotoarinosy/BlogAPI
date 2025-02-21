from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    GOOGLE_REDIRECT_URI : str
    DB_USER: str
    DB_PASSWORD: str
    DB_HOST: str
    DB_PORT: int
    DB_NAME: str
    API_KEY: str
    JWT_SECRET: str
    JWT_ALGORITHM: str
    JWT_EXPIRATION: str

    class Config:
        env_file = ".env"

def get_settings() -> Settings:
    return Settings()