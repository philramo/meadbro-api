"""Configuration management for MeadBro API."""

import os
import json
import logging
from typing import List, Optional
from pydantic import BaseModel


class DatabaseConfig(BaseModel):
    """Database configuration."""
    type: str = "sqlite"  # sqlite, postgresql, mysql
    path: str = "meadbro.db"  # For SQLite
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    database: Optional[str] = None


class RedisConfig(BaseModel):
    """Redis configuration."""
    enabled: bool = False
    url: str = "redis://localhost:6379"
    password: Optional[str] = None
    db: int = 0


class CorsConfig(BaseModel):
    """CORS configuration."""
    enabled: bool = True
    origins: List[str] = ["http://localhost:3000", "https://localhost:3000"]
    methods: List[str] = ["*"]
    headers: List[str] = ["*"]
    credentials: bool = True


class AuthConfig(BaseModel):
    """Authentication configuration."""
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # OAuth providers
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    
    # WebAuthn/Passkeys
    rp_id: str = "localhost"
    rp_name: str = "MeadBro"
    origin: str = "https://localhost:8443"


class ServerConfig(BaseModel):
    """Server configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False
    log_level: str = "INFO"
    
    # SSL
    ssl_enabled: bool = False
    ssl_keyfile: Optional[str] = None
    ssl_certfile: Optional[str] = None


class Config(BaseModel):
    """Main configuration."""
    database: DatabaseConfig = DatabaseConfig()
    redis: RedisConfig = RedisConfig()
    cors: CorsConfig = CorsConfig()
    auth: AuthConfig = AuthConfig()
    server: ServerConfig = ServerConfig()


def load_config(config_file: str = "config.json") -> Config:
    """Load configuration from file or environment variables."""
    config_data = {}
    
    # Load from file if exists
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config_data = json.load(f)
    
    # Override with environment variables
    env_overrides = {
        "database.path": os.getenv("DB_PATH"),
        "database.host": os.getenv("DB_HOST"),
        "database.username": os.getenv("DB_USER"),
        "database.password": os.getenv("DB_PASSWORD"),
        "database.database": os.getenv("DB_NAME"),
        
        "redis.enabled": os.getenv("REDIS_ENABLED", "").lower() == "true",
        "redis.url": os.getenv("REDIS_URL"),
        "redis.password": os.getenv("REDIS_PASSWORD"),
        
        "auth.secret_key": os.getenv("SECRET_KEY"),
        "auth.google_client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "auth.google_client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        
        "server.host": os.getenv("HOST"),
        "server.port": int(os.getenv("PORT", "0")) or None,
        "server.log_level": os.getenv("LOG_LEVEL"),
        
        "cors.origins": os.getenv("CORS_ORIGINS", "").split(",") if os.getenv("CORS_ORIGINS") else None,
    }
    
    # Apply environment overrides
    for key, value in env_overrides.items():
        if value is not None:
            keys = key.split(".")
            current = config_data
            for k in keys[:-1]:
                current = current.setdefault(k, {})
            current[keys[-1]] = value
    
    return Config(**config_data)


def create_default_config(config_file: str = "config.json"):
    """Create a default configuration file."""
    config = Config()
    with open(config_file, 'w') as f:
        json.dump(config.model_dump(), f, indent=2)
    print(f"Created default configuration file: {config_file}")


if __name__ == "__main__":
    # Create default config if run directly
    create_default_config()
