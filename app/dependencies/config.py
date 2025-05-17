import os

from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

def check_sslcerts(cert_path, pem_path) -> list:
    basepath = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    certpath = os.path.join(basepath, cert_path)
    privpath = os.path.join(basepath, pem_path)

    if os.path.exists(certpath) and os.path.exists(privpath):
        return certpath, privpath   
    else:
        return None, None

class GatewayConfig(BaseModel):
    """
        Default for API Host Configuration
    """
    APP_HOST: str = Field(default_factory=lambda: os.getenv("gateway_host", "localhost"))
    APP_PORT: int = Field(default_factory=lambda: int(os.getenv("gateway_port", 8000)))
    APP_DEBUG: bool = Field(default_factory=lambda: str(os.getenv("gateway_debug", "false")).lower() == "true")
    APP_SSLCERT: str = Field(default_factory=lambda: os.getenv("SSL_CERT_PATH"))
    APP_SSLPEM: str = Field(default_factory=lambda: os.getenv("SSL_PEM_PATH"))

    API_NAME: str = Field(default_factory=lambda: os.getenv("API_NAME"))
    API_DEFAULT_ADDRESS_PATH: str = Field(default_factory=lambda: os.getenv("API_DEFAULT_ADDRESS_PATH"))
    API_DESC: str = "" # Load from .ini / .txt
    API_VER: str = Field(default_factory=lambda: os.getenv("API_VERSION"))
    API_ALGORITHM: str = Field(default_factory=lambda: os.getenv("API_ALGORITHM"))
    API_SECRETKEY: str = Field(default_factory=lambda: os.getenv("API_SECRETKEY"))
    API_REFRESHKEY: str = Field(default_factory=lambda: os.getenv("API_REFRESHKEY"))
    API_CSRFKEY: str = Field(default_factory=lambda: os.getenv("API_CSRFKEY"))

    API_EXPIRED_TOKEN_MINUTES: int = Field(default_factory=lambda: os.getenv("EXPIRED_TOKEN_MINUES", 15))
    API_EXPIRED_REFRESH_DAYS: int = Field(default_factory=lambda: os.getenv("EXPIRED_REFRESH_DAYS", 15))
    API_EXPIRED_CSRF_DAYS: int = Field(default_factory=lambda: os.getenv("EXPIRED_CSRF_HOURS"))

    API_ENABLE_DOCS: bool = Field(default_factory=lambda: str(os.getenv("enable_docs", "false")).lower() == "true")



class DatabaseConfig(GatewayConfig):
    DB_HOSTNAME: str = Field(default_factory=lambda: os.getenv("db_hostname", "localhost"))
    DB_PORT: int = Field(default_factory=lambda: os.getenv("db_portnumber", "27017"))
    DB_NAME: str = Field(default_factory=lambda: os.getenv("db_name"))
    