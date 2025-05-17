import jwt
import uuid

from datetime import datetime, timedelta
from typing import Optional, Dict
from jwt import ExpiredSignatureError, InvalidTokenError, InvalidSignatureError
from itsdangerous import URLSafeSerializer, BadSignature, SignatureExpired

from .config import GatewayConfig
from .header_handler import SecureOAuth2Bearer

secure = GatewayConfig()
oauth_schemes = SecureOAuth2Bearer(tokenUrl=secure.API_DEFAULT_ADDRESS_PATH)
csrf_serializer = URLSafeSerializer(secret_key=secure.API_SECRETKEY, salt=secure.API_CSRFKEY)

def _generate_token(
    payload: Dict[str, str],
    secret_key: str,
    algorithm: str,
    expires_delta: timedelta,
    subject: Optional[str] = None
) -> str:
    now = datetime.now()
    payload_to_encode = {
        **payload,
        "iat": now,
        "nbf": now,
        "exp": now + expires_delta,
        "jti": str(uuid.uuid4())  # Unique token ID
    }
    if subject:
        payload_to_encode["sub"] = subject  # Standard subject claim

    token = jwt.encode(payload=payload_to_encode, key=secret_key, algorithm=algorithm)
    return token


async def create_access_token(payload: Dict[str, str], subject: Optional[str] = None) -> str:
    return _generate_token(
        payload=payload,
        secret_key=secure.API_SECRETKEY,
        algorithm=secure.API_ALGORITHM,
        expires_delta=timedelta(minutes=secure.API_EXPIRED_TOKEN_MINUTES),
        subject=subject
    )


async def create_refresh_token(payload: Dict[str, str], subject: Optional[str] = None) -> str:
    return _generate_token(
        payload=payload,
        secret_key=secure.API_REFRESHKEY,
        algorithm=secure.API_ALGORITHM,
        expires_delta=timedelta(days=secure.API_EXPIRED_REFRESH_DAYS),
        subject=subject
    )

async def csrf_token_generator(session_id: str):
    return csrf_serializer.dumps(session_id)

async def verify_csrf_token(token: str, session_id: str):
    try:
        data = csrf_serializer.loads(token, max_age=secure.API_EXPIRED_CSRF_DAYS)
        return data == session_id
    except (BadSignature, SignatureExpired):
        return False
    

def _verify_token(token: str, secret_key: str, algorithm: str) -> Dict:
    try:
        payload = jwt.decode(token, key=secret_key, algorithms=[algorithm])
        return payload
    except ExpiredSignatureError:
        raise ValueError("Token has expired")
    except InvalidSignatureError:
        raise ValueError("Invalid token signature")
    except InvalidTokenError:
        raise ValueError("Invalid token")


def verify_access_token(token: str) -> Dict:
    return _verify_token(token, secret_key=secure.API_SECRETKEY, algorithm=secure.API_ALGORITHM)


def verify_refresh_token(token: str) -> Dict:
    return _verify_token(token, secret_key=secure.API_REFRESHKEY, algorithm=secure.API_ALGORITHM)