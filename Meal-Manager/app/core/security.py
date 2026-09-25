from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
from app.core.config import settings

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return pwd.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd.verify(password, password_hash)
    except Exception:
        return False


def create_token(sub: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": str(sub), "iat": now, "exp": now + timedelta(minutes=settings.access_token_expire_minutes)},
        settings.secret_key, algorithm=ALGORITHM
    )


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
