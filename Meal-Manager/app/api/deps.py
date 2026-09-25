from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.security import decode_token
from app.models.models import User

bearer = HTTPBearer(auto_error=False)


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
                 db: Session = Depends(get_db)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = decode_token(credentials.credentials)
        uid = payload.get("sub")
        if not uid:
            raise ValueError("missing subject")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    user = db.scalar(select(User).where(User.id == str(uid), User.active.is_(True)))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user
