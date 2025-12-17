from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from app.db.database import SessionLocal
from app.models.user import User
from app.core.auth import create_access_token, verify_access_token
from typing import Annotated

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------- SCHEMAS ----------
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str

    class Config:
        from_attributes = True

# ---------- DB DEPENDENCY ----------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------- PASSWORD UTILS ----------
def hash_password(password: str):
    return pwd_context.hash(password)

# ---------- REGISTER USER (Public) ----------
@router.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = hash_password(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully", "user": {"id": new_user.id, "email": new_user.email}}

# ---------- LOGIN USER (Public) ----------
@router.post("/login")
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    access_token = create_access_token(data={"user_id": user.id})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {"id": user.id, "email": user.email, "username": user.username}
    }

# ---------- AUTH CONFIG ----------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user_id = verify_access_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# ---------- GET ALL USERS (Protected) ----------
@router.get("/users", response_model=list[UserResponse], tags=["Users"], dependencies=[Depends(oauth2_scheme)])
def get_all_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(User).all()


# ---------- GET USER BY ID (Protected) ----------
@router.get("/users/{user_id}", response_model=UserResponse, tags=["Users"], dependencies=[Depends(oauth2_scheme)])
def get_user_by_id(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# ---------- ME (Protected) ----------
@router.get("/me", tags=["Users"], dependencies=[Depends(oauth2_scheme)])
def get_my_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email
    }


# ----------------- User management helpers (append after get_my_profile) -----------------

class UserUpdate(BaseModel):
    username: str | None = None
    email: str | None = None

class PasswordChange(BaseModel):
    old_password: str
    new_password: str


@router.patch("/me", tags=["Users"])
def update_my_profile(
    payload: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update current user's username and/or email (partial update)."""
    changed = False

    if payload.username and payload.username != current_user.username:
        current_user.username = payload.username
        changed = True

    if payload.email and payload.email != current_user.email:
        # ensure email uniqueness
        existing = db.query(User).filter(User.email == payload.email).first()
        if existing and existing.id != current_user.id:
            raise HTTPException(status_code=400, detail="Email already in use")
        current_user.email = payload.email
        changed = True

    if changed:
        db.add(current_user)
        db.commit()
        db.refresh(current_user)

    return {
        "message": "Profile updated",
        "user": {"id": current_user.id, "username": current_user.username, "email": current_user.email},
    }
