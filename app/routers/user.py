from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext # type: ignore

from app.models.models import User as UserModel
from app.core.dependencies import DBDep, AuthDep
from jose import jwt
from app.core.config import get_settings

settings = get_settings()


router = APIRouter()

# Pydantic Models
class UserResponse(BaseModel):
    user_id: int
    email: str
    username: str
    is_admin: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class CreateUserRequest(BaseModel):
    email: str
    username: str
    password: str
    is_admin: Optional[bool] = False


class UpdateUserRequest(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    is_admin: Optional[bool] = None


# Endpoint: Get current user
@router.get("/me", response_model=UserResponse)
def get_current_user(
    current_user_id: AuthDep,
    db: Session = DBDep
):
    user = db.query(UserModel).filter_by(user_id=current_user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# Endpoint: Get all users (admin only)
@router.get("/", response_model=List[UserResponse])
def get_users(
    db: Session = DBDep
):
    users = db.query(UserModel).all()
    return users


# Endpoint: Get user by ID
@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = DBDep
):
    user = db.query(UserModel).filter_by(user_id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# Endpoint: Create a new user
@router.post("/", response_model=UserResponse)
def create_user(
    user_req: CreateUserRequest,
    db: Session = DBDep
):
    # Check if email or username already exists
    if db.query(UserModel).filter((UserModel.email == user_req.email) | (UserModel.username == user_req.username)).first():
        raise HTTPException(status_code=400, detail="Email or username already exists")

    new_user = UserModel(
        email=user_req.email,
        username=user_req.username,
        password=user_req.password,  # Assume the password is hashed before being passed here
        is_admin=user_req.is_admin,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


# Endpoint: Update user
@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_req: UpdateUserRequest,
    db: Session = DBDep
):
    db_user = db.query(UserModel).filter(UserModel.user_id == user_id).first()  # Utilisez 'user_id' ici

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Vérifier si le username est modifié
    if user_req.username and user_req.username != db_user.username:
        # Vérifier si le nouveau username existe déjà
        existing_user = db.query(UserModel).filter(UserModel.username == user_req.username).first()  # Correction ici
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")

    # Mettre à jour les champs modifiés
    for key, value in user_req.dict(exclude_unset=True).items():  # Utilisez 'user_req' ici
        setattr(db_user, key, value)

    db.commit()
    db.refresh(db_user)
    return db_user


# Endpoint: Delete user
@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = DBDep
):
    user = db.query(UserModel).filter_by(user_id=user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return {"message": f"User with ID {user_id} deleted successfully"}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user_from_email(email: str, db: Session = DBDep):
    """ Récupérer un utilisateur à partir de son email """
    return db.query(UserModel).filter(UserModel.email == email).first()

def register(new_user: UserResponse, db: Session = DBDep):
    """ Enregistrer un nouvel utilisateur en base de données """
    # Vérifier si l'email existe déjà
    if get_user_from_email(new_user.email, db):
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hacher le mot de passe s'il y en a un (dans ton cas, Google ne fournit pas de mot de passe)
    if new_user.password:
        new_user.password = pwd_context.hash(new_user.password)
    
    new_user.created_at = datetime.utcnow()
    new_user.updated_at = datetime.utcnow()

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + timedelta(minutes=int(settings.JWT_EXPIRATION))
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.API_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt