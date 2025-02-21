from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
# from starlette.requests import Request

import requests
from fastapi import APIRouter
from app.core.db import get_conn
from app.models.models import User
from app.routers.user import create_access_token, get_user_from_email, register

from app.core.config import get_settings

settings = get_settings()

GOOGLE_CLIENT_ID = settings.GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET = settings.GOOGLE_CLIENT_SECRET
GOOGLE_REDIRECT_URI = settings.GOOGLE_REDIRECT_URI

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://oauth2.googleapis.com/token"
)


routers = APIRouter()

@routers.get("/google")
def google_login():
    return {
        "login_url": f"https://accounts.google.com/o/oauth2/auth?client_id={GOOGLE_CLIENT_ID}&response_type=code&scope=email%20profile&redirect_uri={GOOGLE_REDIRECT_URI}"
    }

@routers.get("/callback")
def google_callback(code: str, session=Depends(get_conn)):
    # Échanger le code contre un token d'accès
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": GOOGLE_REDIRECT_URI,
    }
    response = requests.post(token_url, data=data)
    token_data = response.json()

    if "error" in token_data:
        raise HTTPException(status_code=400, detail="Invalid token exchange")

    # Récupérer les infos utilisateur depuis Google
    user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    user_info = requests.get(user_info_url, headers=headers).json()

    email = user_info["email"]
    first_name = user_info.get("given_name", "")
    last_name = user_info.get("family_name", "")

    # Vérifier si l'utilisateur existe en base
    user = get_user_from_email(email, session)
    if not user:
        username = f"{first_name} {last_name}".strip() if first_name or last_name else email.split("@")[0]
        new_user = User(username=username, email=email, password="")
        user = register(new_user, session)  # Enregistrer l'utilisateur si inexistant

    # Générer un token JWT pour l'utilisateur
    jwt_token = create_access_token({"sub": email})
    return {"access_token": jwt_token, "token_type": "bearer"}
