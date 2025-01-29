from fastapi import FastAPI
from app.routers import auth, user, post, category

app = FastAPI(title="Blog API", version="1.0")

# # Inclure les routes
app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(category.router, prefix="/categories", tags=["Categories"])
app.include_router(user.router, prefix="/users", tags=["Users"])
app.include_router(post.router, prefix="/posts", tags=["Posts"])

# Route pour la racine
@app.get("/", tags=["General"])
def read_root():
    return {"message": "Welcome to BlogAPI"}
