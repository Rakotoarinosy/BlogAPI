from typing import Union

from fastapi import FastAPI
from pydantic import BaseModel

from app.routers import categories_router, manage_router, auth_router, users_router

app = FastAPI()
app.include_router(manage_router.router)
app.include_router(auth_router.router)
app.include_router(users_router.router)
app.include_router(categories_router.router)


class Item(BaseModel):
    name: str
    price: float
    is_offer: Union[bool, None] = None

@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}


@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item):
    return {"item_name": item.name, "item_id": item_id}