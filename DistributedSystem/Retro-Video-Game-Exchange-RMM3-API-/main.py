import os
import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from starlette.datastructures import URL
from contextlib import asynccontextmanager


# ------------------------------------------------------------
# Config
# ------------------------------------------------------------
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "").strip()
MONGO_DB = os.getenv("MONGO_DB", "RetroVideoGameExchange")
MONGO_USERS = os.getenv("MONGO_USERS", "Users")
MONGO_GAMES = os.getenv("MONGO_GAMES", "Games")

JWT_SECRET = os.getenv("JWT_SECRET", "change-me").strip()
JWT_ALG = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "120"))

if not MONGO_URI:
    raise RuntimeError("Missing MONGO_URI. Put it in your .env file.")


# ------------------------------------------------------------
# MongoDB connection
# ------------------------------------------------------------
client = MongoClient(MONGO_URI, server_api=ServerApi("1"))
db = client[MONGO_DB]
users_col = db[MONGO_USERS]
games_col = db[MONGO_GAMES]


# ------------------------------------------------------------
# FastAPI app
# ------------------------------------------------------------
async def lifespan(app: FastAPI):
    # Startup
    client.admin.command("ping")
    users_col.create_index([("email", ASCENDING)], unique=True)
    games_col.create_index([("owner_id", ASCENDING)])
    games_col.create_index([("name", ASCENDING)])
    games_col.create_index([("publisher", ASCENDING)])
    games_col.create_index([("system", ASCENDING)])
    yield
    # Shutdown (optional)
    client.close()
    
    
app = FastAPI(
    title="Retro Video Game Exchange API",
    version="1.0.0",
    description="Users register and list retro games for trade. Trades happen outside the API.",
    lifespan=lifespan
)


# ------------------------------------------------------------
# Password hashing + JWT auth
# ------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2PasswordBearer tells FastAPI to expect: Authorization: Bearer <token>
# tokenUrl points at the route that issues tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(user_id: str, email: str) -> str:
    exp = now_utc() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": user_id, "email": email, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def parse_object_id(id_str: str) -> ObjectId:
    try:
        return ObjectId(str(id_str))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id format (expected Mongo ObjectId).")


# ------------------------------------------------------------
# Error handling: always return JSON error bodies
# ------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"status": exc.status_code, "message": exc.detail}},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": {"status": 422, "message": "Validation error", "details": exc.errors()}},
    )



# ------------------------------------------------------------
# HATEOAS helpers (IMPORTANT: generated at request-time)
# ------------------------------------------------------------
def link(href: str, method: str = "GET") -> dict[str, str]:
    return {"href": href, "method": method}


def url_for(request: Request, route_name: str, **params) -> str:
    # request.url_for expects any path params as strings
    str_params = {k: str(v) for k, v in params.items()}
    return str(request.url_for(route_name, **str_params))


def url_with_query(request: Request, route_name: str, query: dict[str, Any], **params) -> str:
    base = url_for(request, route_name, **params)
    return str(URL(base).include_query_params(**{k: v for k, v in query.items() if v is not None}))


def user_public_links(request: Request, user_id: str) -> dict[str, Any]:
    return {
        "self": link(url_for(request, "get_user_public", user_id=user_id), "GET"),
        "games": link(url_for(request, "get_games_for_user", user_id=user_id), "GET"),
    }


def user_me_links(request: Request) -> dict[str, Any]:
    return {
        "self": link(url_for(request, "get_me"), "GET"),
        "update": link(url_for(request, "update_me"), "PATCH"),
        "replace": link(url_for(request, "replace_me"), "PUT"),
        "delete": link(url_for(request, "delete_me"), "DELETE"),
    }


def game_links(request: Request, game_id: str, owner_id: str, can_edit: bool) -> dict[str, Any]:
    links: dict[str, Any] = {
        "self": link(url_for(request, "get_game", game_id=game_id), "GET"),
        "collection": link(url_for(request, "search_games"), "GET"),
        "owner": link(url_for(request, "get_user_public", user_id=owner_id), "GET"),
        "owners_games": link(url_for(request, "get_games_for_user", user_id=owner_id), "GET"),
    }
    if can_edit:
        links["update"] = link(url_for(request, "update_game", game_id=game_id), "PATCH")
        links["replace"] = link(url_for(request, "replace_game", game_id=game_id), "PUT")
        links["delete"] = link(url_for(request, "delete_game", game_id=game_id), "DELETE")
    return links


# ------------------------------------------------------------
# Pydantic models (schemas)
# ------------------------------------------------------------
class Condition(str, Enum):
    mint = "mint"
    good = "good"
    fair = "fair"
    poor = "poor"


class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)
    street_address: str = Field(min_length=1, max_length=200)


class UserUpdate(BaseModel):
    # PATCH: optional fields
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    street_address: Optional[str] = Field(default=None, min_length=1, max_length=200)


class UserReplace(BaseModel):
    # PUT: required fields (email cannot be changed)
    name: str = Field(min_length=1, max_length=120)
    street_address: str = Field(min_length=1, max_length=200)


class UserPublicOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    _links: dict[str, Any]


class UserMeOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    street_address: str
    _links: dict[str, Any]


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    _links: dict[str, Any]


class GameCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    publisher: str = Field(min_length=1, max_length=200)
    year_published: int = Field(ge=1950, le=2100)
    system: str = Field(min_length=1, max_length=120)
    condition: Condition
    previous_owners: Optional[int] = Field(default=None, ge=0, le=50)


class GameUpdate(BaseModel):
    # PATCH: optional fields
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    publisher: Optional[str] = Field(default=None, min_length=1, max_length=200)
    year_published: Optional[int] = Field(default=None, ge=1950, le=2100)
    system: Optional[str] = Field(default=None, min_length=1, max_length=120)
    condition: Optional[Condition] = None
    previous_owners: Optional[int] = Field(default=None, ge=0, le=50)


class GameOut(BaseModel):
    id: str
    owner_id: str
    name: str
    publisher: str
    year_published: int
    system: str
    condition: Condition
    previous_owners: Optional[int]
    _links: dict[str, Any]


class GameListOut(BaseModel):
    items: list[GameOut]
    count: int
    _links: dict[str, Any]


# ------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------
def get_user_by_email(email: str) -> Optional[dict[str, Any]]:
    return users_col.find_one({"email": email})


def get_user_by_id(user_id: str) -> Optional[dict[str, Any]]:
    return users_col.find_one({"_id": parse_object_id(user_id)})


def require_auth(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    """
    Extra credit rule:
    - Anyone can register
    - Everything else requires authentication
    This dependency enforces that.
    """
    cred_error = HTTPException(status_code=401, detail="Invalid or expired token.")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: str = payload.get("sub")  # we store user id here
        if not user_id:
            raise cred_error
    except JWTError:
        raise cred_error

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found for token.")
    return user


# ------------------------------------------------------------
# Root (API entrypoint with HATEOAS)
# ------------------------------------------------------------
@app.get("/", name="api_root")
def api_root(request: Request):
    return {
        "name": "Retro Video Game Exchange API",
        "_links": {
            "register": link(url_for(request, "register_user"), "POST"),
            "login": link(url_for(request, "auth_token"), "POST"),
            "docs": link(url_for(request, "swagger_docs"), "GET"),
            "openapi": link(url_for(request, "openapi_json"), "GET"),
        },
    }


# These names are built into FastAPI; we expose them through url_for above.
@app.get("/docs", include_in_schema=False, name="swagger_docs")
def swagger_docs_redirect():
    # FastAPI already serves swagger at /docs automatically, this keeps url_for stable
    raise HTTPException(status_code=307, detail="Go to /docs")


@app.get("/openapi.json", include_in_schema=False, name="openapi_json")
def openapi_json_redirect():
    raise HTTPException(status_code=307, detail="Go to /openapi.json")


# ------------------------------------------------------------
# Auth endpoints
# ------------------------------------------------------------
@app.post("/auth/token", response_model=TokenOut, name="auth_token")
def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 password flow:
    - form_data.username = user's email
    - form_data.password = password
    """
    email = form_data.username.lower().strip()
    user = get_user_by_email(email)

    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    token = create_access_token(user_id=str(user["_id"]), email=user["email"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "_links": {
            "me": link(url_for(request, "get_me"), "GET"),
            "games": link(url_for(request, "search_games"), "GET"),
            "create_game": link(url_for(request, "create_game"), "POST"),
        },
    }


# ------------------------------------------------------------
# Users
# ------------------------------------------------------------
@app.post("/users", status_code=201, response_model=UserMeOut, name="register_user")
def register_user(payload: UserCreate, request: Request, response: Response):
    """
    Public: anyone can register.
    """
    email = payload.email.lower().strip()

    doc = {
        "name": payload.name.strip(),
        "email": email,
        "password_hash": hash_password(payload.password),
        "street_address": payload.street_address.strip(),
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }

    try:
        result = users_col.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="That email is already registered.")

    user_id = str(result.inserted_id)
    response.headers["Location"] = url_for(request, "get_user_public", user_id=user_id)

    return {
        "id": user_id,
        "name": doc["name"],
        "email": doc["email"],
        "street_address": doc["street_address"],
        "_links": {**user_public_links(request, user_id), **user_me_links(request)},
    }


@app.get("/users/me", response_model=UserMeOut, name="get_me")
def get_me(request: Request, current_user: dict[str, Any] = Depends(require_auth)):
    user_id = str(current_user["_id"])
    return {
        "id": user_id,
        "name": current_user["name"],
        "email": current_user["email"],
        "street_address": current_user["street_address"],
        "_links": {**user_public_links(request, user_id), **user_me_links(request)},
    }


@app.patch("/users/me", status_code=204, name="update_me")
def update_me(payload: UserUpdate, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    """
    Only authenticated user can change their own info.
    Email cannot be changed because it's not in the schema.
    """
    update_doc: dict[str, Any] = {}
    if payload.name is not None:
        update_doc["name"] = payload.name.strip()
    if payload.street_address is not None:
        update_doc["street_address"] = payload.street_address.strip()

    if not update_doc:
        raise HTTPException(status_code=400, detail="No updatable fields provided.")

    update_doc["updated_at"] = now_utc()
    users_col.update_one({"_id": current_user["_id"]}, {"$set": update_doc})

    response.headers["Location"] = url_for(request, "get_me")
    return Response(status_code=204)


@app.put("/users/me", status_code=204, name="replace_me")
def replace_me(payload: UserReplace, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    """
    PUT is a full replacement (of allowed fields only).
    """
    update_doc = {
        "name": payload.name.strip(),
        "street_address": payload.street_address.strip(),
        "updated_at": now_utc(),
    }
    users_col.update_one({"_id": current_user["_id"]}, {"$set": update_doc})

    response.headers["Location"] = url_for(request, "get_me")
    return Response(status_code=204)


@app.delete("/users/me", status_code=204, name="delete_me")
def delete_me(request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    """
    Deletes the user AND all their games (simple cascade).
    """
    games_col.delete_many({"owner_id": current_user["_id"]})
    users_col.delete_one({"_id": current_user["_id"]})

    response.headers["Location"] = url_for(request, "api_root")
    return Response(status_code=204)


@app.get("/users/{user_id}", response_model=UserPublicOut, name="get_user_public")
def get_user_public(user_id: str, request: Request, current_user: dict[str, Any] = Depends(require_auth)):
    """
    Auth required. Shows public info.
    """
    u = get_user_by_id(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found.")

    uid = str(u["_id"])
    return {
        "id": uid,
        "name": u["name"],
        "email": u["email"],
        "_links": user_public_links(request, uid),
    }


@app.get("/users/{user_id}/games", response_model=GameListOut, name="get_games_for_user")
def get_games_for_user(
    user_id: str,
    request: Request,
    limit: int = 20,
    skip: int = 0,
    current_user: dict[str, Any] = Depends(require_auth),
):
    owner_oid = parse_object_id(user_id)
    query = {"owner_id": owner_oid}

    cursor = games_col.find(query).skip(skip).limit(limit)

    items: list[dict[str, Any]] = []
    for g in cursor:
        gid = str(g["_id"])
        owner_id_str = str(g["owner_id"])
        can_edit = g["owner_id"] == current_user["_id"]

        items.append(
            {
                "id": gid,
                "owner_id": owner_id_str,
                "name": g["name"],
                "publisher": g["publisher"],
                "year_published": g["year_published"],
                "system": g["system"],
                "condition": g["condition"],
                "previous_owners": g.get("previous_owners"),
                "_links": game_links(request, gid, owner_id_str, can_edit),
            }
        )

    count = games_col.count_documents(query)

    return {
        "items": items,
        "count": count,
        "_links": {
            "self": link(
                url_with_query(request, "get_games_for_user", {"skip": skip, "limit": limit}, user_id=user_id),
                "GET",
            ),
            "owner": link(url_for(request, "get_user_public", user_id=user_id), "GET"),
        },
    }


# ------------------------------------------------------------
# Games
# ------------------------------------------------------------
@app.post("/games", status_code=201, response_model=GameOut, name="create_game")
def create_game(payload: GameCreate, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    doc = {
        "owner_id": current_user["_id"],
        "name": payload.name.strip(),
        "publisher": payload.publisher.strip(),
        "year_published": payload.year_published,
        "system": payload.system.strip(),
        "condition": payload.condition.value,
        "previous_owners": payload.previous_owners,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }

    result = games_col.insert_one(doc)
    game_id = str(result.inserted_id)

    response.headers["Location"] = url_for(request, "get_game", game_id=game_id)

    owner_id_str = str(current_user["_id"])
    return {
        "id": game_id,
        "owner_id": owner_id_str,
        "name": doc["name"],
        "publisher": doc["publisher"],
        "year_published": doc["year_published"],
        "system": doc["system"],
        "condition": doc["condition"],
        "previous_owners": doc.get("previous_owners"),
        "_links": game_links(request, game_id, owner_id_str, can_edit=True),
    }


@app.get("/games/{game_id}", response_model=GameOut, name="get_game")
def get_game(game_id: str, request: Request, current_user: dict[str, Any] = Depends(require_auth)):
    g = games_col.find_one({"_id": parse_object_id(game_id)})
    if not g:
        raise HTTPException(status_code=404, detail="Game not found.")

    owner_id_str = str(g["owner_id"])
    can_edit = g["owner_id"] == current_user["_id"]

    return {
        "id": str(g["_id"]),
        "owner_id": owner_id_str,
        "name": g["name"],
        "publisher": g["publisher"],
        "year_published": g["year_published"],
        "system": g["system"],
        "condition": g["condition"],
        "previous_owners": g.get("previous_owners"),
        "_links": game_links(request, str(g["_id"]), owner_id_str, can_edit),
    }


@app.get("/games", response_model=GameListOut, name="search_games")
def search_games(
    request: Request,
    q: Optional[str] = None,
    name: Optional[str] = None,
    publisher: Optional[str] = None,
    system: Optional[str] = None,
    year_published: Optional[int] = None,
    condition: Optional[Condition] = None,
    owner_id: Optional[str] = None,
    limit: int = 20,
    skip: int = 0,
    current_user: dict[str, Any] = Depends(require_auth),
):
    """
    Any authenticated user can search games.
    """
    query: dict[str, Any] = {}

    # q searches name OR publisher (partial, case-insensitive)
    if q:
        regex = re.compile(re.escape(q), re.IGNORECASE)
        query["$or"] = [{"name": regex}, {"publisher": regex}]

    if name:
        query["name"] = re.compile(re.escape(name), re.IGNORECASE)
    if publisher:
        query["publisher"] = re.compile(re.escape(publisher), re.IGNORECASE)
    if system:
        query["system"] = re.compile(rf"^{re.escape(system)}$", re.IGNORECASE)
    if year_published is not None:
        query["year_published"] = year_published
    if condition is not None:
        query["condition"] = condition.value
    if owner_id:
        query["owner_id"] = parse_object_id(owner_id)

    cursor = games_col.find(query).skip(skip).limit(limit)

    items: list[dict[str, Any]] = []
    for g in cursor:
        gid = str(g["_id"])
        owner_id_str = str(g["owner_id"])
        can_edit = g["owner_id"] == current_user["_id"]

        items.append(
            {
                "id": gid,
                "owner_id": owner_id_str,
                "name": g["name"],
                "publisher": g["publisher"],
                "year_published": g["year_published"],
                "system": g["system"],
                "condition": g["condition"],
                "previous_owners": g.get("previous_owners"),
                "_links": game_links(request, gid, owner_id_str, can_edit),
            }
        )

    count = games_col.count_documents(query)

    # Self link includes current filters for HATEOAS-friendly pagination
    self_href = url_with_query(
        request,
        "search_games",
        {
            "q": q,
            "name": name,
            "publisher": publisher,
            "system": system,
            "year_published": year_published,
            "condition": condition.value if condition else None,
            "owner_id": owner_id,
            "skip": skip,
            "limit": limit,
        },
    )

    return {
        "items": items,
        "count": count,
        "_links": {
            "self": link(self_href, "GET"),
            "create": link(url_for(request, "create_game"), "POST"),
        },
    }


def require_game_owner(game_id: str, current_user: dict[str, Any]) -> dict[str, Any]:
    g = games_col.find_one({"_id": parse_object_id(game_id)})
    if not g:
        raise HTTPException(status_code=404, detail="Game not found.")
    if g["owner_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="Only the owner can modify this game.")
    return g


@app.patch("/games/{game_id}", status_code=204, name="update_game")
def update_game(game_id: str, payload: GameUpdate, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    require_game_owner(game_id, current_user)

    update_doc: dict[str, Any] = {}
    for field in ["name", "publisher", "year_published", "system", "previous_owners"]:
        val = getattr(payload, field)
        if val is not None:
            update_doc[field] = val.strip() if isinstance(val, str) else val

    if payload.condition is not None:
        update_doc["condition"] = payload.condition.value

    if not update_doc:
        raise HTTPException(status_code=400, detail="No updatable fields provided.")

    update_doc["updated_at"] = now_utc()
    games_col.update_one({"_id": parse_object_id(game_id)}, {"$set": update_doc})

    response.headers["Location"] = url_for(request, "get_game", game_id=game_id)
    return Response(status_code=204)


@app.put("/games/{game_id}", status_code=204, name="replace_game")
def replace_game(game_id: str, payload: GameCreate, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    g = require_game_owner(game_id, current_user)

    update_doc = {
        "name": payload.name.strip(),
        "publisher": payload.publisher.strip(),
        "year_published": payload.year_published,
        "system": payload.system.strip(),
        "condition": payload.condition.value,
        "previous_owners": payload.previous_owners,
        "updated_at": now_utc(),
    }
    games_col.update_one({"_id": g["_id"]}, {"$set": update_doc})

    response.headers["Location"] = url_for(request, "get_game", game_id=game_id)
    return Response(status_code=204)


@app.delete("/games/{game_id}", status_code=204, name="delete_game")
def delete_game(game_id: str, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    require_game_owner(game_id, current_user)

    games_col.delete_one({"_id": parse_object_id(game_id)})

    response.headers["Location"] = url_for(request, "search_games")
    return Response(status_code=204)

# This document was made in help from ChatGPT