import os
import re
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from bson import ObjectId
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from pymongo import ASCENDING, DESCENDING
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
MONGO_OFFERS = os.getenv("MONGO_OFFERS", "Offers")

JWT_SECRET = os.getenv("JWT_SECRET", "change-me").strip()
JWT_ALG = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "120"))

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")

if not MONGO_URI:
    raise RuntimeError("Missing MONGO_URI. Put it in your .env file.")

# ------------------------------------------------------------
# MongoDB connection
# ------------------------------------------------------------
client = MongoClient(MONGO_URI, server_api=ServerApi("1"))
db = client[MONGO_DB]
users_col = db[MONGO_USERS]
games_col = db[MONGO_GAMES]
offers_col = db[MONGO_OFFERS]

# ------------------------------------------------------------
# FastAPI lifespan (startup/shutdown)
# ------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    client.admin.command("ping")

    # Users
    users_col.create_index([("email", ASCENDING)], unique=True)

    # Games
    games_col.create_index([("owner_id", ASCENDING)])
    games_col.create_index([("name", ASCENDING)])
    games_col.create_index([("publisher", ASCENDING)])
    games_col.create_index([("system", ASCENDING)])

    # Offers
    offers_col.create_index([("to_user_id", ASCENDING), ("status", ASCENDING)])
    offers_col.create_index([("from_user_id", ASCENDING), ("status", ASCENDING)])
    offers_col.create_index([("created_at", DESCENDING)])
    offers_col.create_index([("requested_game_id", ASCENDING), ("status", ASCENDING)])
    offers_col.create_index([("offered_game_id", ASCENDING), ("status", ASCENDING)])


    yield

    # Shutdown
    client.close()

app = FastAPI(
    title="Retro Video Game Exchange API",
    version="1.1.0",
    description="Users register and list retro games for trade. Trades happen outside the API.",
    lifespan=lifespan,
)

# ------------------------------------------------------------
# Password hashing + JWT auth
# ------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
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
    
def inc_prev_owners(value: Optional[int]) -> int:
    return (value or 0) + 1

def supports_transactions() -> bool:
    # Best-effort check: if start_session exists, try transaction in runtime.
    return hasattr(client, "start_session")

def auto_reject_conflicting_offers(
    accepted_offer_oid: ObjectId,
    requested_game_oid: ObjectId,
    offered_game_oid: ObjectId,
    session=None,
) -> None:
    """
    Reject any other pending offers that involve either of the traded games.
    This prevents stale offers after a trade is completed.
    """
    q = {
        "status": OfferStatus.pending.value,
        "_id": {"$ne": accepted_offer_oid},
        "$or": [
            {"requested_game_id": {"$in": [requested_game_oid, offered_game_oid]}},
            {"offered_game_id": {"$in": [requested_game_oid, offered_game_oid]}},
        ],
    }

    update = {
        "$set": {
            "status": OfferStatus.rejected.value,
            "updated_at": now_utc(),
            "rejected_at": now_utc(),
            "auto_rejected": True,
            "rejected_reason": "game traded",
        }
    }

    if session is not None:
        offers_col.update_many(q, update, session=session)
    else:
        offers_col.update_many(q, update)

# ------------------------------------------------------------
# Error handling
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
# HATEOAS helpers (request-time URLs)
# ------------------------------------------------------------
def link(href: str, method: str = "GET") -> dict[str, str]:
    return {"href": href, "method": method}

def publicize(generated_url: str) -> str:
    u = URL(generated_url)
    if not PUBLIC_BASE_URL:
        return str(u)
    base = URL(PUBLIC_BASE_URL)
    return str(base.replace(path=u.path, query=u.query, fragment=u.fragment))


def url_for(request: Request, route_name: str, **params) -> str:
    str_params = {k: str(v) for k, v in params.items()}
    generated = URL(str(request.url_for(route_name, **str_params)))  # has correct path

    if PUBLIC_BASE_URL:
        base = URL(PUBLIC_BASE_URL)
        # Keep the generated path, but force the base host/port
        return str(base.replace(path=generated.path))

    return str(generated)

def url_with_query(request: Request, route_name: str, query: dict[str, Any], **params) -> str:
    base = url_for(request, route_name, **params)
    return str(URL(base).include_query_params(**{k: v for k, v in query.items() if v is not None}))

def user_public_links(request: Request, user_id: str) -> dict[str, Any]:
    return {
        "self": link(url_for(request, "get_user_public", user_id=user_id), "GET"),
        "games": link(url_for(request, "get_games_for_user", user_id=user_id), "GET"),
    }

def user_self_links(request: Request) -> dict[str, Any]:
    return {
        "self": link(url_for(request, "get_user_self"), "GET"),
        "update": link(url_for(request, "patch_user_self"), "PATCH"),
        "replace": link(url_for(request, "put_user_self"), "PUT"),
        "delete": link(url_for(request, "delete_user_self"), "DELETE"),
    }

def game_links(request: Request, game_id: str, owner_id: str, can_edit: bool) -> dict[str, Any]:
    links: dict[str, Any] = {
        "self": link(url_for(request, "get_game", game_id=game_id), "GET"),
        "all": link(url_for(request, "get_all_games"), "GET"),
        "search": link(url_for(request, "search_games"), "GET"),
        "owner": link(url_for(request, "get_user_public", user_id=owner_id), "GET"),
        "owners_games": link(url_for(request, "get_games_for_user", user_id=owner_id), "GET"),
    }
    if can_edit:
        links["update"] = link(url_for(request, "patch_game", game_id=game_id), "PATCH")
        links["replace"] = link(url_for(request, "put_game", game_id=game_id), "PUT")
        links["delete"] = link(url_for(request, "delete_game", game_id=game_id), "DELETE")
    return links

def offer_links(
    request: Request,
    offer_id: str,
    can_owner_respond: bool,
    can_offer_cancel: bool
) -> dict[str, Any]:
    links: dict[str, Any] = {
        "self": link(url_for(request, "get_offer", offer_id=offer_id), "GET"),
        "collection": link(url_for(request, "list_offers"), "GET"),
        "update": link(url_for(request, "patch_offer", offer_id=offer_id), "PATCH"),
    }
    if can_owner_respond:
        links["accept"] = link(url_for(request, "patch_offer", offer_id=offer_id), "PATCH")
        links["reject"] = link(url_for(request, "patch_offer", offer_id=offer_id), "PATCH")
    if can_offer_cancel:
        links["cancel"] = link(url_for(request, "patch_offer", offer_id=offer_id), "PATCH")
    return links

# ------------------------------------------------------------
# Schemas
# ------------------------------------------------------------
class Condition(str, Enum):
    mint = "mint"
    good = "good"
    fair = "fair"
    poor = "poor"

class OfferStatus(str, Enum):
    pending = "pending"
    accepted = "accepted"
    rejected = "rejected"
    cancelled = "cancelled"

class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    # bcrypt limitation: keep passwords reasonably sized
    password: str = Field(min_length=8, max_length=72)
    street_address: str = Field(min_length=1, max_length=200)

class UserUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    street_address: Optional[str] = Field(default=None, min_length=1, max_length=200)

class UserReplace(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    street_address: str = Field(min_length=1, max_length=200)

class UserPublicOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    _links: dict[str, Any]

class UserSelfOut(BaseModel):
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

class OfferCreate(BaseModel):
    requested_game_id: str = Field(min_length=1)
    offered_game_id: str = Field(min_length=1)

class OfferUpdate(BaseModel):
    status: OfferStatus

class OfferOut(BaseModel):
    id: str
    from_user_id: str
    to_user_id: str
    requested_game_id: str
    offered_game_id: str
    status: OfferStatus
    created_at: datetime
    updated_at: datetime
    _links: dict[str, Any]

class OfferListOut(BaseModel):
    items: list[OfferOut]
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
    cred_error = HTTPException(status_code=401, detail="Invalid or expired token.")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: str = payload.get("sub")
        if not user_id:
            raise cred_error
    except JWTError:
        raise cred_error

    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found for token.")
    return user

# ------------------------------------------------------------
# Root
# ------------------------------------------------------------
@app.get("/", name="api_root")
def api_root(request: Request):
    return {
        "name": "Retro Video Game Exchange API",
        "_links": {
            "register": link(url_for(request, "register_user"), "POST"),
            "login": link(url_for(request, "auth_token"), "POST"),
            "user": link(url_for(request, "get_user_self"), "GET"),
            "games_all": link(url_for(request, "get_all_games"), "GET"),
            "games_search": link(url_for(request, "search_games"), "GET"),
            "offers": link(url_for(request, "list_offers"), "GET"),
            "create_offer": link(url_for(request, "create_offer"), "POST"),
            "docs": link(publicize(str(request.url_for("swagger_ui_html"))), "GET"),
            "openapi": link(publicize(str(request.url_for("openapi"))), "GET"),
        },
    }

# ------------------------------------------------------------
# Auth endpoints
# ------------------------------------------------------------
@app.post("/auth/token", response_model=TokenOut, name="auth_token")
def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    email = form_data.username.lower().strip()
    user = get_user_by_email(email)
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")

    token = create_access_token(user_id=str(user["_id"]), email=user["email"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "_links": {
            "user": link(url_for(request, "get_user_self"), "GET"),
            "games_all": link(url_for(request, "get_all_games"), "GET"),
            "games_search": link(url_for(request, "search_games"), "GET"),
            "offers": link(url_for(request, "list_offers"), "GET"),
        },
    }

# ------------------------------------------------------------
# Users (SELF endpoints now /user instead of /users/me)
# ------------------------------------------------------------
@app.post("/users", status_code=201, response_model=UserSelfOut, name="register_user")
def register_user(payload: UserCreate, request: Request, response: Response):
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
        "_links": {**user_public_links(request, user_id), **user_self_links(request)},
    }

@app.get("/user", response_model=UserSelfOut, name="get_user_self")
def get_user_self(request: Request, current_user: dict[str, Any] = Depends(require_auth)):
    user_id = str(current_user["_id"])
    return {
        "id": user_id,
        "name": current_user["name"],
        "email": current_user["email"],
        "street_address": current_user["street_address"],
        "_links": {**user_public_links(request, user_id), **user_self_links(request)},
    }

@app.patch("/user", status_code=204, name="patch_user_self")
def patch_user_self(payload: UserUpdate, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    update_doc: dict[str, Any] = {}
    if payload.name is not None:
        update_doc["name"] = payload.name.strip()
    if payload.street_address is not None:
        update_doc["street_address"] = payload.street_address.strip()

    if not update_doc:
        raise HTTPException(status_code=400, detail="No updatable fields provided.")

    update_doc["updated_at"] = now_utc()
    users_col.update_one({"_id": current_user["_id"]}, {"$set": update_doc})

    response.headers["Location"] = url_for(request, "get_user_self")
    return Response(status_code=204)

@app.put("/user", status_code=204, name="put_user_self")
def put_user_self(payload: UserReplace, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    update_doc = {
        "name": payload.name.strip(),
        "street_address": payload.street_address.strip(),
        "updated_at": now_utc(),
    }
    users_col.update_one({"_id": current_user["_id"]}, {"$set": update_doc})

    response.headers["Location"] = url_for(request, "get_user_self")
    return Response(status_code=204)

@app.delete("/user", status_code=204, name="delete_user_self")
def delete_user_self(request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    games_col.delete_many({"owner_id": current_user["_id"]})
    offers_col.delete_many({"$or": [{"from_user_id": current_user["_id"]}, {"to_user_id": current_user["_id"]}]})
    users_col.delete_one({"_id": current_user["_id"]})

    response.headers["Location"] = url_for(request, "api_root")
    return Response(status_code=204)

@app.get("/users/{user_id}", response_model=UserPublicOut, name="get_user_public")
def get_user_public(user_id: str, request: Request, current_user: dict[str, Any] = Depends(require_auth)):
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
            "self": link(url_with_query(request, "get_games_for_user", {"skip": skip, "limit": limit}, user_id=user_id), "GET"),
            "owner": link(url_for(request, "get_user_public", user_id=user_id), "GET"),
        },
    }

# --- NEW: get all games endpoint ---
@app.get("/games", response_model=GameListOut, name="get_all_games")
def get_all_games(
    request: Request,
    limit: int = 20,
    skip: int = 0,
    current_user: dict[str, Any] = Depends(require_auth),
):
    query: dict[str, Any] = {}
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
            "self": link(url_with_query(request, "get_all_games", {"skip": skip, "limit": limit}), "GET"),
            "search": link(url_for(request, "search_games"), "GET"),
            "create": link(url_for(request, "create_game"), "POST"),
        },
    }

# --- Search moved to /games/search ---
@app.get("/games/search", response_model=GameListOut, name="search_games")
def search_games(
    request: Request,
    q: Optional[str] = None,
    name: Optional[str] = None,
    publisher: Optional[str] = None,
    system: Optional[str] = None,
    year_published: Optional[int] = None,
    condition: Optional[Condition] = None,
    owner_id: Optional[str] = None,
    exclude_mine: bool = False,  # handy for "browse other users' games"
    limit: int = 20,
    skip: int = 0,
    current_user: dict[str, Any] = Depends(require_auth),
):
    query: dict[str, Any] = {}

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
    if exclude_mine:
        query["owner_id"] = {"$ne": current_user["_id"]}

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
            "exclude_mine": exclude_mine,
            "skip": skip,
            "limit": limit,
        },
    )
    return {
        "items": items,
        "count": count,
        "_links": {
            "self": link(self_href, "GET"),
            "all": link(url_for(request, "get_all_games"), "GET"),
            "create": link(url_for(request, "create_game"), "POST"),
        },
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

def require_game_owner(game_id: str, current_user: dict[str, Any]) -> dict[str, Any]:
    g = games_col.find_one({"_id": parse_object_id(game_id)})
    if not g:
        raise HTTPException(status_code=404, detail="Game not found.")
    if g["owner_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="Only the owner can modify this game.")
    return g

@app.patch("/games/{game_id}", status_code=204, name="patch_game")
def patch_game(game_id: str, payload: GameUpdate, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
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

@app.put("/games/{game_id}", status_code=204, name="put_game")
def put_game(game_id: str, payload: GameCreate, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
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

    response.headers["Location"] = url_for(request, "get_all_games")
    return Response(status_code=204)

# ------------------------------------------------------------
# Offers (NEW)
# ------------------------------------------------------------
@app.post("/offers", status_code=201, response_model=OfferOut, name="create_offer")
def create_offer(payload: OfferCreate, request: Request, response: Response, current_user: dict[str, Any] = Depends(require_auth)):
    requested_oid = parse_object_id(payload.requested_game_id)
    offered_oid = parse_object_id(payload.offered_game_id)

    requested_game = games_col.find_one({"_id": requested_oid})
    if not requested_game:
        raise HTTPException(status_code=404, detail="Requested game not found.")

    offered_game = games_col.find_one({"_id": offered_oid})
    if not offered_game:
        raise HTTPException(status_code=404, detail="Offered game not found.")

    # Must be offering YOUR game
    if offered_game["owner_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="You can only offer one of your own games.")

    # Cannot offer on your own requested game
    if requested_game["owner_id"] == current_user["_id"]:
        raise HTTPException(status_code=400, detail="You cannot create an offer on your own game.")

    doc = {
        "from_user_id": current_user["_id"],
        "to_user_id": requested_game["owner_id"],
        "requested_game_id": requested_oid,
        "offered_game_id": offered_oid,
        "status": OfferStatus.pending.value,
        "created_at": now_utc(),
        "updated_at": now_utc(),
    }

    result = offers_col.insert_one(doc)
    offer_id = str(result.inserted_id)

    response.headers["Location"] = url_for(request, "get_offer", offer_id=offer_id)

    return {
        "id": offer_id,
        "from_user_id": str(doc["from_user_id"]),
        "to_user_id": str(doc["to_user_id"]),
        "requested_game_id": str(doc["requested_game_id"]),
        "offered_game_id": str(doc["offered_game_id"]),
        "status": doc["status"],
        "created_at": doc["created_at"],
        "updated_at": doc["updated_at"],
        "_links": {
            **offer_links(request, offer_id, can_owner_respond=False, can_offer_cancel=True),
            "requested_game": link(url_for(request, "get_game", game_id=str(doc["requested_game_id"])), "GET"),
            "offered_game": link(url_for(request, "get_game", game_id=str(doc["offered_game_id"])), "GET"),
        },
    }

@app.get("/offers", response_model=OfferListOut, name="list_offers")
def list_offers(
    request: Request,
    status: Optional[OfferStatus] = None,
    type: str = "incoming",  # incoming | outgoing | all
    limit: int = 20,
    skip: int = 0,
    current_user: dict[str, Any] = Depends(require_auth),
):
    query: dict[str, Any] = {}

    if type == "incoming":
        query["to_user_id"] = current_user["_id"]
    elif type == "outgoing":
        query["from_user_id"] = current_user["_id"]
    elif type == "all":
        query["$or"] = [{"to_user_id": current_user["_id"]}, {"from_user_id": current_user["_id"]}]
    else:
        raise HTTPException(status_code=400, detail="type must be incoming, outgoing, or all.")

    if status is not None:
        query["status"] = status.value

    cursor = offers_col.find(query).sort("created_at", DESCENDING).skip(skip).limit(limit)
    items: list[dict[str, Any]] = []

    for o in cursor:
        oid = str(o["_id"])
        from_id = str(o["from_user_id"])
        to_id = str(o["to_user_id"])
        requested_id = str(o["requested_game_id"])
        offered_id = str(o["offered_game_id"])
        st = o["status"]

        can_owner_respond = (o["to_user_id"] == current_user["_id"] and st == OfferStatus.pending.value)
        can_offer_cancel = (o["from_user_id"] == current_user["_id"] and st == OfferStatus.pending.value)

        items.append(
            {
                "id": oid,
                "from_user_id": from_id,
                "to_user_id": to_id,
                "requested_game_id": requested_id,
                "offered_game_id": offered_id,
                "status": st,
                "created_at": o["created_at"],
                "updated_at": o["updated_at"],
                "_links": {
                    **offer_links(request, oid, can_owner_respond, can_offer_cancel),
                    "requested_game": link(url_for(request, "get_game", game_id=requested_id), "GET"),
                    "offered_game": link(url_for(request, "get_game", game_id=offered_id), "GET"),
                    "from_user": link(url_for(request, "get_user_public", user_id=from_id), "GET"),
                    "to_user": link(url_for(request, "get_user_public", user_id=to_id), "GET"),
                },
            }
        )

    count = offers_col.count_documents(query)
    return {
        "items": items,
        "count": count,
        "_links": {
            "self": link(
                url_with_query(
                    request,
                    "list_offers",
                    {"status": status.value if status else None, "type": type, "skip": skip, "limit": limit},
                ),
                "GET",
            ),
            "create": link(url_for(request, "create_offer"), "POST"),
        },
    }

@app.get("/offers/{offer_id}", response_model=OfferOut, name="get_offer")
def get_offer(offer_id: str, request: Request, current_user: dict[str, Any] = Depends(require_auth)):
    o = offers_col.find_one({"_id": parse_object_id(offer_id)})
    if not o:
        raise HTTPException(status_code=404, detail="Offer not found.")

    # Only participants can view
    if o["from_user_id"] != current_user["_id"] and o["to_user_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="You are not allowed to view this offer.")

    st = o["status"]
    can_owner_respond = (o["to_user_id"] == current_user["_id"] and st == OfferStatus.pending.value)
    can_offer_cancel = (o["from_user_id"] == current_user["_id"] and st == OfferStatus.pending.value)

    requested_id = str(o["requested_game_id"])
    offered_id = str(o["offered_game_id"])
    from_id = str(o["from_user_id"])
    to_id = str(o["to_user_id"])

    return {
        "id": str(o["_id"]),
        "from_user_id": from_id,
        "to_user_id": to_id,
        "requested_game_id": requested_id,
        "offered_game_id": offered_id,
        "status": st,
        "created_at": o["created_at"],
        "updated_at": o["updated_at"],
        "_links": {
            **offer_links(request, str(o["_id"]), can_owner_respond, can_offer_cancel),
            "requested_game": link(url_for(request, "get_game", game_id=requested_id), "GET"),
            "offered_game": link(url_for(request, "get_game", game_id=offered_id), "GET"),
            "from_user": link(url_for(request, "get_user_public", user_id=from_id), "GET"),
            "to_user": link(url_for(request, "get_user_public", user_id=to_id), "GET"),
        },
    }

@app.patch("/offers/{offer_id}", status_code=204, name="patch_offer")
def patch_offer(
    offer_id: str,
    payload: OfferUpdate,
    request: Request,
    response: Response,
    current_user: dict[str, Any] = Depends(require_auth),
):
    offer_oid = parse_object_id(offer_id)

    # Always load the offer first (outside transaction is fine for initial auth checks)
    o = offers_col.find_one({"_id": offer_oid})
    if not o:
        raise HTTPException(status_code=404, detail="Offer not found.")

    # Only participants can update (extra-credit rule)
    if o["from_user_id"] != current_user["_id"] and o["to_user_id"] != current_user["_id"]:
        raise HTTPException(status_code=403, detail="You are not allowed to update this offer.")

    if o["status"] != OfferStatus.pending.value:
        raise HTTPException(status_code=409, detail="Only pending offers can be updated.")

    new_status = payload.status.value

    # Validate who can do what
    if new_status in (OfferStatus.accepted.value, OfferStatus.rejected.value):
        if o["to_user_id"] != current_user["_id"]:
            raise HTTPException(status_code=403, detail="Only the owner of the requested game can accept/reject.")
    elif new_status == OfferStatus.cancelled.value:
        if o["from_user_id"] != current_user["_id"]:
            raise HTTPException(status_code=403, detail="Only the user who made the offer can cancel it.")
    else:
        raise HTTPException(status_code=400, detail="Invalid status transition.")

    # Reject/cancel are simple status updates (no game transfer)
    if new_status in (OfferStatus.rejected.value, OfferStatus.cancelled.value):
        offers_col.update_one(
            {"_id": offer_oid, "status": OfferStatus.pending.value},
            {"$set": {"status": new_status, "updated_at": now_utc()}},
        )
        response.headers["Location"] = url_for(request, "get_offer", offer_id=offer_id)
        return Response(status_code=204)

    # --------------------------
    # ACCEPT: Transfer ownership
    # --------------------------
    if new_status == OfferStatus.accepted.value:
        from_user_id = o["from_user_id"]  # offer creator (gets requested game)
        to_user_id = o["to_user_id"]      # owner of requested game (gets offered game)

        requested_game_id = o["requested_game_id"]
        offered_game_id = o["offered_game_id"]

        # Prefer a transaction (Atlas supports this; multi-container will stay consistent)
        if supports_transactions():
            try:
                with client.start_session() as session:
                    with session.start_transaction():
                        # Re-read offer inside transaction and ensure it's still pending
                        live_offer = offers_col.find_one({"_id": offer_oid}, session=session)
                        if not live_offer or live_offer["status"] != OfferStatus.pending.value:
                            raise HTTPException(status_code=409, detail="Offer is no longer pending.")

                        # Load both games
                        requested_game = games_col.find_one({"_id": requested_game_id}, session=session)
                        offered_game = games_col.find_one({"_id": offered_game_id}, session=session)

                        if not requested_game or not offered_game:
                            raise HTTPException(status_code=409, detail="One of the games no longer exists.")

                        # Ensure ownership is still as expected (prevents stale offers)
                        if requested_game["owner_id"] != to_user_id:
                            raise HTTPException(status_code=409, detail="Requested game is no longer owned by the recipient.")
                        if offered_game["owner_id"] != from_user_id:
                            raise HTTPException(status_code=409, detail="Offered game is no longer owned by the offer creator.")

                        # Compute new previous_owners values
                        req_prev = inc_prev_owners(requested_game.get("previous_owners"))
                        off_prev = inc_prev_owners(offered_game.get("previous_owners"))

                        # Swap ownership
                        games_col.update_one(
                            {"_id": requested_game_id},
                            {"$set": {"owner_id": from_user_id, "previous_owners": req_prev, "updated_at": now_utc()}},
                            session=session,
                        )
                        games_col.update_one(
                            {"_id": offered_game_id},
                            {"$set": {"owner_id": to_user_id, "previous_owners": off_prev, "updated_at": now_utc()}},
                            session=session,
                        )

                        # Mark offer accepted
                        offers_col.update_one(
                            {"_id": offer_oid},
                            {"$set": {"status": OfferStatus.accepted.value, "updated_at": now_utc(), "accepted_at": now_utc()}},
                            session=session,
                        )
                        
                        auto_reject_conflicting_offers(
                            accepted_offer_oid=offer_oid,
                            requested_game_oid=requested_game_id,
                            offered_game_oid=offered_game_id,
                            session=session,
                        )

                response.headers["Location"] = url_for(request, "get_offer", offer_id=offer_id)
                return Response(status_code=204)

            except HTTPException:
                # bubble up clean client-friendly errors
                raise
            except Exception:
                # Transaction failed (e.g., not supported). We'll fall back below.
                pass

        # --------------------------
        # Fallback (no transactions)
        # --------------------------
        # Step 1: atomically flip the offer from pending -> accepted (prevents double-accept)
        updated_offer = offers_col.find_one_and_update(
            {"_id": offer_oid, "status": OfferStatus.pending.value},
            {"$set": {"status": OfferStatus.accepted.value, "updated_at": now_utc(), "accepted_at": now_utc()}},
            return_document=True,
        )
        if not updated_offer:
            raise HTTPException(status_code=409, detail="Offer is no longer pending.")

        # Step 2: verify games & perform guarded swaps (only if owners still match)
        requested_game = games_col.find_one({"_id": requested_game_id})
        offered_game = games_col.find_one({"_id": offered_game_id})
        if not requested_game or not offered_game:
            # best-effort rollback
            offers_col.update_one({"_id": offer_oid}, {"$set": {"status": OfferStatus.pending.value, "updated_at": now_utc()}})
            raise HTTPException(status_code=409, detail="One of the games no longer exists.")

        if requested_game["owner_id"] != to_user_id or offered_game["owner_id"] != from_user_id:
            offers_col.update_one({"_id": offer_oid}, {"$set": {"status": OfferStatus.pending.value, "updated_at": now_utc()}})
            raise HTTPException(status_code=409, detail="Game ownership changed; cannot complete trade.")

        req_prev = inc_prev_owners(requested_game.get("previous_owners"))
        off_prev = inc_prev_owners(offered_game.get("previous_owners"))

        # guarded updates
        r1 = games_col.update_one(
            {"_id": requested_game_id, "owner_id": to_user_id},
            {"$set": {"owner_id": from_user_id, "previous_owners": req_prev, "updated_at": now_utc()}},
        )
        r2 = games_col.update_one(
            {"_id": offered_game_id, "owner_id": from_user_id},
            {"$set": {"owner_id": to_user_id, "previous_owners": off_prev, "updated_at": now_utc()}},
        )

        if r1.matched_count != 1 or r2.matched_count != 1:
            # best-effort rollback
            offers_col.update_one({"_id": offer_oid}, {"$set": {"status": OfferStatus.pending.value, "updated_at": now_utc()}})
            raise HTTPException(status_code=409, detail="Could not complete trade due to concurrent change.")

        response.headers["Location"] = url_for(request, "get_offer", offer_id=offer_id)
        return Response(status_code=204)


#This document was made in help by ChatGPT