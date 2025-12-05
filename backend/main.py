from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient


# ------------------- CONFIGURATION -------------------

SECRET_KEY = "0a0bf142ad271aa8d540eb131d2bfd82f061619dda8df953d72a20385d6100c5"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# MongoDB connection
# MongoDB connection
MONGODB_URL = "mongodb+srv://yogeshknit99:D7YKS843eK9BUc10@cluster0.vbzst.mongodb.net/indexAI?retryWrites=true&w=majority&appName=Cluster0"

client = AsyncIOMotorClient(MONGODB_URL)
db = client["indexAI"]
user_collection = db["users"]


# ------------------- MODELS -------------------

class RegisterUser(BaseModel):
    username: str
    password: str
    email: str | None = None
    full_name: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


# ------------------- SECURITY HELPERS -------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Generate JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def hash_password(password: str):
    return pwd_context.hash(password)


async def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


async def get_user(username: str):
    user_data = await user_collection.find_one({"username": username})
    return UserInDB(**user_data) if user_data else None


async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user or not await verify_password(password, user.hashed_password):
        return False
    return user


# ------------------- FASTAPI APP -------------------

app = FastAPI(title="IndexAI", version="1.0.0")


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Validate token and return user"""
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate token", headers={"WWW-Authenticate": "Bearer"}
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        if username is None:
            raise credentials_exception

        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception

    user = await get_user(token_data.username)

    if user is None:
        raise credentials_exception

    return user


async def get_active_user(current_user: User = Depends(get_current_user)):
    """Ensure user is active"""
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="User is inactive")
    return current_user


# ------------------- ROUTES -------------------

@app.post("/register", response_model=User)
async def register_user(user: RegisterUser):
    """User Registration"""

    # Check if user exists
    existing_user = await get_user(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = await hash_password(user.password)

    user_dict = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "disabled": False,
        "hashed_password": hashed_pw
    }

    await user_collection.insert_one(user_dict)
    return User(**user_dict)


@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login and generate JWT"""

    user = await authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": user.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    return {"access_token": token, "token_type": "bearer"}


@app.get("/me", response_model=User)
async def get_profile(current_user: User = Depends(get_active_user)):
    """Protected route: Get logged-in user profile"""
    return current_user
