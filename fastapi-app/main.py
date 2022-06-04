from enum import unique
import jwt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model


app = FastAPI(
    title="Edvora",
    description="Edvora task",
    version="0.0.1",
    terms_of_service="https://www.edvora.com/",
    contact={
        "name": "Edvora Amazing",
        "url": "https://www.edvora.com/",
        "email": "careers@edvora.com",
    },
    license_info={"name": "Edvora Copyright", "url": "https://www.edvora.com/"},
)

tags_metadata = [
    {
        "name": "Users",
        "description": "Operations with users. The **login** logic is also here.",
    },
    {
        "name": "Students",
        "description": "Manage items. So _fancy_ they have their own docs.",
        "externalDocs": {
            "description": "Items external docs",
            "url": "https://fastapi.tiangolo.com/",
        },
    },
]

JWT_SECRET = "myjwtsecret"


class UserDetails(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    email = fields.CharField(50, unique=True)
    phone_number = fields.CharField(13, unique=True)
    password_hash = fields.CharField(128)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


UserDetails_Pydantic = pydantic_model_creator(UserDetails, name="UserDetails")
UserDetailsIn_Pydantic = pydantic_model_creator(
    UserDetails, name="UserDetailsIn", exclude_readonly=True
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def authenticate_user(username: str, password: str):
    user = await UserDetails.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user


@app.get("/")
async def homepage():
    return "Welcome to Edvora Amazing FastAPI !"


@app.post("/token")
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    user_obj = await UserDetails_Pydantic.from_tortoise_orm(user)

    token = jwt.encode(user_obj.dict(), JWT_SECRET)

    return {"token_type": "bearer", "access_token": token}


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = await UserDetails.get(id=payload.get("id"))
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    return await UserDetails_Pydantic.from_tortoise_orm(user)


@app.post("/users", response_model=UserDetails_Pydantic)
async def create_user(user: UserDetailsIn_Pydantic):
    user_obj = UserDetails(
        username=user.username,
        password_hash=bcrypt.hash(user.password_hash),
        email=user.email,
        phone_number=user.phone_number,
    )
    await user_obj.save()
    return await UserDetails_Pydantic.from_tortoise_orm(user_obj)


@app.get("/users/details", response_model=UserDetails_Pydantic)
async def get_user(user: UserDetails_Pydantic = Depends(get_current_user)):
    return user


register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={"models": ["main"]},
    generate_schemas=True,
    add_exception_handlers=True,
)
