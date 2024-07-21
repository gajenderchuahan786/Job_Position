from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from bson import ObjectId
import motor.motor_asyncio
from enum import Enum
import os
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from jose.exceptions import JWTError


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

client = motor.motor_asyncio.AsyncIOMotorClient(os.getenv("MONGO_URI"))
db = client.get_database()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class JobType(str, Enum):
    full_time = "full-time"
    part_time = "part-time"
    contract = "contract"


class JobBase(BaseModel):
    title: str
    description: str
    skills_required: List[str]
    qualifications: List[str]
    company_name: str
    location: str
    job_type: JobType
    salary_amount: float


class JobCreate(JobBase):
    pass


class Job(JobBase):
    id: str


class User(BaseModel):
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # type: ignore
        username: str = payload.get("sub")  # type: ignore
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user(username=token_data.username)  # type: ignore
    if user is None:
        raise credentials_exception
    return user


async def get_user(username: str):
    user = await db["users"].find_one({"username": username})
    if user:
        return UserInDB(**user)


async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  # type: ignore
    return encoded_jwt


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/register/", response_model=User)
async def register_user(username: str, email: EmailStr, password: str):
    hashed_password = pwd_context.hash(password)
    user = {"username": username, "email": email, "hashed_password": hashed_password}
    await db["users"].insert_one(user)
    return user


@app.post("/jobs/", response_model=Job)
async def create_job(job: JobCreate, current_user: User = Depends(get_current_user)):
    job_dict = job.dict()
    result = await db["jobs"].insert_one(job_dict)
    job_dict["id"] = str(result.inserted_id)
    return job_dict


@app.get("/jobs/", response_model=List[Job])
async def read_jobs(skip: int = 0, limit: int = 10, current_user: User = Depends(get_current_user)):
    jobs = await db["jobs"].find().skip(skip).limit(limit).to_list(length=limit)
    for job in jobs:
        job["id"] = str(job["_id"])
    return jobs


@app.get("/jobs/{job_id}", response_model=Job)
async def read_job(job_id: str, current_user: User = Depends(get_current_user)):
    job = await db["jobs"].find_one({"_id": ObjectId(job_id)})
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    job["id"] = str(job["_id"])
    return job


@app.put("/jobs/{job_id}", response_model=Job)
async def update_job(job_id: str, job: JobCreate, current_user: User = Depends(get_current_user)):
    job_dict = job.dict()
    result = await db["jobs"].update_one({"_id": ObjectId(job_id)}, {"$set": job_dict})
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Job not found")
    job_dict["id"] = job_id
    return job_dict


@app.delete("/jobs/{job_id}", response_model=dict)
async def delete_job(job_id: str, current_user: User = Depends(get_current_user)):
    result = await db["jobs"].delete_one({"_id": ObjectId(job_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"message": "Job deleted successfully"}
