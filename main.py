from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Enum as SqlEnum, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import enum

# CONFIG
SECRET_KEY = "jobs-api-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# FastAPI app and DB setup
app = FastAPI()
SQLALCHEMY_DATABASE_URL = "sqlite:///./jobs.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# Auth and Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# ENUMS
class UserRole(str, enum.Enum):
    company = "company"
    candidate = "candidate"

class JobStatus(str, enum.Enum):
    open = "open"
    closed = "closed"

# MODELS
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(SqlEnum(UserRole))
    jobs = relationship("Job", back_populates="company")
    applications = relationship("Application", back_populates="candidate")

class Job(Base):
    __tablename__ = "jobs"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    location = Column(String)
    salary = Column(String)
    status = Column(SqlEnum(JobStatus), default=JobStatus.open)
    posted_at = Column(DateTime, default=datetime.utcnow)
    company_id = Column(Integer, ForeignKey("users.id"))
    company = relationship("User", back_populates="jobs")
    applications = relationship("Application", back_populates="job")

class Application(Base):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True, index=True)
    candidate_id = Column(Integer, ForeignKey("users.id"))
    job_id = Column(Integer, ForeignKey("jobs.id"))
    applied_at = Column(DateTime, default=datetime.utcnow)
    candidate = relationship("User", back_populates="applications")
    job = relationship("Job", back_populates="applications")

Base.metadata.create_all(bind=engine)

# SCHEMAS
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: UserRole

class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: UserRole
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[int] = None

class JobCreate(BaseModel):
    title: str
    description: str
    location: str
    salary: Optional[str] = None

class JobOut(BaseModel):
    id: int
    title: str
    description: str
    location: str
    salary: Optional[str]
    status: JobStatus
    posted_at: datetime
    company_id: int
    class Config:
        from_attributes = True

class ApplyRequest(BaseModel):
    job_id: int

# UTILS
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# AUTH ROUTES
@app.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password, role=user.role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

# JOB ROUTES
@app.post("/jobs", response_model=JobOut)
def post_job(job: JobCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != UserRole.company:
        raise HTTPException(status_code=403, detail="Only companies can post jobs")
    new_job = Job(**job.dict(), company_id=current_user.id)
    db.add(new_job)
    db.commit()
    db.refresh(new_job)
    return new_job

@app.get("/jobs", response_model=List[JobOut])
def get_all_jobs(status: Optional[JobStatus] = None, location: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Job)
    if status:
        query = query.filter(Job.status == status)
    if location:
        query = query.filter(Job.location.ilike(f"%{location}%"))
    return query.all()

@app.post("/apply")
def apply_to_job(request: ApplyRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != UserRole.candidate:
        raise HTTPException(status_code=403, detail="Only candidates can apply")
    job = db.query(Job).filter(Job.id == request.job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    application = Application(candidate_id=current_user.id, job_id=request.job_id)
    db.add(application)
    db.commit()
    return {"message": "Application submitted"}

@app.get("/my-applications", response_model=List[JobOut])
def my_applications(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != UserRole.candidate:
        raise HTTPException(status_code=403, detail="Only candidates can view their applications")
    return [app.job for app in current_user.applications]

@app.get("/my-jobs", response_model=List[JobOut])
def my_jobs(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != UserRole.company:
        raise HTTPException(status_code=403, detail="Only companies can view their posted jobs")
    return current_user.jobs


# New Schema for Applicants
class CandidateOut(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True

# Endpoint: Get Applicants for a Job
@app.get("/applicants/{job_id}", response_model=List[CandidateOut])
def get_applicants(job_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.company_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to view applicants for this job")
    applicants = [app.candidate for app in job.applications]
    return applicants
