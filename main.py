from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import List, Optional
from uuid import UUID, uuid4
from enum import Enum
from datetime import datetime

app = FastAPI()

# Job status options
class JobStatus(str, Enum):
    open = "open"
    closed = "closed"

class Job(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    company: str
    location: str
    salary: Optional[str] = None
    status: JobStatus = JobStatus.open
    posted_at: datetime = Field(default_factory=datetime.utcnow)

fake_jobs_db: List[Job] = []


@app.post("/jobs", response_model=Job)
def create_job(job: Job):
    fake_jobs_db.append(job)
    return job

# GET - Get all jobs
@app.get("/jobs", response_model=List[Job])
def get_jobs():
    return fake_jobs_db
