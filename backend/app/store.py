from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, List
from sqlmodel import SQLModel, Field, create_engine, Session, select, and_
from sqlalchemy import text
import json


class Threat(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    time: datetime = Field(default_factory=lambda: datetime.now().astimezone())
    severity: str
    description: str
    source: str
    action: Optional[str] = None
    filePath: Optional[str] = None
    url: Optional[str] = None
    deep_analysis: Optional[str] = None


class ThreatIn(SQLModel):
    severity: str
    description: str
    source: str
    action: Optional[str] = None
    filePath: Optional[str] = None
    url: Optional[str] = None


class AllowedFile(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hash: str
    path: str
    created: datetime = Field(default_factory=lambda: datetime.now().astimezone())


class BlockedUrl(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(index=True, unique=True)
    host: str = Field(index=True)
    score: float
    category: str
    os_blocked: bool = False
    created: datetime = Field(default_factory=lambda: datetime.now().astimezone())
    last_accessed: Optional[datetime] = None


class ScanJob(SQLModel, table=True):
    """Persistent storage for manual scan jobs and results."""
    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: str = Field(index=True, unique=True)  # Unique job identifier
    status: str = Field(default="queued")  # queued, processing, completed, failed
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_mime: Optional[str] = None
    is_uploaded: bool = False
    temp_path: Optional[str] = None
    progress: int = Field(default=0)  # 0-100
    result: Optional[str] = None  # JSON string of scan result
    error: Optional[str] = None
    threat_id: Optional[int] = None  # Associated threat ID if threat was created
    created: datetime = Field(default_factory=lambda: datetime.now().astimezone())
    started: Optional[datetime] = None
    completed: Optional[datetime] = None


class _DB:
    def __init__(self):
        self.engine = create_engine("sqlite:///./ai_shield.db")
        self.blocked_urls: List[str] = []
        self.state = {"threatLevel": 15, "threatIndex": 42, "filesScanned": 0, "networkAlerts": 0, "protection": {"scan": True, "webshield": True, "snort": True}}
        self.ensure_schema()

    def ensure_schema(self):
        try:
            with self.engine.connect() as conn:
                tbl = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='threat'"))
                row = tbl.fetchone()
                if not row:
                    SQLModel.metadata.create_all(self.engine)
                    return
                cols = conn.execute(text("PRAGMA table_info(threat)"))
                names = {r[1] for r in cols.fetchall()}
                required = {"id", "time", "severity", "description", "source", "action", "filePath", "url", "deep_analysis"}
                if not required.issubset(names):
                    SQLModel.metadata.drop_all(self.engine)
                    SQLModel.metadata.create_all(self.engine)
                # Ensure AllowedFile and BlockedUrl tables exist even if Threat is present
                af_tbl = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='allowedfile'"))
                if af_tbl.fetchone() is None:
                    SQLModel.metadata.create_all(self.engine)
                bu_tbl = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='blockedurl'"))
                if bu_tbl.fetchone() is None:
                    SQLModel.metadata.create_all(self.engine)
                # Ensure ScanJob table exists
                sj_tbl = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='scanjob'"))
                if sj_tbl.fetchone() is None:
                    SQLModel.metadata.create_all(self.engine)
                # Always ensure all tables are created
                SQLModel.metadata.create_all(self.engine)
        except Exception:
            SQLModel.metadata.create_all(self.engine)

    def compute_file_hash(self, path: str) -> str:
        import hashlib
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except Exception:
            return ""
        return h.hexdigest()

    def add_threat(self, t: ThreatIn) -> Threat:
        with Session(self.engine) as s:
            obj = Threat(**t.model_dump())
            s.add(obj)
            s.commit()
            s.refresh(obj)
            return obj

    def allow_file(self, tid: int) -> Threat | None:
        with Session(self.engine) as s:
            obj = s.get(Threat, tid)
            if not obj or not obj.filePath:
                return obj
            file_hash = self.compute_file_hash(obj.filePath)
            if file_hash:
                af = AllowedFile(hash=file_hash, path=obj.filePath)
                s.add(af)
            obj.action = "allowed"
            s.add(obj)
            s.commit()
            s.refresh(obj)
            return obj

    def is_allowed_path(self, path: str) -> bool:
        h = self.compute_file_hash(path)
        if not h:
            return False
        with Session(self.engine) as s:
            stmt = select(AllowedFile).where(AllowedFile.hash == h)
            return s.exec(stmt).first() is not None

    def list_threats(self, limit: int = 100, severity: Optional[str] = None, source: Optional[str] = None, action: Optional[str] = None) -> list[Threat]:
        with Session(self.engine) as s:
            stmt = select(Threat)
            conditions = []
            if severity:
                conditions.append(Threat.severity == severity)
            if source:
                conditions.append(Threat.source == source)
            if action is not None:
                conditions.append(Threat.action == action)
            if conditions:
                stmt = stmt.where(and_(*conditions))
            stmt = stmt.order_by(Threat.time.desc()).limit(limit)
            return list(s.exec(stmt).all())

    def set_action_bulk(self, ids: List[int], action: Optional[str]) -> int:
        with Session(self.engine) as s:
            updated = 0
            for tid in ids:
                obj = s.get(Threat, tid)
                if obj:
                    obj.action = action
                    s.add(obj)
                    updated += 1
            s.commit()
            return updated

    def add_blocked_url(self, url: str, host: str, score: float, category: str, os_blocked: bool = False) -> BlockedUrl:
        with Session(self.engine) as s:
            # Check if URL already exists
            stmt = select(BlockedUrl).where(BlockedUrl.url == url)
            existing = s.exec(stmt).first()
            if existing:
                existing.os_blocked = os_blocked or existing.os_blocked
                existing.score = score
                existing.category = category
                s.add(existing)
                s.commit()
                s.refresh(existing)
                return existing
            # Create new blocked URL entry
            obj = BlockedUrl(url=url, host=host, score=score, category=category, os_blocked=os_blocked)
            s.add(obj)
            s.commit()
            s.refresh(obj)
            return obj

    def is_url_blocked(self, url: str) -> bool:
        with Session(self.engine) as s:
            stmt = select(BlockedUrl).where(BlockedUrl.url == url)
            return s.exec(stmt).first() is not None

    def list_blocked_urls(self, limit: int = 500) -> List[BlockedUrl]:
        with Session(self.engine) as s:
            stmt = select(BlockedUrl).order_by(BlockedUrl.created.desc()).limit(limit)
            return list(s.exec(stmt).all())

    def delete_blocked_url(self, url_id: int) -> bool:
        with Session(self.engine) as s:
            obj = s.get(BlockedUrl, url_id)
            if obj:
                s.delete(obj)
                s.commit()
                return True
            return False

    def create_scan_job(self, job_id: str, file_path: str, file_name: str, 
                       file_size: int, file_mime: str, is_uploaded: bool = False, 
                       temp_path: Optional[str] = None) -> ScanJob:
        """Create a new scan job."""
        with Session(self.engine) as s:
            job = ScanJob(
                job_id=job_id,
                status="queued",
                file_path=file_path,
                file_name=file_name,
                file_size=file_size,
                file_mime=file_mime,
                is_uploaded=is_uploaded,
                temp_path=temp_path,
                progress=0
            )
            s.add(job)
            s.commit()
            s.refresh(job)
            return job

    def get_scan_job(self, job_id: str) -> Optional[ScanJob]:
        """Get a scan job by job_id."""
        with Session(self.engine) as s:
            stmt = select(ScanJob).where(ScanJob.job_id == job_id)
            return s.exec(stmt).first()

    def update_scan_job(self, job_id: str, status: Optional[str] = None, 
                       progress: Optional[int] = None, result: Optional[dict] = None,
                       error: Optional[str] = None, threat_id: Optional[int] = None) -> Optional[ScanJob]:
        """Update a scan job."""
        with Session(self.engine) as s:
            job = s.exec(select(ScanJob).where(ScanJob.job_id == job_id)).first()
            if not job:
                return None
            
            if status is not None:
                job.status = status
                if status == "processing" and job.started is None:
                    job.started = datetime.now().astimezone()
                elif status in ("completed", "failed") and job.completed is None:
                    job.completed = datetime.now().astimezone()
            
            if progress is not None:
                job.progress = max(0, min(100, progress))
            
            if result is not None:
                job.result = json.dumps(result)
            
            if error is not None:
                job.error = error
            
            if threat_id is not None:
                job.threat_id = threat_id
            
            s.add(job)
            s.commit()
            s.refresh(job)
            return job

    def list_scan_jobs(self, limit: int = 100, status: Optional[str] = None) -> List[ScanJob]:
        """List scan jobs, optionally filtered by status."""
        with Session(self.engine) as s:
            stmt = select(ScanJob)
            if status:
                stmt = stmt.where(ScanJob.status == status)
            stmt = stmt.order_by(ScanJob.created.desc()).limit(limit)
            return list(s.exec(stmt).all())

    def delete_scan_job(self, job_id: str) -> bool:
        """Delete a scan job."""
        with Session(self.engine) as s:
            job = s.exec(select(ScanJob).where(ScanJob.job_id == job_id)).first()
            if job:
                s.delete(job)
                s.commit()
                return True
            return False


DB = _DB()
