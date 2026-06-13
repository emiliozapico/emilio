"""FastAPI router that exposes the bugbounty_tool modules over HTTP."""
from __future__ import annotations

import asyncio
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorDatabase

TOOL_ROOT = Path(__file__).resolve().parent.parent
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

from bugbounty_tool.core import run_pipeline  # noqa: E402
from bugbounty_tool.modules import report as report_mod  # noqa: E402
from bugbounty_tool.modules.exploits import ALL_EXPLOITS  # noqa: E402


router = APIRouter(prefix="/api/bb", tags=["bugbounty"])

JOBS: Dict[str, Dict] = {}
_JOBS_LOCK = threading.Lock()


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    modules: List[str] = Field(default_factory=lambda: ["recon", "scan", "vuln"])
    timeout: int = 10
    delay: float = 0.0
    ports: Optional[List[int]] = None
    with_whois: bool = True
    subdomain_wordlist: Optional[List[str]] = None
    dir_wordlist: Optional[List[str]] = None
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    crawl_depth: int = 2
    crawl_max_pages: int = 30
    enabled_exploits: Optional[List[str]] = None
    login_url: Optional[str] = None
    login_user: Optional[str] = None
    login_password: Optional[str] = None
    login_user_field: str = "username"
    login_password_field: str = "password"
    i_have_authorization: bool = False


class JobSummary(BaseModel):
    id: str
    target: str
    modules: List[str]
    status: str
    created_at: str
    finished_at: Optional[str] = None
    counts: Optional[Dict[str, int]] = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _public_job(job: Dict) -> Dict:
    return {
        "id": job["id"],
        "target": job["target"],
        "modules": job["modules"],
        "status": job["status"],
        "created_at": job["created_at"],
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "progress": job.get("progress", [])[-300:],
        "result": job.get("result"),
        "error": job.get("error"),
        "counts": (job.get("result") or {}).get("vuln", {}).get("counts") if job.get("result") else None,
    }


def _run_job(job_id: str, payload: ScanRequest, db: AsyncIOMotorDatabase) -> None:
    with _JOBS_LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["started_at"] = _now()

    def progress(message: str) -> None:
        with _JOBS_LOCK:
            JOBS[job_id]["progress"].append({"ts": _now(), "msg": str(message)[:400]})

    try:
        result = run_pipeline(
            target=payload.target,
            modules=payload.modules,
            timeout=payload.timeout,
            delay=payload.delay,
            ports=payload.ports,
            subdomain_wordlist=payload.subdomain_wordlist,
            dir_wordlist=payload.dir_wordlist,
            with_whois=payload.with_whois,
            cookies=payload.cookies or {},
            headers=payload.headers or {},
            crawl_depth=payload.crawl_depth,
            crawl_max_pages=payload.crawl_max_pages,
            enabled_exploits=payload.enabled_exploits,
            login_url=payload.login_url,
            login_user=payload.login_user,
            login_password=payload.login_password,
            login_user_field=payload.login_user_field,
            login_password_field=payload.login_password_field,
            on_progress=progress,
        )
        with _JOBS_LOCK:
            JOBS[job_id]["result"] = result
            JOBS[job_id]["status"] = "completed"
            JOBS[job_id]["finished_at"] = _now()
        try:
            asyncio.run(_persist(db, JOBS[job_id]))
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001
        with _JOBS_LOCK:
            JOBS[job_id]["status"] = "failed"
            JOBS[job_id]["finished_at"] = _now()
            JOBS[job_id]["error"] = str(exc)


async def _persist(db: AsyncIOMotorDatabase, job: Dict) -> None:
    doc = {
        "_id": job["id"], "id": job["id"],
        "target": job["target"], "modules": job["modules"],
        "status": job["status"], "created_at": job["created_at"],
        "started_at": job.get("started_at"), "finished_at": job.get("finished_at"),
        "result": job.get("result"), "error": job.get("error"),
        "counts": (job.get("result") or {}).get("vuln", {}).get("counts"),
    }
    await db.bb_scans.replace_one({"_id": doc["_id"]}, doc, upsert=True)


def build_router(db: AsyncIOMotorDatabase) -> APIRouter:

    @router.get("/health")
    async def health() -> Dict[str, str]:
        return {"status": "ok", "service": "bugbounty-toolkit", "version": "1.1.0"}

    @router.get("/exploits")
    async def list_exploits() -> Dict[str, List[str]]:
        return {"available": ALL_EXPLOITS}

    @router.post("/scans", response_model=JobSummary)
    async def create_scan(payload: ScanRequest) -> JobSummary:
        if not payload.i_have_authorization:
            raise HTTPException(status_code=400,
                                detail="Field 'i_have_authorization' must be true to start a scan.")
        bad = [m for m in payload.modules if m not in {"recon", "scan", "vuln"}]
        if bad:
            raise HTTPException(status_code=400, detail=f"Unknown module(s): {bad}")
        if payload.enabled_exploits:
            unknown = [e for e in payload.enabled_exploits if e not in ALL_EXPLOITS]
            if unknown:
                raise HTTPException(status_code=400, detail=f"Unknown exploit(s): {unknown}")

        job_id = str(uuid.uuid4())
        job = {
            "id": job_id, "target": payload.target, "modules": payload.modules,
            "status": "queued", "created_at": _now(),
            "progress": [], "result": None, "error": None,
        }
        with _JOBS_LOCK:
            JOBS[job_id] = job
        threading.Thread(target=_run_job, args=(job_id, payload, db), daemon=True).start()
        return JobSummary(
            id=job_id, target=payload.target, modules=payload.modules,
            status=job["status"], created_at=job["created_at"],
        )

    @router.get("/scans")
    async def list_scans(limit: int = 50) -> List[Dict]:
        running = [
            {
                "id": j["id"], "target": j["target"], "modules": j["modules"],
                "status": j["status"], "created_at": j["created_at"],
                "finished_at": j.get("finished_at"),
                "counts": (j.get("result") or {}).get("vuln", {}).get("counts") if j.get("result") else None,
            }
            for j in JOBS.values()
        ]
        persisted = await db.bb_scans.find(
            {}, {"_id": 0, "result": 0, "progress": 0}
        ).sort("created_at", -1).to_list(limit)
        seen = {j["id"] for j in running}
        for p in persisted:
            if p["id"] not in seen:
                running.append(p)
        running.sort(key=lambda j: j["created_at"], reverse=True)
        return running[:limit]

    @router.get("/scans/{job_id}")
    async def get_scan(job_id: str) -> Dict:
        with _JOBS_LOCK:
            job = JOBS.get(job_id)
        if job:
            return _public_job(job)
        doc = await db.bb_scans.find_one({"_id": job_id}, {"_id": 0})
        if not doc:
            raise HTTPException(status_code=404, detail="Scan not found")
        return doc

    @router.get("/scans/{job_id}/report")
    async def get_report(job_id: str, fmt: str = "txt") -> Dict[str, str]:
        with _JOBS_LOCK:
            job = JOBS.get(job_id)
        if job and job.get("result"):
            return {"format": fmt, "content": report_mod.render(job["result"], fmt)}
        doc = await db.bb_scans.find_one({"_id": job_id}, {"_id": 0})
        if not doc or not doc.get("result"):
            raise HTTPException(status_code=404, detail="Report not ready")
        return {"format": fmt, "content": report_mod.render(doc["result"], fmt)}

    @router.delete("/scans/{job_id}")
    async def delete_scan(job_id: str) -> Dict[str, str]:
        with _JOBS_LOCK:
            JOBS.pop(job_id, None)
        await db.bb_scans.delete_one({"_id": job_id})
        return {"status": "deleted", "id": job_id}

    return router
