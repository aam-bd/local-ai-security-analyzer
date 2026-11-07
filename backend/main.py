"""
FastAPI Backend Application for Local AI Security Log Analyzer.
Serves REST endpoints, Server-Sent Events (SSE) for real-time progress streaming,
system telemetry, model management, and frontend assets.
"""
import os
import json
import asyncio
from typing import Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from backend.schemas import AnalysisReport, SystemMetrics
from backend.analyzer import pipeline
from backend.model_manager import model_manager
from backend.telemetry import telemetry

app = FastAPI(
    title="Local AI Security Log Analyzer",
    description="Resource-constrained AI Security Log Analyzer running locally within 4 GB RAM.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
current_active_file: Optional[str] = "Cultive8_Workspace_Agrigen_Server.log"

@app.post("/api/upload")
async def upload_log_file(file: UploadFile = File(...)):
    """Accepts .log or .txt files, validates extension and size, and stages for analysis."""
    global current_active_file
    filename = file.filename or "uploaded.log"
    if not (filename.endswith(".log") or filename.endswith(".txt")):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .log and .txt files are accepted.")

    dest_path = os.path.join(UPLOAD_DIR, filename)
    total_bytes = 0
    with open(dest_path, "wb") as buffer:
        while chunk := await file.read(1024 * 1024):  # 1 MB buffer
            total_bytes += len(chunk)
            if total_bytes > 50 * 1024 * 1024:  # 50 MB safety limit
                raise HTTPException(status_code=413, detail="File too large. Maximum supported size is 50 MB.")
            buffer.write(chunk)

    current_active_file = dest_path
    return {
        "status": "success",
        "filename": filename,
        "size_bytes": total_bytes,
        "message": "File uploaded and staged for analysis."
    }

@app.post("/api/load-sample")
async def load_sample_log():
    """Staging endpoint for the provided benchmark log."""
    global current_active_file
    sample_file = "Cultive8_Workspace_Agrigen_Server.log"
    if not os.path.exists(sample_file):
        raise HTTPException(status_code=404, detail="Sample log file not found in workspace.")
    current_active_file = sample_file
    size = os.path.getsize(sample_file)
    return {
        "status": "success",
        "filename": sample_file,
        "size_bytes": size,
        "message": "Benchmark log loaded successfully."
    }

@app.get("/api/analyze/stream")
async def stream_analysis(
    resume_from: int = Query(1, ge=1),
    reduce_calls: bool = Query(False),
    lines_per_chunk: int = Query(8, ge=2, le=50),
    max_log_tokens: int = Query(1350, ge=500, le=1400)
):
    """Server-Sent Events (SSE) streaming real-time analysis progress."""
    global current_active_file
    if not current_active_file or not os.path.exists(current_active_file):
        raise HTTPException(status_code=400, detail="No active log file selected. Upload a file or load sample first.")

    target_file = current_active_file

    async def event_generator():
        for event in pipeline.analyze_file_streaming(
            target_file,
            resume_from_chunk=resume_from,
            reduce_calls=reduce_calls,
            lines_per_chunk=lines_per_chunk,
            max_log_tokens=max_log_tokens
        ):
            data_str = json.dumps(event)
            yield f"data: {data_str}\n\n"
            await asyncio.sleep(0.01)  # Yield control to event loop

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/report")
async def get_latest_report():
    """Returns the latest finalized security report."""
    if not pipeline.last_report:
        raise HTTPException(status_code=404, detail="No analysis report has been generated yet.")
    return pipeline.last_report

@app.get("/api/metrics", response_model=SystemMetrics)
async def get_metrics():
    """Returns live server resource telemetry (RAM MB, % of 4GB, CPU %, tokens)."""
    return telemetry.get_system_metrics()

@app.get("/api/models")
async def list_models():
    """Lists available local models and active backend."""
    models_dir = "models"
    local_files = []
    if os.path.exists(models_dir):
        local_files = [f for f in os.listdir(models_dir) if f.endswith(".gguf")]

    return {
        "active_backend": model_manager.active_backend,
        "active_model": model_manager.current_model_name,
        "available_gguf_files": local_files,
        "http_endpoint": model_manager.http_endpoint
    }

@app.post("/api/models/select")
async def select_model(backend: str, model_file: Optional[str] = None):
    """Switch active model backend (llama_cpp, openai_http, or simulation)."""
    if backend == "llama_cpp" and model_file:
        full_path = os.path.join("models", model_file)
        if not os.path.exists(full_path):
            raise HTTPException(status_code=404, detail=f"Model file {model_file} not found.")
        model_manager.load_gguf_model(full_path)
    elif backend in ["openai_http", "simulation"]:
        model_manager.active_backend = backend
        model_manager.current_model_name = "Ollama Local Service" if backend == "openai_http" else "Offline Security Analyzer (Simulation)"
        telemetry.set_model_name(model_manager.current_model_name)
    else:
        raise HTTPException(status_code=400, detail="Invalid backend selection.")

    return {
        "status": "success",
        "active_backend": model_manager.active_backend,
        "active_model": model_manager.current_model_name
    }

# Mount frontend directory for static UI serving
if os.path.exists("frontend"):
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)

