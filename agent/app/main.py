from fastapi import FastAPI, UploadFile
from fastapi.responses import JSONResponse
from .fsm import run_fsm

app = FastAPI(title="SentinelLine Agent")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/submit")
async def submit(file: UploadFile):
    """
    Submit a file for malware analysis.
    
    Processes the file through the complete FSM pipeline and returns
    a comprehensive analysis report with recommendation.
    """
    try:
        content = await file.read()
        result = run_fsm(file.filename, content)
        return JSONResponse(content=result, status_code=200)
    except Exception as e:
        return JSONResponse(
            content={
                "error": str(e),
                "error_type": type(e).__name__
            },
            status_code=500
        )
