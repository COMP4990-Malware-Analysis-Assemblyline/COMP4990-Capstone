SentinelLine Architecture

User -> FastAPI Agent (FSM + policy engine) -> Assemblyline submit/poll -> Result
                                            -> Audit Log (JSONL + escalations queue) -> Dashboard
