1. docker compose up -d
2. Open http://localhost:8000/docs
3. POST /submit with benign.txt
4. POST /submit with suspicious_simulated.bin
5. Show response fields:
	- final_report.analysis_summary.routing_decision
	- final_report.analysis_summary.analysis_policy
	- status (complete or pending_human_review)
6. Open http://localhost:8501 to view:
	- Trace Overview
	- Needs Analyst Review
	- Escalation Queue Log
