"""FastAPI backend for RiskView360 x PWNDORA posture dashboard.

Provides endpoints to retrieve generated learner data and computed posture
metrics. On startup a sample dataset is generated and stored in memory.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.data_generator import generate_users
import app.scoring_engine as scoring_engine


app = FastAPI(title="RiskView360 PWNDORA Backend")

# Enable CORS for local frontend origins
origins = [
    "http://localhost:3000",
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event() -> None:
    """Generate and store one sample dataset in memory on application startup.

    The dataset uses 8 users, `profile='mixed'`, and `seed=42` as requested.
    """
    base_dir = Path(__file__).resolve().parent
    # load config and maps via scoring engine helper
    try:
        config, lab_map, csf_map = scoring_engine._load_json_config_files(base_dir)
    except Exception as exc:  # pragma: no cover - surface startup errors
        raise RuntimeError(f"Failed loading configuration or mapping files: {exc}") from exc

    users = generate_users(n_users=8, seed=42, profile="mixed")

    app.state.users = users
    app.state.generated_at = datetime.utcnow().isoformat() + "Z"
    app.state.config = config
    app.state.lab_map = lab_map
    app.state.csf_map = csf_map


@app.get("/")
async def root() -> Dict[str, str]:
    """Health endpoint returning a simple running message."""
    try:
        return {"message": "RiskView360 x PWNDORA Backend Running"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/users")
async def get_users() -> Dict[str, Any]:
    """Return the generated learners stored in memory."""
    try:
        users = getattr(app.state, "users", None)
        if users is None:
            raise RuntimeError("User dataset not generated yet")
        return {"users": users}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/attack-coverage")
async def get_attack_coverage() -> Dict[str, Any]:
    """Return ATT&CK tactic coverage and identified coverage gaps."""
    try:
        users = app.state.users
        config = app.state.config
        lab_map = app.state.lab_map

        tactic_coverage = scoring_engine.compute_attack_tactic_coverage(users, lab_map, config)
        coverage_gaps = scoring_engine.identify_coverage_gaps(tactic_coverage, threshold=float(config.get("min_score_threshold", 50)))
        return {"tactic_coverage": tactic_coverage, "coverage_gaps": coverage_gaps}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/nist-csf-score")
async def get_nist_csf_score() -> Dict[str, Any]:
    """Return NIST CSF function scores computed from learner data."""
    try:
        users = app.state.users
        config = app.state.config
        csf_map = app.state.csf_map
        csf_scores = scoring_engine.compute_nist_csf_scores(users, csf_map, config)
        return {"csf_scores": csf_scores}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/posture-score")
async def get_posture_score() -> Dict[str, Any]:
    """Return overall posture score, NIST CSF scores, and weekly trend.

    Trend is the average weekly posture proxy score across all users.
    """
    try:
        users: List[Dict[str, Any]] = app.state.users
        config = app.state.config
        csf_map = app.state.csf_map

        csf_scores = scoring_engine.compute_nist_csf_scores(users, csf_map, config)
        overall = scoring_engine.compute_overall_posture_score(csf_scores, config)

        # Compute average weekly trend across users
        weeks = []
        if users and users[0].get("weekly_history"):
            n_weeks = len(users[0]["weekly_history"])
            for w in range(n_weeks):
                vals = [u["weekly_history"][w]["posture_proxy_score"] for u in users]
                weeks.append({"week": w + 1, "average_posture_proxy_score": round(sum(vals) / len(vals), 2)})

        return {"overall_score": overall, "csf_scores": csf_scores, "trend": weeks}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/riskview360/posture-export")
async def get_posture_export() -> Dict[str, Any]:
    """Return a posture export payload including scores, coverage, gaps and recommendations."""
    try:
        users = app.state.users
        config = app.state.config
        lab_map = app.state.lab_map
        csf_map = app.state.csf_map

        tactic_coverage = scoring_engine.compute_attack_tactic_coverage(users, lab_map, config)
        coverage_gaps = scoring_engine.identify_coverage_gaps(tactic_coverage, threshold=float(config.get("min_score_threshold", 50)))
        csf_scores = scoring_engine.compute_nist_csf_scores(users, csf_map, config)
        overall = scoring_engine.compute_overall_posture_score(csf_scores, config)
        recommendations = scoring_engine.recommend_top_labs(users, lab_map, tactic_coverage, n=5)

        payload = {
            "schema_version": "1.0",
            "organisation_posture_score": overall,
            "nist_csf_scores": csf_scores,
            "attack_tactic_coverage": tactic_coverage,
            "coverage_gaps": coverage_gaps,
            "recommended_lab_paths": recommendations,
            "generated_at": app.state.generated_at,
        }
        return payload
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
