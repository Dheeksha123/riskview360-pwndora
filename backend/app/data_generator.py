"""Generate realistic simulated PWNDORA learner performance data.

Provides functions to synthesize per-user lab completion, scores, failure
topics, and 8-week weekly history suitable for analytics and testing.

Functions
- generate_users(n_users=8, seed=42, profile="mixed") -> List[dict]
- generate_dataset_file(path, n_users=8, seed=42, profile="mixed")

The generator uses both Python's `random` and `numpy` for reproducible
behavior. Profiles bias overall performance: `strong_team` produces high
scores and completion rates, `weak_team` produces low scores, and `mixed`
creates a wide spread.
"""

from __future__ import annotations

import json
import math
import random
from typing import Dict, List, Tuple

import numpy as np


# Fixed list of lab categories used by PWNDORA training labs
LAB_CATEGORIES: List[str] = [
    "Network Scanning",
    "Phishing Simulation",
    "Password Attacks",
    "Privilege Escalation",
    "Lateral Movement",
    "Web Application Exploitation",
    "Persistence",
    "Defense Evasion",
    "Command and Control / Exfiltration",
    "Discovery",
]


_PLACEHOLDER_NAMES = [
    "Ava Thompson",
    "Liam Johnson",
    "Olivia Martinez",
    "Noah Smith",
    "Emma Davis",
    "Lucas Brown",
    "Mia Wilson",
    "Ethan Taylor",
    "Sophia Anderson",
    "Mason Thomas",
    "Isabella Jackson",
    "Logan White",
    "Charlotte Harris",
    "James Martin",
    "Amelia Thompson",
    "Benjamin Garcia",
]


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _format_user_id(idx: int) -> str:
    return f"user_{idx:02d}"


def _choose_name(rng: random.Random, idx: int) -> str:
    # Choose a realistic placeholder name with deterministic randomness
    return rng.choice(_PLACEHOLDER_NAMES)


def _profile_params(profile: str) -> Dict[str, float]:
    """Return distribution parameters influenced by profile.

    Returns a dict with keys:
    - base_mean: baseline mean score (0-100)
    - base_std: baseline stddev for scores
    - completion_mean: mean completion rate (0-1)
    - completion_std: stddev for completion rate
    - improvement_range: expected total improvement over 8 weeks
    """

    if profile == "strong_team":
        return {
            "base_mean": 80.0,
            "base_std": 8.0,
            "completion_mean": 0.85,
            "completion_std": 0.08,
            "improvement_range": 5.0,
        }
    if profile == "weak_team":
        return {
            "base_mean": 40.0,
            "base_std": 12.0,
            "completion_mean": 0.35,
            "completion_std": 0.12,
            "improvement_range": 18.0,
        }
    # mixed
    return {
        "base_mean": 60.0,
        "base_std": 18.0,
        "completion_mean": 0.55,
        "completion_std": 0.20,
        "improvement_range": 10.0,
    }


def _generate_weekly_history(
    rng: np.random.Generator, base_score: float, improvement: float, weeks: int = 8
) -> List[Dict[str, float]]:
    """Generate an upward-trending weekly posture proxy with noise.

    base_score is 0-100 initial value; improvement is total increase over
    `weeks`. Returns a list of dicts with keys `week` and
    `posture_proxy_score`.
    """

    history: List[Dict[str, float]] = []
    for w in range(1, weeks + 1):
        trend = base_score + (improvement * (w - 1) / (weeks - 1))
        noise = rng.normal(0, max(1.0, improvement * 0.08))
        score = float(max(0.0, min(100.0, trend + noise)))
        history.append({"week": w, "posture_proxy_score": score})
    return history


def _generate_user_scores(
    rng: np.random.Generator, base_mean: float, base_std: float, completion_rate: float
) -> Tuple[List[str], Dict[str, float]]:
    """Select completed labs and generate per-lab scores.

    Returns (labs_completed, scores).
    """

    n_labs = len(LAB_CATEGORIES)
    # Determine number of completed labs from completion_rate
    n_completed = int(round(_clamp01(completion_rate) * n_labs))
    n_completed = max(0, min(n_labs, n_completed))

    # Choose which labs were completed
    completed_indices = np.arange(n_labs)
    rng_idx = rng.permutation(completed_indices)
    chosen = list(rng_idx[:n_completed])
    labs_completed = [LAB_CATEGORIES[i] for i in sorted(chosen)]

    scores: Dict[str, float] = {}
    for lab in labs_completed:
        # sample score from normal distribution with clamping to 0-100
        raw = rng.normal(loc=base_mean, scale=base_std)
        # add small per-lab variability
        per_lab_noise = rng.normal(0, base_std * 0.15)
        val = float(max(0.0, min(100.0, raw + per_lab_noise)))
        scores[lab] = round(val, 1)

    return labs_completed, scores


def generate_users(n_users: int = 8, seed: int = 42, profile: str = "mixed") -> List[Dict]:
    """Generate a list of simulated users with performance data.

    Parameters
    - n_users: number of users to generate (default 8)
    - seed: random seed for reproducibility
    - profile: one of "strong_team", "weak_team", or "mixed" to bias
      generated results.

    Returns a list of dicts representing users.
    """

    if profile not in ("strong_team", "weak_team", "mixed"):
        raise ValueError("profile must be one of 'strong_team', 'weak_team', or 'mixed'")

    # Seed both random and numpy's Generator for reproducibility
    random.seed(seed)
    rng = np.random.default_rng(seed)

    params = _profile_params(profile)
    users: List[Dict] = []

    for i in range(1, n_users + 1):
        user_id = _format_user_id(i)
        name = _choose_name(random, i)

        # per-user skill modifier
        skill_mod = float(rng.normal(0, params["base_std"] * 0.6))

        base_mean = params["base_mean"] + skill_mod
        base_std = max(4.0, params["base_std"] * (0.8 + rng.random() * 0.8))

        # completion rate sampled and clamped
        completion_rate = float(_clamp01(rng.normal(loc=params["completion_mean"], scale=params["completion_std"])))

        labs_completed, scores = _generate_user_scores(rng, base_mean, base_std, completion_rate)

        failure_topics = [lab for lab, s in scores.items() if s < 50.0]

        # weekly history: start around user's mean score, improvement depends on profile
        user_mean_score = float(np.mean(list(scores.values())) if scores else base_mean)
        improvement = float(params["improvement_range"] * (0.5 + rng.random() * 0.9))
        weekly_history = _generate_weekly_history(rng, user_mean_score, improvement, weeks=8)

        user = {
            "user_id": user_id,
            "name": name,
            "labs_completed": labs_completed,
            "scores": scores,
            "failure_topics": failure_topics,
            "completion_rate": round(completion_rate, 3),
            "weekly_history": weekly_history,
        }
        users.append(user)

    return users


def generate_dataset_file(path: str, n_users: int = 8, seed: int = 42, profile: str = "mixed") -> None:
    """Generate dataset and write to `path` as formatted JSON.

    The output contains the top-level key "users" mapping to the list of
    generated user dicts.
    """

    users = generate_users(n_users=n_users, seed=seed, profile=profile)
    out = {"users": users}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=False)


if __name__ == "__main__":
    # Sanity run when executed directly
    sample = generate_users()
    # Pretty-print one user for quick inspection
    import pprint

    pprint.pprint(sample[0])
