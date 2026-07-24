"""Compute organizational security posture scores for the PWNDORA analytics backend.

This module consumes learner performance data produced by
`data_generator.generate_users()`, ATT&CK mappings in
`lab_category_to_attack.json`, CSF mappings in `nist_csf_mapping.json`, and
threshold/weight configuration from `config.yaml`.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List

import yaml

from app.data_generator import generate_users


ConfigType = Dict[str, Any]
AttackTechnique = Dict[str, Any]
UserType = Dict[str, Any]


def _load_yaml_config(path: Path) -> ConfigType:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        try:
            config = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise ValueError(f"Unable to parse YAML config: {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError(f"Expected config YAML to be a mapping at top level, got {type(config).__name__}")
    return config


def _load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"JSON file not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Unable to parse JSON file {path}: {exc}") from exc


def _validate_config(config: ConfigType) -> None:
    if "nist_csf_function_weights" not in config:
        raise KeyError("Missing required config key: nist_csf_function_weights")
    weights = config["nist_csf_function_weights"]
    if not isinstance(weights, dict):
        raise TypeError("nist_csf_function_weights must be a mapping of function names to weights")

    total = sum(float(weights[f]) for f in weights)
    if not math.isclose(total, 1.0, abs_tol=1e-8):
        raise ValueError("nist_csf_function_weights must sum exactly to 1.0")

    for key in ("min_score_threshold", "coverage_pass_threshold", "overall_score_scale"):
        if key not in config:
            raise KeyError(f"Missing required config key: {key}")

    scale = config["overall_score_scale"]
    if not isinstance(scale, dict) or "min" not in scale or "max" not in scale:
        raise TypeError("overall_score_scale must be a mapping containing 'min' and 'max'")
    if scale["min"] >= scale["max"]:
        raise ValueError("overall_score_scale.min must be less than overall_score_scale.max")


def _normalize_tactic_name(tactic: str) -> str:
    if not isinstance(tactic, str) or not tactic:
        return "Unknown"
    return tactic.replace("-", " ").title()


def _user_category_score(user: UserType, category: str) -> float:
    return float(user.get("scores", {}).get(category, 0.0))


def compute_attack_tactic_coverage(
    users: List[UserType],
    category_to_attack_map: Dict[str, List[AttackTechnique]],
    config: ConfigType,
) -> Dict[str, float]:
    """Return coverage percentage per ATT&CK tactic.

    A mapped technique counts as covered when the highest score achieved for
    its lab category is at or above the configured coverage_pass_threshold.
    """
    _validate_config(config)

    threshold = float(config["coverage_pass_threshold"])
    category_max_scores: Dict[str, float] = {}
    for user in users:
        for category, score in user.get("scores", {}).items():
            previous = category_max_scores.get(category, 0.0)
            category_max_scores[category] = max(previous, float(score))

    tactic_totals: Dict[str, int] = {}
    tactic_covered: Dict[str, int] = {}

    for category, techniques in category_to_attack_map.items():
        category_covered = category_max_scores.get(category, 0.0) >= threshold
        for technique in techniques:
            tactic = _normalize_tactic_name(technique.get("tactic", "Unknown"))
            tactic_totals[tactic] = tactic_totals.get(tactic, 0) + 1
            if category_covered:
                tactic_covered[tactic] = tactic_covered.get(tactic, 0) + 1
            else:
                tactic_covered.setdefault(tactic, tactic_covered.get(tactic, 0))

    coverage: Dict[str, float] = {}
    for tactic, total in tactic_totals.items():
        if total == 0:
            coverage[tactic] = 0.0
            continue
        covered = tactic_covered.get(tactic, 0)
        coverage[tactic] = round((covered / total) * 100.0, 1)
    return coverage


def compute_nist_csf_scores(
    users: List[UserType],
    csf_mapping: Dict[str, str],
    config: ConfigType,
) -> Dict[str, float]:
    """Compute NIST CSF function scores from learner performance data.

    Each category score is attributed to its mapped CSF function. Missing
    category scores are treated as zero.
    """
    _validate_config(config)

    function_categories: Dict[str, List[str]] = {}
    for category, function in csf_mapping.items():
        function_categories.setdefault(function, []).append(category)

    csf_scores: Dict[str, float] = {}
    for function, categories in function_categories.items():
        all_scores: List[float] = []
        for user in users:
            for category in categories:
                all_scores.append(_user_category_score(user, category))
        csf_scores[function] = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0
    return csf_scores


def compute_overall_posture_score(csf_scores: Dict[str, float], config: ConfigType) -> float:
    """Compute the overall posture score using configured NIST CSF weights.

    Returns a single score between the configured overall_score_scale values.
    """
    _validate_config(config)

    weights = config["nist_csf_function_weights"]
    total_score = 0.0
    for function, weight in weights.items():
        if function not in csf_scores:
            raise KeyError(f"Missing CSF score for function: {function}")
        total_score += float(csf_scores[function]) * float(weight)

    scale = config["overall_score_scale"]
    min_scale = float(scale["min"])
    max_scale = float(scale["max"])
    overall_score = max(min_scale, min(max_scale, total_score))
    return round(overall_score, 1)


def identify_coverage_gaps(tactic_coverage: Dict[str, float], threshold: float = 50.0) -> List[str]:
    """Return tactics with coverage below the provided threshold.

    The result is sorted from lowest coverage to highest.
    """
    below_threshold = [tactic for tactic, score in tactic_coverage.items() if score < threshold]
    return sorted(below_threshold, key=lambda tactic: tactic_coverage[tactic])


def recommend_top_labs(
    users: List[UserType],
    category_to_attack_map: Dict[str, List[AttackTechnique]],
    tactic_coverage: Dict[str, float],
    n: int = 5,
) -> List[Dict[str, str]]:
    """Recommend lab categories that should be prioritized to improve coverage.

    Recommendations are based on the weakest tactic coverage associated with
    each lab category.
    """
    recommendations: List[Dict[str, str]] = []
    for category, techniques in category_to_attack_map.items():
        tactic_values: Dict[str, List[float]] = {}
        for technique in techniques:
            tactic = _normalize_tactic_name(technique.get("tactic", "Unknown"))
            tactic_values.setdefault(tactic, []).append(tactic_coverage.get(tactic, 0.0))

        if not tactic_values:
            continue

        target_tactic = min(tactic_values, key=lambda t: sum(tactic_values[t]) / len(tactic_values[t]))
        average_coverage = sum(tactic_values[target_tactic]) / len(tactic_values[target_tactic])
        reason = (
            f"Focus on {category} because techniques mapped to '{target_tactic}' "
            f"have an average coverage of {average_coverage:.1f}% and represent an opportunity to improve."
        )
        recommendations.append(
            {
                "lab_category": category,
                "reason": reason,
                "target_tactic": target_tactic,
            }
        )

    recommendations.sort(key=lambda item: tactic_coverage.get(item["target_tactic"], 0.0))
    return recommendations[:n]


def _load_json_config_files(base_dir: Path) -> tuple[ConfigType, Dict[str, List[AttackTechnique]], Dict[str, str]]:
    config_path = base_dir / "config.yaml"
    lab_map_path = base_dir / "data" / "lab_category_to_attack.json"
    csf_map_path = base_dir / "data" / "nist_csf_mapping.json"

    config = _load_yaml_config(config_path)
    lab_map = _load_json(lab_map_path)
    csf_map = _load_json(csf_map_path)

    if not isinstance(lab_map, dict):
        raise TypeError("lab_category_to_attack.json must contain a mapping of category names to attack techniques")
    if not isinstance(csf_map, dict):
        raise TypeError("nist_csf_mapping.json must contain a mapping of category names to NIST CSF functions")

    return config, lab_map, csf_map


def _print_json(title: str, value: Any) -> None:
    print(f"\n{title}")
    print(json.dumps(value, indent=2, sort_keys=True))


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent
    config, lab_map, csf_map = _load_json_config_files(base_dir)

    strong_users = generate_users(profile="strong_team")
    weak_users = generate_users(profile="weak_team")

    strong_tactic_coverage = compute_attack_tactic_coverage(strong_users, lab_map, config)
    strong_csf_scores = compute_nist_csf_scores(strong_users, csf_map, config)
    strong_overall = compute_overall_posture_score(strong_csf_scores, config)

    weak_tactic_coverage = compute_attack_tactic_coverage(weak_users, lab_map, config)
    weak_csf_scores = compute_nist_csf_scores(weak_users, csf_map, config)
    weak_overall = compute_overall_posture_score(weak_csf_scores, config)

    print("Strong Team Score:", strong_overall)
    print("Weak Team Score:", weak_overall)

    print("PASS" if abs(strong_overall - weak_overall) >= 15.0 else "FAIL")
