"""Build a mapping from PWNDORA lab categories to ATT&CK Enterprise techniques.

Behavior and choices:
- Loads the STIX bundle at `backend/app/data/enterprise-attack.json` and
  builds a lookup of valid technique IDs, names and associated tactic(s).
- For each of the 10 required lab categories (see `CATEGORIES`), the script
  selects 3	6 techniques by matching keywords against technique names. This
  approach keeps the mapping tied to the real STIX content rather than hard
  coding IDs that may drift between ATT&CK versions.
- The script validates every chosen technique ID exists in the STIX bundle and
  raises an exception if any are missing.

Output:
- Writes `backend/app/data/lab_category_to_attack.json` with entries of the
  form {"id": "T####", "name": "...", "tactic": "..."} per technique.
"""

from __future__ import annotations

import json
import os
import re
from collections import OrderedDict
from typing import Dict, List, Tuple


# Exact categories required by the project (order preserved)
CATEGORIES: List[str] = [
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


# Keywords used to find relevant techniques for each category. Comments below
# explain the rationale for the chosen keywords and expected technique types.
CATEGORY_KEYWORDS: Dict[str, List[str]] = {
	# Network scanning: look for service/port/network discovery techniques
	"Network Scanning": ["network", "service discovery", "port", "scan"],
	# Phishing: techniques that mention phishing, spearphish, or user interaction
	"Phishing Simulation": ["phish", "spearph", "user execution", "email"],
	# Password attacks: brute force, credential dumping, password spraying
	"Password Attacks": ["password", "credential", "brute force", "dump"],
	# Privilege escalation: techniques that escalate privileges on host
	"Privilege Escalation": ["privilege", "elevat", "escalat", "exploit"],
	# Lateral movement: remote services, pass-the-hash, remote execution
	"Lateral Movement": ["lateral", "remote", "pass the", "remote services"],
	# Web app exploitation: injection, exploitation of web app vulnerabilities
	"Web Application Exploitation": ["web", "application", "sql", "xss", "cross site"],
	# Persistence: autorun, scheduled task, service creation
	"Persistence": ["persist", "registry run", "startup", "service", "scheduled"],
	# Defense evasion: obfuscation, timestomp, disable security tools
	"Defense Evasion": ["evasion", "obfus", "timestomp", "anti-forensic", "disable"],
	# C2 / Exfiltration: command and control and data exfiltration techniques
	"Command and Control / Exfiltration": ["command and control", "exfil", "c2", "beacon"],
	# Discovery: system, network, process discovery
	"Discovery": ["discover", "discovery", "system discovery", "network service discovery"],
}


def load_stix_bundle(path: str) -> dict:
	if not os.path.exists(path):
		raise FileNotFoundError(f"Enterprise ATT&CK STIX bundle not found: {path}")
	with open(path, "r", encoding="utf-8") as f:
		return json.load(f)


def build_lookups(bundle: dict) -> Dict[str, Dict[str, str]]:
	"""Return a mapping of technique ID -> {name, tactic} from the bundle.

	This scans objects for `external_references` containing MITRE ATT&CK
	technique IDs (e.g. "T1059"). For tactic names we consult `kill_chain_phases`
	when available, otherwise resolve `x_mitre_tactic_refs` against tactic
	objects present in the bundle.
	"""

	objects = bundle.get("objects", [])
	# Build tactic id -> name map
	tactic_map: Dict[str, str] = {}
	for obj in objects:
		if obj.get("type") == "x-mitre-tactic":
			tid = obj.get("id")
			name = obj.get("name")
			if tid and name:
				tactic_map[tid] = name

	techniques: Dict[str, Dict[str, str]] = {}
	for obj in objects:
		# Find MITRE technique external id, if present
		ext_id = None
		for er in obj.get("external_references", []) or []:
			eid = er.get("external_id")
			if isinstance(eid, str) and re.match(r"^T\d{4}$", eid):
				ext_id = eid
				break
		if not ext_id:
			continue

		name = obj.get("name", "")

		# Determine tactic name
		tactic = None
		# Preferred: kill_chain_phases -> phase_name
		kcp = obj.get("kill_chain_phases")
		if kcp:
			# Use the first phase name found
			tactic = kcp[0].get("phase_name")
		else:
			# Fallback: x_mitre_tactic_refs -> map to tactic name
			refs = obj.get("x_mitre_tactic_refs") or obj.get("x_mitre_tactic")
			if isinstance(refs, list) and refs:
				tactic = tactic_map.get(refs[0])

		techniques[ext_id] = {"name": name, "tactic": tactic}

	return techniques


def choose_techniques_for_category(
	category: str,
	keywords: List[str],
	techniques: Dict[str, Dict[str, str]],
	used: set,
	max_per_cat: int = 4,
) -> List[Tuple[str, Dict[str, str]]]:
	"""Select up to `max_per_cat` techniques for a category by keyword match.

	Avoids techniques already present in `used` set to maximize coverage.
	"""

	candidates: List[Tuple[str, Dict[str, str]]] = []
	for tid, info in techniques.items():
		if tid in used:
			continue
		name_low = (info.get("name") or "").lower()
		for kw in keywords:
			if kw in name_low:
				candidates.append((tid, info))
				break

	# Sort for determinism and return top N
	candidates.sort(key=lambda x: x[1].get("name", ""))
	selected = candidates[:max_per_cat]
	for tid, _ in selected:
		used.add(tid)
	return selected


def build_category_mapping(bundle_path: str, out_path: str) -> int:
	bundle = load_stix_bundle(bundle_path)
	techniques = build_lookups(bundle)

	mapping: Dict[str, List[Dict[str, str]]] = OrderedDict()
	used_ids = set()

	# First pass: select up to 4 techniques per category using keywords
	for cat in CATEGORIES:
		keywords = CATEGORY_KEYWORDS.get(cat, [])
		selected = choose_techniques_for_category(cat, keywords, techniques, used_ids, max_per_cat=4)

		# If fewer than 3 were found, do a relaxed search using tactic name matches
		if len(selected) < 3:
			for tid, info in techniques.items():
				if tid in used_ids:
					continue
				tactic = (info.get("tactic") or "").lower() if info.get("tactic") else ""
				for kw in keywords:
					if kw in tactic:
						selected.append((tid, info))
						used_ids.add(tid)
						break
				if len(selected) >= 3:
					break

		# As a last resort, expand selection with any technique that contains any
		# category keyword in its name (even if already matched) but ensure
		# uniqueness by checking `used_ids` above.
		if len(selected) < 3:
			for tid, info in sorted(techniques.items(), key=lambda x: x[1].get("name", "")):
				if tid in used_ids:
					continue
				name_low = (info.get("name") or "").lower()
				if any(kw in name_low for kw in keywords):
					selected.append((tid, info))
					used_ids.add(tid)
				if len(selected) >= 3:
					break

		# Build the final list of dicts for this category
		mapping[cat] = [{"id": tid, "name": info.get("name"), "tactic": info.get("tactic")} for tid, info in selected]

	# Validate all technique IDs exist in the bundle
	missing = [tid for cat in mapping for tid_info in mapping[cat] if (tid := tid_info.get("id")) not in techniques]
	if missing:
		raise RuntimeError(f"Technique IDs missing from the STIX bundle: {sorted(set(missing))}")

	# Write output JSON
	os.makedirs(os.path.dirname(out_path), exist_ok=True)
	with open(out_path, "w", encoding="utf-8") as f:
		json.dump(mapping, f, indent=2, sort_keys=False)

	# Count total mappings
	total = sum(len(v) for v in mapping.values())
	return total


def main() -> None:
	here = os.path.dirname(__file__)
	bundle_path = os.path.abspath(os.path.join(here, "..", "data", "enterprise-attack.json"))
	out_path = os.path.abspath(os.path.join(here, "..", "data", "lab_category_to_attack.json"))

	total = build_category_mapping(bundle_path, out_path)

	print(f"Total mappings generated: {total}")
	if total < 30:
		raise RuntimeError(f"Insufficient mappings generated ({total} < 30). Review keyword selection or STIX bundle content.")
	else:
		print("Confirmed: at least 30 mappings present.")


if __name__ == "__main__":
	main()

