"""
rubric.py

Deterministic scoring rubric for the VM Risk Agent.

Pipeline: cull findings → score survivors → attach LLM rationales → return sorted list.

Math is deterministic Python. The LLM (Sonnet 4.6) only writes the rationale
text for each scored finding — it never picks the number.

Score formula:
    cvss_norm        = CVSS / 10
    headroom         = 1.0 - cvss_norm
    base_likelihood  = min(1.0, cvss_norm + headroom * (exposure_boost + exploit_boost))
    material_cost    = (asset_criticality * 0.4) + (data_sensitivity * 0.4) + (CIA_weight * 0.2)
    raw_score        = base_likelihood * material_cost
    adjusted_score   = raw_score * (1 - defense_adjustment)
    final_score      = adjusted_score * org_context_modifier
"""

import re

import anthropic

from keys import ANTHROPIC_API_KEY
from prompt_management import (
    CULL_CVSS_THRESHOLD,
    BUCKET_THRESHOLDS,
    CONFIDENCE_THRESHOLDS,
    get_question_by_id,
)

_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
RATIONALE_MODEL = "claude-sonnet-4-6"


# ============================================================================
# CONSTANTS
# ============================================================================

DEFENSE_ADJUSTMENT_CAP = 0.50

# Headroom-based boosts for base_likelihood.
# CVSS is the floor; exposure and exploit close a fraction of the remaining
# headroom up to 1.0. This avoids the cap-eats-the-signal problem where
# multipliers collapse to 1.0 on internet-facing high-CVSS findings.
EXPOSURE_BOOST = {
    1.0: 0.00,   # internal only
    1.3: 0.05,   # DMZ
    1.5: 0.10,   # internet-facing
}

EXPLOIT_MULTIPLIERS = {
    "metasploit": 1.5,
    "poc": 1.3,
    "none": 1.0,
}

EXPLOIT_BOOST = {
    "metasploit": 0.20,
    "poc": 0.10,
    "none": 0.00,
}

CIA_WEIGHTS = {
    "code_execution": 1.0,
    "confidentiality": 0.8,
    "integrity": 0.7,
    "availability": 0.5,
}

CIA_FALLBACK = "code_execution"  # most cautious default when vector unparseable

ORG_CONTEXT_WEIGHTS = {
    "regulatory_pressure": 0.5,
    "uptime_sensitivity": 0.3,
    "incident_history": 0.2,
}

MATERIAL_COST_WEIGHTS = {
    "asset_criticality": 0.4,
    "data_sensitivity": 0.4,
    "cia": 0.2,
}

PLACEHOLDER_RATIONALE = "[rationale pending — Pass 2 will wire LLM call]"


# ============================================================================
# CVSS VECTOR PARSING
# ============================================================================

def parse_cvss_vector(vector_string):
    """
    Parse a CVSS v3.x vector string into a dict of components.
    Example input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    Returns dict like {"AV": "N", "AC": "L", ..., "C": "H", "I": "H", "A": "H"}
    Returns empty dict if vector is malformed.
    """
    if not isinstance(vector_string, str) or not vector_string.startswith("CVSS:"):
        return {}
    components = {}
    parts = vector_string.split("/")
    for part in parts[1:]:
        if ":" in part:
            key, _, value = part.partition(":")
            components[key.strip()] = value.strip()
    return components


def derive_cia_category(vector_string):
    """
    Map a CVSS vector to one of four CIA categories used by the rubric.
    Returns (category, cia_weight, fallback_used_flag).

    Rules:
      - S:C (scope changed) OR 2+ of C/I/A are H → code_execution (1.0)
      - else C:H dominant → confidentiality (0.8)
      - else I:H dominant → integrity (0.7)
      - else A:H dominant → availability (0.5)
      - vector unparseable or no signal → fallback (code_execution, 1.0) + flag
    """
    components = parse_cvss_vector(vector_string)
    if not components:
        return CIA_FALLBACK, CIA_WEIGHTS[CIA_FALLBACK], True

    scope_changed = components.get("S") == "C"
    c_high = components.get("C") == "H"
    i_high = components.get("I") == "H"
    a_high = components.get("A") == "H"
    high_count = sum([c_high, i_high, a_high])

    if scope_changed or high_count >= 2:
        return "code_execution", CIA_WEIGHTS["code_execution"], False
    if c_high:
        return "confidentiality", CIA_WEIGHTS["confidentiality"], False
    if i_high:
        return "integrity", CIA_WEIGHTS["integrity"], False
    if a_high:
        return "availability", CIA_WEIGHTS["availability"], False

    # No high-impact signal — fall back to most cautious
    return CIA_FALLBACK, CIA_WEIGHTS[CIA_FALLBACK], True


# ============================================================================
# INTERVIEW RESULT ACCESS
# ============================================================================

def get_interview_value(interview_results, question_id, default=None):
    """Pull the .value field from an interview result entry. Returns default if missing/None."""
    entry = interview_results.get(question_id)
    if entry is None:
        return default
    value = entry.get("value")
    return value if value is not None else default


def get_interview_option_id(interview_results, question_id):
    """Pull the .option_id field from an interview result entry."""
    entry = interview_results.get(question_id)
    if entry is None:
        return None
    return entry.get("option_id")


def get_interview_confidence(interview_results, question_id):
    """Pull confidence value for a question. Returns 0.0 if missing."""
    entry = interview_results.get(question_id)
    if entry is None:
        return 0.0
    return entry.get("confidence", 0.0)


# ============================================================================
# CULL STAGE
# ============================================================================

def is_out_of_scope(finding, interview_results):
    """
    Check if this finding hits an out-of-scope asset.
    Interview captures whether any assets are out of scope; specific host list
    would need a follow-up capture. For Pass 1, we honor an explicit
    'out_of_scope_hosts' list on the finding if the interview flagged 'some'.
    """
    if get_interview_option_id(interview_results, "out_of_scope_assets") != "some":
        return False
    out_of_scope_hosts = finding.get("out_of_scope", False)
    return bool(out_of_scope_hosts)


def is_already_mitigated(finding, interview_results):
    """Check if this finding is already mitigated per interview + finding flag."""
    if get_interview_option_id(interview_results, "already_mitigated") != "some":
        return False
    return bool(finding.get("mitigated", False))


def cull_findings(findings, interview_results):
    """
    Apply the 4 cull rules. Returns (survivors, culled_log).
    culled_log is a list of dicts: {finding_id, reason}.
    """
    survivors = []
    culled = []

    for finding in findings:
        fid = finding.get("id", "<no id>")
        cvss = finding.get("cvss", 0.0)
        exploit_status = finding.get("exploit_status", "none")
        severity = finding.get("severity", "").lower()

        if severity == "informational":
            culled.append({"finding_id": fid, "reason": "informational severity"})
            continue

        if cvss < CULL_CVSS_THRESHOLD and exploit_status == "none":
            culled.append({
                "finding_id": fid,
                "reason": f"CVSS {cvss} < {CULL_CVSS_THRESHOLD} and no exploit available",
            })
            continue

        if is_out_of_scope(finding, interview_results):
            culled.append({"finding_id": fid, "reason": "asset out of scope per interview"})
            continue

        if is_already_mitigated(finding, interview_results):
            culled.append({"finding_id": fid, "reason": "already mitigated per interview"})
            continue

        survivors.append(finding)

    return survivors, culled


# ============================================================================
# SCORING COMPONENTS
# ============================================================================

def compute_base_likelihood(finding, interview_results):
    """
    Headroom-based likelihood.

      cvss_normalized = CVSS / 10
      headroom        = 1.0 - cvss_normalized
      total_boost     = exposure_boost + exploit_boost
      base_likelihood = min(1.0, cvss_normalized + headroom * total_boost)

    Exposure and exploit close a fraction of the remaining headroom toward 1.0.
    This guarantees differentiation across the full CVSS range — unlike a
    multiplicative formula, the boosts cannot be eaten by a cap when CVSS is
    already high.

    Returns (base_likelihood, exploit_mult_for_reporting, exposure_mult_for_reporting).
    The reporting multipliers are kept for backwards compatibility with the
    rationale prompt; they describe the *category* of signal, not the math used.
    """
    cvss = finding.get("cvss", 0.0)
    exploit_status = finding.get("exploit_status", "none")
    exposure_mult = get_interview_value(interview_results, "exposure", 1.0)

    cvss_norm = cvss / 10.0
    headroom = max(0.0, 1.0 - cvss_norm)
    exposure_boost = EXPOSURE_BOOST.get(exposure_mult, 0.0)
    exploit_boost = EXPLOIT_BOOST.get(exploit_status, 0.0)
    total_boost = exposure_boost + exploit_boost

    base = min(1.0, cvss_norm + headroom * total_boost)

    # Reporting values for the rationale prompt (category labels, not math factors)
    exploit_mult_label = EXPLOIT_MULTIPLIERS.get(exploit_status, 1.0)
    return base, exploit_mult_label, exposure_mult


def compute_material_cost(finding, interview_results):
    """material_cost = (asset * 0.4) + (data * 0.4) + (cia * 0.2)"""
    asset = get_interview_value(interview_results, "asset_criticality", 0.6)
    data = get_interview_value(interview_results, "data_sensitivity", 0.6)
    category, cia_weight, cia_fallback_used = derive_cia_category(finding.get("cvss_vector", ""))

    cost = (
        asset * MATERIAL_COST_WEIGHTS["asset_criticality"]
        + data * MATERIAL_COST_WEIGHTS["data_sensitivity"]
        + cia_weight * MATERIAL_COST_WEIGHTS["cia"]
    )
    return cost, asset, data, category, cia_weight, cia_fallback_used


def compute_defense_adjustment(interview_results):
    """Sum of four defense dimensions, capped at DEFENSE_ADJUSTMENT_CAP."""
    dims = ["patching_maturity", "segmentation_zerotrust", "detection_response", "resilience"]
    total = 0.0
    breakdown = {}
    for dim in dims:
        value = get_interview_value(interview_results, dim, 0.0) or 0.0
        breakdown[dim] = value
        total += value
    capped = min(total, DEFENSE_ADJUSTMENT_CAP)
    return capped, breakdown, (total > DEFENSE_ADJUSTMENT_CAP)


def compute_org_context_modifier(interview_results):
    """org_modifier = (reg * 0.5) + (uptime * 0.3) + (incident * 0.2)"""
    reg = get_interview_value(interview_results, "regulatory_pressure", 1.0)
    uptime = get_interview_value(interview_results, "uptime_sensitivity", 1.0)
    incident = get_interview_value(interview_results, "incident_history", 1.0)

    modifier = (
        reg * ORG_CONTEXT_WEIGHTS["regulatory_pressure"]
        + uptime * ORG_CONTEXT_WEIGHTS["uptime_sensitivity"]
        + incident * ORG_CONTEXT_WEIGHTS["incident_history"]
    )
    return modifier, reg, uptime, incident


# ============================================================================
# BUCKETING
# ============================================================================

def bucket_score(score):
    """Map a final score to a bucket label per BUCKET_THRESHOLDS."""
    if score >= BUCKET_THRESHOLDS["critical"]:
        return "critical"
    if score >= BUCKET_THRESHOLDS["high"]:
        return "high"
    if score >= BUCKET_THRESHOLDS["medium"]:
        return "medium"
    if score >= BUCKET_THRESHOLDS["low"]:
        return "low"
    return "filtered"


# ============================================================================
# CONFIDENCE
# ============================================================================

# Which interview questions feed each finding's score
SCORE_INPUT_QUESTIONS = [
    "regulatory_pressure",
    "uptime_sensitivity",
    "incident_history",
    "asset_criticality",
    "data_sensitivity",
    "exposure",
    "patching_maturity",
    "segmentation_zerotrust",
    "detection_response",
    "resilience",
]


def compute_confidence(interview_results):
    """Average confidence across all questions that feed scoring. Returns (avg, label)."""
    confidences = [get_interview_confidence(interview_results, qid) for qid in SCORE_INPUT_QUESTIONS]
    avg = sum(confidences) / len(confidences) if confidences else 0.0
    if avg >= CONFIDENCE_THRESHOLDS["high"]:
        label = "high"
    elif avg >= CONFIDENCE_THRESHOLDS["medium"]:
        label = "medium"
    else:
        label = "low"
    return avg, label


# ============================================================================
# BUCKET → RECOMMENDED ACTION MAP (rubric design Section 9)
# ============================================================================

BUCKET_ACTIONS = {
    "critical": "Patch immediately; if patch unavailable, mitigate with compensating controls.",
    "high": "Patch in next cycle; mitigate if patching is blocked.",
    "medium": "Patch in normal cadence; consider systemic measures.",
    "low": "Track; risk-accept with documentation if patching cost exceeds impact.",
    "filtered": "Filtered out (below scoring floor).",
}


# ============================================================================
# RATIONALE PROMPT BUILDER (Pass 2a — no API call yet)
# ============================================================================

def _format_interview_answer_for_prompt(interview_results, question_id):
    """
    Build a one-line description of how the analyst answered a single question.
    Includes verbatim free-form text when present (rubric design Section 8).
    Returns None if the question wasn't answered.
    """
    entry = interview_results.get(question_id)
    if entry is None:
        return None

    question = get_question_by_id(question_id)
    if question is None:
        return None

    raw = entry.get("raw_answer", {})
    answer_type = raw.get("type")
    option_id = entry.get("option_id")
    value = entry.get("value")
    confidence = entry.get("confidence", 0.0)

    # Look up the option label
    option_label = "<unknown>"
    if option_id is not None:
        opt = next((o for o in question["options"] if o["id"] == option_id), None)
        if opt is not None:
            option_label = opt["label"]

    line = f"  - {question['prompt']}\n"
    line += f"    Answer: {option_label} (option_id={option_id}, value={value})"

    if answer_type == "override":
        free_text = raw.get("free_form_text", "")
        line += f"\n    Analyst wrote (verbatim): \"{free_text}\""
        line += f"\n    [Interpreted by LLM from override; confidence={confidence}]"
    elif answer_type == "unsure_with_context":
        free_text = raw.get("free_form_text", "")
        line += f"\n    Analyst was unsure but added context (verbatim): \"{free_text}\""
        line += f"\n    [Interpreted from unsure-with-context; confidence={confidence}]"
    elif answer_type == "unsure_no_context":
        line += f"\n    Analyst marked 'not sure' with no context; conservative default applied."
        line += f"\n    [confidence={confidence}]"
    elif answer_type == "skipped":
        line += f"\n    Analyst skipped; default used."
        line += f"\n    [confidence={confidence}]"
    else:
        line += f"\n    [structured pick; confidence={confidence}]"

    # Defense sub-picks
    sub_picks = entry.get("sub_picks")
    if sub_picks is not None and question["category"] == "defense":
        opt = next((o for o in question["options"] if o["id"] == option_id), None)
        if opt is not None and "sub_questions" in opt:
            total = len(opt["sub_questions"])
            checked = len(sub_picks)
            line += f"\n    Sub-checklist: {checked}/{total} practices checked"
            if sub_picks:
                checked_items = [opt["sub_questions"][i - 1] for i in sub_picks if 1 <= i <= total]
                for item in checked_items:
                    line += f"\n      ✓ {item}"

    return line


# Which questions feed which scoring components (for grouping in the prompt)
COMPONENT_QUESTIONS = {
    "Base Likelihood": ["exposure"],
    "Material Cost": ["asset_criticality", "data_sensitivity"],
    "Defense Adjustment": [
        "patching_maturity",
        "segmentation_zerotrust",
        "detection_response",
        "resilience",
    ],
    "Org Context Modifier": [
        "regulatory_pressure",
        "uptime_sensitivity",
        "incident_history",
    ],
}


def build_rationale_prompt(scored_finding, interview_results):
    """
    Build the user-message prompt for the rationale LLM call.
    Returns a single string. No API call here — just the prompt.
    """
    sub = scored_finding["sub_scores"]
    si = scored_finding["score_inputs"]
    bucket = scored_finding["bucket"]
    action = BUCKET_ACTIONS.get(bucket, "")

    flags = []
    if si.get("cia_fallback_used"):
        flags.append(
            "CIA category fell back to most-cautious default (code_execution, 1.0) because "
            "the CVSS vector did not signal a clear primary impact. Flag this in the rationale."
        )
    if si.get("defense_capped"):
        flags.append(
            "Defense adjustment hit the 0.50 cap — raw sum of defense dimensions exceeded the floor. "
            "Mention this so the analyst knows the score didn't get reduced as much as the inputs suggested."
        )
    if scored_finding["confidence_label"] != "high":
        flags.append(
            f"Confidence on this finding is {scored_finding['confidence_label'].upper()} "
            f"(avg {scored_finding['confidence_avg']}). Name which interview answers were uncertain "
            f"and recommend re-verification."
        )

    parts = []
    parts.append("FINDING")
    parts.append(f"  ID: {scored_finding['id']}")
    parts.append(f"  Title: {scored_finding['title']}")
    parts.append(f"  Host: {scored_finding['host']}")
    parts.append(f"  CVSS: {scored_finding['cvss']}  Vector: {scored_finding['cvss_vector']}")
    parts.append(f"  Exploit status: {scored_finding['exploit_status']}")
    parts.append("")
    parts.append("SCORE")
    parts.append(f"  Final score: {scored_finding['score']} → bucket: {bucket.upper()}")
    parts.append(f"  Recommended action (from bucket map): {action}")
    parts.append("")
    parts.append("SUB-SCORE BREAKDOWN")
    parts.append(f"  base_likelihood   = {sub['base_likelihood']}  "
                 f"(CVSS/10 × exploit_mult {si['exploit_mult']} × exposure_mult {si['exposure_mult']})")
    parts.append(f"  material_cost     = {sub['material_cost']}  "
                 f"(asset {si['asset_criticality']} × 0.4 + data {si['data_sensitivity']} × 0.4 + "
                 f"CIA {si['cia_weight']} × 0.2)")
    parts.append(f"  raw_score         = {sub['raw_score']}  (base_likelihood × material_cost)")
    defense_cap_note = "  (capped at 0.50)" if si.get("defense_capped") else ""
    parts.append(f"  defense_adjustment= {sub['defense_adjustment']}{defense_cap_note}")
    parts.append(f"  adjusted_score    = {sub['adjusted_score']}  (raw × (1 - defense_adjustment))")
    parts.append(f"  org_context_mod   = {sub['org_context_modifier']}")
    parts.append(f"  final_score       = {sub['final_score']}  (adjusted × org_context_mod)")
    parts.append(f"  CIA category: {si['cia_category']} (weight {si['cia_weight']})")
    parts.append("")
    parts.append("INTERVIEW ANSWERS THAT DROVE THIS SCORE")
    for component, qids in COMPONENT_QUESTIONS.items():
        parts.append(f"  [{component}]")
        for qid in qids:
            line = _format_interview_answer_for_prompt(interview_results, qid)
            if line is not None:
                parts.append(line)
        parts.append("")

    if flags:
        parts.append("FLAGS TO ADDRESS IN RATIONALE")
        for f in flags:
            parts.append(f"  - {f}")
        parts.append("")

    parts.append("TASK")
    parts.append(
        "  Write the rationale text that will appear under this finding in the report. "
        "Constraints:\n"
        "  - 3 to 5 sentences. Analyst voice, plain English, no hedging filler.\n"
        "  - Lead by naming the 2-3 factors that most drove the score (which sub-scores, which interview answers).\n"
        "  - When an answer came from a free-form override or unsure-with-context, quote the analyst's "
        "verbatim text in the rationale so they can verify what was captured.\n"
        "  - Address every flag listed above.\n"
        "  - End with the recommended action verbatim from the bucket map.\n"
        "  - Do NOT restate the score number — the report shows it separately.\n"
        "  Output via the write_rationale tool."
    )

    return "\n".join(parts)


# ============================================================================
# RATIONALE LLM CALL (Pass 2b)
# ============================================================================

RATIONALE_SYSTEM_PROMPT = """You are a senior vulnerability management analyst writing the rationale section for a single finding in a remediation report.

Your job: read the score breakdown and interview context, then write 3-5 sentences in plain analyst voice that explain why this finding scored where it did.

Rules:
- Lead with the 2-3 factors that most drove the score. Be specific (name the sub-score AND the interview answer behind it).
- When the inputs include verbatim analyst text from an override or unsure-with-context response, quote that text in your rationale so the analyst can verify what was captured.
- Address every item in the FLAGS section if one is present. Do not skip flags.
- End with the recommended action, copied verbatim from the bucket map.
- Do not restate the numeric score. The report shows it separately.
- No hedging filler. No "it should be noted that." Analyst voice.

Output strictly via the write_rationale tool."""


RATIONALE_TOOL_SCHEMA = {
    "name": "write_rationale",
    "description": "Write the rationale paragraph for a scored vulnerability finding and report on which flags were addressed.",
    "input_schema": {
        "type": "object",
        "properties": {
            "rationale_text": {
                "type": "string",
                "description": "The 3-5 sentence rationale paragraph that will appear under this finding in the report. Plain analyst voice. Ends with the recommended action verbatim.",
            },
            "drivers": {
                "type": "array",
                "items": {"type": "string"},
                "description": "The 2-3 factors named as the primary drivers of the score (e.g. 'base_likelihood=1.0 via Metasploit exploit + internet-facing exposure').",
            },
            "verbatim_quotes_included": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Any verbatim analyst text quoted in the rationale. Empty list if no overrides or unsure-with-context answers fed this finding.",
            },
            "cia_fallback_noted": {
                "type": "boolean",
                "description": "True only if a CIA fallback flag was present in the FLAGS section AND the rationale mentions it. False otherwise.",
            },
            "defense_cap_noted": {
                "type": "boolean",
                "description": "True only if the FLAGS section explicitly stated the defense cap was hit AND the rationale mentions it. False otherwise. The defense adjustment value being shown in the prompt does NOT mean the cap was hit — the cap only triggers when the raw sum of defense dimensions exceeds 0.50.",
            },
            "confidence_noted": {
                "type": "boolean",
                "description": "True only if a confidence flag (medium or low) was present in the FLAGS section AND the rationale addresses it. False otherwise.",
            },
        },
        "required": [
            "rationale_text",
            "drivers",
            "verbatim_quotes_included",
            "cia_fallback_noted",
            "defense_cap_noted",
            "confidence_noted",
        ],
    },
}


def generate_rationale(scored_finding, interview_results):
    """
    Call Sonnet to write the rationale for a single scored finding.
    Returns the full tool input dict from the LLM (rationale_text + flags).
    """
    user_prompt = build_rationale_prompt(scored_finding, interview_results)

    response = _client.messages.create(
        model=RATIONALE_MODEL,
        max_tokens=1024,
        system=RATIONALE_SYSTEM_PROMPT,
        tools=[RATIONALE_TOOL_SCHEMA],
        tool_choice={"type": "tool", "name": "write_rationale"},
        messages=[{"role": "user", "content": user_prompt}],
    )

    for block in response.content:
        if block.type == "tool_use":
            return block.input

    return None




def score_finding(finding, interview_results):
    """
    Score a single finding. Returns the full scored-finding dict.
    """
    base_likelihood, exploit_mult, exposure_mult = compute_base_likelihood(finding, interview_results)
    material_cost, asset, data, cia_category, cia_weight, cia_fallback = compute_material_cost(finding, interview_results)
    defense_adj, defense_breakdown, defense_capped = compute_defense_adjustment(interview_results)
    org_mod, reg, uptime, incident = compute_org_context_modifier(interview_results)

    raw_score = base_likelihood * material_cost
    adjusted_score = raw_score * (1 - defense_adj)
    final_score = adjusted_score * org_mod
    final_score = min(1.0, final_score)
    bucket = bucket_score(final_score)
    confidence_avg, confidence_label = compute_confidence(interview_results)

    # Carry through any extra fields from the input finding (cves, synopsis,
    # solution, description, patch_available, vpr, etc.) so the report layer
    # has full context. Anything below that we compute will overwrite.
    scored = dict(finding)

    scored.update({
        "id": finding.get("id"),
        "cvss": finding.get("cvss"),
        "cvss_vector": finding.get("cvss_vector"),
        "exploit_status": finding.get("exploit_status", "none"),
        "host": finding.get("host"),
        "title": finding.get("title"),
        "score": round(final_score, 4),
        "bucket": bucket,
        "rationale": PLACEHOLDER_RATIONALE,
        "confidence_label": confidence_label,
        "confidence_avg": round(confidence_avg, 4),
        "sub_scores": {
            "base_likelihood": round(base_likelihood, 4),
            "material_cost": round(material_cost, 4),
            "raw_score": round(raw_score, 4),
            "defense_adjustment": round(defense_adj, 4),
            "adjusted_score": round(adjusted_score, 4),
            "org_context_modifier": round(org_mod, 4),
            "final_score": round(final_score, 4),
        },
        "score_inputs": {
            "exploit_mult": exploit_mult,
            "exposure_mult": exposure_mult,
            "asset_criticality": asset,
            "data_sensitivity": data,
            "cia_category": cia_category,
            "cia_weight": cia_weight,
            "cia_fallback_used": cia_fallback,
            "defense_breakdown": defense_breakdown,
            "defense_capped": defense_capped,
            "regulatory_pressure": reg,
            "uptime_sensitivity": uptime,
            "incident_history": incident,
        },
    })
    return scored


def attach_rationales(scored_findings, interview_results, verbose=False):
    """
    Call generate_rationale() for each scored finding and replace the placeholder
    rationale text. Failures on individual findings keep the placeholder so the
    pipeline doesn't halt.
    """
    for i, sf in enumerate(scored_findings, start=1):
        if verbose:
            print(f"  [{i}/{len(scored_findings)}] {sf['id']} — generating rationale...")
        try:
            output = generate_rationale(sf, interview_results)
            if output is None:
                sf["rationale"] = "[rationale generation returned no tool_use block]"
                sf["rationale_meta"] = None
                continue
            sf["rationale"] = output["rationale_text"]
            sf["rationale_meta"] = {
                "drivers": output.get("drivers", []),
                "verbatim_quotes_included": output.get("verbatim_quotes_included", []),
                "cia_fallback_noted": output.get("cia_fallback_noted", False),
                "defense_cap_noted": output.get("defense_cap_noted", False),
                "confidence_noted": output.get("confidence_noted", False),
            }
        except Exception as e:
            sf["rationale"] = f"[rationale generation failed: {type(e).__name__}: {e}]"
            sf["rationale_meta"] = None
    return scored_findings


def score_all(findings, interview_results, attach_rationales_flag=True, verbose=False):
    """
    Full pipeline: cull, score survivors, attach LLM rationales, sort by score desc.
    Set attach_rationales_flag=False to skip LLM calls (useful for testing math only).
    Returns dict with scored list, culled log, and a summary.
    """
    survivors, culled = cull_findings(findings, interview_results)
    scored = [score_finding(f, interview_results) for f in survivors]
    scored.sort(key=lambda x: x["score"], reverse=True)

    if attach_rationales_flag and scored:
        if verbose:
            print(f"\nGenerating rationales for {len(scored)} findings...")
        attach_rationales(scored, interview_results, verbose=verbose)

    summary = {
        "total_input": len(findings),
        "culled_count": len(culled),
        "scored_count": len(scored),
        "by_bucket": {b: 0 for b in ["critical", "high", "medium", "low", "filtered"]},
    }
    for s in scored:
        summary["by_bucket"][s["bucket"]] += 1

    return {
        "scored": scored,
        "culled": culled,
        "summary": summary,
    }


# ============================================================================
# MOCK FINDINGS FOR STANDALONE TESTING
# ============================================================================

MOCK_FINDINGS = [
    {
        "id": "F001",
        "title": "Apache HTTP Server RCE (CVE-2021-41773)",
        "host": "web-prod-01",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploit_status": "metasploit",
        "severity": "critical",
    },
    {
        "id": "F002",
        "title": "OpenSSL Information Disclosure",
        "host": "db-prod-02",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "exploit_status": "poc",
        "severity": "high",
    },
    {
        "id": "F003",
        "title": "TLS Weak Cipher",
        "host": "internal-app-04",
        "cvss": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "exploit_status": "none",
        "severity": "medium",
    },
    {
        "id": "F004",
        "title": "SMB Signing Disabled",
        "host": "fileserver-01",
        "cvss": 3.1,
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "exploit_status": "none",
        "severity": "low",
    },
    {
        "id": "F005",
        "title": "Outdated jQuery Version",
        "host": "intranet-01",
        "cvss": 0.0,
        "cvss_vector": "",
        "exploit_status": "none",
        "severity": "informational",
    },
]

# Mock interview: hospital-style org with strong defenses
MOCK_INTERVIEW = {
    "regulatory_pressure": {"option_id": "heavy", "value": 1.25, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "uptime_sensitivity": {"option_id": "critical_247", "value": 0.90, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "incident_history": {"option_id": "recent_incident", "value": 1.15, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "asset_criticality": {"option_id": "high", "value": 1.0, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "data_sensitivity": {"option_id": "regulated", "value": 1.0, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "exposure": {"option_id": "internet_facing", "value": 1.5, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "patching_maturity": {"option_id": "medium", "value": 0.06, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "segmentation_zerotrust": {"option_id": "strong", "value": 0.13, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "detection_response": {"option_id": "strong", "value": 0.09, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "resilience": {"option_id": "medium", "value": 0.04, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "out_of_scope_assets": {"option_id": "none", "value": None, "confidence": 1.0, "raw_answer": {"type": "structured"}},
    "already_mitigated": {"option_id": "none", "value": None, "confidence": 1.0, "raw_answer": {"type": "structured"}},
}


def _print_results(results):
    print("\n" + "=" * 70)
    print("RUBRIC TEST — MOCK FINDINGS + MOCK INTERVIEW")
    print("=" * 70)
    print(f"\nInput: {results['summary']['total_input']} findings")
    print(f"Culled: {results['summary']['culled_count']}")
    print(f"Scored: {results['summary']['scored_count']}")
    print(f"By bucket: {results['summary']['by_bucket']}\n")

    if results["culled"]:
        print("CULLED:")
        for c in results["culled"]:
            print(f"  {c['finding_id']}: {c['reason']}")
        print()

    print("SCORED (sorted by final score desc):")
    for s in results["scored"]:
        print(f"\n  [{s['id']}] {s['title']}")
        print(f"    host={s['host']}  cvss={s['cvss']}  exploit={s['exploit_status']}")
        print(f"    final_score={s['score']}  bucket={s['bucket']}  confidence={s['confidence_label']}")
        sub = s["sub_scores"]
        print(f"    sub: base_lik={sub['base_likelihood']} | mat_cost={sub['material_cost']} "
              f"| raw={sub['raw_score']} | def_adj={sub['defense_adjustment']} "
              f"| adj={sub['adjusted_score']} | org_mod={sub['org_context_modifier']}")
        si = s["score_inputs"]
        print(f"    inputs: CIA={si['cia_category']} (w={si['cia_weight']}, fallback={si['cia_fallback_used']})")
    print()


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("RUBRIC FULL PIPELINE TEST (Pass 2c)")
    print("=" * 70)
    results = score_all(MOCK_FINDINGS, MOCK_INTERVIEW, attach_rationales_flag=True, verbose=True)
    _print_results(results)

    print("=" * 70)
    print("RATIONALES")
    print("=" * 70)
    for s in results["scored"]:
        print(f"\n[{s['id']}] {s['title']}  →  {s['bucket'].upper()}  (score {s['score']})")
        print(f"\n  {s['rationale']}\n")
        meta = s.get("rationale_meta")
        if meta is not None:
            print(f"  drivers: {meta['drivers']}")
            print(f"  verbatim_quotes: {meta['verbatim_quotes_included']}")
            print(f"  flags noted — CIA fallback: {meta['cia_fallback_noted']}, "
                  f"defense cap: {meta['defense_cap_noted']}, confidence: {meta['confidence_noted']}")
        print("  " + "-" * 66)