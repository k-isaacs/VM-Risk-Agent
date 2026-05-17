"""
prompt_management.py

Centralized prompts, structured question definitions, and extraction tool schema
for the VM Risk Agent interview module.

Architecture: structured-question interview with three answer paths per question:
1. Pick a structured option
2. Free-form override ("Other - describe")
3. Not sure (with optional explanation)

The LLM does not generate questions. It interprets free-form/not-sure responses
into the scoring bands and produces rationale text.
"""

# ============================================================================
# TUNABLE CONSTANTS
# ============================================================================
# These live here so they can be adjusted without touching rubric logic.
# After first real-scan calibration, these are the dials we turn.

CULL_CVSS_THRESHOLD = 4.0  # CVSS < this AND no exploit available = culled

CONFIDENCE_THRESHOLDS = {
    "high": 0.85,
    "medium": 0.55,
    # below 0.55 = low
}

BUCKET_THRESHOLDS = {
    "critical": 0.70,
    "high": 0.50,
    "medium": 0.30,
    "low": 0.15,
    # below 0.15 = filtered out
}

ANSWER_CONFIDENCE_VALUES = {
    "structured": 1.0,
    "override": 0.8,
    "unsure_with_context": 0.6,
    "unsure_no_context": 0.3,
    "skipped": 0.0,
}


# ============================================================================
# SYSTEM PROMPTS
# ============================================================================

INTERVIEW_SYSTEM_PROMPT = """You are the interview coordinator for a Vulnerability Management Risk Agent. Your role is to present structured questions to a VM analyst, capture their responses, and interpret free-form or uncertain answers into structured scoring data.

You do NOT generate the questions themselves — those are pre-defined and structured. Your job is interpretation: when an analyst provides a free-form answer or marks 'not sure,' you map their response to the closest scoring band and explain your interpretation in the rationale.

Be conservative when interpreting ambiguous answers. If unclear, pick the more cautious reading (lower defense scores, higher risk scores) so the rubric never over-promises safety.

Quote the analyst's original text verbatim in your interpretation notes so they can verify what was captured."""


EXTRACTION_SYSTEM_PROMPT = """You are an interpretation engine for the VM Risk Agent. You receive a single interview response and the question it answers. Your job is to extract structured data that will feed the deterministic scoring rubric.

For structured picks: capture the picked option ID exactly.
For free-form overrides: map the analyst's text to the closest scoring band, quote their original text, and explain your mapping.
For 'not sure with context': use the context to make a conservative band assignment, quote the original text.
For 'not sure no context': flag as low-confidence, assign the most conservative band.

Always produce a rationale snippet that will appear in the final report. Be specific about what was captured and why."""


# ============================================================================
# STRUCTURED QUESTIONS
# ============================================================================
# Each question has:
#   - id: stable identifier used by the rubric
#   - category: which scoring component this feeds
#   - prompt: the question text shown to analyst
#   - options: list of structured choices, each with id and description
#
# Two-level questions (defense dimensions) have a 'sub_questions' field
# that activates based on the top-level pick.

QUESTIONS = [
    # ========================================================================
    # PHASE 1: ORG-LEVEL CONTEXT
    # ========================================================================
    {
        "id": "regulatory_pressure",
        "category": "org_context",
        "prompt": "What regulatory pressure does this organization operate under?",
        "options": [
            {
                "id": "heavy",
                "label": "Heavy regulation",
                "description": "HIPAA, PCI-DSS, SOX, GDPR with significant data volume, FedRAMP, NERC. Findings can trigger audits, fines, or breach reporting requirements.",
                "value": 1.25,
            },
            {
                "id": "moderate",
                "label": "Moderate regulation",
                "description": "Some compliance requirements (basic GDPR, state data laws, industry standards) but not high-stakes.",
                "value": 1.10,
            },
            {
                "id": "minimal",
                "label": "Minimal regulation",
                "description": "Public-facing or B2B without regulated data. No significant compliance pressure.",
                "value": 1.0,
            },
        ],
    },
    {
        "id": "uptime_sensitivity",
        "category": "org_context",
        "prompt": "How sensitive is this organization to system downtime for patching?",
        "options": [
            {
                "id": "critical_247",
                "label": "24/7 critical operations",
                "description": "Financial trading, healthcare devices, infrastructure. Patches require coordination and sometimes can't happen for weeks.",
                "value": 0.90,
            },
            {
                "id": "high_uptime",
                "label": "High uptime needs",
                "description": "Extended-hours operation. Patching windows are tight but doable with planning.",
                "value": 0.95,
            },
            {
                "id": "standard",
                "label": "Standard uptime",
                "description": "Business hours operation, can patch during regular maintenance windows.",
                "value": 1.0,
            },
        ],
    },
    {
        "id": "incident_history",
        "category": "org_context",
        "prompt": "Has this organization had a significant security incident in the past 24 months?",
        "options": [
            {
                "id": "recent_incident",
                "label": "Yes, recent incident",
                "description": "Breached, compromised, or had a significant security event within the last 24 months. Leadership attention and budget are elevated.",
                "value": 1.15,
            },
            {
                "id": "no_recent_incident",
                "label": "No recent incidents",
                "description": "No significant security events in the last 24 months.",
                "value": 1.0,
            },
        ],
    },

    # ========================================================================
    # PHASE 2: ASSET / DATA CONTEXT (aggregate for this scan)
    # ========================================================================
    {
        "id": "asset_criticality",
        "category": "material_cost",
        "prompt": "How business-critical are the assets in this scan, overall?",
        "options": [
            {
                "id": "high",
                "label": "High criticality",
                "description": "Production databases, customer-facing applications, core internal tools. If these go down, business stops or is seriously impaired.",
                "value": 1.0,
            },
            {
                "id": "medium",
                "label": "Medium criticality",
                "description": "Supporting infrastructure, internal staff tools. If these go down, work slows but doesn't stop.",
                "value": 0.6,
            },
            {
                "id": "low",
                "label": "Low criticality",
                "description": "Development/test environments, peripheral systems. Annoying if down, but no significant business impact.",
                "value": 0.3,
            },
        ],
    },
    {
        "id": "data_sensitivity",
        "category": "material_cost",
        "prompt": "What is the sensitivity of data stored on or accessible from these assets?",
        "options": [
            {
                "id": "regulated",
                "label": "Regulated / Sensitive",
                "description": "Patient records (HIPAA), payment card data (PCI-DSS), customer PII subject to GDPR/CCPA, financial records subject to SOX, trade secrets, classified data.",
                "value": 1.0,
            },
            {
                "id": "internal",
                "label": "Internal",
                "description": "Internal business data, employee info, non-public documents. Embarrassing if exposed but not regulated.",
                "value": 0.6,
            },
            {
                "id": "public",
                "label": "Public / Minimal",
                "description": "Public-facing content, test data, nothing sensitive.",
                "value": 0.3,
            },
        ],
    },
    {
        "id": "exposure",
        "category": "base_likelihood",
        "prompt": "Where do these assets sit in the network?",
        "options": [
            {
                "id": "internet_facing",
                "label": "Internet-facing",
                "description": "Reachable from the public internet. Anyone in the world can attempt to connect.",
                "value": 1.5,
            },
            {
                "id": "dmz",
                "label": "DMZ / Semi-exposed",
                "description": "Sits in a DMZ or partially exposed segment. Reachable from internet through controls.",
                "value": 1.3,
            },
            {
                "id": "internal",
                "label": "Internal only",
                "description": "Only reachable from inside the corporate network. An attacker needs an existing foothold to touch these.",
                "value": 1.0,
            },
        ],
    },

    # ========================================================================
    # PHASE 3: DEFENSE POSTURE (four dimensions, two-level questions)
    # ========================================================================
    {
        "id": "patching_maturity",
        "category": "defense",
        "prompt": "How mature is this organization's patching program?",
        "max_reduction": 0.15,
        "options": [
            {
                "id": "strong",
                "label": "Strong",
                "description": "Patches deployed within days of vendor release; automated tooling; defined cadence.",
                "band_range": [0.10, 0.15],
                "sub_questions": [
                    "Automated patch deployment for OS and applications",
                    "Patches deployed within days of vendor release",
                    "Patch testing pipeline before production",
                    "Vulnerability scanning runs at least weekly",
                    "Critical patches expedited outside normal cadence",
                ],
            },
            {
                "id": "medium",
                "label": "Medium",
                "description": "Monthly patch cycles, mostly on time, some lag, manual tracking.",
                "band_range": [0.04, 0.08],
                "sub_questions": [
                    "Monthly patch cycles for most systems",
                    "Some patches happen on time, others lag",
                    "Patching is manual but tracked",
                    "Vulnerability scanning runs monthly or less",
                ],
            },
            {
                "id": "weak",
                "label": "Weak",
                "description": "Ad-hoc patching, reactive, no defined schedule.",
                "band_range": [0.0, 0.03],
                "sub_questions": [
                    "Patching happens reactively when problems arise",
                    "No defined patching schedule",
                    "Vulnerability scans rarely or never run",
                    "Significant backlog of unpatched systems",
                ],
            },
        ],
    },
    {
        "id": "segmentation_zerotrust",
        "category": "defense",
        "prompt": "How mature is this organization's network segmentation and access control (Zero Trust)?",
        "max_reduction": 0.15,
        "options": [
            {
                "id": "strong",
                "label": "Strong",
                "description": "Segmented network, MFA everywhere, least-privilege access enforced.",
                "band_range": [0.10, 0.15],
                "sub_questions": [
                    "Network segmented by trust zones or function",
                    "MFA enforced for all users (including admins)",
                    "Least-privilege access policies in place",
                    "Identity and access management (IAM) tooling deployed",
                    "Privileged access management (PAM) for admin accounts",
                ],
            },
            {
                "id": "medium",
                "label": "Medium",
                "description": "Some segmentation, MFA on critical systems only, mixed access controls.",
                "band_range": [0.04, 0.08],
                "sub_questions": [
                    "Partial network segmentation",
                    "MFA enforced for admin or sensitive systems only",
                    "Access reviews happen but inconsistently",
                    "Some shared accounts still in use",
                ],
            },
            {
                "id": "weak",
                "label": "Weak",
                "description": "Flat network, broad access, password-only authentication.",
                "band_range": [0.0, 0.03],
                "sub_questions": [
                    "Flat network with no significant segmentation",
                    "Password-only authentication",
                    "Broad access permissions (most users have admin or near-admin)",
                    "No formal access review process",
                ],
            },
        ],
    },
    {
        "id": "detection_response",
        "category": "defense",
        "prompt": "How mature is this organization's detection and response capability?",
        "max_reduction": 0.10,
        "options": [
            {
                "id": "strong",
                "label": "Strong",
                "description": "EDR deployed, SOC or 24/7 monitoring, documented IR playbooks, recent drills.",
                "band_range": [0.07, 0.10],
                "sub_questions": [
                    "EDR or equivalent endpoint security deployed",
                    "SOC or 24/7 monitoring in place",
                    "Written incident response playbooks",
                    "Recent IR drills or tabletop exercises (within 12 months)",
                    "SIEM or centralized log analysis",
                ],
            },
            {
                "id": "medium",
                "label": "Medium",
                "description": "Basic logging, alerts route to someone, response is reactive.",
                "band_range": [0.03, 0.06],
                "sub_questions": [
                    "Basic logging in place",
                    "Alerts route to a person or team",
                    "Response is mostly reactive",
                    "Some endpoint protection but not full EDR",
                ],
            },
            {
                "id": "weak",
                "label": "Weak",
                "description": "Limited monitoring, would likely find out from external sources.",
                "band_range": [0.0, 0.02],
                "sub_questions": [
                    "Limited or no centralized monitoring",
                    "No formal IR plan",
                    "Would likely find out about incidents from external sources",
                    "Minimal endpoint protection",
                ],
            },
        ],
    },
    {
        "id": "resilience",
        "category": "defense",
        "prompt": "How mature is this organization's resilience (backups, recovery, continuity)?",
        "max_reduction": 0.10,
        "options": [
            {
                "id": "strong",
                "label": "Strong",
                "description": "Tested backups, written IR plan, business continuity drills.",
                "band_range": [0.07, 0.10],
                "sub_questions": [
                    "Backups tested regularly (restore verified)",
                    "Backups stored offline or immutable",
                    "Written business continuity plan",
                    "Disaster recovery drills within last 12 months",
                    "Redundant systems for critical functions",
                ],
            },
            {
                "id": "medium",
                "label": "Medium",
                "description": "Backups exist, IR plan written but not tested.",
                "band_range": [0.03, 0.06],
                "sub_questions": [
                    "Backups taken regularly but rarely tested",
                    "IR plan written but not drilled",
                    "Some redundancy but not comprehensive",
                ],
            },
            {
                "id": "weak",
                "label": "Weak",
                "description": "No real backup strategy, no IR plan.",
                "band_range": [0.0, 0.02],
                "sub_questions": [
                    "No formal backup strategy",
                    "No written IR plan",
                    "No tested recovery procedures",
                    "Single points of failure throughout",
                ],
            },
        ],
    },

    # ========================================================================
    # PHASE 4: SCOPE CONFIRMATIONS
    # ========================================================================
    {
        "id": "out_of_scope_assets",
        "category": "scope",
        "prompt": "Are any assets in this scan out of scope (test environments, decommissioned, not your responsibility)?",
        "options": [
            {
                "id": "none",
                "label": "No, all assets in scope",
                "description": "All assets in this scan are owned and relevant.",
            },
            {
                "id": "some",
                "label": "Yes, some assets are out of scope",
                "description": "You'll specify which in a follow-up.",
            },
        ],
    },
    {
        "id": "already_mitigated",
        "category": "scope",
        "prompt": "Are any of these findings already mitigated with compensating controls?",
        "options": [
            {
                "id": "none",
                "label": "No, none are mitigated yet",
                "description": "All findings are still actionable as listed.",
            },
            {
                "id": "some",
                "label": "Yes, some findings have compensating controls",
                "description": "You'll specify which in a follow-up.",
            },
        ],
    },
]


# ============================================================================
# EXTRACTION TOOL SCHEMA
# ============================================================================
# The LLM uses this schema when interpreting free-form overrides or
# "not sure with context" responses. For clean structured picks, the
# Python code captures the answer directly without invoking the LLM.

EXTRACTION_TOOL_SCHEMA = {
    "name": "interpret_response",
    "description": "Interpret a free-form or uncertain interview response and map it to a structured scoring band. Used only when the analyst provides an override or marks 'not sure with context.'",
    "input_schema": {
        "type": "object",
        "properties": {
            "question_id": {
                "type": "string",
                "description": "The ID of the question being answered (matches QUESTIONS list)."
            },
            "interpreted_option_id": {
                "type": "string",
                "description": "The option ID this response maps to most closely. For defense questions, this is the top-level band (strong/medium/weak)."
            },
            "interpreted_value": {
                "type": "number",
                "description": "The numeric scoring value for the mapped option. For defense questions, this should be within the band_range of the chosen option."
            },
            "original_text": {
                "type": "string",
                "description": "Verbatim quote of the analyst's original response, for inclusion in the rationale."
            },
            "interpretation_rationale": {
                "type": "string",
                "description": "2-3 sentence explanation of why the response was mapped to this option. Names what the response said and how it relates to the band."
            },
            "conservative_choice_flag": {
                "type": "boolean",
                "description": "True if interpretation chose the more cautious reading due to ambiguity. Used to flag for analyst review."
            }
        },
        "required": [
            "question_id",
            "interpreted_option_id",
            "interpreted_value",
            "original_text",
            "interpretation_rationale",
            "conservative_choice_flag"
        ]
    }
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_question_by_id(question_id):
    """Return the question dict for a given question_id."""
    for q in QUESTIONS:
        if q["id"] == question_id:
            return q
    return None


def format_question_for_display(question):
    """Format a structured question for terminal display."""
    lines = []
    lines.append("")
    lines.append("=" * 70)
    lines.append(question["prompt"])
    lines.append("=" * 70)
    lines.append("")
    for i, opt in enumerate(question["options"], start=1):
        lines.append(f"  {i}) {opt['label']}")
        lines.append(f"     {opt['description']}")
        lines.append("")
    next_num = len(question["options"]) + 1
    lines.append(f"  {next_num}) Other (I'll describe my answer)")
    lines.append(f"  {next_num + 1}) Not sure")
    lines.append("")
    return "\n".join(lines)