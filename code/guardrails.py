"""
guardrails.py

Pipeline guardrails for the VM Risk Agent. Each checkpoint validates the
state of the data between pipeline stages and raises GuardrailError when
something is wrong.

Four checkpoints:
1. context_completeness   - verify interview captured enough usable data
2. model_known            - verify the configured model string is valid
3. prompt_size            - verify prompts won't blow token limits
4. rationale_confidence   - verify scored findings have rationale + confidence
"""

from prompt_management import (
    QUESTIONS,
    ANSWER_CONFIDENCE_VALUES,
    CONFIDENCE_THRESHOLDS,
)


class GuardrailError(Exception):
    """Raised when a guardrail check fails. Halts the pipeline."""
    pass


# Models the project is allowed to use. Update if new models are released.
KNOWN_MODELS = {
    "claude-sonnet-4-6",
    "claude-haiku-4-5-20251001",
    "claude-opus-4-7",
}

# Minimum fraction of questions that must have usable answers (not skipped).
# Below this, the interview is too incomplete to produce a defensible score.
MIN_USABLE_ANSWER_RATIO = 0.6

# Maximum prompt size in characters before we worry about token limits.
# Sonnet 4.6 has a 1M context window, but we set a much lower soft cap
# because most prompts in this project should be well under it.
MAX_PROMPT_CHARS = 50000


def check_context_completeness(interview_results):
    """
    Checkpoint 1: verify the interview captured enough usable data.

    Counts how many questions got non-skipped answers. If fewer than
    MIN_USABLE_ANSWER_RATIO of questions were answered, halt — the rubric
    cannot produce a defensible score with too little context.

    Also computes an overall interview confidence value and flags it as
    low/medium/high so downstream code can route accordingly.
    """
    total_questions = len(QUESTIONS)
    if total_questions == 0:
        raise GuardrailError("No questions defined in prompt_management.QUESTIONS.")

    if not isinstance(interview_results, dict):
        raise GuardrailError(
            f"context_completeness: expected dict, got {type(interview_results).__name__}"
        )

    # Count answered questions (anything not skipped)
    answered = 0
    confidence_sum = 0.0
    skipped_ids = []

    for question in QUESTIONS:
        qid = question["id"]
        if qid not in interview_results:
            skipped_ids.append(qid)
            continue
        entry = interview_results[qid]
        if not isinstance(entry, dict):
            raise GuardrailError(
                f"context_completeness: entry for {qid} is not a dict"
            )
        answer_type = entry.get("raw_answer", {}).get("type")
        if answer_type == "skipped" or answer_type is None:
            skipped_ids.append(qid)
        else:
            answered += 1
        confidence_sum += entry.get("confidence", 0.0)

    ratio = answered / total_questions
    if ratio < MIN_USABLE_ANSWER_RATIO:
        raise GuardrailError(
            f"context_completeness: only {answered}/{total_questions} questions "
            f"answered (ratio {ratio:.2f} < required {MIN_USABLE_ANSWER_RATIO:.2f}). "
            f"Skipped: {skipped_ids}"
        )

    avg_confidence = confidence_sum / total_questions
    if avg_confidence >= CONFIDENCE_THRESHOLDS["high"]:
        confidence_label = "high"
    elif avg_confidence >= CONFIDENCE_THRESHOLDS["medium"]:
        confidence_label = "medium"
    else:
        confidence_label = "low"

    return {
        "answered": answered,
        "total": total_questions,
        "ratio": ratio,
        "avg_confidence": avg_confidence,
        "confidence_label": confidence_label,
        "skipped_ids": skipped_ids,
    }


def check_model_known(model_string):
    """
    Checkpoint 2: verify the configured model is one this project supports.

    If a typo or stale model name slips in, halt before burning API calls.
    """
    if model_string not in KNOWN_MODELS:
        raise GuardrailError(
            f"model_known: '{model_string}' is not a recognized model. "
            f"Known: {sorted(KNOWN_MODELS)}"
        )
    return True


def check_prompt_size(prompt_text, label="prompt"):
    """
    Checkpoint 3: verify a prompt is within reasonable size limits.

    Prevents accidentally sending a massive prompt that bloats cost or
    exceeds limits. Sonnet 4.6 has a 1M context window but the project's
    soft cap is much lower because we don't need that much.
    """
    if not isinstance(prompt_text, str):
        raise GuardrailError(
            f"prompt_size: {label} is not a string (got {type(prompt_text).__name__})"
        )
    char_count = len(prompt_text)
    if char_count > MAX_PROMPT_CHARS:
        raise GuardrailError(
            f"prompt_size: {label} is {char_count} chars (soft cap {MAX_PROMPT_CHARS}). "
            f"Trim before sending."
        )
    return True


def check_rationale_confidence(scored_finding):
    """
    Checkpoint 4: verify a scored finding carries the rationale and confidence
    fields needed for the report.

    Called per-finding after the rubric runs. A finding without rationale or
    confidence is not shippable to the report stage.
    """
    if not isinstance(scored_finding, dict):
        raise GuardrailError(
            f"rationale_confidence: expected dict, got {type(scored_finding).__name__}"
        )

    required_fields = ["score", "bucket", "rationale", "confidence_label", "sub_scores"]
    missing = [f for f in required_fields if f not in scored_finding]
    if missing:
        raise GuardrailError(
            f"rationale_confidence: scored finding missing fields {missing}. "
            f"Finding: {scored_finding.get('id', '<no id>')}"
        )

    if not scored_finding["rationale"] or not isinstance(scored_finding["rationale"], str):
        raise GuardrailError(
            f"rationale_confidence: rationale is empty or non-string for "
            f"finding {scored_finding.get('id', '<no id>')}"
        )

    if scored_finding["confidence_label"] not in ("high", "medium", "low"):
        raise GuardrailError(
            f"rationale_confidence: confidence_label '{scored_finding['confidence_label']}' "
            f"is not high/medium/low for finding {scored_finding.get('id', '<no id>')}"
        )

    return True


# Convenience: run all relevant checks at once for the interview stage
def run_post_interview_guardrails(interview_results, model_string):
    """
    Run guardrail checks after the interview module finishes, before the
    rubric stage runs. Returns the completeness summary dict.
    """
    check_model_known(model_string)
    summary = check_context_completeness(interview_results)
    return summary