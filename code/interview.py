"""
interview.py

Structured-question interview module for the VM Risk Agent.

Loop: present structured question → capture pick / override / not-sure →
record answer with confidence value → repeat for all questions → return
captured context dict.

Free-form overrides and "not sure with context" responses are sent to the
LLM for interpretation. Clean structured picks bypass the LLM entirely
(deterministic capture, faster, cheaper).
"""

import anthropic
from keys import ANTHROPIC_API_KEY
from prompt_management import (
    QUESTIONS,
    INTERVIEW_SYSTEM_PROMPT,
    EXTRACTION_SYSTEM_PROMPT,
    EXTRACTION_TOOL_SCHEMA,
    ANSWER_CONFIDENCE_VALUES,
    get_question_by_id,
    format_question_for_display,
)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
MODEL = "claude-sonnet-4-6"


def prompt_analyst(question):
    """
    Display a structured question and capture the analyst's choice.
    Returns a dict describing the answer:
      {
        "type": "structured" | "override" | "unsure_with_context" | "unsure_no_context" | "skipped",
        "option_id": str or None,
        "free_form_text": str or None,
      }
    """
    print(format_question_for_display(question))
    num_options = len(question["options"])
    override_num = num_options + 1
    unsure_num = num_options + 2
    valid_range = f"1-{unsure_num}"

    while True:
        choice = input(f"Your choice [{valid_range}], or 's' to skip: ").strip().lower()

        if choice == "s":
            return {"type": "skipped", "option_id": None, "free_form_text": None}

        if not choice.isdigit():
            print(f"  Please enter a number {valid_range} or 's'.\n")
            continue

        choice_num = int(choice)
        if choice_num < 1 or choice_num > unsure_num:
            print(f"  Please enter a number {valid_range} or 's'.\n")
            continue

        # Structured pick
        if choice_num <= num_options:
            picked = question["options"][choice_num - 1]
            return {
                "type": "structured",
                "option_id": picked["id"],
                "free_form_text": None,
            }

        # Free-form override
        if choice_num == override_num:
            print("\nDescribe your answer:")
            text = input("> ").strip()
            if not text:
                print("  Empty response, treating as skipped.\n")
                return {"type": "skipped", "option_id": None, "free_form_text": None}
            return {
                "type": "override",
                "option_id": None,
                "free_form_text": text,
            }

        # Not sure
        if choice_num == unsure_num:
            print("\nOptional: add context to help interpret your uncertainty.")
            print("(Press Enter to skip the context.)")
            text = input("> ").strip()
            if text:
                return {
                    "type": "unsure_with_context",
                    "option_id": None,
                    "free_form_text": text,
                }
            return {
                "type": "unsure_no_context",
                "option_id": None,
                "free_form_text": None,
            }


def interpret_response_with_llm(question, raw_answer):
    """
    Send a free-form override or 'unsure with context' to the LLM for
    interpretation. Returns the structured interpretation dict from the
    extraction tool.
    """
    user_msg = (
        f"Question being answered:\n"
        f"  ID: {question['id']}\n"
        f"  Prompt: {question['prompt']}\n\n"
        f"Available structured options:\n"
    )
    for opt in question["options"]:
        if "band_range" in opt:
            user_msg += (
                f"  - {opt['id']} ({opt['label']}): {opt['description']} "
                f"[band range: {opt['band_range']}]\n"
            )
        elif "value" in opt:
            user_msg += (
                f"  - {opt['id']} ({opt['label']}): {opt['description']} "
                f"[value: {opt['value']}]\n"
            )
        else:
            user_msg += f"  - {opt['id']} ({opt['label']}): {opt['description']}\n"

    user_msg += f"\nAnalyst response type: {raw_answer['type']}\n"
    user_msg += f"Analyst response text: \"{raw_answer['free_form_text']}\"\n\n"
    user_msg += (
        "Interpret this response. Map it to the closest option. If ambiguous, "
        "pick the more conservative (more cautious) reading. Use the interpret_response tool."
    )

    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=EXTRACTION_SYSTEM_PROMPT,
        tools=[EXTRACTION_TOOL_SCHEMA],
        tool_choice={"type": "tool", "name": "interpret_response"},
        messages=[{"role": "user", "content": user_msg}],
    )

    for block in response.content:
        if block.type == "tool_use":
            return block.input

    return None


def ask_subquestions(question, top_level_option_id):
    """
    For defense questions, after the top-level pick, ask which sub-items apply.
    Returns a list of checked sub-item indices.
    """
    option = next(
        (opt for opt in question["options"] if opt["id"] == top_level_option_id),
        None,
    )
    if option is None or "sub_questions" not in option:
        return []

    print("\n" + "-" * 70)
    print(f"You picked: {option['label']}")
    print("Which of these apply to your organization? (enter numbers separated by commas, or press Enter for none)")
    print("-" * 70)
    for i, sub in enumerate(option["sub_questions"], start=1):
        print(f"  {i}) {sub}")
    print()

    while True:
        raw = input("Applicable items: ").strip()
        if raw == "":
            return []
        try:
            picked = [int(x.strip()) for x in raw.split(",") if x.strip()]
            if all(1 <= n <= len(option["sub_questions"]) for n in picked):
                return picked
            print(f"  Please use numbers 1-{len(option['sub_questions'])}.\n")
        except ValueError:
            print("  Please enter comma-separated numbers.\n")


def compute_defense_band_value(option, sub_picks_count):
    """
    For defense questions, compute the numeric value within the band based on
    how many sub-items were checked. More sub-items = higher value within band.
    """
    band_low, band_high = option["band_range"]
    total_subs = len(option["sub_questions"])
    if total_subs == 0:
        return band_low
    fraction = sub_picks_count / total_subs
    return round(band_low + (band_high - band_low) * fraction, 4)


def confidence_for_answer(answer_type):
    """Map answer type to confidence value (from prompt_management constants)."""
    return ANSWER_CONFIDENCE_VALUES.get(answer_type, 0.0)


def run_interview():
    """
    Run the full interview loop. Returns a dict of captured answers keyed by
    question_id, each with: option_id, value, confidence, raw_answer, interpretation.
    """
    print("\n" + "=" * 70)
    print("VM RISK AGENT — ANALYST INTERVIEW")
    print("=" * 70)
    print(
        "\nThis interview captures the organizational context needed to score\n"
        "the vulnerabilities in the Tenable scan. For each question, pick the\n"
        "option that best matches, or use 'Other' / 'Not sure' if needed.\n"
    )

    results = {}

    for question in QUESTIONS:
        raw = prompt_analyst(question)
        entry = {
            "question_id": question["id"],
            "category": question["category"],
            "raw_answer": raw,
            "option_id": None,
            "value": None,
            "confidence": confidence_for_answer(raw["type"]),
            "interpretation": None,
            "sub_picks": None,
        }

        # Structured pick path
        if raw["type"] == "structured":
            entry["option_id"] = raw["option_id"]
            picked_option = next(
                (opt for opt in question["options"] if opt["id"] == raw["option_id"]),
                None,
            )
            # Defense questions need sub-question follow-up
            if question["category"] == "defense" and picked_option is not None:
                sub_picks = ask_subquestions(question, raw["option_id"])
                entry["sub_picks"] = sub_picks
                entry["value"] = compute_defense_band_value(picked_option, len(sub_picks))
            elif picked_option is not None and "value" in picked_option:
                entry["value"] = picked_option["value"]

        # Override or unsure-with-context: send to LLM for interpretation
        elif raw["type"] in ("override", "unsure_with_context"):
            print("\nInterpreting your response...\n")
            interpretation = interpret_response_with_llm(question, raw)
            entry["interpretation"] = interpretation
            if interpretation:
                entry["option_id"] = interpretation["interpreted_option_id"]
                entry["value"] = interpretation["interpreted_value"]
                # Defense questions: if interpreted as a band, still ask sub-questions
                if question["category"] == "defense":
                    sub_picks = ask_subquestions(question, interpretation["interpreted_option_id"])
                    entry["sub_picks"] = sub_picks
                    picked_option = next(
                        (opt for opt in question["options"] if opt["id"] == interpretation["interpreted_option_id"]),
                        None,
                    )
                    if picked_option is not None:
                        entry["value"] = compute_defense_band_value(picked_option, len(sub_picks))

        # Unsure no context: assign most conservative option
        elif raw["type"] == "unsure_no_context":
            # Pick the most conservative option (last in list for defense/cost, first for likelihood multipliers)
            if question["category"] == "defense":
                conservative = question["options"][-1]  # weak
                entry["option_id"] = conservative["id"]
                entry["value"] = conservative["band_range"][0]
            elif question["category"] in ("material_cost", "org_context"):
                # Conservative = pick the middle option to avoid over/under-scoring
                middle = question["options"][len(question["options"]) // 2]
                entry["option_id"] = middle["id"]
                entry["value"] = middle.get("value")
            elif question["category"] == "base_likelihood":
                # Conservative = highest multiplier (assume more exposed)
                entry["option_id"] = question["options"][0]["id"]
                entry["value"] = question["options"][0]["value"]
            elif question["category"] == "scope":
                # Conservative = assume nothing out of scope / nothing mitigated
                entry["option_id"] = question["options"][0]["id"]

        # Skipped: leave value as None, confidence 0.0
        # (rubric.py will handle missing values appropriately)

        results[question["id"]] = entry

    print("\n" + "=" * 70)
    print("INTERVIEW COMPLETE")
    print("=" * 70 + "\n")
    return results


def summarize_results(results):
    """Print a human-readable summary of captured interview data."""
    print("Summary of captured answers:\n")
    for qid, entry in results.items():
        question = get_question_by_id(qid)
        line = f"  [{qid}] "
        if entry["raw_answer"]["type"] == "structured":
            line += f"picked '{entry['option_id']}'"
            if entry["sub_picks"] is not None:
                line += f" ({len(entry['sub_picks'])} sub-items checked)"
        elif entry["raw_answer"]["type"] == "override":
            line += f"override → mapped to '{entry['option_id']}'"
        elif entry["raw_answer"]["type"] == "unsure_with_context":
            line += f"unsure (with context) → mapped to '{entry['option_id']}'"
        elif entry["raw_answer"]["type"] == "unsure_no_context":
            line += f"unsure → defaulted to conservative '{entry['option_id']}'"
        else:
            line += "skipped"
        line += f" | value={entry['value']} | confidence={entry['confidence']}"
        print(line)
    print()


if __name__ == "__main__":
    results = run_interview()
    summarize_results(results)
    