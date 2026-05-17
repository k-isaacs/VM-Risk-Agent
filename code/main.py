"""
main.py

End-to-end orchestrator for the VM Risk Agent.

Pipeline:
  1. Parse Tenable CSV → findings list
  2. Run analyst interview → interview_results
  3. Guardrails: model_known, context_completeness
  4. Score findings → cull + rubric + LLM rationales
  5. Generate Markdown report
  6. Write report to disk

Usage:
  python3 main.py <path_to_tenable.csv> [--output report.md] [--no-rationales]
"""

import argparse
import os
import sys
from datetime import datetime

from csv_parser import parse_csv
from interview import run_interview, summarize_results
from guardrails import (
    GuardrailError,
    run_post_interview_guardrails,
)
import rubric
from report_generator import write_report


def banner(text):
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


def parse_args():
    parser = argparse.ArgumentParser(
        description="VM Risk Agent — score and prioritize a Tenable CSV scan."
    )
    parser.add_argument(
        "csv_path",
        help="Path to the Tenable CSV export.",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Path for the Markdown report. Default: vm_risk_report_<timestamp>.md",
    )
    parser.add_argument(
        "--no-rationales",
        action="store_true",
        help="Skip LLM rationale generation (math only, no API cost). Useful for quick tests.",
    )
    parser.add_argument(
        "--scan-name",
        default=None,
        help="Scan label to show in the report header.",
    )
    parser.add_argument(
        "--analyst",
        default=None,
        help="Analyst name to show in the report header.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not os.path.exists(args.csv_path):
        print(f"ERROR: CSV file not found: {args.csv_path}", file=sys.stderr)
        sys.exit(1)

    # ----- Stage 1: parse CSV -----
    banner("STAGE 1 — Parsing Tenable CSV")
    findings = parse_csv(args.csv_path)
    if not findings:
        print("ERROR: parser returned 0 findings. CSV may be malformed.", file=sys.stderr)
        sys.exit(1)
    print(f"Parsed {len(findings)} unique findings from {args.csv_path}.")

    # Pull the host(s) from the findings for the report header
    hosts = sorted(set(f.get("host", "") for f in findings if f.get("host")))
    host_label = ", ".join(hosts) if hosts else "_host TBD_"

    # ----- Stage 2: model guardrail -----
    banner("STAGE 2 — Pre-flight checks")
    try:
        from guardrails import check_model_known
        check_model_known(rubric.RATIONALE_MODEL)
        print(f"Model '{rubric.RATIONALE_MODEL}' is known. ✓")
    except GuardrailError as e:
        print(f"GUARDRAIL FAILED: {e}", file=sys.stderr)
        sys.exit(2)

    # ----- Stage 3: run the interview -----
    banner("STAGE 3 — Analyst interview")
    print(
        "About to start the interview. You'll be asked ~12 structured questions about\n"
        "the organizational context. Each has multiple-choice options plus an 'Other'\n"
        "and 'Not sure' path. Take your time — your answers drive the scoring."
    )
    input("\nPress Enter to begin the interview...")

    interview_results = run_interview()
    summarize_results(interview_results)

    # ----- Stage 4: post-interview guardrails -----
    banner("STAGE 4 — Post-interview guardrails")
    try:
        summary = run_post_interview_guardrails(interview_results, rubric.RATIONALE_MODEL)
        print(f"Context completeness: {summary['answered']}/{summary['total']} answered "
              f"(ratio {summary['ratio']:.2f}). ✓")
        print(f"Interview confidence: {summary['confidence_label']} "
              f"(avg {summary['avg_confidence']:.2f}).")
        if summary["skipped_ids"]:
            print(f"Skipped questions: {summary['skipped_ids']}")
    except GuardrailError as e:
        print(f"\nGUARDRAIL FAILED: {e}", file=sys.stderr)
        print("\nThe interview did not capture enough usable context to produce a "
              "defensible report. Please re-run and answer more questions.", file=sys.stderr)
        sys.exit(3)

    # ----- Stage 5: score findings -----
    banner("STAGE 5 — Scoring findings")
    if args.no_rationales:
        print("Math only — LLM rationale generation skipped (--no-rationales).")
    else:
        print(f"Scoring {len(findings)} findings. LLM rationales will run after the math.")

    results = rubric.score_all(
        findings,
        interview_results,
        attach_rationales_flag=(not args.no_rationales),
        verbose=True,
    )

    print(f"\nScored: {results['summary']['scored_count']}")
    print(f"Culled: {results['summary']['culled_count']}")
    print(f"By bucket: {results['summary']['by_bucket']}")

    # ----- Stage 6: generate and write the report -----
    banner("STAGE 6 — Writing report")

    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"vm_risk_report_{timestamp}.md"

    scan_name = args.scan_name or os.path.basename(args.csv_path).rsplit(".", 1)[0]
    metadata = {
        "scan_name": scan_name,
        "host": host_label,
        "scan_date": datetime.now().strftime("%Y-%m-%d"),
        "analyst": args.analyst or "",
    }

    # Build the report
    from report_generator import generate_report
    markdown = generate_report(results, metadata)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown)

    print(f"Report written: {output_path}")
    print(f"Size: {len(markdown)} chars")

    banner("DONE")
    print(f"\n  Open the report: open {output_path}")
    print(f"  Or view in terminal: cat {output_path} | less\n")


if __name__ == "__main__":
    main()