"""
report_generator.py

Takes the scored output from rubric.score_all() and produces an analyst-facing
Markdown report.

Structure (rubric design Section 9 + Section 10):
  1. Header (date, host, source)
  2. Opening note (Section 10 safeguard — inputs-only-as-good-as-the-interview)
  3. Executive summary (bucket counts, top findings)
  4. Findings by bucket (Critical → High → Medium → Low)
  5. Culled findings appendix
  6. Methodology footer
"""

from datetime import datetime
from collections import defaultdict


BUCKET_ORDER = ["critical", "high", "medium", "low"]

BUCKET_HEADERS = {
    "critical": "🔴 Critical",
    "high":     "🟠 High",
    "medium":   "🟡 Medium",
    "low":      "🟢 Low",
}

BUCKET_ACTIONS = {
    "critical": "Patch immediately; if patch unavailable, mitigate with compensating controls.",
    "high":     "Patch in next cycle; mitigate if patching is blocked.",
    "medium":   "Patch in normal cadence; consider systemic measures.",
    "low":      "Track; risk-accept with documentation if patching cost exceeds impact.",
}


def _format_cve_list(cves, max_inline=3):
    """Show first N CVEs inline, summarize the rest."""
    if not cves:
        return "_no CVE assigned_"
    if len(cves) <= max_inline:
        return ", ".join(f"`{c}`" for c in cves)
    shown = ", ".join(f"`{c}`" for c in cves[:max_inline])
    return f"{shown} (+ {len(cves) - max_inline} more)"


def _format_finding_block(finding):
    """Render a single scored finding as a Markdown section."""
    lines = []
    score_pct = int(round(finding["score"] * 100))
    title = finding.get("title") or "_no title_"
    host = finding.get("host") or "_unknown host_"
    cvss = finding.get("cvss", 0.0)
    plugin_id = finding.get("id", "?")
    exploit_status = finding.get("exploit_status", "none")
    cves = finding.get("cves", [])
    confidence = finding.get("confidence_label", "unknown")

    lines.append(f"### `[{plugin_id}]` {title}")
    lines.append("")
    lines.append(
        f"**Host:** {host}  |  **CVSS:** {cvss}  |  **Exploit:** {exploit_status}  |  "
        f"**Score:** {score_pct}/100  |  **Confidence:** {confidence}"
    )
    lines.append("")
    lines.append(f"**CVEs:** {_format_cve_list(cves)}")
    lines.append("")

    rationale = finding.get("rationale") or "_no rationale generated_"
    lines.append(rationale)
    lines.append("")

    sub = finding.get("sub_scores", {})
    si = finding.get("score_inputs", {})
    lines.append("<details><summary>Sub-score breakdown</summary>")
    lines.append("")
    lines.append("| Component | Value | Notes |")
    lines.append("|---|---|---|")
    lines.append(f"| base_likelihood | {sub.get('base_likelihood', 'n/a')} | "
                 f"CVSS {cvss}, exposure {si.get('exposure_mult', 'n/a')}, exploit {exploit_status} |")
    lines.append(f"| material_cost | {sub.get('material_cost', 'n/a')} | "
                 f"asset {si.get('asset_criticality', 'n/a')}, data {si.get('data_sensitivity', 'n/a')}, "
                 f"CIA {si.get('cia_category', 'n/a')} ({si.get('cia_weight', 'n/a')}) |")
    lines.append(f"| raw_score | {sub.get('raw_score', 'n/a')} | base × material |")
    lines.append(f"| defense_adjustment | {sub.get('defense_adjustment', 'n/a')} | "
                 f"capped at 0.50, {'reached cap' if si.get('defense_capped') else 'under cap'} |")
    lines.append(f"| adjusted_score | {sub.get('adjusted_score', 'n/a')} | raw × (1 - defense_adjustment) |")
    lines.append(f"| org_context_modifier | {sub.get('org_context_modifier', 'n/a')} | "
                 f"regulatory {si.get('regulatory_pressure', 'n/a')}, "
                 f"uptime {si.get('uptime_sensitivity', 'n/a')}, "
                 f"incident {si.get('incident_history', 'n/a')} |")
    lines.append(f"| **final_score** | **{sub.get('final_score', 'n/a')}** | adjusted × org_mod |")
    lines.append("")
    lines.append("</details>")
    lines.append("")

    return "\n".join(lines)


def _group_by_bucket(scored_findings):
    groups = defaultdict(list)
    for f in scored_findings:
        groups[f.get("bucket", "unknown")].append(f)
    return groups


def _exec_summary_table(summary):
    lines = []
    lines.append("| Bucket | Count | Recommended Action |")
    lines.append("|---|---|---|")
    for bucket in BUCKET_ORDER:
        count = summary["by_bucket"].get(bucket, 0)
        action = BUCKET_ACTIONS[bucket]
        lines.append(f"| {BUCKET_HEADERS[bucket]} | {count} | {action} |")
    return "\n".join(lines)


def _top_findings_table(scored_findings, n=5):
    if not scored_findings:
        return "_No findings scored above the filter floor._"
    lines = []
    lines.append("| Rank | Plugin ID | Title | Score | Bucket |")
    lines.append("|---|---|---|---|---|")
    for i, f in enumerate(scored_findings[:n], start=1):
        title = (f.get("title") or "")[:60]
        score_pct = int(round(f["score"] * 100))
        bucket = BUCKET_HEADERS.get(f.get("bucket", ""), f.get("bucket", ""))
        lines.append(f"| {i} | `{f.get('id', '?')}` | {title} | {score_pct}/100 | {bucket} |")
    return "\n".join(lines)


def _culled_appendix(culled):
    if not culled:
        return "_No findings were culled._"
    lines = []
    lines.append("| Plugin ID | Reason |")
    lines.append("|---|---|")
    for c in culled:
        lines.append(f"| `{c['finding_id']}` | {c['reason']} |")
    return "\n".join(lines)


def generate_report(results, scan_metadata=None):
    """
    Build the full Markdown report.

    Args:
        results: dict from rubric.score_all(), with keys 'scored', 'culled', 'summary'
        scan_metadata: optional dict with 'scan_name', 'host', 'scan_date', 'analyst'

    Returns:
        Markdown string ready to write to a .md file.
    """
    meta = scan_metadata or {}
    scan_name = meta.get("scan_name", "Tenable VM Scan")
    host = meta.get("host", "_host TBD_")
    scan_date = meta.get("scan_date", datetime.now().strftime("%Y-%m-%d"))
    analyst = meta.get("analyst", "")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    scored = results["scored"]
    culled = results["culled"]
    summary = results["summary"]
    grouped = _group_by_bucket(scored)

    parts = []

    parts.append(f"# VM Risk Report — {scan_name}")
    parts.append("")
    parts.append(f"**Host(s):** {host}  ")
    parts.append(f"**Scan date:** {scan_date}  ")
    if analyst:
        parts.append(f"**Analyst:** {analyst}  ")
    parts.append(f"**Report generated:** {generated_at}  ")
    parts.append("")
    parts.append("---")
    parts.append("")

    parts.append("## About this report")
    parts.append("")
    parts.append(
        "This report was generated based on the organizational context provided during the analyst "
        "interview. Scoring is only as accurate as those inputs. If you were uncertain about any "
        "interview answer — particularly around **data sensitivity**, **asset criticality**, or "
        "**regulatory environment** — consider running this analysis again with a colleague or "
        "someone more familiar with the affected systems."
    )
    parts.append("")
    parts.append(
        "Each finding's score is computed deterministically from a transparent formula "
        "(see Methodology). The rationale text under each finding is generated by an LLM and explains "
        "which inputs drove the score; it does not produce the number itself."
    )
    parts.append("")
    parts.append(
        "**A note on duplicate-looking findings.** Some vulnerability scanners report the same "
        "product across multiple plugin entries — for example, every superseded version of a browser "
        "or library may appear as its own row. This is faithful to the scanner output and the scoring "
        "rubric does not collapse them. If you see many similar entries clustered in the same bucket, "
        "check whether patching to the latest version of that product resolves the earlier entries as "
        "well. Treat the bucket as one remediation effort, not many."
    )
    parts.append("")

    parts.append("## Executive summary")
    parts.append("")
    parts.append(
        f"**{summary['total_input']}** total findings in the scan. "
        f"**{summary['scored_count']}** scored and prioritized. "
        f"**{summary['culled_count']}** filtered out by cull rules (see appendix)."
    )
    parts.append("")
    parts.append(_exec_summary_table(summary))
    parts.append("")
    parts.append("### Top findings")
    parts.append("")
    parts.append(_top_findings_table(scored))
    parts.append("")

    parts.append("## Findings by priority")
    parts.append("")

    for bucket in BUCKET_ORDER:
        bucket_findings = grouped.get(bucket, [])
        if not bucket_findings:
            continue
        parts.append(f"### {BUCKET_HEADERS[bucket]} ({len(bucket_findings)})")
        parts.append("")
        parts.append(f"**Recommended action:** {BUCKET_ACTIONS[bucket]}")
        parts.append("")
        for finding in bucket_findings:
            parts.append(_format_finding_block(finding))
        parts.append("")

    parts.append("## Appendix: filtered findings")
    parts.append("")
    parts.append(
        f"The following {len(culled)} findings were filtered out by the rubric's cull rules. "
        "They are listed here for completeness — the analyst should still glance through to confirm "
        "nothing important was unfairly dropped."
    )
    parts.append("")
    parts.append("<details><summary>Show culled findings</summary>")
    parts.append("")
    parts.append(_culled_appendix(culled))
    parts.append("")
    parts.append("</details>")
    parts.append("")

    parts.append("## Methodology")
    parts.append("")
    parts.append(
        "Each finding is scored using a deterministic formula combining technical severity (CVSS), "
        "asset and data context from the analyst interview, organizational defense posture, and "
        "regulatory/operational pressures."
    )
    parts.append("")
    parts.append("```")
    parts.append("cvss_norm        = CVSS / 10")
    parts.append("headroom         = 1.0 - cvss_norm")
    parts.append("base_likelihood  = min(1.0, cvss_norm + headroom × (exposure_boost + exploit_boost))")
    parts.append("material_cost    = (asset × 0.4) + (data × 0.4) + (CIA × 0.2)")
    parts.append("raw_score        = base_likelihood × material_cost")
    parts.append("adjusted_score   = raw_score × (1 - defense_adjustment)")
    parts.append("final_score      = adjusted_score × org_context_modifier")
    parts.append("```")
    parts.append("")
    parts.append(
        "Bucket thresholds, multipliers, and cull rules are tunable constants in "
        "`prompt_management.py`. See the rubric design report for the reasoning behind each component."
    )
    parts.append("")
    parts.append("---")
    parts.append("")
    parts.append("_Generated by VM Risk Agent._")

    return "\n".join(parts)


def write_report(results, output_path, scan_metadata=None):
    """Generate the report and write it to disk. Returns the output_path."""
    markdown = generate_report(results, scan_metadata)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown)
    return output_path


if __name__ == "__main__":
    # Standalone test: generate a report from rubric mock data with placeholder rationales
    import sys
    sys.path.insert(0, ".")
    import rubric

    print("Generating sample report from mock findings (no LLM rationale)...")
    results = rubric.score_all(
        rubric.MOCK_FINDINGS,
        rubric.MOCK_INTERVIEW,
        attach_rationales_flag=False,
    )
    metadata = {
        "scan_name": "Sample Mock Scan",
        "host": "mock-host-01",
        "scan_date": datetime.now().strftime("%Y-%m-%d"),
        "analyst": "Test Analyst",
    }
    output_path = "sample_report.md"
    write_report(results, output_path, metadata)
    print(f"Report written to: {output_path}")