"""
csv_parser.py

Translates a Tenable Vulnerability Management CSV export into the finding-dict
format that rubric.py expects.

Tenable writes one row per CVE. Multiple CVEs covered by the same plugin
appear as multiple rows sharing a Plugin ID. The parser de-duplicates by
Plugin ID and preserves all CVEs as a list on the finding.

Output finding dict shape (matches rubric.py expectations):
    {
        "id": "211725",                          # Plugin ID
        "title": "7-Zip < 24.07 RCE (ZDI-24-1532)",
        "host": "vm-risk-lab-01",
        "cvss": 7.8,                             # prefer CVSS3, fallback to CVSS v2
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/...", # normalized with CVSS:3.1/ prefix
        "exploit_status": "metasploit" | "poc" | "none",
        "severity": "critical" | "high" | "medium" | "low" | "informational",
        # extras for report context
        "cves": ["CVE-2024-..."],
        "synopsis": "...",
        "description": "...",
        "solution": "...",
        "patch_available": True | False,
        "unsupported_by_vendor": True | False,
        "vpr": 7.2 | None,                       # Tenable's own priority
        "cvss_source": "v3" | "v2" | "none",     # which CVSS we used
    }
"""

import csv
from collections import defaultdict


# Tenable Risk column → rubric severity
SEVERITY_MAP = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "None": "informational",
    "": "informational",
}


def _to_bool(value):
    """Tenable writes 'true'/'false' as lowercase strings."""
    if isinstance(value, bool):
        return value
    if not value:
        return False
    return str(value).strip().lower() == "true"


def _to_float(value):
    """Best-effort float parse. Returns None if blank or unparseable."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def derive_exploit_status(row):
    """
    Map Tenable's exploit-availability columns to the rubric's three-level
    exploit_status. Conservative: any weaponized-exploit signal wins over PoC.

    Strong signals (→ "metasploit", 1.5x multiplier):
      - Metasploit module exists
      - Core Exploits available (commercial weaponized)
      - Exploited by Malware (in-the-wild abuse)

    Weak signal (→ "poc", 1.3x multiplier):
      - Exploit Available true (PoC or technique known)

    Otherwise → "none" (1.0x multiplier).
    """
    weaponized_signals = [
        _to_bool(row.get("Metasploit")),
        _to_bool(row.get("Core Exploits")),
        _to_bool(row.get("Exploited by Malware")),
        _to_bool(row.get("CANVAS")),
        _to_bool(row.get("D2 Elliot")),
    ]
    if any(weaponized_signals):
        return "metasploit"
    if _to_bool(row.get("Exploit Available")):
        return "poc"
    return "none"


def pick_cvss(row):
    """
    Return (cvss_score, cvss_vector, source_label).
    Prefer CVSS v3 (modern standard). Fall back to CVSS v2.

    Tenable writes vectors without the 'CVSS:3.1/' or 'CVSS:2.0/' prefix
    (e.g., 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'). The rubric's parser expects
    a 'CVSS:X/' prefix to recognize the vector as valid, so we add it back.
    """
    v3_score = _to_float(row.get("CVSS3 Base Score"))
    v3_vector = (row.get("CVSS3 Vector") or "").strip()
    if v3_score is not None and v3_vector:
        return v3_score, f"CVSS:3.1/{v3_vector}", "v3"

    v2_score = _to_float(row.get("CVSS Base Score") or row.get("CVSS"))
    v2_vector = (row.get("CVSS Vector") or "").strip()
    if v2_score is not None and v2_vector:
        return v2_score, f"CVSS:2.0/{v2_vector}", "v2"

    # Last resort: CVSS column with no vector. Score will work, vector parse
    # will fail in rubric.py and trigger the CIA fallback to code_execution (1.0).
    bare_score = _to_float(row.get("CVSS"))
    if bare_score is not None:
        return bare_score, "", "score_only"

    return 0.0, "", "none"


def parse_csv(csv_path):
    """
    Parse a Tenable VM CSV export. Returns a list of finding dicts ready for
    rubric.score_all().
    """
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    # Group rows by Plugin ID. Tenable splits multi-CVE plugins across rows.
    groups = defaultdict(list)
    for row in rows:
        plugin_id = (row.get("Plugin ID") or "").strip()
        if not plugin_id:
            continue
        groups[plugin_id].append(row)

    findings = []
    for plugin_id, group_rows in groups.items():
        # All rows in a group share the same plugin metadata. Use the first
        # row for shared fields and collect CVEs across all rows.
        first = group_rows[0]

        cves = []
        seen_cves = set()
        for r in group_rows:
            cve = (r.get("CVE") or "").strip()
            if cve and cve not in seen_cves:
                cves.append(cve)
                seen_cves.add(cve)

        cvss_score, cvss_vector, cvss_source = pick_cvss(first)
        severity = SEVERITY_MAP.get((first.get("Risk") or "").strip(), "informational")

        finding = {
            "id": plugin_id,
            "title": (first.get("Name") or "").strip(),
            "host": (first.get("Host") or "").strip() or (first.get("FQDN") or "").strip(),
            "cvss": cvss_score,
            "cvss_vector": cvss_vector,
            "exploit_status": derive_exploit_status(first),
            "severity": severity,
            "cves": cves,
            "synopsis": (first.get("Synopsis") or "").strip(),
            "description": (first.get("Description") or "").strip(),
            "solution": (first.get("Solution") or "").strip(),
            "patch_available": _to_bool(first.get("Patch Available")),
            "unsupported_by_vendor": _to_bool(first.get("Unsupported By Vendor")),
            "vpr": _to_float(first.get("Vulnerability Priority Rating (VPR)")),
            "cvss_source": cvss_source,
        }
        findings.append(finding)

    return findings


def summarize(findings):
    """Quick stats on parsed findings — useful for sanity-checking the parse."""
    by_severity = defaultdict(int)
    by_exploit = defaultdict(int)
    by_cvss_source = defaultdict(int)
    with_patch = 0
    unsupported = 0
    no_vector = 0

    for f in findings:
        by_severity[f["severity"]] += 1
        by_exploit[f["exploit_status"]] += 1
        by_cvss_source[f["cvss_source"]] += 1
        if f["patch_available"]:
            with_patch += 1
        if f["unsupported_by_vendor"]:
            unsupported += 1
        if not f["cvss_vector"]:
            no_vector += 1

    return {
        "total": len(findings),
        "by_severity": dict(by_severity),
        "by_exploit_status": dict(by_exploit),
        "by_cvss_source": dict(by_cvss_source),
        "with_patch_available": with_patch,
        "unsupported_by_vendor": unsupported,
        "no_cvss_vector": no_vector,
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 csv_parser.py <path_to_tenable.csv>")
        sys.exit(1)

    csv_path = sys.argv[1]
    findings = parse_csv(csv_path)
    stats = summarize(findings)

    print("\n" + "=" * 70)
    print("CSV PARSE SUMMARY")
    print("=" * 70)
    print(f"\nUnique findings (by Plugin ID): {stats['total']}")
    print(f"\nBy severity: {stats['by_severity']}")
    print(f"By exploit status: {stats['by_exploit_status']}")
    print(f"By CVSS source: {stats['by_cvss_source']}")
    print(f"\nWith patch available: {stats['with_patch_available']}")
    print(f"Unsupported by vendor: {stats['unsupported_by_vendor']}")
    print(f"Missing CVSS vector: {stats['no_cvss_vector']}")

    # Show a few sample findings
    print("\n" + "=" * 70)
    print("SAMPLE FINDINGS (first scored finding from each severity)")
    print("=" * 70)
    seen_severities = set()
    for f in findings:
        if f["severity"] in seen_severities or f["severity"] == "informational":
            continue
        seen_severities.add(f["severity"])
        print(f"\n[{f['id']}] {f['title']}")
        print(f"  severity={f['severity']}  cvss={f['cvss']}  exploit={f['exploit_status']}")
        print(f"  vector={f['cvss_vector'][:60]}...")
        print(f"  CVEs ({len(f['cves'])}): {f['cves'][:3]}{'...' if len(f['cves']) > 3 else ''}")
        print(f"  patch_available={f['patch_available']}  vpr={f['vpr']}")
