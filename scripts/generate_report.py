#!/usr/bin/env python3
"""
Generate markdown daily/weekly/monthly reports from collected metrics.
"""

import json
import re
from datetime import datetime
from typing import Dict, Any, List


def format_pr_status(pr: Dict[str, Any]) -> str:
    """Format PR status section."""
    state_emoji = "🟢" if pr["state"] == "open" else "🟣"
    merged_emoji = "✅" if pr.get("merged_at") else ""

    lines = [
        "## PR Status",
        "",
        f"**{state_emoji} #{pr['url'].split('/')[-1]}** — {pr['title']}",
        f"  • State: {pr['state'].upper()} {merged_emoji}",
        f"  • Comments: {pr['comments_count']}",
        f"  • Reviews: {pr['review_count']}",
        f"  • Reactions: 👍 {pr['reactions'].get('thumbs_up', 0)} ❤️ {pr['reactions'].get('heart', 0)}",
        f"  • Created: {pr['created_at'][:10]}",
        f"  • Updated: {pr['updated_at'][:10]}",
        "",
    ]

    if pr["latest_comments"]:
        lines.append("### Recent Comments")
        for comment in pr["latest_comments"]:
            lines.append(
                f"  > **{comment['author']}** ({comment['created_at'][:10]}): "
                f"{comment['body']}..."
            )
        lines.append("")

    return "\n".join(lines)


def format_repo_stats(repo: Dict[str, Any]) -> str:
    """Format repository statistics."""
    lines = [
        "## Repository Stats",
        "",
        f"**{repo['full_name']}**",
        f"  • ⭐ Stars: {repo['stars']:,}",
        f"  • 🍴 Forks: {repo['forks']:,}",
        f"  • 👀 Watchers: {repo['watchers']:,}",
        f"  • 🐛 Open Issues: {repo['open_issues']}",
        f"  • 📝 Language: {repo['language'] or 'N/A'}",
        f"  • 📅 Last Updated: {repo['updated_at'][:10]}",
        "",
    ]

    if repo["topics"]:
        lines.append(f"**Topics:** {', '.join([f'`{t}`' for t in repo['topics'][:8]])}")
        lines.append("")

    return "\n".join(lines)


def format_related_issues(issues_by_keyword: Dict[str, list]) -> str:
    """Format related issues section."""
    lines = [
        "## Related Issues & Activity",
        "",
    ]

    issue_count = sum(len(v) for v in issues_by_keyword.values())
    lines.append(f"**Found {issue_count} related issues across {len(issues_by_keyword)} keywords**")
    lines.append("")

    for keyword, issues in issues_by_keyword.items():
        if issues:
            lines.append(f"### {keyword.capitalize()}")
            for issue in issues[:3]:
                status = "✅" if issue["state"] == "closed" else "🔵"
                lines.append(
                    f"  {status} [#{issue['number']}]({issue['url']}) — {issue['title']}"
                )
                lines.append(f"     • {issue['comments']} comments | {issue['created_at'][:10]}")
            lines.append("")

    return "\n".join(lines)


_SECURITY_SIGNAL_PATTERNS = [
    (
        "critical",
        [
            "exposed secret",
            "leaked credential",
            "leaked secret",
            "hardcoded secret",
            "hardcoded credential",
            "private key leak",
            "remote code execution",
            "rce",
            "backdoor",
            "malicious package",
            "malicious dependency",
            "mal-",
        ],
    ),
    (
        "high",
        [
            "secret leak",
            "credential leak",
            "token leak",
            "api key",
            "apikey",
            "supply chain",
            "exfiltrat",
            "cve-",
            "ghsa-",
            "pysec-",
            "rustsec-",
            "arbitrary code",
            "typosquat",
            "dependency confusion",
            "package hijack",
            "model poisoning",
            "data poisoning",
        ],
    ),
    (
        "medium",
        [
            "secret",
            "credential",
            "password",
            "hardcode",
            "vulnerab",
            "injection",
            "unauthorized",
            "leak",
        ],
    ),
]

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1}
_SEVERITY_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨"}

# An open critical/high issue with no activity for this many days is stale: the
# risk is still live but nobody is working it, which is exactly what a maintainer
# scanning the report wants surfaced above the noise of freshly-active issues.
_STALE_DAYS = 14


def _age_in_days(updated_at: str, reference: str):
    """Whole days between an issue's last update and the report reference time.

    Returns None when either timestamp is missing or unparseable, so callers can
    treat unknown ages as "not stale" rather than guessing.
    """
    try:
        updated = datetime.strptime((updated_at or "")[:10], "%Y-%m-%d")
        ref = datetime.strptime((reference or "")[:10], "%Y-%m-%d")
    except ValueError:
        return None
    return (ref - updated).days

# Pre-compile each keyword as a word-boundary-anchored prefix match. Anchoring on
# `\b` stops short acronyms (e.g. "rce") from matching inside unrelated words
# ("source", "resource", "enforce", "commerce") while still allowing genuine
# stems ("exfiltrat" → "exfiltration", "vulnerab" → "vulnerability") to match.
# Internal spaces in multi-word terms are compiled to `[\s-]+`, so hyphenated or
# line-wrapped variants ("supply-chain", "remote-code-execution", "api\nkey")
# still match the same signal.
def _compile_signal_term(term: str) -> "re.Pattern[str]":
    return re.compile(r"\b" + r"[\s-]+".join(re.escape(part) for part in term.split(" ")))


_COMPILED_SIGNAL_PATTERNS = [
    (severity, [(term, _compile_signal_term(term)) for term in terms])
    for severity, terms in _SECURITY_SIGNAL_PATTERNS
]


# A `cve-` keyword match tells a maintainer *that* a CVE is referenced, but the
# actionable detail is *which* one. Extract the full identifier(s) so the report
# surfaces `CVE-2024-1234` directly instead of a bare "matched cve-". The year is
# four digits; the sequence is 4+ digits per the CVE ID format.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def extract_cve_ids(*texts: str) -> List[str]:
    """Return uppercased, de-duplicated CVE identifiers across the given texts.

    Order is preserved by first appearance so the most prominently-referenced ID
    (usually the title's) leads. Non-CVE text yields an empty list.
    """
    seen: Dict[str, None] = {}
    for text in texts:
        for match in _CVE_RE.findall(text or ""):
            seen.setdefault(match.upper(), None)
    return list(seen)


# GitHub Security Advisory IDs identify advisories that often have no CVE yet —
# the common case for PyPI/npm package vulnerabilities surfaced through GitHub.
# The syntax is a fixed `GHSA` prefix plus three hyphen-separated groups of four
# characters drawn from the base32-style set `23456789cfghjmpqrvwx` (canonically
# lowercase). Extracting the full ID gives a maintainer the exact advisory to
# open, the same way `extract_cve_ids` does for CVEs.
_GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE)


def extract_ghsa_ids(*texts: str) -> List[str]:
    """Return canonicalized, de-duplicated GHSA identifiers across the texts.

    Canonical form is an uppercase `GHSA` prefix with a lowercase body. Order is
    preserved by first appearance. Non-GHSA text yields an empty list.
    """
    seen: Dict[str, None] = {}
    for text in texts:
        for match in _GHSA_RE.findall(text or ""):
            prefix, _, body = match.partition("-")
            seen.setdefault(f"{prefix.upper()}-{body.lower()}", None)
    return list(seen)


# A CWE (Common Weakness Enumeration) identifier names the *class* of flaw — e.g.
# CWE-798 "Use of Hard-coded Credentials" or CWE-522 "Insufficiently Protected
# Credentials", both squarely on-theme for this tracker. Advisories and issues
# cite them alongside or instead of a CVE, so surfacing the weakness class gives a
# maintainer the "what kind of bug" at a glance. IDs are `CWE-` plus 1–5 digits.
_CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)


def extract_cwe_ids(*texts: str) -> List[str]:
    """Return uppercased, de-duplicated CWE identifiers across the given texts.

    Order is preserved by first appearance. Non-CWE text yields an empty list.
    """
    seen: Dict[str, None] = {}
    for text in texts:
        for match in _CWE_RE.findall(text or ""):
            seen.setdefault(match.upper(), None)
    return list(seen)


# An OSV `MAL-YYYY-N` identifier names a *malicious* package advisory (a typosquat,
# backdoor, or hijacked dependency) rather than a vulnerability in benign code —
# the single most on-theme signal for an AI supply-chain tracker. Malicious
# packages are often published with a MAL advisory (frequently aliased to a PYSEC
# ID) and no CVE at all, so keying only on `cve-` missed them. The format is a
# fixed `MAL-` prefix, a four-digit year, and a numeric sequence.
_MAL_RE = re.compile(r"\bMAL-\d{4}-\d+\b", re.IGNORECASE)


def extract_mal_ids(*texts: str) -> List[str]:
    """Return uppercased, de-duplicated OSV MAL advisory IDs across the texts.

    Order is preserved by first appearance. Non-MAL text yields an empty list.
    """
    seen: Dict[str, None] = {}
    for text in texts:
        for match in _MAL_RE.findall(text or ""):
            seen.setdefault(match.upper(), None)
    return list(seen)


# A `PYSEC-YYYY-N` identifier is the PyPA advisory-database ID for a Python
# package vulnerability — the direct namespace for the PyPI supply chain that
# underpins virtually every ML/AI toolchain. Many PyPI advisories carry a PYSEC
# ID with no CVE (the same root issue may surface as a GHSA on GitHub and a PYSEC
# in PyPA), so keying only on `cve-`/`ghsa-` missed the Python-native case. The
# format mirrors MAL: a fixed `PYSEC-` prefix, a four-digit year, and a numeric
# sequence (verified against OSV, e.g. PYSEC-2026-188, PYSEC-2026-3).
_PYSEC_RE = re.compile(r"\bPYSEC-\d{4}-\d+\b", re.IGNORECASE)


def extract_pysec_ids(*texts: str) -> List[str]:
    """Return uppercased, de-duplicated PyPA PYSEC advisory IDs across the texts.

    Order is preserved by first appearance. Non-PYSEC text yields an empty list.
    """
    seen: Dict[str, None] = {}
    for text in texts:
        for match in _PYSEC_RE.findall(text or ""):
            seen.setdefault(match.upper(), None)
    return list(seen)


# A `RUSTSEC-YYYY-NNNN` identifier is the RustSec advisory-database ID for a
# vulnerability in a crate published through crates.io — directly on-theme for an
# AI supply-chain tracker, since the Rust ecosystem now underpins core ML tooling
# (HuggingFace `safetensors`, `tokenizers`, and the `candle` inference framework
# are all Rust crates). RustSec advisories frequently predate or never receive a
# CVE, so keying only on `cve-`/`ghsa-` missed the Rust-native case. The format is
# a fixed `RUSTSEC-` prefix, a four-digit year, and a four-digit zero-padded
# sequence (verified against rustsec.org, e.g. RUSTSEC-2021-0125, RUSTSEC-2018-0001).
_RUSTSEC_RE = re.compile(r"\bRUSTSEC-\d{4}-\d{4}\b", re.IGNORECASE)


def extract_rustsec_ids(*texts: str) -> List[str]:
    """Return uppercased, de-duplicated RustSec advisory IDs across the texts.

    Order is preserved by first appearance. Non-RUSTSEC text yields an empty list.
    """
    seen: Dict[str, None] = {}
    for text in texts:
        for match in _RUSTSEC_RE.findall(text or ""):
            seen.setdefault(match.upper(), None)
    return list(seen)


# A `GO-YYYY-NNNN` identifier is the Go vulnerability database ID (pkg.go.dev/vuln)
# for a flaw in a Go module — on-theme because the Go ecosystem hosts a growing
# share of AI infrastructure and LLM-serving tooling (Ollama, LocalAI, and most
# container/orchestration layers are written in Go). Go advisories are frequently
# published with no CVE. The format is a fixed `GO-` prefix, a four-digit year, and
# a four-digit zero-padded sequence (verified against pkg.go.dev/vuln, e.g.
# GO-2022-0322, GO-2021-0113). Unlike the other advisory stems this is NOT added to
# the keyword tiers: a bare `go-` stem would false-match "go-live" / "go-to", so the
# precise full-ID anchor is used both to extract and — below — to detect.
_GO_RE = re.compile(r"\bGO-\d{4}-\d{4}\b", re.IGNORECASE)


def extract_go_ids(*texts: str) -> List[str]:
    """Return uppercased, de-duplicated Go vuln-database IDs across the texts.

    Order is preserved by first appearance. Non-GO text yields an empty list.
    """
    seen: Dict[str, None] = {}
    for text in texts:
        for match in _GO_RE.findall(text or ""):
            seen.setdefault(match.upper(), None)
    return list(seen)


def _match_severity(text: str):
    """Return the highest-severity (severity, term) matched in text, or (None, None)."""
    text = (text or "").lower()
    for severity, terms in _COMPILED_SIGNAL_PATTERNS:
        for term, pattern in terms:
            if pattern.search(text):
                return severity, term
    return None, None


# Maintainer-applied labels are curated signals: a bare `security` label carries
# intent that free-text matching deliberately ignores (the word "security" is too
# common in this ecosystem to key on in a body). These map label names the keyword
# tiers miss to a severity; labels that already contain a tiered stem (e.g.
# "vulnerability", "supply-chain") fall through to _match_severity.
_SECURITY_LABELS = {
    "security": "high",
    "cve": "high",
    "exploit": "high",
    "0day": "high",
}


def _match_label_severity(labels):
    """Return the highest-severity (severity, term) matched across issue labels."""
    best_severity, best_term = None, None
    for name in labels or []:
        key = (name or "").strip().lower()
        severity = _SECURITY_LABELS.get(key)
        term = key
        if severity is None:
            severity, term = _match_severity(key)
        if severity and (
            best_severity is None
            or _SEVERITY_RANK[severity] > _SEVERITY_RANK[best_severity]
        ):
            best_severity, best_term = severity, term
    return best_severity, best_term


def detect_security_signals(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scan tracked issues for security-risk keywords and rank by severity.

    Each issue's labels, title, and body are matched against tiered keyword
    patterns; the issue is assigned the highest-severity tier matched across the
    three, with labels preferred over the title and the title over the body on
    ties (a maintainer-applied label is the strongest signal). Returns a
    de-duplicated list sorted by severity (critical first), then open-before-
    closed (open issues are still actionable), then stale-before-fresh (a live
    risk nobody is working outranks a freshly-active peer), then by comment
    activity.
    """
    signals: Dict[int, Dict[str, Any]] = {}
    reference = metrics.get("generated_at", "")

    for keyword, issues in (metrics.get("related_issues") or {}).items():
        for issue in issues:
            label_sev, label_term = _match_label_severity(issue.get("labels"))
            title_sev, title_term = _match_severity(issue.get("title"))
            body_sev, body_term = _match_severity(issue.get("body"))

            title_text = issue.get("title", "")
            body_text = issue.get("body", "")
            go_ids = extract_go_ids(title_text, body_text)

            candidates = []
            if label_sev:
                candidates.append((_SEVERITY_RANK[label_sev], 3, label_sev, label_term, "label"))
            if title_sev:
                candidates.append((_SEVERITY_RANK[title_sev], 2, title_sev, title_term, "title"))
            if body_sev:
                candidates.append((_SEVERITY_RANK[body_sev], 1, body_sev, body_term, "body"))
            if go_ids:
                go_in_title = bool(_GO_RE.search(title_text))
                candidates.append((
                    _SEVERITY_RANK["high"], 2 if go_in_title else 1,
                    "high", go_ids[0], "title" if go_in_title else "body",
                ))
            if not candidates:
                continue

            candidates.sort(reverse=True)
            _, _, matched_severity, matched_term, matched_in = candidates[0]

            number = issue.get("number")
            existing = signals.get(number)
            if existing and _SEVERITY_RANK[existing["severity"]] >= _SEVERITY_RANK[matched_severity]:
                continue

            state = issue.get("state", "")
            cve_ids = extract_cve_ids(issue.get("title", ""), issue.get("body", ""))
            ghsa_ids = extract_ghsa_ids(issue.get("title", ""), issue.get("body", ""))
            cwe_ids = extract_cwe_ids(issue.get("title", ""), issue.get("body", ""))
            mal_ids = extract_mal_ids(issue.get("title", ""), issue.get("body", ""))
            pysec_ids = extract_pysec_ids(issue.get("title", ""), issue.get("body", ""))
            rustsec_ids = extract_rustsec_ids(issue.get("title", ""), issue.get("body", ""))
            age_days = _age_in_days(issue.get("updated_at", ""), reference)
            stale = (
                state != "closed"
                and matched_severity in ("critical", "high")
                and age_days is not None
                and age_days >= _STALE_DAYS
            )

            signals[number] = {
                "number": number,
                "title": issue.get("title", ""),
                "url": issue.get("url", ""),
                "state": state,
                "comments": issue.get("comments", 0),
                "severity": matched_severity,
                "matched_term": matched_term,
                "matched_in": matched_in,
                "cve_ids": cve_ids,
                "ghsa_ids": ghsa_ids,
                "cwe_ids": cwe_ids,
                "mal_ids": mal_ids,
                "pysec_ids": pysec_ids,
                "rustsec_ids": rustsec_ids,
                "go_ids": go_ids,
                "age_days": age_days,
                "stale": stale,
            }

    return sorted(
        signals.values(),
        key=lambda s: (
            _SEVERITY_RANK[s["severity"]],
            0 if s["state"] == "closed" else 1,
            1 if s.get("stale") else 0,
            s["comments"],
        ),
        reverse=True,
    )


def format_security_signals(signals: List[Dict[str, Any]]) -> str:
    """Format the ranked security-signal section."""
    lines = ["## 🔐 Security Signals", ""]

    if not signals:
        lines.append("No elevated security signals detected in tracked issues.")
        lines.append("")
        return "\n".join(lines)

    counts = {"critical": 0, "high": 0, "medium": 0}
    for signal in signals:
        counts[signal["severity"]] += 1

    stale_total = sum(1 for s in signals if s.get("stale"))
    header = (
        f"**{len(signals)} signal(s)** — "
        f"🟥 {counts['critical']} critical · "
        f"🟧 {counts['high']} high · "
        f"🟨 {counts['medium']} medium"
    )
    if stale_total:
        header += f" · ⚠️ {stale_total} stale"
    tracked_cves = list(dict.fromkeys(c for s in signals for c in s.get("cve_ids", [])))
    if tracked_cves:
        header += f" · 🆔 {len(tracked_cves)} CVE(s)"
    tracked_ghsa = list(dict.fromkeys(g for s in signals for g in s.get("ghsa_ids", [])))
    if tracked_ghsa:
        header += f" · 📛 {len(tracked_ghsa)} GHSA(s)"
    tracked_cwe = list(dict.fromkeys(w for s in signals for w in s.get("cwe_ids", [])))
    if tracked_cwe:
        header += f" · 🧬 {len(tracked_cwe)} CWE(s)"
    tracked_mal = list(dict.fromkeys(m for s in signals for m in s.get("mal_ids", [])))
    if tracked_mal:
        header += f" · 🦠 {len(tracked_mal)} MAL(s)"
    tracked_pysec = list(dict.fromkeys(p for s in signals for p in s.get("pysec_ids", [])))
    if tracked_pysec:
        header += f" · 🐍 {len(tracked_pysec)} PYSEC(s)"
    tracked_rustsec = list(dict.fromkeys(r for s in signals for r in s.get("rustsec_ids", [])))
    if tracked_rustsec:
        header += f" · 🦀 {len(tracked_rustsec)} RUSTSEC(s)"
    tracked_go = list(dict.fromkeys(g for s in signals for g in s.get("go_ids", [])))
    if tracked_go:
        header += f" · 🐹 {len(tracked_go)} GO(s)"
    lines.append(header)
    lines.append("")

    for signal in signals:
        emoji = _SEVERITY_EMOJI[signal["severity"]]
        state = "✅" if signal["state"] == "closed" else "🔵"
        lines.append(
            f"  {emoji} **{signal['severity'].upper()}** {state} "
            f"[#{signal['number']}]({signal['url']}) — {signal['title']}"
        )
        detail = (
            f"     • matched `{signal['matched_term']}` in {signal.get('matched_in', 'title')} "
            f"| {signal['comments']} comments"
        )
        if signal.get("cve_ids"):
            detail += f" | 🆔 {', '.join(signal['cve_ids'])}"
        if signal.get("ghsa_ids"):
            detail += f" | 📛 {', '.join(signal['ghsa_ids'])}"
        if signal.get("cwe_ids"):
            detail += f" | 🧬 {', '.join(signal['cwe_ids'])}"
        if signal.get("mal_ids"):
            detail += f" | 🦠 {', '.join(signal['mal_ids'])}"
        if signal.get("pysec_ids"):
            detail += f" | 🐍 {', '.join(signal['pysec_ids'])}"
        if signal.get("rustsec_ids"):
            detail += f" | 🦀 {', '.join(signal['rustsec_ids'])}"
        if signal.get("go_ids"):
            detail += f" | 🐹 {', '.join(signal['go_ids'])}"
        if signal.get("stale"):
            detail += f" | ⚠️ stale {signal['age_days']}d"
        lines.append(detail)
    lines.append("")

    return "\n".join(lines)


def format_signal_insight(signals: List[Dict[str, Any]]) -> str:
    """Build the Key Insights line, leading with the open critical/high count.

    The headline number for triage is how many high-severity signals are still
    open — those are what a maintainer must act on today, not the resolved ones.
    """
    total = len(signals)
    if total == 0:
        return "0 elevated signal(s) detected in tracked issues"

    open_actionable = sum(
        1
        for s in signals
        if s["state"] != "closed" and s["severity"] in ("critical", "high")
    )
    if open_actionable:
        stale = sum(1 for s in signals if s.get("stale"))
        tail = f"{open_actionable} open critical/high need attention"
        if stale:
            tail += f" ({stale} stale >{_STALE_DAYS}d)"
    else:
        tail = "none open critical/high"
    return f"{total} elevated signal(s) — {tail}"


def generate_daily_report(metrics: Dict[str, Any]) -> str:
    """Generate daily report markdown."""
    generated = metrics.get("generated_at", "").split("T")[0]

    report = f"""================================================================================
  📊 Credential Guard Tracker — Daily Report
  {generated}
================================================================================

> Automated ecosystem tracking for credential-guard plugin (#62099)

{format_pr_status(metrics['pr'])}

{format_repo_stats(metrics['repo'])}

{format_related_issues(metrics['related_issues'])}

{format_security_signals(detect_security_signals(metrics))}

## 🎯 Key Insights

- **PR Health:** {metrics['pr']['state'].upper()} with {metrics['pr']['comments_count']} comments
- **Repository Momentum:** ⭐ {metrics['repo']['stars']:,} stars, 📊 {metrics['repo']['watchers']:,} watchers
- **Ecosystem Activity:** {sum(len(v) for v in metrics['related_issues'].values())} related issues found
- **Security Signals:** {format_signal_insight(detect_security_signals(metrics))}
- **Last Activity:** {metrics['repo']['updated_at'][:10]}

## 📌 Notes

This report is auto-generated daily. Last update: {datetime.utcnow().isoformat()}Z

---

**Links:**
- PR: {metrics['pr']['url']}
- Repo: https://github.com/{metrics['repo']['full_name']}
- Issues: {metrics['repo']['full_name']}/issues

"""

    return report


def _format_delta(delta: int) -> str:
    """Render a signed change, avoiding '+-3' for negative deltas."""
    if delta > 0:
        return f"+{delta}"
    if delta < 0:
        return str(delta)
    return "0"


def _weekly_highlights(earliest: Dict[str, Any], latest: Dict[str, Any]) -> str:
    """Build data-driven highlights from the actual start/end deltas."""
    stars_delta = latest["repo"]["stars"] - earliest["repo"]["stars"]
    comments_delta = latest["pr"]["comments_count"] - earliest["pr"]["comments_count"]
    pr_state = latest["pr"]["state"]
    issues_total = sum(len(v) for v in latest.get("related_issues", {}).values())

    lines = []

    if latest["pr"].get("merged_at"):
        lines.append("✅ **Merged** — PR landed during this window")
    elif pr_state == "open":
        lines.append("🟢 **Open** — PR remains open during this window")
    else:
        lines.append("🟣 **Closed** — PR was closed during this window")

    if comments_delta > 0:
        lines.append(f"💬 **Active Discussion** — {_format_delta(comments_delta)} comments over the window")
    elif comments_delta == 0:
        lines.append("💬 **Quiet** — no new comments over the window")

    if stars_delta > 0:
        lines.append(f"✅ **Growing Interest** — {_format_delta(stars_delta)} stars over the 7-day window")
    elif stars_delta == 0:
        lines.append("➖ **Stable Interest** — star count unchanged over the window")
    else:
        lines.append(f"🔻 **Declining Interest** — {_format_delta(stars_delta)} stars over the window")

    if issues_total > 0:
        lines.append(f"🔵 **Ecosystem Engagement** — {issues_total} related issues detected in the Claude Code ecosystem")

    return "\n".join(lines)


def generate_weekly_report(metrics_history: list) -> str:
    """Generate weekly rollup report."""
    if not metrics_history:
        return "No metrics history available."

    latest = metrics_history[-1]
    earliest = metrics_history[0]

    comments_delta = latest['pr']['comments_count'] - earliest['pr']['comments_count']
    stars_delta = latest['repo']['stars'] - earliest['repo']['stars']
    issues_delta = latest['repo']['open_issues'] - earliest['repo']['open_issues']

    report = f"""================================================================================
  📈 Credential Guard Tracker — Weekly Rollup
  Week of {earliest.get('generated_at', '')[:10]}
================================================================================

> 7-day trend analysis for credential-guard security plugin

## Summary

| Metric | Start | End | Change |
|--------|-------|-----|--------|
| PR Comments | {earliest['pr']['comments_count']} | {latest['pr']['comments_count']} | {_format_delta(comments_delta)} |
| Repository Stars | {earliest['repo']['stars']} | {latest['repo']['stars']} | {_format_delta(stars_delta)} |
| Open Issues | {earliest['repo']['open_issues']} | {latest['repo']['open_issues']} | {_format_delta(issues_delta)} |

## Highlights

{_weekly_highlights(earliest, latest)}

## Recommendations

1. Monitor for maintainer feedback on PR
2. Prepare for potential feature requests or change requests
3. Consider documentation updates based on community feedback
4. Track adoption metrics once PR is merged

---

*Report generated: {datetime.utcnow().isoformat()}Z*

"""

    return report


def main():
    """Main entry point."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: generate_report.py <metrics.json> [weekly|monthly]")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        metrics = json.load(f)

    report_type = sys.argv[2] if len(sys.argv) > 2 else "daily"

    if report_type == "weekly":
        report = generate_weekly_report([metrics])
    else:
        report = generate_daily_report(metrics)

    print(report)


if __name__ == "__main__":
    main()
