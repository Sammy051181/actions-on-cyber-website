import calendar
import datetime as dt
import hashlib
import html
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

import feedparser
import requests
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from openai import OpenAI


# ============================================================
# Configuration
# ============================================================

TIMEZONE = ZoneInfo("Europe/London")

ROOT_DIR = Path(__file__).resolve().parents[1]

INDEX_PAGE = ROOT_DIR / "pages" / "daily-int-brief.html"
ARCHIVE_DIR = ROOT_DIR / "pages" / "daily-int-briefs"
STATE_FILE = ROOT_DIR / "data" / "daily-int-brief-seen-items.json"

MAX_BRIEFS_PER_DAY = 3
LOOKBACK_HOURS = 48
MAX_ITEMS_TO_REVIEW = 60
MAX_CANDIDATES_FOR_AI = 12
MIN_SCORE_TO_PUBLISH = 10
STATE_RETENTION_DAYS = 90

MODEL = os.getenv("OPENAI_MODEL", "gpt-5.2")
FORCE_PUBLISH = os.getenv("FORCE_PUBLISH", "false").lower() == "true"

USER_AGENT = (
    "ActionsOnCyberDailySMBIntelligenceBrief/1.0 "
    "(https://actionsoncyber.com; hello@actionsoncyber.com)"
)


# ============================================================
# Feeds
# ============================================================
#
# The aim is not to make this a vulnerability feed.
# These sources are used to spot:
# - major cyber incidents
# - supplier risk
# - ransomware
# - cloud/SaaS disruption
# - scams and phishing campaigns
# - big cyber stories being widely reported
# - official UK/US cyber warnings
#
# You can add/remove feeds later.

FEEDS = [
    {
        "name": "NCSC All Updates",
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
        "weight": 6,
    },
    {
        "name": "NCSC News",
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml",
        "weight": 6,
    },
    {
        "name": "NCSC Threat Reports",
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        "weight": 7,
    },
    {
        "name": "CISA Cybersecurity Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "weight": 5,
    },
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/cybersecurity-advisories/alerts.xml",
        "weight": 5,
    },
    {
        "name": "CISA News",
        "url": "https://www.cisa.gov/news.xml",
        "weight": 4,
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "weight": 4,
    },
    {
        "name": "The Hacker News",
        "url": "https://thehackernews.com/feeds/posts/default",
        "weight": 3,
    },
    {
        "name": "Google Threat Intelligence",
        "url": "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
        "weight": 5,
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "weight": 4,
    },
    {
        "name": "Sophos News",
        "url": "https://news.sophos.com/en-us/feed/",
        "weight": 3,
    },
    {
        "name": "Cisco Talos",
        "url": "https://blog.talosintelligence.com/rss/",
        "weight": 3,
    },
]


# ============================================================
# Scoring terms
# ============================================================

SME_RELEVANT_TERMS = {
    "ransomware": 8,
    "extortion": 6,
    "data breach": 7,
    "data leak": 6,
    "cyber attack": 7,
    "cyberattack": 7,
    "outage": 6,
    "disruption": 6,
    "supplier": 7,
    "supply chain": 8,
    "managed service provider": 8,
    "msp": 8,
    "it provider": 7,
    "cloud": 5,
    "saas": 5,
    "microsoft 365": 8,
    "office 365": 8,
    "google workspace": 7,
    "email compromise": 8,
    "business email compromise": 9,
    "bec": 7,
    "phishing": 7,
    "smishing": 6,
    "vishing": 6,
    "invoice": 7,
    "payment": 7,
    "bank details": 8,
    "fraud": 8,
    "scam": 7,
    "credential": 6,
    "password": 5,
    "mfa": 6,
    "token theft": 8,
    "session cookie": 7,
    "help desk": 6,
    "social engineering": 7,
    "deepfake": 7,
    "ai-generated": 5,
    "malware": 5,
    "infostealer": 7,
    "stealer": 6,
    "remote access": 6,
    "vpn": 5,
    "rdp": 5,
    "router": 5,
    "firewall": 5,
    "backup": 5,
    "retail": 4,
    "school": 5,
    "college": 5,
    "charity": 5,
    "healthcare": 4,
    "nhs": 5,
    "council": 5,
    "local government": 5,
    "law firm": 5,
    "accounting": 5,
    "payroll": 8,
    "hr": 5,
    "telecom": 5,
    "logistics": 5,
    "shipping": 5,
    "payment processor": 8,
    "bank": 5,
    "insurance": 4,
}

VULNERABILITY_ONLY_TERMS = [
    "cve-",
    "cvss",
    "proof-of-concept",
    "poc exploit",
    "patch tuesday",
    "security update",
    "remote code execution",
    "rce",
    "buffer overflow",
]

STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "have", "has", "are",
    "was", "were", "into", "after", "over", "under", "new", "latest", "update",
    "updates", "security", "cyber", "attack", "attacks", "hacking", "hackers",
    "breach", "data", "malware", "vulnerability", "vulnerabilities", "exploit",
    "exploits", "warns", "warning", "says", "report", "reports", "reported",
}


# ============================================================
# Utility functions
# ============================================================

def now_london() -> dt.datetime:
    return dt.datetime.now(TIMEZONE)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ensure_dirs() -> None:
    INDEX_PAGE.parent.mkdir(parents=True, exist_ok=True)
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)


def clean_text(value: str) -> str:
    if not value:
        return ""
    soup = BeautifulSoup(value, "html.parser")
    text = soup.get_text(" ", strip=True)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def stable_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def slugify(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value[:80] or "brief"


def parse_entry_date(entry: Any) -> dt.datetime:
    for key in ("published_parsed", "updated_parsed"):
        parsed = entry.get(key)
        if parsed:
            return dt.datetime.fromtimestamp(calendar.timegm(parsed), tz=dt.timezone.utc)

    for key in ("published", "updated", "created"):
        raw = entry.get(key)
        if raw:
            try:
                parsed_date = date_parser.parse(raw)
                if parsed_date.tzinfo is None:
                    parsed_date = parsed_date.replace(tzinfo=dt.timezone.utc)
                return parsed_date.astimezone(dt.timezone.utc)
            except Exception:
                pass

    return utc_now()


def read_state() -> Dict[str, Any]:
    if not STATE_FILE.exists():
        return {"seen_urls": {}, "published_briefs": []}

    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"seen_urls": {}, "published_briefs": []}

    data.setdefault("seen_urls", {})
    data.setdefault("published_briefs", [])
    return data


def save_state(state: Dict[str, Any]) -> None:
    cutoff = now_london() - dt.timedelta(days=STATE_RETENTION_DAYS)

    cleaned_seen = {}
    for url_hash, item in state.get("seen_urls", {}).items():
        seen_at = item.get("seen_at")
        try:
            seen_dt = date_parser.parse(seen_at)
            if seen_dt.tzinfo is None:
                seen_dt = seen_dt.replace(tzinfo=TIMEZONE)
        except Exception:
            continue

        if seen_dt >= cutoff:
            cleaned_seen[url_hash] = item

    cleaned_briefs = []
    for brief in state.get("published_briefs", []):
        published_at = brief.get("published_at")
        try:
            brief_dt = date_parser.parse(published_at)
            if brief_dt.tzinfo is None:
                brief_dt = brief_dt.replace(tzinfo=TIMEZONE)
        except Exception:
            continue

        if brief_dt >= cutoff:
            cleaned_briefs.append(brief)

    cleaned_briefs.sort(key=lambda x: x.get("published_at", ""), reverse=True)

    state["seen_urls"] = cleaned_seen
    state["published_briefs"] = cleaned_briefs[:250]

    with STATE_FILE.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def count_briefs_today(state: Dict[str, Any]) -> int:
    today = now_london().date().isoformat()
    count = 0

    for brief in state.get("published_briefs", []):
        published_at = brief.get("published_at", "")
        if published_at.startswith(today):
            count += 1

    return count


# ============================================================
# Feed collection and scoring
# ============================================================

def fetch_feed(feed: Dict[str, Any]) -> List[Dict[str, Any]]:
    headers = {"User-Agent": USER_AGENT}
    items = []

    try:
        response = requests.get(feed["url"], headers=headers, timeout=20)
        response.raise_for_status()
    except Exception as exc:
        print(f"Feed fetch failed: {feed['name']} - {exc}")
        return items

    parsed = feedparser.parse(response.content)

    for entry in parsed.entries[:30]:
        title = clean_text(entry.get("title", ""))
        summary = clean_text(entry.get("summary", "") or entry.get("description", ""))
        link = entry.get("link", "").strip()

        if not title or not link:
            continue

        published_utc = parse_entry_date(entry)
        age_hours = (utc_now() - published_utc).total_seconds() / 3600

        if age_hours > LOOKBACK_HOURS and not FORCE_PUBLISH:
            continue

        item_id = stable_id(link or title)

        items.append({
            "id": f"item_{item_id}",
            "source": feed["name"],
            "source_weight": feed.get("weight", 1),
            "title": title,
            "summary": summary[:800],
            "url": link,
            "published_utc": published_utc.isoformat(),
            "age_hours": round(age_hours, 1),
        })

    return items


def topic_tokens(text: str) -> set:
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s-]", " ", text)
    words = [w for w in text.split() if len(w) > 3 and w not in STOPWORDS]
    return set(words)


def score_item(item: Dict[str, Any]) -> int:
    text = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    score = int(item.get("source_weight", 1))

    for term, weight in SME_RELEVANT_TERMS.items():
        if term in text:
            score += weight

    vuln_term_hits = sum(1 for term in VULNERABILITY_ONLY_TERMS if term in text)
    has_business_context = any(
        term in text
        for term in [
            "supplier", "supply chain", "ransomware", "phishing", "fraud",
            "data breach", "outage", "msp", "managed service provider",
            "microsoft 365", "payment", "invoice", "cloud", "school",
            "charity", "retail", "healthcare", "council", "smb", "small business",
        ]
    )

    if vuln_term_hits >= 2 and not has_business_context:
        score -= 8
    elif vuln_term_hits >= 1 and not has_business_context:
        score -= 4

    if item.get("age_hours", 999) <= 12:
        score += 3
    elif item.get("age_hours", 999) <= 24:
        score += 2

    return score


def apply_cross_source_boost(items: List[Dict[str, Any]]) -> None:
    token_map = {}

    for item in items:
        tokens = topic_tokens(f"{item['title']} {item['summary']}")
        item["topic_tokens"] = list(tokens)

    for i, item in enumerate(items):
        boost = 0
        item_tokens = set(item.get("topic_tokens", []))

        if not item_tokens:
            item["score"] = item.get("score", 0)
            continue

        for j, other in enumerate(items):
            if i == j:
                continue
            if item["source"] == other["source"]:
                continue

            other_tokens = set(other.get("topic_tokens", []))
            overlap = item_tokens.intersection(other_tokens)

            if len(overlap) >= 4:
                boost += 2

        item["cross_source_boost"] = min(boost, 6)
        item["score"] = item.get("score", 0) + min(boost, 6)


def collect_candidates(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    all_items = []

    for feed in FEEDS:
        all_items.extend(fetch_feed(feed))

    deduped = {}
    for item in all_items:
        url_hash = stable_id(item["url"])

        if url_hash in state.get("seen_urls", {}) and not FORCE_PUBLISH:
            continue

        if item["url"] not in deduped:
            item["score"] = score_item(item)
            deduped[item["url"]] = item
        else:
            # Keep the higher scoring version if duplicated.
            existing = deduped[item["url"]]
            new_score = score_item(item)
            if new_score > existing.get("score", 0):
                item["score"] = new_score
                deduped[item["url"]] = item

    candidates = list(deduped.values())
    apply_cross_source_boost(candidates)

    candidates.sort(key=lambda x: x.get("score", 0), reverse=True)

    return candidates[:MAX_ITEMS_TO_REVIEW]


# ============================================================
# OpenAI generation
# ============================================================

SYSTEM_INSTRUCTIONS = """
You write the Actions On Cyber Daily SMB Cyber Intelligence Brief.

Audience:
Small and medium-sized businesses, charities, schools, professional services, local businesses, owners, office managers, finance teams and outsourced IT providers.

Purpose:
Explain what SMEs should look out for today. Focus on:
- big cyber stories being widely reported;
- scams and phishing themes;
- supplier or SaaS risk;
- ransomware and business disruption;
- data breach ripple effects;
- cloud, payment, payroll, HR, telecoms, logistics or MSP dependency risk;
- practical warning signs;
- questions to ask an IT provider.

Important:
Do not turn this into a vulnerability brief.
Do not lead with CVEs, CVSS, affected versions or patch lists.
A CVE can be mentioned only if it creates a broader SME look-out, supplier risk or business disruption issue.
Do not include exploit instructions, proof-of-concept details, payloads, commands or offensive steps.

Style:
Plain English.
UK-friendly.
Calm and practical.
Useful to non-cyber professionals.
Avoid hype.
Avoid fearmongering.
Avoid long technical explanations.

Use only the supplied candidate items as source material.
Do not invent facts.
Do not include source URLs inside the HTML fragment.
Return valid JSON only.
"""


def build_ai_prompt(candidates: List[Dict[str, Any]]) -> str:
    simple_candidates = []

    for item in candidates[:MAX_CANDIDATES_FOR_AI]:
        simple_candidates.append({
            "id": item["id"],
            "source": item["source"],
            "title": item["title"],
            "summary": item["summary"],
            "url": item["url"],
            "published_utc": item["published_utc"],
            "score": item["score"],
        })

    return json.dumps({
        "task": "Select whether to publish an SMB cyber intelligence brief from these candidates. Publish only if there is something SMEs should look out for, question, prepare for, or warn staff about.",
        "current_date_london": now_london().strftime("%A %d %B %Y"),
        "candidate_items": simple_candidates,
        "required_json_schema": {
            "publish": "boolean",
            "reason": "short explanation of why to publish or not publish",
            "headline": "short page headline",
            "risk_level": "Low | Moderate | High | Critical",
            "todays_lookout": "short theme, e.g. Supplier incident scams, fake payment changes, cloud disruption",
            "html_fragment": "HTML fragment only. Use h2, h3, p, ul, li, table where helpful. Do not include html/head/body/source URLs.",
            "source_ids": ["candidate item ids used as sources"],
            "one_action": "single practical action SMEs should take today",
            "related_resource": "one suggested Actions On Cyber resource or checklist CTA",
        },
        "html_fragment_required_sections": [
            "What to look out for today",
            "Why this matters to smaller businesses",
            "Warning signs",
            "How attackers may exploit the situation",
            "What to do today",
            "Ask your IT provider",
            "Patch watch - only one short paragraph, and only if relevant",
        ],
    }, ensure_ascii=False, indent=2)


def extract_json_object(text: str) -> Dict[str, Any]:
    text = text.strip()

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text.strip(), flags=re.IGNORECASE).strip()
        text = re.sub(r"```$", "", text.strip()).strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in model response.")

    return json.loads(match.group(0))


def generate_brief_with_ai(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

    response = client.responses.create(
        model=MODEL,
        instructions=SYSTEM_INSTRUCTIONS,
        input=build_ai_prompt(candidates),
        max_output_tokens=4500,
    )

    return extract_json_object(response.output_text)


def fallback_brief(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    top = candidates[0]
    title = html.escape(top["title"])
    source = html.escape(top["source"])

    fragment = f"""
<h2>What to look out for today</h2>
<p>A cyber story from <strong>{source}</strong> may be relevant to small and medium-sized businesses today: <strong>{title}</strong>.</p>

<h2>Why this matters to smaller businesses</h2>
<p>Even when a cyber incident affects a larger organisation, SMEs can still be exposed through suppliers, IT providers, cloud services, payment systems, email platforms or customer confidence.</p>

<h2>Warning signs</h2>
<ul>
  <li>Unexpected supplier updates or service notices.</li>
  <li>Requests to reset passwords or re-authenticate through links.</li>
  <li>Changed payment or bank details.</li>
  <li>Delays or disruption in services you rely on.</li>
  <li>Unusual emails claiming to be linked to a cyber incident.</li>
</ul>

<h2>How attackers may exploit the situation</h2>
<p>Attackers often use public cyber incidents as cover for phishing, fake support calls, invoice fraud and credential theft.</p>

<h2>What to do today</h2>
<ul>
  <li>Do not approve payment changes by email alone.</li>
  <li>Verify supplier messages using a known contact route.</li>
  <li>Report suspicious emails or login prompts quickly.</li>
</ul>

<h2>Ask your IT provider</h2>
<ul>
  <li>Are any of our key suppliers affected by this issue?</li>
  <li>Do any suppliers have remote access to our systems?</li>
  <li>Are unusual sign-ins, forwarding rules and admin changes being monitored?</li>
</ul>

<h2>Patch watch</h2>
<p>If the issue is vulnerability-related, use the separate Daily Vulnerability Brief for patch details.</p>
"""

    return {
        "publish": True,
        "reason": "Fallback brief generated from the top-ranked SME-relevant item.",
        "headline": "Cyber story SMEs should watch today",
        "risk_level": "Moderate",
        "todays_lookout": "Supplier, scam or disruption risk",
        "html_fragment": fragment,
        "source_ids": [top["id"]],
        "one_action": "Verify any unexpected supplier, payment or password-reset request using a trusted contact route.",
        "related_resource": "Supplier Security Questionnaire",
    }


# ============================================================
# HTML generation
# ============================================================

def sanitise_html_fragment(fragment: str) -> str:
    if not fragment:
        return ""

    fragment = re.sub(
        r"<\s*/?\s*(script|style|iframe|object|embed)[^>]*>",
        "",
        fragment,
        flags=re.IGNORECASE,
    )
    fragment = re.sub(
        r"\son\w+\s*=\s*(['\"]).*?\1",
        "",
        fragment,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return fragment.strip()


def risk_badge(risk_level: str) -> str:
    value = html.escape(risk_level or "Moderate")
    return f'<span class="tag">{value}</span>'


def page_header(title: str, asset_prefix: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="description" content="Daily SMB cyber intelligence brief from Actions On Cyber. Plain-English cyber risks, scams, supplier incidents and practical actions for small and medium-sized businesses." />
  <title>{html.escape(title)} | Actions On Cyber</title>
  <link rel="stylesheet" href="{asset_prefix}assets/styles.css" />
  <link rel="icon" href="{asset_prefix}assets/actions-on-cyber-logo.png" type="image/png" />
</head>
<body>
<a href="#main" class="skip">Skip to content</a>

<div class="topbar">
  <div class="container topbar-inner">
    <div>Free practical cybersecurity guidance for organisations without a security team.</div>
    <a href="mailto:hello@actionsoncyber.com">hello@actionsoncyber.com</a>
  </div>
</div>

<header class="site-header">
  <div class="container header-inner">
    <a href="{asset_prefix}index.html" class="brand" style="display:flex;align-items:center;text-decoration:none;">
      <img
        src="{asset_prefix}assets/actions-on-cyber-logo.png"
        alt="Actions On Cyber"
        style="width:220px !important;max-width:220px !important;height:auto !important;display:block !important;object-fit:contain !important;"
      />
    </a>

    <nav class="nav">
      <a href="{asset_prefix}pages/daily-int-brief.html">Daily Intelligence</a>
      <a href="{asset_prefix}pages/daily-vulnerability-brief.html">Daily Vulnerabilities</a>
      <a href="{asset_prefix}pages/field-manual.html">Field Manual</a>
      <a href="{asset_prefix}pages/contact.html">Contact</a>
    </nav>
  </div>
</header>
"""


def page_footer() -> str:
    year = now_london().year
    return f"""
<footer class="site-footer">
  <div class="container">
    <p>&copy; {year} Actions On Cyber. Practical cybersecurity guidance for small organisations.</p>
  </div>
</footer>
</body>
</html>
"""


def build_archive_page(brief: Dict[str, Any], source_items: List[Dict[str, Any]], slug: str) -> str:
    published_at = now_london()
    title = brief.get("headline") or "Daily SMB Cyber Intelligence Brief"
    risk_level = brief.get("risk_level") or "Moderate"
    lookout = brief.get("todays_lookout") or "Cyber risk watch"
    one_action = brief.get("one_action") or ""
    related_resource = brief.get("related_resource") or ""
    fragment = sanitise_html_fragment(brief.get("html_fragment", ""))

    source_html = ""
    if source_items:
        source_html += "<ul>"
        for item in source_items:
            source_html += (
                f'<li><a href="{html.escape(item["url"])}" rel="noopener noreferrer">'
                f'{html.escape(item["title"])}</a> '
                f'<span class="muted">({html.escape(item["source"])})</span></li>'
            )
        source_html += "</ul>"

    return f"""{page_header(title, "../../")}
<main id="main">
  <section class="hero">
    <div class="container">
      <p class="eyebrow">Daily SMB Cyber Intelligence Brief</p>
      <h1>{html.escape(title)}</h1>
      <p class="lede">What small and medium-sized businesses should look out for today.</p>
      <div class="meta-row">
        {risk_badge(risk_level)}
        <span>{html.escape(published_at.strftime("%A %d %B %Y, %H:%M"))} UK time</span>
      </div>
    </div>
  </section>

  <section class="section">
    <div class="container content-grid">
      <article class="content-main">
        <div class="callout">
          <strong>Today’s look-out:</strong> {html.escape(lookout)}
        </div>

        {fragment}

        <h2>One action today</h2>
        <p>{html.escape(one_action)}</p>

        <h2>Related Actions On Cyber resource</h2>
        <p>{html.escape(related_resource)}</p>

        <h2>Sources</h2>
        {source_html}

        <p class="muted">
          This brief is for general awareness and does not replace advice from your IT provider,
          legal adviser, insurer or incident response specialist.
        </p>
      </article>

      <aside class="content-side">
        <div class="card">
          <h2>Need patch details?</h2>
          <p>This intelligence brief focuses on what to look out for. For exploited vulnerabilities and patch priorities, use the Daily Vulnerability Brief.</p>
          <a class="button" href="../daily-vulnerability-brief.html">View Vulnerability Brief</a>
        </div>

        <div class="card">
          <h2>Ask your IT provider</h2>
          <p>Use the questions in this brief to check supplier exposure, account protection, logging and business continuity.</p>
        </div>
      </aside>
    </div>
  </section>
</main>
{page_footer()}"""


def build_index_page(state: Dict[str, Any]) -> str:
    briefs = state.get("published_briefs", [])[:30]

    if briefs:
        latest = briefs[0]
        latest_html = f"""
        <article class="card feature-card">
          <p class="eyebrow">Latest brief</p>
          <h2><a href="daily-int-briefs/{html.escape(latest['slug'])}.html">{html.escape(latest['headline'])}</a></h2>
          <p><strong>Look-out:</strong> {html.escape(latest.get('todays_lookout', 'Cyber risk watch'))}</p>
          <p><strong>Risk level:</strong> {html.escape(latest.get('risk_level', 'Moderate'))}</p>
          <p class="muted">{html.escape(latest.get('published_label', ''))}</p>
          <a class="button" href="daily-int-briefs/{html.escape(latest['slug'])}.html">Read latest brief</a>
        </article>
        """
    else:
        latest_html = """
        <article class="card feature-card">
          <p class="eyebrow">Latest brief</p>
          <h2>No intelligence brief has been published yet.</h2>
          <p>The automation will publish when there is a strong SME-relevant cyber story.</p>
        </article>
        """

    archive_items = ""
    for brief in briefs:
        archive_items += f"""
        <li>
          <a href="daily-int-briefs/{html.escape(brief['slug'])}.html">{html.escape(brief['headline'])}</a>
          <span class="muted"> — {html.escape(brief.get('published_label', ''))}</span>
        </li>
        """

    if not archive_items:
        archive_items = "<li>No archived briefs yet.</li>"

    return f"""{page_header("Daily SMB Cyber Intelligence Brief", "../")}
<main id="main">
  <section class="hero">
    <div class="container">
      <p class="eyebrow">Actions On Cyber</p>
      <h1>Daily SMB Cyber Intelligence Brief</h1>
      <p class="lede">
        What small and medium-sized businesses should look out for today —
        including scams, attacker behaviour, supplier risk, major cyber incidents and practical actions.
      </p>
    </div>
  </section>

  <section class="section">
    <div class="container content-grid">
      <article class="content-main">
        {latest_html}

        <div class="callout">
          <strong>How this differs from the Daily Vulnerability Brief:</strong>
          this page focuses on what SMEs should watch, question and prepare for.
          The vulnerability brief focuses on what to patch.
        </div>

        <h2>Recent intelligence briefs</h2>
        <ul>
          {archive_items}
        </ul>
      </article>

      <aside class="content-side">
        <div class="card">
          <h2>What we monitor</h2>
          <ul>
            <li>Major cyber incidents</li>
            <li>Supplier and MSP risk</li>
            <li>Ransomware and data breaches</li>
            <li>Phishing and payment fraud</li>
            <li>Cloud, SaaS and business disruption</li>
            <li>Stories widely reported by credible cyber sources</li>
          </ul>
        </div>

        <div class="card">
          <h2>Need CVE and patch detail?</h2>
          <p>Use the separate Daily Vulnerability Brief for exploited vulnerabilities and patch priorities.</p>
          <a class="button" href="daily-vulnerability-brief.html">Daily Vulnerability Brief</a>
        </div>
      </aside>
    </div>
  </section>
</main>
{page_footer()}"""


# ============================================================
# Main flow
# ============================================================

def main() -> None:
    ensure_dirs()
    state = read_state()

    todays_count = count_briefs_today(state)
    if todays_count >= MAX_BRIEFS_PER_DAY and not FORCE_PUBLISH:
        print(f"Already published {todays_count} intelligence briefs today. No action.")
        save_state(state)
        return

    candidates = collect_candidates(state)

    if not candidates:
        print("No new candidate items found.")
        save_state(state)
        return

    best_score = candidates[0].get("score", 0)
    print(f"Top candidate score: {best_score}")
    print(f"Top candidate: {candidates[0].get('title')}")

    if best_score < MIN_SCORE_TO_PUBLISH and not FORCE_PUBLISH:
        print("No candidate met the publish threshold.")
        save_state(state)
        return

    try:
        brief = generate_brief_with_ai(candidates)
    except Exception as exc:
        print(f"AI generation failed; using fallback brief. Error: {exc}")
        brief = fallback_brief(candidates)

    if not brief.get("publish") and not FORCE_PUBLISH:
        print(f"AI decided not to publish: {brief.get('reason', 'No reason provided')}")
        save_state(state)
        return

    allowed_by_id = {item["id"]: item for item in candidates}
    source_ids = brief.get("source_ids") or []

    source_items = []
    for source_id in source_ids:
        item = allowed_by_id.get(source_id)
        if item and item not in source_items:
            source_items.append(item)

    if not source_items:
        source_items = candidates[:3]

    published_at = now_london()
    headline = brief.get("headline") or "Daily SMB Cyber Intelligence Brief"
    slug_base = slugify(headline)
    slug = f"{published_at.strftime('%Y-%m-%d-%H%M')}-{slug_base}"

    archive_html = build_archive_page(brief, source_items, slug)
    archive_path = ARCHIVE_DIR / f"{slug}.html"
    archive_path.write_text(archive_html, encoding="utf-8")

    brief_record = {
        "slug": slug,
        "headline": headline,
        "risk_level": brief.get("risk_level", "Moderate"),
        "todays_lookout": brief.get("todays_lookout", "Cyber risk watch"),
        "published_at": published_at.isoformat(),
        "published_label": published_at.strftime("%A %d %B %Y, %H:%M UK time"),
        "source_urls": [item["url"] for item in source_items],
    }

    state.setdefault("published_briefs", [])
    state["published_briefs"].insert(0, brief_record)

    state.setdefault("seen_urls", {})
    for item in source_items:
        url_hash = stable_id(item["url"])
        state["seen_urls"][url_hash] = {
            "url": item["url"],
            "title": item["title"],
            "source": item["source"],
            "seen_at": published_at.isoformat(),
            "brief_slug": slug,
        }

    INDEX_PAGE.write_text(build_index_page(state), encoding="utf-8")
    save_state(state)

    print(f"Published intelligence brief: {archive_path}")


if __name__ == "__main__":
    main()
