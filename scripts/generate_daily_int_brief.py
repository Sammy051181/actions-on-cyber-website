import os
import re
import json
import requests
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from slugify import slugify
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

UK_NOW = datetime.now(ZoneInfo("Europe/London"))

TODAY = UK_NOW.strftime("%Y-%m-%d")
DISPLAY_DATE = UK_NOW.strftime("%d %B %Y")
MONTH_TITLE = UK_NOW.strftime("%B %Y")
MONTH_FOLDER = UK_NOW.strftime("%B-%Y")

SITE_ROOT = Path(".")
PAGES_DIR = SITE_ROOT / "pages"
DAILY_INDEX = PAGES_DIR / "daily-int-brief.html"
DAILY_ROOT = PAGES_DIR / "daily"
MONTH_DIR = DAILY_ROOT / MONTH_FOLDER
MONTH_INDEX = MONTH_DIR / "index.html"

MONTH_DIR.mkdir(parents=True, exist_ok=True)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def esc(value):
    if value is None:
        return ""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def render_list(items, ordered=False):
    tag = "ol" if ordered else "ul"
    body = "\n".join(f"<li>{esc(item)}</li>" for item in items)
    return f"<{tag}>{body}</{tag}>"


def render_sources(sources):
    items = []
    for source in sources:
        title = esc(source.get("title", "Source"))
        url = esc(source.get("url", "#"))
        items.append(f'<li><a href="{url}">{title}</a></li>')
    return "<ul>" + "\n".join(items) + "</ul>"


def fetch_top_kev():
    """
    Fetch the latest 5 entries from CISA's Known Exploited Vulnerabilities catalogue.
    These are included in every Daily Int Brief as the 'Top 5 Known Exploited Vulnerabilities'.
    """
    try:
        response = requests.get(CISA_KEV_URL, timeout=20)
        response.raise_for_status()
        data = response.json()
        vulns = data.get("vulnerabilities", [])

        vulns = sorted(
            vulns,
            key=lambda item: item.get("dateAdded", ""),
            reverse=True
        )

        top_five = []
        for vuln in vulns[:5]:
            top_five.append({
                "cve": vuln.get("cveID", "Unknown CVE"),
                "vendor": vuln.get("vendorProject", "Unknown vendor"),
                "product": vuln.get("product", "Unknown product"),
                "name": vuln.get("vulnerabilityName", "Known exploited vulnerability"),
                "date_added": vuln.get("dateAdded", "Unknown date"),
                "required_action": vuln.get("requiredAction", "Check vendor guidance and apply mitigations or updates where relevant."),
            })

        return top_five

    except Exception as error:
        print(f"Warning: Could not fetch CISA KEV feed: {error}")
        return []


TOP_KEV = fetch_top_kev()

TOP_KEV_PROMPT = json.dumps(TOP_KEV, indent=2)

PROMPT = f"""
You are writing for Actions On Cyber.

Create one Actions On Cyber Daily Int Brief for {DISPLAY_DATE}.

Audience:
UK small businesses, charities, clubs and community organisations without a cyber security team.

Task:
Search for current cyber threat topics relevant to the audience.
Select the strongest topic suitable for a Daily Int Brief.

Prioritise reliable sources:
- NCSC
- CISA
- NVD
- vendor advisories
- reputable cyber security reporting

Also include the following latest CISA Known Exploited Vulnerabilities in the brief as a separate section called:
Top 5 Known Exploited Vulnerabilities.

Use this CISA KEV data:
{TOP_KEV_PROMPT}

Rules:
- Do not copy source wording.
- Do not reproduce full articles.
- Do not include exploit instructions, malware code, payloads, proof-of-concept details or offensive technical steps.
- Keep the tone calm, practical and plain-English.
- Write for non-technical leaders.
- Focus on what organisations should do next.
- Include source links.
- Use the heading Executive Summary, not One-paragraph summary.
- The Daily Int Brief should be practical and suitable for Actions On Cyber.
- The Top 5 Known Exploited Vulnerabilities section should tell readers what to ask their IT provider, not how to exploit anything.

Return only valid JSON with this exact structure:
{{
  "title": "",
  "date": "{DISPLAY_DATE}",
  "relevance_rating": "Act Now | Check | Monitor | Low relevance",
  "executive_summary": "",
  "situation": "",
  "who_should_care": [],
  "why_it_matters": "",
  "top_5_known_exploited_vulnerabilities": [
    {{
      "cve": "",
      "vendor": "",
      "product": "",
      "plain_english_risk": "",
      "question_to_ask_it_provider": ""
    }}
  ],
  "actions_on": [],
  "question_to_ask_it_provider": "",
  "after_action_review": [],
  "sources": [
    {{"title": "", "url": ""}}
  ],
  "archive_tags": [],
  "linkedin_post": ""
}}
"""


def clean_json(raw):
    """
    Extract a JSON object even if the model returns markdown around it.
    """
    raw = raw.strip()

    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?", "", raw).strip()
        raw = re.sub(r"```$", "", raw).strip()

    match = re.search(r"\{.*\}", raw, re.S)
    if not match:
        raise ValueError("The model did not return a valid JSON object.")

    return json.loads(match.group(0))


def render_kev_table(items):
    if not items:
        return """
        <div class="warning">
          <strong>Known exploited vulnerabilities unavailable:</strong>
          The CISA KEV feed could not be retrieved when this brief was generated.
        </div>
        """

    rows = []
    for item in items:
        rows.append(f"""
          <tr>
            <td><strong>{esc(item.get("cve", ""))}</strong></td>
            <td>{esc(item.get("vendor", ""))}</td>
            <td>{esc(item.get("product", ""))}</td>
            <td>{esc(item.get("plain_english_risk", ""))}</td>
            <td>{esc(item.get("question_to_ask_it_provider", ""))}</td>
          </tr>
        """)

    return f"""
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Vendor</th>
              <th>Product</th>
              <th>Plain-English risk</th>
              <th>Question to ask IT provider</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
      </div>
    """


def create_article(data):
    slug = slugify(data["title"])[:90]
    filename = f"{TODAY}-{slug}.html"
    path = MONTH_DIR / filename

    tags = ", ".join(esc(tag) for tag in data.get("archive_tags", []))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{esc(data["title"])} | Actions On Cyber</title>
  <link rel="stylesheet" href="/assets/styles.css">
</head>
<body>
  <main class="section">
    <div class="container content-layout">
      <aside class="sidebar">
        <div class="card">
          <h3>Brief details</h3>
          <p><strong>Date:</strong><br>{DISPLAY_DATE}</p>
          <p><strong>Archive:</strong><br>{MONTH_TITLE}</p>
          <p><strong>Rating:</strong><br>{esc(data["relevance_rating"])}</p>
          <p><strong>Tags:</strong><br>{tags}</p>
          <p><a class="btn btn-secondary" href="/pages/daily-int-brief.html">Back to Daily Int Briefs</a></p>
          <p><a class="btn btn-secondary" href="/pages/daily/{MONTH_FOLDER}/index.html">Back to {MONTH_TITLE} archive</a></p>
        </div>
      </aside>

      <article class="article">
        <p class="small"><strong>{DISPLAY_DATE}</strong></p>

        <h1>Daily Int Brief: {esc(data["title"])}</h1>

        <div class="danger">
          <strong>Relevance rating: {esc(data["relevance_rating"])}</strong>
        </div>

        <h2>Executive Summary</h2>
        <p>{esc(data["executive_summary"])}</p>

        <h2>Situation</h2>
        <p>{esc(data["situation"])}</p>

        <h2>Who should care</h2>
        {render_list(data.get("who_should_care", []))}

        <h2>Why it matters</h2>
        <p>{esc(data["why_it_matters"])}</p>

        <h2>Top 5 Known Exploited Vulnerabilities</h2>
        <p>
          These are the latest known exploited vulnerabilities from the CISA KEV catalogue at the time this brief was generated.
          Small organisations do not need the technical exploit detail. The practical action is to ask whether affected products are used and whether vendor mitigations or updates have been applied.
        </p>
        {render_kev_table(data.get("top_5_known_exploited_vulnerabilities", []))}

        <h2>Actions On</h2>
        {render_list(data.get("actions_on", []), ordered=True)}

        <h2>Question to ask your IT provider</h2>
        <div class="success">
          {esc(data["question_to_ask_it_provider"])}
        </div>

        <h2>After-action review</h2>
        {render_list(data.get("after_action_review", []))}

        <h2>Sources</h2>
        {render_sources(data.get("sources", []))}

        <h2>LinkedIn post draft</h2>
        <p>{esc(data.get("linkedin_post", "")).replace(chr(10), "<br>")}</p>
      </article>
    </div>
  </main>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")
    return filename


def create_card(data, filename):
    link = f"/pages/daily/{MONTH_FOLDER}/{filename}"

    return f"""
      <article class="card">
        <span class="tag">{esc(data["relevance_rating"])}</span>
        <p class="small"><strong>{DISPLAY_DATE}</strong></p>
        <h3>{esc(data["title"])}</h3>
        <p>{esc(data["executive_summary"])}</p>
        <a class="btn btn-secondary" href="{link}">Read brief</a>
      </article>
"""


def update_daily_index(data, filename):
    """
    Update the main Daily Int Brief page with the new brief card and a link to the month archive.
    """
    link = f"/pages/daily/{MONTH_FOLDER}/{filename}"
    archive_link = f"/pages/daily/{MONTH_FOLDER}/index.html"
    card = create_card(data, filename)

    if DAILY_INDEX.exists():
        content = DAILY_INDEX.read_text(encoding="utf-8")
    else:
        content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Daily Int Brief | Actions On Cyber</title>
  <link rel="stylesheet" href="/assets/styles.css">
</head>
<body>
<main>
<section class="page-hero">
  <div class="container page-title">
    <h1>Daily Int Brief</h1>
    <p>Daily cyber intelligence for small organisations, archived by month.</p>
  </div>
</section>
<section class="section">
  <div class="container">
    <h2>Monthly archives</h2>
    <div class="grid-3">
      <!-- MONTHLY_ARCHIVES_START -->
    </div>
  </div>
</section>
<section class="section">
  <div class="container">
    <h2>Latest Daily Int Briefs</h2>
    <div class="grid-3">
      <!-- DAILY_BRIEFS_START -->
    </div>
  </div>
</section>
</main>
</body>
</html>
"""

    if "<!-- MONTHLY_ARCHIVES_START -->" not in content:
        content = content.replace(
            "<main>",
            """<main>
<section class="section">
  <div class="container">
    <h2>Monthly archives</h2>
    <div class="grid-3">
      <!-- MONTHLY_ARCHIVES_START -->
    </div>
  </div>
</section>""",
            1
        )

    archive_card = f"""
      <article class="card">
        <span class="tag">Archive</span>
        <h3>{MONTH_TITLE}</h3>
        <p>Daily Int Briefs produced during {MONTH_TITLE}.</p>
        <a class="btn btn-secondary" href="{archive_link}">Open archive</a>
      </article>
"""

    if archive_link not in content:
        content = content.replace("<!-- MONTHLY_ARCHIVES_START -->", "<!-- MONTHLY_ARCHIVES_START -->\n" + archive_card, 1)

    if link in content:
        DAILY_INDEX.write_text(content, encoding="utf-8")
        return

    if "<!-- DAILY_BRIEFS_START -->" in content:
        content = content.replace("<!-- DAILY_BRIEFS_START -->", "<!-- DAILY_BRIEFS_START -->\n" + card, 1)
    elif '<div class="grid-3">' in content:
        content = content.replace('<div class="grid-3">', '<div class="grid-3">\n      <!-- DAILY_BRIEFS_START -->\n' + card, 1)
    else:
        content += card

    DAILY_INDEX.write_text(content, encoding="utf-8")


def update_month_index(data, filename):
    """
    Create/update the monthly archive page, for example:
    /pages/daily/May-2026/index.html
    """
    link = f"/pages/daily/{MONTH_FOLDER}/{filename}"
    card = create_card(data, filename)

    if MONTH_INDEX.exists():
        content = MONTH_INDEX.read_text(encoding="utf-8")
    else:
        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{MONTH_TITLE} Daily Int Brief Archive | Actions On Cyber</title>
  <link rel="stylesheet" href="/assets/styles.css">
</head>
<body>
<main>
<section class="page-hero">
  <div class="container page-title">
    <a class="breadcrumb" href="/pages/daily-int-brief.html">← Back to Daily Int Briefs</a>
    <h1>{MONTH_TITLE} Daily Int Brief Archive</h1>
    <p>Daily Int Briefs produced during {MONTH_TITLE}.</p>
  </div>
</section>

<section class="section">
  <div class="container">
    <div class="grid-3">
      <!-- MONTH_DAILY_BRIEFS_START -->
    </div>
  </div>
</section>
</main>
</body>
</html>
"""

    if link in content:
        return

    content = content.replace("<!-- MONTH_DAILY_BRIEFS_START -->", "<!-- MONTH_DAILY_BRIEFS_START -->\n" + card, 1)
    MONTH_INDEX.write_text(content, encoding="utf-8")


def main():
    response = client.responses.create(
        model="gpt-5.5",
        tools=[{"type": "web_search"}],
        input=PROMPT
    )

    raw = response.output_text.strip()
    data = clean_json(raw)
    data["date"] = DISPLAY_DATE

    forbidden_terms = [
        "exploit code",
        "proof of concept",
        "payload",
        "reverse shell",
        "weaponize",
        "malware code",
    ]

    combined = json.dumps(data).lower()
    if any(term in combined for term in forbidden_terms):
        raise ValueError("Blocked: output contained offensive technical detail.")

    filename = create_article(data)
    update_daily_index(data, filename)
    update_month_index(data, filename)

    print(f"Created Daily Int Brief: /pages/daily/{MONTH_FOLDER}/{filename}")
    print(f"Updated monthly archive: /pages/daily/{MONTH_FOLDER}/index.html")


if __name__ == "__main__":
    main()
