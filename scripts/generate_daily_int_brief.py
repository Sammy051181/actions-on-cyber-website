import os
import re
import json
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from slugify import slugify
from openai import OpenAI


client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


# =========================
# Date and folder settings
# =========================

UK_NOW = datetime.now(ZoneInfo("Europe/London"))

TODAY = UK_NOW.strftime("%Y-%m-%d")
DISPLAY_DATE = UK_NOW.strftime("%d %B %Y")
MONTH_TITLE = UK_NOW.strftime("%B %Y")
MONTH_FOLDER = UK_NOW.strftime("%B-%Y")

SITE_ROOT = Path(".")
PAGES_DIR = SITE_ROOT / "pages"
DAILY_ROOT_DIR = PAGES_DIR / "daily"
MONTH_DIR = DAILY_ROOT_DIR / MONTH_FOLDER

DAILY_INDEX = PAGES_DIR / "daily-int-brief.html"
MONTH_INDEX = MONTH_DIR / "index.html"

MONTH_DIR.mkdir(parents=True, exist_ok=True)


# =========================
# CISA KEV settings
# =========================

CISA_KEV_PRIMARY_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_FALLBACK_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"


def fetch_top_5_kev():
    """
    Fetch the latest five CISA Known Exploited Vulnerabilities.
    Falls back to the CISA GitHub mirror if the main CISA feed is unavailable.
    """

    headers = {
        "User-Agent": "ActionsOnCyberDailyBrief/1.0"
    }

    for url in [CISA_KEV_PRIMARY_URL, CISA_KEV_FALLBACK_URL]:
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])

            vulnerabilities = sorted(
                vulnerabilities,
                key=lambda item: item.get("dateAdded", ""),
                reverse=True
            )

            top_5 = vulnerabilities[:5]

            return [
                {
                    "cve_id": item.get("cveID", "Unknown CVE"),
                    "vendor_project": item.get("vendorProject", "Unknown vendor"),
                    "product": item.get("product", "Unknown product"),
                    "vulnerability_name": item.get("vulnerabilityName", "Unknown vulnerability"),
                    "date_added": item.get("dateAdded", "Unknown date"),
                    "required_action": item.get(
                        "requiredAction",
                        "Check vendor guidance and apply mitigations or updates where relevant."
                    ),
                    "due_date": item.get("dueDate", "N/A"),
                    "notes": item.get("notes", "")
                }
                for item in top_5
            ]

        except Exception as exc:
            print(f"Warning: failed to fetch KEV feed from {url}: {exc}")

    return []


TOP_5_KEV = fetch_top_5_kev()


# =========================
# Prompt
# =========================

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

Also include the provided Top 5 Known Exploited Vulnerabilities from CISA KEV.
Do not invent vulnerabilities. Use the provided KEV list exactly.

Rules:
- Do not copy source wording.
- Do not reproduce full articles.
- Do not include exploit instructions, malware code, payloads, proof-of-concept details or offensive technical steps.
- Keep the tone calm, practical and plain-English.
- Write for non-technical leaders.
- Focus on what organisations should do next.
- Include source links.
- Use the heading Executive Summary, not One-paragraph summary.
- The main Daily Int Brief topic does not have to be one of the KEV items, but the KEV table must still be included.
- Do not create a LinkedIn post.
- Do not create a social media post.
- Do not include a section called LinkedIn post draft.
- Do not include any LinkedIn content in the JSON.

Top 5 Known Exploited Vulnerabilities from CISA KEV:
{json.dumps(TOP_5_KEV, indent=2)}

Return only valid JSON with this exact structure:
{{
  "title": "",
  "date": "{DISPLAY_DATE}",
  "relevance_rating": "Act Now | Check | Monitor | Low relevance",
  "executive_summary": "",
  "situation": "",
  "who_should_care": [],
  "why_it_matters": "",
  "top_5_kev_summary": "",
  "actions_on": [],
  "question_to_ask_it_provider": "",
  "after_action_review": [],
  "sources": [
    {{"title": "", "url": ""}}
  ],
  "archive_tags": []
}}
"""


# =========================
# HTML helpers
# =========================

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


def render_kev_table(kev_items):
    if not kev_items:
        return """
        <div class="warning">
          <strong>Top 5 Known Exploited Vulnerabilities unavailable:</strong>
          The CISA KEV feed could not be retrieved when this brief was generated.
        </div>
        """

    rows = []

    for item in kev_items:
        rows.append(
            f"""
            <tr>
              <td>{esc(item["date_added"])}</td>
              <td>{esc(item["cve_id"])}</td>
              <td>{esc(item["vendor_project"])}</td>
              <td>{esc(item["product"])}</td>
              <td>{esc(item["vulnerability_name"])}</td>
              <td>{esc(item["required_action"])}</td>
            </tr>
            """
        )

    return f"""
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Date added</th>
            <th>CVE</th>
            <th>Vendor</th>
            <th>Product</th>
            <th>Vulnerability</th>
            <th>Required action</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </div>
    """


def make_page_shell(title, body):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{esc(title)} | Actions On Cyber</title>
  <link rel="stylesheet" href="/assets/styles.css">
</head>
<body>
  {body}
</body>
</html>
"""


def clean_json(raw):
    raw = raw.strip()

    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?", "", raw).strip()
        raw = re.sub(r"```$", "", raw).strip()

    match = re.search(r"\{.*\}", raw, re.S)

    if not match:
        raise ValueError("The model did not return valid JSON.")

    return json.loads(match.group(0))


# =========================
# Remove old LinkedIn sections
# =========================

def remove_existing_linkedin_sections():
    """
    Removes old LinkedIn post draft sections from existing generated pages.
    This cleans previously published pages as well as preventing future output.
    """

    if not PAGES_DIR.exists():
        return

    changed_files = []

    patterns = [
        re.compile(
            r"\s*<h2>\s*LinkedIn post draft\s*</h2>\s*<p>.*?</p>",
            re.IGNORECASE | re.DOTALL
        ),
        re.compile(
            r"\s*<h2>\s*LinkedIn post draft\s*</h2>.*?(?=<h2>|</article>|</main>|</body>|</html>)",
            re.IGNORECASE | re.DOTALL
        ),
    ]

    for html_file in PAGES_DIR.rglob("*.html"):
        text = html_file.read_text(encoding="utf-8")
        new_text = text

        for pattern in patterns:
            new_text = pattern.sub("", new_text)

        if new_text != text:
            html_file.write_text(new_text, encoding="utf-8")
            changed_files.append(str(html_file))

    if changed_files:
        print("Removed old LinkedIn post draft sections from:")
        for file_name in changed_files:
            print(f"- {file_name}")
    else:
        print("No old LinkedIn post draft sections found.")


# =========================
# Article generation
# =========================

def create_article(data):
    slug = slugify(data["title"])[:90]
    filename = f"{TODAY}-{slug}.html"
    path = MONTH_DIR / filename

    tags = ", ".join(esc(tag) for tag in data.get("archive_tags", []))

    body = f"""
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
          <p><a class="btn btn-secondary" href="/pages/daily/{MONTH_FOLDER}/index.html">View {MONTH_TITLE} Archive</a></p>
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
        <p>{esc(data.get("top_5_kev_summary", "These are the latest entries from the CISA Known Exploited Vulnerabilities catalogue."))}</p>
        {render_kev_table(TOP_5_KEV)}

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
        <ul>
          <li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA Known Exploited Vulnerabilities Catalog</a></li>
          <li><a href="https://github.com/cisagov/kev-data">CISA KEV JSON/CSV data mirror</a></li>
        </ul>
      </article>
    </div>
  </main>
"""

    html = make_page_shell(data["title"], body)
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


# =========================
# Index page updates
# =========================

def create_month_archive_if_missing():
    if MONTH_INDEX.exists():
        return

    body = f"""
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
"""

    MONTH_INDEX.write_text(
        make_page_shell(f"{MONTH_TITLE} Daily Int Brief Archive", body),
        encoding="utf-8"
    )


def update_month_archive(data, filename):
    create_month_archive_if_missing()

    link = f"/pages/daily/{MONTH_FOLDER}/{filename}"
    card = create_card(data, filename)

    content = MONTH_INDEX.read_text(encoding="utf-8")

    if link in content:
        return

    if "<!-- MONTH_DAILY_BRIEFS_START -->" in content:
        content = content.replace(
            "<!-- MONTH_DAILY_BRIEFS_START -->",
            "<!-- MONTH_DAILY_BRIEFS_START -->\n" + card,
            1
        )
    elif '<div class="grid-3">' in content:
        content = content.replace(
            '<div class="grid-3">',
            '<div class="grid-3">\n      <!-- MONTH_DAILY_BRIEFS_START -->\n' + card,
            1
        )
    else:
        content += card

    MONTH_INDEX.write_text(content, encoding="utf-8")


def update_daily_index(data, filename):
    link = f"/pages/daily/{MONTH_FOLDER}/{filename}"
    card = create_card(data, filename)

    month_archive_card = f"""
      <article class="card">
        <span class="tag">Monthly Archive</span>
        <h3>{MONTH_TITLE}</h3>
        <p>Daily Int Briefs produced during {MONTH_TITLE}.</p>
        <a class="btn btn-secondary" href="/pages/daily/{MONTH_FOLDER}/index.html">Open archive</a>
      </article>
"""

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
    <div class="section-head">
      <div>
        <span class="badge">Latest Daily Briefs</span>
        <h2>Latest briefings</h2>
        <p>New Daily Int Briefs are added automatically.</p>
      </div>
    </div>
    <div class="grid-3">
      <!-- DAILY_BRIEFS_START -->
    </div>
  </div>
</section>

<section class="section section-alt">
  <div class="container">
    <div class="section-head">
      <div>
        <span class="badge">Monthly Archives</span>
        <h2>Daily Int Brief archives</h2>
        <p>Each month has its own archive folder.</p>
      </div>
    </div>
    <div class="grid-3">
      <!-- MONTH_ARCHIVES_START -->
    </div>
  </div>
</section>
</main>
</body>
</html>
"""

    if "<!-- DAILY_BRIEFS_START -->" not in content and '<div class="grid-3">' in content:
        content = content.replace(
            '<div class="grid-3">',
            '<div class="grid-3">\n      <!-- DAILY_BRIEFS_START -->',
            1
        )

    if link not in content:
        content = content.replace(
            "<!-- DAILY_BRIEFS_START -->",
            "<!-- DAILY_BRIEFS_START -->\n" + card,
            1
        )

    if "<!-- MONTH_ARCHIVES_START -->" not in content:
        content += f"""
<section class="section section-alt">
  <div class="container">
    <div class="section-head">
      <div>
        <span class="badge">Monthly Archives</span>
        <h2>Daily Int Brief archives</h2>
        <p>Each month has its own archive folder.</p>
      </div>
    </div>
    <div class="grid-3">
      <!-- MONTH_ARCHIVES_START -->
    </div>
  </div>
</section>
"""

    month_link = f"/pages/daily/{MONTH_FOLDER}/index.html"

    if month_link not in content:
        content = content.replace(
            "<!-- MONTH_ARCHIVES_START -->",
            "<!-- MONTH_ARCHIVES_START -->\n" + month_archive_card,
            1
        )

    DAILY_INDEX.write_text(content, encoding="utf-8")


# =========================
# Main
# =========================

def main():
    remove_existing_linkedin_sections()

    response = client.responses.create(
        model="gpt-5.4-mini",
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
        "step-by-step exploit",
        "exploit chain",
        "linkedin_post",
        "linkedin post draft",
        "social media post draft"
    ]

    combined = json.dumps(data).lower()

    if any(term in combined for term in forbidden_terms):
        raise ValueError("Blocked: output contained forbidden content.")

    filename = create_article(data)
    update_month_archive(data, filename)
    update_daily_index(data, filename)

    remove_existing_linkedin_sections()

    print(f"Created Daily Int Brief: /pages/daily/{MONTH_FOLDER}/{filename}")
    print(f"Updated monthly archive: /pages/daily/{MONTH_FOLDER}/index.html")
    print("Included Top 5 CISA Known Exploited Vulnerabilities.")
    print("Removed LinkedIn post draft sections from website output.")


if __name__ == "__main__":
    main()
