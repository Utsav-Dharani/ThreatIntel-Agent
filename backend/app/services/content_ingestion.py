import json
import re
from io import BytesIO
from typing import Optional, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from pypdf import PdfReader

try:
    import trafilatura
except ImportError:
    trafilatura = None


MAX_TEXT_LENGTH = 50000
MIN_TEXT_LENGTH = 100


BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/pdf,application/json,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
}


CISA_ADVISORY_FALLBACKS = {
    "aa25-071a": [
        "https://www.ic3.gov/CSA/2025/250312.pdf",
        "https://www.cisa.gov/sites/default/files/2025-03/AA25-071A-StopRansomware-Medusa-Ransomware.stix_.json",
    ],
}


def clean_text(text: str) -> str:
    if not text:
        return ""

    text = text.replace("\x00", " ")
    text = text.replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def validate_url(url: str) -> str:
    url = (url or "").strip()

    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        raise ValueError("Please enter a full URL starting with http:// or https://.")

    if not parsed.netloc:
        raise ValueError("Invalid URL. Please provide a complete public URL.")

    return url


def looks_like_pdf_url(url: str, content_type: str = "") -> bool:
    url_lower = url.lower()
    content_type_lower = (content_type or "").lower()

    return url_lower.endswith(".pdf") or "application/pdf" in content_type_lower


def looks_like_json_url(url: str, content_type: str = "") -> bool:
    url_lower = url.lower()
    content_type_lower = (content_type or "").lower()

    return (
        url_lower.endswith(".json")
        or "application/json" in content_type_lower
        or "text/json" in content_type_lower
    )


def looks_like_block_page(text: str) -> bool:
    text_lower = (text or "").lower()

    block_signals = [
        "access denied",
        "enable javascript",
        "checking your browser",
        "cloudflare",
        "attention required",
        "bot detection",
        "captcha",
        "forbidden",
        "request blocked",
        "security check",
        "temporarily unavailable",
    ]

    return any(signal in text_lower for signal in block_signals)


def fetch_url_bytes(url: str) -> Tuple[bytes, str]:
    response = requests.get(
        url,
        headers=BROWSER_HEADERS,
        timeout=30,
        allow_redirects=True,
    )

    response.raise_for_status()

    content_type = response.headers.get("Content-Type", "")

    return response.content, content_type


def extract_text_from_pdf_bytes(pdf_bytes: bytes) -> str:
    if not pdf_bytes:
        raise ValueError("PDF file is empty.")

    reader = PdfReader(BytesIO(pdf_bytes))

    pages_text = []

    for page in reader.pages:
        page_text = page.extract_text() or ""
        pages_text.append(page_text)

    cleaned = clean_text("\n".join(pages_text))

    if len(cleaned) < MIN_TEXT_LENGTH:
        raise ValueError(
            "Could not extract enough readable text from this PDF. "
            "Text-based PDFs work best. Image-only or scanned PDFs may not extract correctly."
        )

    return cleaned[:MAX_TEXT_LENGTH]


def extract_text_from_json_bytes(json_bytes: bytes) -> str:
    try:
        data = json.loads(json_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        raw_text = json_bytes.decode("utf-8", errors="ignore")
        cleaned = clean_text(raw_text)

        if len(cleaned) < MIN_TEXT_LENGTH:
            raise ValueError("Could not extract enough readable text from JSON content.")

        return cleaned[:MAX_TEXT_LENGTH]

    parts = []

    if isinstance(data, dict):
        objects = data.get("objects", [])

        if isinstance(objects, list):
            for obj in objects:
                if not isinstance(obj, dict):
                    continue

                obj_type = obj.get("type")
                name = obj.get("name")
                description = obj.get("description")
                pattern = obj.get("pattern")

                if obj_type or name:
                    parts.append(f"Object Type: {obj_type or 'unknown'}")
                    parts.append(f"Name: {name or 'N/A'}")

                if description:
                    parts.append(f"Description: {description}")

                if pattern:
                    parts.append(f"Pattern: {pattern}")

                external_refs = obj.get("external_references", [])
                if isinstance(external_refs, list):
                    for ref in external_refs:
                        if not isinstance(ref, dict):
                            continue

                        source_name = ref.get("source_name")
                        external_id = ref.get("external_id")
                        url = ref.get("url")

                        if source_name or external_id or url:
                            parts.append(
                                f"Reference: {source_name or ''} {external_id or ''} {url or ''}".strip()
                            )

                parts.append("")

        else:
            parts.append(json.dumps(data, indent=2))

    else:
        parts.append(json.dumps(data, indent=2))

    cleaned = clean_text("\n".join(parts))

    if len(cleaned) < MIN_TEXT_LENGTH:
        raise ValueError("Could not extract enough readable text from JSON content.")

    return cleaned[:MAX_TEXT_LENGTH]


def extract_text_with_trafilatura(html: str) -> str:
    if not trafilatura:
        return ""

    try:
        extracted = trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
            favor_recall=True,
            output_format="txt",
        )

        return extracted or ""
    except Exception:
        return ""


def extract_text_with_bs4(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup(
        [
            "script",
            "style",
            "nav",
            "footer",
            "header",
            "aside",
            "form",
            "noscript",
            "svg",
            "button",
            "iframe",
        ]
    ):
        tag.decompose()

    candidates = []

    selectors = [
        "main",
        "article",
        "[role='main']",
        ".content",
        ".main-content",
        ".article",
        ".article-content",
        ".field--name-body",
        ".usa-prose",
        "#content",
        "#main-content",
    ]

    for selector in selectors:
        for element in soup.select(selector):
            text = element.get_text(separator=" ")
            cleaned = clean_text(text)

            if cleaned:
                candidates.append(cleaned)

    body_text = soup.body.get_text(separator=" ") if soup.body else soup.get_text(separator=" ")
    candidates.append(clean_text(body_text))

    candidates = [candidate for candidate in candidates if len(candidate) > 50]

    if not candidates:
        return ""

    return max(candidates, key=len)


def extract_text_with_jina_reader(url: str) -> str:
    reader_url = f"https://r.jina.ai/{url}"

    response = requests.get(
        reader_url,
        headers={
            "User-Agent": BROWSER_HEADERS["User-Agent"],
            "Accept": "text/plain,text/markdown,*/*",
            "X-Return-Format": "markdown",
        },
        timeout=45,
        allow_redirects=True,
    )

    response.raise_for_status()

    return response.text or ""


def get_cisa_fallback_urls(url: str) -> list[str]:
    url_lower = url.lower()
    fallback_urls = []

    for advisory_id, candidates in CISA_ADVISORY_FALLBACKS.items():
        if advisory_id in url_lower:
            fallback_urls.extend(candidates)

    return fallback_urls


def extract_text_from_direct_url(url: str) -> str:
    content_bytes, content_type = fetch_url_bytes(url)

    if looks_like_pdf_url(url, content_type):
        return extract_text_from_pdf_bytes(content_bytes)

    if looks_like_json_url(url, content_type):
        return extract_text_from_json_bytes(content_bytes)

    html = content_bytes.decode("utf-8", errors="ignore")

    extracted_text = extract_text_with_trafilatura(html)

    if not extracted_text:
        extracted_text = extract_text_with_bs4(html)

    extracted_text = clean_text(extracted_text)

    if len(extracted_text) >= MIN_TEXT_LENGTH and not looks_like_block_page(extracted_text):
        return extracted_text[:MAX_TEXT_LENGTH]

    raise ValueError("Not enough readable text extracted from direct URL.")


def extract_text_from_url(url: str) -> str:
    url = validate_url(url)

    direct_error: Optional[str] = None

    # Method 1: direct URL read.
    try:
        return extract_text_from_direct_url(url)
    except requests.exceptions.HTTPError as error:
        status_code = error.response.status_code if error.response else "unknown"
        direct_error = f"Website returned HTTP {status_code}."
    except requests.exceptions.Timeout:
        direct_error = "The website took too long to respond."
    except requests.exceptions.RequestException as error:
        direct_error = str(error)
    except Exception as error:
        direct_error = str(error)

    # Method 2: known advisory fallbacks.
    for fallback_url in get_cisa_fallback_urls(url):
        try:
            return extract_text_from_direct_url(fallback_url)
        except Exception:
            continue

    # Method 3: trafilatura direct fetch.
    if trafilatura:
        try:
            downloaded = trafilatura.fetch_url(url)

            if downloaded:
                extracted_text = extract_text_with_trafilatura(downloaded)

                if not extracted_text:
                    extracted_text = extract_text_with_bs4(downloaded)

                extracted_text = clean_text(extracted_text)

                if (
                    len(extracted_text) >= MIN_TEXT_LENGTH
                    and not looks_like_block_page(extracted_text)
                ):
                    return extracted_text[:MAX_TEXT_LENGTH]

        except Exception:
            pass

    # Method 4: Jina Reader fallback.
    try:
        reader_text = extract_text_with_jina_reader(url)
        reader_text = clean_text(reader_text)

        if len(reader_text) >= MIN_TEXT_LENGTH and not looks_like_block_page(reader_text):
            return reader_text[:MAX_TEXT_LENGTH]

    except Exception:
        pass

    if direct_error:
        raise ValueError(
            f"This page could not be read automatically. Reason: {direct_error} "
            "Try another public advisory URL or paste the article text in Text Report mode."
        )

    raise ValueError(
        "This page could not be read automatically. Some websites restrict automated reading "
        "or load content dynamically. Try another public advisory URL or paste the article text "
        "in Text Report mode."
    )