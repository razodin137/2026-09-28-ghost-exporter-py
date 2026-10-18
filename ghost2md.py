#!/usr/bin/env python3
"""ghost2md.py — Export Ghost.org content into YAML-frontmatter Markdown files.

Usage:
    ./ghost2md.py EXPORT.json [-o OUTPUT_DIR] [--base-url URL]   # from a backup file
    ./ghost2md.py --api [--config ghost2md.config.json]         # live from the publication

Every post becomes one Markdown file named YYYY-MM-DD-slug.md. By default
the frontmatter is a portable, tool-agnostic schema (title, slug, status,
summary, dates, tags split into public/private, ...) readable by anything
from Ghost to Hugo; pages go to pages/, posts to posts/. Use
--frontmatter full for the complete round-trippable Ghost header with
every metadata field preserved, including nulls, and all content in
posts/. A post-count integrity check runs at the end: the script exits
non-zero if any post in the source did not make it to disk.

The --api mode talks to the Ghost Admin API (read-only GETs) using the
Admin API key from a Ghost custom integration; credentials live in the
config file (gitignored), never in the script.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import date, datetime
from pathlib import Path

import yaml
from bs4 import BeautifulSoup, Comment
from markdownify import MarkdownConverter

# Frontmatter fields pulled from the posts table, in emission order.
# (source_field, yaml_key, transform)  — None for derived/joined fields.
BOOL_FIELDS = {"featured", "show_title_and_feature_image"}

POST_FIELDS: list[tuple[str, str]] = [
    ("title", "title"),
    ("slug", "slug"),
    ("uuid", "uuid"),
    ("id", "ghost_id"),
    ("type", "type"),
    ("status", "status"),
    ("visibility", "visibility"),
    ("featured", "featured"),
    ("show_title_and_feature_image", "show_title_and_feature_image"),
    ("locale", "locale"),
    ("email_recipient_filter", "email_recipient_filter"),
    ("newsletter_id", "newsletter_id"),
    ("custom_excerpt", "excerpt"),
    ("feature_image", "feature_image"),
    ("canonical_url", "canonical_url"),
    ("custom_template", "custom_template"),
    ("codeinjection_head", "codeinjection_head"),
    ("codeinjection_foot", "codeinjection_foot"),
    ("created_at", "created_at"),
    ("updated_at", "updated_at"),
    ("published_at", "published_at"),
    (None, "tags"),
    (None, "authors"),
]

# Frontmatter fields pulled from posts_meta, in emission order.
POSTS_META_FIELDS: list[tuple[str, str]] = [
    ("meta_title", "meta_title"),
    ("meta_description", "meta_description"),
    ("og_title", "og_title"),
    ("og_description", "og_description"),
    ("og_image", "og_image"),
    ("twitter_title", "twitter_title"),
    ("twitter_description", "twitter_description"),
    ("twitter_image", "twitter_image"),
    ("email_subject", "email_subject"),
    ("email_only", "email_only"),
    ("feature_image_alt", "feature_image_alt"),
    ("feature_image_caption", "feature_image_caption"),
]

# Content/derived fields intentionally excluded from frontmatter.
# html/mobiledoc/lexical become the body, plaintext is an unreliable derived value.


def load_export(path: Path) -> dict:
    """Load a Ghost export and merge all db[] entries' data tables."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    merged: dict[str, list] = {}
    for entry in raw.get("db", []):
        for table, rows in entry.get("data", {}).items():
            merged.setdefault(table, []).extend(rows or [])
    return merged


def build_indexes(data: dict) -> dict:
    """Index tags, users, and the posts_tags / posts_authors / posts_meta joins."""
    tags_by_id = {t["id"]: t for t in data.get("tags", [])}
    users_by_id = {u["id"]: u for u in data.get("users", [])}

    tags_by_post: dict[str, list[str]] = {}
    for join in sorted(data.get("posts_tags", []), key=lambda j: j.get("sort_order", 0)):
        tag = tags_by_id.get(join.get("tag_id"))
        name = tag["name"] if tag else None
        if name:
            tags_by_post.setdefault(join["post_id"], []).append(name)

    authors_by_post: dict[str, list[str]] = {}
    for join in sorted(data.get("posts_authors", []), key=lambda j: j.get("sort_order", 0)):
        user = users_by_id.get(join.get("author_id"))
        name = user["name"] if user else None
        if name:
            authors_by_post.setdefault(join["post_id"], []).append(name)

    meta_by_post = {m["post_id"]: m for m in data.get("posts_meta", [])}

    return {
        "tags_by_post": tags_by_post,
        "authors_by_post": authors_by_post,
        "meta_by_post": meta_by_post,
    }


# ---------------------------------------------------------------------------
# Source adapters — both produce a list of records:
#   {"post": <post dict>, "tags": [...], "authors": [...], "meta": {...}}
# so the export pipeline is identical regardless of where content came from.
# ---------------------------------------------------------------------------


def records_from_export(data: dict) -> list[dict]:
    """Turn a parsed Ghost backup's tables into normalized records."""
    indexes = build_indexes(data)
    records = []
    for post in data.get("posts", []):
        records.append({
            "post": post,
            "tags": indexes["tags_by_post"].get(post["id"], []),
            "authors": indexes["authors_by_post"].get(post["id"], []),
            "meta": indexes["meta_by_post"].get(post["id"], {}),
        })
    return records


def make_token(admin_key: str) -> str:
    """Create the short-lived HS256 JWT Ghost's Admin API expects.

    The Admin key is "<id>:<hex secret>"; the id goes in the JWT header
    as `kid`, and the secret signs the token.
    """
    key_id, _, secret_hex = admin_key.partition(":")
    if not secret_hex:
        raise ValueError("admin key must look like '<id>:<secret>'")

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": key_id}).encode())
    now = int(time.time())
    payload = b64(json.dumps({"iat": now, "exp": now + 300}).encode())
    signing_input = f"{header}.{payload}".encode()
    signature = hmac.new(bytes.fromhex(secret_hex), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64(signature)}"


def api_get(url: str, token: str) -> dict:
    """GET a Ghost Admin API endpoint and return the parsed JSON."""
    request = urllib.request.Request(
        url, headers={"Authorization": f"Ghost {token}", "Accept": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def records_from_api(api_url: str, admin_key: str) -> list[dict]:
    """Fetch every post and page (all statuses, incl. drafts) from the Admin API."""
    base = api_url.rstrip("/")
    token = make_token(admin_key)
    records: list[dict] = []

    for content_type in ("post", "page"):
        url = (
            f"{base}/ghost/api/admin/posts/"
            f"?limit=all&filter={urllib.parse.quote(f'type:{content_type}')}"
        )
        data = api_get(url, token)
        for post in data.get("posts", []):
            records.append({
                "post": post,
                "tags": [t["name"] for t in post.get("tags") or []],
                "authors": [a["name"] for a in post.get("authors") or []],
                # posts_meta fields are flattened onto the API post object.
                "meta": {source: post.get(source) for source, _ in POSTS_META_FIELDS},
            })

    return records


def sanitize_slug(slug: str | None) -> str:
    """Reduce a slug to lowercase alphanumerics and dashes."""
    slug = (slug or "untitled").lower()
    slug = re.sub(r"[^a-z0-9-]+", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    return slug or "untitled"


def date_prefix(post: dict) -> str:
    """Date prefix from published_at, falling back to created_at."""
    for field in ("published_at", "created_at"):
        value = post.get(field)
        if value:
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            except ValueError:
                pass
    return "1970-01-01"


def html_to_markdown(html: str, base_url: str | None) -> str:
    """Best-effort HTML → Markdown.

    Top-level Ghost cards that Markdown cannot express (callouts, CTA,
    bookmark, button, ...) are preserved verbatim as raw HTML blocks.
    Simple image cards become `![alt](src)`; everything else goes
    through markdownify. Falls back to the raw HTML if conversion
    somehow yields nothing, so content is never lost.
    """
    if not html:
        return ""
    if base_url:
        html = html.replace("__GHOST_URL__", base_url.rstrip("/"))

    soup = BeautifulSoup(html, "html.parser")
    converter = MarkdownConverter(heading_style="ATX", bullets="-")
    blocks: list[str] = []

    for node in list(soup.children):
        if isinstance(node, Comment):
            # HTML comments are meaningful in Ghost (e.g. <!--members-only-->).
            text = str(node).strip()
            if text:
                blocks.append(f"<!--{text}-->")
            continue

        if isinstance(node, str):
            text = node.strip()
            if text:
                blocks.append(text)
            continue

        classes = node.get("class") or []
        if "kg-card" in classes:
            imgs = node.find_all("img", recursive=True)
            is_simple_image = (
                "kg-image-card" in classes
                and len(node.find_all(["p", "div", "figcaption"], recursive=True)) <= 1
                and imgs
            )
            if is_simple_image:
                img = imgs[0]
                alt = img.get("alt", "")
                src = img.get("src", "")
                blocks.append(f"![{alt}]({src})")
            else:
                # No Markdown equivalent: keep the card as a raw HTML block.
                blocks.append(str(node).strip())
            continue

        md = converter.convert_soup(node) if hasattr(converter, "convert_soup") else None
        if md is None:
            md = converter.convert(str(node))
        md = md.strip()
        if md:
            blocks.append(md)

    body = "\n\n".join(b for b in blocks if b).strip()
    return body if body else html.strip()


def iso_date(value: str | None) -> date | None:
    """Reduce a Ghost ISO timestamp to a YAML date (emits unquoted YYYY-MM-DD)."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def derive_summary(post: dict) -> str | None:
    """Custom excerpt if set, else the opening of the first paragraph (~160 chars).

    Paragraphs that just repeat the title are skipped so the summary
    never merely restates it.
    """
    excerpt = post.get("custom_excerpt")
    if excerpt:
        return excerpt
    text = (post.get("plaintext") or "").strip()
    if not text:
        return None
    title = (post.get("title") or "").strip().lower()
    paragraph = ""
    for para in text.split("\n\n"):
        paragraph = " ".join(para.split())
        if paragraph and paragraph.lower() != title:
            break
    if not paragraph or paragraph.lower() == title:
        return None
    if len(paragraph) <= 160:
        return paragraph
    return paragraph[:160].rsplit(" ", 1)[0].rstrip(" ,;:") + "…"


def build_clean_frontmatter(post: dict, tags: list[str], authors: list[str]) -> dict:
    """Portable frontmatter schema: readable by anything from Ghost to Hugo.

    Ghost's internal tags (names starting with '#') are split into
    private_tags so consumers can treat them as workflow/stage markers
    instead of public categories.
    """
    return {
        "title": post.get("title"),
        "slug": post.get("slug"),
        "type": post.get("type", "post"),
        "status": post.get("status"),
        "featured": bool(post.get("featured")),
        "summary": derive_summary(post),
        "published_date": iso_date(post.get("published_at")),
        "created_date": iso_date(post.get("created_at")),
        "public_tags": [t for t in tags if not t.startswith("#")],
        "private_tags": [t for t in tags if t.startswith("#")],
        "authors": list(authors),
        "featured_image": post.get("feature_image"),
    }


def build_frontmatter(post: dict, tags: list[str], authors: list[str], meta: dict) -> dict:
    """Assemble the ordered frontmatter mapping for one post."""
    fm: dict = {}
    for source, key in POST_FIELDS:
        if source is None:
            continue
        value = post.get(source)
        if source in BOOL_FIELDS:
            value = bool(value)
        fm[key] = value
    fm["tags"] = list(tags)
    fm["authors"] = list(authors)

    for source, key in POSTS_META_FIELDS:
        value = meta.get(source)
        if source == "email_only":
            value = bool(value)
        fm[key] = value

    return fm


def render_document(frontmatter: dict, body: str) -> str:
    yaml_text = yaml.dump(
        frontmatter,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=100,
    )
    return f"---\n{yaml_text}---\n\n{body}\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export Ghost content (backup JSON or live publication) to Markdown files."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("export", nargs="?", type=Path, help="Ghost export .json file")
    source.add_argument("--api", action="store_true",
                         help="fetch live content from the publication via the Admin API")
    parser.add_argument("--config", type=Path, default=Path("ghost2md.config.json"),
                        help="config file with api_url/admin_api_key for --api mode")
    parser.add_argument("--api-url", default=None, help="override the config's api_url")
    parser.add_argument("--admin-key", default=None,
                        help="override the config's admin_api_key (prefer the config file)")
    parser.add_argument("-o", "--output", type=Path, default=Path("output"),
                        help="output directory (default: ./output)")
    parser.add_argument("--base-url", default=None,
                        help="replace __GHOST_URL__ placeholders in content with this URL")
    parser.add_argument("--frontmatter", choices=("clean", "full"), default="clean",
                        help="frontmatter schema: 'clean' portable (default) or "
                             "'full' round-trippable Ghost export")
    args = parser.parse_args()

    if not args.api and args.export is None:
        parser.error("give an EXPORT.json file, or use --api to fetch from the publication")

    try:
        if args.api:
            config = json.loads(args.config.read_text(encoding="utf-8")) \
                if args.config.is_file() else {}
            api_url = args.api_url or config.get("api_url")
            admin_key = args.admin_key or config.get("admin_api_key")
            if not api_url or not admin_key:
                print(f"error: --api needs api_url and admin_api_key "
                      f"(in {args.config} or via --api-url/--admin-key)", file=sys.stderr)
                return 2
            print(f"Fetching from {api_url} ...")
            records = records_from_api(api_url, admin_key)
            source_label = api_url
        else:
            if not args.export.is_file():
                print(f"error: export file not found: {args.export}", file=sys.stderr)
                return 2
            records = records_from_export(load_export(args.export))
            source_label = str(args.export)
    except (urllib.error.URLError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: failed to read source: {exc}", file=sys.stderr)
        return 2

    if not records:
        print("error: no posts found in source", file=sys.stderr)
        return 2

    print(f"Source: {source_label} — {len(records)} posts found")

    posts_dir = args.output / "posts"
    posts_dir.mkdir(parents=True, exist_ok=True)
    pages_dir = args.output / "pages"
    if args.frontmatter == "clean":
        pages_dir.mkdir(parents=True, exist_ok=True)

    expected: Counter = Counter()
    written: Counter = Counter()
    failures: list[str] = []
    names_used: dict[Path, set[str]] = {}

    for record in records:
        post = record["post"]
        bucket = f"{post.get('type', 'post')}/{post.get('status', '?')}"
        expected[bucket] += 1

        if args.frontmatter == "clean":
            frontmatter = build_clean_frontmatter(post, record["tags"], record["authors"])
        else:
            frontmatter = build_frontmatter(post, record["tags"], record["authors"], record["meta"])
        body = html_to_markdown(post.get("html"), args.base_url)
        document = render_document(frontmatter, body)

        slug = sanitize_slug(post.get("slug"))
        name = f"{date_prefix(post)}-{slug}.md"
        target_dir = (pages_dir
                      if args.frontmatter == "clean" and post.get("type") == "page"
                      else posts_dir)
        used = names_used.setdefault(target_dir, set())
        if name in used:
            # Two posts in this export collide: disambiguate with the uuid.
            name = f"{date_prefix(post)}-{slug}-{(post.get('uuid') or '')[:8]}.md"
        used.add(name)
        target = target_dir / name

        try:
            target.write_text(document, encoding="utf-8")
        except OSError as exc:
            failures.append(f"{post.get('slug', '?')}: write failed: {exc}")
            continue

        # Integrity check: re-read from disk and confirm identity.
        try:
            text = target.read_text(encoding="utf-8")
            on_disk = yaml.safe_load(text.split("---", 2)[1])
            if args.frontmatter == "clean":
                if on_disk.get("slug") != post.get("slug"):
                    failures.append(f"{target.name}: slug mismatch after write")
                    continue
            elif on_disk.get("ghost_id") != post.get("id"):
                failures.append(f"{target.name}: ghost_id mismatch after write")
                continue
            if body and len(text) <= len(document.split("---", 2)[-1]):
                failures.append(f"{target.name}: body missing after write")
                continue
        except (OSError, yaml.YAMLError, IndexError) as exc:
            failures.append(f"{target.name}: verification failed: {exc}")
            continue

        written[bucket] += 1
        print(f"  wrote {target.relative_to(args.output)}")

    # ---- Summary / count check -------------------------------------------
    print()
    print("Post count check")
    print(f"  {'type/status':<24} {'in source':>10} {'exported':>10}")
    ok = True
    for bucket in sorted(expected):
        exp, got = expected[bucket], written[bucket]
        mark = "OK" if exp == got else "MISMATCH"
        print(f"  {bucket:<24} {exp:>10} {got:>10}   {mark}")
        if exp != got:
            ok = False
    total_exp, total_got = sum(expected.values()), sum(written.values())
    print(f"  {'TOTAL':<24} {total_exp:>10} {total_got:>10}")

    if failures:
        ok = False
        print("\nFailures:")
        for f in failures:
            print(f"  - {f}")

    if not ok:
        print(f"\nFAILED: exported {total_got}/{total_exp} posts.", file=sys.stderr)
        return 1

    print(f"\nSuccess: {total_got}/{total_exp} posts exported to {args.output}/"
          + (" (posts/ + pages/)" if args.frontmatter == "clean" else " posts/"))
    return 0


if __name__ == "__main__":
    sys.exit(main())