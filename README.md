# ghost2md — Ghost content to portable Markdown

One script that exports a [Ghost](https://ghost.org) publication into
YAML-frontmatter Markdown files — from a backup JSON export or live from
the Admin API.

Every post becomes one `YYYY-MM-DD-slug.md`. A post-count integrity check
runs at the end: the script exits non-zero if any post in the source did
not make it to disk.

## Usage

```sh
# from a Ghost backup file
./ghost2md.py EXPORT.json [-o OUTPUT_DIR] [--base-url URL]

# live from the publication
./ghost2md.py --api [--config ghost2md.config.json]
```

## Frontmatter modes

- `--frontmatter clean` (default) — a portable, tool-agnostic schema
  (title, slug, status, summary, dates, tags split into public/private, …)
  readable by anything from Ghost to Hugo. Pages go to `pages/`, posts
  to `posts/`.
- `--frontmatter full` — the complete round-trippable Ghost header with
  every metadata field preserved, including nulls; all content in
  `posts/`.

## API mode

`--api` talks to the Ghost Admin API (read-only GETs) using an Admin API
key from a Ghost custom integration. Credentials live in the config file
(gitignored), never in the script.

Also live at: https://razodin137.github.io/2026-09-28-ghost-exporter-py/