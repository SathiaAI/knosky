# Privacy

KnoSky is **local-first**. It runs on your machine, reads your folder, and writes files on your machine. There is no KnoSky account, no server, and no telemetry. Your source code is never uploaded by KnoSky.

## What KnoSky reads

To build the map, the indexer reads file and folder names and the **first ~4 KB** of text files (to pull a title, a few headings, and a one-line excerpt). It does **not** copy full file bodies.

## What ends up in a generated city

A generated `city-data.json` / city HTML contains **pointers and light projections**, not your code:

- file paths (relative), folder/category names
- titles, a handful of headings, and a short (<=200 char) excerpt per file
- tags (file extensions), simple link relationships, and a source revision

It does **not** contain full file contents.

## Defaults that protect you

- The absolute root path is **stripped to its basename** by default (use `--include-absolute-root` only for private, local diagnostics).
- Text projections run through a **secret/PII scrubber**, and the build **fails closed** if a secret-like value is detected (override only with `--allow-leaks`).
- `--share-safe` prints a safety report (files scanned/skipped, secrets found, risk level) before you share anything.
- `.gitignore` and a `.kcignore` are honored; inside a git repo, git's own ignore rules are applied.

## What we don't promise

We do **not** claim "zero data risk." A generated city is like a directory listing with short snippets. Treat it accordingly: **review a city file (or build with `--share-safe`) before sharing it**, and open city files you did not generate the same way you'd open any untrusted HTML.

See also: [SECURITY.md](SECURITY.md), [LIMITATIONS.md](LIMITATIONS.md).
