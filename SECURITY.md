# Security Policy

KnoSky is a **local-first** tool: it runs on your machine, indexes your own folder, and writes a self-contained city file. It does not upload your source and has no hosted backend. The security surface that matters is the **generated artifact** (the city HTML / `city-data.json`) and the local indexer/MCP.

## Supported versions

The latest release on the `main` branch is supported. KnoSky is pre-1.0; please run the newest version before reporting an issue.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for anything exploitable.

- Preferred: GitHub **"Report a vulnerability"** (Security → Advisories) on this repository, which opens a private channel.
- We aim to acknowledge reports within **5 business days** and to publish a fix or mitigation for confirmed issues as quickly as is practical.

When reporting, please include: the version/commit, steps to reproduce, and the impact you observed. A minimal proof-of-concept (e.g., a tiny repo or `city-data.json` that triggers the issue) helps a lot.

## Safe testing guidelines

- Test only against repositories and folders **you own or control**.
- Do not include real secrets or third-party personal data in proof-of-concept artifacts.
- Do not perform testing that degrades the service for others (there is no shared service; this is a local tool).

## Handling generated artifacts (for users)

- A generated city embeds **file names, paths, headings, and short excerpts** — not full file bodies. Treat a generated file as you would a directory listing with snippets.
- Build with `--share-safe` before sharing: it strips the absolute root path (basename only), runs a fail-closed secret scan, and prints a safety report. Builds **fail closed** if a secret-like value is detected (override only with `--allow-leaks`).
- Open city files you did not generate the same way you would any untrusted HTML.

## Scope

In scope: injection in generated artifacts, secret leakage through projections, the local MCP server, and the indexer's privacy defaults. Out of scope: issues that require an attacker to already control your machine or your repository's contents with your knowledge.
