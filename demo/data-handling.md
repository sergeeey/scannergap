# BlindSpotSec Data Handling Note

This note is intended for early scoped POCs.

## Default Approach

- Request the smallest useful scope: one repo, one service, or selected files.
- Prefer read-only access or client-provided archives.
- Do not request production secrets.
- Do not publish customer code, findings, or names without written approval.
- Minimize code snippets in reports.
- Redact secrets, tokens, and personal data if encountered.

## Local / Offline Option

If customer code cannot leave the customer environment, the review can be run as a guided local/offline audit:

- customer runs agreed scanner commands;
- customer shares scanner summaries or selected redacted outputs;
- BlindSpotSec reviews agreed snippets or screenshare evidence;
- final report avoids proprietary code unless explicitly approved.

## Retention

For a first POC, agree on retention before receiving code:

- delete local working copies after final report, if requested;
- keep only final report and commercial records;
- do not use customer code in demos or public benchmark artifacts.

## Boundaries

This is not a production SaaS data-processing agreement. For hosted or recurring processing, a separate security architecture, DPA, retention policy, and tenant isolation model are required.
