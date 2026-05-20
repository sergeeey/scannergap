# BlindSpotSec Discovery Call Script

## Goal

Qualify whether a scoped scanner blind-spot audit is useful, without selling it as a production SaaS or pentest.

## Opening

"I am looking for teams that already use SAST and want to understand where their current scanner stack may still be blind. The first pilot is a scoped manual audit of one repo or service."

## Questions

1. Which SAST tools are currently in CI or used by AppSec?
2. Which languages and frameworks are most critical?
3. Do security findings often appear late in code review, pentest, or incident review?
4. Are there known vulnerability classes that your scanners struggle with?
5. Would your team prefer a coverage matrix, custom rule ideas, or process recommendations?
6. What repo/service would be small enough for a first pilot?
7. Can code leave your environment, or should this be local/offline?
8. Who would evaluate whether the report is useful?

## Positioning

Use:

> "This is a focused scanner-gap assessment."

Avoid:

> "This does not replace SAST."
> "This is a full pentest."
> "This is a production SaaS."

## Close

"A useful first step would be one repo or one service, 3-5 critical flows, and a short report with blind-spot classes, concrete examples, and practical next steps. Should I send the POC scope?"
