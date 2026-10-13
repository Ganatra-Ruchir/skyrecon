# SkyRecon — Case Desk V2

Release date: 12 October 2026.

## User-facing features

1. Create a named investigation case.
2. Assign an analyst or team owner.
3. Set low, medium, high or critical priority.
4. Track open, investigating and resolved states.
5. Link and unlink indicators already ingested in the console.
6. Record investigation notes.
7. Maintain a checklist with completion state.
8. Search titles, owners and notes.
9. Filter cases by status.
10. Export all cases as a versioned JSON backup.
11. Import validated JSON, skip duplicate IDs and enforce size/count limits.
12. Download an individual Markdown handover.
13. Duplicate a case with its evidence and checklist.
14. Persist cases locally with explicit save/error feedback.

## Use and limits

Open console/index.html and choose Case desk. Cases use a separate browser-local store even if the existing indicator workspace has a cloud store available. Cases do not sync between devices; export backups. Limits: 100 cases, 100 tasks/case, 200 linked indicators/case, 20,000 characters of notes, 2 MB imports. JSON imports merge new IDs; they do not overwrite existing cases. Indicators are references, not an immutable evidence archive. Deleting the workspace also deletes local cases.

## Interface and reliability

Responsive layouts, keyboard focus, lightweight CSS animation with a pause control, and operating-system reduced-motion support. Browser checks cover representative workflows, download events, reload persistence where applicable, JavaScript errors and mobile overflow. Passing these checks is not a guarantee of zero defects.

## Verification

```sh
npm ci
npx playwright install chromium
npm run test:browser
```

