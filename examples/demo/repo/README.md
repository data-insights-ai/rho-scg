# scg-demo

A repository that pins `scg-demo-action@v1` with SCG and shows what
happens when the tag moves.

Set up once, in an empty repository `data-insights-ai/scg-demo`:

1. Copy this directory in, then in the checkout: `scg init --watch`
   (with `SCG_API_KEY` set) and commit `scg.lock`.
2. Repository secrets: `SCG_API_KEY` (an organization key) and
   `DEMO_ACTION_TOKEN` (fine-grained token, Contents: write on
   `scg-demo-action` only).
3. A drift webhook on the organization's account page, pointing at
   somewhere you can see (a request bin works).

The demonstration, in this order:

| Minute | Action | What SCG shows |
| --- | --- | --- |
| 0 | Actions → hijack demo → Run with `on` | the tag `v1` now points at the "hijacked" commit |
| ≤ 15 | nothing | the platform re-checks watched tools every quarter hour: signed webhook delivered, `scg intel --private` lists `watched_drift` |
| any | Actions → ci → Run | `CRITICAL DRIFT DETECTED`, exit 1; the job fails before the action runs |
| end | hijack demo → Run with `off` | next ci run green; the private feed keeps the incident |

`scg history github_action data-insights-ai/scg-demo-action@v1` shows
both commits with the time the tag moved.
