# Modal failure and timeout alert acceptance — 2026-09-15

This record proves the hosted Modal timeout-alert path without intentionally failing a production
Denali worker. It contains bounded operational metadata only and excludes application secrets,
request data, provider payloads, and customer identifiers.

## Environment and boundary

- Date and UTC window: 2026-09-15 21:33–21:35 UTC
- Operator: KK Mookhey / Codex
- Production app inspected: `denali-production` in `denali-prod`
- Disposable drill app: `denali-alert-p0-acceptance` in isolated `denali-dev`
- Drill function: `expected_timeout_for_alert_acceptance`
- Configured function timeout: 10 seconds
- Drill schedule: every 60 seconds while the drill app was active

The production app and its secrets were not changed. The disposable function slept beyond its
ten-second limit and did not read or write Denali, provider, or customer data.

## Configuration evidence

- [x] The Modal notification settings had **All notifications**, **Deployed Function alerts**,
      **Failure digests**, **Usage alerts**, and **Client deprecation warnings** enabled.
- [x] The production `denali-production` function dashboard was reachable and showed the durable
      scheduled workers running successfully before the drill.
- [x] The drill used the isolated `denali-dev` environment rather than production.

## Exercise result

- [x] Modal scheduled the disposable function at 2026-09-15 21:33:25 UTC.
- [x] The function started after a bounded cold start and executed for exactly 10.00 seconds.
- [x] Modal classified the call as **Timed out**.
- [x] Modal delivered an email titled `Scheduled function failure in
      denali-alert-p0-acceptance (denali-dev)` at 2026-09-15 21:33 UTC.
- [x] The email named the workspace, environment, deployment, and function without including
      Denali secrets, request data, provider payloads, prompts, or responses.
- [x] The disposable app was stopped immediately after delivery was verified; it no longer
      appears among active `denali-dev` apps.

## Result

- Modal failure/timeout detection: passed
- Email notification delivery: passed
- Production isolation: passed
- Drill cleanup: passed
- Vercel monitoring: not covered by this record and remains a separate P0 gate

