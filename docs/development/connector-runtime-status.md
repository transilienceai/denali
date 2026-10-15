# AWS and Azure runtime collection status

AWS and Azure deployment evidence and opt-in agent runtime activity are separate
collection planes. The browser derives the selected planes from the saved
`declared_scopes`; a runtime-only connection must not wait for an unrelated
deployment result. Mixed connections wait for a new terminal result from every
selected plane. An absent result, unchanged previous timestamp, or an older
successful result while a job is running is not completion of the accepted run.

The common progress indicator, connection readiness badge, Grant → Verify →
Collect journey and dependent-data refresh recognize both runtime job fields.
Partial or failed runtime results remain visible as incomplete evidence even when
deployment collection succeeded. Shared AWS and Microsoft detail panels show
per-plane validation proof and selected collection results with state, finish
time, available counts and sanitized provider diagnostics. While a new run is
active, any retained result is explicitly labeled as the previous run. These
browser status changes neither start
additional provider reads nor change API, CLI/MCP, authentication, scope grants,
job persistence or collection-worker behavior.

Regression coverage includes runtime-only and mixed selection, both completion
orders, missing/unchanged results, failed/partial runtime, and restored native and
shared connection details after navigation. Hosted acceptance must still check
actual runtime evidence independently of access validation.

## Separate existing UI limitation

The Connections page still holds a page-wide `busy` value while a manually
requested validation polls its durable result. Some shared connection detail
buttons therefore remain disabled when a different connection is validating.
Reloading clears that browser-only value without canceling the durable job. This
limitation predates unified onboarding and is intentionally not changed by the
runtime-status patch. A separate fix must scope pending requests by connection
and fence overlapping completions and organization changes; merely hiding the
global value would introduce async state races.
