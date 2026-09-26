# Hosted provider acceptance record template

Copy this file to `docs/product/<provider>-hosted-acceptance-YYYY-MM-DD.md` for each P0 provider.
One record covers one production connection exercised end to end. Do not include customer email
addresses, access tokens, callback codes, setup commands, signed URLs, secrets, DSNs, private
keys, source contents, prompts, responses, or provider payloads.

## Environment and revision

- Provider:
- Date and UTC window:
- Operator:
- Reviewed production `main` SHA:
- Production deployment workflow URL:
- Denali tenant UUID:
- Connection UUID:
- Provider-side non-secret scope identifiers:
- Applicable ADR:

## Preconditions

- [ ] Direct Modal and same-origin health returned ready.
- [ ] Unauthenticated protected API request returned `401`.
- [ ] Production configuration check reported the provider group ready.
- [ ] No validation or collection job was already active for the connection.
- [ ] Provider-side customer grant was reviewed as read-only and revocable.

## Lifecycle evidence

Record timestamps, HTTP status/state, bounded counts, coverage states, and safe identifiers only.

- [ ] Admin created the connection.
- [ ] Member create/setup/validate/collect/disable/delete attempts returned `403`.
- [ ] Other-organization detail and mutation attempts returned `404`.
- [ ] Setup/callback completed using the provider's exact account/tenant/domain/install/scope
      binding and one-time state contract.
- [ ] A replayed, expired, or mismatched setup capability was rejected.
- [ ] Validation completed durably and every declared plane had an explicit result.
- [ ] Duplicate validation returned `already_running` or otherwise proved active-job uniqueness.
- [ ] Healthy validation queued the applicable primary collection job.
- [ ] Collection completed durably after an API-container replacement test.
- [ ] Duplicate worker delivery was idempotent and did not duplicate evidence.
- [ ] Collected evidence and coverage appeared in the hosted UI.
- [ ] Missing, failed, partial, unsupported, and unselected evidence was not displayed as safe or
      complete.
- [ ] Disable was rejected while a job was active, then succeeded after the job completed.
- [ ] Disabled validation and collection attempts returned `409`.
- [ ] Delete was rejected before disable and for a wrong display-name confirmation.
- [ ] Delete succeeded after disable with exact confirmation.
- [ ] Previously collected evidence remained and connection configuration was no longer readable.
- [ ] Customer-side access revocation instructions were exercised or separately dated.

## Provider-specific evidence

Copy the applicable provider row from the
[agent security roadmap](../product/agent-security-roadmap.md) and record the result of every
required scope check. Collection is a separate acceptance plane from validation.

## Privacy and logging inspection

- [ ] Retained connection, job, coverage, activity, and evidence records contained no prohibited
      secret, token, callback, source-content, prompt, response, or tool-payload fields.
- [ ] Operational logs used only bounded tenant, connection, job, route, state, and error-class
      identifiers.
- [ ] Provider and SDK failures were sanitized to bounded classifications.

## Result

- Lifecycle: passed / failed / partial
- Validation: passed / failed / partial
- Collection: passed / failed / partial / not applicable
- Tenancy and authorization: passed / failed
- Privacy inspection: passed / failed
- Open blockers:
- Follow-up issue or PR:
- Rollback/revocation result:
