# P0 external-action handoff — 2026-09-17

This is the ordered runbook for the P0 work that cannot be completed from repository, Modal, or
the currently signed-in product session alone. Do not send credentials, access tokens, private
keys, callback codes, database URLs, or provider payloads in chat, screenshots, issues, or the
repository.

## Current state

- Production revision `16b49a082c242694cf58038b2dcdfad8fc2935f9` is deployed and healthy through
  protected workflow `35302266387`.
- The fail-closed production configuration gate covers core, AWS, Azure, GCP, Entra, Google
  Workspace, GitHub, and Azure Repos and has passed at that revision.
- Modal failure/timeout alerting, the Neon runtime/migration role split, non-empty Organization
  switching, and the hosted `org:member` read-only UI have passed.
- Keep the disabled `AWS AgentCore P0 Acceptance` connection. It is retained evidence and is not
  the AWS delete specimen.
- Open external gates are Vercel runtime monitoring, Neon managed backup/alert/restore evidence,
  the browser-token direct authorization matrix, and complete disposable lifecycle records for
  every P0 provider.

## Operator steps — KK

### Vercel account handoff

1. In the open Vercel login tab, use the email or passkey method already attached to the existing
   Vercel account. Do not start with GitHub; Vercel currently reports that the GitHub identity is
   not linked.
2. In the account avatar menu, open **Settings → Authentication** and add GitHub as a login
   connection. Approve the Vercel GitHub App request to verify identity, read the required email
   and account resources, and act through the App.
3. Confirm that the account can open team `transilience-dev`, project `denali`, and its Production
   Analytics/Observability pages. Stop if Vercel proposes creating a new account or project.
4. Leave that project page open and tell Codex the login/link is complete. Codex will enable or
   verify Web Analytics, exercise the production path, and record the result.

### Provider sessions and deletion confirmations

1. Sign in to the applicable AWS, Microsoft, Google Cloud/Workspace, and GitHub consoles only when
   the corresponding disposable lifecycle drill is ready. Use an administrator identity with the
   bounded permissions listed below; do not provide its credential to Denali or Codex.
2. Review every generated CloudFormation, Cloud Shell, consent, delegation, or GitHub App screen
   before approving it. Denali should request only the documented read-only boundary.
3. For each disposable connection, confirm the observed account/tenant/domain/installation and
   selected scopes before Codex validates or collects.
4. After evidence collection, Codex will disable the connection. Immediately before any UI delete
   action, Codex will ask for a fresh confirmation naming that exact disposable connection. This
   confirmation is required even though the overall drill is authorized.
5. After Denali deletion, remove the matching provider-side temporary role, service principal,
   consent, delegation, or installation grant when the provider runbook says it is customer-owned.
   Do not remove grants used by retained production connections.

### Clerk direct-API probe

No operator action is needed for the completed member UI check. The remaining live `403`/`404`
matrix requires a supported way to use a browser-issued Clerk token without printing or persisting
it. Do not copy a token from browser storage or developer tools into chat. Until that harness is
available, the automated API authorization suite remains the direct-mutation evidence.

## Administrator steps

### Neon project owner

1. Invite the current Neon account to the Organization and exact production project. Prefer the
   least privilege that permits branch creation, project settings, integrations, and monitoring;
   Neon currently documents Organization Collaborator plus project Editor for that boundary.
   Do not grant project deletion or Organization billing authority unless independently required.
2. Alternatively, create a project-scoped Organization API key and place it through an approved
   secret channel. Never paste it into chat, a ticket, or the repository.
3. Confirm the production project's point-in-time recovery retention meets the agreed RPO and that
   the project has the required monitoring/alert integration. If alerts are delivered through
   Datadog, the Datadog administrator must provide the destination and permit test delivery.
4. Tell Codex only that access is ready and identify the project by its non-secret project name or
   ID. Codex will create a temporary historical restore branch, verify schema and bounded record
   counts, test alert delivery, record timestamps/RPO/RTO, and request confirmation before deleting
   the temporary branch.

References: [Neon per-project permissions](https://neon.com/blog/neon-now-has-per-project-permissions),
[project-scoped Organization API keys](https://neon.com/docs/manage/orgs-api),
[point-in-time restore](https://neon.com/blog/announcing-point-in-time-restore), and
[Datadog monitoring](https://neon.com/docs/guides/datadog).

### Vercel team owner

1. If the operator cannot see `transilience-dev/denali` after linking GitHub, invite the existing
   Vercel account to that team/project with permission to manage Analytics and inspect Production
   deployments. Do not create a duplicate Denali project.
2. Confirm Production remains sourced only from merged `main`; Preview remains isolated in
   `denali-dev`.

References: [Vercel account login connections](https://vercel.com/docs/accounts) and
[Web Analytics](https://vercel.com/docs/analytics/using-web-analytics).

### AWS administrator

1. Use a new disposable Denali AWS connection and a unique CloudFormation stack/role; do not reuse
   or delete the retained `AWS AgentCore P0 Acceptance` fixture.
2. Review and create Denali's generated CloudFormation stack with its exact external-ID trust and
   read-only policies. Select only the acceptance Region/planes.
3. After Denali validates, collects, disables, and deletes the disposable record, delete only that
   stack and wait for its IAM role to disappear. Codex then verifies that retained evidence remains.

### Microsoft tenant and subscription administrators

1. **Azure:** a tenant identity must be able to create/confirm the enterprise application. An
   Owner or User Access Administrator grants Reader on only the selected disposable subscription.
2. **Entra:** a tenant administrator reviews and grants the disclosed fixed Microsoft Graph
   application permissions through Denali's one-time consent state.
3. **Azure Repos:** a user proves access to the exact Azure DevOps Organization and selects exact
   repository UUIDs; an application administrator ensures Denali's read-only service principal can
   access only those repositories.
4. After each deletion record, remove only the temporary role assignments, consent, or repository
   grant and verify the retained evidence remains in Denali.

### Google Cloud and Workspace administrators

1. **Google Cloud:** run the generated Cloud Shell setup while signed in as a project IAM
   administrator. Grant Denali's unique per-connection keyless principal only the documented read
   roles on the selected disposable projects.
2. **Google Workspace:** a super administrator adds the disclosed Denali service-account client ID
   to domain-wide delegation for only the fixed Admin Reports read scope and confirms the delegated
   administrator/domain boundary.
3. After the lifecycle record, remove only the temporary project bindings or delegation entry and
   verify retained evidence remains.

### GitHub Organization or installation owner

1. Install or update the Denali GitHub App on a disposable exact-repository selection. Keep OAuth
   during installation disabled; the separate user authorization proves installer access and its
   token is transient.
2. Confirm Denali receives Metadata read and Contents read only for the selected repositories.
3. After the Denali disable/delete record, remove the disposable repository selection or App
   installation only if it is not shared by a retained production connection.

## Codex steps after access is ready

1. Complete Vercel Web Analytics/Observability setup and retain a production exercise record.
2. Verify Neon recovery retention and alerts, create and validate a temporary restore branch, and
   record the restore drill without changing the production branch.
3. Run one provider at a time through create → setup/callback → validate → collect → disable →
   delete, using the hosted acceptance template and a fresh action-time delete confirmation.
4. Verify provider-side revocation and Denali-side retained evidence after each delete.
5. Update the roadmap/checklist and open a reviewable documentation PR. P0 is complete only after
   all external gates have dated records; no open item is converted into a pass by documentation.
