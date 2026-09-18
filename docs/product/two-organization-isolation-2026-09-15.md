# Hosted two-Organization isolation acceptance — 2026-09-15

This record covers the production Clerk Organization and Denali tenant boundary. It contains
bounded organization, tenant, and connection identifiers only. It excludes user email addresses,
session tokens, authorization headers, provider credentials, and provider payloads.

## Environment and organizations

- Date: 2026-09-15
- Operator: KK Mookhey / Codex
- Existing Organization: `alternatetransilience` (`org_3E0bPUIqv5jGEGelUVHXnh9iQno`)
- Existing Denali tenant: `3cf9aef8-17fe-4d57-a878-c0af70adf1db`
- Isolation Organization: `Denali P0 Isolation 2026-09-15`
  (`org_3JNkiqJzjZ6UAJ6lvY98hc1erFj`)
- Isolation Organization slug: `denali-p0-isolation-20260915`
- Isolation Denali tenant: `0b12afe7-5024-4119-a73d-b8beb901af53`
- User role in both organizations: `org:admin`

## Completed evidence

- [x] The production Clerk backend reported that the current user initially belonged only to the
      existing Organization.
- [x] Created the bounded isolation Organization with a maximum of three memberships and recorded
      its P0-only purpose in private metadata.
- [x] Added the current user as `org:admin` without creating a new user or password.
- [x] Production had no `DENALI_CLERK_ORGANIZATIONS` allowlist, so no secret or redeployment change
      was needed for the new Organization.
- [x] The live Denali organization switcher displayed both Organizations.
- [x] Switching to the isolation Organization completed authenticated tenant resolution and
      showed zero connections without exposing the existing Organization's nine connections.
- [x] Opening the known AgentCore connection UUID from the isolation Organization normalized back
      to the zero-connection list; no connection detail or lifecycle mutation control was exposed.
- [x] Created `P0 Isolation Tenant AWS` (`c9230a92-e1bf-4289-8cfd-1abf248569a4`) in the isolation
      Organization, limited to AgentCore inventory and metadata-only runtime activity in
      `ap-south-1`.
- [x] Corrected the exact per-connection external-ID trust grant without printing or retaining the
      value outside the customer role policy and Denali connection record.
- [x] Hosted validation passed runtime, gateway, workload-identity, memory, and runtime-span
      planes for the exact account and selected Region.
- [x] The automatically queued durable collection finished complete with no partial or failed
      Region and retained two externally verified AgentCore inventory resources.
- [x] After switching back to the existing Organization, opening the isolation connection UUID
      normalized to an authorized existing-Organization connection and exposed none of the
      isolation connection's detail or controls.
- [x] Switching between the two now non-empty Organizations preserved distinct connection and
      inventory views.

## Follow-up evidence — 2026-09-17

- [x] Identified that the new Google SSO session belonged to a newer Clerk user record, while the
      evidence Organizations retained the prior user's memberships.
- [x] Added the current Clerk user as `org:admin` to both evidence Organizations without creating
      a password or changing either tenant mapping.
- [x] Repeated hosted switching with non-empty evidence: `alternatetransilience` exposed its nine
      connections and the isolation Organization exposed only `P0 Isolation Tenant AWS`.
- [x] Temporarily changed the current isolation membership to `org:member`. Read access to its one
      connection remained, the read-only banner appeared, connection creation disappeared, and
      lifecycle controls were non-interactive.
- [x] Restored the current isolation membership to `org:admin` and verified that creation controls
      returned.
- [x] A backend-minted Clerk token reflected the temporary `member` role. It did not contain the
      browser-issued `azp` claim, so Denali correctly rejected it before the direct API matrix.
      Clerk also rejected backend session creation in its production instance. Authorized-party
      verification was not weakened to make the probe pass.

## Remaining acceptance steps

- [ ] Record direct authenticated API `404` outcomes for cross-Organization detail and mutation
      attempts in both directions; the hosted UI read-isolation checks above passed.
- [ ] Exercise browser-token direct API `403` setup, validation, collection, disable, and delete
      outcomes in both Organizations when a supported harness can obtain a browser-issued token
      without exposing it.
- [x] Repeat the non-empty switching and read-only UI test using an `org:member` session.

The temporary role change was explicitly authorized, restricted to the current isolation
membership, and restored. The production account now has both the prior and current Clerk user
memberships; this is intentional until the older identity is reviewed separately and must not be
silently deleted as part of this acceptance.

## Result

- Real Clerk Organizations and admin switching: passed
- Empty-side cross-tenant read isolation: passed
- Non-empty two-Organization read isolation: passed
- Hosted `org:member` read-only UI: passed
- Cross-tenant browser-token direct API mutation matrix: pending supported harness
