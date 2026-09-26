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

## Remaining acceptance steps

- [ ] Record direct authenticated API `404` outcomes for cross-Organization detail and mutation
      attempts in both directions; the hosted UI read-isolation checks above passed.
- [ ] Exercise `org:member` read access and `403` setup, validation, collection, disable, and delete
      outcomes in both Organizations.
- [ ] Repeat the non-empty switching test using an `org:member` session after the role matrix is
      available.

On 2026-09-17 the Clerk backend was checked for a non-administrator test identity before any
membership change was attempted. The isolation Organization has one membership and the existing
Organization has three; every membership is `org:admin`. There is therefore no existing real
`org:member` session with which to complete the role matrix. Completing this gate requires an
explicitly authorized temporary role change with guaranteed restoration, or a bounded test member
created through the normal invitation/user-provisioning path. No administrator access was changed
during this check.

## Result

- Real Clerk Organizations and admin switching: passed
- Empty-side cross-tenant read isolation: passed
- Non-empty two-Organization read isolation: passed
- Cross-tenant direct API mutation and member-role matrix: pending
