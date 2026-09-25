# Shared GitHub dev pilot

Denali can attach a platform-owned GitHub installation without copying the GitHub App key, user OAuth token, or installation token into Denali. This path is additive: existing Denali GitHub App connections still work.

## Dev prerequisites

- Platform GitHub API deployed in the **dev** Modal environment with a separate Platform Dev GitHub App, callback URLs, and its private key in a dev-only Modal Secret. Do not reuse Denali's App key.
- The platform entitlement for the chosen Clerk organization grants Denali only the GitHub read scopes it needs: repository metadata, contents, and Actions workflows.
- Denali dev API and workers have `DENALI_PLATFORM_CONNECTIONS_ORIGIN` and `DENALI_PLATFORM_MACHINE_SECRET_KEY` configured, as for shared AWS. No new Denali-side GitHub secret is needed.

## End-to-end check

1. In Denali dev's Connections page, select **Connect GitHub** in the shared pilot section and open the returned GitHub setup link. Choose the intended repositories; complete the platform-owned OAuth confirmation. Return to Denali and refresh.
2. Confirm the shared installation shows `ready` and the expected repository count. Select **Use in Denali**. Denali retrieves the exact repository IDs and tests one scoped token lease without retaining it.
3. In the new Denali GitHub connection, run **Validate connection**. Each repository and declared read plane must report its own result. Run **Collect source & correlate** and check the source collection summary.
4. Verify cross-org access is denied by the platform. In a disposable dev-only installation, disable the shared connection and confirm subsequent Denali validation and collection cannot lease another token. Do not disable an active team pilot just to run this check.

The worker fetches a fresh server-side token from `/internal/v1/connections/github/{id}/token`, bound to the Clerk org, Denali app entitlement, selected installation, exact repository ID, and requested scopes. The broker rechecks the live GitHub installation on issuance. Denali's existing read-only validator and bounded source collector then use that token; the token is never serialized to the browser or stored in Denali's database.

Disabling the Denali connection affects Denali only. Disabling the shared connection stops new leases across entitled apps; previously issued short-lived tokens expire on their own. Production and customer installations are out of scope for this pilot.
