# Entra AI application discovery preview

The first live Microsoft slice answers three narrow questions with attributable
evidence:

1. Which catalog-matched AI SaaS applications have enterprise service principals in
   this Entra tenant?
2. What delegated OAuth grants or application permissions are attached to them?
3. Which of those applications appear in recent Entra sign-in or directory-audit
   activity?

The preview intentionally does **not** claim that a catalog-matched application trains
on customer input, is sanctioned, or is dangerous. Those require independent policy,
contract, configuration, or human-governance evidence.

## Running a live scan

The scanner reads its secret from the process environment and never accepts it on the
command line:

```bash
export DENALI_ENTRA_TENANT_ID="..."
export DENALI_ENTRA_CLIENT_ID="..."
export DENALI_ENTRA_CLIENT_SECRET="..."
denali-entra-scan --lookback-hours 168
```

For compatibility with the existing Shasta test environment, `ENTRA_TENANT_ID`,
`ENTRA_CLIENT_ID`, and `ENTRA_CLIENT_SECRET` are also recognized.

The application needs Microsoft Graph application permissions sufficient to read
service principals, OAuth grants, app-role assignments, sign-ins, and directory audit
logs. Missing permission or licensing is reported in Sources & coverage.
