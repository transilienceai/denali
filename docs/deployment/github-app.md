# GitHub App registration (`transilience-denali`)

Denali connects to customers' GitHub repositories through an organization-owned GitHub
App rather than anyone's personal login. Customers install the app on the repositories
they choose, and it receives only the read-only permissions the connector requires
(`src/denali/connections/github.py` enforces the same set at setup time). The API signs
GitHub App JWTs with the PEM private key. The client secret is used only for the brief,
PKCE-protected user OAuth exchange that verifies access to the selected installation;
the resulting user token is discarded.

The app was registered on 2026-08-30 at
`https://github.com/organizations/transilienceai/settings/apps/new` so it is owned by
the `transilienceai` organization, not an individual account.

## Registered values

| Setting | Value |
| --- | --- |
| Owner | `@transilienceai` |
| App name | Transilience Denali |
| App slug | `transilience-denali` |
| App ID | `4776431` |
| Public link | <https://github.com/apps/transilience-denali> |
| Production Homepage URL | `https://denali.transilience.cloud/` |
| Production Callback URL | `https://denali.transilience.cloud/api/v1/connections/github/oauth/callback` |
| Production Setup URL | `https://denali.transilience.cloud/api/v1/connections/github/setup/callback` |
| Webhooks | Disabled |
| Request user authorization (OAuth) during installation | Disabled |
| Device flow | Disabled |
| Repository permissions | Metadata: read-only, Contents: read-only, Actions: read-only |
| Installation target | Any account |

For local-only App registration, use the equivalent localhost routes. The production App must keep
the three hosted values above; the `/api` prefix is required by the Vercel same-origin rewrite.

## Screenshots

App identity and callback URL:

![App name, description, homepage, and callback URL](images/github-app/01-app-identity.png)

OAuth-during-installation disabled, setup URL, and webhook inactive:

![OAuth during installation disabled, setup URL, webhook inactive](images/github-app/02-oauth-and-webhook.png)

Repository permissions — Actions, Contents, and Metadata are read-only; everything else
is "No access":

![Actions read-only](images/github-app/03-permissions-actions.png)

![Contents read-only](images/github-app/04-permissions-contents.png)

![Metadata read-only (mandatory)](images/github-app/05-permissions-metadata.png)

Installable by any account, so customers can install it on their own organizations:

![Any account installation target](images/github-app/06-install-any-account.png)

Registration result with the App ID and Client ID:

![Created app with App ID and Client ID](images/github-app/07-app-created.png)

## Credentials

Both credentials were generated on 2026-08-30 on the app's settings page
(`https://github.com/organizations/transilienceai/settings/apps/transilience-denali`):

- **Client secret** — generated under **Client secrets**. Its value and suffix are
  intentionally not recorded in this repository. GitHub shows the full value only once,
  at generation time; production deployments should load it from a secret manager.
- **Private key** — generated under **Private keys**, fingerprint
  `SHA256:Ysxinmx5uaCNl4AMXI3teiUeYDZhuJDFpJlWKbVZ0uc=`. GitHub downloads the `.pem`
  file at generation time. Production deployments should store it in a secret manager
  and mount it read-only into the API container.

For local acceptance only, the ignored `.env` and ignored PEM host file are mode `0600`;
the key is mounted read-only and neither credential is stored in Denali's connection
database or container image.

Never commit either value. To rotate, generate a new secret/key on the same page, roll
the deployment, then delete the old one.

## API configuration

The API enables the GitHub connector only when all of these are set
(`_github_app_from_environment` in `src/denali/api/app.py`):

```bash
DENALI_GITHUB_APP_ID=4776431
DENALI_GITHUB_CLIENT_ID=Iv23livoDPdg3faSnjG2
DENALI_GITHUB_CLIENT_SECRET=REPLACE_ME
DENALI_GITHUB_APP_SLUG=transilience-denali
DENALI_GITHUB_PRIVATE_KEY_FILE=/path/to/transilience-denali.private-key.pem
# Optional; defaults to the local callback below.
DENALI_GITHUB_CALLBACK_URL=https://denali.transilience.cloud/api/v1/connections/github/oauth/callback
```

`DENALI_GITHUB_CALLBACK_URL` and the URL registered on the production App must stay in sync.
