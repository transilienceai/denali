export function githubConnectionPresentation(credentialType: string) {
  if (credentialType === "platform_shared_github") {
    return {
      shared: true,
      planTitle: "1. Shared Platform connection attached",
      planDetail: "Denali records a reference to the Platform-owned GitHub installation, its declared read planes and exact repository IDs. No App private key or provider token is stored in this reference.",
      setupTitle: "2. Platform installation verified",
      setupDetail: "Platform owns the GitHub App and verifies installation consent and the exact selected repositories. Denali reuses this organization’s verified shared connection.",
      setupHint: "Choose Manage access and selected resources to review GitHub consent and available repositories. An admin explicitly approves a replacement selection; this pinned connection stays unchanged.",
      validationDetail: "Denali requests a fresh, short-lived installation token from Platform for one recorded repository at a time, rechecks its immutable identity and tests each declared read plane independently.",
      notValidatedDetail: "Validate this shared connection to check every recorded repository and its declared read planes.",
      allRepositoriesDetail: "Platform’s installation is set to all repositories, but this Denali reference covers only the exact recorded list. Newly added repositories need an explicitly selected separate attachment; this pinned connection stays unchanged.",
      lifecycleDetail: "Disconnect from Denali stops this attachment’s validation and collection only. Deleting its disabled configuration preserves the Platform installation and collected evidence. Organization-wide access is managed separately and affects every consuming application.",
    };
  }
  return {
    shared: false,
    planTitle: "1. Connection plan created",
    planDetail: "Denali’s GitHub App, declared read planes, and an initially empty repository boundary are recorded. No personal access token is requested or stored.",
    setupTitle: "2. Install the App and select repositories",
    setupDetail: "GitHub shows the App’s exact read permissions and lets you choose repositories. After installation, Denali briefly verifies that the signed-in GitHub user can access that exact installation, records immutable repository IDs, and immediately discards the user token.",
    setupHint: "GitHub onboarding requires Denali’s configured GitHub App and private signing key.",
    validationDetail: "Denali mints a separate short-lived installation token for one recorded repository at a time, rebinds its immutable identity, and tests each declared read plane independently.",
    notValidatedDetail: "Install the GitHub App and finish repository selection first.",
    allRepositoriesDetail: "GitHub’s installation is set to all repositories, but Denali’s stored coverage remains this exact list. Newly created repositories are not claimed until you reconfigure and verify again.",
    lifecycleDetail: "Disabling prevents further validation. Deleting removes Denali’s connection configuration and validation history only; uninstall the GitHub App separately in GitHub. Previously collected evidence remains.",
  };
}
