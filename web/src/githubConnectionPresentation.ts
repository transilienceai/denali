export function githubConnectionPresentation(credentialType: string) {
  if (credentialType === "platform_shared_github") {
    return {
      shared: true,
      planTitle: "1. Shared Platform connection attached",
      planDetail: "Denali records a reference to the Platform-owned GitHub installation, its declared read planes and exact repository IDs. No App private key or provider token is stored in this reference.",
      setupTitle: "2. Platform installation verified",
      setupDetail: "Platform owns the GitHub App and verifies installation consent and the exact selected repositories. Denali reuses this organization’s verified shared connection.",
      setupHint: "Manage consent in the reusable GitHub section above. Selection changes never update this reference automatically; an admin must review an explicit local detach and re-attach.",
      validationDetail: "Denali requests a fresh, short-lived installation token from Platform for one recorded repository at a time, rechecks its immutable identity and tests each declared read plane independently.",
      notValidatedDetail: "Validate this shared connection to check every recorded repository and its declared read planes.",
      allRepositoriesDetail: "Platform’s installation is set to all repositories, but this Denali reference covers only the exact recorded list. Newly added repositories require a reviewed detach and re-attach; they are not included automatically.",
      lifecycleDetail: "Local Disable stops Denali validation and collection only. Local Delete removes this Denali reference and its validation/job history, while preserving the Platform installation and collected evidence. Disable for organization in the reusable GitHub section stops new shared leases for every consuming app.",
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
