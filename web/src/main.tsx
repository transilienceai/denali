import {
  ClerkProvider,
  OrganizationSwitcher,
  Show,
  SignIn,
  UserButton,
  useAuth,
} from "@clerk/react";
import { Analytics } from "@vercel/analytics/react";
import posthog from "posthog-js";
import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { sanitizeAnalyticsEvent } from "./analytics";
import { api, configureApiTokenProvider, type DenaliContext } from "./api";
import ProfilePage from "./ProfilePage";
import { posthogConfig } from "./posthog";
import "./styles.css";
import { initializeTheme } from "./theme";

const publishableKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY?.trim();
initializeTheme();

const projectToken = import.meta.env.VITE_POSTHOG_PROJECT_TOKEN?.trim();
if (projectToken) {
  try {
    posthog.init(projectToken, {
      ...posthogConfig,
      api_host: import.meta.env.VITE_POSTHOG_HOST?.trim() || "https://us.i.posthog.com",
    });
  } catch {
    // Optional analytics must not prevent Denali from becoming interactive.
    console.warn("Product analytics could not initialize.");
  }
}

function HostedDenali() {
  const { getToken, isLoaded, isSignedIn, orgId } = useAuth();
  const [context, setContext] = useState<DenaliContext | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    configureApiTokenProvider(() => getToken());
    return () => configureApiTokenProvider(async () => null);
  }, [getToken, orgId]);

  useEffect(() => {
    setContext(null);
    setError(null);
    if (!isLoaded || !isSignedIn || !orgId) return;
    const controller = new AbortController();
    void api.context(controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        if (result.organization_id === orgId) setContext(result);
        else setError("Workspace authorization changed. Select the organization again to continue.");
      })
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Unable to authorize this workspace");
      });
    return () => controller.abort();
  }, [isLoaded, isSignedIn, orgId]);

  if (!isLoaded) return <div className="auth-shell"><div className="auth-status">Loading Denali…</div></div>;
  if (!orgId) {
    return <div className="auth-shell"><div className="auth-card"><h1>Select a workspace</h1><p>Denali requires an active Clerk organization.</p><OrganizationSwitcher hidePersonal organizationProfileMode="navigation" organizationProfileUrl="/profile" /></div></div>;
  }
  if (error) return <div className="auth-shell"><div className="auth-card"><h1>Workspace unavailable</h1><p>{error}</p><OrganizationSwitcher hidePersonal organizationProfileMode="navigation" organizationProfileUrl="/profile" /><UserButton userProfileMode="navigation" userProfileUrl="/profile" /></div></div>;
  if (!context || context.organization_id !== orgId) return <div className="auth-shell"><div className="auth-status">Authorizing workspace…</div></div>;

  return <App
    key={orgId}
    canWrite={context.can_write}
    accountControls={<>
      <div className="identity-control"><span>Workspace</span><OrganizationSwitcher hidePersonal organizationProfileMode="navigation" organizationProfileUrl="/profile" /></div>
      <div className="identity-control"><span>Account</span><UserButton userProfileMode="navigation" userProfileUrl="/profile" /></div>
    </>}
    profilePage={<ProfilePage />}
  />;
}

const application = publishableKey ? (
  <ClerkProvider publishableKey={publishableKey}>
    <Show when="signed-out"><div className="auth-shell"><SignIn /></div></Show>
    <Show when="signed-in"><HostedDenali /></Show>
  </ClerkProvider>
) : <App canWrite />;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {application}
    <Analytics beforeSend={sanitizeAnalyticsEvent} />
  </StrictMode>,
);
