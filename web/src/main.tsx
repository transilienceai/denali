import {
  ClerkProvider,
  OrganizationSwitcher,
  Show,
  SignIn,
  UserButton,
  useAuth,
} from "@clerk/react";
import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { api, configureApiTokenProvider, type DenaliContext } from "./api";
import ProfilePage from "./ProfilePage";
import "./styles.css";

const publishableKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY?.trim();

function HostedDenali() {
  const { getToken, isLoaded, isSignedIn, orgId } = useAuth();
  const [context, setContext] = useState<DenaliContext | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    configureApiTokenProvider(() => getToken());
    return () => configureApiTokenProvider(async () => null);
  }, [getToken]);

  useEffect(() => {
    setContext(null);
    setError(null);
    if (!isLoaded || !isSignedIn || !orgId) return;
    void api.context()
      .then(setContext)
      .catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to authorize this workspace"));
  }, [isLoaded, isSignedIn, orgId]);

  if (!isLoaded) return <div className="auth-shell"><div className="auth-status">Loading Denali…</div></div>;
  if (!orgId) {
    return <div className="auth-shell"><div className="auth-card"><h1>Select a workspace</h1><p>Denali requires an active Clerk organization.</p><OrganizationSwitcher hidePersonal organizationProfileMode="navigation" organizationProfileUrl="/profile" /></div></div>;
  }
  if (error) return <div className="auth-shell"><div className="auth-card"><h1>Workspace unavailable</h1><p>{error}</p><OrganizationSwitcher hidePersonal organizationProfileMode="navigation" organizationProfileUrl="/profile" /><UserButton userProfileMode="navigation" userProfileUrl="/profile" /></div></div>;
  if (!context) return <div className="auth-shell"><div className="auth-status">Authorizing workspace…</div></div>;

  return <App
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

createRoot(document.getElementById("root")!).render(<StrictMode>{application}</StrictMode>);
