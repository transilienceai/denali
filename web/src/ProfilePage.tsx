import {
  OrganizationSwitcher,
  useClerk,
  useOrganization,
  useSession,
  useUser,
} from "@clerk/react";
import type {
  OrganizationInvitationResource,
  OrganizationMembershipResource,
  SessionWithActivitiesResource,
} from "@clerk/react/types";
import {
  Building2,
  Camera,
  Check,
  Clock3,
  Copy,
  FileUp,
  KeyRound,
  LoaderCircle,
  LogOut,
  Mail,
  MonitorSmartphone,
  Save,
  ShieldCheck,
  Trash2,
  UserPlus,
  UserRound,
  Users,
} from "lucide-react";
import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type FormEvent,
} from "react";
import { api, type OrganizationRole } from "./api";
import { MAX_BULK_INVITES, parseBulkEmails } from "./profileMembers";

type ProfileSection = "account" | "organization" | "members";
type Notice = { kind: "success" | "error"; message: string };

const MAX_IMAGE_BYTES = 10 * 1024 * 1024;

function errorMessage(error: unknown, fallback: string) {
  if (typeof error === "object" && error !== null && "errors" in error) {
    const errors = (error as { errors?: Array<{ longMessage?: string; message?: string }> }).errors;
    const message = errors?.[0]?.longMessage ?? errors?.[0]?.message;
    if (message) return message;
  }
  return error instanceof Error ? error.message : fallback;
}

function cleanRole(role: string | null | undefined) {
  return (role ?? "org:member").replace(/^org:/, "");
}

function displayName(member: OrganizationMembershipResource) {
  const firstName = member.publicUserData?.firstName?.trim();
  const lastName = member.publicUserData?.lastName?.trim();
  return [firstName, lastName].filter(Boolean).join(" ") || member.publicUserData?.identifier || "Member";
}

function initials(firstName?: string | null, lastName?: string | null, fallback = "U") {
  const value = [firstName, lastName]
    .filter(Boolean)
    .map((part) => part!.trim().charAt(0))
    .join("");
  return (value || fallback.charAt(0) || "U").toUpperCase();
}

export default function ProfilePage() {
  const { user, isLoaded: userLoaded } = useUser();
  const { session } = useSession();
  const { signOut } = useClerk();
  const {
    organization,
    membership,
    memberships,
    invitations,
    isLoaded: organizationLoaded,
  } = useOrganization({
    memberships: { pageSize: 50, infinite: true, keepPreviousData: true },
    invitations: {
      pageSize: 50,
      infinite: true,
      keepPreviousData: true,
      status: ["pending"],
    },
  });

  const [section, setSection] = useState<ProfileSection>("account");
  const [notice, setNotice] = useState<Notice | null>(null);

  const isAdmin = cleanRole(membership?.role) === "admin";

  if (!userLoaded || !organizationLoaded || !user) {
    return (
      <div className="profile-loading">
        <LoaderCircle className="spin" />
        <span>Loading your workspace profile…</span>
      </div>
    );
  }

  return (
    <div className="profile-page page-stack">
      <section className="profile-hero">
        <div className="profile-hero-identity">
          <ProfileAvatar
            imageUrl={user.imageUrl}
            firstName={user.firstName}
            lastName={user.lastName}
            fallback={user.primaryEmailAddress?.emailAddress ?? "User"}
          />
          <div>
            <span className="eyebrow">IDENTITY & ACCESS</span>
            <h2>{user.fullName || user.firstName || "Your profile"}</h2>
            <p>
              Manage your Denali identity, workspace settings, and organization members without
              leaving the product.
            </p>
          </div>
        </div>
        <div className="profile-hero-context">
          <span>Active organization</span>
          <OrganizationSwitcher hidePersonal organizationProfileMode="navigation" organizationProfileUrl="/profile" />
        </div>
      </section>

      <nav className="profile-tabs" aria-label="Profile sections" role="tablist">
        <ProfileTab
          active={section === "account"}
          icon={UserRound}
          label="Account"
          onClick={() => setSection("account")}
        />
        <ProfileTab
          active={section === "organization"}
          icon={Building2}
          label="Organization"
          onClick={() => setSection("organization")}
        />
        <ProfileTab
          active={section === "members"}
          icon={Users}
          label="Members"
          onClick={() => setSection("members")}
        />
      </nav>

      {notice && (
        <div className={`profile-notice ${notice.kind}`} role={notice.kind === "error" ? "alert" : "status"}>
          {notice.kind === "success" ? <Check /> : <ShieldCheck />}
          <span>{notice.message}</span>
          <button aria-label="Dismiss message" onClick={() => setNotice(null)}>×</button>
        </div>
      )}

      {section === "account" ? (
        <AccountSection user={user} currentSessionId={session?.id} onNotice={setNotice} onSignOut={signOut} />
      ) : section === "organization" ? (
        <OrganizationSection organization={organization} role={membership?.role} isAdmin={isAdmin} onNotice={setNotice} />
      ) : (
        <MembersSection
          organization={organization}
          currentUserId={user.id}
          isAdmin={isAdmin}
          memberships={memberships}
          invitations={invitations}
          onNotice={setNotice}
        />
      )}
    </div>
  );
}

function ProfileTab({
  active,
  icon: Icon,
  label,
  onClick,
}: {
  active: boolean;
  icon: typeof UserRound;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      className={active ? "active" : ""}
      onClick={onClick}
    >
      <Icon />
      {label}
    </button>
  );
}

function ProfileAvatar({
  imageUrl,
  firstName,
  lastName,
  fallback,
  size = "large",
}: {
  imageUrl?: string;
  firstName?: string | null;
  lastName?: string | null;
  fallback: string;
  size?: "small" | "large";
}) {
  return imageUrl ? (
    <img className={`profile-avatar ${size}`} src={imageUrl} alt="" />
  ) : (
    <span className={`profile-avatar ${size} fallback`} aria-hidden="true">
      {initials(firstName, lastName, fallback)}
    </span>
  );
}

type UserResource = NonNullable<ReturnType<typeof useUser>["user"]>;
type SignOut = ReturnType<typeof useClerk>["signOut"];

function AccountSection({
  user,
  currentSessionId,
  onNotice,
  onSignOut,
}: {
  user: UserResource;
  currentSessionId?: string;
  onNotice: (notice: Notice) => void;
  onSignOut: SignOut;
}) {
  const [firstName, setFirstName] = useState(user.firstName ?? "");
  const [lastName, setLastName] = useState(user.lastName ?? "");
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [changingPassword, setChangingPassword] = useState(false);
  const [sessions, setSessions] = useState<SessionWithActivitiesResource[]>([]);
  const [loadingSessions, setLoadingSessions] = useState(true);
  const [revokingSession, setRevokingSession] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setFirstName(user.firstName ?? "");
    setLastName(user.lastName ?? "");
  }, [user.firstName, user.lastName]);

  useEffect(() => {
    let cancelled = false;
    setLoadingSessions(true);
    void user.getSessions()
      .then((result) => {
        if (!cancelled) setSessions(result);
      })
      .catch((error) => {
        if (!cancelled) onNotice({ kind: "error", message: errorMessage(error, "Unable to load sessions") });
      })
      .finally(() => {
        if (!cancelled) setLoadingSessions(false);
      });
    return () => {
      cancelled = true;
    };
  }, [user.id]);

  async function saveProfile(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await user.update({ firstName: firstName.trim(), lastName: lastName.trim() });
      onNotice({ kind: "success", message: "Profile details updated." });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to update profile") });
    } finally {
      setSaving(false);
    }
  }

  async function uploadImage(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (!file.type.startsWith("image/") || file.size > MAX_IMAGE_BYTES) {
      onNotice({ kind: "error", message: "Choose an image smaller than 10 MB." });
      return;
    }
    setUploading(true);
    try {
      await user.setProfileImage({ file });
      onNotice({ kind: "success", message: "Profile photo updated." });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to update profile photo") });
    } finally {
      setUploading(false);
    }
  }

  async function updatePassword(event: FormEvent) {
    event.preventDefault();
    if (newPassword.length < 8) {
      onNotice({ kind: "error", message: "The new password must contain at least 8 characters." });
      return;
    }
    if (newPassword !== confirmPassword) {
      onNotice({ kind: "error", message: "The new passwords do not match." });
      return;
    }
    setChangingPassword(true);
    try {
      await user.updatePassword({ currentPassword: currentPassword || undefined, newPassword });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      onNotice({ kind: "success", message: "Password updated." });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to update password") });
    } finally {
      setChangingPassword(false);
    }
  }

  async function revokeSession(target: SessionWithActivitiesResource) {
    setRevokingSession(target.id);
    try {
      await target.revoke();
      setSessions((current) => current.filter((item) => item.id !== target.id));
      onNotice({ kind: "success", message: "Session revoked." });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to revoke session") });
    } finally {
      setRevokingSession(null);
    }
  }

  return (
    <div className="profile-section-grid" role="tabpanel">
      <section className="profile-card profile-account-card">
        <header>
          <div><span>Personal details</span><h3>Account information</h3></div>
          <UserRound />
        </header>
        <div className="profile-photo-row">
          <div className="profile-photo-control">
            <ProfileAvatar
              imageUrl={user.imageUrl}
              firstName={user.firstName}
              lastName={user.lastName}
              fallback={user.primaryEmailAddress?.emailAddress ?? "User"}
            />
            <button type="button" aria-label="Upload profile photo" onClick={() => fileInput.current?.click()} disabled={uploading}>
              {uploading ? <LoaderCircle className="spin" /> : <Camera />}
            </button>
            <input ref={fileInput} type="file" accept="image/*" onChange={uploadImage} hidden />
          </div>
          <div><strong>Profile photo</strong><span>PNG, JPG, GIF, or WebP up to 10 MB.</span></div>
        </div>
        <form className="profile-form" onSubmit={saveProfile}>
          <div className="profile-form-grid">
            <label><span>First name</span><input value={firstName} onChange={(event) => setFirstName(event.target.value)} autoComplete="given-name" /></label>
            <label><span>Last name</span><input value={lastName} onChange={(event) => setLastName(event.target.value)} autoComplete="family-name" /></label>
          </div>
          <label><span>Email address</span><div className="profile-readonly-field"><Mail />{user.primaryEmailAddress?.emailAddress ?? "No primary email"}</div></label>
          <div className="profile-form-actions"><button className="primary-action" disabled={saving}><Save />{saving ? "Saving…" : "Save profile"}</button></div>
        </form>
      </section>

      <section className="profile-card">
        <header>
          <div><span>Credential security</span><h3>Change password</h3></div>
          <KeyRound />
        </header>
        <form className="profile-form" onSubmit={updatePassword}>
          <label><span>Current password</span><input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} autoComplete="current-password" /></label>
          <label><span>New password</span><input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} autoComplete="new-password" /></label>
          <label><span>Confirm new password</span><input type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} autoComplete="new-password" /></label>
          <div className="profile-form-actions"><button className="secondary-action profile-inline-action" disabled={changingPassword}>{changingPassword ? "Updating…" : "Update password"}</button></div>
        </form>
      </section>

      <section className="profile-card profile-wide-card">
        <header>
          <div><span>Signed-in devices</span><h3>Active sessions</h3></div>
          <MonitorSmartphone />
        </header>
        {loadingSessions ? (
          <div className="profile-inline-loading"><LoaderCircle className="spin" /> Loading sessions…</div>
        ) : sessions.length === 0 ? (
          <div className="profile-empty">No active sessions were returned by Clerk.</div>
        ) : (
          <div className="profile-row-list">
            {sessions.map((item) => {
              const activity = item.latestActivity;
              const isCurrent = item.id === currentSessionId;
              return (
                <div className="profile-data-row" key={item.id}>
                  <span className="profile-row-icon"><MonitorSmartphone /></span>
                  <div className="profile-row-copy">
                    <strong>{activity.browserName || "Browser"} · {activity.deviceType || "Unknown device"}</strong>
                    <span>{[activity.city, activity.country, activity.ipAddress].filter(Boolean).join(" · ") || "Location unavailable"}</span>
                  </div>
                  <div className="profile-row-meta"><Clock3 />{item.lastActiveAt.toLocaleString()}</div>
                  {isCurrent ? <span className="profile-role admin">Current</span> : (
                    <button className="profile-row-action danger" disabled={revokingSession === item.id} onClick={() => void revokeSession(item)}>
                      {revokingSession === item.id ? "Revoking…" : "Revoke"}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
        <div className="profile-signout-row">
          <div><strong>Finished working?</strong><span>Sign out of the current Denali session.</span></div>
          <button className="profile-row-action" onClick={() => void onSignOut({ redirectUrl: "/" })}><LogOut /> Sign out</button>
        </div>
      </section>
    </div>
  );
}

type OrganizationResource = NonNullable<ReturnType<typeof useOrganization>["organization"]>;

function OrganizationSection({
  organization,
  role,
  isAdmin,
  onNotice,
}: {
  organization: OrganizationResource | null;
  role?: string | null;
  isAdmin: boolean;
  onNotice: (notice: Notice) => void;
}) {
  const [name, setName] = useState(organization?.name ?? "");
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const logoInput = useRef<HTMLInputElement>(null);

  useEffect(() => setName(organization?.name ?? ""), [organization?.id, organization?.name]);

  if (!organization) return <NoOrganization />;

  async function saveOrganization(event: FormEvent) {
    event.preventDefault();
    const nextName = name.trim();
    if (!nextName) {
      onNotice({ kind: "error", message: "Organization name is required." });
      return;
    }
    setSaving(true);
    try {
      await organization!.update({ name: nextName });
      onNotice({ kind: "success", message: "Organization details updated." });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to update organization") });
    } finally {
      setSaving(false);
    }
  }

  async function uploadLogo(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (!file.type.startsWith("image/") || file.size > MAX_IMAGE_BYTES) {
      onNotice({ kind: "error", message: "Choose an image smaller than 10 MB." });
      return;
    }
    setUploading(true);
    try {
      await organization!.setLogo({ file });
      onNotice({ kind: "success", message: "Organization logo updated." });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to update organization logo") });
    } finally {
      setUploading(false);
    }
  }

  return (
    <div className="profile-section-grid" role="tabpanel">
      <section className="profile-card profile-wide-card organization-identity-card">
        <div className="organization-identity">
          <ProfileAvatar imageUrl={organization.imageUrl} fallback={organization.name} />
          <div><span>Current organization</span><h3>{organization.name}</h3><p>{organization.slug || "No organization slug"}</p></div>
        </div>
        <div className="organization-switcher-block"><span>Switch workspace</span><OrganizationSwitcher hidePersonal organizationProfileMode="navigation" organizationProfileUrl="/profile" /></div>
      </section>

      <section className="profile-stat-grid profile-wide-card">
        <ProfileStat label="Members" value={String(organization.membersCount)} icon={Users} />
        <ProfileStat label="Your role" value={cleanRole(role)} icon={ShieldCheck} />
        <ProfileStat label="Pending invites" value={String(organization.pendingInvitationsCount)} icon={Mail} />
        <ProfileStat label="Created" value={organization.createdAt.toLocaleDateString()} icon={Clock3} />
      </section>

      <section className="profile-card profile-wide-card">
        <header><div><span>Workspace identity</span><h3>Organization details</h3></div><Building2 /></header>
        {!isAdmin && <div className="profile-permission-note"><ShieldCheck />Only organization admins can edit these details.</div>}
        <div className="organization-editor">
          <div className="profile-photo-row">
            <div className="profile-photo-control">
              <ProfileAvatar imageUrl={organization.imageUrl} fallback={organization.name} />
              {isAdmin && <button type="button" aria-label="Upload organization logo" onClick={() => logoInput.current?.click()} disabled={uploading}>{uploading ? <LoaderCircle className="spin" /> : <Camera />}</button>}
              <input ref={logoInput} type="file" accept="image/*" onChange={uploadLogo} hidden />
            </div>
            <div><strong>Organization logo</strong><span>Shown in workspace selectors and invitations.</span></div>
          </div>
          <form className="profile-form" onSubmit={saveOrganization}>
            <label><span>Organization name</span><input value={name} onChange={(event) => setName(event.target.value)} disabled={!isAdmin} /></label>
            <label><span>Clerk organization ID</span><div className="profile-readonly-field mono">{organization.id}</div></label>
            <div className="profile-form-actions"><button className="primary-action" disabled={!isAdmin || saving}><Save />{saving ? "Saving…" : "Save organization"}</button></div>
          </form>
        </div>
      </section>
    </div>
  );
}

function ProfileStat({ label, value, icon: Icon }: { label: string; value: string; icon: typeof Users }) {
  return <div className="profile-stat"><span><Icon /></span><div><small>{label}</small><strong>{value}</strong></div></div>;
}

function NoOrganization() {
  return (
    <section className="profile-card profile-empty-organization" role="tabpanel">
      <Building2 />
      <h3>Select an organization</h3>
      <p>Denali requires an active Clerk organization before workspace settings can be managed.</p>
      <OrganizationSwitcher hidePersonal organizationProfileMode="navigation" organizationProfileUrl="/profile" />
    </section>
  );
}

type PaginatedCollection<T> = {
  data?: T[];
  isLoading?: boolean;
  isFetching?: boolean;
  hasNextPage?: boolean;
  fetchNext?: () => void;
  revalidate?: () => Promise<void>;
};
type PaginatedMembers = PaginatedCollection<OrganizationMembershipResource>;
type PaginatedInvitations = PaginatedCollection<OrganizationInvitationResource>;
type MemberAccessMode = "invite" | "bulk" | "create";

function MembersSection({
  organization,
  currentUserId,
  isAdmin,
  memberships,
  invitations,
  onNotice,
}: {
  organization: OrganizationResource | null;
  currentUserId: string;
  isAdmin: boolean;
  memberships: PaginatedMembers | null;
  invitations: PaginatedInvitations | null;
  onNotice: (notice: Notice) => void;
}) {
  const [email, setEmail] = useState("");
  const [accessMode, setAccessMode] = useState<MemberAccessMode>("invite");
  const [inviteRole, setInviteRole] = useState<OrganizationRole>("org:member");
  const [bulkEmails, setBulkEmails] = useState("");
  const [createEmail, setCreateEmail] = useState("");
  const [createFirstName, setCreateFirstName] = useState("");
  const [createLastName, setCreateLastName] = useState("");
  const [createPassword, setCreatePassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submittingAccess, setSubmittingAccess] = useState(false);
  const [createdCredentials, setCreatedCredentials] = useState<{
    email: string;
    password: string;
    userId: string;
  } | null>(null);
  const [memberAction, setMemberAction] = useState<string | null>(null);
  const [invitationAction, setInvitationAction] = useState<string | null>(null);

  if (!organization) return <NoOrganization />;

  async function invite(event: FormEvent) {
    event.preventDefault();
    if (!isAdmin) return;
    const targetEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(targetEmail)) {
      onNotice({ kind: "error", message: "Enter a valid email address." });
      return;
    }
    setSubmittingAccess(true);
    try {
      const result = await api.inviteOrganizationMembers([targetEmail], inviteRole);
      if (result.failed) throw new Error(result.results[0]?.error ?? "Clerk rejected the invitation");
      setEmail("");
      await invitations?.revalidate?.();
      onNotice({ kind: "success", message: `Invitation sent to ${targetEmail}.` });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to send invitation") });
    } finally {
      setSubmittingAccess(false);
    }
  }

  async function inviteBulk(event: FormEvent) {
    event.preventDefault();
    if (!isAdmin) return;
    const parsed = parseBulkEmails(bulkEmails);
    if (parsed.invalid.length) {
      onNotice({
        kind: "error",
        message: `Remove ${parsed.invalid.length} invalid email address${parsed.invalid.length === 1 ? "" : "es"}.`,
      });
      return;
    }
    if (!parsed.emails.length) {
      onNotice({ kind: "error", message: "Add at least one email address." });
      return;
    }
    if (parsed.emails.length > MAX_BULK_INVITES) {
      onNotice({ kind: "error", message: `Send no more than ${MAX_BULK_INVITES} invitations at once.` });
      return;
    }
    setSubmittingAccess(true);
    try {
      const result = await api.inviteOrganizationMembers(parsed.emails, inviteRole);
      if (result.sent) {
        setBulkEmails(result.failed ? result.results.filter((item) => item.status === "failed").map((item) => item.email).join("\n") : "");
        await invitations?.revalidate?.();
      }
      onNotice({
        kind: result.failed ? "error" : "success",
        message: result.failed
          ? `${result.sent} invitation${result.sent === 1 ? "" : "s"} sent; ${result.failed} failed and remain in the list.`
          : `${result.sent} invitation${result.sent === 1 ? "" : "s"} sent.`,
      });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to send invitations") });
    } finally {
      setSubmittingAccess(false);
    }
  }

  async function createUser(event: FormEvent) {
    event.preventDefault();
    if (!isAdmin) return;
    const targetEmail = createEmail.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(targetEmail)) {
      onNotice({ kind: "error", message: "Enter a valid email address." });
      return;
    }
    if (createPassword.length < 8) {
      onNotice({ kind: "error", message: "The password must contain at least 8 characters." });
      return;
    }
    if (createPassword !== confirmPassword) {
      onNotice({ kind: "error", message: "The passwords do not match." });
      return;
    }
    setSubmittingAccess(true);
    const passwordForClerk = createPassword;
    try {
      const result = await api.createOrganizationUser({
        email: targetEmail,
        password: passwordForClerk,
        first_name: createFirstName.trim() || undefined,
        last_name: createLastName.trim() || undefined,
        role: inviteRole,
      });
      setCreatedCredentials({
        email: result.email,
        password: passwordForClerk,
        userId: result.user_id,
      });
      setCreateEmail("");
      setCreateFirstName("");
      setCreateLastName("");
      setCreatePassword("");
      setConfirmPassword("");
      await memberships?.revalidate?.();
      onNotice({ kind: "success", message: `${result.email} was created and added to the organization.` });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to create user") });
    } finally {
      setSubmittingAccess(false);
    }
  }

  function changeAccessMode(mode: MemberAccessMode) {
    setAccessMode(mode);
    setCreatedCredentials(null);
    setCreatePassword("");
    setConfirmPassword("");
  }

  async function loadBulkFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > 256 * 1024) {
      onNotice({ kind: "error", message: "Use a CSV or text file smaller than 256 KB." });
      return;
    }
    setBulkEmails(await file.text());
  }

  async function copyCredentials() {
    if (!createdCredentials) return;
    try {
      await navigator.clipboard.writeText(
        `Email: ${createdCredentials.email}\nPassword: ${createdCredentials.password}\nClerk user ID: ${createdCredentials.userId}`,
      );
      onNotice({ kind: "success", message: "Credentials copied. Share them through a secure channel." });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to copy credentials") });
    }
  }

  async function updateRole(member: OrganizationMembershipResource, role: string) {
    const userId = member.publicUserData?.userId;
    if (!userId || userId === currentUserId) return;
    setMemberAction(member.id);
    try {
      await organization!.updateMember({ userId, role });
      await memberships?.revalidate?.();
      onNotice({ kind: "success", message: `${displayName(member)} is now ${cleanRole(role)}.` });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to update member role") });
    } finally {
      setMemberAction(null);
    }
  }

  async function removeMember(member: OrganizationMembershipResource) {
    const userId = member.publicUserData?.userId;
    if (!userId || userId === currentUserId) return;
    if (!window.confirm(`Remove ${displayName(member)} from ${organization!.name}?`)) return;
    setMemberAction(member.id);
    try {
      await organization!.removeMember(userId);
      await memberships?.revalidate?.();
      onNotice({ kind: "success", message: `${displayName(member)} was removed.` });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to remove member") });
    } finally {
      setMemberAction(null);
    }
  }

  async function revokeInvitation(invitation: OrganizationInvitationResource) {
    setInvitationAction(invitation.id);
    try {
      await invitation.revoke();
      await invitations?.revalidate?.();
      onNotice({ kind: "success", message: `Invitation to ${invitation.emailAddress} revoked.` });
    } catch (error) {
      onNotice({ kind: "error", message: errorMessage(error, "Unable to revoke invitation") });
    } finally {
      setInvitationAction(null);
    }
  }

  const members = memberships?.data ?? [];
  const pending = invitations?.data ?? [];

  return (
    <div className="profile-section-grid" role="tabpanel">
      <section className="profile-card profile-wide-card">
        <header><div><span>Workspace access</span><h3>Members</h3></div><Users /></header>
        {!isAdmin && <div className="profile-permission-note"><ShieldCheck />Member management is available to organization admins.</div>}
        {isAdmin && (
          <div className="profile-member-access">
            <div className="profile-access-tabs" role="tablist" aria-label="Add organization members">
              <button type="button" role="tab" aria-selected={accessMode === "invite"} className={accessMode === "invite" ? "active" : ""} onClick={() => changeAccessMode("invite")}><Mail />Invite one</button>
              <button type="button" role="tab" aria-selected={accessMode === "bulk"} className={accessMode === "bulk" ? "active" : ""} onClick={() => changeAccessMode("bulk")}><Users />Bulk invite</button>
              <button type="button" role="tab" aria-selected={accessMode === "create"} className={accessMode === "create" ? "active" : ""} onClick={() => changeAccessMode("create")}><UserPlus />Create user</button>
            </div>

            {accessMode === "invite" && (
              <form className="profile-invite-form" onSubmit={invite}>
                <label><span>Email address</span><input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="teammate@company.com" /></label>
                <RoleSelect value={inviteRole} onChange={setInviteRole} />
                <button className="primary-action" disabled={submittingAccess}><Mail />{submittingAccess ? "Sending…" : "Send invitation"}</button>
              </form>
            )}

            {accessMode === "bulk" && (
              <form className="profile-access-form" onSubmit={inviteBulk}>
                <label className="profile-field-wide"><span>Email addresses</span><textarea rows={5} value={bulkEmails} onChange={(event) => setBulkEmails(event.target.value)} placeholder={"one@company.com\ntwo@company.com\nthree@company.com"} /><small>Separate with lines, commas, or semicolons. Up to {MAX_BULK_INVITES} unique addresses.</small></label>
                <div className="profile-access-actions">
                  <RoleSelect value={inviteRole} onChange={setInviteRole} />
                  <label className="secondary-action profile-file-action"><FileUp />Import CSV or text<input type="file" accept=".csv,.txt,text/csv,text/plain" onChange={(event) => void loadBulkFile(event)} /></label>
                  <button className="primary-action" disabled={submittingAccess}><Mail />{submittingAccess ? "Sending…" : "Send invitations"}</button>
                </div>
              </form>
            )}

            {accessMode === "create" && (
              <form className="profile-access-form" onSubmit={createUser} autoComplete="off">
                <div className="profile-form-grid">
                  <label><span>Email address</span><input type="email" autoComplete="off" value={createEmail} onChange={(event) => setCreateEmail(event.target.value)} placeholder="new.user@company.com" /></label>
                  <RoleSelect value={inviteRole} onChange={setInviteRole} />
                  <label><span>First name</span><input value={createFirstName} onChange={(event) => setCreateFirstName(event.target.value)} /></label>
                  <label><span>Last name</span><input value={createLastName} onChange={(event) => setCreateLastName(event.target.value)} /></label>
                  <label><span>Initial password</span><input type="password" autoComplete="new-password" value={createPassword} onChange={(event) => setCreatePassword(event.target.value)} minLength={8} /></label>
                  <label><span>Confirm password</span><input type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} minLength={8} /></label>
                </div>
                <div className="profile-sensitive-note"><KeyRound /><span>Denali forwards this password to Clerk once and never stores it. Share it securely and ask the user to change it after signing in.</span></div>
                <button className="primary-action profile-create-user" disabled={submittingAccess}><UserPlus />{submittingAccess ? "Creating…" : "Create user"}</button>
              </form>
            )}

            {accessMode === "create" && createdCredentials && (
              <div className="profile-credential-result" role="status">
                <div><span>Credentials ready</span><strong>{createdCredentials.email}</strong><code>{createdCredentials.password}</code><small>Clerk ID: {createdCredentials.userId}</small></div>
                <button type="button" className="secondary-action" onClick={() => void copyCredentials()}><Copy />Copy credentials</button>
                <button type="button" className="profile-row-action" onClick={() => setCreatedCredentials(null)}>Clear</button>
              </div>
            )}
          </div>
        )}

        {memberships?.isLoading ? <div className="profile-inline-loading"><LoaderCircle className="spin" />Loading members…</div> : (
          <div className="profile-row-list">
            {members.map((member) => {
              const memberUserId = member.publicUserData?.userId;
              const isCurrentUser = memberUserId === currentUserId;
              const busy = memberAction === member.id;
              return (
                <div className="profile-data-row member" key={member.id}>
                  <ProfileAvatar
                    size="small"
                    imageUrl={member.publicUserData?.imageUrl}
                    firstName={member.publicUserData?.firstName}
                    lastName={member.publicUserData?.lastName}
                    fallback={member.publicUserData?.identifier ?? "Member"}
                  />
                  <div className="profile-row-copy"><strong>{displayName(member)}{isCurrentUser ? " (you)" : ""}</strong><span>{member.publicUserData?.identifier}</span></div>
                  {isAdmin && !isCurrentUser ? (
                    <select aria-label={`Role for ${displayName(member)}`} value={member.role} disabled={busy} onChange={(event) => void updateRole(member, event.target.value)}><option value="org:member">Member</option><option value="org:admin">Admin</option></select>
                  ) : <span className={`profile-role ${cleanRole(member.role)}`}>{cleanRole(member.role)}</span>}
                  {isAdmin && !isCurrentUser && <button className="profile-icon-action danger" aria-label={`Remove ${displayName(member)}`} disabled={busy} onClick={() => void removeMember(member)}>{busy ? <LoaderCircle className="spin" /> : <Trash2 />}</button>}
                </div>
              );
            })}
            {members.length === 0 && <div className="profile-empty">No members were returned by Clerk.</div>}
          </div>
        )}
        {memberships?.hasNextPage && <button className="profile-load-more" onClick={() => memberships.fetchNext?.()} disabled={memberships.isFetching}>Load more members</button>}
      </section>

      <section className="profile-card profile-wide-card">
        <header><div><span>Awaiting acceptance</span><h3>Pending invitations</h3></div><Mail /></header>
        {invitations?.isLoading ? <div className="profile-inline-loading"><LoaderCircle className="spin" />Loading invitations…</div> : (
          <div className="profile-row-list">
            {pending.map((invitation) => (
              <div className="profile-data-row" key={invitation.id}>
                <span className="profile-row-icon"><Mail /></span>
                <div className="profile-row-copy"><strong>{invitation.emailAddress}</strong><span>Invited {invitation.createdAt.toLocaleDateString()}</span></div>
                <span className={`profile-role ${cleanRole(invitation.role)}`}>{cleanRole(invitation.role)}</span>
                {isAdmin && <button className="profile-row-action danger" disabled={invitationAction === invitation.id} onClick={() => void revokeInvitation(invitation)}>{invitationAction === invitation.id ? "Revoking…" : "Revoke"}</button>}
              </div>
            ))}
            {pending.length === 0 && <div className="profile-empty">There are no pending invitations.</div>}
          </div>
        )}
        {invitations?.hasNextPage && <button className="profile-load-more" onClick={() => invitations.fetchNext?.()} disabled={invitations.isFetching}>Load more invitations</button>}
      </section>
    </div>
  );
}

function RoleSelect({
  value,
  onChange,
}: {
  value: OrganizationRole;
  onChange: (role: OrganizationRole) => void;
}) {
  return (
    <label>
      <span>Role</span>
      <select value={value} onChange={(event) => onChange(event.target.value as OrganizationRole)}>
        <option value="org:member">Member · read only</option>
        <option value="org:admin">Admin · can manage</option>
      </select>
    </label>
  );
}
