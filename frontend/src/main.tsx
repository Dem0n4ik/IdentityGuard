import { StrictMode, useEffect, useRef, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, RouterProvider, createRootRoute, createRoute, createRouter, lazyRouteComponent, useNavigate, useRouterState } from "@tanstack/react-router";
import { Activity, BellRing, Cloud, Database, Filter, GitFork, Network, Settings2, ShieldAlert, Timer, FolderOpen, Globe2, History, LayoutDashboard, ListFilter, Moon, Search, ShieldCheck, Sparkles, Sun, UserRound, Users, X } from "lucide-react";
import { IntlProvider } from "react-intl";
import { ApiError, api, data, setCsrf, setToken, type Overview } from "./api/client";
import { Failure, Skeleton } from "./design-system/primitives";
import { en, uk, useText } from "./i18n";
import { CasesPage, DetailPage, IdentitiesPage, IncidentsPage, NotFound, OverviewPage } from "./pages";
import { useFilters, filterSchema, Workspace, formatAccount, usePreferences, Preferences } from "./workspace";
import { AuditPage, HuntPage, SourcesPage } from "./records";
import { AwsIntegrationPage, ProfilePage } from "./settings";
import { AssistantPage } from "./assistant";
import { Access, canVisit, Login, roles } from "./access";
import { useWords } from "./words";
import "./theme.css";
import "./workspace-settings.css";
import "./operations.css";

const browserHasPreferences = localStorage.getItem("identityguard.preferences") !== null;

const nav = [
  { group: "operations", items: [
    { path: "/", label: "overview", icon: LayoutDashboard },
    { path: "/cases", label: "cases", icon: FolderOpen },
    { path: "/incidents", label: "incidents", icon: Activity },
  ] },
  { group: "identitiesGroup", items: [
    { path: "/identities", label: "identities", icon: Users },
    { path: "/cloud", label: "cloudConfig", icon: Cloud },
  ] },
  { group: "investigation", items: [
    { path: "/hunt", label: "hunt", icon: Search },
    { path: "/attack-paths", label: "attackPaths", icon: Network },
    { path: "/role-chains", label: "roleChains", icon: GitFork },
    { path: "/assistant", label: "assistant", icon: Sparkles },
  ] },
  { group: "riskGovernance", items: [
    { path: "/detections", label: "detections", icon: ShieldAlert },
    { path: "/suppressions", label: "suppressions", icon: Filter },
    { path: "/models", label: "riskModels", icon: Settings2 },
    { path: "/quality", label: "quality", icon: Activity },
    { path: "/sla", label: "sla", icon: Timer },
  ] },
  { group: "platform", items: [
    { path: "/sources", label: "sources", icon: Database },
    { path: "/integrations/aws", label: "awsIntegration", icon: Cloud },
    { path: "/integrations/notifications", label: "notificationIntegrations", icon: BellRing },
    { path: "/audit", label: "audit", icon: History },
  ] },
] as const;

function AppShell() {
  const t = useText();
  const words = useWords();
  const client = useQueryClient();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const { prefs, update } = usePreferences();
  const access = useQuery({ queryKey: ["access"], queryFn: () => data(api.GET("/api/v1/auth/status")), retry: false });
  const session = useQuery({
    queryKey: ["session"], enabled: access.data?.enabled === true, retry: false,
    queryFn: async () => {
      try {
        const result = await data(api.GET("/api/v1/auth/session"));
        setCsrf(result.csrf);
        return result;
      } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 401) throw error;
        setCsrf("");
        return null;
      }
    },
  });
  const role = session.data?.role;
  const scoped = !!session.data?.accounts?.length;
  const workspace = useQuery({
    queryKey: ["workspace"], enabled: access.isSuccess && (!access.data.enabled || !!role),
    queryFn: () => data(api.GET("/api/v1/overview")), retry: false,
  });
  const profile = useQuery({ queryKey: ["profile"], enabled: workspace.isSuccess && (!role || role === "admin"), queryFn: () => data(api.GET("/api/v1/profile")) });
  const hydrated = useRef(browserHasPreferences);
  useEffect(() => {
    if (!hydrated.current && profile.data) {
      hydrated.current = true;
      update({
        language: profile.data.language, theme: profile.data.theme,
        compact: profile.data.compact, localTime: profile.data.local_time,
      });
    }
  }, [profile.data, update]);
  const filters = useFilters();
  const navigate = useNavigate();
  const [token, setInput] = useState("");
  const [pattern, setPattern] = useState("");
  const dialog = useRef<HTMLDialogElement>(null);
  const accounts = Array.from(new Set(workspace.data?.identities.map((item) => item.account_id))).sort();

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        if (!dialog.current?.open) dialog.current?.showModal();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  function unlock(event: FormEvent) {
    event.preventDefault();
    setToken(token);
    setInput("");
    void workspace.refetch();
  }

  const [logoutFailed, setLogoutFailed] = useState(false);
  async function logout() {
    setLogoutFailed(false);
    try {
      await data(api.POST("/api/v1/auth/logout"));
      setCsrf("");
      client.clear();
      window.location.reload();
    } catch {
      setLogoutFailed(true);
    }
  }

  if (access.isPending || (access.data?.enabled && session.isPending)) return <Skeleton />;
  if (access.isError) return <Failure error={access.error} retry={() => void access.refetch()} />;
  if (session.isError) return <Failure error={session.error} retry={() => void session.refetch()} />;
  if (access.data?.enabled && (!role || workspace.error instanceof ApiError && workspace.error.status === 401)) {
    return <main id="main" className="workspace"><Login unlocked={async () => {
      client.removeQueries({ predicate: ({ queryKey }) => !["access", "session"].includes(String(queryKey[0])) });
      await session.refetch();
      await workspace.refetch();
    }} /></main>;
  }

  return <div className="shell">
    <a className="skip" href="#main">{t("work")}</a>
    <aside className="side">
      <Link className="brand" to="/" aria-label={t("home")}><span className="brand-icon"><ShieldCheck size={19} /></span><strong>IdentityGuard</strong></Link>
      <nav aria-label={t("nav")}>{nav.map(({ group, items }) => ({ group, items: items.filter(({ path }) => canVisit(role, path, scoped)) })).filter(({ items }) => items.length).map(({ group, items }) => <section key={group}>
        <div className="nav-group">{t(group)}</div>
        {items.map(({ path, label, icon: Icon }) => <Link key={path} to={path} search={{ account: filters.account, range: filters.range }}
          activeOptions={{ exact: path === "/" }} activeProps={{ className: "selected" }}><Icon size={16} strokeWidth={1.75} /><span>{t(label)}</span></Link>)}
      </section>)}</nav>
      <div className="side-footer"><span className="connected-dot" /><span>{t(workspace.data?.source === "aws" ? "live" : "local")}</span><small>v0.1</small></div>
    </aside>
    <div className="workspace">
      <header className="topbar">
        <div className="top-filters">
          <label className="scope"><Cloud size={16} aria-hidden="true" /><select aria-label={t("accounts")} value={filters.account ?? ""} onChange={(event) =>
            void navigate({ to: ".", search: () => ({ ...filters, account: event.target.value || undefined, cursor: undefined }) })}>
            <option value="">{t("allAccounts")}</option>
            {accounts.map((account) => <option key={account} value={account}>{formatAccount(account, workspace.data?.source ?? "demo")}</option>)}
          </select></label>
          <select aria-label={t("time")} value={filters.range ?? "7"} onChange={(event) =>
            void navigate({ to: ".", search: () => ({ ...filters, range: event.target.value as "7" | "30" | "all", cursor: undefined }) })}>
            <option value="7">{t("last7")}</option><option value="30">{t("last30")}</option><option value="all">{t("allTime")}</option>
          </select>
        </div>
        <div className="top-tools">
          <button className="search-button" onClick={() => dialog.current?.showModal()}><Search size={15} /><span>{t("search")}</span><kbd>Ctrl K</kbd></button>
          <button className="icon-button time-button" aria-label={(prefs.localTime ? "LOCAL" : "UTC") + " · " + t("utc")} onClick={() => update({ localTime: !prefs.localTime })}>{prefs.localTime ? "LOCAL" : "UTC"}</button>
          <button className="icon-button" aria-label={t("dense")} aria-pressed={prefs.compact} onClick={() => update({ compact: !prefs.compact })}><ListFilter size={16} /></button>
          <button className="icon-button" aria-label={t("theme")} onClick={() => update({ theme: prefs.theme === "dark" ? "light" : "dark" })}>{prefs.theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}</button>
          <button className="icon-button" aria-label={prefs.language.toUpperCase() + " · " + t("language")} onClick={() => update({ language: prefs.language === "uk" ? "en" : "uk" })}><Globe2 size={15} />{prefs.language.toUpperCase()}</button>
          {canVisit(role, "/profile", scoped) && <Link to="/profile" className="profile-button" activeProps={{ className: "selected" }} title={t("profile")}>
            <UserRound size={15} /><span>{profile.data?.name || t("profile")}</span>
          </Link>}
          {role === "admin" && <Link to="/admin/access" className="profile-button">{words("Доступ", "Access")}</Link>}
          {role && <button className="profile-button" type="button" onClick={() => void logout()}>
            {words(roles[role].uk, roles[role].en)} · {words("Вийти", "Sign out")}
          </button>}
          {logoutFailed && <span role="alert">{words("Не вдалося завершити сеанс.", "Could not sign out.")}</span>}
        </div>
      </header>
      <main id="main">
        {workspace.isPending ? <Skeleton /> : workspace.isError ? workspace.error instanceof ApiError && workspace.error.status === 401 ?
          <form className="unlock panel" onSubmit={unlock}><h1>{t("tokenTitle")}</h1>
            <label>{t("tokenLabel")}<input type="password" required value={token} onChange={(event) => setInput(event.target.value)} /></label>
            <button className="primary">{t("tokenButton")}</button>
          </form> : <Failure error={workspace.error} retry={() => void workspace.refetch()} /> :
          <Workspace.Provider value={workspace.data as Overview}>{canVisit(role, pathname.replace(/\/$/, "") || "/", scoped)
            ? <Access.Provider value={{ role, scoped }}><Outlet /></Access.Provider>
            : <section className="unlock panel"><h1>{words("Немає доступу", "Access denied")}</h1></section>}
          </Workspace.Provider>}
      </main>
    </div>
    <dialog ref={dialog} onClose={() => setPattern("")} aria-label={t("command")}>
      <div className="dialog-head"><strong>{t("command")}</strong><button className="icon-button" aria-label={t("close")} onClick={() => dialog.current?.close()}><X size={16} /></button></div>
      <input autoFocus aria-label={t("search")} value={pattern} onChange={(event) => setPattern(event.target.value)} placeholder={t("command")} />
      <div className="commands">
        {nav.map(({ group, items }) => <div key={group}>{items.filter(({ label }) => t(label).toLowerCase().includes(pattern.toLowerCase())).map(({ path, label }) =>
          <Link key={path} to={path} onClick={() => dialog.current?.close()}>{t(label)}</Link>)}</div>)}
        {pattern && workspace.data?.identities.filter((item) => item.name.toLowerCase().includes(pattern.toLowerCase())).slice(0, 10).map((item) =>
          <Link key={item.id} to="/identities/$id" params={{ id: item.id }} onClick={() => dialog.current?.close()}><code>{item.name}</code></Link>)}
      </div>
    </dialog>
  </div>;
}

const root = createRootRoute({ component: AppShell, validateSearch: filterSchema, notFoundComponent: NotFound });
const overview = createRoute({ getParentRoute: () => root, path: "/", component: OverviewPage });
const cases = createRoute({ getParentRoute: () => root, path: "/cases", component: CasesPage });
const caseDetail = createRoute({ getParentRoute: () => root, path: "/cases/$id", component: () => <DetailPage type="case" /> });
const incidents = createRoute({ getParentRoute: () => root, path: "/incidents", component: IncidentsPage });
const incidentDetail = createRoute({ getParentRoute: () => root, path: "/incidents/$id", component: () => <DetailPage type="incident" /> });
const identities = createRoute({ getParentRoute: () => root, path: "/identities", component: IdentitiesPage });
const identityDetail = createRoute({ getParentRoute: () => root, path: "/identities/$id", component: () => <DetailPage type="identity" /> });
const hunt = createRoute({ getParentRoute: () => root, path: "/hunt", component: HuntPage });
const sources = createRoute({ getParentRoute: () => root, path: "/sources", component: SourcesPage });
const audit = createRoute({ getParentRoute: () => root, path: "/audit", component: AuditPage });
const profile = createRoute({ getParentRoute: () => root, path: "/profile", component: ProfilePage });
const aws = createRoute({ getParentRoute: () => root, path: "/integrations/aws", component: AwsIntegrationPage });
const assistant = createRoute({ getParentRoute: () => root, path: "/assistant", component: AssistantPage });
const detections = createRoute({ getParentRoute: () => root, path: "/detections", component: lazyRouteComponent(() => import("./operations"), "DetectionsPage") });
const suppressions = createRoute({ getParentRoute: () => root, path: "/suppressions", component: lazyRouteComponent(() => import("./operations"), "SuppressionsPage") });
const models = createRoute({ getParentRoute: () => root, path: "/models", component: lazyRouteComponent(() => import("./governance"), "ModelsPage") });
const quality = createRoute({ getParentRoute: () => root, path: "/quality", component: lazyRouteComponent(() => import("./governance"), "QualityPage") });
const sla = createRoute({ getParentRoute: () => root, path: "/sla", component: lazyRouteComponent(() => import("./governance"), "SlaPage") });
const cloud = createRoute({ getParentRoute: () => root, path: "/cloud", component: lazyRouteComponent(() => import("./cloud-operations"), "CloudPage") });
const paths = createRoute({ getParentRoute: () => root, path: "/attack-paths", component: lazyRouteComponent(() => import("./cloud-operations"), "AttackPathsPage") });
const chains = createRoute({ getParentRoute: () => root, path: "/role-chains", component: lazyRouteComponent(() => import("./cloud-operations"), "RoleChainsPage") });
const notifications = createRoute({ getParentRoute: () => root, path: "/integrations/notifications", component: lazyRouteComponent(() => import("./notifications"), "NotificationsPage") });
const accessAdmin = createRoute({ getParentRoute: () => root, path: "/admin/access", component: lazyRouteComponent(() => import("./access-admin"), "AccessAdminPage") });
const router = createRouter({ routeTree: root.addChildren([accessAdmin, overview, cases, caseDetail, incidents, incidentDetail, identities, identityDetail, hunt, sources, audit, profile, aws, assistant, detections, suppressions, models, quality, sla, cloud, paths, chains, notifications]) });
declare module "@tanstack/react-router" { interface Register { router: typeof router } }

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 10000 } } });

function App() {
  const { prefs } = usePreferences();
  return <IntlProvider locale={prefs.language} messages={prefs.language === "uk" ? uk : en}>
    <QueryClientProvider client={queryClient}><RouterProvider router={router} /></QueryClientProvider>
  </IntlProvider>;
}

createRoot(document.getElementById("root")!).render(<StrictMode><Preferences.ProviderComponent><App /></Preferences.ProviderComponent></StrictMode>);
