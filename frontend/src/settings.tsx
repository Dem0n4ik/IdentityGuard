import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowUpRight, CheckCircle2, Cloud, LockKeyhole, RefreshCw } from "lucide-react";
import { api, data, type AwsSettings, type AwsWorkspace, type Profile } from "./api/client";
import { Failure, Panel, Skeleton } from "./design-system/primitives";
import { Page } from "./design-system/Page";
import { useText } from "./i18n";
import { DateTime, usePreferences } from "./workspace";

function ProfileForm({ profile }: { profile: Profile }) {
  const t = useText();
  const { prefs, update } = usePreferences();
  const client = useQueryClient();
  const [name, setName] = useState(profile.name ?? "");
  const [email, setEmail] = useState(profile.email ?? "");
  const [position, setPosition] = useState(profile.position ?? "");
  const [language, setLanguage] = useState(profile.language ?? prefs.language);
  const [theme, setTheme] = useState(profile.theme ?? prefs.theme);
  const [compact, setCompact] = useState(profile.compact ?? prefs.compact);
  const [localTime, setLocalTime] = useState(profile.local_time ?? prefs.localTime);
  const save = useMutation({
    mutationFn: () => data(api.PUT("/api/v1/profile", { body: {
      name, email, position, language, theme, compact, local_time: localTime,
    } })),
    onSuccess: (result) => {
      client.setQueryData(["profile"], result);
      update({ language, theme, compact, localTime });
    },
  });
  return <form onSubmit={(event) => { event.preventDefault(); save.mutate(); }} className="settings-layout">
    <Panel title={t("personalDetails")} subtitle={t("profileScope")}>
      <div className="settings-form">
        <label>{t("displayName")}<input autoComplete="name" value={name} maxLength={100} onChange={(event) => setName(event.target.value)} /></label>
        <label>{t("email")}<input type="email" autoComplete="email" value={email} maxLength={254} onChange={(event) => setEmail(event.target.value)} /></label>
        <label>{t("position")}<input autoComplete="organization-title" value={position} maxLength={100} onChange={(event) => setPosition(event.target.value)} /></label>
      </div>
    </Panel>
    <Panel title={t("appearance")}>
      <div className="settings-form">
        <label>{t("displayLanguage")}<select value={language} onChange={(event) => setLanguage(event.target.value === "en" ? "en" : "uk")}>
          <option value="uk">Українська</option><option value="en">English</option>
        </select></label>
        <label>{t("displayTheme")}<select value={theme} onChange={(event) => setTheme(event.target.value === "light" ? "light" : "dark")}>
          <option value="dark">{t("darkTheme")}</option><option value="light">{t("lightTheme")}</option>
        </select></label>
        <label className="checkbox"><input type="checkbox" checked={compact} onChange={(event) => setCompact(event.target.checked)} />{t("compactRows")}</label>
        <label className="checkbox"><input type="checkbox" checked={localTime} onChange={(event) => setLocalTime(event.target.checked)} />{t("useLocalTime")}</label>
      </div>
    </Panel>
    <div className="form-actions">
      <button className="primary" type="submit" disabled={save.isPending}>{t("save")}</button>
      {save.isSuccess && <span className="inline-status" role="status"><CheckCircle2 size={15} />{t("profileSaved")}</span>}
    </div>
    {save.isError && <Failure error={save.error} />}
  </form>;
}

export function ProfilePage() {
  const result = useQuery({ queryKey: ["profile"], queryFn: () => data(api.GET("/api/v1/profile")) });
  return <Page title="profile">{result.isPending ? <Skeleton /> : result.isError ?
    <Failure error={result.error} retry={() => void result.refetch()} /> : <ProfileForm profile={result.data} />}</Page>;
}

function AwsSetup() {
  const t = useText();
  return <>
    <Panel title={t("privateAws")} subtitle={t("privateAwsHint")}
      action={<a className="panel-link" href="http://127.0.0.1:8010/integrations/aws">{t("openAws")}<ArrowUpRight size={14} /></a>}>
      <ol className="integration-steps">
        <li><strong>{t("awsCredentials")}</strong><p>{t("awsCredentialsHint")}</p><code>aws configure sso --profile identityguard</code><code>aws sso login --profile identityguard</code></li>
        <li><strong>{t("startAws")}</strong><p>{t("startAwsHint")}</p><code>./scripts/start-aws-history.ps1</code></li>
        <li><strong>{t("verifyAndImport")}</strong><p>{t("verifyAndImportHint")}</p></li>
      </ol>
    </Panel>
    <div className="info-strip"><LockKeyhole size={16} />{t("awsSecretsHint")}</div>
  </>;
}

function Connection({ workspace, refresh }: { workspace: AwsWorkspace; refresh: () => void }) {
  const t = useText();
  const client = useQueryClient();
  const saved = workspace.last_import?.settings;
  const [account, setAccount] = useState(workspace.account_id ?? "");
  const [region, setRegion] = useState(saved?.region ?? "eu-central-1");
  const [profile, setProfile] = useState(saved?.profile && workspace.available_profiles.includes(saved.profile) ? saved.profile : workspace.available_profiles[0] ?? "");
  const [source, setSource] = useState<"profile" | "environment">(() =>
    workspace.environment_credentials && (saved?.credential_source === "environment" || !workspace.available_profiles.length) ? "environment" : "profile");
  const [days, setDays] = useState(21);
  const [includeIam, setIncludeIam] = useState(true);
  const [verified, setVerified] = useState("");
  const body: AwsSettings = { account_id: account, region: region.trim(), profile: source === "profile" ? profile : "", credential_source: source };
  const fingerprint = JSON.stringify(body);
  const valid = /^\d{12}$/.test(account) && /^[a-z]{2}(?:-[a-z]+)+-\d$/.test(body.region)
    && (source === "profile" ? !!profile : workspace.environment_credentials);
  const verify = useMutation({
    mutationFn: (settings: AwsSettings) => data(api.POST("/api/v1/integrations/aws/verify", { body: settings })),
    onMutate: () => setVerified(""),
    onSuccess: (_, settings) => setVerified(JSON.stringify(settings)),
  });
  const runImport = useMutation({
    mutationFn: () => data(api.POST("/api/v1/integrations/aws/import", { body: { ...body, days, include_iam: includeIam } })),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["aws-workspace"] });
      void client.invalidateQueries({ queryKey: ["workspace"] });
      void client.invalidateQueries({ queryKey: ["events"] });
      void client.invalidateQueries({ queryKey: ["audit"] });
    },
  });
  const busy = verify.isPending || runImport.isPending;
  const lastImport = runImport.data ?? workspace.last_import;
  function submit(event: FormEvent) {
    event.preventDefault();
    if (valid && !busy) verify.mutate(body);
  }
  return <>
    <Panel title={t("awsConnection")} subtitle={t("awsConnectionHint")}
      action={<button className="icon-button" aria-label={t("refreshProfiles")} onClick={refresh}><RefreshCw size={16} /></button>}>
      <form className="settings-form aws-form" onSubmit={submit}>
        <div className="split-inputs">
          <label>{t("awsAccountId")}<input inputMode="numeric" pattern="[0-9]{12}" required maxLength={12} value={account} readOnly={!!workspace.account_id}
            onChange={(event) => setAccount(event.target.value)} /></label>
          <label>{t("region")}<input required value={region} maxLength={30} onChange={(event) => setRegion(event.target.value)} /></label>
        </div>
        <div className="split-inputs">
          <label>{t("credentialSource")}<select value={source} onChange={(event) => setSource(event.target.value === "environment" ? "environment" : "profile")}>
            <option value="profile">{t("awsNamedProfile")}</option>
            <option value="environment" disabled={!workspace.environment_credentials}>{t("awsProcessEnv")}</option>
          </select></label>
          {source === "profile" && <label>{t("awsNamedProfile")}<select required value={profile} onChange={(event) => setProfile(event.target.value)}>
            <option value="">{t("chooseAwsProfile")}</option>
            {workspace.available_profiles.map((name) => <option key={name} value={name}>{name}</option>)}
          </select></label>}
        </div>
        {!workspace.available_profiles.length && !workspace.environment_credentials && <p className="secondary">{t("noAwsCredentials")}</p>}
        <div className="form-actions">
          <button type="submit" disabled={!valid || busy}>{t(verify.isPending ? "verifyingAws" : "verifyAws")}</button>
          {verified === fingerprint && <span className="inline-status" role="status"><CheckCircle2 size={15} />{t("awsVerified")}</span>}
        </div>
        {verify.isError && <Failure error={verify.error} />}
      </form>
    </Panel>
    <Panel title={t("importAws")} subtitle={t("awsScope")}>
      <div className="settings-form">
        <label>{t("historyDays")}<input type="number" min={1} max={90} value={days} onChange={(event) => setDays(event.target.valueAsNumber || 1)} /></label>
        <label className="checkbox"><input type="checkbox" checked={includeIam} onChange={(event) => setIncludeIam(event.target.checked)} />{t("includeIam")}</label>
        <div className="form-actions">
          <button type="button" className="primary" onClick={() => runImport.mutate()} disabled={verified !== fingerprint || busy || days < 1 || days > 90}>
            {t(runImport.isPending ? "importing" : "importAws")}
          </button>
        </div>
        {runImport.isError && <Failure error={runImport.error} />}
      </div>
    </Panel>
    {lastImport && <Panel title={t("lastAwsImport")} action={<DateTime value={lastImport.imported_at} />}>
      <dl className="integration-metrics">
        <div><dt>{t("importedEvents")}</dt><dd>{lastImport.cloudtrail.inserted}</dd></div>
        <div><dt>{t("storedEvents")}</dt><dd>{lastImport.cloudtrail.events}</dd></div>
        <div><dt>{t("identities")}</dt><dd>{lastImport.iam_identities}</dd></div>
        <div><dt>{t("iamStatus")}</dt><dd>{t(lastImport.iam === "imported" ? "iamImported" : lastImport.iam === "skipped" ? "iamSkipped" : "iamUnavailable")}</dd></div>
      </dl>
    </Panel>}
  </>;
}

export function AwsIntegrationPage() {
  const t = useText();
  const result = useQuery({ queryKey: ["aws-workspace"], queryFn: () => data(api.GET("/api/v1/integrations/aws")) });
  return <Page title="awsIntegration">
    {result.isPending ? <Skeleton /> : result.isError ? <Failure error={result.error} retry={() => void result.refetch()} /> :
      result.data.enabled ? <Connection workspace={result.data} refresh={() => void result.refetch()} /> : <AwsSetup />}
    <div className="info-strip"><Cloud size={16} />{t("awsReadOnlyHint")}</div>
  </Page>;
}
