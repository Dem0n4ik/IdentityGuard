import { useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft, ArrowUpRight } from "lucide-react";
import { useIntl } from "react-intl";
import { api, data, type Case, type Identity, type Incident, type IncidentUpdate, type Overview } from "./api/client";
import { Badge, Empty, Failure, Panel, Risk, Tile, localName } from "./design-system/primitives";
import { useText, type Message } from "./i18n";
import { DateTime, actorId, formatAccount, useFilters, useWorkspace, type Filters } from "./workspace";
import { Page } from "./design-system/Page";
import { CaseAnalysisPanel } from "./assistant";
import { CaseTimelinePanel } from "./case-timeline";
import { useWords } from "./words";
import { IncidentTracePanel } from "./incident-trace";
import { useAccess } from "./access";

const caseTitle = (item: Case, words: ReturnType<typeof useWords>) =>
  item.simulation ? words(item.simulation.title_uk, item.simulation.title_en)
    : item.identities.map((identity) => identity.name).join(" · ");
const quadrants: Record<Identity["quadrant"], Message> = { act_now: "actNow", investigate: "investigate", harden: "harden", normal: "normal" };

function filteredCases(workspace: Overview, filters: Filters, state = "open"): Case[] {
  const range = filters.range ?? "7";
  const since = range === "all" ? 0 : new Date(workspace.now).getTime() - Number(range) * 86400000;
  const active = filters.state ?? state;
  return workspace.cases.filter((item) =>
    (!filters.account || item.identities.some((identity) => identity.account_id === filters.account))
    && (!filters.level || item.level === filters.level)
    && (active === "all" || (active === "closed" ? item.status === "closed" : item.status !== "closed"))
    && new Date(item.updated).getTime() >= since,
  );
}

function CasesTable({ rows }: { rows: Case[] }) {
  const t = useText();
  const words = useWords();
  const intl = useIntl();
  const filters = useFilters();
  const { source } = useWorkspace();
  const links = useRef<Array<HTMLAnchorElement | null>>([]);
  if (!rows.length) return <Empty />;
  return <div className="table-wrap"><table><thead><tr>
    <th>{t("severity")}</th><th>{t("case")}</th><th>{t("account")}</th><th>{t("status")}</th>
    <th className="num">{t("risk")}</th><th>{t("updated")}</th>
  </tr></thead><tbody>
    {rows.map((item, index) => <tr key={item.id}>
      <td><Badge level={item.level} /></td>
      <td><Link className="entity" to="/cases/$id" params={{ id: item.id }} search={filters}
        ref={(element) => { links.current[index] = element; }}
        onKeyDown={(event) => {
          const offset = event.key === "j" ? 1 : event.key === "k" ? -1 : 0;
          if (offset) { event.preventDefault(); links.current[index + offset]?.focus(); }
        }}>{caseTitle(item, words)}</Link></td>
      <td><span className="account-tag">{Array.from(new Set(item.identities.map((actor) => formatAccount(actor.account_id, source)))).join(", ")}</span></td>
      <td><span className="status"><span />{t(item.status)}</span></td>
      <td className="num mono">{intl.formatNumber(item.risk, { maximumFractionDigits: 1 })}</td>
      <td className="secondary"><DateTime value={item.updated} /></td>
    </tr>)}
  </tbody></table></div>;
}

function IdentitiesTable({ rows, small = false }: { rows: Identity[]; small?: boolean }) {
  const t = useText();
  const intl = useIntl();
  const filters = useFilters();
  const { source } = useWorkspace();
  if (!rows.length) return <Empty />;
  return <div className="table-wrap"><table><thead><tr>
    <th>{t("identity")}</th>{!small && <><th>{t("type")}</th><th>{t("account")}</th></>}
    <th className="num">{t("activeRisk")}</th><th className="num">{t("exposure")}</th>{!small && <th>{t("quadrant")}</th>}
  </tr></thead><tbody>{rows.map((item) => {
    const kind = localName(item.kind);
    return <tr key={item.id}>
      <td><Link className="entity" to="/identities/$id" params={{ id: item.id }} search={filters}>{item.name}</Link></td>
      {!small && <><td>{kind ? t(kind) : item.kind}</td><td><span className="account-tag">{formatAccount(item.account_id, source)}</span></td></>}
      <td className="num mono">{intl.formatNumber(item.risk, { maximumFractionDigits: 1 })}</td>
      <td className="num mono">{intl.formatNumber(item.exposure, { maximumFractionDigits: 1 })}</td>
      {!small && <td>{t(quadrants[item.quadrant])}</td>}
    </tr>;
  })}</tbody></table></div>;
}

function Trend({ workspace, account }: { workspace: Overview; account?: string }) {
  const t = useText();
  const intl = useIntl();
  const [table, setTable] = useState(false);
  const incidents = workspace.cases.flatMap((item) => item.incidents);
  const days = Object.entries(workspace.timeline).sort(([a], [b]) => a.localeCompare(b));
  const entries = days.map(([day, count]) => [day, account ? incidents.filter((item) => item.identity.account_id === account && item.hour.startsWith(day)).length : count] as const);
  const peak = Math.max(4, ...entries.map(([, value]) => value));
  const points = entries.map(([, value], index) => [48 + index * 70, 138 - (value / peak) * 110] as const);
  return <Panel title={t("trend")} subtitle={t("last7")} action={<button onClick={() => setTable(!table)}>{t(table ? "hideData" : "showData")}</button>}>
    {table ? <div className="table-wrap"><table><thead><tr><th>{t("time")}</th><th className="num">{t("incidents")}</th></tr></thead>
      <tbody>{entries.map(([day, count]) => <tr key={day}><td>{day}</td><td className="num">{intl.formatNumber(count)}</td></tr>)}</tbody></table></div> :
      <div className="chart"><svg role="img" aria-label={t("trend")} viewBox="0 0 500 173">
        {[0, 1, 2, 3, 4].map((tick) => <g key={tick}><line x1="47" x2="477" y1={138 - tick * 27.5} y2={138 - tick * 27.5} />
          <text x="32" y={142 - tick * 27.5} textAnchor="end">{intl.formatNumber(tick * peak / 4, { maximumFractionDigits: 1 })}</text></g>)}
        <polyline points={points.map((point) => point.join(",")).join(" ")} />
        {points.map(([x, y], index) => {
          const entry = entries[index];
          if (!entry) return null;
          const [day, count] = entry;
          return <g key={day}><circle cx={x} cy={y} r="3.5"><title>{day + " · " + count}</title></circle>
            <text x={x} y="160" textAnchor="middle">{intl.formatDate(day + "T00:00:00Z", { month: "short", day: "numeric", timeZone: "UTC" })}</text></g>;
        })}
      </svg></div>}
  </Panel>;
}

export function OverviewPage() {
  const t = useText();
  const workspace = useWorkspace();
  const filters = useFilters();
  const { account, range } = filters;
  const rows = filteredCases(workspace, filters);
  const identities = workspace.identities.filter((item) => !account || item.account_id === account);
  return <Page title="overview">
    <div className="overview-tiles">
      <Tile label={t("openCases")} value={rows.length} detail={t("open")}><Link to="/cases" search={{ account, range, state: "open" }}>{t("cases")}</Link></Tile>
      <Tile label={t("highPriority")} value={rows.filter((item) => item.level === "high").length} detail={<Badge level="high" />}><Link to="/cases" search={{ account, range, level: "high", state: "open" }}>{t("allCases")}</Link></Tile>
      <Tile label={t("mediumPriority")} value={rows.filter((item) => item.level === "medium").length} detail={<Badge level="medium" />}><Link to="/cases" search={{ account, range, level: "medium", state: "open" }}>{t("allCases")}</Link></Tile>
      <Tile label={t("identities")} value={identities.length} detail={t("accounts")}><Link to="/identities" search={{ account }}>{t("identities")}</Link></Tile>
    </div>
    <Panel title={t("attention")} subtitle={t("attentionHint")}
      action={<Link to="/cases" search={{ account, range }} className="panel-link">{t("allCases")}<ArrowUpRight size={14} /></Link>}>
      <CasesTable rows={rows.slice(0, 5)} />
    </Panel>
    <div className="overview-bottom">
      <Trend workspace={workspace} account={account} />
      <Panel title={t("topRisk")} subtitle={t("topRiskHint")}><IdentitiesTable rows={identities.slice(0, 5)} small /></Panel>
    </div>
  </Page>;
}

export function CasesPage() {
  const t = useText();
  const workspace = useWorkspace();
  const filters = useFilters();
  const navigate = useNavigate({ from: "/cases" });
  const rows = filteredCases(workspace, filters);
  return <Page title="cases"><Panel title={t("rowCount", { count: rows.length })} action={<div className="filters">
    <select aria-label={t("status")} value={filters.state ?? "open"} onChange={(event) =>
      void navigate({ to: ".", search: () => ({ ...filters, state: event.target.value as Filters["state"] }) })}>
      <option value="open">{t("open")}</option><option value="closed">{t("closed")}</option><option value="all">{t("all")}</option>
    </select>
    <select aria-label={t("severity")} value={filters.level ?? ""} onChange={(event) =>
      void navigate({ to: ".", search: () => ({ ...filters, level: (event.target.value || undefined) as Filters["level"] }) })}>
      <option value="">{t("allLevels")}</option>{(["high", "medium", "low"] as const).map((level) => <option key={level} value={level}>{t(level)}</option>)}
    </select>
  </div>}><CasesTable rows={rows} /></Panel></Page>;
}

function IncidentsTable({ rows, showVerdict = false }: { rows: Incident[]; showVerdict?: boolean }) {
  const t = useText();
  const intl = useIntl();
  const filters = useFilters();
  if (!rows.length) return <Empty />;
  return <div className="table-wrap"><table aria-label={showVerdict ? t("incidents") : undefined}><thead><tr>
    <th>{t("severity")}</th><th>{t("identity")}</th><th>{t("status")}</th>
    {showVerdict && <th>{t("verdict")}</th>}<th>{t("time")}</th>
    <th className="num">B</th><th className="num">M</th><th className="num">R</th><th className="num">{t("eventCount")}</th>
  </tr></thead><tbody>{rows.map((incident) => <tr key={incident.id}>
    <td><Badge level={incident.level} /></td>
    <td><Link className="entity" to="/incidents/$id" params={{ id: incident.id }} search={filters}>{incident.identity.name}</Link></td>
    <td>{t(incident.status)}</td>{showVerdict && <td>{incident.verdict ? t(incident.verdict) : "—"}</td>}
    <td><DateTime value={incident.hour} /></td>
    {[incident.behavior, incident.modifier, incident.risk, incident.events].map((value, index) =>
      <td key={index} className="num mono">{intl.formatNumber(value, { maximumFractionDigits: 2 })}</td>,
    )}
  </tr>)}</tbody></table></div>;
}

export function IncidentsPage() {
  const t = useText();
  const workspace = useWorkspace();
  const filters = useFilters();
  const rows = filteredCases(workspace, filters, "all").flatMap((item) => item.incidents)
    .filter((item) => !filters.account || item.identity.account_id === filters.account);
  return <Page title="incidents"><Panel title={t("rowCount", { count: rows.length })}><IncidentsTable rows={rows} /></Panel></Page>;
}

export function IdentitiesPage() {
  const t = useText();
  const workspace = useWorkspace();
  const { account } = useFilters();
  const rows = workspace.identities.filter((item) => !account || item.account_id === account);
  return <Page title="identities"><Panel title={t("rowCount", { count: rows.length })}><IdentitiesTable rows={rows} /></Panel></Page>;
}

function IncidentEditor({ incident }: { incident: Incident }) {
  const t = useText();
  const client = useQueryClient();
  const [status, setStatus] = useState(incident.status);
  const [verdict, setVerdict] = useState<NonNullable<IncidentUpdate["verdict"]> | "">(incident.verdict ?? "");
  const [reason, setReason] = useState(incident.reason ?? "");
  const [note, setNote] = useState(incident.note);
  const save = useMutation({
    mutationFn: () => data(api.PATCH("/api/v1/incidents/{incident_id}", {
      params: { path: { incident_id: incident.id }, header: { "if-match": '"' + incident.version + '"' } },
      body: { status, note, verdict: status === "closed" ? verdict || null : null, reason: status === "closed" ? reason : null },
    })),
    onSuccess: () => client.invalidateQueries({ queryKey: ["workspace"] }),
  });
  return <form className="incident-form" onSubmit={(event) => { event.preventDefault(); save.mutate(); }}>
    <label>{t("status")}<select value={status} onChange={(event) => setStatus(event.target.value as Incident["status"])}>
      {(["new", "investigating", "responded", "closed"] as const).map((value) => <option key={value} value={value}>{t(value)}</option>)}
    </select></label>
    {status === "closed" && <div className="split-inputs">
      <label>{t("verdict")}<select required value={verdict} onChange={(event) => setVerdict(event.target.value as typeof verdict)}>
        <option value="">{t("chooseVerdict")}</option>
        {(["true_positive", "benign_true_positive", "false_positive"] as const).map((value) => <option key={value} value={value}>{t(value)}</option>)}
      </select></label>
      <label>{t("reason")}<input required maxLength={250} value={reason} onChange={(event) => setReason(event.target.value)} /></label>
    </div>}
    <label>{t("note")}<textarea rows={4} value={note} maxLength={4000} onChange={(event) => setNote(event.target.value)} /></label>
    <button type="submit" className="primary" disabled={save.isPending}>{t("save")}</button>
    {save.isSuccess && <span role="status">{t("saved")}</span>}
    {save.isError && <Failure error={save.error} />}
  </form>;
}

function Isolation({ incident }: { incident: Incident }) {
  const t = useText();
  const client = useQueryClient();
  const [confirmation, setConfirmation] = useState("");
  const key = useRef<string>();
  const action = useMutation({
    mutationFn: () => {
      key.current ??= crypto.randomUUID();
      return data(api.POST("/api/v1/incidents/{incident_id}/isolation", {
        params: { path: { incident_id: incident.id }, header: { "idempotency-key": key.current } },
        body: { confirmation },
      }));
    },
    onSuccess: () => client.invalidateQueries({ queryKey: ["workspace"] }),
  });
  return <Panel title={t("isolation")} subtitle={t("isolationHint")}>
    <form className="incident-form" onSubmit={(event) => { event.preventDefault(); action.mutate(); }}>
      <code>iam:AttachUserPolicy</code>
      <pre>{JSON.stringify({ UserName: incident.identity.name, PolicyArn: "arn:aws:iam::aws:policy/AWSDenyAll" }, null, 2)}</pre>
      <label>{t("confirmIdentity")}<input value={confirmation} maxLength={64} onChange={(event) => setConfirmation(event.target.value)} /></label>
      <button type="submit" className="primary" disabled={confirmation !== incident.identity.name || action.isPending || action.isSuccess}>{t("runDry")}</button>
      {action.isSuccess && <span role="status">{t("drySaved")}</span>}
      {action.isError && <Failure error={action.error} />}
    </form>
  </Panel>;
}

export function DetailPage({ type }: { type: "case" | "incident" | "identity" }) {
  const t = useText();
  const words = useWords();
  const intl = useIntl();
  const workspace = useWorkspace();
  const { role, scoped } = useAccess();
  const mayEdit = !role || role === "admin" || role === "analyst";
  const { id } = useParams({ strict: false });
  const filters = useFilters();
  const incidents = workspace.cases.flatMap((entry) => entry.incidents);
  if (type === "case") {
    const item = workspace.cases.find((entry) => entry.id === id);
    if (!item) return <NotFound />;
    return <><header className="page-header">
      <Link to="/cases" search={filters} className="back-link"><ArrowLeft size={14} /> {t("cases")}</Link>
      <div className="heading-inline"><h1 className={item.simulation ? undefined : "mono"}>{caseTitle(item, words)}</h1><Badge level={item.level} /></div>
      <p>{t(item.status)} · <DateTime value={item.updated} /></p>
      {item.simulation && <p>{words(item.simulation.context_uk, item.simulation.context_en)}</p>}
    </header><Panel title={t("incidents")}><IncidentsTable rows={item.incidents} showVerdict /></Panel>
    <CaseTimelinePanel item={item} />
    {!scoped && <CaseAnalysisPanel item={item} key={item.id} />}
    {item.incidents.map((incident) => <Panel key={incident.id} title={incident.identity.name} subtitle={incident.model_version}><Risk incident={incident} /></Panel>)}</>;
  }
  if (type === "incident") {
    const item = incidents.find((entry) => entry.id === id);
    if (!item) return <NotFound />;
    return <><header className="page-header">
      <Link to="/incidents" search={filters} className="back-link"><ArrowLeft size={14} /> {t("incidents")}</Link>
      <div className="heading-inline"><h1 className="mono">{item.identity.name}</h1><Badge level={item.level} /></div>
      <p><DateTime value={item.hour} /> · {item.model_version} · {t(item.status)}</p>
    </header>
    <Panel title={t("detail")} action={<Link to="/hunt" className="panel-link" search={{ identity: actorId(item.identity) }}>{t("viewEvents")}<ArrowUpRight size={14} /></Link>}><Risk incident={item} /></Panel>
    <IncidentTracePanel incident={item} />
    {workspace.source === "demo" && (!role || role === "admin") && <Panel title={t("suppressions")} action={<Link to="/suppressions" className="panel-link" search={{ caseId: item.case_id }}>{t("createSuppression")}<ArrowUpRight size={14} /></Link>} />}
    {workspace.source === "demo" && mayEdit && <Panel title={t("note")}><IncidentEditor incident={item} key={item.id + ":" + item.status} /></Panel>}
    {workspace.source === "demo" && mayEdit && !scoped && item.identity.kind === "user" && item.status !== "closed" && <Isolation incident={item} key={item.id} />}</>;
  }
  const item = workspace.identities.find((entry) => entry.id === id);
  if (!item) return <NotFound />;
  const kind = localName(item.kind);
  return <><header className="page-header">
    <Link to="/identities" className="back-link"><ArrowLeft size={14} /> {t("identities")}</Link>
    <h1 className="mono">{item.name}</h1><p>{kind ? t(kind) : item.kind} · {formatAccount(item.account_id, workspace.source)}</p>
  </header>
  <Panel title={t(quadrants[item.quadrant])} action={<Link to="/hunt" className="panel-link" search={{ identity: item.id }}>{t("viewEvents")}<ArrowUpRight size={14} /></Link>}>
    <div className="identity-summary"><div><span>{t("activeRisk")}</span><strong>{intl.formatNumber(item.risk, { maximumFractionDigits: 1 })}</strong></div>
    <div><span>{t("exposure")}</span><strong>{intl.formatNumber(item.exposure, { maximumFractionDigits: 1 })}</strong></div>
    <div className="pills">{item.facts.map((fact) => {
      const label = localName(fact);
      return <span className="pill" key={fact}>{label ? t(label) : fact}</span>;
    })}</div></div>
  </Panel>
  <Panel title={t("incidents")}><IncidentsTable rows={incidents.filter((incident) => actorId(incident.identity) === item.id)} /></Panel></>;
}

export function NotFound() {
  const t = useText();
  return <div className="empty"><strong>{t("notFound")}</strong><Link to="/">{t("back")}</Link></div>;
}
