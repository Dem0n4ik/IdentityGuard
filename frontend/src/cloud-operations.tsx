import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api, data } from "./api/client";
import type { components } from "./api/schema";
import { Page } from "./design-system/Page";
import { Empty, Failure, Panel, Skeleton } from "./design-system/primitives";
import { useText } from "./i18n";
import { useWords } from "./words";
import { DateTime, useFilters, usePreferences, useWorkspace } from "./workspace";

type PathDetail = components["schemas"]["PathDetail"];
type Edge = components["schemas"]["AccessEdge"];

const CHECK_NAMES: Record<string, [string, string]> = {
  root_mfa: ["MFA кореневого користувача", "Root MFA"],
  root_keys: ["Відсутність кореневих ключів", "No root access keys"],
  trail_logging: ["CloudTrail записує події", "CloudTrail logging"],
  trail_regions: ["Охоплення всіх регіонів", "Multi-region trail"],
  trail_validation: ["Перевірка цілісності журналів", "Log file validation"],
  trail_data: ["Події даних критичних бакетів", "Critical bucket data events"],
  imds_v2: ["Примусовий IMDSv2", "IMDSv2 enforced"],
  log_freshness: ["Остання подія за 6 годин", "Event observed within six hours"],
};

const EDGE_NAMES: Record<Edge["kind"], [string, string]> = {
  can_assume: ["Прийняття ролі", "Assume role"], member_of: ["Членство в групі", "Group membership"],
  has_access: ["Доступ до ресурсу", "Resource access"], runs_as: ["Робоча роль", "Workload role"],
  can_escalate: ["Підвищення привілеїв", "Privilege escalation"],
};

export function CloudPage() {
  const words = useWords();
  const t = useText();
  const client = useQueryClient();
  const workspace = useWorkspace();
  const result = useQuery({ queryKey: ["cloud-checks"], queryFn: () => data(api.GET("/api/v1/cloud")) });
  const refresh = useMutation({
    mutationFn: () => data(api.POST("/api/v1/cloud/refresh")),
    onSuccess: (snapshot) => {
      client.setQueryData(["cloud-checks"], snapshot);
      void client.invalidateQueries({ queryKey: ["attack-origins"] });
      void client.invalidateQueries({ queryKey: ["attack-paths"] });
      void client.invalidateQueries({ queryKey: ["workspace"] });
    },
  });
  const cloud = result.data;
  return <Page title="cloudConfig">
    <Panel title={words("Перевірки конфігурації", "Configuration checks")}
      subtitle={cloud ? cloud.account_id + " · " + cloud.region + (cloud.source === "demo" ? " · " + t("demo") : "") : undefined}
      action={workspace.source === "aws" ? <button onClick={() => refresh.mutate()} disabled={refresh.isPending}>
        {refresh.isPending ? words("Збирання даних", "Collecting configuration") : words("Оновити з AWS", "Refresh from AWS")}
      </button> : undefined}>
      {result.isPending ? <Skeleton /> : result.isError ? <Failure error={result.error} /> : !cloud ? <div className="panel-content">
        <p>{words("Перевірте підключення AWS і запустіть збирання конфігурації.", "Verify the AWS connection and run a configuration refresh.")}</p>
        <Link to="/integrations/aws">{t("awsIntegration")}</Link>
      </div> : <>
        <div className="table-wrap"><table><thead><tr><th>{words("Перевірка", "Check")}</th><th>{t("severity")}</th><th>{t("status")}</th></tr></thead>
          <tbody>{cloud.checks.map((row) => <tr key={row.id}>
            <td>{words(CHECK_NAMES[row.id]?.[0] ?? row.id, CHECK_NAMES[row.id]?.[1] ?? row.id)}</td>
            <td>{row.level === "critical" ? words("Критичний", "Critical") : t(row.level)}</td>
            <td><span className={"pill check-" + String(row.passed)}>{row.passed == null ? words("Немає даних", "Unknown") : row.passed ? words("Виконано", "Pass") : words("Потребує уваги", "Needs attention")}</span></td>
          </tr>)}</tbody>
        </table></div>
        <div className="panel-content">
          <p>{words("Остання спостережена подія", "Last observed event")} · {cloud.newest_event ? <DateTime value={cloud.newest_event} /> : "—"}</p>
          {cloud.unavailable.length > 0 && <p className="secondary">{words("Часткове покриття", "Partial coverage")} · {cloud.unavailable.join(", ")}</p>}
        </div>
      </>}
      {refresh.isError && <Failure error={refresh.error} showDetail />}
    </Panel>
  </Page>;
}

export function RoleChainsPage() {
  const words = useWords();
  const t = useText();
  const { account, range } = useFilters();
  const days = range === "30" || range === "all" ? 30 : 7;
  const result = useQuery({ queryKey: ["role-chains", days], queryFn: () => data(api.GET("/api/v1/role-chains", { params: { query: { days } } })) });
  const rows = result.data?.filter((row) => !account || row.source_account === account || row.target_account === account) ?? [];
  return <Page title="roleChains"><Panel title={words("Спостережені переходи STS", "Observed STS transitions")}
    subtitle={words("Успішні виклики CloudTrail. Мережа довір IAM відображається в графі доступу.", "Successful CloudTrail calls. IAM trust relationships appear in the access graph.")}>
    {result.isPending ? <Skeleton /> : result.isError ? <Failure error={result.error} /> : !rows.length ? <Empty /> :
      <div className="table-wrap"><table><thead><tr>
        <th>{words("Джерело", "Source")}</th><th>{words("Цільова роль", "Target role")}</th><th>{t("account")}</th>
        <th className="num">{words("Переходів", "Transitions")}</th><th className="num">{words("Ризикових", "Risky")}</th><th>{t("time")}</th>
      </tr></thead><tbody>{rows.map((row) => <tr key={row.source + row.target}>
        <td><Link className="entity" to="/identities/$id" params={{ id: row.source }}>{row.source_name}</Link></td>
        <td><code>{row.target_name}</code></td><td>{row.source_account} → {row.target_account}
          {row.cross_account && <span className="pill">{words("Між акаунтами", "Cross-account")}</span>}</td>
        <td className="num">{row.count}</td><td className="num">{row.risky}</td><td><DateTime value={row.latest} /></td>
      </tr>)}</tbody></table></div>}
  </Panel></Page>;
}

function PathGraph({ path, selected, onSelect }: { path: PathDetail; selected: string; onSelect: (id: string) => void }) {
  const words = useWords();
  const depth = new Map([[path.origin.id, 0]]);
  const edges = new Map<string, Edge>();
  for (const route of path.routes) {
    route.forEach((item, index) => {
      depth.set(item.target, index + 1);
      edges.set(item.id, item);
    });
  }
  const columns = new Map<number, string[]>();
  for (const [id, column] of depth) columns.set(column, [...(columns.get(column) ?? []), id]);
  const positions = new Map<string, [number, number]>();
  const width = Math.max(420, (path.hops + 1) * 220);
  const height = Math.max(140, Math.max(...Array.from(columns.values()).map((column) => column.length)) * 78 + 36);
  for (const [column, items] of columns) {
    items.forEach((id, index) => positions.set(id, [column * 220 + 12, (height - (items.length - 1) * 78) / 2 + index * 78]));
  }
  return <div className="access-graph"><svg role="group" aria-label={words("Граф доступу", "Access graph")} viewBox={`0 0 ${width} ${height}`} width={width} height={height}>
    {Array.from(edges.values()).map((item) => {
      const from = positions.get(item.source);
      const to = positions.get(item.target);
      if (!from || !to) return null;
      const [sx, sy] = from;
      const [tx, ty] = to;
      return <path key={item.id} data-edge-id={item.id} className={["path-edge", path.key_links.includes(item.id) ? "mandatory" : "", selected === item.id ? "highlight" : ""].join(" ")}
        aria-label={words(...EDGE_NAMES[item.kind])} role="button" tabIndex={0} onFocus={() => onSelect(item.id)} onBlur={() => onSelect("")}
        onPointerEnter={() => onSelect(item.id)} onPointerLeave={() => onSelect("")}
        onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(item.id); } }}
        d={`M ${sx + 158} ${sy} C ${sx + 185} ${sy}, ${tx - 26} ${ty}, ${tx} ${ty}`} />;
    })}
    {path.nodes.map((node) => {
      const point = positions.get(node.id);
      if (!point) return null;
      const [x, y] = point;
      return <g key={node.id} transform={`translate(${x},${y - 22})`}>
        <title>{node.name}</title><rect width="158" height="44" rx="5" className={node.critical ? "critical-node" : "access-node"} />
        <text x="9" y="18">{node.name.length > 21 ? node.name.slice(0, 20) + "…" : node.name}</text>
        <text className="node-caption" x="9" y="34">{node.kind}{node.critical ? " · " + words("критичний", "critical") : ""}</text>
      </g>;
    })}
  </svg></div>;
}

function PathCard({ path }: { path: PathDetail }) {
  const words = useWords();
  const { prefs: { language } } = usePreferences();
  const [selected, setSelected] = useState("");
  const [consent, setConsent] = useState(false);
  const status = useQuery({ queryKey: ["assistant"], queryFn: () => data(api.GET("/api/v1/assistant")) });
  const generate = useMutation({
    mutationFn: () => data(api.POST("/api/v1/attack-paths/{path_id}/explain", {
      params: { path: { path_id: path.id } }, body: { origin: path.origin.id, language, consent: true },
    })),
    onSuccess: () => setConsent(false),
  });
  const description = generate.data ?? path.explanation;
  return <Panel title={path.resource.name}
    subtitle={path.origin.name + " → " + path.resource.name + " · " + path.hops + " " + words("переходів", "hops")}
    action={<span className="pill">{description.source === "template" ? words("Шаблонне пояснення", "Template explanation") : words("Пояснення згенеровано ШІ", "AI-generated explanation")}</span>}>
    <PathGraph path={path} selected={selected} onSelect={setSelected} />
    <div className="analysis-content">
      <p>{description.summary}</p>
      <ol className="path-explanation">
        {description.steps.map((step) => <li key={step.edge_id}>
          <button className={selected === step.edge_id ? "active-step" : ""} onPointerEnter={() => setSelected(step.edge_id)}
            onPointerLeave={() => setSelected("")} onFocus={() => setSelected(step.edge_id)} onBlur={() => setSelected("")}>
            {step.text}{path.key_links.includes(step.edge_id) && <span className="pill">{words("Ключова ланка", "Key link")}</span>}
          </button>
        </li>)}
      </ol>
      <details><summary>{words("Ребра й дії IAM", "Edges and IAM actions")}</summary>
        <ul>{path.routes[0]?.map((item) => <li key={item.id}>{words(...EDGE_NAMES[item.kind])} · <code>{(item.actions ?? []).join(", ") || "—"}</code></li>)}</ul>
      </details>
      {status.data?.enabled && <div className="form-actions">
        <label className="checkbox"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} />
          {words("Надіслати знеособлену структуру шляху Anthropic", "Send the de-identified path structure to Anthropic")}</label>
        <button disabled={!consent || generate.isPending} onClick={() => generate.mutate()}>{words("Згенерувати пояснення", "Generate explanation")}</button>
      </div>}
      {generate.isError && <Failure error={generate.error} showDetail />}
    </div>
  </Panel>;
}

export function AttackPathsPage() {
  const t = useText();
  const words = useWords();
  const filters = useFilters();
  const { prefs: { language } } = usePreferences();
  const [choice, setChoice] = useState(filters.identity ?? "");
  const origins = useQuery({ queryKey: ["attack-origins"], queryFn: () => data(api.GET("/api/v1/attack-paths/origins")) });
  const options = origins.data?.filter((item) => !filters.account || item.account_id === filters.account) ?? [];
  const selected = options.find((item) => item.id === choice) ?? options.find((item) => item.name === "DeployRole") ?? options[0];
  const result = useQuery({
    queryKey: ["attack-paths", selected?.id, language], enabled: !!selected,
    queryFn: () => data(api.GET("/api/v1/attack-paths", { params: { query: { origin: selected?.id ?? "", language } } })),
  });
  return <Page title="attackPaths">
    <Panel title={words("Граф доступу", "Access graph")} subtitle={words("Оцінка може бути завищена через обмеження IAM, умови й SCP.", "IAM conditions, boundaries and SCPs can make this estimate overstate access.")}
      action={options.length > 0 && <label>{t("identity")} <select value={selected?.id ?? ""} onChange={(event) => setChoice(event.target.value)}>
        {options.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.account_id}</option>)}
      </select></label>} />
    {origins.isPending ? <Skeleton /> : origins.isError ? <Failure error={origins.error} /> : !selected ?
      <Panel title={words("Немає знімка графа", "No access graph snapshot")}><div className="panel-content"><Link to="/cloud">{t("cloudConfig")}</Link></div></Panel> :
      result.isPending ? <Skeleton /> : result.isError ? <Failure error={result.error} /> : result.data.length ?
      result.data.map((path) => <PathCard path={path} key={path.id + language} />) :
      <Panel title={words("Критичні ресурси", "Critical resources")}><p className="panel-content">{words("У зібраному графі немає шляхів до критичних ресурсів за чотири переходи.", "The collected graph has no path to a critical resource within four hops.")}</p></Panel>}
  </Page>;
}
