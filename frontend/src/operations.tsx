import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api, data } from "./api/client";
import type { components } from "./api/schema";
import { Page } from "./design-system/Page";
import { Badge, Empty, Failure, Panel, Skeleton } from "./design-system/primitives";
import { useText } from "./i18n";
import { useWords } from "./words";
import { DateTime, useFilters, useWorkspace } from "./workspace";

type RuleRevision = components["schemas"]["RuleRevision"];
type ExceptionRecord = components["schemas"]["ExceptionRecord"];

const SAMPLE = `id: ig-guardduty-change
name: GuardDuty configuration change
description: Increase evasion signal for detector modifications.
category: evasion
value: 1.0
scope:
  accounts: ["*"]
  identity_kinds: [user, role, sso_user]
condition:
  field: event_name
  op: in
  value: [DeleteDetector, UpdateDetector]
tests:
  - event: {event_name: UpdateDetector, identity: {kind: user}}
    expect: match
  - event: {event_name: ListDetectors, identity: {kind: user}}
    expect: no_match
`;

export function ComparisonTable({ comparison }: { comparison: components["schemas"]["Comparison"] }) {
  const words = useWords();
  const t = useText();
  return <div className="ops-results">
    <div className="result-line">
      <span>{words("Вікон", "Windows")} <strong>{comparison.evaluated}</strong></span>
      <span>{words("Змінено рівень", "Severity changed")} <strong>{comparison.changed}</strong></span>
      <span>{words("Нових інцидентів", "New incidents")} <strong>{comparison.new_incidents}</strong></span>
    </div>
    {Object.keys(comparison.new_by_day).length > 0 && <div className="result-line">{Object.entries(comparison.new_by_day).sort().map(([day, count]) =>
      <span key={day}><time dateTime={day}>{day}</time> <strong>{count}</strong></span>)}</div>}
    {comparison.examples.length > 0 && <div className="table-wrap"><table><thead><tr>
      <th>{t("identity")}</th><th>{t("time")}</th><th>{words("Було", "Before")}</th><th>{words("Стало", "After")}</th>
    </tr></thead><tbody>{comparison.examples.map((row) => <tr key={row.identity_id + row.hour}>
      <td><Link className="entity" to="/identities/$id" params={{ id: row.identity_id }}>{row.identity_id.split(":").slice(2).join(":")}</Link></td>
      <td><DateTime value={row.hour} /></td>
      <td>{row.before} · {row.risk_before.toFixed(2)}</td><td>{row.after} · {row.risk_after.toFixed(2)}</td>
    </tr>)}</tbody></table></div>}
  </div>;
}

function exportRule(source: string, id: string) {
  const url = URL.createObjectURL(new Blob([source], { type: "application/yaml" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = id + ".yaml";
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 500);
}

export function DetectionsPage() {
  const words = useWords();
  const t = useText();
  const client = useQueryClient();
  const workspace = useWorkspace();
  const editable = workspace.source === "demo";
  const [source, setSource] = useState(SAMPLE);
  const [status, setStatus] = useState<RuleRevision["status"]>("draft");
  const [days, setDays] = useState(7);
  const [fileTooBig, setFileTooBig] = useState(false);
  const rules = useQuery({ queryKey: ["rule-revisions"], queryFn: () => data(api.GET("/api/v1/detections")) });
  const backtest = useMutation({ mutationFn: () => data(api.POST("/api/v1/detections/backtest", { body: { yaml: source, days } })) });
  const save = useMutation({
    mutationFn: () => data(api.POST("/api/v1/detections", { body: { yaml: source, status } })),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["rule-revisions"] });
      void client.invalidateQueries({ queryKey: ["workspace"] });
    },
  });
  return <Page title="detections">
    <Panel title={words("Редактор правила", "Rule editor")}
      subtitle={words("Обов’язкові вбудовані тести виконуються перед збереженням і бектестом.", "Embedded tests run before saving or backtesting.")}>
      <div className="settings-form">
        <label>{words("Правило YAML", "YAML rule")}<textarea className="yaml-editor" spellCheck={false} maxLength={32768} rows={20} value={source} onChange={(e) => {
          setSource(e.target.value);
          backtest.reset();
          save.reset();
        }} /></label>
        <div className="form-actions">
          <label>{words("Імпорт YAML", "Import YAML")} <input type="file" accept=".yaml,.yml" onChange={(event) => {
            const file = event.target.files?.[0];
            setFileTooBig(!!file && file.size > 32768);
            if (file && file.size <= 32768) void file.text().then(setSource);
          }} /></label>
          <button onClick={() => exportRule(source, "identityguard-rule")}>{words("Експорт YAML", "Export YAML")}</button>
        </div>
        {fileTooBig && <p role="alert">{words("Файл завеликий. Межа — 32 КБ.", "The file exceeds 32 KiB.")}</p>}
        <div className="form-actions">
          <label>{words("Діб історії", "Days of history")} <input type="number" min={1} max={30} value={days} onChange={(event) => setDays(event.target.valueAsNumber || 1)} /></label>
          <button onClick={() => backtest.mutate()} disabled={backtest.isPending || days < 1 || days > 30 || !source.trim()}>
            {words(backtest.isPending ? "Триває бектест" : "Запустити бектест", backtest.isPending ? "Backtesting" : "Run backtest")}
          </button>
          {editable && <>
            <label>{t("status")} <select value={status} onChange={(event) => setStatus(event.target.value as RuleRevision["status"])}>
              <option value="draft">{words("Чернетка", "Draft")}</option><option value="enabled">{words("Увімкнено", "Enabled")}</option>
              <option value="disabled">{words("Вимкнено", "Disabled")}</option>
            </select></label>
            <button className="primary" onClick={() => save.mutate()} disabled={save.isPending || !source.trim()}>{words("Зберегти версію", "Save revision")}</button>
          </>}
        </div>
        {save.isSuccess && <p className="inline-status" role="status">{words("Версію збережено", "Revision saved")} · {save.data.id}@{save.data.revision}</p>}
        {(save.isError || backtest.isError) && <Failure error={save.error ?? backtest.error} showDetail />}
      </div>
    </Panel>
    {backtest.data && <Panel title={words("Результат бектесту", "Backtest result")}>
      <div className="panel-content" role="status">{words("Збігів подій", "Matching events")} <strong>{backtest.data.matches}</strong></div>
      <ComparisonTable comparison={backtest.data} />
      {backtest.data.examples_events.length > 0 && <div className="table-wrap"><table><thead><tr>
        <th>{t("event")}</th><th>{t("region")}</th><th>{t("time")}</th>
      </tr></thead><tbody>{backtest.data.examples_events.map((row) => <tr key={row.event_id}>
        <td><code>{row.operation}</code></td><td>{row.region}</td><td><DateTime value={row.time} /></td>
      </tr>)}</tbody></table></div>}
    </Panel>}
    <Panel title={words("Історія версій", "Revision history")}>
      {rules.isPending ? <Skeleton /> : rules.isError ? <Failure error={rules.error} /> : rules.data.length ? <div className="table-wrap"><table><thead><tr>
        <th>ID</th><th>{words("Назва", "Name")}</th><th>{t("status")}</th><th>{words("Редакція", "Revision")}</th><th>{t("time")}</th>
      </tr></thead><tbody>{rules.data.map((row) => <tr key={row.id + row.revision}>
        <td><button onClick={() => { setSource(row.yaml); setStatus(row.status); save.reset(); backtest.reset(); }}>{row.id}</button></td>
        <td>{row.name}</td><td>{row.status}</td><td>{row.revision}</td><td><DateTime value={row.created_at} /></td>
      </tr>)}</tbody></table></div> : <Empty />}
    </Panel>
  </Page>;
}

const INDICATORS = ["geo", "ip", "time", "seq", "vol", "priv", "secret", "dormant", "wexfil"] as const;
const MATCH_FIELDS = ["region", "ip_prefix", "cidr", "event_name", "user_agent_prefix"] as const;
const identityKey = (actor: components["schemas"]["Principal"]) => [actor.account_id, actor.kind, actor.name].join(":");

export function SuppressionsPage() {
  const t = useText();
  const words = useWords();
  const client = useQueryClient();
  const workspace = useWorkspace();
  const { caseId } = useFilters();
  const [selection, setSelection] = useState(caseId ?? "");
  const [actor, setActor] = useState("");
  const [indicator, setIndicator] = useState<ExceptionRecord["indicator"]>("geo");
  const [field, setField] = useState<ExceptionRecord["field"]>("region");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(7);
  const available = workspace.cases.find((item) => item.id === selection);
  const actorId = available?.identities.some((identity) => identityKey(identity) === actor) ? actor : available?.identities[0] && identityKey(available.identities[0]);
  const rows = useQuery({ queryKey: ["suppressions"], queryFn: () => data(api.GET("/api/v1/suppressions")) });
  function refresh() {
    void client.invalidateQueries({ queryKey: ["suppressions"] });
    void client.invalidateQueries({ queryKey: ["workspace"] });
  }
  const save = useMutation({
    mutationFn: () => data(api.POST("/api/v1/suppressions", { body: { identity_id: actorId ?? "", indicator, field, value, reason, days, case_id: selection } })),
    onSuccess: refresh,
  });
  const toggle = useMutation({
    mutationFn: (row: ExceptionRecord) => data(api.PATCH("/api/v1/suppressions/{item_id}", { params: { path: { item_id: row.id } }, body: { enabled: !row.enabled } })),
    onSuccess: refresh,
  });
  const rescore = useMutation({ mutationFn: () => data(api.POST("/api/v1/suppressions/rescore")), onSuccess: refresh });
  return <Page title="suppressions">
    {workspace.source === "demo" && <Panel title={words("Новий виняток", "New suppression")} subtitle={words("Виняток діє до агрегації подій. Уникнення журналювання приглушити неможливо.", "Suppression applies before event aggregation. Logging evasion cannot be suppressed.")}>
      <form className="settings-form" onSubmit={(event) => { event.preventDefault(); save.mutate(); }}>
        <div className="split-inputs">
          <label>{t("case")}<select required value={selection} onChange={(event) => setSelection(event.target.value)}>
            <option value="">{words("Виберіть кейс", "Select a case")}</option>
            {workspace.cases.map((item) => <option key={item.id} value={item.id}>{item.identities.map((person) => person.name).join(" · ")} · {item.updated.slice(0, 10)}</option>)}
          </select></label>
          <label>{t("identity")}<select required value={actorId ?? ""} onChange={(event) => setActor(event.target.value)}>
            {available?.identities.map((identity) => <option key={identityKey(identity)} value={identityKey(identity)}>{identity.name}</option>)}
          </select></label>
        </div>
        <div className="split-inputs">
          <label>{words("Індикатор", "Indicator")}<select value={indicator} onChange={(event) => setIndicator(event.target.value as typeof indicator)}>
            {INDICATORS.map((item) => <option key={item}>{item}</option>)}
          </select></label>
          <label>{words("Умова", "Condition")}<select value={field} onChange={(event) => setField(event.target.value as typeof field)}>
            {MATCH_FIELDS.map((item) => <option key={item}>{item}</option>)}
          </select></label>
        </div>
        <div className="split-inputs">
          <label>{words("Значення", "Value")}<input required maxLength={250} value={value} onChange={(event) => setValue(event.target.value)} /></label>
          <label>{words("Строк дії, діб", "Expiry, days")}<input type="number" min={1} max={90} value={days} onChange={(event) => setDays(event.target.valueAsNumber || 1)} /></label>
        </div>
        <label>{words("Обґрунтування", "Reason")}<textarea required minLength={10} maxLength={1000} value={reason} onChange={(event) => setReason(event.target.value)} /></label>
        <div className="form-actions"><button className="primary" type="submit" disabled={!actorId || save.isPending}>{words("Зберегти й перерахувати", "Save and rescore")}</button></div>
        {save.isSuccess && <p className="inline-status" role="status">{words("Виняток збережено", "Suppression saved")} · {save.data.hits} {words("збігів", "hits")}</p>}
        {save.isError && <Failure error={save.error} showDetail />}
      </form>
    </Panel>}
    <Panel title={t("suppressions")} action={workspace.source === "demo" && <button disabled={rescore.isPending} onClick={() => rescore.mutate()}>{words("Перерахувати", "Rescore")}</button>}>
      {rows.isPending ? <Skeleton /> : rows.isError ? <Failure error={rows.error} /> : rows.data.length ? <div className="table-wrap"><table><thead><tr>
        <th>{t("identity")}</th><th>{words("Індикатор", "Indicator")}</th><th>{words("Умова", "Condition")}</th>
        <th>{words("Збігів", "Hits")}</th><th>{words("До", "Expires")}</th><th>{t("status")}</th>
      </tr></thead><tbody>{rows.data.map((row) => <tr key={row.id}>
        <td><Link className="entity" to="/identities/$id" params={{ id: row.identity_id }}>{row.identity_id.split(":").slice(2).join(":")}</Link></td>
        <td><code>{row.indicator}</code></td><td><code>{row.field} = {row.value}</code></td><td>{row.hits}</td>
        <td><DateTime value={row.expires_at} /></td>
        <td>{new Date(row.expires_at).getTime() < Date.now() ? words("Прострочено", "Expired") :
          workspace.source === "demo" ? <button disabled={toggle.isPending} onClick={() => toggle.mutate(row)}>{row.enabled ? words("Вимкнути", "Disable") : words("Увімкнути", "Enable")}</button> : row.enabled ? words("Активний", "Active") : words("Вимкнений", "Disabled")}</td>
      </tr>)}</tbody></table></div> : <Empty />}
      {(toggle.isError || rescore.isError) && <Failure error={toggle.error ?? rescore.error} showDetail />}
    </Panel>
  </Page>;
}
