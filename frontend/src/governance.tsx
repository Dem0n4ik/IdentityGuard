import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { api, data } from "./api/client";
import type { components } from "./api/schema";
import { Page } from "./design-system/Page";
import { Badge, Empty, Failure, Panel, Skeleton } from "./design-system/primitives";
import { useText } from "./i18n";
import { ComparisonTable } from "./operations";
import { useWords } from "./words";
import { DateTime, formatAccount, useFilters, useWorkspace } from "./workspace";

type Baseline = components["schemas"]["Baseline"];
type Version = components["schemas"]["Version"];
type SLASettings = components["schemas"]["SLASettings"];
const scale = [1 / 9, 1 / 8, 1 / 7, 1 / 6, 1 / 5, 1 / 4, 1 / 3, 1 / 2, 1, 2, 3, 4, 5, 6, 7, 8, 9];
const scaleLabel = (value: number) => value < 1 ? "1/" + Math.round(1 / value) : String(value);

function AhpEditor({ baseline }: { baseline: Baseline }) {
  const words = useWords();
  const client = useQueryClient();
  const workspace = useWorkspace();
  const { recommended } = useFilters();
  const [name, setName] = useState("");
  const [matrix, setMatrix] = useState(baseline.matrix);
  const [mid, setMid] = useState(baseline.thr_mid);
  const [high, setHigh] = useState(recommended && recommended > baseline.thr_mid ? recommended : baseline.thr_high);
  const keys = Object.keys(baseline.weights);
  const analysis = useQuery({
    queryKey: ["ahp", baseline.profile, matrix],
    queryFn: () => data(api.POST("/api/v1/models/ahp", { body: { profile: baseline.profile, matrix } })),
    retry: false,
  });
  const save = useMutation({
    mutationFn: () => data(api.POST("/api/v1/models/drafts", { body: { profile: baseline.profile, matrix, name, thr_mid: mid, thr_high: high } })),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["model-drafts"] }),
  });
  const result = analysis.data;
  return <Panel title={words("Парні порівняння AHP", "AHP pairwise comparisons")}
    subtitle={words("Редагуйте верхній трикутник за шкалою Сааті. Нижній оновлюється автоматично.", "Edit the upper triangle on Saaty’s scale. Reciprocal entries update automatically.")}>
    <div className="table-wrap ahp-table"><table><thead><tr><th scope="col">AHP</th>{keys.map((key) => <th scope="col" key={key}>{key}</th>)}</tr></thead>
      <tbody>{matrix.map((row, i) => <tr key={keys[i]}><th scope="row">{keys[i]}</th>{row.map((value, j) =>
        <td key={keys[j]} className={result?.inconsistent_pairs.some(([a, b]) => a === i && b === j) ? "ahp-conflict" : ""}>{j > i ?
          <select value={value} aria-label={keys[i] + " / " + keys[j]} onChange={(event) => {
            const next = Number(event.target.value);
            setMatrix((old) => old.map((line, left) => line.map((item, right) =>
              left === i && right === j ? next : left === j && right === i ? 1 / next : item)));
          }}>{scale.map((item) => <option key={item} value={item}>{scaleLabel(item)}</option>)}</select> : scaleLabel(value)}</td>)}</tr>)}</tbody>
    </table></div>
    {result && <div className="panel-content">
      <div className="result-line">
        <span>λmax <strong>{result.eigenvalue.toFixed(3)}</strong></span><span>CI <strong>{result.ci.toFixed(3)}</strong></span>
        <span>CR <strong>{result.cr.toFixed(4)}</strong></span>
        <span role="status">{result.consistent ? words("Узгоджено", "Consistent") : words("Потрібно CR < 0,1", "CR must be below 0.1")}</span>
      </div>
      <dl className="ops-weights">{Object.entries(result.weights).map(([key, weight]) => <div key={key}><dt>{key}</dt><dd>{(weight * 100).toFixed(1)}%</dd></div>)}</dl>
      <details><summary>{words("Ваги фактів стану", "Posture fact weights")}</summary>
        <dl className="ops-weights">{Object.entries(baseline.fact_weights).map(([key, weight]) => <div key={key}><dt>{key}</dt><dd>{(weight * 100).toFixed(1)}%</dd></div>)}</dl>
      </details>
    </div>}
    {analysis.isError && <Failure error={analysis.error} showDetail />}
    {workspace.source === "demo" && <form className="settings-form" onSubmit={(event) => { event.preventDefault(); save.mutate(); }}>
      <label>{words("Назва чернетки", "Draft name")}<input required minLength={3} maxLength={100} value={name} onChange={(event) => setName(event.target.value)} /></label>
      <div className="split-inputs">
        <label>{words("Середній поріг", "Medium threshold")}<input type="number" min={0.01} max={99.99} step="any" value={mid} onChange={(event) => setMid(event.target.valueAsNumber || 0)} /></label>
        <label>{words("Високий поріг", "High threshold")}<input type="number" min={0.01} max={100} step="any" value={high} onChange={(event) => setHigh(event.target.valueAsNumber || 0)} /></label>
      </div>
      <div className="form-actions"><button className="primary" type="submit" disabled={!result?.consistent || mid >= high || save.isPending}>{words("Зберегти чернетку", "Save draft")}</button></div>
      {save.isSuccess && <p className="inline-status" role="status">{words("Чернетку збережено", "Draft saved")}</p>}
      {save.isError && <Failure error={save.error} showDetail />}
    </form>}
  </Panel>;
}

export function ModelsPage() {
  const t = useText();
  const words = useWords();
  const client = useQueryClient();
  const workspace = useWorkspace();
  const [selection, setSelection] = useState<Baseline["profile"]>("cloud-v2");
  const [days, setDays] = useState(7);
  const bases = useQuery({ queryKey: ["model-baselines"], queryFn: () => data(api.GET("/api/v1/models/baselines")) });
  const versions = useQuery({ queryKey: ["model-drafts"], queryFn: () => data(api.GET("/api/v1/models/drafts")) });
  const shadow = useMutation({
    mutationFn: (version: Version) => data(api.POST("/api/v1/models/drafts/{model_id}/shadow", { params: { path: { model_id: version.id } }, body: { days } })),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["model-drafts"] }),
  });
  const baseline = bases.data?.find((item) => item.profile === selection);
  return <Page title="riskModels">
    <Panel title={words("Базова модель", "Baseline model")} action={<label>{words("Профіль AHP", "AHP profile")} <select value={selection} onChange={(event) => setSelection(event.target.value as Baseline["profile"])}>
      <option>cloud-v2</option><option>core-v1</option>
    </select></label>} />
    {bases.isPending ? <Skeleton /> : bases.isError ? <Failure error={bases.error} /> : baseline && <AhpEditor baseline={baseline} key={baseline.profile} />}
    <Panel title={words("Чернетки й тіньовий режим", "Drafts and shadow evaluation")}
      subtitle={words("Тіньова оцінка порівнює історичні вікна та не створює інцидентів.", "Shadow evaluation compares historical windows without creating incidents.")}
      action={<label>{words("Діб історії", "Days of history")} <input type="number" min={1} max={30} value={days} onChange={(event) => setDays(event.target.valueAsNumber || 1)} /></label>}>
      {versions.isPending ? <Skeleton /> : versions.isError ? <Failure error={versions.error} /> : versions.data.length ? <div className="table-wrap"><table><thead><tr>
        <th>{words("Версія", "Version")}</th><th>{words("Профіль AHP", "AHP profile")}</th><th>CR</th><th>{t("time")}</th><th>{t("action")}</th>
      </tr></thead><tbody>{versions.data.map((version) => <tr key={version.id}>
        <td>{version.name}</td><td><code>{version.profile}</code></td><td>{version.report.cr.toFixed(4)}</td><td><DateTime value={version.created_at} /></td>
        <td>{workspace.source === "demo" && <button onClick={() => shadow.mutate(version)} disabled={shadow.isPending || days < 1 || days > 30}>{words("Тіньовий прогін", "Run shadow")}</button>}</td>
      </tr>)}</tbody></table></div> : <Empty />}
      {shadow.isError && <Failure error={shadow.error} showDetail />}
    </Panel>
    {versions.data?.filter((item) => item.shadow).map((item) => item.shadow && <Panel key={item.id} title={item.name} subtitle={words("Останній тіньовий результат", "Latest shadow result")}>
      <ComparisonTable comparison={item.shadow} />
    </Panel>)}
  </Page>;
}

function TargetsForm({ initial }: { initial: SLASettings }) {
  const words = useWords();
  const t = useText();
  const client = useQueryClient();
  const [settings, setSettings] = useState(initial);
  const [account, setAccount] = useState("");
  const accounts = Array.from(new Set(useWorkspace().identities.map((item) => item.account_id)));
  const selected = (account && settings.accounts?.[account]) || settings;
  const save = useMutation({
    mutationFn: () => data(api.PUT("/api/v1/sla/settings", { body: settings })),
    onSuccess: () => void client.invalidateQueries({ queryKey: ["sla"] }),
  });
  function update(level: "high" | "medium", field: "response" | "resolution", value: number) {
    const changed = {
      high: selected.high, medium: selected.medium,
      [level]: { ...selected[level], [field]: value },
    };
    setSettings(account ? { ...settings, accounts: { ...settings.accounts, [account]: changed } } : { ...settings, ...changed });
  }
  return <form className="settings-form" onSubmit={(event) => { event.preventDefault(); save.mutate(); }}>
    <label>{t("account")}<select value={account} onChange={(event) => setAccount(event.target.value)}>
      <option value="">{t("allAccounts")}</option>{accounts.map((value) => <option key={value}>{value}</option>)}
    </select></label>
    {(["high", "medium"] as const).map((level) => <fieldset key={level} className="settings-fieldset"><legend>{t(level)}</legend>
      <div className="split-inputs">{(["response", "resolution"] as const).map((field) => <label key={field}>
        {field === "response" ? words("Реакція, год", "Response, hours") : words("Вирішення, год", "Resolution, hours")}
        <input type="number" required min={0.01} max={720} step="any" value={selected[level]?.[field] ?? 0} onChange={(event) => update(level, field, event.target.valueAsNumber || 0)} />
      </label>)}</div>
    </fieldset>)}
    <div className="form-actions"><button className="primary" type="submit" disabled={save.isPending}>{t("save")}</button></div>
    {save.isSuccess && <p className="inline-status" role="status">{words("Збережено", "Saved")}</p>}
    {save.isError && <Failure error={save.error} showDetail />}
  </form>;
}

export function SlaPage() {
  const words = useWords();
  const t = useText();
  const intl = useIntl();
  const workspace = useWorkspace();
  const settings = useQuery({ queryKey: ["sla-settings"], queryFn: () => data(api.GET("/api/v1/sla/settings")) });
  const { account, range } = useFilters();
  const query = { account, range: range ?? "7" };
  const cases = new Map(workspace.cases.map((item) => [item.id, item]));
  const report = useQuery({ queryKey: ["sla", query], queryFn: () => data(api.GET("/api/v1/sla", { params: { query } })) });
  return <Page title="sla">
    <Panel title={words("Показники роботи з кейсами", "Case handling metrics")}>
      {report.isPending ? <Skeleton /> : report.isError ? <Failure error={report.error} /> : <div className="panel-content">
        <dl className="ops-weights">
          {[
            [t("openCases"), report.data.open_cases], [words("Прострочена реакція", "Response overdue"), report.data.awaiting_response],
            [words("Прострочене вирішення", "Resolution overdue"), report.data.overdue_resolution],
            ["MTTA · p50", report.data.mtta_median_hours], ["MTTA · p90", report.data.mtta_p90_hours],
            ["MTTR · p50", report.data.mttr_median_hours], ["MTTR · p90", report.data.mttr_p90_hours],
          ].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{typeof value === "number" ? intl.formatNumber(value, { maximumFractionDigits: 2 }) : "—"}</dd></div>)}
          <div><dt>{words("Вирішено вчасно", "Resolved on time")}</dt><dd>{report.data.within_resolution_target == null ? "—" : intl.formatNumber(report.data.within_resolution_target, { style: "percent" })}</dd></div>
        </dl>
        {report.data.overdue.length > 0 && <div className="table-wrap"><table><thead><tr>
          <th>{t("case")}</th><th>{t("account")}</th><th>{t("severity")}</th><th>{words("Порушення", "Breach")}</th>
        </tr></thead><tbody>{report.data.overdue.map((item) => {
          const entry = cases.get(item.case_id);
          const title = entry?.simulation ? words(entry.simulation.title_uk, entry.simulation.title_en) : entry?.identities[0]?.name ?? item.case_id;
          return <tr key={item.case_id}>
          <td><Link className="entity" to="/cases/$id" params={{ id: item.case_id }} search={{ account, range }}>{title}</Link></td><td>{formatAccount(item.account, workspace.source)}</td>
          <td><Badge level={item.level === "high" ? "high" : "medium"} /></td>
          <td>{[item.response_late && words("Реакція", "Response"), item.resolution_late && words("Вирішення", "Resolution")].filter(Boolean).join(" · ")}</td>
        </tr>})}</tbody></table></div>}
      </div>}
    </Panel>
    {workspace.source === "demo" && <Panel title={words("Цілі SLA", "SLA targets")}>
      {settings.isPending ? <Skeleton /> : settings.isError ? <Failure error={settings.error} /> : <TargetsForm initial={settings.data} />}
    </Panel>}
  </Page>;
}

export function QualityPage() {
  const words = useWords();
  const t = useText();
  const intl = useIntl();
  const quality = useQuery({ queryKey: ["quality"], queryFn: () => data(api.GET("/api/v1/quality")) });
  return <Page title="quality">
    {quality.isPending ? <Skeleton /> : quality.isError ? <Failure error={quality.error} /> : <>
      <Panel title={words("Точність за вердиктами", "Verdict-based precision")}
        action={quality.data.recommended && <Link className="panel-link" to="/models" search={{ recommended: quality.data.recommended.threshold }}>{words("Поріг у редакторі", "Open threshold in editor")}</Link>}>
        {quality.data.by_week.length ? <div className="table-wrap"><table><thead><tr>
          <th>{words("Тиждень", "Week")}</th><th>{words("Розмічено", "Labeled")}</th><th>{words("Підтверджено", "Confirmed")}</th><th>{words("Точність", "Precision")}</th>
        </tr></thead><tbody>{quality.data.by_week.map((row) => <tr key={row.starts}>
          <td>{row.starts}</td><td>{row.labeled}</td><td>{row.true_positives}</td><td>{intl.formatNumber(row.precision, { style: "percent" })}</td>
        </tr>)}</tbody></table></div> : <p className="panel-content">{words("Закрийте інциденти з вердиктом, щоб отримати показники точності.", "Close incidents with a verdict to see precision metrics.")}</p>}
        {quality.data.recommended && <p className="panel-content">{words("Рекомендований поріг", "Recommended threshold")} <strong>{quality.data.recommended.threshold}</strong> · F1 {quality.data.recommended.f1.toFixed(3)}</p>}
      </Panel>
      <Panel title={t("incidents")}>
        <dl className="panel-content ops-weights">{Object.entries(quality.data.incidents_by_day).map(([day, count]) => <div key={day}><dt>{day}</dt><dd>{count}</dd></div>)}</dl>
      </Panel>
      {([
        [words("Індикатори хибних спрацювань", "False-positive indicators"), quality.data.false_positive_indicators],
        [words("Факти хибних спрацювань", "False-positive facts"), quality.data.false_positive_facts],
        [words("Причини легітимних аномалій", "Benign anomaly reasons"), quality.data.benign_reasons],
      ] as const).map(([label, values]) => <Panel key={label} title={label}>
        {Object.keys(values).length ? <dl className="panel-content ops-weights">{Object.entries(values).map(([key, value]) =>
          <div key={key}><dt>{key}</dt><dd>{intl.formatNumber(value, { maximumFractionDigits: 2 })}</dd></div>)}</dl> : <Empty />}
      </Panel>)}
    </>}
  </Page>;
}
