import { useQuery } from "@tanstack/react-query";
import { useIntl } from "react-intl";
import { api, data, type Incident } from "./api/client";
import { Badge, Failure, Panel, Skeleton, localName } from "./design-system/primitives";
import { useText } from "./i18n";
import { useWords } from "./words";
import { DateTime } from "./workspace";

export function IncidentTracePanel({ incident }: { incident: Incident }) {
  const words = useWords();
  const t = useText();
  const intl = useIntl();
  const result = useQuery({
    queryKey: ["incident-trace", incident.id, incident.version],
    queryFn: () => data(api.GET("/api/v1/incidents/{incident_id}/trace", { params: { path: { incident_id: incident.id } } })),
  });
  const format = (value: number, digits = 2) => intl.formatNumber(value, { maximumFractionDigits: digits });
  const label = (value: string) => {
    const key = localName(value === "ip" || value === "time" ? value + "_factor" : value);
    return key ? t(key) : value;
  };
  const trace = result.data;
  const events = new Map(trace?.events.map((event) => [event.event_id, event]));
  return <Panel title={words("Докази розрахунку ризику", "Risk calculation evidence")} subtitle={incident.model_version}>
    {result.isPending ? <Skeleton /> : result.isError ? <Failure error={result.error} retry={() => void result.refetch()} /> : trace && <>
      <div className="trace-overview">
        <div><span>{words("Без контексту · M = 1", "Without context · M = 1")}</span><strong>{format(trace.behavior_without_context)} / 100</strong><Badge level={trace.without_context_level} /></div>
        <div><span>{words("З контекстом", "With context")}</span><strong>{format(incident.risk)} / 100</strong><Badge level={incident.level} /></div>
        <div><span>{words("Внесок контексту", "Context uplift")}</span><strong>+{format(trace.context_uplift)}</strong><small>{words("балів ризику", "risk points")}</small></div>
        <div><span>{words("Пороги рішення", "Decision thresholds")}</span><strong>{format(trace.medium_threshold)} / {format(trace.high_threshold)}</strong><small>{words("середній / високий", "medium / high")}</small></div>
      </div>
      <div className="trace-description">
        {trace.policy_override && <p>{trace.policy_override === "root"
          ? words("Політика root примусово встановлює високий рівень. Числова оцінка зберігається.", "The root policy forces high severity and preserves the numeric score.")
          : words("Політика аварійного доступу встановлює високий рівень.", "The break-glass policy forces high severity.")}</p>}
        {trace.uncapped_risk > 100 && <p>{words("Оцінку обмежено значенням 100.", "The score is capped at 100.")}</p>}
        <div className="pills">{Object.entries(trace.fact_weights).map(([fact, weight]) =>
          <span key={fact} className="pill">{label(fact)} +{format(weight)}</span>)}</div>
        {trace.baseline ? <div className="trace-history">
          <strong>{words("Поведінковий профіль до оцінки", "Behavior profile before scoring")}</strong>
          <span>{words("Подій у профілі", "Profile events")} {format(trace.baseline.baseline_events, 0)} · {words("активних днів", "active days")} {trace.baseline.baseline_days}</span>
          <span>{words("Середнє за годину", "Hourly mean")} {trace.baseline.mean == null ? "—" : format(trace.baseline.mean)} · σ {trace.baseline.std == null ? "—" : format(trace.baseline.std)}</span>
          <span>{words("Знімок стану", "Posture snapshot")} {trace.baseline.snapshot_at ? <DateTime value={trace.baseline.snapshot_at} /> : "—"}</span>
        </div> : <p>{words("Цей запис створено до збереження профілю в журналі розрахунку.", "This record predates capture of the behavior profile in the scoring trace.")}</p>}
      </div>
      <div className="table-wrap"><table>
        <caption>{words("Внески в поведінкову оцінку B", "Contributions to behavior score B")}</caption>
        <thead><tr><th>{words("Індикатор", "Indicator")}</th><th className="num">x</th><th className="num">{words("Вага", "Weight")}</th>
          <th className="num">{words("Внесок", "Contribution")}</th><th>{words("Подія з максимумом", "Event with peak signal")}</th>
        </tr></thead>
        <tbody>{trace.signals.map((row) => {
          const event = row.event_id ? events.get(row.event_id) : undefined;
          return <tr key={row.indicator}><td>{label(row.indicator)}</td><td className="num mono">{format(row.value, 3)}</td>
            <td className="num mono">{format(row.weight, 4)}</td><td className="num mono">{format(row.contribution, 4)}</td>
            <td>{event ? <span><code>{event.operation}</code> · <DateTime value={event.time} /></span> : "—"}</td></tr>;
        })}</tbody>
      </table></div>
    </>}
  </Panel>;
}
