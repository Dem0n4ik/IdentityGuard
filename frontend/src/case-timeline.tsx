import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { api, data, type Case } from "./api/client";
import { Empty, Failure, Panel, Skeleton } from "./design-system/primitives";
import { useText } from "./i18n";
import { useWords } from "./words";
import { DateTime, useFilters } from "./workspace";

export function CaseTimelinePanel({ item }: { item: Case }) {
  const words = useWords();
  const t = useText();
  const intl = useIntl();
  const filters = useFilters();
  const result = useQuery({
    queryKey: ["case-timeline", item.id, item.incidents.map(({ id, version }) => [id, version])],
    queryFn: () => data(api.GET("/api/v1/cases/{case_id}/timeline", { params: { path: { case_id: item.id } } })),
  });
  const timeline = result.data;
  const transitions = timeline?.items.filter((entry) => entry.role_transition) ?? [];
  return <Panel title={words("Хронологія кейсу", "Case timeline")}
    subtitle={words("Події з часових вікон, які сформували цей кейс", "Events from the scored windows in this case")}>
    {result.isPending ? <Skeleton /> : result.isError ? <Failure error={result.error} retry={() => void result.refetch()} />
      : !timeline?.items.length ? <Empty /> : <>
        {transitions.length > 0 && <div className="case-transitions">
          <h3>{words("Успішні переходи між ролями", "Successful role transitions")} · {transitions.length}</h3>
          <ol>{transitions.map(({ event }) => {
            const targetAccount = event.target.split(":")[4];
            const targetRole = event.target.split("/").at(-1);
            return <li key={event.event_id}>
              <span className="mono">{event.identity?.name} <small>{event.identity?.account_id}</small></span>
              <span aria-hidden="true"> → </span>
              <span className="mono">{targetRole} <small>{targetAccount}</small></span>
            </li>;
          })}</ol>
        </div>}
        {timeline.total > timeline.items.length && <p className="case-event-note secondary">{words(
          `Показано ${timeline.items.length} із ${timeline.total} подій. Пріоритет мають успішні переходи й найбільші поведінкові сигнали.`,
          `Showing ${timeline.items.length} of ${timeline.total} events, prioritizing successful transitions and the strongest behavioral signals.`,
        )}</p>}
        <div className="table-wrap"><table>
          <caption>{words("Хмарні операції", "Cloud operations")} · {timeline.total}</caption>
          <thead><tr>
            <th>{t("time")}</th><th>{t("identity")}</th><th>{words("Операція", "Operation")}</th>
            <th>{words("Ціль", "Target")}</th><th>{words("Регіон · IP", "Region · IP")}</th>
            <th className="num">{words("B події", "Event B")}</th>
          </tr></thead>
          <tbody>{timeline.items.map(({ incident_id, behavior, event }) => <tr key={event.event_id}>
            <td><DateTime value={event.time} /></td>
            <td><Link className="entity" to="/incidents/$id" params={{ id: incident_id }} search={filters}>
              {event.identity?.name ?? event.account_id}
            </Link></td>
            <td><code>{event.name}</code>{event.error_code && <small className="case-cell-detail">{event.error_code}</small>}</td>
            <td className="case-event-target"><code>{event.target || "—"}</code></td>
            <td><span>{event.region || "—"}</span>{event.source_ip && <small className="case-cell-detail mono">{event.source_ip}</small>}</td>
            <td className="num mono">{intl.formatNumber(behavior, { style: "percent", maximumFractionDigits: 1 })}</td>
          </tr>)}</tbody>
        </table></div>
      </>}
  </Panel>;
}
