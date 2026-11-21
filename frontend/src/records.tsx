import { useEffect, useState, type FormEvent } from "react";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ApiError, api, data, requestHeaders, type Event } from "./api/client";
import { Empty, Failure, Panel, Skeleton } from "./design-system/primitives";
import { useText } from "./i18n";
import { useWords } from "./words";
import { Page } from "./design-system/Page";
import { DateTime, actorId, useFilters, useWorkspace } from "./workspace";

function EventTable({ events }: { events: Event[] }) {
  const t = useText();
  if (!events.length) return <Empty />;
  return <div className="table-wrap"><table><thead><tr>
    <th>{t("time")}</th><th>{t("event")}</th><th>{t("identity")}</th><th>{t("region")}</th><th>{t("ip")}</th><th>{t("category")}</th><th>{t("key")}</th>
  </tr></thead><tbody>{events.map((item) => <tr key={item.event_id}>
    <td><DateTime value={item.time} /></td><td><code>{item.name}</code></td>
    <td>{item.identity ? <Link to="/identities/$id" params={{ id: actorId(item.identity) }} className="entity">{item.identity.name}</Link> : "—"}</td>
    <td><code>{item.region}</code></td><td><code>{item.source_ip}</code></td><td>{item.category}</td><td><code>{item.access_key_id || "—"}</code></td>
  </tr>)}</tbody></table></div>;
}

export function HuntPage() {
  const t = useText();
  const words = useWords();
  const workspace = useWorkspace();
  const filters = useFilters();
  const navigate = useNavigate({ from: "/hunt" });
  const [operation, setOperation] = useState(filters.operation ?? "");
  const [region, setRegion] = useState(filters.region ?? "");
  const [category, setCategory] = useState(filters.category ?? "");
  useEffect(() => setOperation(filters.operation ?? ""), [filters.operation]);
  useEffect(() => setRegion(filters.region ?? ""), [filters.region]);
  useEffect(() => setCategory(filters.category ?? ""), [filters.category]);
  const since = filters.range === "all" ? undefined : new Date(new Date(workspace.now).getTime() - Number(filters.range ?? "7") * 86400000).toISOString();
  const query = { account: filters.account, identity: filters.identity, operation: filters.operation, region: filters.region, category: filters.category, cursor: filters.cursor, since, limit: 50 };
  const result = useQuery({ queryKey: ["events", query], queryFn: () => data(api.GET("/api/v1/events", { params: { query } })), placeholderData: keepPreviousData });
  function submit(event: FormEvent) {
    event.preventDefault();
    void navigate({ to: ".", search: () => ({ ...filters, operation: operation.trim() || undefined, region: region.trim() || undefined, category: category || undefined, cursor: undefined }) });
  }
  return <Page title="hunt"><Panel title={t("hunt")} subtitle={result.data?.engine === "clickhouse"
    ? words("ClickHouse · індексовані події", "ClickHouse · indexed events")
    : result.data ? words("Локальна історія подій", "Local event history") : undefined} action={<form className="filters hunt-filters" onSubmit={submit}>
    <input aria-label={t("searchEvents")} placeholder="GetObject" value={operation} maxLength={128} onChange={(event) => setOperation(event.target.value)} />
    <input aria-label={t("region")} placeholder="eu-central-1" value={region} maxLength={50} onChange={(event) => setRegion(event.target.value)} />
    <select aria-label={t("category")} value={category} onChange={(event) => setCategory(event.target.value)}>
      <option value="">{words("Усі категорії", "All categories")}</option>
      {["Management", "Data", "NetworkActivity", "Insight"].map((value) => <option key={value}>{value}</option>)}
    </select>
    <button>{t("filter")}</button>
  </form>}>
    {filters.identity && <div className="filter-summary"><span className="pill">{filters.identity}</span><button onClick={() =>
      void navigate({ to: ".", search: () => ({ ...filters, identity: undefined, cursor: undefined }) })}>{t("close")}</button></div>}
    {result.isPending ? <Skeleton /> : result.isError ? <Failure error={result.error} retry={() => void result.refetch()} /> : <>
      <EventTable events={result.data.items} />
      {(filters.cursor || result.data.next_cursor) && <div className="pagination">
        <button disabled={!filters.cursor} onClick={() => void navigate({ to: ".", search: () => ({ ...filters, cursor: undefined }) })}>{t("first")}</button>
        <button disabled={!result.data.next_cursor || result.isFetching}
          onClick={() => void navigate({ to: ".", search: () => ({ ...filters, cursor: result.data.next_cursor ?? undefined }) })}>{t("next")}</button>
      </div>}</>}
  </Panel></Page>;
}

function PipelineStatus() {
  const words = useWords();
  const result = useQuery({ queryKey: ["pipeline-status"], queryFn: () => data(api.GET("/api/v1/pipeline")), refetchInterval: 10000 });
  return <Panel title={words("Стан конвеєра подій", "Event pipeline status")}>
    {result.isPending ? <Skeleton /> : result.isError ? <Failure error={result.error} /> : <dl className="panel-content ops-weights">
      <div><dt>Kafka</dt><dd>{result.data.kafka_configured ? words("Налаштовано", "Configured") : words("Локальний режим", "Local mode")}</dd></div>
      <div><dt>Temporal</dt><dd>{result.data.temporal_configured ? words("Налаштовано", "Configured") : words("Локальний режим", "Local mode")}</dd></div>
      <div><dt>{words("У черзі", "Pending outbox")}</dt><dd>{result.data.outbox_pending}</dd></div>
      <div><dt>{words("Опубліковано", "Published")}</dt><dd>{result.data.outbox_published}</dd></div>
      <div><dt>ClickHouse</dt><dd>{result.data.clickhouse_events ?? "—"}</dd></div>
      <div><dt>{words("Оцінено до", "Scored through")}</dt><dd>{result.data.scoring_through ? <DateTime value={result.data.scoring_through} /> : "—"}</dd></div>
    </dl>}
  </Panel>;
}

export function SourcesPage() {
  const t = useText();
  const workspace = useWorkspace();
  const client = useQueryClient();
  const [file, setFile] = useState<File>();
  const upload = useMutation({
    mutationFn: async (value: File) => {
      const response = await fetch("/api/v1/sources/upload", { method: "POST", body: value,
        headers: { ...requestHeaders(), "Content-Type": "application/octet-stream" } });
      if (!response.ok) throw new ApiError(response.status, response.headers.get("X-Request-ID"));
      return (await response.json()) as { inserted: number };
    },
    onSuccess: () => client.invalidateQueries(),
  });
  return <Page title="sources"><PipelineStatus /><Panel title={t("awsIntegration")} subtitle={t("awsIntegrationIntro")} action={<Link className="panel-link" to="/integrations/aws">{t("awsIntegration")}</Link>} />{workspace.source === "aws" ?
    <Panel title={t("awsReadOnly")}><p className="panel-content">{t("awsScope")}</p></Panel> :
    <Panel title={t("sourceStatus")} subtitle={t("fileHint")}><form className="panel-content upload-form" onSubmit={(event) => { event.preventDefault(); if (file) upload.mutate(file); }}>
      <label>{t("chooseFile")}<input type="file" accept=".json,.gz" onChange={(event) => setFile(event.target.files?.[0])} /></label>
      <button type="submit" className="primary" disabled={!file || upload.isPending}>{t(upload.isPending ? "importing" : "import")}</button>
      {upload.isSuccess && <span role="status">{t("imported", { count: upload.data.inserted })}</span>}
      {upload.isError && <Failure error={upload.error} />}
    </form></Panel>}</Page>;
}

export function AuditPage() {
  const t = useText();
  const result = useQuery({ queryKey: ["audit"], queryFn: () => data(api.GET("/api/v1/audit")) });
  return <Page title="audit">{result.isPending ? <Skeleton /> : result.isError ? <Failure error={result.error} /> :
    <Panel title={t(result.data.valid ? "integrity" : "integrityFail")}>
      {result.data.items.length ? <div className="table-wrap"><table><thead><tr><th>#</th><th>{t("time")}</th><th>{t("action")}</th><th>{t("target")}</th><th>SHA-256</th></tr></thead><tbody>
        {result.data.items.map((row) => <tr key={row.seq}><td className="mono">{row.seq}</td><td><DateTime value={row.at} /></td><td><code>{row.action}</code></td><td><code>{row.target}</code></td><td><code title={row.hash}>{row.hash.slice(0, 16)}</code></td></tr>)}
      </tbody></table></div> : <Empty />}
    </Panel>}</Page>;
}
