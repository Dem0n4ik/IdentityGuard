import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowUpRight, Sparkles } from "lucide-react";
import { api, data, type Case } from "./api/client";
import { Badge, Empty, Failure, Panel, Skeleton } from "./design-system/primitives";
import { Page } from "./design-system/Page";
import { useText } from "./i18n";
import { useAccess } from "./access";
import { DateTime, usePreferences, useWorkspace } from "./workspace";

const assistantKey = ["assistant"];
const getStatus = () => data(api.GET("/api/v1/assistant"));

export function CaseAnalysisPanel({ item }: { item: Case }) {
  const t = useText();
  const { role } = useAccess();
  const { prefs: { language } } = usePreferences();
  const client = useQueryClient();
  const [consent, setConsent] = useState(false);
  const status = useQuery({ queryKey: assistantKey, queryFn: getStatus });
  const queryKey = ["case-analysis", item.id, language];
  const analysis = useQuery({
    queryKey,
    queryFn: () => data(api.GET("/api/v1/cases/{case_id}/analysis", { params: { path: { case_id: item.id }, query: { language } } })),
  });
  const generate = useMutation({
    mutationFn: (locale: typeof language) => data(api.POST("/api/v1/cases/{case_id}/analysis", {
      params: { path: { case_id: item.id } }, body: { language: locale, consent: true },
    })),
    onSuccess: (result, locale) => {
      client.setQueryData(["case-analysis", item.id, locale], result);
      setConsent(false);
    },
  });
  return <Panel title={t("assistant")} subtitle={t("caseAnalysisHint")}
    action={analysis.data && <span className="pill">{t(analysis.data.source === "anthropic" ? "analysisAi" : "analysisTemplate")}</span>}>
    {analysis.isPending ? <Skeleton /> : analysis.isError ? <Failure error={analysis.error} retry={() => void analysis.refetch()} /> :
      <div className="analysis-content">
        <div className="analysis-summary">
          <p>{analysis.data.summary}</p>
          <span className="pill">{t(analysis.data.verdict)}</span>
        </div>
        <div className="analysis-details">
          <div><h3>{t("nextSteps")}</h3><ol>{analysis.data.next_steps.map((step, index) => <li key={index}>{step}</li>)}</ol>
            {analysis.data.mitre.length > 0 && <div className="pills" aria-label="MITRE ATT&CK">{analysis.data.mitre.map((technique) => <code className="pill" key={technique}>{technique}</code>)}</div>}
          </div>
          <div><h3>{t("ownerDraft")}</h3><p>{analysis.data.owner_message}</p></div>
        </div>
        {analysis.data.model && <p className="secondary"><code>{analysis.data.model}</code>{analysis.data.created_at && <> · <DateTime value={analysis.data.created_at} /></>}</p>}
      </div>}
    {(!role || role === "admin") && <div className="analysis-actions">
      {status.isError ? <Failure error={status.error} retry={() => void status.refetch()} /> : status.data?.enabled ?
        <>
          <label className="checkbox"><input type="checkbox" checked={consent} onChange={(event) => setConsent(event.target.checked)} />{t("aiConsent")}</label>
          <button className="primary" disabled={!consent || generate.isPending} onClick={() => generate.mutate(language)}>
            {t(generate.isPending ? "generatingAi" : "generateAi")}
          </button>
          {generate.isError && <Failure error={generate.error} />}
        </> : !status.isPending && <p className="secondary">{t("aiOffHint")}</p>}
    </div>}
  </Panel>;
}

export function AssistantPage() {
  const t = useText();
  const { cases } = useWorkspace();
  const [selection, setSelection] = useState("");
  const selected = cases.find((item) => item.id === selection) ?? cases[0];
  const status = useQuery({ queryKey: assistantKey, queryFn: getStatus });
  return <Page title="assistant">
    <Panel title={t("assistantStatus")} action={<span className="pill"><Sparkles size={13} /> {t(status.data?.enabled ? "aiOn" : "aiOff")}</span>}>
      <div className="settings-form">
        {status.isError ? <Failure error={status.error} retry={() => void status.refetch()} /> :
          status.isPending ? <Skeleton /> : status.data.enabled ? <p><code>{status.data.model}</code></p> :
          <p className="secondary">{t("aiOffHint")}</p>}
        {selected && <label>{t("case")}<select value={selected.id} onChange={(event) => setSelection(event.target.value)}>
          {cases.map((item) => <option key={item.id} value={item.id}>
            {item.identities.map((identity) => identity.name).join(" · ")} · {new Date(item.updated).toISOString().slice(0, 16)} UTC
          </option>)}
        </select></label>}
        {selected && <div className="form-actions"><Badge level={selected.level} /><Link to="/cases/$id" params={{ id: selected.id }} className="panel-link">{t("openCase")}<ArrowUpRight size={14} /></Link></div>}
      </div>
    </Panel>
    {selected ? <CaseAnalysisPanel item={selected} key={selected.id} /> : <Empty />}
  </Page>;
}
