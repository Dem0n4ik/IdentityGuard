import { AlertCircle, ArrowUpRight, FolderSearch } from "lucide-react";
import type { ReactNode } from "react";
import { useIntl } from "react-intl";
import { ApiError, type Incident } from "../api/client";
import { en, useText, type Message } from "../i18n";

export function Badge({ level }: { level: Incident["level"] }) {
  const t = useText();
  return <span className={"badge " + level}><span aria-hidden="true" className="badge-dot" />{t(level)}</span>;
}

export function Empty() {
  const t = useText();
  return <div className="empty"><FolderSearch size={24} /><strong>{t("empty")}</strong><span>{t("emptyHint")}</span></div>;
}

export function Failure({ error, retry, showDetail }: { error: unknown; retry?: () => void; showDetail?: boolean }) {
  const t = useText();
  return <div className="empty" role="alert">
    <AlertCircle size={24} /><strong>{t("failed")}</strong>
    {showDetail && error instanceof ApiError && error.detail && <p>{error.detail}</p>}
    {error instanceof ApiError && error.requestId && <code>{error.requestId}</code>}
    {retry && <button type="button" onClick={retry}>{t("retry")}</button>}
  </div>;
}

export function Skeleton() {
  const t = useText();
  return <div className="skeleton" role="status" aria-label={t("loading")}>
    <div /><div /><div /><div /><div />
  </div>;
}

export function Panel({ title, subtitle, action, children }: { title: string; subtitle?: string; action?: ReactNode; children?: ReactNode }) {
  return <section className="panel">
    <header className="panel-head"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</header>
    {children}
  </section>;
}

export function Tile({ label, value, detail, children }: { label: string; value: number; detail?: ReactNode; children: ReactNode }) {
  const intl = useIntl();
  return <div className="tile">
    <span>{label}</span><strong>{intl.formatNumber(value)}</strong>
    <div>{detail}</div>
    <span className="tile-link">{children}<ArrowUpRight size={13} aria-hidden="true" /></span>
  </div>;
}

export function localName(value: string): Message | null {
  return Object.hasOwn(en, value) ? (value as Message) : null;
}

export function Risk({ incident }: { incident: Incident }) {
  const intl = useIntl();
  const t = useText();
  const contributions = Object.entries(incident.contributions).sort((a, b) => b[1] - a[1]);
  return <div className="risk">
    <div className="equation">
      <div><span>{t("behavior")}</span><strong>{intl.formatNumber(incident.behavior, { style: "percent", maximumFractionDigits: 1 })}</strong></div>
      <span aria-hidden="true">×</span>
      <div><span>{t("context")}</span><strong>{intl.formatNumber(incident.modifier, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</strong></div>
      <span aria-hidden="true">=</span>
      <div><span>{t("score")}</span><strong>{intl.formatNumber(incident.risk, { maximumFractionDigits: 1 })}<small> / 100</small></strong></div>
    </div>
    <p className="explanation">{intl.locale === "uk" ? incident.explanation_uk : incident.explanation_en}</p>
    <div className="risk-columns">
      <div>{contributions.map(([name, value]) => {
        const label = localName(name === "ip" || name === "time" ? name + "_factor" : name);
        return <div className="contribution" key={name}><span>{label ? t(label) : name}</span>
          <progress value={value} max={1} aria-label={label ? t(label) : name} />
          <span>{intl.formatNumber(value, { style: "percent", maximumFractionDigits: 0 })}</span>
        </div>;
      })}</div>
      <div className="pills">{incident.facts.length ? incident.facts.map((fact) => {
        const label = localName(fact);
        return <span key={fact} className="pill">{label ? t(label) : fact}</span>;
      }) : <span>{t("noFactors")}</span>}</div>
    </div>
  </div>;
}
