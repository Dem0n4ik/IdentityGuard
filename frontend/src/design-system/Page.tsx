import type { ReactNode } from "react";
import { useText } from "../i18n";

const intro = {
  notificationIntegrations: "notificationIntegrationsIntro",
  detections: "detectionsIntro", suppressions: "suppressionsIntro", riskModels: "riskModelsIntro",
  sla: "slaIntro", quality: "qualityIntro", attackPaths: "attackPathsIntro", cloudConfig: "cloudConfigIntro",
  roleChains: "roleChainsIntro",
  overview: "overviewIntro", cases: "caseIntro", incidents: "incidentIntro", identities: "identityIntro",
  profile: "profileIntro", awsIntegration: "awsIntegrationIntro", assistant: "assistantIntro",
  hunt: "huntIntro", sources: "sourceIntro", audit: "auditIntro",
} as const;

export function Page({ title, children }: { title: keyof typeof intro; children: ReactNode }) {
  const t = useText();
  return <><header className="page-header">
    <div className="breadcrumbs">{t("work")} <span>/</span> {t(title)}</div>
    <h1>{t(title)}</h1><p>{t(intro[title])}</p>
  </header>{children}</>;
}
