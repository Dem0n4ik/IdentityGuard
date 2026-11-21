import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, data } from "./api/client";
import { Failure, Panel, Skeleton } from "./design-system/primitives";
import { Page } from "./design-system/Page";
import { useText } from "./i18n";
import { useWords } from "./words";
import { DateTime, useWorkspace } from "./workspace";

function WebhookForm({ saved, secret }: { saved: string | null; secret: boolean }) {
  const words = useWords();
  const t = useText();
  const client = useQueryClient();
  const { source } = useWorkspace();
  const [url, setUrl] = useState(saved ?? "");
  const save = useMutation({
    mutationFn: () => data(api.PUT("/api/v1/integrations/webhook", { body: { url: url.trim() } })),
    onSuccess: (result) => client.setQueryData(["webhook"], result),
  });
  const deliver = useMutation({ mutationFn: () => data(api.POST("/api/v1/integrations/webhook/test")) });
  return <div className="settings-form">
    {source === "demo" && <form className="settings-layout" onSubmit={(event) => { event.preventDefault(); save.mutate(); }}>
      <label className="webhook-input">{words("HTTPS-адреса", "HTTPS endpoint")}
        <input type="url" required value={url} maxLength={512} onChange={(event) => setUrl(event.target.value)} />
      </label>
      <button className="primary" type="submit" disabled={save.isPending}>{t("save")}</button>
    </form>}
    {!secret && <p className="secondary">{words("Для підпису налаштуйте IG_WEBHOOK_SECRET у середовищі сервера.", "Set IG_WEBHOOK_SECRET in the server environment to sign deliveries.")}</p>}
    {source === "demo" && <div className="form-actions">
      <button disabled={!secret || !saved || deliver.isPending || saved !== url.trim()} onClick={() => deliver.mutate()}>{words("Надіслати тестову подію", "Send test event")}</button>
      {save.isSuccess && <span className="inline-status" role="status">{words("Адресу збережено", "Endpoint saved")}</span>}
    </div>}
    {deliver.data && <p role="status">{deliver.data.delivered ? words("Доставлено", "Delivered") : words("Одержувач відхилив", "Rejected by endpoint")} · HTTP {deliver.data.status} · <DateTime value={deliver.data.sent_at} /></p>}
    {(save.isError || deliver.isError) && <Failure error={save.error ?? deliver.error} showDetail />}
  </div>;
}

export function NotificationsPage() {
  const words = useWords();
  const result = useQuery({ queryKey: ["webhook"], queryFn: () => data(api.GET("/api/v1/integrations/webhook")) });
  return <Page title="notificationIntegrations"><Panel title="HTTPS webhook"
    subtitle={words("Тестова доставка містить HMAC-підпис та синтетичну подію.", "Test deliveries contain an HMAC signature and a synthetic event.")}>
    {result.isPending ? <Skeleton /> : result.isError ? <Failure error={result.error} /> : <WebhookForm saved={result.data.url} secret={result.data.secret_configured} />}
  </Panel></Page>;
}
