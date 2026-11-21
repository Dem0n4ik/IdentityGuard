import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { useSearch } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { z } from "zod";
import type { Incident, Overview } from "./api/client";

export const filterSchema = z.object({
  caseId: z.string().max(350).optional().catch(undefined),
  recommended: z.coerce.number().int().min(20).max(80).optional().catch(undefined),
  account: z.string().regex(/^\d{12}$/).optional().catch(undefined),
  range: z.enum(["7", "30", "all"]).optional().catch(undefined),
  level: z.enum(["high", "medium", "low"]).optional().catch(undefined),
  state: z.enum(["open", "closed", "all"]).optional().catch(undefined),
  identity: z.string().max(350).optional().catch(undefined),
  operation: z.string().max(128).optional().catch(undefined),
  region: z.string().max(50).optional().catch(undefined),
  category: z.string().max(30).optional().catch(undefined),
  cursor: z.string().max(1024).optional().catch(undefined),
});
export const useFilters = () => useSearch({ strict: false });
export type Filters = z.infer<typeof filterSchema>;
export const Workspace = createContext<Overview | null>(null);

export function useWorkspace() {
  const workspace = useContext(Workspace);
  if (!workspace) throw new Error("Workspace data unavailable");
  return workspace;
}

export function actorId(actor: Incident["identity"]) {
  return [actor.account_id, actor.kind, actor.name].join(":");
}

const demoAccounts: Record<string, string> = {
  "111122223333": "production",
  "222233334444": "shared-services",
  "111000001001": "engineering-sandbox",
  "111000001002": "delivery-platform",
  "111000001003": "customer-data",
  "111000001004": "payments-production",
  "111000001005": "security-and-audit",
};

export function formatAccount(id: string, source: Overview["source"]) {
  return source === "demo" ? demoAccounts[id] ?? id : id;
}

const schema = z.object({ language: z.enum(["uk", "en"]), theme: z.enum(["dark", "light"]), compact: z.boolean(), localTime: z.boolean() });
type Prefs = z.infer<typeof schema>;
const defaults: Prefs = { language: "uk", theme: "dark", compact: false, localTime: false };
const Context = createContext({ prefs: defaults, update: (_value: Partial<Prefs>) => {} });

function ProviderComponent({ children }: { children: ReactNode }) {
  const [prefs, setPrefs] = useState(() => {
    try { return schema.parse({ ...defaults, ...JSON.parse(localStorage.getItem("identityguard.preferences") ?? "{}") }); }
    catch { return defaults; }
  });
  useEffect(() => {
    document.documentElement.lang = prefs.language;
    document.documentElement.dataset.theme = prefs.theme;
    document.documentElement.dataset.compact = String(prefs.compact);
    localStorage.setItem("identityguard.preferences", JSON.stringify(prefs));
  }, [prefs]);
  return <Context.Provider value={{ prefs, update: (value) => setPrefs((old) => ({ ...old, ...value })) }}>{children}</Context.Provider>;
}

export const Preferences = { ProviderComponent };
export function usePreferences() { return useContext(Context); }

export function DateTime({ value }: { value: string }) {
  const intl = useIntl();
  const { prefs } = usePreferences();
  return <time dateTime={value} title={new Date(value).toISOString()}>
    {intl.formatDate(value, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", ...(!prefs.localTime ? { timeZone: "UTC" } : {}) })}
  </time>;
}
