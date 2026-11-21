import createClient from "openapi-fetch";
import type { components, paths } from "./schema";

export type Incident = components["schemas"]["Incident"];
export type Case = components["schemas"]["Case"];
export type Overview = components["schemas"]["Overview"];
export type Identity = components["schemas"]["IdentitySummary"];
export type Event = components["schemas"]["TrailEvent"];
export type IncidentUpdate = components["schemas"]["IncidentUpdate"];

export type Profile = components["schemas"]["Profile"];
export type AwsSettings = components["schemas"]["AwsSettings"];
export type AwsWorkspace = components["schemas"]["AwsWorkspace"];

let token = "";
let csrf = "";

export function setCsrf(value: string) {
  csrf = value;
}

export function setToken(value: string) {
  token = value;
}

export function requestHeaders(): Record<string, string> {
  return {
    "X-IdentityGuard-Local": "1",
    ...(token ? { Authorization: "Bearer " + token } : {}),
    ...(csrf ? { "X-CSRF-Token": csrf } : {}),
  };
}

export const api = createClient<paths>();
api.use({ onRequest({ request }) {
  Object.entries(requestHeaders()).forEach(([key, value]) => request.headers.set(key, value));
  return request;
} });

export class ApiError extends Error {
  constructor(readonly status: number, readonly requestId: string | null, readonly detail?: string) {
    super("API request failed");
  }
}

export async function data<T>(request: Promise<{ data?: T; response: Response }>): Promise<T> {
  const result = await request;
  if (result.data === undefined) {
    const error = "error" in result ? result.error : undefined;
    const detail = error && typeof error === "object" && "detail" in error && typeof error.detail === "string" ? error.detail : undefined;
    throw new ApiError(result.response.status, result.response.headers.get("X-Request-ID"), detail);
  }
  return result.data;
}
