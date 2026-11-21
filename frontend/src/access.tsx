import { createContext, useContext, useState, type FormEvent } from "react";
import { api, data, setCsrf } from "./api/client";
import { useWords } from "./words";

export const roles = {
  admin: { uk: "Адміністратор", en: "Administrator" },
  analyst: { uk: "Аналітик", en: "Analyst" },
  detection_engineer: { uk: "Інженер детекцій", en: "Detection engineer" },
  viewer: { uk: "Спостерігач", en: "Viewer" },
} as const;

export type Role = keyof typeof roles;

export const Access = createContext<{ role?: Role; scoped: boolean }>({ scoped: false });
export const useAccess = () => useContext(Access);

const adminPages = new Set([
  "/audit", "/profile", "/sources", "/integrations/aws", "/integrations/notifications", "/suppressions",
]);

const scopedPages = new Set(["/", "/cases", "/incidents", "/identities", "/hunt"]);

export function canVisit(role: Role | undefined, path: string, scoped = false) {
  if (scoped) return scopedPages.has(path) || ["/cases/", "/incidents/", "/identities/"].some((prefix) => path.startsWith(prefix));
  if (!role || role === "admin") return true;
  if (adminPages.has(path) || path === "/admin" || path.startsWith("/admin/")) return false;
  return !["/detections", "/models"].includes(path) || role === "detection_engineer";
}

export function Login({ unlocked }: { unlocked: () => Promise<unknown> }) {
  const words = useWords();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function authenticate(event: FormEvent) {
    event.preventDefault();
    setError("");
    setPending(true);
    try {
      if (challenge) {
        const result = await data(api.POST("/api/v1/auth/verify", { body: { challenge, code } }));
        setCsrf(result.csrf);
        await unlocked();
      } else {
        const result = await data(api.POST("/api/v1/auth/login", { body: { email, password } }));
        setPassword("");
        setChallenge(result.challenge);
      }
    } catch {
      setError(challenge
        ? words("Код неправильний або прострочений.", "The verification code is incorrect or expired.")
        : words("Не вдалося увійти з цими даними.", "Could not sign in with these credentials."));
    } finally {
      setPending(false);
    }
  }

  return <form className="unlock panel" onSubmit={(event) => void authenticate(event)}>
    <h1>{challenge ? words("Двофакторна перевірка", "Two-factor verification") : words("Вхід до IdentityGuard", "Sign in to IdentityGuard")}</h1>
    {challenge ? <label>{words("Код з автентифікатора або резервний код", "Authenticator or recovery code")}
      <input autoComplete="one-time-code" required maxLength={64} value={code} onChange={(event) => setCode(event.target.value)} />
    </label> : <>
      <label>{words("Електронна пошта", "Email")}<input type="email" autoComplete="username" required maxLength={254} value={email} onChange={(event) => setEmail(event.target.value)} /></label>
      <label>{words("Пароль", "Password")}<input type="password" autoComplete="current-password" required maxLength={512} value={password} onChange={(event) => setPassword(event.target.value)} /></label>
    </>}
    {error && <p role="alert">{error}</p>}
    <button className="primary" disabled={pending}>{challenge ? words("Перевірити код", "Verify code") : words("Увійти", "Sign in")}</button>
    {challenge && <button type="button" disabled={pending} onClick={() => { setChallenge(""); setCode(""); setError(""); }}>
      {words("Повернутися до входу", "Back to sign in")}
    </button>}
  </form>;
}
