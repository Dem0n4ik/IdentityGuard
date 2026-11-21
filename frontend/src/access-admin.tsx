import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, data } from "./api/client";
import type { components } from "./api/schema";
import { Failure, Panel, Skeleton } from "./design-system/primitives";
import { roles, type Role } from "./access";
import { useWords } from "./words";

type User = components["schemas"]["WorkspaceUser"];
const usersKey = ["access-users"];

function Assignment({ user }: { user: User }) {
  const words = useWords();
  const client = useQueryClient();
  const [role, setRole] = useState<Role>(user.role);
  const [scope, setScope] = useState((user.accounts ?? []).join(", "));
  const [invalid, setInvalid] = useState(false);
  const save = useMutation({
    mutationFn: (accounts: string[]) => data(api.PUT("/api/v1/admin/access/{email}", {
      params: { path: { email: user.email } },
      body: { role, accounts },
    })),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: usersKey });
      void client.invalidateQueries({ queryKey: ["session"] });
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    const accounts = role === "admin" ? [] : scope.split(",").map((value) => value.trim()).filter(Boolean);
    const malformed = accounts.some((account) => !/^\d{12}$/.test(account));
    setInvalid(malformed);
    if (!malformed) save.mutate(accounts);
  }

  return <form className="unlock" onSubmit={submit}>
    <p>{user.mfa_enrolled ? words("TOTP підтверджено", "TOTP verified") : words("Очікує першого входу з TOTP", "Awaiting first TOTP sign-in")}</p>
    <label>{words("Роль", "Role")}<select value={role} onChange={(event) => setRole(event.target.value as Role)}>
      {Object.entries(roles).map(([key, label]) => <option key={key} value={key}>{words(label.uk, label.en)}</option>)}
    </select></label>
    <label>{words("Дозволені AWS-акаунти", "Allowed AWS accounts")}
      <input value={role === "admin" ? "" : scope} disabled={role === "admin"} onChange={(event) => setScope(event.target.value)}
        placeholder={words("Усі акаунти", "All accounts")} />
    </label>
    {invalid && <p role="alert">{words("Введіть 12-значні ID через кому.", "Enter twelve-digit account IDs separated by commas.")}</p>}
    {save.isError && <Failure error={save.error} />}
    {save.isSuccess && <p role="status">{words("Доступ оновлено.", "Access updated.")}</p>}
    <button className="primary" disabled={save.isPending}>{words("Зберегти права", "Save access")}</button>
  </form>;
}

export function AccessAdminPage() {
  const words = useWords();
  const users = useQuery({ queryKey: usersKey, queryFn: () => data(api.GET("/api/v1/admin/access")), retry: false });
  return <>
    <header className="page-header"><h1>{words("Керування доступом", "Access management")}</h1></header>
    {users.isPending ? <Skeleton /> : users.isError ? <Failure error={users.error} retry={() => void users.refetch()} /> :
      users.data.map((user) => <Panel title={user.email} key={user.email}><Assignment user={user} /></Panel>)}
  </>;
}
