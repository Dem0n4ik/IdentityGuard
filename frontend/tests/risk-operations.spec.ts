import { expect, test } from "@playwright/test";

test("FR-PATH shows access routes, mandatory links and a template explanation", async ({ page }) => {
  await page.goto("/attack-paths");
  await expect(page.getByRole("heading", { name: "Шляхи атак", exact: true })).toBeVisible();
  await expect(page.getByText("Шаблонне пояснення", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "ig-demo-customer-data", exact: true })).toBeVisible();
  const step = page.getByRole("button", { name: /DeployRole.*ключова ланка/i });
  await step.hover();
  await expect(page.locator(".path-edge.highlight")).toHaveCount(1);
});

test("FR-DET runs a backtest against workspace history", async ({ page }) => {
  await page.goto("/detections");
  await page.getByRole("button", { name: "Запустити бектест" }).click();
  await expect(page.getByRole("heading", { name: "Результат бектесту" })).toBeVisible({ timeout: 20000 });
  await expect(page.getByText("Змінено рівень", { exact: false })).toBeVisible();
});

test("FR-GOV calculates the AHP matrix and displays the consistency ratio", async ({ page }) => {
  await page.goto("/models");
  await expect(page.getByRole("heading", { name: "Парні порівняння AHP" })).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "Узгоджено" })).toBeVisible();
  await page.getByLabel("Профіль AHP").selectOption("core-v1");
  await expect(page.getByLabel("geo / ip")).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "Узгоджено" })).toBeVisible();
});

test("Role, configuration, SLA, quality and notification routes render their data", async ({ page }) => {
  for (const [path, label] of [
    ["/role-chains", "Ланцюжки ролей"], ["/cloud", "Хмарна конфігурація"], ["/sla", "SLA та метрики"],
    ["/quality", "Якість моделі"], ["/integrations/notifications", "Інтеграції сповіщень"],
  ]) {
    await page.goto(path ?? "");
    await expect(page.getByRole("heading", { name: label, exact: true, level: 1 })).toBeVisible();
  }
});
