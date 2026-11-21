import { expect, test } from "@playwright/test";

test("Profile is discoverable and persists local workspace details", async ({ page, request }) => {
  const headers = { "X-IdentityGuard-Local": "1" };
  const previous = await (await request.get("/api/v1/profile")).json();
  try {
    await page.goto("/");
    await page.locator(".profile-button").click();
    await expect(page.getByRole("heading", { name: "Профіль", exact: true })).toBeVisible();
    await page.getByLabel("Ім’я та прізвище").fill("SOC Analyst");
    await page.getByLabel("Електронна пошта").fill("analyst@example.test");
    await page.getByRole("button", { name: "Зберегти зміни" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Профіль збережено" })).toBeVisible();
    await expect(page.locator(".profile-button")).toHaveText("SOC Analyst");
    await page.reload();
    await expect(page.getByLabel("Електронна пошта")).toHaveValue("analyst@example.test");
  } finally {
    const restored = await request.put("/api/v1/profile", { headers, data: previous });
    expect(restored.ok()).toBe(true);
  }
});

test("AWS integration explains how to launch the protected workspace", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("navigation").getByRole("link", { name: "Інтеграція AWS" }).click();
  await expect(page.getByRole("heading", { name: "Інтеграція AWS", exact: true })).toBeVisible();
  await expect(page.getByText("aws configure sso --profile identityguard")).toBeVisible();
  await expect(page.getByRole("link", { name: "Відкрити область AWS" })).toHaveAttribute("href", "http://127.0.0.1:8010/integrations/aws");
});

test("Assistant opens case analysis with an explicit template state", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("navigation").getByRole("link", { name: "ШІ-асистент" }).click();
  await expect(page.getByRole("heading", { name: "ШІ-асистент", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByText("Шаблонний аналіз", { exact: true })).toBeVisible();
  await expect(page.getByText("Чернетка для власника ідентичності")).toBeVisible();
  await expect(page.getByText("Anthropic неактивний")).toBeVisible();
  await page.getByRole("link", { name: "Відкрити кейс" }).click();
  await expect(page.getByText("Шаблонний аналіз", { exact: true })).toBeVisible();
});
