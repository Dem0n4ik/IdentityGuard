import { expect, test } from "@playwright/test";

test("An incident exposes the recorded evidence and context comparison in place", async ({ page }) => {
  await page.goto("/incidents?range=all");
  await page.getByRole("table").getByRole("link", { name: "root", exact: true }).first().click();
  await expect(page.getByRole("heading", { name: "Докази розрахунку ризику" })).toBeVisible();
  await expect(page.getByText("Без контексту · M = 1")).toBeVisible();
  await expect(page.getByText("Поведінковий профіль до оцінки")).toBeVisible();
  await expect(page.getByText("Політика root примусово встановлює високий рівень", { exact: false })).toBeVisible();
  await expect(page.getByRole("table", { name: "Внески в поведінкову оцінку B" }).getByRole("columnheader", { name: "Подія з максимумом" })).toBeVisible();
});

test("Hunt applies region and category filters from a shareable URL", async ({ page, request }) => {
  const response = await request.get("/api/v1/events?limit=1");
  expect(response.ok()).toBeTruthy();
  const seed = (await response.json()).items[0];
  await page.goto("/hunt?range=all");
  await page.getByLabel("Фільтр за операцією").fill(seed.name);
  await page.getByLabel("Регіон", { exact: true }).fill(seed.region);
  await page.getByLabel("Категорія", { exact: true }).selectOption(seed.category);
  await page.getByRole("button", { name: "Застосувати фільтр" }).click();
  await expect(page).toHaveURL(/region=/);
  await expect(page).toHaveURL(/category=/);
  const rows = page.locator("tbody tr");
  await expect(rows.first()).toContainText(seed.name);
  await expect(rows.first()).toContainText(seed.region);
  await expect(rows.first()).toContainText(seed.category);
});
