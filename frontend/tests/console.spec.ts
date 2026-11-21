import { expect, test } from "@playwright/test";

test("UX-P1 dashboard renders scored cases and translates labels", async ({ page }) => {
  const uncaught: string[] = [];
  page.on("pageerror", (error) => uncaught.push(error.message));
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Огляд", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Потребують уваги" })).toBeVisible();
  await expect(page.locator("tbody tr").first()).toBeVisible();
  await page.getByRole("button", { name: "Змінити тему" }).click();
  await page.getByRole("button", { name: "Змінити мову" }).click();
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator("body")).not.toHaveText(/[А-Яа-яІіЇїЄє]/);
  await page.reload();
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  expect(uncaught).toEqual([]);
});

test("UX-P4 account and severity filters update the URL and browser history", async ({ page }) => {
  await page.goto("/cases?range=all");
  await expect(page.getByRole("heading", { name: "Кейси", exact: true })).toBeVisible();
  await page.getByLabel("Облікові записи AWS").selectOption("222233334444");
  await expect(page).toHaveURL(/\/cases\?.*account=/);
  await expect(page.locator("tbody")).toContainText("ProdAdminRole");
  await page.getByRole("combobox", { name: "Рівень", exact: true }).selectOption("high");
  await expect(page).toHaveURL(/level=high/);
  await expect(page.getByText("Результатів немає")).toBeVisible();
  await page.goBack();
  await expect(page.locator("tbody")).toContainText("ProdAdminRole");
});

test("UX-P5 command palette opens an identity and pivots into events", async ({ page }) => {
  await page.goto("/?range=all");
  await expect(page.getByRole("heading", { name: "Огляд", exact: true })).toBeVisible();
  await page.keyboard.press("Control+k");
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await dialog.getByRole("textbox").fill("bohdan-dev");
  await dialog.getByRole("link", { name: "bohdan-dev" }).click();
  await expect(page.getByRole("heading", { name: "bohdan-dev", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Переглянути події" }).click();
  await expect(page).toHaveURL(/\/hunt\?.*identity=/);
  await page.getByRole("combobox", { name: "Час", exact: true }).selectOption("all");
  await page.getByRole("textbox", { name: "Фільтр за операцією" }).fill("CreateAccessKey");
  await page.getByRole("button", { name: "Застосувати фільтр" }).click();
  await expect(page.locator("tbody")).toContainText("CreateAccessKey");
  await expect(page.locator("tbody")).not.toContainText("olena-analyst");
});

test("FR-CHAIN S8 case includes both identities", async ({ page }) => {
  await page.goto("/cases?range=all");
  await page.getByRole("link", { name: /bohdan-dev.*ProdAdminRole|ProdAdminRole.*bohdan-dev/ }).click();
  const incidents = page.getByRole("table", { name: "Інциденти", exact: true });
  await expect(incidents.locator("tbody tr")).toHaveCount(2);
  await expect(incidents).toContainText("bohdan-dev");
  await expect(incidents).toContainText("ProdAdminRole");
  await expect(page.getByText("Ризикове джерело ролі", { exact: true })).toBeVisible();
});



test("FR-RESP isolation confirms the exact identity and records a dry run", async ({ page }) => {
  await page.goto("/incidents?range=all");
  await page.getByRole("link", { name: "bohdan-dev", exact: true }).first().click();
  const confirm = page.getByLabel("Введіть точну назву користувача IAM");
  const action = page.getByRole("button", { name: "Записати дію в режимі перевірки" });
  await expect(action).toBeDisabled();
  await confirm.fill("Bohdan-dev");
  await expect(action).toBeDisabled();
  await confirm.fill("bohdan-dev");
  await action.click();
  await expect(page.getByRole("status").filter({ hasText: "Дію записано в режимі перевірки" })).toBeVisible();
  await expect(page.locator(".page-header")).toContainText("Відреаговано");
});
