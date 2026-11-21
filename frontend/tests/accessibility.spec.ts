import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("UX-P7 WCAG checks pass on the overview in both themes", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Огляд", exact: true })).toBeVisible();
  for (const theme of ["dark", "light"]) {
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
    expect(result.violations.map((issue) => ({ id: issue.id, nodes: issue.nodes.map((node) => node.target) }))).toEqual([]);
    if (theme === "dark") await page.getByRole("button", { name: "Змінити тему" }).click();
  }
});
