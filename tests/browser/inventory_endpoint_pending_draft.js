// Playwright CLI run-code regression. Start on a clean authenticated PC card with a RAM discrepancy.
async (page) => {
  const ram = page.getByRole("spinbutton", { name: "Объём RAM, ГБ" });
  const person = page.getByRole("textbox", { name: "Ответственный", exact: true });
  const notes = page.getByRole("textbox", { name: "Описание", exact: true });
  let captured;
  const intercepted = new Promise((resolve) => { captured = resolve; });
  const pattern = "**/discrepancies/ram_gb/resolve";
  await page.route(pattern, (route) => captured(route), { times: 1 });
  try {
    await page.getByRole("button", { name: "Оставить ручное", exact: true }).click();
    const route = await intercepted;
    await ram.fill("12");
    await person.fill("Draft entered during request");
    await notes.fill("Pending action must preserve this note");
    const responseReady = page.waitForResponse((response) => response.url().includes("/discrepancies/ram_gb/resolve"));
    await route.continue();
    const response = await responseReady;
    if (response.status() !== 200) throw new Error("Expected successful Endpoint action");
    await page.waitForLoadState("networkidle");
    if (await ram.inputValue() !== "12" || await person.inputValue() !== "Draft entered during request"
        || await notes.inputValue() !== "Pending action must preserve this note") {
      throw new Error("Completed Endpoint action discarded a draft entered while waiting");
    }
    if (!(await page.locator("[data-endpoint-feedback]").innerText()).includes("Действие выполнено")) {
      throw new Error("Missing completed-action explanation while preserving new draft");
    }
    return { draftPreserved: true, endpointMutationCompleted: true };
  } finally {
    await page.unroute(pattern);
  }
};
