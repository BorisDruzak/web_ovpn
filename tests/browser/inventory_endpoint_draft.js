// Playwright CLI run-code regression. Start on an authenticated PC card with a RAM discrepancy.
async (page) => {
  const ram = page.getByRole("spinbutton", { name: "Объём RAM, ГБ" });
  const person = page.getByRole("textbox", { name: "Ответственный", exact: true });
  const notes = page.getByRole("textbox", { name: "Описание", exact: true });
  await ram.fill("12");
  await person.fill("Unsaved assigned person");
  await notes.fill("Unsaved physical inventory notes");
  const mutations = [];
  const capture = (request) => {
    if (request.method() === "POST" && request.url().includes("/discrepancies/")) mutations.push(request.url());
  };
  page.on("request", capture);
  try {
    await page.getByRole("button", { name: "Оставить ручное", exact: true }).click();
    await page.waitForLoadState("networkidle");
    if (await ram.inputValue() !== "12" || await person.inputValue() !== "Unsaved assigned person"
        || await notes.inputValue() !== "Unsaved physical inventory notes") {
      throw new Error("Endpoint action discarded unsaved manual fields");
    }
    if (mutations.length) throw new Error("Endpoint action must wait until the manual draft is saved or discarded");
    if (!(await page.locator("[data-endpoint-feedback]").innerText()).includes("Сохраните")) {
      throw new Error("Missing explanation for the blocked Endpoint action");
    }
    return { draftPreserved: true, endpointMutationSent: false };
  } finally {
    page.off("request", capture);
  }
};
