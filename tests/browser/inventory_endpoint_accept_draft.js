// Playwright CLI run-code regression. Start on a clean PC card with manual RAM 8 and Endpoint RAM 16.
async (page) => {
  const ram = page.getByRole("spinbutton", { name: "Объём RAM, ГБ" });
  const notes = page.getByRole("textbox", { name: "Описание", exact: true });
  const save = page.getByRole("button", { name: "СОХРАНИТЬ", exact: true });
  const draftNotes = "Unrelated draft while accepting Endpoint RAM " + Date.now();
  let captured;
  let held;
  const intercepted = new Promise((resolve) => { captured = resolve; });
  const pattern = "**/discrepancies/ram_gb/resolve";
  await page.route(pattern, (route) => captured(route), { times: 1 });
  await page.evaluate(() => { window.__inventoryOriginalConfirm = window.confirm; window.confirm = () => true; });
  try {
    await page.getByRole("button", { name: "Принять Endpoint", exact: true }).click();
    held = await intercepted;
    const submitDisabled = await save.isDisabled();
    const submitPrevented = await page.locator("[data-inventory-asset-form]").evaluate(
      (form) => !form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
    await notes.fill(draftNotes);
    const responseReady = page.waitForResponse((response) => response.url().includes("/discrepancies/ram_gb/resolve"));
    await held.continue();
    held = null;
    const response = await responseReady;
    if (response.status() !== 200) throw new Error("Expected accepted Endpoint value");
    await page.waitForLoadState("networkidle");
    if (await ram.inputValue() !== "16") throw new Error("Untouched RAM input still contains the pre-action value");
    if (await notes.inputValue() !== draftNotes) throw new Error("Unrelated draft lost");
    await save.click();
    await page.waitForLoadState("networkidle");
    if (await ram.inputValue() !== "16") throw new Error("Saving unrelated edits reverted accepted Endpoint RAM");
    if (await notes.inputValue() !== draftNotes) throw new Error("Unrelated draft was not saved");
    if (!submitDisabled || !submitPrevented) throw new Error("Manual form submission was possible during Endpoint request");
    return { acceptedRamAfterSave: 16, unrelatedDraftSaved: true, concurrentSubmitBlocked: true };
  } finally {
    if (held) await held.abort();
    await page.unroute(pattern);
    await page.evaluate(() => {
      if (window.__inventoryOriginalConfirm) window.confirm = window.__inventoryOriginalConfirm;
      delete window.__inventoryOriginalConfirm;
    });
  }
};
