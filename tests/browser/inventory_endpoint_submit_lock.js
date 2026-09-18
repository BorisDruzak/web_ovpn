// Playwright CLI run-code regression. Start on a clean PC card with a RAM discrepancy.
async (page) => {
  let captured;
  let held;
  const intercepted = new Promise((resolve) => { captured = resolve; });
  const pattern = "**/discrepancies/ram_gb/resolve";
  await page.route(pattern, (route) => captured(route), { times: 1 });
  try {
    await page.getByRole("button", { name: "Оставить ручное", exact: true }).click();
    held = await intercepted;
    const disabled = await page.getByRole("button", { name: "СОХРАНИТЬ", exact: true }).isDisabled();
    const prevented = await page.locator("[data-inventory-asset-form]").evaluate(
      (form) => !form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
    if (!disabled || !prevented) throw new Error("Manual form submission is not locked during Endpoint action");
    return { concurrentSubmitBlocked: true };
  } finally {
    if (held) await held.abort();
    await page.unroute(pattern);
  }
};
