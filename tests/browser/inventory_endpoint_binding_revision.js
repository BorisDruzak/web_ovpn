// Run on a clean synthetic PC card with a confirmed Endpoint binding.
async (page) => {
  const errors = [];
  const onError = (error) => errors.push(error.message);
  const onDialog = (dialog) => dialog.accept();
  page.on('pageerror', onError);
  page.on('dialog', onDialog);
  try {
    // Accept confirmation in-page so CLI does not yield before assertions finish.
    await page.evaluate(() => { window.confirm = () => true; });
    const card = page.locator('[data-endpoint-card]');
    const original = await card.getAttribute('data-manual-revision');
    const csrf = await card.getAttribute('data-csrf');
    const oldURL = page.url();
    const button = page.getByRole('button', {name:'Отвязать агент', exact:true});
    const path = await button.getAttribute('data-endpoint-action');
    let result;
    await page.route('**' + path, async (route) => {
      const upstream = await route.fetch();
      result = await upstream.json();
      await route.fulfill({response:upstream});
    }, {times:1});
    const responsePromise = page.waitForResponse((response) => response.url().endsWith(path) && response.request().method() === 'POST');
    await button.click();
    const response = await responsePromise;
    if (response.status() !== 200 || response.request().headers()['x-inventory-revision'] !== original) {
      throw new Error('Binding action did not claim displayed manual revision');
    }
    await page.waitForURL((url) => url.href !== oldURL && url.searchParams.has('draft_id'));
    await page.getByText('Агент не привязан', {exact:true}).waitFor();
    const newBase = await page.locator('[data-inventory-asset-form] [name="expected_revision"]').inputValue();
    if (newBase !== String(result.manual_revision)) throw new Error('Clean draft retained old revision after decision');
    const retryURL = await page.evaluate((path) => new URL(path, location.href).href, path);
    const retry = await page.request.post(retryURL, {
      headers:{'X-CSRF-Token':csrf, 'X-Inventory-Revision':original}, data:{}
    });
    if (retry.status() !== 409) throw new Error('Stale binding retry was not rejected');
    if (errors.length) throw new Error(errors.join('; '));
    await page.evaluate(() => { window.endpointBindingRevisionVerified = true; });
    return {bindingRevisionSent:true, cleanDraftRenewed:true, staleRetryRejected:true, pageErrors:errors.length};
  } finally {
    page.off('pageerror', onError);
    page.off('dialog', onDialog);
  }
};
