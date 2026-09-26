// Run on a clean synthetic PC card with manual RAM8 and cached Endpoint RAM16.
// The public session API is exercised directly; current field UI uses insertion.
async (page) => {
  const errors = [];
  const onError = error => errors.push(error.message);
  page.on('pageerror', onError);
  try {
    const root = await page.evaluate(() => location.origin);
    const bare = page.url().split('?')[0];
    const asset = bare.split('/').pop();
    const contextURL = root + '/api/v1/inventory/assets/' + asset + '/context';
    const context = await page.request.get(contextURL).then(response => response.json());
    const original = String(context.data.manual_revision);
    const comparison = context.data.discrepancies.find(row => row.field === 'ram_gb').revision;
    const csrf = await page.locator('[data-endpoint-card]').getAttribute('data-csrf');
    const target = root + '/api/v1/inventory/assets/' + asset + '/discrepancies/ram_gb/resolve';
    const payload = {action:'accept_endpoint', expected_revision:comparison};
    const missing = await page.request.post(target, {headers:{'X-CSRF-Token':csrf}, data:payload});
    if (missing.status() !== 428) throw new Error('Card revision is not required');
    await page.getByRole('textbox', {name:'Описание', exact:true}).fill('Synthetic unrelated manual edit');
    const saved = page.waitForResponse(response => response.request().method() === 'POST' && response.url() === bare);
    await page.getByRole('button', {name:'СОХРАНИТЬ', exact:true}).click();
    if ((await saved).status() !== 303) throw new Error('Synthetic manual edit failed');
    await page.waitForLoadState('networkidle');
    const current = await page.request.get(contextURL).then(response => response.json());
    if (current.data.discrepancies.find(row => row.field === 'ram_gb').revision !== comparison) {
      throw new Error('Unrelated edit unexpectedly changed comparison hash');
    }
    const stale = await page.request.post(target, {headers:{'X-CSRF-Token':csrf,'X-Inventory-Revision':original}, data:payload});
    if (stale.status() !== 409) throw new Error('Old card revision bypassed unchanged comparison hash');
    const accepted = await page.request.post(target, {headers:{'X-CSRF-Token':csrf,
      'X-Inventory-Revision':String(current.data.manual_revision)}, data:payload});
    if (accepted.status() !== 200) throw new Error('Fresh comparison was not accepted');
    const result = await accepted.json();
    await page.goto(bare);
    const form = page.locator('[data-inventory-asset-form]');
    if (await form.locator('[name=expected_revision]').inputValue() !== String(result.manual_revision)
        || await form.locator('[name=ram_gb]').inputValue() !== '16'
        || await form.locator('[name=description]').inputValue() !== 'Synthetic unrelated manual edit') {
      throw new Error('Fresh draft/manual facts disagree with committed decision');
    }
    if (errors.length) throw new Error(errors.join('; '));
    return {missing428:true, unchangedHashStale409:true, freshDecision200:true, freshDraft:true, pageErrors:0};
  } finally { page.off('pageerror', onError); }
};
