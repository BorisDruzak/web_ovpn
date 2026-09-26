// Run only against the authenticated synthetic loopback fixture.
async (page) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  // Accept the expected dirty-form beforeunload warning during reload QA.
  page.on('dialog', dialog => dialog.accept());
  await page.goto('http://127.0.0.1:8874/inventory/network-links?network_key=mac%3A02%3A00%3A00%3A00%3A00%3A24');
  if (await page.getByRole('button',{name:'Открыть форму создания',exact:true}).isDisabled()) {
    await page.getByRole('link',{name:'Сначала создать локацию',exact:true}).click();
    await page.getByRole('textbox',{name:'Название локации',exact:true}).fill('Synthetic network creation location');
    await page.getByRole('button',{name:'СОХРАНИТЬ ЛОКАЦИЮ',exact:true}).click();
    await page.goto('http://127.0.0.1:8874/inventory/network-links?network_key=mac%3A02%3A00%3A00%3A00%3A00%3A24');
  }
  await page.getByRole('button',{name:'Открыть форму создания',exact:true}).click();
  const form = page.locator('[data-inventory-asset-form]');
  await form.locator('[name="custom_name"]').fill('Synthetic atomic network PC');
  await form.locator('[name="ram_gb"]').fill('16');
  await form.locator('[name="network_reason"]').fill('Compared physical label and all possible duplicate cards');
  await form.locator('[name="network_confirmation"]').check();
  const draftId = await form.locator('[name="draft_id"]').inputValue();
  await page.waitForTimeout(5500);
  await page.reload();
  if (await form.locator('[name="draft_id"]').inputValue() !== draftId) throw new Error('Draft replaced');
  if (await form.locator('[name="custom_name"]').inputValue() !== 'Synthetic atomic network PC') throw new Error('Owned draft lost input');
  if (!(await form.locator('[name="network_confirmation"]').isChecked())) throw new Error('Confirmation draft lost');
  await form.getByRole('button',{name:'СОХРАНИТЬ',exact:true}).click();
  await page.waitForURL(/\/inventory\/locations\//);
  await page.getByRole('link',{name:/^Synthetic atomic network PC PC$/}).click();
  const network = await page.locator('[aria-label="Сеть"]').innerText();
  if (!network.includes('Связано') || !network.includes('192.0.2.24')) throw new Error('Card binding missing');
  if (await page.locator('[data-inventory-asset-form] [name="ram_gb"]').inputValue() !== '16') throw new Error('Full details lost');
  if (errors.length) throw new Error(errors.join(';'));
  return {result:'PASS owned autosave/full-card create+first confirmed link/details',draftId,errors};
}
