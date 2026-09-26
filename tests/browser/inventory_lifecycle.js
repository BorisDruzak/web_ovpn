// Start on a fresh synthetic PC card; no production cards are used.
async page => {
  const id = await page.locator('form[action$="/delete"] [name="confirmation"]').getAttribute('value');
  const name = await page.locator('[name="custom_name"]').inputValue();
  await page.locator('summary').filter({hasText:/^Удалить устройство$/}).click();
  await page.locator('form[action$="/delete"] [name="reason"]').fill('Синтетическая ошибочная карточка');
  await page.locator('form[action$="/delete"] [name="confirmation"]').check();
  await page.locator('form[action$="/delete"]').getByRole('button', {name:'Удалить устройство',exact:true}).click();
  await page.waitForURL(`**/inventory/deleted/${id}`);
  if (!(await page.locator('main').innerText()).includes('Связи не восстанавливаются автоматически')) throw new Error('Missing restore consequence');
  const ordinaryUrl = await page.evaluate(id => new URL(`/inventory/assets/${id}`, location.href).href, id);
  const read = await page.request.get(ordinaryUrl);
  if (read.status() !== 404) throw new Error('Deleted card remains accessible through ordinary URL');
  await page.getByRole('button',{name:'Восстановить карточку',exact:true}).click();
  await page.waitForURL(`**/inventory/assets/${id}?draft_id=*`);
  if (await page.locator('[name="custom_name"]').inputValue() !== name) throw new Error('Restored card lost its name');
  return {deletedHidden:true, historyVisible:true, sameIdRestored:true};
}
