// Run on the synthetic asset in inventory_fixture_server.py.
async (page) => {
  const url = await page.evaluate(() => { const fresh = new URL(location.href); fresh.searchParams.delete('draft_id'); return fresh.href; });
  const second = await page.context().newPage();
  await second.goto(url);
  const revision = await page.locator('[name="expected_revision"]').inputValue();
  await page.locator('[name="custom_name"]').fill('Сохранено первым редактором');
  await page.getByRole('button', {name:'СОХРАНИТЬ', exact:true}).click();
  await page.waitForLoadState('networkidle');
  await second.locator('[name="custom_name"]').fill('Ввод второго редактора');
  await second.getByRole('button', {name:'СОХРАНИТЬ', exact:true}).click();
  await second.waitForLoadState('networkidle');
  if (await second.locator('[name="expected_revision"]').inputValue() !== revision) throw new Error('Stale revision was silently replaced');
  if (await second.locator('[name="custom_name"]').inputValue() !== 'Ввод второго редактора') throw new Error('Conflict lost input');
  if (!(await second.locator('[role="alert"]').innerText()).includes('Сохранено первым редактором')) throw new Error('Missing current value comparison');
  await second.getByRole('button', {name:'СОХРАНИТЬ', exact:true}).click();
  await second.waitForLoadState('networkidle');
  if (await second.locator('[name="expected_revision"]').inputValue() !== revision) throw new Error('Repeated stale submission bypassed guard');
  await second.close();
  return {staleRejected:true, inputRetained:true, compared:true, repeatedStaleRejected:true};
};
