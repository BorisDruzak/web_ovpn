// Run on the authenticated card created by inventory_fixture_server.py.
async (page) => {
  const ip = page.locator('input[name="ip_address"]');
  const mac = page.locator('input[name="mac_address"]');
  const description = page.locator('textarea[name="description"]');
  await ip.fill('192.0.2.10');
  await description.fill('Несохранённое описание');
  const insert = page.locator('[data-endpoint-insert="ip"]');
  await insert.click();
  if (await ip.inputValue() !== '192.0.2.24') throw new Error('IP source-to-form mapping failed');
  await insert.click();
  if (await ip.inputValue() !== '192.0.2.10') throw new Error('Undo discarded previous manual IP');
  await insert.click();
  await page.locator('[data-endpoint-insert="mac"]').click();
  if (await mac.inputValue() !== '02:00:00:00:00:24') throw new Error('MAC mapping failed');
  await page.locator('[data-endpoint-insert="ram_gb"]').click();
  if (await page.locator('[name="ram_gb"]').inputValue() !== '0') throw new Error('Zero lost');
  const os = page.locator('[name="os_name"]');
  await os.selectOption('Windows');
  await page.locator('[data-endpoint-insert="os_name"]').click();
  if (await os.inputValue() !== 'Windows') throw new Error('Unsupported OS overwrote manual value');
  if (!(await page.locator('[data-inventory-insert-feedback]').innerText()).includes('не поддерживается')) {
    throw new Error('Missing normalization explanation');
  }
  if (await description.inputValue() !== 'Несохранённое описание') throw new Error('Other fields lost');
  let endpointMutations = 0;
  const capture = (request) => {
    if (request.method() === 'POST' && request.url().includes('endpoint-refresh')) endpointMutations++;
  };
  page.on('request', capture);
  await page.getByRole('button', {name:'Обновить данные агента', exact:true}).click();
  if (endpointMutations) throw new Error('Insertion did not mark form dirty');
  page.off('request', capture);
  await page.getByRole('button', {name:'СОХРАНИТЬ', exact:true}).click();
  await page.waitForLoadState('networkidle');
  if (await ip.inputValue() !== '192.0.2.24' || await mac.inputValue() !== '02:00:00:00:00:24') {
    throw new Error('Inserted identifiers not persisted');
  }
  await page.reload();
  if (await description.inputValue() !== 'Несохранённое описание') throw new Error('Saved data lost on reload');
  return {ip: await ip.inputValue(), mac: await mac.inputValue(), zero: true, undo: true,
    unsupportedSelectPreserved: true, dirtyLock: true, savedAndReloaded: true};
};
