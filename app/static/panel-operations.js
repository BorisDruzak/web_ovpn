// One explicit submission intent per form; transport retry uses the same key.
(() => {
  const newKey = () => Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
  window.addEventListener('pageshow',()=>{
    // History can restore form values even without bfcache (persisted=false).
    // Every displayed page starts a new intent; retries retain their sent body.
    // Rotate the restored form only; the already-sent request body stays intact.
    document.querySelectorAll('form[action="/inventory/export"],form[action="/network/export"]').forEach(form=>{
      const field = form.querySelector('[name="operation_key"]');
      if(field) field.value = newKey();
    });
  });
  document.addEventListener('submit', event => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || form.method.toLowerCase() !== 'post') return;
    const path = new URL(form.action, window.location.href).pathname;
    if (!/^\/(clients|connections|settings\/openvpn|networks|network-templates|network\/)/.test(path)) return;
    if (form.querySelector('[name="operation_key"]')) return;
    const field = document.createElement('input');
    field.type = 'hidden';
    field.name = 'operation_key';
    field.value = newKey();
    form.append(field);
  }, true);
})();
